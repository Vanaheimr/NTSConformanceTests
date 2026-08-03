using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// The <c>ntske/1</c> ALPN identifier as a precondition rather than an ornament, on the server's
/// side of the connection.
///
/// <para>
/// RFC 8915 § 3 calls the Application-Layer Protocol Negotiation extension "integral to NTS" and
/// its support "REQUIRED for interoperability"; § 4 describes the exchange as one "with the
/// client offering (via an ALPN extension), and the server accepting, an application-layer
/// protocol of ntske/1". Neither spells out what either end does when the other does not play
/// along, which is exactly why both ends of Norn used to let it slide — and why chrony checks it
/// explicitly, in both roles, comparing the selected name after every handshake.
/// </para>
/// <para>
/// Norn's server had half the rule for free: naming the protocol makes BouncyCastle fail the
/// handshake when a client offers ALPN and none of it matches. The other half — a client that
/// offers no ALPN extension at all — was not covered, because RFC 7301 lets a server say nothing
/// about a negotiation it was never asked for, so the handshake completed and the server handed
/// out cookies to a peer that had never claimed to be doing NTS.
/// </para>
/// <para>
/// The client's half of the same rule is in <c>ClientRequestOnTheWireTests</c>, which needs a
/// server that can decline to select the protocol.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsKeAlpnTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(
                               certificate: TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]));


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// A client that offers no ALPN extension gets no handshake, and no records.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Refused during the ClientHello rather than after the handshake, which is where chrony
    /// refuses it. Earlier is better here: nothing is signed, no key is derived, and the client
    /// learns the reason from a TLS alert instead of from a connection that closes for no stated
    /// cause.
    /// </para>
    /// <para>
    /// The second assertion is the one that matters. A handshake failure alone would be
    /// satisfied by a server that fell over for any reason at all; that no NTS-KE record came
    /// back is the statement that nothing was served.
    /// </para>
    /// </remarks>
    [Test]
    public async Task AClientOfferingNoAlpn_IsRefused()
    {

        var exchange = await RawNtsKeClient.ExchangeAsync("127.0.0.1",
                                                          fixture!.NTSKEPort,
                                                          RawNtsKeCodec.ClientRequest(),
                                                          TimeSpan.FromSeconds(10),
                                                          offerAlpn: false);

        Assert.Multiple(() => {

            Assert.That(exchange.HandshakeSucceeded, Is.False,
                        $"a peer that never asked for ntske/1 is not an NTS-KE client\n{exchange}");

            Assert.That(exchange.Records, Is.Null,
                        $"and it must be served nothing\n{exchange}");

        });

    }


    /// <summary>
    /// The control: the same request with the ALPN extension is answered in full.
    /// </summary>
    /// <remarks>
    /// Without this, the test above is satisfied by a server that refuses everyone — which is
    /// the shape the enforcement would take if the condition were inverted, and the cheapest
    /// mistake to make here.
    /// </remarks>
    [Test]
    public async Task AClientOfferingNtske1_IsAnswered()
    {

        var exchange = await RawNtsKeClient.ExchangeAsync("127.0.0.1",
                                                          fixture!.NTSKEPort,
                                                          RawNtsKeCodec.ClientRequest(),
                                                          TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {

            Assert.That(exchange.HandshakeSucceeded, Is.True, $"{exchange}");

            Assert.That(exchange.NegotiatedAlpn, Is.EqualTo("ntske/1"),
                        $"the server has to select it, not merely tolerate it\n{exchange}");

            Assert.That(exchange.FirstRecordOfType(RawNtsKeRecordTypes.NewCookieForNtpv4),
                        Is.Not.Null,
                        $"and answer with a usable key exchange\n{exchange}");

        });

    }

}
