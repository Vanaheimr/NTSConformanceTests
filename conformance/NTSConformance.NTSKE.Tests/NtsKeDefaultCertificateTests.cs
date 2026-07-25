using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// The certificate Norn generates for itself when none is supplied.
///
/// A separate fixture from the rest because it must run against a server started with **no**
/// injected certificate — the whole point is what Norn produces unaided, which is what anyone
/// gets on first run and what the README's own quickstart yields.
///
/// The client here is .NET's <c>SslStream</c>, i.e. Windows' SChannel. That is deliberately a
/// different TLS stack from the BouncyCastle one Norn uses on both ends, and from the GnuTLS
/// one the interop tests use: a certificate only ever validated by the library that produced
/// it has not been validated.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsKeDefaultCertificateTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServerWithoutACertificate()
        => fixture = await NornServerFixture.StartAsync();   // no certificate: Norn generates one


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// A standards-compliant TLS 1.3 client must be able to complete an NTS-KE handshake
    /// against a default-configured server.
    ///
    /// Norn built its EC key from an <c>ECDomainParameters</c> assembled out of the curve's
    /// components rather than from the curve's OID, which makes BouncyCastle encode the whole
    /// curve specification into the certificate as explicit EC parameters — 335 octets of
    /// SubjectPublicKeyInfo instead of 91. RFC 5480 §2.1.1 permits that encoding, but
    /// Windows' SChannel/CNG implements only named curves and rejects the certificate with
    /// <c>CRYPT_E_ASN1_BADTAG</c> before any validation callback is consulted.
    ///
    /// The effect was that no .NET client on Windows could talk to a default-configured Norn
    /// server, while BouncyCastle and GnuTLS clients — the only ones previously tested —
    /// accepted it happily. Certificate validation cannot be switched off around this: the
    /// failure is in parsing, not in trust.
    /// </summary>
    [Test]
    public async Task DefaultCertificate_IsAcceptedByASchannelClient()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var exchange = await RawNtsKeClient.ExchangeAsync("127.0.0.1",
                                                          fixture.NTSKEPort,
                                                          RawNtsKeCodec.ClientRequest(),
                                                          TimeSpan.FromSeconds(15));

        Assert.That(exchange.HandshakeSucceeded,
                    Is.True,
                    "a default-configured server must be usable by a standards-compliant TLS client. " +
                    "CRYPT_E_ASN1_BADTAG (0x8009310B) here means the certificate carries explicit EC " +
                    $"parameters instead of a named curve.\n{exchange}");

        Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).Any(),
                    Is.True,
                    $"the exchange should complete and yield cookies\n{exchange}");

    }


    /// <summary>
    /// The default certificate must still carry what RFC 8915 §4 needs around it: TLS 1.3 and
    /// the ntske/1 ALPN protocol.
    /// </summary>
    [Test]
    public async Task DefaultCertificate_StillNegotiatesTls13AndAlpn()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var exchange = await RawNtsKeClient.ExchangeAsync("127.0.0.1",
                                                          fixture.NTSKEPort,
                                                          RawNtsKeCodec.ClientRequest(),
                                                          TimeSpan.FromSeconds(15));

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        Assert.Multiple(() => {

            Assert.That(exchange.TlsVersion.ToString(),
                        Does.Contain("13"),
                        $"RFC 8915 §4 requires TLS 1.3 or later\n{exchange}");

            Assert.That(exchange.NegotiatedAlpn,
                        Is.EqualTo("ntske/1"),
                        $"RFC 8915 §4 runs NTS-KE under the ntske/1 ALPN protocol\n{exchange}");

        });

    }

}
