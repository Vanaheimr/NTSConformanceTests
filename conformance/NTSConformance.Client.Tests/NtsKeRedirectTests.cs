using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// RFC 8915 §4.1.7 (NTPv4 Server Negotiation) and §4.1.8 (NTPv4 Port Negotiation): the
/// key exchange tells the client where to send its time queries, and that destination need
/// not be the host it just spoke TLS to.
///
/// This is how every real NTS deployment scales — a key-exchange front end handing clients
/// off to a fleet of time servers — and it is the mechanism the NTS pool drafts build on.
///
/// The records themselves are covered elsewhere: Norn emits them, parses them and reports
/// them. What was never checked is the only part that matters operationally, that the UDP
/// query <em>goes</em> where the records say. A client that parses both records perfectly and
/// then queries the key-exchange host anyway returns a flawless measurement from the wrong
/// server, and no assertion on its return value can see it.
///
/// So the assertions here are made from the far end. A <see cref="UdpRelayProbe"/> occupies
/// the advertised address, records what arrives and passes it to the real server, which keeps
/// the exchange working end to end rather than proving the redirect by breaking it.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsKeRedirectTests
{

    private UdpRelayProbe?      probe;
    private NornServerFixture?  fixture;

    private static readonly TimeSpan queryTimeout = TimeSpan.FromSeconds(15);


    [TearDown]
    public async Task StopEverything()
    {

        if (fixture is not null)
            await fixture.DisposeAsync();

        probe?.Dispose();

        fixture = null;
        probe   = null;

    }


    /// <summary>
    /// Start a probe, then a server that advertises the probe's port — and optionally a
    /// different host — while listening on its own.
    /// </summary>
    private async Task StartRedirectedServer(String? advertisedHost = null)
    {

        // The probe has to exist before the server, because the server's advertised port is
        // the port the probe ended up with.
        probe    = UdpRelayProbe.StartObserving();

        fixture  = await NornServerFixture.StartAsync(
                             certificate:        TestCertificate.Generate("redirect.test", [ "redirect.test" ]),
                             externalHostName:   advertisedHost,
                             advertisedNTPPort:  probe.Port
                         );

        // ...and only now is there a real NTP port to put behind it.
        probe.RelayTo(fixture.NTPPort);

    }


    /// <summary>
    /// A full NTS exchange: key establishment first, then a time query carrying the cookies it
    /// produced.
    ///
    /// The two steps have to be separate. <c>QueryTime</c> without a key exchange response
    /// sends a plain NTP packet, and a plain NTP client has no records to follow — the
    /// negotiation records only exist for a client that did the key exchange.
    /// </summary>
    private async Task<NTSQueryResult> NtsQuery()
    {

        var client        = fixture!.CreateClient(queryTimeout);
        var keyExchange   = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success,
                    Is.True,
                    $"the key exchange itself failed, so nothing can be said about where the " +
                    $"time query went: {keyExchange.ErrorMessage}");

        return await client.QueryTime(NTSKEResponse:  keyExchange.Response!,
                                      Timeout:        queryTimeout);

    }


    #region the query follows the records

    /// <summary>
    /// RFC 8915 §4.1.8: the port in the NTPv4 Port Negotiation record is the port the client
    /// must query; §4.1.8 makes 123 the assumption only when no such record was sent.
    ///
    /// The client is constructed with the server's real NTP port as its fallback, so a client
    /// that ignored the record would still succeed — and the probe would see nothing. Traffic
    /// at the probe is therefore evidence the record was read and obeyed, not merely parsed.
    /// </summary>
    [Test]
    public async Task PortNegotiation_RedirectsTheTimeQuery()
    {

        await StartRedirectedServer();

        if (probe is null || fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var result = await NtsQuery();

        Assert.Multiple(() => {

            Assert.That(probe.Observations.Count,
                        Is.GreaterThan(0),
                        $"nothing reached the advertised port {probe.Port}, so the client " +
                        $"queried the key-exchange host's own NTP port {fixture.NTPPort} and " +
                        $"ignored the Port Negotiation record");

            Assert.That(result.Success,
                        Is.True,
                        $"the redirected query should still succeed — the probe relays to the " +
                        $"real server: {result.ErrorMessage}");

        });

    }


    /// <summary>
    /// RFC 8915 §4.1.7: the same for the host. Here the advertised name is the loopback
    /// literal while the client was pointed at "localhost", so the two differ textually and
    /// the client has to resolve and use what it was told rather than reuse the connection it
    /// already has.
    ///
    /// Both records are in play at once, which is the shape of a real deployment: a key
    /// exchange front end handing the client to a time server elsewhere.
    /// </summary>
    [Test]
    public async Task ServerAndPortNegotiation_TogetherRedirectTheTimeQuery()
    {

        await StartRedirectedServer(advertisedHost: "127.0.0.1");

        if (probe is null || fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var result = await NtsQuery();

        Assert.Multiple(() => {

            Assert.That(probe.Observations.Count,
                        Is.GreaterThan(0),
                        $"nothing reached the advertised 127.0.0.1:{probe.Port}");

            Assert.That(result.Success,
                        Is.True,
                        $"the redirected query should still succeed: {result.ErrorMessage}");

        });

    }


    /// <summary>
    /// The sensitivity check for both tests above: with the server advertising its own port,
    /// the very same probe must stay silent and the real server must receive the query.
    ///
    /// Without this, a probe that somehow attracted traffic — a stray socket, a mistaken
    /// fallback — would make the redirect tests pass for the wrong reason.
    /// </summary>
    [Test]
    public async Task WithoutARedirect_TheQueryGoesToTheKeyExchangeHost()
    {

        probe    = UdpRelayProbe.StartObserving();

        fixture  = await NornServerFixture.StartAsync(
                             certificate: TestCertificate.Generate("redirect.test", [ "redirect.test" ]));

        var before = fixture.Server.Metrics.NTPRequestsReceived;
        var result = await NtsQuery();

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.True, result.ErrorMessage);

            Assert.That(fixture.Server.Metrics.NTPRequestsReceived,
                        Is.GreaterThan(before),
                        "the server itself should have been queried");

            Assert.That(probe.Observations.Count,
                        Is.Zero,
                        $"a probe on an unrelated port {probe.Port} received traffic, so the " +
                        $"redirect tests could pass without any redirect happening");

        });

    }

    #endregion

    #region an advertised server may not be quietly swapped out

    /// <summary>
    /// RFC 8915 §4.1.7 names the NTPv4 server "with which the client should associate and that
    /// will accept the supplied cookies", and it is the second half that settles what to do
    /// when that server cannot be reached: nobody else was said to accept these cookies.
    ///
    /// Falling back to the key-exchange host is the tempting move and the wrong one. In a real
    /// deployment the front end holds different cookie keys, so the query fails anyway — after
    /// the cookie has been spent and sent to a host that was never named. Here on loopback the
    /// two happen to be the same process, which is exactly why the fallback looks harmless in
    /// testing and is not in the field.
    ///
    /// The advertised name is in <c>.invalid</c>, which RFC 2606 guarantees will never resolve.
    /// The assertion is on the real server's own counter rather than on the client's error
    /// message, because a hijacking resolver can turn the latter into anything: whatever the
    /// client made of the name it was given, it must not have quietly queried the host it did
    /// the key exchange with.
    /// </summary>
    [Test]
    public async Task AnUnreachableAdvertisedServer_IsNotSilentlyReplacedByTheKeyExchangeHost()
    {

        fixture = await NornServerFixture.StartAsync(
                            certificate:       TestCertificate.Generate("redirect.test", [ "redirect.test" ]),
                            externalHostName:  "nts-redirect-target.invalid");

        var before = fixture.Server.Metrics.NTPRequestsReceived;
        var result = await NtsQuery();

        Assert.Multiple(() => {

            Assert.That(fixture.Server.Metrics.NTPRequestsReceived,
                        Is.EqualTo(before),
                        "the client was told to query another server and fell back to the " +
                        "key-exchange host instead");

            Assert.That(result.Success,
                        Is.False,
                        "a query to a server that cannot be resolved must be reported as a " +
                        "failure, not answered from somewhere else");

        });

    }

    #endregion

}
