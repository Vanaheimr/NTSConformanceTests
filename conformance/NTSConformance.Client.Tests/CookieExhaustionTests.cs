using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSConformance.Client.Tests;

/// <summary>
/// RFC 8915 § 5.7: "If the client does not have any cookies that it has not already sent, it
/// SHOULD initiate a rerun of the NTS-KE protocol."
///
/// <para>
/// Nothing else can recover from an empty pool. A cookie arrives only in answer to a request, and
/// a request cannot be made without one — so a client that runs dry stays dry however long it
/// waits, and the only way out is a new key exchange.
/// </para>
/// <para>
/// It empties when requests go unanswered: each one spends a cookie and brings none back. That is
/// what these tests do, by pointing the client at a socket that swallows datagrams and then
/// letting it through again — a network outage and its end, which is the situation § 5.7 is
/// written for rather than a contrived one.
/// </para>
/// <para>
/// The same section attaches a condition to doing it automatically: an implementation "must
/// implement rate limiting to avoid rapid retry loops". A key exchange is a TLS handshake, and a
/// server that is answering nothing is exactly the one a client would otherwise ask fastest.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class CookieExhaustionTests
{

    /// <summary>
    /// A pool of two, so two swallowed queries empty it and the test does not spend eight
    /// timeouts doing it.
    /// </summary>
    private static NTSCookiePoolPolicy SmallPool(Boolean   Renegotiate    = true,
                                                 TimeSpan? MinimumInterval = null)

        => new () {
               MaxCookiePoolSize             = 2,
               TargetCookieCount             = 2,
               MaxPlaceholders               = 0,
               RenegotiateWhenExhausted      = Renegotiate,
               MinimumRenegotiationInterval  = MinimumInterval ?? TimeSpan.Zero
           };


    /// <summary>
    /// Spend every cookie against a socket that answers nothing, and stop the moment the last
    /// one is gone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stopping exactly there matters: the query <em>after</em> the pool empties is the one under
    /// test, and issuing it here would spend the renegotiation the test is about to look for.
    /// </para>
    /// <para>
    /// The loop cannot be guarded on the count beforehand either, because the pool is empty until
    /// the first query fills it. A key exchange leaves its cookies in the response, and
    /// <c>TryTakeCookie</c> seeds the pool from there the first time it is handed one — so a
    /// freshly negotiated client reports zero available cookies and is not out of them at all.
    /// Guarding on that count skips the loop entirely and leaves an assertion that the pool is
    /// empty passing for the wrong reason, which is how this helper was written the first time.
    /// </para>
    /// </remarks>
    private static async Task DrainThePool(NTSClient client, NTSKE_Response keys)
    {

        for (var attempt = 1; attempt <= 8; attempt++)
        {

            await client.QueryTime(NTSKEResponse: keys, Timeout: TimeSpan.FromSeconds(1));

            if (client.AvailableCookieCount == 0)
                return;

        }

        Assert.Fail($"the pool still holds {client.AvailableCookieCount} cookies after eight " +
                    $"unanswered queries, so nothing below is testing what it says");

    }


    /// <summary>
    /// An empty pool is refilled by a key exchange the client runs itself, and the query goes
    /// through.
    /// </summary>
    /// <remarks>
    /// The whole of § 5.7's sentence in one test: dry pool, network back, time measured. Note
    /// what is <em>not</em> passed to the last query — the caller still hands over the original
    /// key exchange, and the client has to notice that its cookies no longer belong to it.
    /// </remarks>
    [Test]
    public async Task AnEmptyPool_IsRefilledByTheClientItself()
    {

        using var blackHole = UdpRelayProbe.StartObserving();

        await using var fixture = await NornServerFixture.StartAsync(advertisedNTPPort: blackHole.Port);

        var client = fixture.CreateClient(TimeSpan.FromSeconds(10), cookiePoolPolicy: SmallPool());
        var keys   = await client.GetNTSKERecords();

        Assert.That(keys.Success, Is.True, keys.ErrorMessage);

        await DrainThePool(client, keys.Response!);

        Assert.That(client.AutomaticKeyExchanges, Is.EqualTo(0),
                    "nothing has been renegotiated yet — the queries above failed on the network, " +
                    "not on the pool");

        // The outage ends.
        blackHole.RelayTo(fixture.NTPPort);

        var recovered = await client.QueryTime(NTSKEResponse: keys.Response!,
                                               Timeout:       TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {

            Assert.That(recovered.Success, Is.True,
                        $"an empty pool has to be recoverable: {recovered.ErrorMessage}");

            Assert.That(client.AutomaticKeyExchanges, Is.EqualTo(1),
                        "by exactly one key exchange, which the client started");

            Assert.That(client.LastNTSKEResponse, Is.Not.SameAs(keys.Response),
                        "and the new keys are on offer to the caller, whose own copy is now stale");

        });

    }


    /// <summary>
    /// Turned off, the client fails as it always did rather than renegotiating behind the
    /// caller's back.
    /// </summary>
    /// <remarks>
    /// A caller that manages its own key exchanges — the monitoring engine is one, refreshing on
    /// a timer and on a low pool — may not want a query to open a TLS connection. The failure it
    /// gets instead has to be the specific one, so it can tell an empty pool from a lost packet.
    /// </remarks>
    [Test]
    public async Task WithRenegotiationOff_AnEmptyPoolIsAnError()
    {

        using var blackHole = UdpRelayProbe.StartObserving();

        await using var fixture = await NornServerFixture.StartAsync(advertisedNTPPort: blackHole.Port);

        var client = fixture.CreateClient(TimeSpan.FromSeconds(10),
                                          cookiePoolPolicy: SmallPool(Renegotiate: false));

        var keys   = await client.GetNTSKERecords();
        Assert.That(keys.Success, Is.True, keys.ErrorMessage);

        await DrainThePool(client, keys.Response!);

        blackHole.RelayTo(fixture.NTPPort);

        var result = await client.QueryTime(NTSKEResponse: keys.Response!,
                                            Timeout:       TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.False);

            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.Cookie),
                        $"an empty pool is its own kind of failure: {result.ErrorMessage}");

            Assert.That(client.AutomaticKeyExchanges, Is.EqualTo(0),
                        "and nothing was renegotiated");

        });

    }


    /// <summary>
    /// The rate limit holds: a second empty pool inside the interval does not buy a second
    /// handshake.
    /// </summary>
    /// <remarks>
    /// <para>
    /// § 5.7 on automatic reruns: "must implement rate limiting to avoid rapid retry loops". The
    /// loop it guards against is not hypothetical — a server that answers nothing empties the
    /// pool as fast as the client can query, and every empty pool asks for a TLS handshake.
    /// </para>
    /// <para>
    /// The network stays down here, so the pool the renegotiation just refilled empties again
    /// immediately. With an interval of an hour, that second emptying must be answered with a
    /// refusal rather than a handshake.
    /// </para>
    /// </remarks>
    [Test]
    public async Task TheRateLimit_StopsASecondHandshake()
    {

        using var blackHole = UdpRelayProbe.StartObserving();

        await using var fixture = await NornServerFixture.StartAsync(advertisedNTPPort: blackHole.Port);

        var client = fixture.CreateClient(TimeSpan.FromSeconds(10),
                                          cookiePoolPolicy: SmallPool(MinimumInterval: TimeSpan.FromHours(1)));

        var keys   = await client.GetNTSKERecords();
        Assert.That(keys.Success, Is.True, keys.ErrorMessage);

        await DrainThePool(client, keys.Response!);

        // First empty pool: one handshake, and the query still fails because the network is down.
        await client.QueryTime(NTSKEResponse: keys.Response!, Timeout: TimeSpan.FromSeconds(1));

        Assert.That(client.AutomaticKeyExchanges, Is.EqualTo(1),
                    "the first empty pool is answered immediately — the limit is between reruns");

        // Drain the refilled pool and empty it again.
        await DrainThePool(client, keys.Response!);

        var second = await client.QueryTime(NTSKEResponse: keys.Response!, Timeout: TimeSpan.FromSeconds(1));

        Assert.Multiple(() => {

            Assert.That(client.AutomaticKeyExchanges, Is.EqualTo(1),
                        "the second one is inside the interval and must be refused");

            Assert.That(second.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.Cookie),
                        $"and reported as the empty pool it is: {second.ErrorMessage}");

        });

    }


    /// <summary>
    /// The monitoring engine's own rule: a cache entry with one cookie left already needs a
    /// refresh.
    /// </summary>
    /// <remarks>
    /// Its answer to § 5.7 is to pre-empt rather than recover — it refreshes the key exchange
    /// while a cookie is still in hand, so a round never starts with nothing. That only leaves
    /// the client's own rerun for the case a whole round of packets is lost, which is why both
    /// exist.
    /// </remarks>
    [TestCase(0, true,  "an empty pool")]
    [TestCase(1, true,  "one cookie is the reserve, not a supply")]
    [TestCase(2, false, "two is enough to start a round")]
    [TestCase(8, false, "a full pool")]
    public void TheEngineRefreshes_BeforeTheLastCookieIsSpent(Byte     RemainingCookies,
                                                              Boolean  ExpectedNeedsRefresh,
                                                              String   Because)
    {

        var clock = TestClock.FrozenAt(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));

        var state = new CachedNTSKEState {
                        LastRefreshed     = clock.GetUtcNow(),
                        RemainingCookies  = RemainingCookies
                    };

        Assert.That(state.NeedsRefresh(TimeSpan.FromHours(1), clock),
                    Is.EqualTo(ExpectedNeedsRefresh),
                    Because);

    }

}
