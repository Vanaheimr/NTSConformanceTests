using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.Server.Tests;

/// <summary>
/// RFC 8915 §5.7 cookie replenishment.
///
/// "The number of NTS Cookie extension fields included SHOULD be equal to, and MUST NOT
/// exceed, one plus the number of valid NTS Cookie Placeholder extension fields included
/// in the request."
///
/// This is what keeps a client's cookie pool from draining: it spends one cookie per
/// request, so without a replacement plus one per placeholder it would have to re-run the
/// TLS handshake every few queries.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class CookieReplenishmentTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync();


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    private static Int32 CountOf(NTPPacket packet, ExtensionTypes extensionType)
        => packet.Extensions.Count(extension => extension.Type == extensionType);


    /// <summary>
    /// The response must carry exactly one cookie per spent cookie plus one per valid
    /// placeholder — no fewer (the pool drains) and no more (a request could be amplified
    /// into a much larger response).
    /// </summary>
    [Test]
    public async Task ResponseCookieCount_MatchesOnePlusPlaceholders()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var client       = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult  = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var queryResult  = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                 Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success, Is.True, $"the NTS query failed: {queryResult.ErrorMessage}");

        var response     = queryResult.Response!;
        var request      = response.Request;

        Assert.That(request, Is.Not.Null, "the response should carry the request it answered");

        var placeholders = CountOf(request!, ExtensionTypes.NTSCookiePlaceholder);
        var cookies      = CountOf(response,  ExtensionTypes.NTSCookie);

        Assert.That(cookies,
                    Is.EqualTo(1 + placeholders),
                    $"the request carried {placeholders} placeholder(s), so the response should carry " +
                    $"{1 + placeholders} cookie(s) but carried {cookies}.\n" +
                    $"request extensions:  {String.Join(", ", request!.Extensions.Select(e => $"{e.Type}({e.Value.Length})"))}\n" +
                    $"response extensions: {String.Join(", ", response.Extensions.Select(e => $"{e.Type}({e.Value.Length})"))}");

    }


    /// <summary>
    /// Across a run of queries the pool must not shrink. With replenishment working the
    /// client never has to re-run NTS-KE mid-session; without it, the count falls by one
    /// per query.
    /// </summary>
    [Test]
    public async Task CookiePool_DoesNotDrainAcrossRepeatedQueries()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var remaining   = new List<Int32>();

        for (var i = 0; i < 6; i++)
        {

            var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                     Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(queryResult.Success, Is.True, $"query {i + 1} failed: {queryResult.ErrorMessage}");

            remaining.Add(queryResult.RemainingCookiesAfterQuery);

        }

        Assert.That(remaining[^1],
                    Is.GreaterThanOrEqualTo(remaining[0]),
                    $"the cookie pool shrank over six queries: {String.Join(" -> ", remaining)}");

    }

}
