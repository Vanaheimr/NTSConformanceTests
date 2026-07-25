using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTP;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Client.Tests;

/// <summary>
/// Which clock the client stamps its requests from, and reads its own arrival times with.
///
/// T1 and T4 of the RFC 5905 § 8 offset calculation are readings of the <em>client's</em> clock;
/// T2 and T3 are the server's. An offset assembled from two different local clocks is not an
/// offset at all, so both client-side reads have to come from the same place — and once that
/// place is a stated dependency, it can be checked.
///
/// The server here keeps ordinary time, and it echoes the client's transmit timestamp back in
/// the Originate field (§ 7.3), which makes the server a witness to what the client actually
/// put on the wire.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ClientClockTests
{

    private static readonly DateTimeOffset frozenInstant =
        new (2031, 3, 14, 9, 26, 53, TimeSpan.Zero);


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


    /// <summary>
    /// Run one NTS exchange with the client on a frozen clock and return the response, which
    /// carries both the server's echo of T1 and the client's own T4.
    /// </summary>
    private async Task<NTPPacket> QueryWithAFrozenClock()
    {

        if (fixture is null)
            throw new InvalidOperationException("the server fixture did not start");

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10),
                                               TestClock.FrozenAt(frozenInstant));

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success,
                    Is.True,
                    $"the NTS query failed: {queryResult.ErrorMessage}\n" +
                    $"server metrics: {fixture.Server.Metrics}");

        return queryResult.Response!;

    }


    /// <summary>
    /// The transmit timestamp the client sent is its own clock's reading — read back out of the
    /// server's Originate echo, so this is what was on the wire rather than what the client
    /// reports about itself.
    /// </summary>
    [Test]
    public async Task RequestTimestamp_ComesFromTheClientsClock()
    {

        var response = await QueryWithAFrozenClock();

        Assert.That(RawNtpTimestamp.ToDateTime(response.OriginateTimestamp),
                    Is.EqualTo(frozenInstant.UtcDateTime),
                    "the server echoes the client's transmit timestamp, which should be the " +
                    "client's own clock reading");

    }


    /// <summary>
    /// T4 — when the client recorded the response as arriving — comes from the same clock. If it
    /// came from the ambient one instead, the two ends of the measurement would be years apart
    /// here and merely inconsistent in production.
    /// </summary>
    [Test]
    public async Task ArrivalTimestamp_ComesFromTheSameClock()
    {

        var response = await QueryWithAFrozenClock();

        Assert.That(response.DestinationTimestamp, Is.Not.Null,
                    "the client should record when the response arrived");

        Assert.That(RawNtpTimestamp.ToDateTime(response.DestinationTimestamp!.Value),
                    Is.EqualTo(frozenInstant.UtcDateTime),
                    "T4 must be read from the same clock as T1");

    }


    /// <summary>
    /// A client this wrong still completes the exchange — which is the point of the protocol, and
    /// the reason a client must never refuse a server for disagreeing with it. What the resulting
    /// measurement should come out at, for displacements of every sign and size, is
    /// <see cref="ClockDisplacementTests"/>.
    /// </summary>
    [Test]
    public async Task AClockYearsOff_DoesNotPreventTheExchange()
    {

        var response = await QueryWithAFrozenClock();

        Assert.That(response.ClockOffset,
                    Is.Not.Null,
                    "the client should still produce a measurement against a server it disagrees with");

    }

}
