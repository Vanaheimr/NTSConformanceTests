using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What an NTS exchange measures when the two clocks disagree — which is the only thing the
/// protocol is for.
///
/// Each test displaces the server's clock, the client's, or both by a random amount and then
/// checks that the RFC 5905 § 8 arithmetic recovers exactly that displacement. Randomised on
/// purpose: a fixed offset can be passed by code that happens to be right for one value, and the
/// interesting failures here are sign errors and cases where a displacement leaks into the wrong
/// term. NUnit records the seed, so a failure is reproducible, and every message carries the
/// drawn values.
///
/// Two invariants matter more than the offsets themselves:
///
/// <list type="bullet">
/// <item>The round-trip delay must stay small no matter how wrong either clock is. Both
/// displacements cancel in δ = (T4-T1) - (T3-T2) — T1 and T4 are the client's, T2 and T3 the
/// server's — so a displacement showing up in the delay would mean a timestamp had been read
/// from the wrong clock.</item>
/// <item>Only the <em>difference</em> is observable. Two clocks displaced identically are, to
/// NTP, two clocks in agreement.</item>
/// </list>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ClockDisplacementTests
{

    /// <summary>
    /// How far the measured offset may sit from the injected displacement.
    ///
    /// The error is really bounded by path asymmetry — half the difference between the outbound
    /// and return legs — which on loopback is well under a millisecond. A quarter second leaves
    /// room for a scheduling stall on a loaded machine while still being a thousand times finer
    /// than the displacements being recovered.
    /// </summary>
    private static readonly TimeSpan tolerance = TimeSpan.FromMilliseconds(250);

    /// <summary>Loopback plus AEAD work; nowhere near a displacement even at the low end.</summary>
    private static readonly TimeSpan maxPlausibleDelay = TimeSpan.FromSeconds(2);


    /// <summary>What one exchange between two displaced clocks yielded.</summary>
    /// <param name="Offset">θ, computed here from the four wire timestamps.</param>
    /// <param name="Delay">δ, likewise.</param>
    /// <param name="NornOffset">Norn's own θ, for comparison.</param>
    private sealed record Measurement(TimeSpan   Offset,
                                      TimeSpan   Delay,
                                      TimeSpan?  NornOffset);


    /// <summary>
    /// Run one NTS exchange with each end on its own displaced clock, and compute θ and δ from
    /// the wire timestamps using this suite's own decoder.
    /// </summary>
    private static async Task<Measurement> Measure(TimeSpan serverDisplacement,
                                                   TimeSpan clientDisplacement)
    {

        await using var fixture = await NornServerFixture.StartAsync(
                                            timeProvider: TestClock.ShiftedBy(serverDisplacement)
                                        );

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10),
                                               TestClock.ShiftedBy(clientDisplacement));

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success,
                    Is.True,
                    $"NTS-KE failed with the server {serverDisplacement.TotalSeconds:F3} s and the " +
                    $"client {clientDisplacement.TotalSeconds:F3} s off: {ntsKeResult.ErrorMessage}");

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success,
                    Is.True,
                    $"the NTS query failed with the server {serverDisplacement.TotalSeconds:F3} s and " +
                    $"the client {clientDisplacement.TotalSeconds:F3} s off: {queryResult.ErrorMessage}\n" +
                    $"server metrics: {fixture.Server.Metrics}");

        var response = queryResult.Response!;

        Assert.That(response.DestinationTimestamp, Is.Not.Null, "the client must record T4");

        var t1       = RawNtpTimestamp.ToDateTime(response.OriginateTimestamp);          // client sent
        var t2       = RawNtpTimestamp.ToDateTime(response.ReceiveTimestamp);            // server received
        var t3       = RawNtpTimestamp.ToDateTime(response.TransmitTimestamp ?? 0);      // server sent
        var t4       = RawNtpTimestamp.ToDateTime(response.DestinationTimestamp!.Value); // client received

        return new Measurement(
                   Offset:      TimeSpan.FromTicks(((t2 - t1) + (t3 - t4)).Ticks / 2),
                   Delay:       (t4 - t1) - (t3 - t2),
                   NornOffset:  response.ClockOffset
               );

    }


    /// <summary>
    /// The invariants that hold whatever the two clocks say: the delay is a network measurement
    /// and must not absorb either displacement, and Norn's own offset must agree with the value
    /// computed here from the same four timestamps.
    /// </summary>
    private static void AssertTheDelayAndNornAgree(Measurement measurement, String context)
    {

        Assert.That(measurement.Delay,
                    Is.GreaterThanOrEqualTo(TimeSpan.Zero).And.LessThan(maxPlausibleDelay),
                    $"the round-trip delay must stay a network measurement, but was " +
                    $"{measurement.Delay.TotalSeconds:F3} s — a displacement has leaked into it ({context})");

        Assert.That(measurement.NornOffset,
                    Is.EqualTo(measurement.Offset),
                    $"Norn's own offset should equal the one computed here from the same wire " +
                    $"timestamps ({context})");

    }


    /// <summary>
    /// Case 1 — the server's clock is wrong, the client's is right. The client should measure the
    /// server as being off by exactly that much, sign included.
    /// </summary>
    [Test]
    public async Task ADisplacedServer_IsMeasuredAsDisplacedByThatMuch(

        [Random(-3600.0, 3600.0, 3)] Double serverOffsetSeconds)

    {

        var displacement = TimeSpan.FromSeconds(serverOffsetSeconds);
        var context      = $"server {displacement.TotalSeconds:F3} s off, client correct";

        var measurement  = await Measure(displacement, TimeSpan.Zero);

        Assert.That(measurement.Offset,
                    Is.EqualTo(displacement).Within(tolerance),
                    $"a server {displacement.TotalSeconds:F3} s off should be measured as " +
                    $"{displacement.TotalSeconds:F3} s off, but came out at " +
                    $"{measurement.Offset.TotalSeconds:F3} s");

        AssertTheDelayAndNornAgree(measurement, context);

    }


    /// <summary>
    /// Case 2 — the client's clock is wrong, the server's is right. The offset is the correction
    /// the client would apply to itself, so it is the negation of the client's own error: a client
    /// running fast measures a negative offset.
    /// </summary>
    [Test]
    public async Task ADisplacedClient_MeasuresItsOwnErrorNegated(

        [Random(-3600.0, 3600.0, 3)] Double clientOffsetSeconds)

    {

        var displacement = TimeSpan.FromSeconds(clientOffsetSeconds);
        var context      = $"client {displacement.TotalSeconds:F3} s off, server correct";

        var measurement  = await Measure(TimeSpan.Zero, displacement);

        Assert.That(measurement.Offset,
                    Is.EqualTo(-displacement).Within(tolerance),
                    $"a client {displacement.TotalSeconds:F3} s off should measure an offset of " +
                    $"{-displacement.TotalSeconds:F3} s — the correction back to the server — but " +
                    $"came out at {measurement.Offset.TotalSeconds:F3} s");

        AssertTheDelayAndNornAgree(measurement, context);

    }


    /// <summary>
    /// Case 3 — both clocks are wrong, independently. Only the difference between them is
    /// observable, so the offset is the server's error minus the client's. This is the case that
    /// catches a displacement applied to the wrong term: with one clock displaced, several wrong
    /// formulas still produce the right number.
    /// </summary>
    [Test]
    public async Task TwoDisplacedClocks_MeasureTheDifferenceBetweenThem(

        [Random(-3600.0, 3600.0, 2)] Double serverOffsetSeconds,
        [Random(-3600.0, 3600.0, 2)] Double clientOffsetSeconds)

    {

        var serverDisplacement = TimeSpan.FromSeconds(serverOffsetSeconds);
        var clientDisplacement = TimeSpan.FromSeconds(clientOffsetSeconds);
        var expected           = serverDisplacement - clientDisplacement;

        var context            = $"server {serverDisplacement.TotalSeconds:F3} s off, " +
                                 $"client {clientDisplacement.TotalSeconds:F3} s off";

        var measurement        = await Measure(serverDisplacement, clientDisplacement);

        Assert.That(measurement.Offset,
                    Is.EqualTo(expected).Within(tolerance),
                    $"with the server {serverDisplacement.TotalSeconds:F3} s off and the client " +
                    $"{clientDisplacement.TotalSeconds:F3} s off, the measured offset should be the " +
                    $"difference, {expected.TotalSeconds:F3} s, but came out at " +
                    $"{measurement.Offset.TotalSeconds:F3} s");

        AssertTheDelayAndNornAgree(measurement, context);

    }


    /// <summary>
    /// The limiting case of the one above: two clocks wrong by the same amount are, to NTP, two
    /// clocks that agree. Worth stating on its own — it is the clearest statement of what the
    /// measurement can and cannot see, and it fails loudly if either end ever reads a clock that
    /// is not its own.
    /// </summary>
    [Test]
    public async Task IdenticallyDisplacedClocks_AgreeWithEachOther(

        [Random(-3600.0, 3600.0, 2)] Double offsetSeconds)

    {

        var displacement = TimeSpan.FromSeconds(offsetSeconds);
        var context      = $"both clocks {displacement.TotalSeconds:F3} s off";

        var measurement  = await Measure(displacement, displacement);

        Assert.That(measurement.Offset,
                    Is.EqualTo(TimeSpan.Zero).Within(tolerance),
                    $"two clocks both {displacement.TotalSeconds:F3} s off should measure no offset " +
                    $"between them, but the measurement came out at " +
                    $"{measurement.Offset.TotalSeconds:F3} s");

        AssertTheDelayAndNornAgree(measurement, context);

    }

}
