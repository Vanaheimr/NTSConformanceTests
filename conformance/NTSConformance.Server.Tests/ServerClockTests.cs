using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Server.Tests;

/// <summary>
/// Which clock the server actually reads.
///
/// A time server's clock is its entire output, so it should be a stated dependency rather than
/// an ambient one. Everything time-dependent — the response timestamps, master key rotation,
/// cookie timestamps, generated certificate validity — has to come from the same clock: the
/// cookie's timestamp is checked against the master key's validity window when it comes back, so
/// a component reading a different clock than the key rotation does would mint cookies that are
/// rejected the moment they are used.
///
/// These tests inject a clock and check what reaches the wire. A substituted clock is also the
/// only way to assert an exact reported time — against the real clock the value has moved on by
/// the time the assertion runs.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ServerClockTests
{

    private static readonly DateTimeOffset frozenInstant =
        new (2030, 6, 1, 12, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// The transmit timestamp is the injected clock's reading, exactly. Frozen, so this is an
    /// equality rather than a tolerance: any component still reading the ambient clock would
    /// report today instead of 2030.
    /// </summary>
    [Test]
    public async Task ReportedTime_IsTheInjectedClocksTime()
    {

        await using var fixture = await NornServerFixture.StartAsync(
                                            timeProvider: TestClock.FrozenAt(frozenInstant)
                                        );

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(),
                                               "127.0.0.1",
                                               fixture.NTPPort);

        Assert.Multiple(() => {

            Assert.That(RawNtpTimestamp.ToDateTime(response.TransmitTimestamp),
                        Is.EqualTo(frozenInstant.UtcDateTime),
                        "the transmit timestamp should be the injected clock's reading");

            Assert.That(RawNtpTimestamp.ToDateTime(response.ReceiveTimestamp),
                        Is.EqualTo(frozenInstant.UtcDateTime),
                        "and so should the receive timestamp");

            // RFC 5905 § 7.3: when the clock was last set. The server records that on startup,
            // which under this clock is also 2030.
            Assert.That(RawNtpTimestamp.ToDateTime(response.ReferenceTimestamp),
                        Is.EqualTo(frozenInstant.UtcDateTime),
                        "the reference timestamp should come from the same clock");

        });

    }


    /// <summary>
    /// A clock that never advances has no observable granularity, and the server says so with a
    /// deliberately coarse figure instead of inventing a precise one — a claim of precision the
    /// clock cannot support is exactly what the Precision field must not carry.
    /// </summary>
    [Test]
    public async Task AClockThatNeverAdvances_IsReportedAsCoarse()
    {

        await using var fixture = await NornServerFixture.StartAsync(
                                            timeProvider: TestClock.FrozenAt(frozenInstant)
                                        );

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(),
                                               "127.0.0.1",
                                               fixture.NTPPort);

        Assert.Multiple(() => {

            Assert.That(fixture.Server.ClockResolution,
                        Is.EqualTo(NTSServer.UnknownClockResolution),
                        "an unmeasurable clock's resolution is unknown, not fine");

            // 2^-10 s ≈ 0.98 ms, the largest exponent that does not overstate a 1 ms clock.
            Assert.That(response.Precision,
                        Is.EqualTo((SByte) (-10)),
                        "the precision exponent should describe the reported resolution");

        });

    }


    /// <summary>
    /// An operator who knows the clock better than it can be measured can say so, and that
    /// figure is what reaches the wire. 2^-20 s ≈ 0.95 µs.
    /// </summary>
    [Test]
    public async Task AStatedClockResolution_IsWhatIsReported()
    {

        await using var fixture = await NornServerFixture.StartAsync(
                                            clockResolution: TimeSpan.FromMicroseconds(1)
                                        );

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(),
                                               "127.0.0.1",
                                               fixture.NTPPort);

        Assert.Multiple(() => {

            Assert.That(fixture.Server.ClockResolution,
                        Is.EqualTo(TimeSpan.FromMicroseconds(1)));

            Assert.That(response.Precision,
                        Is.EqualTo((SByte) (-20)));

        });

    }


    /// <summary>
    /// The real clock's resolution is measured, not assumed — and it must be finer than a
    /// millisecond on any machine worth serving time from, which also proves the measurement is
    /// not silently falling back to the "unknown" figure.
    /// </summary>
    [Test]
    public async Task TheRealClocksResolution_IsMeasured()
    {

        await using var fixture = await NornServerFixture.StartAsync();

        Assert.That(fixture.Server.ClockResolution,
                    Is.GreaterThan(TimeSpan.Zero).And.LessThan(NTSServer.UnknownClockResolution),
                    $"the system clock's resolution should be measurable and sub-millisecond, " +
                    $"but was measured as {NornServerFixture.DescribeClockResolution()}");

    }


    /// <summary>
    /// A full NTS exchange on a displaced clock.
    ///
    /// This is what pins the clock down as one dependency rather than several. The cookie handed
    /// out during NTS-KE is timestamped from the server's clock and checked against a master key
    /// whose validity window comes from the same clock; if either read the ambient clock instead,
    /// the two would be an hour apart and the cookie would be refused with an NTS NAK on first
    /// use — while every test on an undisplaced clock still passed.
    /// </summary>
    [Test]
    public async Task ADisplacedClock_StillCompletesAnNtsExchange()
    {

        var displacement = TimeSpan.FromHours(1);

        await using var fixture = await NornServerFixture.StartAsync(
                                            timeProvider: TestClock.ShiftedBy(displacement)
                                        );

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success,
                    Is.True,
                    $"the NTS query failed: {queryResult.ErrorMessage}\n" +
                    $"server metrics: {fixture.Server.Metrics}");

        var transmitTimestamp = queryResult.Response!.TransmitTimestamp;

        Assert.That(transmitTimestamp, Is.Not.Null.And.Not.EqualTo(0UL));

        // And the time really is displaced, so the exchange succeeded on the injected clock
        // rather than because the injection was ignored.
        Assert.That(RawNtpTimestamp.ToDateTime(transmitTimestamp!.Value),
                    Is.EqualTo(DateTime.UtcNow + displacement).Within(TimeSpan.FromMinutes(1)),
                    "the server should be reporting the displaced clock");

    }

}
