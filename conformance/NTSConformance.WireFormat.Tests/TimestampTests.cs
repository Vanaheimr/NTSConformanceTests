using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.WireFormat.Tests;

/// <summary>
/// RFC 5905 §6 timestamps: 32 bits of seconds since the 1900 prime epoch plus a 32-bit
/// binary fraction, and the era arithmetic that keeps them meaningful past 2036.
/// </summary>
[TestFixture]
public class TimestampTests
{

    #region Round-trip within era 0

    /// <summary>
    /// Well-known instants must convert to the documented second counts.
    /// The 1970 offset (2208988800) is the classic NTP-to-Unix constant.
    /// </summary>
    [Test]
    public void KnownInstants_HaveTheExpectedSecondCounts()
    {

        Assert.Multiple(() => {

            Assert.That(RawNtpTimestamp.Seconds(RawNtpTimestamp.FromDateTime(new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc))),
                        Is.EqualTo(0U), "the prime epoch is second zero");

            Assert.That(RawNtpTimestamp.Seconds(RawNtpTimestamp.FromDateTime(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc))),
                        Is.EqualTo(2208988800U), "the Unix epoch is 2208988800 seconds into era 0");

            Assert.That(RawNtpTimestamp.Seconds(RawNtpTimestamp.FromDateTime(new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc))),
                        Is.EqualTo(3913056000U), "2024-01-01");

        });

    }


    /// <summary>
    /// Norn and the reference must agree on the conversion, to within the format's precision.
    /// </summary>
    [Test]
    public void NornAgreesWithReference_WithinEra0()
    {

        foreach (var instant in new[] {
                     new DateTime(1970,  1,  1,  0,  0,  0, DateTimeKind.Utc),
                     new DateTime(2000,  1,  1,  0,  0,  0, DateTimeKind.Utc),
                     new DateTime(2024,  6, 15, 12, 30, 45, DateTimeKind.Utc),
                     new DateTime(2036,  2,  7,  6, 28, 15, DateTimeKind.Utc)
                 })
        {

            var reference = RawNtpTimestamp.FromDateTime(instant);
            var norn      = NTPPacket.GetCurrentNTPTimestamp(instant);

            Assert.That(RawNtpTimestamp.Seconds(norn),
                        Is.EqualTo(RawNtpTimestamp.Seconds(reference)),
                        $"the seconds field for {instant:O}");

            // Exact, not approximate: both sides now compute the fraction in integers. Routing
            // it through a Double, as Norn used to, threw away everything below about a
            // microsecond in a format that resolves to roughly 233 ps.
            Assert.That(RawNtpTimestamp.Fraction(norn),
                        Is.EqualTo(RawNtpTimestamp.Fraction(reference)),
                        $"the fraction for {instant:O}");

        }

    }


    /// <summary>
    /// The fraction must actually carry sub-second information — a timestamp that only
    /// ever encodes whole seconds would be useless for time transfer.
    /// </summary>
    [Test]
    public void Fraction_EncodesSubSecondPrecision()
    {

        var baseInstant = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        Assert.Multiple(() => {

            Assert.That(RawNtpTimestamp.Fraction(RawNtpTimestamp.FromDateTime(baseInstant)),
                        Is.EqualTo(0U), "a whole second has a zero fraction");

            Assert.That(RawNtpTimestamp.Fraction(RawNtpTimestamp.FromDateTime(baseInstant.AddMilliseconds(500))),
                        Is.EqualTo(0x80000000U), "half a second is the top fraction bit");

            Assert.That(RawNtpTimestamp.Fraction(RawNtpTimestamp.FromDateTime(baseInstant.AddMilliseconds(250))),
                        Is.EqualTo(0x40000000U), "a quarter second");

        });

    }


    /// <summary>
    /// Converting to a timestamp and back must be lossless at 100 ns granularity.
    /// </summary>
    [Test]
    public void ReferenceRoundTrip_IsLossless()
    {

        foreach (var instant in new[] {
                     new DateTime(1900, 1, 1,  0,  0,  0,   0, DateTimeKind.Utc),
                     new DateTime(1970, 1, 1,  0,  0,  0, 123, DateTimeKind.Utc),
                     new DateTime(2024, 7, 4, 13, 45, 22, 456, DateTimeKind.Utc)
                 })
        {

            var recovered = RawNtpTimestamp.ToDateTime(RawNtpTimestamp.FromDateTime(instant));

            Assert.That((recovered - instant).Duration(), Is.LessThan(TimeSpan.FromTicks(10)),
                        $"{instant:O} should survive the round trip");

        }

    }

    #endregion

    #region Era handling

    /// <summary>
    /// The seconds field wraps at 2036-02-07T06:28:16Z. The reference resolves this with an
    /// explicit era, so second-count 0 can mean either 1900 or 2036.
    /// </summary>
    [Test]
    public void Reference_DistinguishesEras()
    {

        var justBefore = new DateTime(2036, 2, 7, 6, 28, 15, DateTimeKind.Utc);
        var justAfter  = new DateTime(2036, 2, 7, 6, 28, 17, DateTimeKind.Utc);

        Assert.Multiple(() => {

            Assert.That(RawNtpTimestamp.EraFor(justBefore), Is.EqualTo(0), "1900-2036 is era 0");
            Assert.That(RawNtpTimestamp.EraFor(justAfter),  Is.EqualTo(1), "2036-2172 is era 1");

            Assert.That(RawNtpTimestamp.Seconds(RawNtpTimestamp.FromDateTime(justBefore)),
                        Is.EqualTo(4294967295U), "the last second of era 0 is 2^32-1");

            Assert.That(RawNtpTimestamp.Seconds(RawNtpTimestamp.FromDateTime(justAfter, era: 1)),
                        Is.EqualTo(1U), "one second into era 1 wraps back to a small count");

            Assert.That(RawNtpTimestamp.ToDateTime(RawNtpTimestamp.FromDateTime(justAfter, era: 1), era: 1),
                        Is.EqualTo(justAfter),
                        "decoding with the era restores the 2036 instant");

            Assert.That(RawNtpTimestamp.ToDateTime(RawNtpTimestamp.FromDateTime(justAfter, era: 1), era: 0),
                        Is.EqualTo(RawNtpTimestamp.Epoch.AddSeconds(1)),
                        "decoding the same octets as era 0 lands in 1900 — which is the ambiguity the era resolves");

        });

    }


    /// <summary>
    /// RFC 5905 § 6: the wire carries only the low 32 bits of the second count, so the
    /// era has to be recovered from context. Norn used to add that count to 1900
    /// unconditionally, decoding every post-2036 timestamp as a date in the early 1900s; it now
    /// picks the era that places the timestamp nearest the expected instant.
    ///
    /// Not a live defect until 2036-02-07, but the ambiguity is real today and the RFC
    /// addresses it explicitly.
    /// </summary>
    [Test]
    public void Norn_HandlesTheEra2036Rollover()
    {

        var afterRollover  = new DateTime(2036, 6, 1, 12, 0, 0, DateTimeKind.Utc);

        // The on-wire seconds count such a clock would send, i.e. era 1.
        var wireTimestamp  = RawNtpTimestamp.FromDateTime(afterRollover, era: 1);

        var nornDecoded    = NTPPacket.NTPTimestampToDateTime(wireTimestamp);

        Assert.That(nornDecoded.Year,
                    Is.EqualTo(2036),
                    $"a timestamp generated at {afterRollover:O} in era 1 carries the seconds count " +
                    $"{RawNtpTimestamp.Seconds(wireTimestamp)}, which Norn decodes as {nornDecoded:O}. " +
                    "RFC 5905 §6 requires era disambiguation.");

    }

    #endregion


    #region Era resolution with a clock reset to 1970

    // The clock the era is resolved against, the time the server sent, and what the case is about.
    private static readonly Object[] ResetClockCases = [

        new Object[] { new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2026, 11, 27, 12, 0, 0, DateTimeKind.Utc), "clock at 1970, server in era 0 (today)"                                   },
        new Object[] { new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2036,  6,  1, 12, 0, 0, DateTimeKind.Utc), "clock at 1970, server just into era 1, still nearer 1970 than 1900"       },
        new Object[] { new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2038,  6,  1, 12, 0, 0, DateTimeKind.Utc), "clock at 1970, server past 2038-01-19, its era-0 reading (1902) is nearer" },
        new Object[] { new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2040,  1,  1,  0, 0, 0, DateTimeKind.Utc), "clock at 1970, server in 2040"                                            },
        new Object[] { new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2060,  1,  1,  0, 0, 0, DateTimeKind.Utc), "clock at 1970, server in 2060"                                            },
        new Object[] { new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2040,  1,  1,  0, 0, 0, DateTimeKind.Utc), "clock at 2000, server in 2040"                                            }

    ];


    /// <summary>
    /// RFC 5905 § 6 leaves the era to context, and Norn's context is a clock: it picks the era
    /// that puts a timestamp nearest to it. That is right while the clock is roughly right, and
    /// wrong for the device the 2036 discussion is about (IETF 127, "The 2036 rollover in
    /// practice"): embedded gear without a battery-backed clock, which boots at the Unix epoch
    /// and asks NTP what time it is. Asking is the point - its clock is wrong because it has
    /// nothing better yet - so a server's time after 2036 has to come out after 2036. Nearest to
    /// 1970 puts everything after 2038-01-19 into era 0, and the client would set itself to the
    /// early 1900s.
    ///
    /// ntpd and chrony resolve the era against a fixed point of their own build (ntpd's build
    /// date, chrony's configure --with-ntp-era) rather than against the clock being corrected.
    /// The cases the nearest-era rule already gets right are here too, so that a fix for the
    /// reset clock cannot break them.
    ///
    /// Tested on the decoder and not through a client: Norn's ClockOffset resolves the era
    /// against the machine's own clock, not the client's TimeProvider, so a client given a
    /// frozen 1970 clock on a 2026 machine never shows the fault a real 1970 machine has.
    /// </summary>
    [TestCaseSource(nameof(ResetClockCases))]
    public void Norn_ResolvesTheEra_EvenWithItsClockResetTo1970(DateTime  ClientClock,
                                                                DateTime  ServerTime,
                                                                String    Why)
    {

        var wireTimestamp = RawNtpTimestamp.FromDateTime(ServerTime, era: RawNtpTimestamp.EraFor(ServerTime));

        var nornDecoded   = NTPPacket.NTPTimestampToDateTime(wireTimestamp, ApproximateTime: ClientClock);

        Assert.That(nornDecoded,
                    Is.EqualTo(ServerTime).Within(TimeSpan.FromSeconds(1)),
                    $"{Why}: a server time of {ServerTime:O} carries the seconds count " +
                    $"{RawNtpTimestamp.Seconds(wireTimestamp)}, which Norn, with its clock at {ClientClock:O}, " +
                    $"decodes as {nornDecoded:O} - and would set its clock to that");

    }

    #endregion

    #region Offset and delay arithmetic

    /// <summary>
    /// RFC 5905 §8: offset = ((t2 - t1) + (t3 - t4)) / 2 and delay = (t4 - t1) - (t3 - t2).
    /// Checked against a hand-built exchange with a known 5 s offset and 200 ms round trip.
    /// </summary>
    [Test]
    public void ClockOffsetAndDelay_MatchRfc5905()
    {

        var t1 = new DateTime(2024, 1, 1, 12, 0,  0,   0, DateTimeKind.Utc);  // client sends
        var t2 = new DateTime(2024, 1, 1, 12, 0,  5, 100, DateTimeKind.Utc);  // server receives
        var t3 = new DateTime(2024, 1, 1, 12, 0,  5, 100, DateTimeKind.Utc);  // server sends
        var t4 = new DateTime(2024, 1, 1, 12, 0,  0, 200, DateTimeKind.Utc);  // client receives

        var bytes = RawNtpWriter.Write(new RawNtpPacket {
                        Mode                = RawNtpMode.Server,
                        Stratum             = 2,
                        OriginTimestamp     = RawNtpTimestamp.FromDateTime(t1),
                        ReceiveTimestamp    = RawNtpTimestamp.FromDateTime(t2),
                        TransmitTimestamp   = RawNtpTimestamp.FromDateTime(t3),
                        ReferenceTimestamp  = RawNtpTimestamp.FromDateTime(t1)
                    });

        if (!NTPResponse.TryParse(bytes,
                                  out var parsed,
                                  out var errorResponse,
                                  DestinationTimestamp: RawNtpTimestamp.FromDateTime(t4)))
        {
            Assert.Fail($"failed to parse: {errorResponse}");
            return;
        }

        Assert.Multiple(() => {

            Assert.That(parsed.ClockOffset?.TotalMilliseconds,
                        Is.EqualTo(5000).Within(1),
                        "the server clock is 5 s ahead");

            Assert.That(parsed.RoundTripDelay?.TotalMilliseconds,
                        Is.EqualTo(200).Within(1),
                        "the round trip took 200 ms");

        });

    }

    #endregion

}
