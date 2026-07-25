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


    /// <summary>Norn and the reference must agree on the conversion, to within the format's precision.</summary>
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

            // The fraction may differ in the low bits: Norn routes it through a Double.
            var fractionDelta = Math.Abs((Int64) RawNtpTimestamp.Fraction(norn) -
                                         (Int64) RawNtpTimestamp.Fraction(reference));

            Assert.That(fractionDelta, Is.LessThan(4096),
                        $"the fraction for {instant:O} should agree to well under a microsecond");

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


    /// <summary>Converting to a timestamp and back must be lossless at 100 ns granularity.</summary>
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

    #region Era handling (F10)

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
    /// F10 — Norn's <c>NTPTimestampToDateTime</c> has no era parameter: it always adds the
    /// second count to 1900, so every timestamp generated after the 2036 rollover decodes
    /// as a date in the early 1900s.
    ///
    /// This is not yet a live defect — it becomes one on 2036-02-07 — but it is a wire-format
    /// limitation the RFC explicitly addresses, so the suite records it rather than waiting.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
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
