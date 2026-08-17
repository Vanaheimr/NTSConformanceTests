using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.WireFormat.Tests;

/// <summary>
/// RFC 5905 §7.3: the 48-octet NTP header. Every field is checked in both directions —
/// the reference encoder's bytes must decode correctly in Norn, and Norn's bytes must
/// decode correctly in the reference.
/// </summary>
[TestFixture]
public class NtpHeaderTests
{

    #region Field decoding

    /// <summary>
    /// The first octet packs Leap Indicator (2 bits), Version (3 bits) and Mode (3 bits).
    /// Norn must recover all three from every combination.
    /// </summary>
    [Test]
    public void FirstOctet_LeapVersionModeAreUnpacked()
    {

        Assert.Multiple(() => {

            for (Byte leap = 0; leap <= 3; leap++)
                for (Byte version = 0; version <= 7; version++)
                    for (Byte mode = 0; mode <= 7; mode++)
                    {

                        var packet = new RawNtpPacket {
                                         LeapIndicator  = leap,
                                         Version        = version,
                                         Mode           = mode,
                                         Stratum        = 2
                                     };

                        // A response parse needs the packet to be at least a bare header.
                        var bytes  = RawNtpWriter.Write(packet);

                        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
                        {
                            Assert.Fail($"LI {leap}, VN {version}, Mode {mode} failed to parse: {errorResponse}");
                            return;
                        }

                        Assert.That(parsed.LI,   Is.EqualTo(leap),    $"leap indicator for LI {leap}, VN {version}, Mode {mode}");
                        Assert.That(parsed.VN,   Is.EqualTo(version), $"version for LI {leap}, VN {version}, Mode {mode}");
                        Assert.That(parsed.Mode, Is.EqualTo(mode),    $"mode for LI {leap}, VN {version}, Mode {mode}");

                    }

        });

    }


    /// <summary>
    /// RFC 5905 §7.3: Precision is a signed exponent, so the whole signed-byte range
    /// must survive the round trip. A parser reading it as unsigned would turn -6 into 250.
    /// </summary>
    [TestCase((SByte) (-32))]
    [TestCase((SByte) (-29))]
    [TestCase((SByte) (-20))]
    [TestCase((SByte)  (-6))]
    [TestCase((SByte)  (-1))]
    [TestCase((SByte)    0)]
    [TestCase((SByte)    1)]
    [TestCase((SByte)  127)]
    [TestCase((SByte) (-128))]
    public void Precision_IsSigned(SByte precision)
    {

        var bytes = RawNtpWriter.Write(new RawNtpPacket { Stratum = 2, Precision = precision });

        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
        {
            Assert.Fail($"precision {precision} failed to parse: {errorResponse}");
            return;
        }

        Assert.That(parsed.Precision, Is.EqualTo(precision));

    }


    /// <summary>
    /// Root Delay and Root Dispersion are 32-bit 16.16 fixed-point values.
    /// </summary>
    [Test]
    public void RootDelayAndDispersion_RoundTrip()
    {

        var packet = new RawNtpPacket {
                         Stratum         = 2,
                         RootDelay       = RawNtpTimestamp.SecondsToShort(0.125),
                         RootDispersion  = RawNtpTimestamp.SecondsToShort(1.5)
                     };

        var bytes  = RawNtpWriter.Write(packet);

        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
        {
            Assert.Fail($"failed to parse: {errorResponse}");
            return;
        }

        Assert.Multiple(() => {
            Assert.That(parsed.RootDelay,      Is.EqualTo(packet.RootDelay),      "root delay, raw 16.16");
            Assert.That(parsed.RootDispersion, Is.EqualTo(packet.RootDispersion), "root dispersion, raw 16.16");
            Assert.That(RawNtpTimestamp.ShortToSeconds(parsed.RootDelay),      Is.EqualTo(0.125), "root delay in seconds");
            Assert.That(RawNtpTimestamp.ShortToSeconds(parsed.RootDispersion), Is.EqualTo(1.5),   "root dispersion in seconds");
        });

    }


    /// <summary>
    /// All four 64-bit timestamps must land in the right fields, not be transposed.
    /// </summary>
    [Test]
    public void Timestamps_AreNotTransposed()
    {

        var packet = new RawNtpPacket {
                         Stratum             = 2,
                         ReferenceTimestamp  = 0x1111111111111111,
                         OriginTimestamp     = 0x2222222222222222,
                         ReceiveTimestamp    = 0x3333333333333333,
                         TransmitTimestamp   = 0x4444444444444444
                     };

        var bytes  = RawNtpWriter.Write(packet);

        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
        {
            Assert.Fail($"failed to parse: {errorResponse}");
            return;
        }

        Assert.Multiple(() => {
            Assert.That(parsed.ReferenceTimestamp, Is.EqualTo(0x1111111111111111UL), "reference timestamp");
            Assert.That(parsed.OriginateTimestamp, Is.EqualTo(0x2222222222222222UL), "originate timestamp");
            Assert.That(parsed.ReceiveTimestamp,   Is.EqualTo(0x3333333333333333UL), "receive timestamp");
            Assert.That(parsed.TransmitTimestamp,  Is.EqualTo(0x4444444444444444UL), "transmit timestamp");
        });

    }


    /// <summary>
    /// A packet shorter than the 48-octet header must be rejected, at every length.
    /// </summary>
    [Test]
    public void ShortPacket_IsRejected()
    {

        Assert.Multiple(() => {
            for (var length = 0; length < 48; length++)
            {

                var parsed = NTPResponse.TryParse(new Byte[length], out _, out _);

                Assert.That(parsed, Is.False, $"a {length}-octet packet is shorter than the NTP header and must be rejected");

            }
        });

    }

    #endregion

    #region Byte-exact encoding

    /// <summary>
    /// Norn's serializer must produce exactly the bytes the reference encoder does for the
    /// same header — this is what lets later tests trust either side's output.
    /// </summary>
    [Test]
    public void Serialization_MatchesReferenceByteForByte()
    {

        var reference = new RawNtpPacket {
                            LeapIndicator       = 1,
                            Version             = 4,
                            Mode                = RawNtpMode.Server,
                            Stratum             = 3,
                            Poll                = 6,
                            Precision           = -20,
                            RootDelay           = 0x00012345,
                            RootDispersion      = 0x00067890,
                            ReferenceTimestamp  = 0x1111111122222222,
                            OriginTimestamp     = 0x3333333344444444,
                            ReceiveTimestamp    = 0x5555555566666666,
                            TransmitTimestamp   = 0x7777777788888888
                        }.WithReferenceIdentifier("PTB");

        var norn      = new NTPPacket(
                            LI:                   1,
                            VN:                   4,
                            Mode:                 RawNtpMode.Server,
                            Stratum:              3,
                            Poll:                 6,
                            Precision:            -20,
                            RootDelay:            0x00012345,
                            RootDispersion:       0x00067890,
                            ReferenceIdentifier:  ReferenceIdentifier.From("PTB"),
                            ReferenceTimestamp:   0x1111111122222222,
                            OriginateTimestamp:   0x3333333344444444,
                            ReceiveTimestamp:     0x5555555566666666,
                            TransmitTimestamp:    0x7777777788888888
                        );

        var expected  = RawNtpWriter.Write(reference);
        var actual    = norn.ToByteArray();

        Assert.That(actual, Is.EqualTo(expected).AsCollection, Bytes.Diff(expected, actual));

    }

    #endregion

    #region Kiss-o'-Death

    /// <summary>
    /// RFC 5905 §7.4: stratum 0 marks a Kiss-o'-Death and the Reference Identifier
    /// carries a four-character ASCII kiss code. RFC 8915 §5.7 adds "NTSN" for an NTS NAK.
    /// </summary>
    [TestCase("DENY")]
    [TestCase("RSTR")]
    [TestCase("RATE")]
    [TestCase("NTSN")]
    public void KissOfDeath_CodeIsReadable(String kissCode)
    {

        var bytes = RawNtpWriter.Write(
                        new RawNtpPacket {
                            Mode     = RawNtpMode.Server,
                            Stratum  = 0
                        }.WithReferenceIdentifier(kissCode)
                    );

        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
        {
            Assert.Fail($"the '{kissCode}' KoD packet failed to parse: {errorResponse}");
            return;
        }

        Assert.Multiple(() => {

            Assert.That(parsed.Stratum, Is.EqualTo(0), "a KoD packet is stratum 0");

            Assert.That(parsed.ReferenceIdentifier.AsASCII,
                        Is.EqualTo(kissCode),
                        $"the reference identifier should read back as the kiss code '{kissCode}'");

            Assert.That(parsed.ReferenceIdentifier.ErrorString,
                        Does.Contain(kissCode),
                        $"'{kissCode}' should be recognised as a known kiss code and described");

        });

    }

    #endregion

}
