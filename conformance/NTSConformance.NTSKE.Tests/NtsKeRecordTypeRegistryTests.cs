using NUnit.Framework;

using NTSConformance.Core;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// Every NTS-KE record type Norn names must be one it is entitled to use.
///
/// <para>
/// RFC 8915 § 7.6 divides the registry into three ranges with three different answers to "may I
/// take this value": <b>0–1023</b> needs IETF Review, <b>1024–16383</b> needs a published
/// specification, and <b>16384–32767</b> is Private or Experimental Use and needs nobody's
/// permission. An implementation that helps itself to a value from the first two ranges is not
/// merely impolite — it has taken a number IANA can assign to someone else, and on the day that
/// happens it will read a stranger's record as one of its own.
/// </para>
/// <para>
/// Norn did exactly that: its two public-key records sat at 32 and 33 for years. The pool draft
/// has since been assigned 8 to 14, so the range they were squatting in is actively filling up.
/// </para>
/// <para>
/// This asserts the rule rather than the two values, so it catches the next record added in the
/// wrong place rather than only the two that were.
/// </para>
/// </summary>
[TestFixture]
public class NtsKeRecordTypeRegistryTests
{

    /// <summary>
    /// The values RFC 8915 § 4.1 defines, and the one later registration Norn implements.
    /// </summary>
    /// <remarks>
    /// Record 1024 is chrony's "Compliant AES-128-GCM-SIV Exporter Context", registered with
    /// IANA under Specification Required. Norn may use it because it is assigned and Norn speaks
    /// it, not because 1024 happened to be free.
    /// </remarks>
    private static readonly HashSet<UInt16> registered = [
                                                 0,  // End of Message
                                                 1,  // NTS Next Protocol Negotiation
                                                 2,  // Error
                                                 3,  // Warning
                                                 4,  // AEAD Algorithm Negotiation
                                                 5,  // New Cookie for NTPv4
                                                 6,  // NTPv4 Server Negotiation
                                                 7,  // NTPv4 Port Negotiation
                                              1024   // Compliant AES-128-GCM-SIV Exporter Context
                                             ];

    private const UInt16 PrivateUseFirst = 16384;
    private const UInt16 PrivateUseLast  = 32767;


    /// <summary>
    /// Every named record type is either assigned to something Norn implements, or inside the
    /// private-use range.
    /// </summary>
    [Test]
    public void EveryRecordType_IsOneNornMayUse()
    {

        Assert.Multiple(() => {

            foreach (var recordType in Enum.GetValues<NTSKE_RecordTypes>())
            {

                var value = (UInt16) recordType;

                if (registered.Contains(value))
                    continue;

                Assert.That(value,
                            Is.InRange(PrivateUseFirst, PrivateUseLast),
                            $"{recordType} ({value}) is neither an assigned record type nor inside " +
                            $"IANA's Private or Experimental Use range {PrivateUseFirst}–{PrivateUseLast}. " +
                            $"Values below {PrivateUseFirst} belong to IANA and it can hand this one to " +
                            $"somebody else.");

            }

        });

    }


    /// <summary>
    /// The record type is 15 bits, so nothing may reach the critical bit.
    /// </summary>
    /// <remarks>
    /// RFC 8915 § 4 puts the Critical Bit in the top bit of the same 16-bit word. A record type of
    /// 32768 or more would set it on the wire whatever the sender intended, and be read back as a
    /// different type entirely — the encoder masks with 0x7FFF, so the mistake would be silent in
    /// both directions.
    /// </remarks>
    [Test]
    public void NoRecordType_ReachesIntoTheCriticalBit()

        => Assert.Multiple(() => {

            foreach (var recordType in Enum.GetValues<NTSKE_RecordTypes>())
                Assert.That((UInt16) recordType,
                            Is.LessThanOrEqualTo(PrivateUseLast),
                            $"{recordType} does not fit in the 15 bits the record type field has");

        });


    /// <summary>
    /// Each type describes itself as something other than "unknown".
    /// </summary>
    /// <remarks>
    /// <para>
    /// The description switch is written on the numbers rather than on the enum, which makes it
    /// the one place a renumbering can be forgotten. It used to switch on a Byte, too, silently
    /// folding everything above 255 onto another entry — record 1024 described itself as "End of
    /// Message" for as long as it existed.
    /// </para>
    /// <para>
    /// Not also asserted here: that no two types share a wire value. It cannot fail.
    /// <c>Enum.GetValues</c> collapses duplicates into one entry, and the parser's switch
    /// expression would not compile — a second arm for the same value is CS8510, an unreachable
    /// pattern. The compiler is a better place for that rule than a test.
    /// </para>
    /// </remarks>
    [Test]
    public void EveryRecordType_DescribesItself()

        => Assert.Multiple(() => {

            foreach (var recordType in Enum.GetValues<NTSKE_RecordTypes>())
                Assert.That(recordType.Description(),
                            Is.Not.EqualTo("Unknown or custom record type!"),
                            $"{recordType} ({(UInt16) recordType}) has a name but no description, " +
                            $"which means the description switch was not renumbered with it");

        });

}
