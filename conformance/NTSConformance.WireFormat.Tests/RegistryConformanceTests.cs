using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.WireFormat.Tests;

/// <summary>
/// RFC 9748, "Updating the NTP Registries" (February 2025) — the one specification change
/// affecting Norn that landed after this suite was written.
///
/// It updates RFCs 5905, 5906, 7821, 7822 and 8573, and changes no bytes on the wire. What it
/// changes is what the codes in those bytes mean: it reviews every NTP and NTS registry,
/// corrects the assignments that were wrong, and fixes two rules that were previously only
/// convention — codes are uppercase letters and digits, and anything beginning with "X" is
/// reserved for experimentation and can never be assigned by IANA.
///
/// A registry is easy to implement once and then leave behind. These tests hold Norn's code
/// tables against the registries as they stand today, so that drift is a red test rather than
/// a puzzling display string years later. That is not hypothetical for the "X" rule: ntpd-rs
/// serves the reference identifier <c>XNON</c> when it has no upstream, and this suite's own
/// interop tests meet it.
/// </summary>
[TestFixture]
public class RegistryConformanceTests
{

    #region NTP Kiss-o'-Death Codes

    /// <summary>
    /// The complete IANA "NTP Kiss-o'-Death Codes" registry. RFC 9748 left the entries
    /// themselves unchanged, so this is the RFC 5905 §7.4 table plus <c>NTSN</c> from
    /// RFC 8915 §5.7.
    /// </summary>
    private static readonly String[] kissOfDeathCodes = [
        "ACST", "AUTH", "AUTO", "BCST", "CRYP", "DENY", "DROP", "RSTR",
        "INIT", "MCST", "NKEY", "NTSN", "RATE", "RMOT", "STEP"
    ];


    /// <summary>
    /// Every registered kiss code must be recognized, because a client that cannot read one
    /// cannot obey it. These are the codes by which a server tells a client to slow down
    /// (<c>RATE</c>) or to stop entirely (<c>DENY</c>), and RFC 5905 §7.4 makes acting on them
    /// mandatory — a client that renders <c>DENY</c> as four unremarkable letters keeps
    /// hammering a server that has just refused it.
    /// </summary>
    [Test]
    public void EveryRegisteredKissCode_IsRecognized()
    {

        Assert.Multiple(() => {

            foreach (var code in kissOfDeathCodes)
            {

                var referenceIdentifier = ReferenceIdentifier.From(code);

                Assert.That(referenceIdentifier.ErrorString,
                            Is.Not.Null.And.Not.EqualTo(code),
                            $"kiss code '{code}' is in the IANA registry but Norn has no meaning " +
                            $"for it, so a server sending it would not be understood");

            }

        });

    }


    /// <summary>
    /// A kiss code reaches a client as a stratum-0 packet, and it is the stratum that says to
    /// read the four octets that way. Rendering the code correctly only when asked in the
    /// abstract, and not when the packet says stratum 0, would be no use at all.
    /// </summary>
    [Test]
    public void AKissCode_IsRenderedAsSuchAtStratumZero()
    {

        Assert.That(ReferenceIdentifier.From("RATE").ToString(0),
                    Does.Contain("Rate exceeded"),
                    "stratum 0 means the reference identifier is a Kiss-o'-Death code");

    }

    #endregion

    #region NTP Reference Identifier Codes

    /// <summary>
    /// The complete IANA "NTP Reference Identifier Codes" registry — the stratum-1 clock
    /// sources.
    ///
    /// Worth noting where this differs from RFC 4330's table, which is the one most
    /// implementations copied: the registry has since gained <c>GAL</c> (Galileo),
    /// <c>JJY</c> (Japan), <c>HBG</c> (Switzerland), <c>GOES</c>, <c>NIST</c> and <c>DFM</c>,
    /// and never carried <c>CESM</c>, <c>RBDM</c> or <c>OMEG</c>. <c>LOCL</c> is likewise not
    /// registered, though every implementation emits it — so this list is what must be
    /// understood, not the whole of what may be.
    /// </summary>
    private static readonly String[] referenceIdentifierCodes = [
        "GOES", "GPS",  "GAL",  "PPS",  "IRIG", "WWVB", "DCF",
        "HBG",  "MSF",  "JJY",  "LORC", "TDF",  "CHU",  "WWV",
        "WWVH", "NIST", "ACTS", "USNO", "PTB",  "DFM"
    ];


    /// <summary>
    /// Every registered clock source must be recognized. This is the display path a monitoring
    /// operator reads: an unrecognized code becomes four bare letters, and whether the server
    /// upstream is on GPS or on a telephone modem stops being visible.
    /// </summary>
    [Test]
    public void EveryRegisteredReferenceIdentifierCode_IsRecognized()
    {

        Assert.Multiple(() => {

            foreach (var code in referenceIdentifierCodes)
            {

                var referenceIdentifier = ReferenceIdentifier.From(code);

                Assert.That(referenceIdentifier.TimeSource,
                            Is.Not.Null.And.Not.EqualTo(code),
                            $"'{code}' is in the IANA NTP Reference Identifier Codes registry but " +
                            $"Norn has no description for it");

            }

        });

    }


    /// <summary>
    /// And at stratum 1, where a clock source is what the four octets mean.
    /// </summary>
    [Test]
    public void AClockSource_IsRenderedAsSuchAtStratumOne()
    {

        Assert.That(ReferenceIdentifier.From("GPS").ToString(1),
                    Does.Contain("Position").IgnoreCase,
                    "stratum 1 means the reference identifier names a reference clock");

    }

    #endregion

    #region The "X" prefix and the character rule

    /// <summary>
    /// RFC 9748: "Codes beginning with the character 'X' are reserved for experimentation and
    /// development. IANA cannot assign them."
    ///
    /// So no X-prefixed code can ever carry a registered meaning, and an implementation must
    /// not claim one for it. <c>XNON</c> is not invented for this test: it is what ntpd-rs
    /// serves when it has no upstream, and this suite's interop tests receive it.
    /// </summary>
    [Test]
    public void CodesBeginningWithX_AreNeverGivenARegisteredMeaning()
    {

        Assert.Multiple(() => {

            foreach (var code in new[] { "XNON", "XFAC", "X", "XGPS" })
            {

                var referenceIdentifier = ReferenceIdentifier.From(code);

                Assert.That(referenceIdentifier.ErrorString,
                            Is.EqualTo(code),
                            $"'{code}' is reserved for experimentation, so it must be passed " +
                            $"through as written rather than given a meaning");

                Assert.That(referenceIdentifier.TimeSource,
                            Is.EqualTo(code),
                            $"'{code}' is reserved for experimentation and names no clock source");

            }

        });

    }


    /// <summary>
    /// An experimental code must still be readable. Passing it through as text is the whole of
    /// what an implementation may do with it — throwing, or rendering it as a hexadecimal
    /// address, would make the packets this suite already receives from ntpd-rs unreadable.
    /// </summary>
    [Test]
    public void AnExperimentalCode_IsStillReadableAtStratumZero()
    {

        Assert.That(ReferenceIdentifier.From("XNON").ToString(0),
                    Is.EqualTo("XNON"),
                    "an unassigned code is shown as it arrived");

    }


    /// <summary>
    /// RFC 9748 restricts registry entries to uppercase letters and digits, which makes the
    /// codes case-sensitive as a matter of specification rather than of taste. Matching
    /// case-insensitively would give a meaning to a byte sequence that is not a registered
    /// code — and those byte sequences are exactly the ones left free for other uses.
    /// </summary>
    [Test]
    public void CodesAreMatchedExactly_NotCaseInsensitively()
    {

        Assert.Multiple(() => {

            Assert.That(ReferenceIdentifier.From("deny").ErrorString,
                        Is.EqualTo("deny"),
                        "lowercase 'deny' is not the registered code DENY");

            Assert.That(ReferenceIdentifier.From("gps").TimeSource,
                        Is.EqualTo("gps"),
                        "lowercase 'gps' is not the registered code GPS");

        });

    }

    #endregion

    #region NTP Extension Field Types

    /// <summary>
    /// RFC 9748 rewrote the "NTP Extension Field Types" registry, reserving a long list of
    /// values that Autokey had documented with swapped nibbles and confirming the four NTS
    /// field types.
    ///
    /// These four are load-bearing in a way a display string is not: a wrong value here means
    /// a field no other implementation can find.
    /// </summary>
    [Test]
    public void TheNTSExtensionFieldTypes_MatchTheRegistry()
    {

        Assert.Multiple(() => {
            Assert.That((UInt16) ExtensionTypes.UniqueIdentifier,           Is.EqualTo(0x0104), "Unique Identifier");
            Assert.That((UInt16) ExtensionTypes.NTSCookie,                  Is.EqualTo(0x0204), "NTS Cookie");
            Assert.That((UInt16) ExtensionTypes.NTSCookiePlaceholder,       Is.EqualTo(0x0304), "NTS Cookie Placeholder");
            Assert.That((UInt16) ExtensionTypes.AuthenticatorAndEncrypted,  Is.EqualTo(0x0404), "NTS Authenticator and Encrypted Extension Fields");
        });

    }


    /// <summary>
    /// RFC 9748 set aside 0xF000–0xFFFF for experimentation and development. Norn's own
    /// extension fields — its debug field and the three for signed responses, none of which is
    /// specified anywhere — have to live inside it.
    ///
    /// The rule protects two parties at once. A private field outside the range squats on a
    /// number IANA may assign to something else tomorrow, and once assigned, two
    /// implementations would read the same field type as two different things.
    /// </summary>
    [Test]
    public void UnspecifiedExtensionFields_StayInTheExperimentalRange()
    {

        var privateTypes = new[] {
                               ExtensionTypes.Debug,
                               ExtensionTypes.NTSRequestSignedResponse,
                               ExtensionTypes.NTSSignedResponseAnnouncement,
                               ExtensionTypes.NTSSignedResponse
                           };

        Assert.Multiple(() => {

            foreach (var extensionType in privateTypes)
                Assert.That((UInt16) extensionType,
                            Is.InRange(0xF000, 0xFFFF),
                            $"{extensionType} is Norn's own invention, so RFC 9748 puts it in " +
                            $"0xF000–0xFFFF and nowhere else");

        });

    }

    #endregion

}
