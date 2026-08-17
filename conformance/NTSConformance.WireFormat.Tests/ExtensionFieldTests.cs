using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.WireFormat.Tests;

/// <summary>
/// RFC 7822 extension field framing, as it applies to NTPv4 packets carrying no MAC —
/// which is every NTS packet.
///
/// The rules under test: the Length field covers the entire field including padding;
/// fields are zero-padded to a four-octet boundary; and in the absence of a MAC a lone
/// field must be at least 28 octets while in a series the last must be at least 28 and
/// the others at least 16 (§7.5.1.4).
///
/// Each malformed input is first run through the suite's own strict reader to establish
/// what a conformant parser concludes, then through Norn's.
/// </summary>
[TestFixture]
public class ExtensionFieldTests
{

    #region Helpers

    /// <summary>
    /// A well-formed 32-octet Unique Identifier field — 36 octets on the wire.
    /// </summary>
    private static RawExtensionField WellFormedUniqueIdentifier()
        => RawNtsExtensionFields.UniqueIdentifier(Enumerable.Range(0, 32).Select(i => (Byte) i).ToArray());

    /// <summary>
    /// A well-formed 100-octet cookie field — 104 octets on the wire.
    /// </summary>
    private static RawExtensionField WellFormedCookie()
        => RawNtsExtensionFields.NtsCookie(Enumerable.Range(0, 100).Select(i => (Byte) (i * 3)).ToArray());


    private static RawNtpPacket ServerPacketWith(params RawExtensionField[] fields)
    {

        var packet = new RawNtpPacket {
                         Mode     = RawNtpMode.Server,
                         Stratum  = 2,
                         Version  = 4
                     };

        packet.ExtensionFields.AddRange(fields);

        return packet;

    }


    /// <summary>
    /// Confirm the suite's own reader rejects the input, and report why.
    /// </summary>
    private static String AssertReferenceRejects(Byte[] bytes)
    {

        var accepted = RawNtpReader.TryRead(bytes, out _, out var referenceError);

        Assert.That(accepted, Is.False,
                    "the suite's own strict reader should reject this input — if it does not, the test case is wrong, not Norn");

        return referenceError!;

    }

    #endregion

    #region Well-formed fields

    /// <summary>
    /// A conformant single field must parse, and its value must survive intact.
    /// </summary>
    [Test]
    public void SingleWellFormedField_Parses()
    {

        var field  = WellFormedUniqueIdentifier();
        var bytes  = RawNtpWriter.Write(ServerPacketWith(field));

        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
        {
            Assert.Fail($"a conformant 36-octet Unique Identifier field should parse: {errorResponse}");
            return;
        }

        Assert.Multiple(() => {
            Assert.That(parsed.Extensions.Count(), Is.EqualTo(1), "one extension field");
            Assert.That(parsed.UniqueIdentifier(), Is.EqualTo(field.Value).AsCollection, "the identifier value");
        });

    }


    /// <summary>
    /// Several conformant fields must all be recovered, in order.
    /// </summary>
    [Test]
    public void MultipleWellFormedFields_AllParse()
    {

        var bytes = RawNtpWriter.Write(ServerPacketWith(
                        WellFormedUniqueIdentifier(),
                        WellFormedCookie(),
                        RawNtsExtensionFields.NtsCookiePlaceholder(100)
                    ));

        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
        {
            Assert.Fail($"three conformant fields should parse: {errorResponse}");
            return;
        }

        Assert.That(parsed.Extensions.Count(), Is.EqualTo(3),
                    $"expected three extension fields, got: {String.Join(", ", parsed.Extensions.Select(e => e.Type.ToString()))}");

    }


    /// <summary>
    /// The reference reader and Norn must agree that a realistic NTS-shaped packet is valid,
    /// and agree on how many fields it contains.
    /// </summary>
    [Test]
    public void RealisticNtsPacket_BothParsersAgree()
    {

        var packet = ServerPacketWith(WellFormedUniqueIdentifier(), WellFormedCookie());
        var bytes  = RawNtpWriter.Write(packet);

        var referenceAccepted = RawNtpReader.TryRead(bytes, out var referencePacket, out var referenceError);
        var nornAccepted      = NTPResponse.TryParse(bytes, out var nornPacket, out var nornError);

        Assert.Multiple(() => {
            Assert.That(referenceAccepted, Is.True, $"reference reader: {referenceError}");
            Assert.That(nornAccepted,      Is.True, $"Norn: {nornError}");
            Assert.That(nornPacket?.Extensions.Count(),
                        Is.EqualTo(referencePacket?.ExtensionFields.Count),
                        "both parsers should find the same number of extension fields");
        });

    }

    #endregion

    #region Malformed: truncation

    /// <summary>
    /// a final field whose declared Length runs past the end of the packet must be
    /// rejected. Norn's parser instead breaks out of its loop and returns success, silently
    /// discarding that field, so a truncated packet is accepted as if it were shorter.
    ///
    /// This is the most consequential of the framing gaps: an attacker can append a
    /// truncated field to reshape how a packet is interpreted without invalidating it.
    /// </summary>
    [Test]
    public void TruncatedFinalField_IsRejected()
    {

        // Declare 60 octets of field but supply only 36.
        var field = WellFormedUniqueIdentifier() with { LengthOverride = 60 };
        var bytes = RawNtpWriter.Write(ServerPacketWith(field));

        var referenceError = AssertReferenceRejects(bytes);

        var accepted = NTPResponse.TryParse(bytes, out var parsed, out var nornError);

        Assert.That(accepted, Is.False,
                    "a field declaring 60 octets inside a 36-octet remainder must be rejected. " +
                    $"The reference reader says: {referenceError}. " +
                    $"Norn accepted it{(parsed is not null ? $" and kept {parsed.Extensions.Count()} extension field(s)" : "")} " +
                    $"(error: {nornError ?? "none"}).");

    }


    /// <summary>
    /// The same defect with the truncated field following a valid one: the valid field is
    /// kept and the truncated tail vanishes, so the packet parses as something the sender
    /// never sent.
    /// </summary>
    [Test]
    public void TruncatedFieldAfterValidField_IsRejected()
    {

        var bytes = RawNtpWriter.Write(ServerPacketWith(
                        WellFormedUniqueIdentifier(),
                        WellFormedCookie() with { LengthOverride = 400 }
                    ));

        var referenceError = AssertReferenceRejects(bytes);

        Assert.That(NTPResponse.TryParse(bytes, out var parsed, out var nornError), Is.False,
                    $"the reference reader says: {referenceError}. " +
                    $"Norn accepted it and kept {parsed?.Extensions.Count() ?? 0} extension field(s) (error: {nornError ?? "none"}).");

    }

    #endregion

    #region Malformed: length not a multiple of four

    /// <summary>
    /// RFC 7822 pads every field to a four-octet boundary, so a Length that is not a
    /// multiple of 4 cannot describe a conformant field and must be rejected.
    /// </summary>
    [TestCase((UInt16) 37)]
    [TestCase((UInt16) 38)]
    [TestCase((UInt16) 39)]
    public void LengthNotMultipleOfFour_IsRejected(UInt16 declaredLength)
    {

        // A 40-octet field body so the declared length always fits inside the buffer;
        // only the "not a multiple of 4" property is under test.
        var field = RawNtsExtensionFields.UniqueIdentifier(new Byte[40]) with { LengthOverride = declaredLength };
        var bytes = RawNtpWriter.Write(ServerPacketWith(field));

        var referenceError = AssertReferenceRejects(bytes);

        Assert.That(NTPResponse.TryParse(bytes, out _, out var nornError), Is.False,
                    $"a declared length of {declaredLength} is not a multiple of 4. " +
                    $"The reference reader says: {referenceError}. Norn's error was: {nornError ?? "none"}.");

    }

    #endregion

    #region Malformed: trailing bytes

    /// <summary>
    /// one to three octets after the last field cannot begin another field, and
    /// RFC 7822 provides nowhere for them to live. Norn's loop condition
    /// (<c>offset + 4 &lt;= length</c>) walks off the end and ignores them.
    /// </summary>
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    public void TrailingBytes_AreRejected(Int32 trailingByteCount)
    {

        var packet = ServerPacketWith(WellFormedUniqueIdentifier());
        packet.TrailingBytes = Enumerable.Repeat((Byte) 0xAA, trailingByteCount).ToArray();

        var bytes          = RawNtpWriter.Write(packet);
        var referenceError = AssertReferenceRejects(bytes);

        Assert.That(NTPResponse.TryParse(bytes, out _, out var nornError), Is.False,
                    $"{trailingByteCount} octet(s) of trailing data must not be silently ignored. " +
                    $"The reference reader says: {referenceError}. Norn's error was: {nornError ?? "none"}.");

    }

    #endregion

    #region Malformed: sub-minimum lengths

    /// <summary>
    /// A declared length below 4 cannot even cover the Field Type and Length words.
    /// Norn already rejects this, so it stands as a regression guard.
    /// </summary>
    [TestCase((UInt16) 0)]
    [TestCase((UInt16) 1)]
    [TestCase((UInt16) 2)]
    [TestCase((UInt16) 3)]
    public void LengthBelowFour_IsRejected(UInt16 declaredLength)
    {

        var field = WellFormedUniqueIdentifier() with { LengthOverride = declaredLength };
        var bytes = RawNtpWriter.Write(ServerPacketWith(field));

        Assert.That(NTPResponse.TryParse(bytes, out _, out _), Is.False,
                    $"a declared length of {declaredLength} cannot describe an extension field");

    }


    /// <summary>
    /// RFC 7822 §7.5.1.4: absent a MAC, a lone extension field must be at least 28
    /// octets. Shorter fields are the ambiguous range the rule exists to keep off the wire.
    /// </summary>
    [TestCase((UInt16) 8)]
    [TestCase((UInt16) 12)]
    [TestCase((UInt16) 16)]
    [TestCase((UInt16) 20)]
    [TestCase((UInt16) 24)]
    public void LoneFieldShorterThan28Octets_IsRejected(UInt16 totalLength)
    {

        var field = new RawExtensionField(RawExtensionFieldTypes.UniqueIdentifier, new Byte[totalLength - 4]);
        var bytes = RawNtpWriter.Write(ServerPacketWith(field));

        var referenceError = AssertReferenceRejects(bytes);

        Assert.That(NTPResponse.TryParse(bytes, out _, out var nornError), Is.False,
                    $"a lone {totalLength}-octet field is below the 28-octet minimum. " +
                    $"The reference reader says: {referenceError}. Norn's error was: {nornError ?? "none"}.");

    }


    /// <summary>
    /// An unknown field type with a body shorter than 16 octets drives Norn's
    /// parser into <c>new NTPExtension(...)</c>, whose constructor throws
    /// <see cref="ArgumentOutOfRangeException"/>. A <c>TryParse</c> must return false for
    /// malformed input, never throw: the exception escapes the contract and, on the server,
    /// is only caught by a blanket handler several frames up.
    /// </summary>
    [TestCase((UInt16) 4)]
    [TestCase((UInt16) 8)]
    [TestCase((UInt16) 12)]
    [TestCase((UInt16) 16)]
    public void UnknownFieldTypeWithShortBody_DoesNotThrow(UInt16 totalLength)
    {

        var field = new RawExtensionField(0x0999, new Byte[totalLength - 4]);
        var bytes = RawNtpWriter.Write(ServerPacketWith(field));

        Boolean accepted;
        String? nornError;

        try
        {
            accepted = NTPResponse.TryParse(bytes, out _, out nornError);
        }
        catch (Exception e)
        {
            Assert.Fail($"TryParse threw {e.GetType().Name} instead of returning false for a " +
                        $"{totalLength}-octet field of unknown type 0x0999: {e.Message}");
            return;
        }

        Assert.That(accepted, Is.False,
                    $"a {totalLength}-octet field is below the RFC 7822 minimum and must be rejected " +
                    $"(Norn's error: {nornError ?? "none"})");

    }

    #endregion

    #region Duplicate fields

    /// <summary>
    /// RFC 8915 §5.7 requires exactly one Unique Identifier field. Two must not both be
    /// accepted, because a peer could then match against whichever one it prefers.
    /// </summary>
    [Test]
    public void DuplicateUniqueIdentifier_IsRejected()
    {

        var first  = RawNtsExtensionFields.UniqueIdentifier(Enumerable.Repeat((Byte) 0x11, 32).ToArray());
        var second = RawNtsExtensionFields.UniqueIdentifier(Enumerable.Repeat((Byte) 0x22, 32).ToArray());

        var bytes  = RawNtpWriter.Write(ServerPacketWith(first, second));

        if (!NTPResponse.TryParse(bytes, out var parsed, out _))
            Assert.Pass("the packet was rejected outright, which satisfies the requirement");

        Assert.That(parsed!.Extensions.Count(e => e.Type == ExtensionTypes.UniqueIdentifier),
                    Is.LessThan(2),
                    "RFC 8915 §5.7 permits exactly one Unique Identifier extension field; " +
                    "accepting two leaves which one is authoritative undefined");

    }

    #endregion

    #region Value round-trip

    /// <summary>
    /// A field whose value length is not a multiple of four is padded on the wire, and a
    /// parser cannot tell padding from payload — so the recovered value is longer than the
    /// original. The NTS fields all happen to be aligned, so this is a latent sharp edge
    /// rather than a live bug; it is pinned here so it stays visible.
    /// </summary>
    [TestCase(29)]
    [TestCase(30)]
    [TestCase(31)]
    public void UnalignedValueLength_GrowsByPadding(Int32 valueLength)
    {

        var original = Enumerable.Range(0, valueLength).Select(i => (Byte) (i + 1)).ToArray();
        var bytes    = RawNtpWriter.Write(ServerPacketWith(RawNtsExtensionFields.UniqueIdentifier(original)));

        if (!NTPResponse.TryParse(bytes, out var parsed, out var errorResponse))
        {
            Assert.Fail($"failed to parse: {errorResponse}");
            return;
        }

        var recovered = parsed.UniqueIdentifier();

        Assert.Multiple(() => {

            Assert.That(recovered!.Length, Is.EqualTo((valueLength + 3) & ~3),
                        "the recovered value includes the RFC 7822 padding");

            Assert.That(recovered.Take(valueLength), Is.EqualTo(original).AsCollection,
                        "the payload itself must be unchanged");

            Assert.That(recovered.Skip(valueLength), Is.All.Zero,
                        "the padding must be zero octets");

        });

    }

    #endregion

}
