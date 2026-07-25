namespace NTSConformance.Core.RawNtp;

/// <summary>
/// Well-known NTP extension field types.
/// The NTS ones are registered by RFC 8915 §5.2-§5.6.
/// </summary>
public static class RawExtensionFieldTypes
{

    public const UInt16 UniqueIdentifier             = 0x0104;
    public const UInt16 NTSCookie                    = 0x0204;
    public const UInt16 NTSCookiePlaceholder         = 0x0304;
    public const UInt16 NTSAuthenticatorAndEncrypted = 0x0404;

    /// <summary>Norn vendor extensions — not IANA registered, exercised only to confirm they stay opt-in.</summary>
    public const UInt16 NornRequestSignedResponse    = 0xFF00;
    public const UInt16 NornSignedResponseAnnounce   = 0xFF01;
    public const UInt16 NornSignedResponse           = 0xFF02;

    public const UInt16 Debug                        = 0xFFFF;


    public static String Describe(UInt16 fieldType)

        => fieldType switch {
               UniqueIdentifier              => "Unique Identifier",
               NTSCookie                     => "NTS Cookie",
               NTSCookiePlaceholder          => "NTS Cookie Placeholder",
               NTSAuthenticatorAndEncrypted  => "NTS Authenticator and Encrypted Extension Fields",
               NornRequestSignedResponse     => "Norn Request Signed Response (vendor)",
               NornSignedResponseAnnounce    => "Norn Signed Response Announcement (vendor)",
               NornSignedResponse            => "Norn Signed Response (vendor)",
               Debug                         => "Debug (vendor)",
               _                             => $"unknown (0x{fieldType:X4})"
           };

}


/// <summary>
/// One NTP extension field, per RFC 7822 (which replaces RFC 5905 §7.5):
///
/// <code>
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +---------------------------------------------------------------+
/// |          Field Type           |            Length             |
/// +---------------------------------------------------------------+
/// .                            Value                              .
/// +---------------------------------------------------------------+
/// |                       Padding (as needed)                     |
/// +---------------------------------------------------------------+
/// </code>
///
/// <c>Length</c> covers the <em>entire</em> field — Field Type, Length, Value and
/// Padding — and every field is zero-padded to a four-octet boundary.
///
/// <see cref="Value"/> holds the unpadded payload. The overrides below exist so tests
/// can emit deliberately malformed fields; leave them unset for conformant output.
/// </summary>
public sealed record RawExtensionField(UInt16 FieldType, Byte[] Value)
{

    /// <summary>The number of octets a conformant encoder would put in the Length field.</summary>
    public UInt16 ConformantLength
        => (UInt16) (4 + PaddedValueLength);

    /// <summary>Value length rounded up to a four-octet boundary.</summary>
    public Int32 PaddedValueLength
        => (Value.Length + 3) & ~3;


    /// <summary>
    /// Emit this exact value in the Length field instead of the correct one.
    /// For truncation / overlong / non-multiple-of-4 conformance tests.
    /// </summary>
    public UInt16? LengthOverride { get; init; }

    /// <summary>
    /// Write <see cref="Value"/> without padding it to a four-octet boundary,
    /// violating RFC 7822. Only for negative tests.
    /// </summary>
    public Boolean SuppressPadding { get; init; }


    /// <summary>A conformant field with the given type and value.</summary>
    public static RawExtensionField Create(UInt16 fieldType, Byte[] value)
        => new (fieldType, value);

    /// <summary>
    /// A field padded out to at least <paramref name="minimumTotalLength"/> octets.
    /// RFC 7822 §7.5.1.4 requires ≥ 28 octets for the last field in a packet with no
    /// MAC, and ≥ 16 octets for the others.
    /// </summary>
    public static RawExtensionField CreatePadded(UInt16 fieldType, Byte[] value, Int32 minimumTotalLength)
    {

        var needed = minimumTotalLength - 4;

        return value.Length >= needed
                   ? new RawExtensionField(fieldType, value)
                   : new RawExtensionField(fieldType, [ .. value, .. new Byte[needed - value.Length] ]);

    }


    public override String ToString()
        => $"{RawExtensionFieldTypes.Describe(FieldType)}, {Value.Length} octets of value" +
           (LengthOverride.HasValue  ? $", length forced to {LengthOverride.Value}" : "") +
           (SuppressPadding          ? ", padding suppressed"                       : "");

}
