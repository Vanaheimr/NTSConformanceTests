using System.Text;

namespace NTSConformance.Core.RawNtp;

/// <summary>
/// NTP association modes, RFC 5905 §7.3.
/// </summary>
public static class RawNtpMode
{
    public const Byte Reserved          = 0;
    public const Byte SymmetricActive   = 1;
    public const Byte SymmetricPassive  = 2;
    public const Byte Client            = 3;
    public const Byte Server            = 4;
    public const Byte Broadcast         = 5;
    public const Byte Control           = 6;
    public const Byte Private           = 7;
}


/// <summary>
/// Leap indicator values, RFC 5905 §7.3.
/// </summary>
public static class RawNtpLeapIndicator
{
    public const Byte NoWarning       = 0;
    public const Byte LastMinute61    = 1;
    public const Byte LastMinute59    = 2;
    public const Byte Unsynchronized  = 3;
}


/// <summary>
/// An NTP packet in its RFC 5905 §7.3 wire shape, plus RFC 7822 extension fields.
///
/// This is a deliberately dumb data holder: every field is independently settable so a
/// test can construct any packet, valid or invalid. It shares no code with Norn's
/// <c>NTPPacket</c> / <c>NTPRequest</c> / <c>NTPResponse</c>, which is what makes
/// comparisons between the two meaningful.
/// </summary>
public sealed class RawNtpPacket
{

    /// <summary>
    /// The fixed NTP header is always 48 octets.
    /// </summary>
    public const Int32 HeaderLength = 48;


    public Byte    LeapIndicator       { get; set; }
    public Byte    Version             { get; set; } = 4;
    public Byte    Mode                { get; set; } = RawNtpMode.Client;
    public Byte    Stratum             { get; set; }
    public Byte    Poll                { get; set; }
    public SByte   Precision           { get; set; }

    /// <summary>
    /// Root delay, 16.16 fixed point seconds.
    /// </summary>
    public UInt32  RootDelay           { get; set; }

    /// <summary>
    /// Root dispersion, 16.16 fixed point seconds.
    /// </summary>
    public UInt32  RootDispersion      { get; set; }

    /// <summary>
    /// Four octets: an IPv4 address at stratum 2+, or ASCII at stratum 0/1.
    /// </summary>
    public Byte[]  ReferenceIdentifier { get; set; } = new Byte[4];

    public UInt64  ReferenceTimestamp  { get; set; }
    public UInt64  OriginTimestamp     { get; set; }
    public UInt64  ReceiveTimestamp    { get; set; }
    public UInt64  TransmitTimestamp   { get; set; }

    public List<RawExtensionField> ExtensionFields { get; } = [];


    /// <summary>
    /// Octets appended after the last extension field. RFC 7822 leaves no room for
    /// these; used to check that parsers reject trailing garbage.
    /// </summary>
    public Byte[]? TrailingBytes { get; set; }


    #region Convenience accessors

    /// <summary>
    /// True when this is a Kiss-o'-Death packet (RFC 5905 §7.4: stratum 0).
    /// </summary>
    public Boolean IsKissOfDeath
        => Stratum == 0;

    /// <summary>
    /// The four-character kiss code carried in the Reference Identifier of a KoD packet,
    /// e.g. "NTSN" for an NTS NAK (RFC 8915 §5.7).
    /// </summary>
    public String KissCode
        => Encoding.ASCII.GetString(ReferenceIdentifier).TrimEnd('\0');


    public IEnumerable<RawExtensionField> FieldsOfType(UInt16 fieldType)
        => ExtensionFields.Where(field => field.FieldType == fieldType);

    public RawExtensionField? FirstFieldOfType(UInt16 fieldType)
        => ExtensionFields.FirstOrDefault(field => field.FieldType == fieldType);

    public Int32 CountOfType(UInt16 fieldType)
        => ExtensionFields.Count(field => field.FieldType == fieldType);


    /// <summary>
    /// The Unique Identifier value (RFC 8915 §5.3), or null when absent.
    /// </summary>
    public Byte[]? UniqueIdentifier
        => FirstFieldOfType(RawExtensionFieldTypes.UniqueIdentifier)?.Value;

    #endregion


    /// <summary>
    /// Set the reference identifier from a four-character kiss code or refid string.
    /// </summary>
    public RawNtpPacket WithReferenceIdentifier(String ascii)
    {

        var bytes = new Byte[4];
        var text  = Encoding.ASCII.GetBytes(ascii);

        Array.Copy(text, bytes, Math.Min(4, text.Length));
        ReferenceIdentifier = bytes;

        return this;

    }


    public RawNtpPacket WithExtensionField(RawExtensionField field)
    {
        ExtensionFields.Add(field);
        return this;
    }


    /// <summary>
    /// A conformant NTPv4 client request: LI 0, VN 4, Mode 3, transmit timestamp set to now.
    /// </summary>
    public static RawNtpPacket ClientRequest(DateTime? transmitTime = null)

        => new () {
               LeapIndicator      = RawNtpLeapIndicator.NoWarning,
               Version            = 4,
               Mode               = RawNtpMode.Client,
               Stratum            = 0,
               Poll               = 4,
               Precision          = -6,
               TransmitTimestamp  = RawNtpTimestamp.FromDateTime(transmitTime ?? DateTime.UtcNow)
           };


    public override String ToString()
        => $"LI {LeapIndicator}, VN {Version}, Mode {Mode}, Stratum {Stratum}" +
           (IsKissOfDeath && KissCode.Length > 0 ? $" (KoD '{KissCode}')" : "") +
           (ExtensionFields.Count > 0
                ? $", extension fields: {String.Join(", ", ExtensionFields.Select(f => RawExtensionFieldTypes.Describe(f.FieldType)))}"
                : ", no extension fields");

}
