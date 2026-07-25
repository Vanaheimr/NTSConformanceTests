using System.Diagnostics.CodeAnalysis;

namespace NTSConformance.Core.RawNtp;

/// <summary>
/// Which RFC 7822 rules the reader enforces. The defaults are strict — this is the
/// reference behaviour a conformant parser is expected to show.
/// </summary>
public sealed record RawNtpReadOptions
{

    /// <summary>RFC 7822: every extension field is zero-padded to a four-octet boundary, so Length is a multiple of 4.</summary>
    public Boolean RequireLengthMultipleOfFour { get; init; } = true;

    /// <summary>
    /// RFC 7822 §7.5.1.4: with no MAC present, a lone extension field must be at least
    /// 28 octets; with several, the last must be at least 28 and the others at least 16.
    /// </summary>
    public Boolean EnforceMinimumFieldLengths  { get; init; } = true;

    /// <summary>Reject 1-3 leftover octets after the last extension field.</summary>
    public Boolean RejectTrailingBytes         { get; init; } = true;

    /// <summary>
    /// Treat a trailing 4-octet (crypto-NAK), 20-octet (MD5) or 24-octet (SHA-1) blob as a
    /// legacy RFC 5905 §7.5 MAC rather than an extension field. NTS packets never carry one.
    /// </summary>
    public Boolean AllowLegacyMac              { get; init; }


    /// <summary>Strict RFC 7822, no legacy MAC — what NTS traffic must satisfy.</summary>
    public static readonly RawNtpReadOptions Strict = new ();

    /// <summary>Parse structure only, enforcing nothing beyond "the bytes are there".</summary>
    public static readonly RawNtpReadOptions Lenient = new () {
        RequireLengthMultipleOfFour  = false,
        EnforceMinimumFieldLengths   = false,
        RejectTrailingBytes          = false
    };

}


/// <summary>
/// A strict, independent NTP/RFC 7822 decoder.
///
/// Norn's <c>NTPRequest.TryParse</c> / <c>NTPResponse.TryParse</c> accept several classes of
/// malformed packet (notably a truncated final extension field, which they silently drop while
/// still returning success). This decoder is written from the RFCs to say what the answer
/// should have been, so the tests compare two implementations rather than asserting against
/// the behaviour of the one under test.
/// </summary>
public static class RawNtpReader
{

    /// <summary>
    /// Parse a packet. Returns false with a specific <paramref name="errorResponse"/>
    /// on any violation; never throws for malformed input.
    /// </summary>
    public static Boolean TryRead(Byte[]                                  buffer,
                                  [NotNullWhen(true)]  out RawNtpPacket?  packet,
                                  [NotNullWhen(false)] out String?        errorResponse,
                                  RawNtpReadOptions?                      options = null)
    {

        packet         = null;
        errorResponse  = null;

        var opts       = options ?? RawNtpReadOptions.Strict;

        try
        {

            if (buffer.Length < RawNtpPacket.HeaderLength)
            {
                errorResponse = $"An NTP packet is at least {RawNtpPacket.HeaderLength} octets, got {buffer.Length}.";
                return false;
            }

            var result = new RawNtpPacket {
                             LeapIndicator        = (Byte)  ((buffer[0] >> 6) & 0x03),
                             Version              = (Byte)  ((buffer[0] >> 3) & 0x07),
                             Mode                 = (Byte)   (buffer[0]       & 0x07),
                             Stratum              =           buffer[1],
                             Poll                 =           buffer[2],
                             Precision            = unchecked((SByte) buffer[3]),
                             RootDelay            = ReadUInt32(buffer,  4),
                             RootDispersion       = ReadUInt32(buffer,  8),
                             ReferenceIdentifier  = buffer[12..16],
                             ReferenceTimestamp   = ReadUInt64(buffer, 16),
                             OriginTimestamp      = ReadUInt64(buffer, 24),
                             ReceiveTimestamp     = ReadUInt64(buffer, 32),
                             TransmitTimestamp    = ReadUInt64(buffer, 40)
                         };

            var offset = RawNtpPacket.HeaderLength;

            while (offset < buffer.Length)
            {

                var remaining = buffer.Length - offset;

                if (opts.AllowLegacyMac && remaining is 4 or 20 or 24)
                {
                    // A legacy MAC (crypto-NAK / MD5 / SHA-1), not an extension field.
                    result.TrailingBytes = buffer[offset..];
                    offset = buffer.Length;
                    break;
                }

                if (remaining < 4)
                {

                    if (opts.RejectTrailingBytes)
                    {
                        errorResponse = $"{remaining} octet(s) of trailing data after the last extension field at offset {offset}; " +
                                        "an extension field header is 4 octets and RFC 7822 leaves no room for anything else.";
                        return false;
                    }

                    result.TrailingBytes = buffer[offset..];
                    break;

                }

                var fieldType    = ReadUInt16(buffer, offset);
                var fieldLength  = ReadUInt16(buffer, offset + 2);

                if (fieldLength < 4)
                {
                    errorResponse = $"The extension field at offset {offset} declares a length of {fieldLength} octets, " +
                                     "but the Field Type and Length fields alone occupy 4.";
                    return false;
                }

                if (opts.RequireLengthMultipleOfFour && fieldLength % 4 != 0)
                {
                    errorResponse = $"The extension field at offset {offset} declares a length of {fieldLength} octets, " +
                                     "which is not a multiple of 4 (RFC 7822: fields are zero-padded to a four-octet boundary).";
                    return false;
                }

                if (offset + fieldLength > buffer.Length)
                {
                    errorResponse = $"The extension field at offset {offset} declares a length of {fieldLength} octets, " +
                                    $"which runs {offset + fieldLength - buffer.Length} octet(s) past the end of the {buffer.Length}-octet packet.";
                    return false;
                }

                result.ExtensionFields.Add(
                    new RawExtensionField(fieldType, buffer[(offset + 4)..(offset + fieldLength)])
                );

                offset += fieldLength;

            }

            if (opts.EnforceMinimumFieldLengths && result.ExtensionFields.Count > 0)
            {

                // RFC 7822 §7.5.1.4, absent a MAC.
                for (var i = 0; i < result.ExtensionFields.Count; i++)
                {

                    var isLast   = i == result.ExtensionFields.Count - 1;
                    var minimum  = isLast ? 28 : 16;
                    var actual   = result.ExtensionFields[i].ConformantLength;

                    if (actual < minimum)
                    {
                        errorResponse = $"The {(isLast ? "last" : $"#{i + 1}")} extension field " +
                                        $"({RawExtensionFieldTypes.Describe(result.ExtensionFields[i].FieldType)}) is {actual} octets; " +
                                        $"RFC 7822 §7.5.1.4 requires at least {minimum} in a packet without a MAC.";
                        return false;
                    }

                }

            }

            packet = result;
            return true;

        }
        catch (Exception e)
        {
            errorResponse = $"Malformed NTP packet: {e.Message}";
            return false;
        }

    }


    #region Big-endian primitives

    public static UInt16 ReadUInt16(Byte[] buffer, Int32 offset)
        => (UInt16) ((buffer[offset] << 8) | buffer[offset + 1]);

    public static UInt32 ReadUInt32(Byte[] buffer, Int32 offset)
    {

        UInt32 value = 0;

        for (var i = 0; i < 4; i++)
            value = (value << 8) | buffer[offset + i];

        return value;

    }

    public static UInt64 ReadUInt64(Byte[] buffer, Int32 offset)
    {

        UInt64 value = 0;

        for (var i = 0; i < 8; i++)
            value = (value << 8) | buffer[offset + i];

        return value;

    }

    #endregion

}
