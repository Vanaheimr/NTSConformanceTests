namespace NTSConformance.Core.RawNtp;

/// <summary>
/// Serializes <see cref="RawNtpPacket"/> to the wire, straight from RFC 5905 §7.3 and
/// RFC 7822. Faithfully emits whatever it is told to — including malformed lengths and
/// missing padding — because provoking a parser is the point.
/// </summary>
public static class RawNtpWriter
{

    /// <summary>Serialize a packet: 48-octet header, extension fields, optional trailing bytes.</summary>
    public static Byte[] Write(RawNtpPacket packet)
    {

        using var stream = new MemoryStream();

        WriteHeader(stream, packet);

        foreach (var field in packet.ExtensionFields)
            WriteExtensionField(stream, field);

        if (packet.TrailingBytes is { Length: > 0 })
            stream.Write(packet.TrailingBytes);

        return stream.ToArray();

    }


    /// <summary>Just the 48-octet header — the associated data an NTS authenticator covers.</summary>
    public static Byte[] WriteHeaderOnly(RawNtpPacket packet)
    {

        using var stream = new MemoryStream();

        WriteHeader(stream, packet);

        return stream.ToArray();

    }


    private static void WriteHeader(Stream stream, RawNtpPacket packet)
    {

        // LI (2 bits) | VN (3 bits) | Mode (3 bits)
        stream.WriteByte((Byte) (((packet.LeapIndicator & 0x03) << 6) |
                                 ((packet.Version       & 0x07) << 3) |
                                  (packet.Mode          & 0x07)));

        stream.WriteByte(packet.Stratum);
        stream.WriteByte(packet.Poll);
        stream.WriteByte(unchecked((Byte) packet.Precision));

        WriteUInt32(stream, packet.RootDelay);
        WriteUInt32(stream, packet.RootDispersion);

        // The reference identifier is exactly four octets; pad or truncate defensively so
        // a test that sets a short one still produces a parseable header.
        var referenceIdentifier = new Byte[4];
        Array.Copy(packet.ReferenceIdentifier, referenceIdentifier,
                   Math.Min(4, packet.ReferenceIdentifier.Length));
        stream.Write(referenceIdentifier);

        WriteUInt64(stream, packet.ReferenceTimestamp);
        WriteUInt64(stream, packet.OriginTimestamp);
        WriteUInt64(stream, packet.ReceiveTimestamp);
        WriteUInt64(stream, packet.TransmitTimestamp);

    }


    private static void WriteExtensionField(Stream stream, RawExtensionField field)
    {

        WriteUInt16(stream, field.FieldType);
        WriteUInt16(stream, field.LengthOverride ?? field.ConformantLength);

        stream.Write(field.Value);

        if (!field.SuppressPadding)
        {
            var padding = field.PaddedValueLength - field.Value.Length;

            for (var i = 0; i < padding; i++)
                stream.WriteByte(0x00);
        }

    }


    #region Big-endian primitives

    public static void WriteUInt16(Stream stream, UInt16 value)
    {
        stream.WriteByte((Byte) (value >> 8));
        stream.WriteByte((Byte)  value);
    }

    public static void WriteUInt32(Stream stream, UInt32 value)
    {
        for (var shift = 24; shift >= 0; shift -= 8)
            stream.WriteByte((Byte) (value >> shift));
    }

    public static void WriteUInt64(Stream stream, UInt64 value)
    {
        for (var shift = 56; shift >= 0; shift -= 8)
            stream.WriteByte((Byte) (value >> shift));
    }

    public static Byte[] UInt16Bytes(UInt16 value)
        => [ (Byte) (value >> 8), (Byte) value ];

    public static Byte[] UInt64Bytes(UInt64 value)
    {

        var bytes = new Byte[8];

        for (var i = 0; i < 8; i++)
            bytes[i] = (Byte) (value >> (56 - 8 * i));

        return bytes;

    }

    #endregion

}
