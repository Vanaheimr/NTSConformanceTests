namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// NTS-KE record types, RFC 8915 §4.1.
/// </summary>
public static class RawNtsKeRecordTypes
{

    public const UInt16 EndOfMessage               = 0;
    public const UInt16 NextProtocolNegotiation    = 1;
    public const UInt16 Error                      = 2;
    public const UInt16 Warning                    = 3;
    public const UInt16 AeadAlgorithmNegotiation   = 4;
    public const UInt16 NewCookieForNtpv4          = 5;
    public const UInt16 Ntpv4ServerNegotiation     = 6;
    public const UInt16 Ntpv4PortNegotiation       = 7;

    /// <summary>
    /// Compliant AES-128-GCM-SIV Exporter Context. Not from RFC 8915 — IANA record type 1024,
    /// registered by the chrony project in the range that requires a specification.
    /// </summary>
    public const UInt16 CompliantAes128GcmSivExporterContext = 1024;


    public static String Describe(UInt16 recordType)

        => recordType switch {
               EndOfMessage                          => "End of Message",
               NextProtocolNegotiation               => "NTS Next Protocol Negotiation",
               Error                                 => "Error",
               Warning                               => "Warning",
               AeadAlgorithmNegotiation              => "AEAD Algorithm Negotiation",
               NewCookieForNtpv4                     => "New Cookie for NTPv4",
               Ntpv4ServerNegotiation                => "NTPv4 Server Negotiation",
               Ntpv4PortNegotiation                  => "NTPv4 Port Negotiation",
               CompliantAes128GcmSivExporterContext  => "Compliant AES-128-GCM-SIV Exporter Context",
               _                                     => $"unknown ({recordType})"
           };

}


/// <summary>
/// NTS-KE error codes, RFC 8915 §4.1.3.
/// </summary>
public static class RawNtsKeErrorCodes
{

    /// <summary>
    /// The request contained a record the server did not understand with its critical bit set.
    /// </summary>
    public const UInt16 UnrecognizedCriticalRecord  = 0;

    /// <summary>
    /// The request was not complete and syntactically well-formed.
    /// </summary>
    public const UInt16 BadRequest                  = 1;

    /// <summary>
    /// The server could not respond due to an internal condition; the client may retry.
    /// </summary>
    public const UInt16 InternalServerError         = 2;

}


/// <summary>
/// Next-protocol identifiers, RFC 8915 §4.1.2.
/// </summary>
public static class RawNtsKeNextProtocols
{
    public const UInt16 Ntpv4 = 0;
}


/// <summary>
/// One NTS-KE record, RFC 8915 §4:
///
/// <code>
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +---------------------------------------------------------------+
/// |C|        Record Type          |          Body Length          |
/// +---------------------------------------------------------------+
/// |                          Record Body                          |
/// +---------------------------------------------------------------+
/// </code>
///
/// The top bit of the first 16-bit word is the Critical Bit, leaving 15 bits of record
/// type. Unlike NTP extension fields, the length here counts only the body — not the
/// four-octet header — and there is no padding requirement.
/// </summary>
public sealed record RawNtsKeRecord(Boolean IsCritical, UInt16 RecordType, Byte[] Body)
{

    /// <summary>
    /// Emit a body length other than the real one, for negative tests.
    /// </summary>
    public UInt16? LengthOverride { get; init; }


    public Byte[] ToByteArray()
    {

        var declaredLength  = LengthOverride ?? (UInt16) Body.Length;
        var typeField       = (UInt16) ((IsCritical ? 0x8000 : 0x0000) | (RecordType & 0x7FFF));

        var bytes           = new Byte[4 + Body.Length];

        bytes[0] = (Byte) (typeField      >> 8);
        bytes[1] = (Byte)  typeField;
        bytes[2] = (Byte) (declaredLength >> 8);
        bytes[3] = (Byte)  declaredLength;

        Buffer.BlockCopy(Body, 0, bytes, 4, Body.Length);

        return bytes;

    }


    public override String ToString()
        => $"{(IsCritical ? "critical " : "")}{RawNtsKeRecordTypes.Describe(RecordType)}, {Body.Length} octet body";


    #region Factories

    /// <summary>
    /// RFC 8915 §4.1.1: End of Message. Critical bit set, empty body, always last.
    /// </summary>
    public static RawNtsKeRecord EndOfMessage()
        => new (true, RawNtsKeRecordTypes.EndOfMessage, []);

    /// <summary>
    /// RFC 8915 §4.1.2: the protocols the client supports, most preferred first.
    /// </summary>
    public static RawNtsKeRecord NextProtocolNegotiation(params UInt16[] protocolIds)
        => new (true, RawNtsKeRecordTypes.NextProtocolNegotiation, UInt16Body(protocolIds));

    /// <summary>
    /// RFC 8915 §4.1.5: the AEAD algorithms the client supports, most preferred first.
    /// </summary>
    public static RawNtsKeRecord AeadAlgorithmNegotiation(params UInt16[] algorithmIds)
        => new (false, RawNtsKeRecordTypes.AeadAlgorithmNegotiation, UInt16Body(algorithmIds));

    /// <summary>
    /// RFC 8915 §4.1.3: an error code. Critical bit set.
    /// </summary>
    public static RawNtsKeRecord Error(UInt16 errorCode)
        => new (true, RawNtsKeRecordTypes.Error, UInt16Body(errorCode));

    /// <summary>
    /// RFC 8915 §4.1.4: a warning code. Critical bit set.
    /// </summary>
    public static RawNtsKeRecord Warning(UInt16 warningCode)
        => new (true, RawNtsKeRecordTypes.Warning, UInt16Body(warningCode));

    public static RawNtsKeRecord NewCookieForNtpv4(Byte[] cookie)
        => new (false, RawNtsKeRecordTypes.NewCookieForNtpv4, cookie);

    /// <summary>
    /// IANA record type 1024: this peer derives AES-128-GCM-SIV's keys with the algorithm id
    /// RFC 8915 § 5.1 specifies, rather than the 15 that chrony writes there. Empty body, and
    /// never critical — a peer that does not know it has to be able to ignore it.
    /// </summary>
    public static RawNtsKeRecord CompliantAes128GcmSivExporterContext(Boolean isCritical = false)
        => new (isCritical, RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext, []);


    private static Byte[] UInt16Body(params UInt16[] values)
    {

        var body = new Byte[values.Length * 2];

        for (var i = 0; i < values.Length; i++)
        {
            body[i * 2]     = (Byte) (values[i] >> 8);
            body[i * 2 + 1] = (Byte)  values[i];
        }

        return body;

    }

    #endregion

}


/// <summary>
/// Encodes and decodes NTS-KE record streams independently of Norn.
/// </summary>
public static class RawNtsKeCodec
{

    /// <summary>
    /// A conformant client request: NTPv4 as the next protocol, AES-SIV-CMAC-256 as the
    /// AEAD, terminated by End of Message.
    /// </summary>
    public static Byte[] ClientRequest(UInt16 aeadAlgorithmId = 15)

        => Encode([
               RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
               RawNtsKeRecord.AeadAlgorithmNegotiation(aeadAlgorithmId),
               RawNtsKeRecord.EndOfMessage()
           ]);


    public static Byte[] Encode(IEnumerable<RawNtsKeRecord> records)
        => Bytes.Concat([ .. records.Select(record => record.ToByteArray()) ]);


    /// <summary>
    /// Decode a record stream. Stops after End of Message, as RFC 8915 §4 requires — a
    /// message ends there and anything after it is not part of it.
    /// </summary>
    public static Boolean TryDecode(Byte[]                      buffer,
                                    out List<RawNtsKeRecord>?   records,
                                    out String?                 errorResponse)
    {

        records        = null;
        errorResponse  = null;

        var decoded    = new List<RawNtsKeRecord>();
        var offset     = 0;

        while (offset < buffer.Length)
        {

            if (offset + 4 > buffer.Length)
            {
                errorResponse = $"A record header is 4 octets, but only {buffer.Length - offset} remain at offset {offset}.";
                return false;
            }

            var typeField   = (UInt16) ((buffer[offset]     << 8) | buffer[offset + 1]);
            var bodyLength  = (UInt16) ((buffer[offset + 2] << 8) | buffer[offset + 3]);

            var isCritical  = (typeField & 0x8000) != 0;
            var recordType  = (UInt16)   (typeField & 0x7FFF);

            if (offset + 4 + bodyLength > buffer.Length)
            {
                errorResponse = $"The {RawNtsKeRecordTypes.Describe(recordType)} record at offset {offset} declares a " +
                                $"{bodyLength}-octet body, which runs past the end of the {buffer.Length}-octet message.";
                return false;
            }

            decoded.Add(new RawNtsKeRecord(isCritical, recordType, buffer[(offset + 4)..(offset + 4 + bodyLength)]));

            offset += 4 + bodyLength;

            if (recordType == RawNtsKeRecordTypes.EndOfMessage)
                break;

        }

        records = decoded;
        return true;

    }


    /// <summary>
    /// Read a body of 16-bit big-endian values, as the negotiation records carry.
    /// </summary>
    public static UInt16[] ReadUInt16Body(RawNtsKeRecord record)
    {

        var values = new UInt16[record.Body.Length / 2];

        for (var i = 0; i < values.Length; i++)
            values[i] = (UInt16) ((record.Body[i * 2] << 8) | record.Body[i * 2 + 1]);

        return values;

    }

}
