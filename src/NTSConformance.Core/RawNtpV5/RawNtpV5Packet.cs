using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core.RawNtpV5;

/// <summary>
/// The codepoints and constants of draft-ietf-ntp-ntpv5-10, copied from the draft text and not
/// from any implementation, so that a server is checked against the document rather than
/// against itself.
/// </summary>
public static class RawNtpV5Draft
{

    /// <summary>
    /// § 7.1: the full name of the draft, ASCII, not null-terminated.
    /// </summary>
    public const String  Identification         = "draft-ietf-ntp-ntpv5-10";

    /// <summary>
    /// § 12: "NTP5DRFT" in the reference timestamp of an NTPv4 request, the draft's form of the
    /// NTPv5 negotiation.
    /// </summary>
    public const UInt64  NegotiationMagic       = 0x4E54503544524654UL;

    /// <summary>
    /// § 12: "NTP5NTP5", the final form - which a draft implementation is to use instead of.
    /// </summary>
    public const UInt64  FinalNegotiationMagic  = 0x4E5450354E545035UL;

    /// <summary>
    /// § 6: the header, and the shortest valid message.
    /// </summary>
    public const Int32   HeaderLength           = 48;


    // § 7 and § 13, the draft codepoints.
    public const UInt16  Padding                    = 0xF501;
    public const UInt16  MessageAuthenticationCode  = 0xF502;
    public const UInt16  ReferenceIDsRequest        = 0xF503;
    public const UInt16  ReferenceIDsResponse       = 0xF504;
    public const UInt16  ServerInformation          = 0xF505;
    public const UInt16  Correction                 = 0xF506;
    public const UInt16  ReferenceTimestamp         = 0xF507;
    public const UInt16  MonotonicReceiveTimestamp  = 0xF508;
    public const UInt16  SecondaryReceiveTimestamp  = 0xF509;
    public const UInt16  TimeSourcesRequest         = 0xF50A;
    public const UInt16  TimeSourcesResponse        = 0xF50B;
    public const UInt16  DraftIdentification        = 0xF5FF;


    // § 6, the Flags field.
    public const UInt16  Unsynchronized             = 0x0001;
    public const UInt16  InterleavedMode            = 0x0002;
    public const UInt16  AuthenticationNAK          = 0x0004;
    public const UInt16  KnownFlags                 = Unsynchronized | InterleavedMode | AuthenticationNAK;


    // § 6, the Timescale field.
    public const Byte    UTC                        = 0;
    public const Byte    TAI                        = 1;
    public const Byte    UT1                        = 2;

}


/// <summary>
/// The time32 type of § 5: 4 integer and 28 fractional bits, all ones meaning infinity.
/// </summary>
public static class RawTime32
{

    /// <summary>
    /// § 5: all bits set is infinity, not a time.
    /// </summary>
    public const UInt32 Infinity = UInt32.MaxValue;

    /// <summary>
    /// Units per second: 2^28.
    /// </summary>
    public const Int64  UnitsPerSecond = 1L << 28;

    /// <summary>
    /// The time32 value a duration has when rounded up, as § 6 asks of root delay and
    /// dispersion, with what does not fit as infinity. Exact in ticks.
    /// </summary>
    public static UInt32 RoundedUp(TimeSpan Value)
    {

        if (Value <= TimeSpan.Zero)
            return 0;

        var units = (Value.Ticks * UnitsPerSecond + TimeSpan.TicksPerSecond - 1) / TimeSpan.TicksPerSecond;

        // The largest finite value is all ones but one.
        return units >= Infinity ? Infinity : (UInt32) units;

    }

    public static Double ToSeconds(UInt32 Value)
        => Value == Infinity ? Double.PositiveInfinity : Value / (Double) UnitsPerSecond;

}


/// <summary>
/// An NTPv5 extension field (§ 7): a 16-bit type, a 16-bit length that counts the header and the
/// data but not the message-level padding up to the next multiple of 4.
/// </summary>
/// <param name="Type">The field type.</param>
/// <param name="Data">The data, unpadded.</param>
public sealed record RawNtpV5ExtensionField(UInt16 Type, Byte[] Data)
{

    /// <summary>
    /// § 7: the length as written, header included, padding not.
    /// </summary>
    public Int32 Length
        => 4 + Data.Length;

    /// <summary>
    /// What the field takes in the message, padding included.
    /// </summary>
    public Int32 PaddedLength
        => (Length + 3) & ~3;


    public static RawNtpV5ExtensionField DraftIdentification(String Identification = RawNtpV5Draft.Identification)
        => new (RawNtpV5Draft.DraftIdentification, Encoding.ASCII.GetBytes(Identification));

    /// <summary>
    /// § 7.6: in requests, all data fields contain 0; 8 octets in all.
    /// </summary>
    public static RawNtpV5ExtensionField ServerInformationRequest()
        => new (RawNtpV5Draft.ServerInformation, new Byte[4]);

    public static RawNtpV5ExtensionField Padding(Int32 DataLength)
        => new (RawNtpV5Draft.Padding, new Byte[DataLength]);

    public override String ToString()
        => $"0x{Type:X4}, length {Length}";

}


/// <summary>
/// An NTPv5 message as § 6 lays it out, written and read by this suite alone.
/// </summary>
public sealed class RawNtpV5Packet
{

    /// <summary>
    /// The 2 bits that were the leap indicator: 0, to be ignored by a receiver.
    /// </summary>
    public Byte    Reserved            { get; set; }
    public Byte    Version             { get; set; } = 5;
    public Byte    Mode                { get; set; } = 3;
    public Byte    Stratum             { get; set; }
    public SByte   Poll                { get; set; }
    public SByte   Precision           { get; set; }
    public UInt32  RootDelay           { get; set; }
    public UInt32  RootDispersion      { get; set; }
    public Byte    Timescale           { get; set; }
    public Byte    Era                 { get; set; }
    public UInt16  Flags               { get; set; }
    public UInt64  ServerCookie        { get; set; }
    public UInt64  ClientCookie        { get; set; }
    public UInt64  ReceiveTimestamp    { get; set; }
    public UInt64  TransmitTimestamp   { get; set; }

    public List<RawNtpV5ExtensionField> ExtensionFields { get; init; } = [];


    /// <summary>
    /// A request as § 9 forms it: everything zero but the version, the mode, the timescale, the
    /// flags and a new random client cookie - and, from a draft implementation, the Draft
    /// Identification field that § 7.1 makes mandatory.
    /// </summary>
    public static RawNtpV5Packet ClientRequest(Byte     Timescale          = RawNtpV5Draft.UTC,
                                               UInt16   Flags              = 0,
                                               String?  DraftIdentification = RawNtpV5Draft.Identification)
    {

        var request = new RawNtpV5Packet {
                          Timescale     = Timescale,
                          Flags         = Flags,
                          ClientCookie  = BinaryPrimitives.ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8))
                      };

        if (DraftIdentification is not null)
            request.ExtensionFields.Add(RawNtpV5ExtensionField.DraftIdentification(DraftIdentification));

        return request;

    }


    public RawNtpV5ExtensionField? Find(UInt16 Type)
        => ExtensionFields.FirstOrDefault(field => field.Type == Type);


    public Byte[] Write()
    {

        var length = RawNtpV5Draft.HeaderLength + ExtensionFields.Sum(field => field.PaddedLength);
        var buffer = new Byte[length];
        var span   = buffer.AsSpan();

        span[0] = (Byte) ((Reserved & 0x3) << 6 | (Version & 0x7) << 3 | (Mode & 0x7));
        span[1] = Stratum;
        span[2] = (Byte) Poll;
        span[3] = (Byte) Precision;
        BinaryPrimitives.WriteUInt32BigEndian(span[ 4..], RootDelay);
        BinaryPrimitives.WriteUInt32BigEndian(span[ 8..], RootDispersion);
        span[12] = Timescale;
        span[13] = Era;
        BinaryPrimitives.WriteUInt16BigEndian(span[14..], Flags);
        BinaryPrimitives.WriteUInt64BigEndian(span[16..], ServerCookie);
        BinaryPrimitives.WriteUInt64BigEndian(span[24..], ClientCookie);
        BinaryPrimitives.WriteUInt64BigEndian(span[32..], ReceiveTimestamp);
        BinaryPrimitives.WriteUInt64BigEndian(span[40..], TransmitTimestamp);

        var offset = RawNtpV5Draft.HeaderLength;

        foreach (var field in ExtensionFields)
        {
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..],       field.Type);
            BinaryPrimitives.WriteUInt16BigEndian(span[(offset + 2)..], (UInt16) field.Length);
            field.Data.CopyTo(span[(offset + 4)..]);
            offset += field.PaddedLength;
        }

        return buffer;

    }


    /// <summary>
    /// Read a message strictly by § 6 and § 7: at least the header, a length divisible by 4, and
    /// extension fields whose lengths are at least 4 and, padded, end exactly at the end.
    /// </summary>
    public static Boolean TryRead(ReadOnlySpan<Byte> Buffer, out RawNtpV5Packet? Packet, out String? Error)
    {

        Packet = null;
        Error  = null;

        if (Buffer.Length < RawNtpV5Draft.HeaderLength)
        {
            Error = $"{Buffer.Length} octets are shorter than the 48-octet header";
            return false;
        }

        if (Buffer.Length % 4 != 0)
        {
            Error = $"{Buffer.Length} octets are not divisible by 4 (§ 6)";
            return false;
        }

        var packet = new RawNtpV5Packet {
                         Reserved           = (Byte)  (Buffer[0] >> 6),
                         Version            = (Byte) ((Buffer[0] >> 3) & 0x7),
                         Mode               = (Byte)  (Buffer[0]       & 0x7),
                         Stratum            = Buffer[1],
                         Poll               = (SByte) Buffer[2],
                         Precision          = (SByte) Buffer[3],
                         RootDelay          = BinaryPrimitives.ReadUInt32BigEndian(Buffer[ 4..]),
                         RootDispersion     = BinaryPrimitives.ReadUInt32BigEndian(Buffer[ 8..]),
                         Timescale          = Buffer[12],
                         Era                = Buffer[13],
                         Flags              = BinaryPrimitives.ReadUInt16BigEndian(Buffer[14..]),
                         ServerCookie       = BinaryPrimitives.ReadUInt64BigEndian(Buffer[16..]),
                         ClientCookie       = BinaryPrimitives.ReadUInt64BigEndian(Buffer[24..]),
                         ReceiveTimestamp   = BinaryPrimitives.ReadUInt64BigEndian(Buffer[32..]),
                         TransmitTimestamp  = BinaryPrimitives.ReadUInt64BigEndian(Buffer[40..])
                     };

        var offset = RawNtpV5Draft.HeaderLength;

        while (offset < Buffer.Length)
        {

            if (Buffer.Length - offset < 4)
            {
                Error = $"{Buffer.Length - offset} octets at offset {offset} are too short for an extension field header";
                return false;
            }

            var type   = BinaryPrimitives.ReadUInt16BigEndian(Buffer[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(Buffer[(offset + 2)..]);

            if (length < 4)
            {
                Error = $"the extension field 0x{type:X4} at offset {offset} has a length of {length}, below the minimum of 4 (§ 7)";
                return false;
            }

            var padded = (length + 3) & ~3;

            if (offset + padded > Buffer.Length)
            {
                Error = $"the extension field 0x{type:X4} at offset {offset} with length {length} runs past the end of the {Buffer.Length}-octet message";
                return false;
            }

            packet.ExtensionFields.Add(new RawNtpV5ExtensionField(type, Buffer.Slice(offset + 4, length - 4).ToArray()));

            offset += padded;

        }

        Packet = packet;
        return true;

    }

}


/// <summary>
/// One UDP datagram out and at most one back, as octets: NTPv5 replies are read by the caller,
/// and a reply may be missing on purpose.
/// </summary>
public static class RawUdpExchange
{

    public static Byte[]? TryExchange(Byte[]     Request,
                                      String     Host,
                                      IPPort     Port,
                                      TimeSpan?  Timeout = null)
    {

        using var udp = new UdpClient(AddressFamily.InterNetwork);

        udp.Client.ReceiveTimeout = (Int32) (Timeout ?? TimeSpan.FromSeconds(5)).TotalMilliseconds;
        udp.Connect(Host, Port.ToUInt16());
        udp.Send(Request);

        var remote = new IPEndPoint(IPAddress.Any, 0);

        try
        {
            return udp.Receive(ref remote);
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.TimedOut
                                                          or SocketError.ConnectionReset)
        {
            return null;
        }

    }

}


/// <summary>
/// The extension fields of draft -10 that carry data of their own, as § 7.4, § 7.5 and § 7.7 to
/// § 7.10 lay them out: requests to send, and readers of what comes back.
/// </summary>
public static class RawNtpV5Fields
{

    #region § 7.4 Reference IDs

    /// <summary>
    /// § 7.4: a Reference IDs Request for the entries from Index on, as many as DataLength / 8.
    /// The data is the index and then padding, at least 8 octets and divisible by 8.
    /// </summary>
    public static RawNtpV5ExtensionField ReferenceIDsRequest(Byte Index, Int32 DataLength = 256)
    {
        var data = new Byte[DataLength];
        data[0]  = Index;
        return new (RawNtpV5Draft.ReferenceIDsRequest, data);
    }

    /// <summary>
    /// § 7.4: the entries of a Reference IDs Response, each an 8-bit share and a 56-bit ID.
    /// </summary>
    public static IReadOnlyList<(Byte Share, UInt64 ReferenceId)> ReferenceIDs(RawNtpV5ExtensionField Response)
    {

        var entries = new List<(Byte, UInt64)>();

        for (var offset = 0; offset + 8 <= Response.Data.Length; offset += 8)
            entries.Add((Response.Data[offset],
                         BinaryPrimitives.ReadUInt64BigEndian(Response.Data.AsSpan(offset)) & 0x00FFFFFFFFFFFFFFUL));

        return entries;

    }

    /// <summary>
    /// § 7.4: a share encoded as -16 * log2(s), rounded up and clamped to 8 bits.
    /// </summary>
    public static Byte EncodeShare(Double Share)
    {

        if (Share <= 0)
            return 255;

        var encoded = Math.Ceiling(-16.0 * Math.Log2(Share) - 1e-9);

        return (Byte) Math.Clamp(encoded, 0, 255);

    }

    #endregion

    #region § 7.7 Correction

    /// <summary>
    /// § 7.7: 28 octets - Origin Correction (64), Origin Path ID (16), Reserved (16), Delay
    /// Correction (64), Delay Path ID (16), Checksum Complement (16).
    /// </summary>
    public static RawNtpV5ExtensionField Correction(Int64   OriginCorrection    = 0,
                                                    UInt16  OriginPathId        = 0,
                                                    UInt16  Reserved            = 0,
                                                    Int64   DelayCorrection     = 0,
                                                    UInt16  DelayPathId         = 0,
                                                    UInt16  ChecksumComplement  = 0)
    {

        var data = new Byte[24];
        var span = data.AsSpan();

        BinaryPrimitives.WriteInt64BigEndian (span[ 0..], OriginCorrection);
        BinaryPrimitives.WriteUInt16BigEndian(span[ 8..], OriginPathId);
        BinaryPrimitives.WriteUInt16BigEndian(span[10..], Reserved);
        BinaryPrimitives.WriteInt64BigEndian (span[12..], DelayCorrection);
        BinaryPrimitives.WriteUInt16BigEndian(span[20..], DelayPathId);
        BinaryPrimitives.WriteUInt16BigEndian(span[22..], ChecksumComplement);

        return new (RawNtpV5Draft.Correction, data);

    }

    public static (Int64 OriginCorrection, UInt16 OriginPathId, UInt16 Reserved, Int64 DelayCorrection, UInt16 DelayPathId)
        ReadCorrection(RawNtpV5ExtensionField Field)

        => (BinaryPrimitives.ReadInt64BigEndian (Field.Data.AsSpan( 0)),
            BinaryPrimitives.ReadUInt16BigEndian(Field.Data.AsSpan( 8)),
            BinaryPrimitives.ReadUInt16BigEndian(Field.Data.AsSpan(10)),
            BinaryPrimitives.ReadInt64BigEndian (Field.Data.AsSpan(12)),
            BinaryPrimitives.ReadUInt16BigEndian(Field.Data.AsSpan(20)));

    #endregion

    #region § 7.8 Reference Timestamp, § 7.9 Monotonic Receive Timestamp

    /// <summary>
    /// § 7.8: 12 octets, the timestamp 0 in a request.
    /// </summary>
    public static RawNtpV5ExtensionField ReferenceTimestampRequest()
        => new (RawNtpV5Draft.ReferenceTimestamp, new Byte[8]);

    public static UInt64 ReadReferenceTimestamp(RawNtpV5ExtensionField Field)
        => BinaryPrimitives.ReadUInt64BigEndian(Field.Data);

    /// <summary>
    /// § 7.9: 16 octets, epoch ID and timestamp 0 in a request.
    /// </summary>
    public static RawNtpV5ExtensionField MonotonicReceiveTimestampRequest()
        => new (RawNtpV5Draft.MonotonicReceiveTimestamp, new Byte[12]);

    public static (UInt32 EpochId, UInt64 Timestamp) ReadMonotonicReceiveTimestamp(RawNtpV5ExtensionField Field)
        => (BinaryPrimitives.ReadUInt32BigEndian(Field.Data),
            BinaryPrimitives.ReadUInt64BigEndian(Field.Data.AsSpan(4)));

    #endregion

    #region § 7.5 Time Sources

    /// <summary>
    /// § 7.5: a Time Sources Request for the sources from Index on. The data is the index and
    /// then padding; "1 plus padding length" MUST be at least 20 octets and divisible by 4 -
    /// which this writer does not check, so that a test can send one that is not.
    /// </summary>
    public static RawNtpV5ExtensionField TimeSourcesRequest(Byte Index, Int32 DataLength = 20)
    {
        var data = new Byte[DataLength];
        data[0]  = Index;
        return new (RawNtpV5Draft.TimeSourcesRequest, data);
    }

    /// <summary>
    /// § 7.5: the entries of a Time Sources Response - Share (8), Flags (8), IdType (8),
    /// Length (8), then the identifier of that length. Null where an entry runs past the end.
    /// </summary>
    public static IReadOnlyList<(Byte Share, Byte Flags, Byte IdType, Byte[] Identifier)>? TimeSources(RawNtpV5ExtensionField Response)
    {

        var entries = new List<(Byte, Byte, Byte, Byte[])>();
        var data    = Response.Data;
        var offset  = 0;

        while (offset < data.Length)
        {

            if (offset + 4 > data.Length || offset + 4 + data[offset + 3] > data.Length)
                return null;

            entries.Add((data[offset], data[offset + 1], data[offset + 2], data.AsSpan(offset + 4, data[offset + 3]).ToArray()));

            offset += 4 + data[offset + 3];

        }

        return entries;

    }

    /// <summary>
    /// § 7.5: the flag of an authenticated source.
    /// </summary>
    public const Byte TimeSourceAuthenticated = 0x1;

    /// <summary>
    /// § 7.5: the kinds of identifier, and the length each has.
    /// </summary>
    public const Byte TimeSourceNone       = 0;
    public const Byte TimeSourceIPv4       = 1;
    public const Byte TimeSourceIPv6       = 2;
    public const Byte TimeSourceRefId      = 3;

    #endregion

    #region § 7.10 Secondary Receive Timestamp

    /// <summary>
    /// § 7.10: 16 octets - Timescale (8), Era (8), Reserved (16), Secondary Receive Timestamp
    /// (64). In a request the Timescale selects the timescale and "the other data fields ... MUST
    /// be set to 0".
    /// </summary>
    public static RawNtpV5ExtensionField SecondaryReceiveTimestampRequest(Byte    Timescale,
                                                                          Byte    Era        = 0,
                                                                          UInt16  Reserved   = 0,
                                                                          UInt64  Timestamp  = 0)
    {

        var data = new Byte[12];
        var span = data.AsSpan();

        span[0] = Timescale;
        span[1] = Era;
        BinaryPrimitives.WriteUInt16BigEndian(span[2..], Reserved);
        BinaryPrimitives.WriteUInt64BigEndian(span[4..], Timestamp);

        return new (RawNtpV5Draft.SecondaryReceiveTimestamp, data);

    }

    public static (Byte Timescale, Byte Era, UInt16 Reserved, UInt64 Timestamp) ReadSecondaryReceiveTimestamp(RawNtpV5ExtensionField Field)
        => (Field.Data[0],
            Field.Data[1],
            BinaryPrimitives.ReadUInt16BigEndian(Field.Data.AsSpan(2)),
            BinaryPrimitives.ReadUInt64BigEndian(Field.Data.AsSpan(4)));

    /// <summary>
    /// An era and a timestamp64 as one number of 2^-32 s since the start of era 0.
    /// </summary>
    public static Int128 Continuous(Byte Era, UInt64 Timestamp)
        => ((Int128) Era << 64) | Timestamp;

    #endregion

}


/// <summary>
/// One UDP socket for several exchanges, so that the server sees the same client address and
/// port each time - which the interleaved mode, keyed by the client, needs.
/// </summary>
public sealed class RawUdpSession : IDisposable
{

    private readonly UdpClient udp = new (AddressFamily.InterNetwork);

    public RawUdpSession(String Host, IPPort Port)
        => udp.Connect(Host, Port.ToUInt16());

    public Byte[]? TryExchange(Byte[] Request, TimeSpan? Timeout = null)
    {

        udp.Client.ReceiveTimeout = (Int32) (Timeout ?? TimeSpan.FromSeconds(5)).TotalMilliseconds;
        udp.Send(Request);

        var remote = new IPEndPoint(IPAddress.Any, 0);

        try
        {
            return udp.Receive(ref remote);
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.TimedOut
                                                          or SocketError.ConnectionReset)
        {
            return null;
        }

    }

    public void Dispose()
        => udp.Dispose();

}
