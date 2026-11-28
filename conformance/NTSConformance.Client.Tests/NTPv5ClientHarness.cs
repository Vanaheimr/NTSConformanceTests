using System.Security.Cryptography;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

namespace NTSConformance.Client.Tests;

/// <summary>
/// Norn's NTPv5 client against a <see cref="ScriptedNtpV5Server"/>: a client on a clock that
/// stands still, so that T1 and T4 are the same known instant and an offset comes out exactly,
/// and an NTS key exchange of this suite's making - keys and cookies it knows - that negotiated
/// NTPv5 and names the scripted server.
/// </summary>
/// <remarks>
/// The key exchange is records, not a handshake: what is under test is the time exchange, and
/// RFC 8915 § 4 leaves the cookies opaque to the client, so any octets do. The keys are random
/// and the scripted server seals with them directly, as a server would with the keys its
/// exporter gave it.
/// </remarks>
internal sealed class NTPv5ClientHarness : IAsyncDisposable
{

    #region Data

    /// <summary>
    /// The instant the client's clock stands at, by default: inside era 0.
    /// </summary>
    public static readonly DateTimeOffset DefaultNow = new (2030, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// AEAD_AES_SIV_CMAC_256, the algorithm RFC 8915 § 5.1 has every implementation support.
    /// </summary>
    public const UInt16 Aead = 15;

    #endregion

    #region Properties

    public ScriptedNtpV5Server  Server        { get; }
    public ManualClock          Clock         { get; }
    public NTSClient            Client        { get; }

    public Byte[]               C2SKey        { get; } = RandomNumberGenerator.GetBytes(32);
    public Byte[]               S2CKey        { get; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// The cookies of the key exchange, each 64 random octets.
    /// </summary>
    public IReadOnlyList<Byte[]> Cookies      { get; }

    /// <summary>
    /// The key exchange: NTPv5 (0x8001), AES-SIV-CMAC-256, the cookies, and the scripted
    /// server's address and port.
    /// </summary>
    public NTSKE_Response       KeyExchange   { get; }

    /// <summary>
    /// What the server answers each request with. Set by the test, read per request.
    /// </summary>
    public Func<ReceivedNtpV5Request, IEnumerable<ScriptedDatagram>> Script { get; set; } = _ => [];

    /// <summary>
    /// The client's T1 and T4.
    /// </summary>
    public DateTime             Now
        => Clock.GetUtcNow().UtcDateTime;

    #endregion

    #region Constructor(s)

    public NTPv5ClientHarness(Int32            CookieCount         = 8,
                              DateTimeOffset?  Now                 = null,
                              UInt64?          OwnReferenceId      = null)
    {

        Server       = new ScriptedNtpV5Server(request => Script(request));
        Clock        = new ManualClock(Now ?? DefaultNow);

        Cookies      = Enumerable.Range(0, CookieCount).
                                  Select(_ => RandomNumberGenerator.GetBytes(64)).
                                  ToArray();

        var port     = Server.Port.ToUInt16();

        KeyExchange  = new NTSKE_Response(
                           [
                               new NTSKE_Record(true, NTSKE_RecordTypes.NTSNextProtocolNegotiation, [ 0x80, 0x01 ]),
                               new NTSKE_Record(true, NTSKE_RecordTypes.AEADAlgorithmNegotiation,   [ 0x00, (Byte) Aead ]),
                               .. Cookies.Select(cookie => new NTSKE_Record(false, NTSKE_RecordTypes.NewCookieForNTPv4, cookie)),
                               NTSKE_Record.NTPv4ServerNegotiation(System.Text.Encoding.ASCII.GetBytes("127.0.0.1")),
                               NTSKE_Record.NTPv4PortNegotiation([ (Byte) (port >> 8), (Byte) port ]),
                               NTSKE_Record.EndOfMessage
                           ],
                           C2SKey.ToArray(),
                           S2CKey.ToArray()
                       );

        Client       = new NTSClient(DomainName.Parse("127.0.0.1"),
                                     NTP_Port:             Server.Port,
                                     IPVersionPreference:  IPVersionPreference.IPv4Only,
                                     Timeout:              TimeSpan.FromSeconds(2),
                                     TimeProvider:         Clock) {
                           NTPv5OwnReferenceId = OwnReferenceId
                       };

    }

    #endregion


    #region Query(NTS = false, Timeout = null, ...)

    /// <summary>
    /// One NTPv5 query of the client: plain, or under the key exchange.
    /// </summary>
    public Task<NTPv5QueryResult> Query(Boolean                                                       NTS                    = false,
                                        TimeSpan?                                                     Timeout                = null,
                                        NTPv5Timescale          Timescale              = NTPv5Timescale.UTC,
                                        Boolean                                                       AcceptUnsynchronized   = false,
                                        Boolean                                                       RequestCorrection      = false,
                                        NTPServerAccessState?                                         AccessState            = null,
                                        NTPv5UsabilityLimits?   Limits                 = null,
                                        NTPv5CorrectionParameters? CorrectionParameters = null)

        => Client.QueryNTPv5(Timeout:               Timeout ?? TimeSpan.FromSeconds(2),
                             NTSKEResponse:         NTS ? KeyExchange : null,
                             Timescale:             Timescale,
                             AcceptUnsynchronized:  AcceptUnsynchronized,
                             RequestCorrection:     RequestCorrection,
                             AccessState:           AccessState,
                             Limits:                Limits,
                             CorrectionParameters:  CorrectionParameters);

    #endregion


    #region Answers

    /// <summary>
    /// A valid, usable response to the request, its receive and transmit time the client's clock
    /// plus the given offset - so that the client measures exactly that offset - and then changed
    /// as the test wants it.
    /// </summary>
    public RawNtpV5Packet Answer(ReceivedNtpV5Request     Request,
                                 TimeSpan                 Offset,
                                 Action<RawNtpV5Packet>?  Change    = null,
                                 TimeSpan?                Transmit  = null)
    {

        var response = RawNtpV5Responses.Answer(Request.Packet!,
                                                Now + Offset,
                                                Now + Offset + (Transmit ?? TimeSpan.Zero));

        Change?.Invoke(response);

        return response;

    }

    /// <summary>
    /// <see cref="Answer"/> as octets, for a plain request.
    /// </summary>
    public Byte[] Plain(ReceivedNtpV5Request     Request,
                        TimeSpan                 Offset,
                        Action<RawNtpV5Packet>?  Change = null)

        => Answer(Request, Offset, Change).Write();

    /// <summary>
    /// <see cref="Answer"/> sealed for an NTS request: the request's Unique Identifier echoed,
    /// the authenticator under the S2C key, and the given cookies in it.
    /// </summary>
    public Byte[] Sealed(ReceivedNtpV5Request                  Request,
                         TimeSpan                              Offset,
                         Action<RawNtpV5Packet>?               Change              = null,
                         Int32                                 NewCookies          = 1,
                         Byte[]?                               Key                 = null,
                         Byte[]?                               UniqueIdentifier    = null,
                         Boolean                               EchoTheIdentifier   = true,
                         IEnumerable<RawNtpV5ExtensionField>?  AfterAuthenticator  = null)

        => RawNtpV5Responses.Sealed(Answer(Request, Offset, Change),
                                    EchoTheIdentifier ? UniqueIdentifier ?? UniqueIdentifierOf(Request) : null,
                                    Aead,
                                    Key ?? S2CKey,
                                    Enumerable.Range(0, NewCookies).Select(_ => RandomNumberGenerator.GetBytes(64)),
                                    AfterAuthenticator);

    /// <summary>
    /// The Unique Identifier of an NTS request.
    /// </summary>
    public static Byte[] UniqueIdentifierOf(ReceivedNtpV5Request Request)
        => Request.Packet!.Find(RawNtpV5Nts.UniqueIdentifier)!.Data;

    /// <summary>
    /// Datagrams to answer with, in order, from the server's port.
    /// </summary>
    public static IEnumerable<ScriptedDatagram> Send(params Byte[][] Datagrams)
        => Datagrams.Select(datagram => new ScriptedDatagram(datagram));

    #endregion


    #region The first request

    /// <summary>
    /// The first request the server received, read by this suite.
    /// </summary>
    public ReceivedNtpV5Request FirstRequest
    {
        get
        {

            var requests = Server.Requests;

            NUnit.Framework.Assert.That(requests, NUnit.Framework.Is.Not.Empty, "the client sent no request");

            return requests[0];

        }
    }

    #endregion


    public async ValueTask DisposeAsync()
    {
        await Client.DisposeAsync();
        await Server.DisposeAsync();
    }

}
