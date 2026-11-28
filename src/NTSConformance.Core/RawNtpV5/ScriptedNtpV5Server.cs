using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Hermod;

using NTSConformance.Core.RawNtp;

namespace NTSConformance.Core.RawNtpV5;

/// <summary>
/// One datagram as the scripted server received it: the octets, the message where this suite's
/// reader takes it, and where it came from.
/// </summary>
/// <param name="Octets">The datagram exactly as it arrived.</param>
/// <param name="Packet">The message, where it reads by § 6 and § 7; null where it does not.</param>
/// <param name="Error">Why it does not read, where it does not.</param>
/// <param name="From">The client's address and port.</param>
public sealed record ReceivedNtpV5Request(Byte[]           Octets,
                                          RawNtpV5Packet?  Packet,
                                          String?          Error,
                                          IPEndPoint       From);


/// <summary>
/// A datagram the script answers with.
/// </summary>
/// <param name="Octets">The datagram.</param>
/// <param name="FromAnotherPort">Whether to send it from a second socket on another port, as an
/// off-path sender would: not from the address the request went to.</param>
public sealed record ScriptedDatagram(Byte[]   Octets,
                                      Boolean  FromAnotherPort = false);


/// <summary>
/// An NTPv5 server on the loopback that answers each request with whatever a test scripts:
/// nothing, one datagram, or several - valid, invalid or forged ones in any order. The
/// counterpart of <see cref="RawNtsKe.ScriptedNtsKeServer"/> for the time exchange, and like it
/// written with this suite's own encoder alone, so that what a client under test accepts or
/// refuses is decided against octets it had no hand in.
/// </summary>
public sealed class ScriptedNtpV5Server : IAsyncDisposable
{

    #region Data

    private readonly UdpClient                                                  udp;
    private readonly UdpClient                                                  other;
    private readonly Func<ReceivedNtpV5Request, IEnumerable<ScriptedDatagram>>  script;
    private readonly CancellationTokenSource                                    cts       = new ();
    private readonly ConcurrentQueue<ReceivedNtpV5Request>                      requests  = new ();
    private readonly ConcurrentQueue<Exception>                                 errors    = new ();
    private readonly Task                                                       loop;

    #endregion

    #region Properties

    /// <summary>
    /// The port the server listens on, on 127.0.0.1.
    /// </summary>
    public IPPort                               Port      { get; }

    /// <summary>
    /// Every request received so far, in order.
    /// </summary>
    public IReadOnlyList<ReceivedNtpV5Request>  Requests
        => requests.ToArray();

    /// <summary>
    /// What the script threw, if it threw: a test that sees no answer should know whether
    /// that was the client's doing or its own.
    /// </summary>
    public IReadOnlyList<Exception>             ScriptErrors
        => errors.ToArray();

    #endregion

    #region Constructor(s)

    public ScriptedNtpV5Server(Func<ReceivedNtpV5Request, IEnumerable<ScriptedDatagram>> Script)
    {

        this.script  = Script;
        this.udp     = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        this.other   = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        this.Port    = IPPort.Parse(((IPEndPoint) udp.Client.LocalEndPoint!).Port);
        this.loop    = Task.Run(RunAsync);

    }

    #endregion


    #region (private) RunAsync()

    private async Task RunAsync()
    {

        while (!cts.IsCancellationRequested)
        {

            UdpReceiveResult received;

            try
            {
                received = await udp.ReceiveAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                // Windows reports an ICMP port unreachable for an earlier answer - to a client
                // that had already closed its socket - on the next receive.
                continue;
            }

            var reads    = RawNtpV5Packet.TryRead(received.Buffer, out var packet, out var error);
            var request  = new ReceivedNtpV5Request(received.Buffer, reads ? packet : null, error, received.RemoteEndPoint);

            requests.Enqueue(request);

            ScriptedDatagram[] answers;

            try
            {
                answers = script(request).ToArray();
            }
            catch (Exception e)
            {
                errors.Enqueue(e);
                continue;
            }

            foreach (var answer in answers)
            {
                try
                {
                    await (answer.FromAnotherPort ? other : udp).SendAsync(answer.Octets, received.RemoteEndPoint, cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception e)
                {
                    errors.Enqueue(e);
                }
            }

        }

    }

    #endregion

    #region DisposeAsync()

    public async ValueTask DisposeAsync()
    {

        cts.Cancel();

        try
        {
            await loop;
        }
        catch
        { }

        udp.  Dispose();
        other.Dispose();
        cts.  Dispose();

    }

    #endregion

}


/// <summary>
/// Responses of draft-ietf-ntp-ntpv5-10 § 10 to a request, built by this suite: a valid one to
/// start from, which a test then breaks in exactly the one place it is about, and the NTS
/// sealing of RFC 8915 § 5.7 over it.
/// </summary>
public static class RawNtpV5Responses
{

    /// <summary>
    /// The NTP epoch, 1900-01-01T00:00:00Z, where era 0 begins.
    /// </summary>
    public static readonly DateTime Epoch = new (1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>
    /// 2^32 seconds, the length of an era.
    /// </summary>
    public const Int64 SecondsPerEra = 1L << 32;


    #region ToTimestamp(Time)

    /// <summary>
    /// A date as § 6 carries it: the era, and the 64-bit timestamp within it - 32 bits of
    /// seconds and 32 of fraction.
    /// </summary>
    /// <remarks>
    /// The fraction is rounded up, to the next of the 2^32 steps of a second: a reader that
    /// rounds down to its 100 ns ticks, as most do, then gets the date back to the tick - and a
    /// test can compare an offset exactly. Rounded down here as well, every fraction would come
    /// back a tick short.
    /// </remarks>
    public static (Byte Era, UInt64 Timestamp) ToTimestamp(DateTime Time)
    {

        var ticks     = (Time.ToUniversalTime() - Epoch).Ticks;
        var seconds   = ticks / TimeSpan.TicksPerSecond;
        var fraction  = ((UInt64) (ticks % TimeSpan.TicksPerSecond) * 0x1_0000_0000UL + (UInt64) TimeSpan.TicksPerSecond - 1) /
                        (UInt64) TimeSpan.TicksPerSecond;

        return ((Byte) (seconds / SecondsPerEra),
                ((UInt64) (seconds % SecondsPerEra) << 32) | fraction);

    }

    #endregion

    #region Answer(Request, Receive, Transmit = null)

    /// <summary>
    /// A valid, usable response to the request, as § 10 has a synchronized server of stratum 1
    /// form it: version 5, mode 4, the request's timescale and client cookie, a server cookie,
    /// no flags, the era of the receive timestamp, root delay and dispersion of a millisecond,
    /// a poll of 6, and the Draft Identification echoed where the request carried one. No other
    /// field of the request is answered.
    /// </summary>
    /// <param name="Request">The request answered.</param>
    /// <param name="Receive">The server's receive time.</param>
    /// <param name="Transmit">The server's transmit time; by default the receive time.</param>
    public static RawNtpV5Packet Answer(RawNtpV5Packet  Request,
                                        DateTime        Receive,
                                        DateTime?       Transmit = null)
    {

        var (era, receive)  = ToTimestamp(Receive);
        var (_,   transmit) = ToTimestamp(Transmit ?? Receive);

        var response = new RawNtpV5Packet {
                           Version            = 5,
                           Mode               = 4,
                           Stratum            = 1,
                           Poll               = 6,
                           Precision          = -20,
                           RootDelay          = RawTime32.RoundedUp(TimeSpan.FromMilliseconds(1)),
                           RootDispersion     = RawTime32.RoundedUp(TimeSpan.FromMilliseconds(1)),
                           Timescale          = Request.Timescale,
                           Era                = era,
                           Flags              = 0,
                           ServerCookie       = BinaryPrimitives.ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8)),
                           ClientCookie       = Request.ClientCookie,
                           ReceiveTimestamp   = receive,
                           TransmitTimestamp  = transmit
                       };

        if (Request.Find(RawNtpV5Draft.DraftIdentification) is RawNtpV5ExtensionField draft)
            response.ExtensionFields.Add(draft);

        return response;

    }

    #endregion

    #region Sealed(Response, UniqueIdentifier, AeadAlgorithm, S2CKey, Cookies, ...)

    /// <summary>
    /// An NTS response of RFC 8915 § 5.7 to the given one: the Unique Identifier of the request,
    /// then the authenticator under the server-to-client key over the header and every field
    /// before it, with the given cookies encrypted in it as NTS Cookie fields, then whatever is to
    /// go unauthenticated after it.
    /// </summary>
    /// <param name="Response">The response without NTS; it is changed.</param>
    /// <param name="UniqueIdentifier">The Unique Identifier to echo; null to leave it out.</param>
    /// <param name="AeadAlgorithm">The algorithm of the key exchange.</param>
    /// <param name="S2CKey">The key to seal it under.</param>
    /// <param name="Cookies">The new cookies, encrypted.</param>
    /// <param name="AfterAuthenticator">Fields after the authenticator, outside it.</param>
    public static Byte[] Sealed(RawNtpV5Packet                         Response,
                                Byte[]?                                UniqueIdentifier,
                                UInt16                                 AeadAlgorithm,
                                Byte[]                                 S2CKey,
                                IEnumerable<Byte[]>                    Cookies,
                                IEnumerable<RawNtpV5ExtensionField>?   AfterAuthenticator = null)
    {

        if (UniqueIdentifier is not null)
            Response.ExtensionFields.Add(new RawNtpV5ExtensionField(RawNtpV5Nts.UniqueIdentifier, UniqueIdentifier));

        var plaintext = Cookies.SelectMany(cookie => RawNtsExtensionFields.EncodeField(RawNtsExtensionFields.NtsCookie(cookie))).
                                ToArray();

        Response.ExtensionFields.Add(RawNtpV5Nts.Authenticator(AeadAlgorithm, S2CKey, Response.Write(), plaintext));
        Response.ExtensionFields.AddRange(AfterAuthenticator ?? []);

        return Response.Write();

    }

    #endregion

}
