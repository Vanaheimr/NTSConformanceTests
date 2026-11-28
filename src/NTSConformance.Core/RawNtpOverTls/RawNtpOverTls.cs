using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Core.RawNtpOverTls;

/// <summary>
/// NTP over TLS after chapter 7 of BSI TR-03109-5, as this suite speaks it: the bare 48-octet
/// NTPv4 header of RFC 5905 Figure 8 in a TLS connection, with no length prefix and no
/// extension fields (§ 7.1.1, REQ.TA.NTP.BuildRequest.30).
///
/// <para>
/// The TLS here is the platform's own <see cref="SslStream"/> - SChannel on Windows, OpenSSL on
/// Linux - and the NTP codec is this suite's, so that neither shares code with Norn, whose two
/// ends both run on BouncyCastle.
/// </para>
/// </summary>
public static class RawNtpOverTls
{

    public const Int32 PacketLength = RawNtpPacket.HeaderLength;


    /// <summary>
    /// Read up to <paramref name="count"/> octets: as many as come until then or the end of the
    /// stream. Returns what was read - fewer when the peer closed first.
    /// </summary>
    public static async Task<Byte[]> ReadUpToAsync(Stream            stream,
                                                   Int32             count,
                                                   CancellationToken cancellationToken)
    {

        var buffer = new Byte[count];
        var read   = 0;

        while (read < count)
        {

            Int32 n;

            try
            {
                n = await stream.ReadAsync(buffer.AsMemory(read, count - read), cancellationToken);
            }
            catch (IOException)
            {
                break;
            }

            if (n == 0)
                break;

            read += n;

        }

        return buffer[..read];

    }

}


/// <summary>
/// A TLS connection to an NTP-over-TLS server, made with <see cref="SslStream"/>.
/// </summary>
public sealed class RawNtpOverTlsConnection : IAsyncDisposable
{

    private readonly TcpClient  tcp;

    public SslStream   Tls                { get; }
    public SslProtocols Protocol          => Tls.SslProtocol;
    public X509Certificate2? ServerCertificate { get; }

    private RawNtpOverTlsConnection(TcpClient tcp, SslStream tls, X509Certificate2? serverCertificate)
    {
        this.tcp               = tcp;
        this.Tls               = tls;
        this.ServerCertificate = serverCertificate;
    }


    /// <summary>
    /// Connect and complete the handshake. Every server certificate is taken; what it was is
    /// in <see cref="ServerCertificate"/>.
    /// </summary>
    public static async Task<RawNtpOverTlsConnection> ConnectAsync(Int32                          port,
                                                                   SslProtocols                   protocols          = SslProtocols.Tls12 | SslProtocols.Tls13,
                                                                   String                         targetHost         = "localhost",
                                                                   X509Certificate2?              clientCertificate  = null,
                                                                   List<SslApplicationProtocol>?  alpn               = null,
                                                                   CancellationToken              cancellationToken  = default)
    {

        var tcp = new TcpClient(AddressFamily.InterNetwork);

        try
        {

            await tcp.ConnectAsync(IPAddress.Loopback, port, cancellationToken);

            X509Certificate2? seen = null;

            var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);

            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                                                    TargetHost                          = targetHost,
                                                    EnabledSslProtocols                 = protocols,
                                                    ApplicationProtocols                = alpn,
                                                    ClientCertificates                  = clientCertificate is null ? null : [ clientCertificate ],
                                                    LocalCertificateSelectionCallback   = clientCertificate is null
                                                                                              ? null
                                                                                              : (sender, host, local, remote, issuers) => clientCertificate,
                                                    RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => {
                                                                                              seen = certificate is null ? null : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                                                                                              return true;
                                                                                          },
                                                    CertificateRevocationCheckMode      = X509RevocationMode.NoCheck
                                                },
                                                cancellationToken);

            return new RawNtpOverTlsConnection(tcp, tls, seen);

        }
        catch
        {
            tcp.Dispose();
            throw;
        }

    }


    /// <summary>
    /// Send one request and read what comes back, up to 48 octets: all of them, fewer where
    /// the server closed first, none where it closed at once.
    /// </summary>
    public async Task<Byte[]> ExchangeAsync(Byte[]            request,
                                            TimeSpan?         timeout            = null,
                                            CancellationToken cancellationToken  = default)
    {

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(10));

        await Tls.WriteAsync(request, cts.Token);
        await Tls.FlushAsync(cts.Token);

        return await RawNtpOverTls.ReadUpToAsync(Tls, RawNtpOverTls.PacketLength, cts.Token);

    }


    public async ValueTask DisposeAsync()
    {
        try { await Tls.DisposeAsync(); } catch { }
        tcp.Dispose();
    }

}


/// <summary>
/// What a client sent to <see cref="ScriptedNtpOverTlsServer"/>, and how.
/// </summary>
public sealed record CapturedNtpOverTlsRequest(Byte[]        Bytes,
                                               RawNtpPacket? Packet,
                                               DateTime      ReceivedAt,
                                               SslProtocols  Protocol,
                                               String        TargetHostName,
                                               String?       NegotiatedAlpn,
                                               String?       ClientCertificateSubject)
{

    /// <summary>
    /// Octets the client sent after the 48 of its request, while the connection was open.
    /// </summary>
    public Int32   OctetsAfterTheRequest  { get; set; }

    /// <summary>
    /// Whether the client closed the connection after it had its response.
    /// </summary>
    public Boolean ClosedByTheClient      { get; set; }

}


/// <summary>
/// An NTP-over-TLS server whose answers a test writes: it records each request, hands it to
/// the script, and sends back exactly what the script returns - a response, a truncated one,
/// one of the wrong mode, or nothing.
/// </summary>
public sealed class ScriptedNtpOverTlsServer : IAsyncDisposable
{

    #region Data

    private readonly TcpListener                                     listener;
    private readonly X509Certificate2                                certificate;
    private readonly Func<CapturedNtpOverTlsRequest, Byte[]?>        respond;
    private readonly SslProtocols                                    protocols;
    private readonly Boolean                                         requireClientCertificate;
    private readonly TimeSpan                                        delay;
    private readonly CancellationTokenSource                         shutdown     = new ();
    private readonly Lock                                            requestLock  = new ();
    private readonly List<CapturedNtpOverTlsRequest>                 requests     = [];
    private readonly List<String>                                    failures     = [];
    private readonly Task                                            acceptLoop;

    #endregion

    #region Properties

    public Int32 Port { get; }

    public IReadOnlyList<CapturedNtpOverTlsRequest> Requests
    {
        get { lock (requestLock) return [ .. requests ]; }
    }

    public CapturedNtpOverTlsRequest? LastRequest
    {
        get { lock (requestLock) return requests.Count > 0 ? requests[^1] : null; }
    }

    public IReadOnlyList<String> Failures
    {
        get { lock (requestLock) return [ .. failures ]; }
    }

    #endregion

    #region Constructor / Start

    private ScriptedNtpOverTlsServer(TcpListener                               listener,
                                     X509Certificate2                          certificate,
                                     Func<CapturedNtpOverTlsRequest, Byte[]?>  respond,
                                     SslProtocols                              protocols,
                                     Boolean                                   requireClientCertificate,
                                     TimeSpan                                  delay)
    {

        this.listener                  = listener;
        this.certificate               = certificate;
        this.respond                   = respond;
        this.protocols                 = protocols;
        this.requireClientCertificate  = requireClientCertificate;
        this.delay                     = delay;
        this.Port                      = ((IPEndPoint) listener.LocalEndpoint).Port;
        this.acceptLoop                = Task.Run(AcceptLoop);

    }


    /// <param name="certificate">The server's certificate (default: a fresh one for "ntp-tls.test").</param>
    /// <param name="respond">The script: the response to a request, or null for none (default: <see cref="Answer"/>).</param>
    /// <param name="protocols">The TLS versions offered (default: 1.2 and 1.3).</param>
    /// <param name="requireClientCertificate">Whether a client certificate is asked for.</param>
    /// <param name="delay">How long to wait before answering.</param>
    public static ScriptedNtpOverTlsServer Start(TestCertificate?                           certificate               = null,
                                                 Func<CapturedNtpOverTlsRequest, Byte[]?>?  respond                   = null,
                                                 SslProtocols?                              protocols                 = null,
                                                 Boolean                                    requireClientCertificate  = false,
                                                 TimeSpan?                                  delay                     = null)
    {

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        return new ScriptedNtpOverTlsServer(listener,
                                            (certificate ?? TestCertificate.Generate("ntp-tls.test", [ "ntp-tls.test", "localhost" ], ipAddresses: [ "127.0.0.1" ])).ToDotNetWithPrivateKey(),
                                            respond ?? (request => Answer(request)),
                                            protocols ?? (SslProtocols.Tls12 | SslProtocols.Tls13),
                                            requireClientCertificate,
                                            delay ?? TimeSpan.Zero);

    }

    #endregion

    #region Answer(Request, Tweak = null, ServerClockOffset = null)

    /// <summary>
    /// A correct RFC 5905 server response to the request: stratum 1, synchronized, the request's
    /// transmit timestamp as origin, and the server's time as receive and transmit - this
    /// machine's clock plus <paramref name="serverClockOffset"/>. <paramref name="tweak"/> may
    /// change anything before it is written.
    /// </summary>
    public static Byte[] Answer(CapturedNtpOverTlsRequest  request,
                                Action<RawNtpPacket>?      tweak              = null,
                                TimeSpan?                  serverClockOffset  = null)
    {

        var now      = DateTime.UtcNow + (serverClockOffset ?? TimeSpan.Zero);
        var received = request.ReceivedAt + (serverClockOffset ?? TimeSpan.Zero);

        var response = new RawNtpPacket {
                           LeapIndicator       = RawNtpLeapIndicator.NoWarning,
                           Version             = 4,
                           Mode                = RawNtpMode.Server,
                           Stratum             = 1,
                           Poll                = request.Packet?.Poll ?? 0,
                           Precision           = -20,
                           RootDelay           = RawNtpTimestamp.SecondsToShort(0.010),
                           RootDispersion      = RawNtpTimestamp.SecondsToShort(0.002),
                           ReferenceTimestamp  = RawNtpTimestamp.FromDateTime(now.AddSeconds(-16)),
                           OriginTimestamp     = request.Packet?.TransmitTimestamp ?? 0,
                           ReceiveTimestamp    = RawNtpTimestamp.FromDateTime(received),
                           TransmitTimestamp   = RawNtpTimestamp.FromDateTime(now)
                       }.WithReferenceIdentifier("GPS");

        tweak?.Invoke(response);

        return RawNtpWriter.WriteHeaderOnly(response);

    }

    #endregion

    #region (private) AcceptLoop() / Serve(Client)

    private async Task AcceptLoop()
    {

        while (!shutdown.IsCancellationRequested)
        {

            TcpClient client;

            try
            {
                client = await listener.AcceptTcpClientAsync(shutdown.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = Task.Run(() => Serve(client));

        }

    }


    private async Task Serve(TcpClient client)
    {

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));

        try
        {

            using (client)
            await using (var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false))
            {

                String? clientCertificateSubject = null;

                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {
                                                        ServerCertificate                   = certificate,
                                                        EnabledSslProtocols                 = protocols,
                                                        ClientCertificateRequired           = requireClientCertificate,
                                                        CertificateRevocationCheckMode      = X509RevocationMode.NoCheck,
                                                        RemoteCertificateValidationCallback = (sender, clientCertificate, chain, errors) => {
                                                                                                  clientCertificateSubject = clientCertificate?.Subject;
                                                                                                  return !requireClientCertificate || clientCertificate is not null;
                                                                                              }
                                                    },
                                                    timeout.Token);

                var bytes      = await RawNtpOverTls.ReadUpToAsync(tls, RawNtpOverTls.PacketLength, timeout.Token);
                var receivedAt = DateTime.UtcNow;

                if (bytes.Length == 0)
                    return;

                var request    = new CapturedNtpOverTlsRequest(bytes,
                                                               RawNtpReader.TryRead(bytes, out var packet, out _, RawNtpReadOptions.Lenient) ? packet : null,
                                                               receivedAt,
                                                               tls.SslProtocol,
                                                               tls.TargetHostName,
                                                               tls.NegotiatedApplicationProtocol.Protocol.Length > 0 ? tls.NegotiatedApplicationProtocol.ToString() : null,
                                                               clientCertificateSubject);

                lock (requestLock)
                    requests.Add(request);

                if (delay > TimeSpan.Zero)
                    await Task.Delay(delay, timeout.Token);

                var response   = respond(request);

                if (response is not null)
                {
                    await tls.WriteAsync(response, timeout.Token);
                    await tls.FlushAsync(timeout.Token);
                }

                // What the client does after its response: a client of one request per
                // connection says nothing more and closes.
                using var linger = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
                linger.CancelAfter(TimeSpan.FromSeconds(1.5));

                try
                {
                    var after = await RawNtpOverTls.ReadUpToAsync(tls, 4096, linger.Token);
                    request.OctetsAfterTheRequest = after.Length;
                    request.ClosedByTheClient     = true;
                }
                catch (OperationCanceledException)
                {
                    request.ClosedByTheClient     = false;
                }

            }

        }
        catch (Exception e)
        {
            lock (requestLock)
                failures.Add($"{e.GetType().Name}: {e.Message}");
        }

    }

    #endregion

    #region DisposeAsync()

    public async ValueTask DisposeAsync()
    {

        await shutdown.CancelAsync();

        try { listener.Stop(); } catch { }

        try { await acceptLoop.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }

        certificate.Dispose();
        shutdown.Dispose();

    }

    #endregion

}
