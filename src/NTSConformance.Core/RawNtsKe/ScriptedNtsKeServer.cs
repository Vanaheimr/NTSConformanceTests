using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

using org.GraphDefined.Vanaheimr.Hermod;

using NTSConformance.Core.Fixtures;

namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// One connection as the server saw it: what the client sent, and what was sent back.
/// </summary>
/// <param name="Records">
/// The decoded request, or null when it could not be decoded — which is itself worth seeing.
/// </param>
/// <param name="Bytes">The request exactly as it arrived, for assertions the decoder would hide.</param>
public sealed record CapturedNtsKeRequest(List<RawNtsKeRecord>?  Records,
                                          Byte[]                 Bytes,
                                          String?                DecodeError,
                                          String?                NegotiatedAlpn)
{

    public IEnumerable<RawNtsKeRecord> RecordsOfType(UInt16 RecordType)
        => Records?.Where(record => record.RecordType == RecordType) ?? [];

    public RawNtsKeRecord? FirstRecordOfType(UInt16 RecordType)
        => Records?.FirstOrDefault(record => record.RecordType == RecordType);

    /// <summary>
    /// Whether a record of the given type is present at all.
    /// </summary>
    public Boolean Contains(UInt16 RecordType)
        => Records?.Any(record => record.RecordType == RecordType) == true;

    /// <summary>
    /// The 16-bit values in a record's body, for the two list-valued record types.
    /// </summary>
    public UInt16[] UInt16Body(UInt16 RecordType)
    {

        var record = FirstRecordOfType(RecordType);

        if (record is null)
            return [];

        var values = new UInt16[record.Body.Length / 2];

        for (var i = 0; i < values.Length; i++)
            values[i] = (UInt16) ((record.Body[i * 2] << 8) | record.Body[i * 2 + 1]);

        return values;

    }


    public override String ToString()
    {

        if (Records is null)
            return $"undecodable request ({DecodeError}): {Bytes.Length} octets\n{Core.Bytes.Dump(Bytes)}";

        return $"request over ALPN {NegotiatedAlpn ?? "(none)"}, {Records.Count} records:\n" +
               String.Join("\n", Records.Select(record => $"  {record}" +
                                                          (record.Body.Length > 0 ? $" = {Core.Bytes.ToHex(record.Body)}" : "")));

    }

}


/// <summary>
/// An NTS-KE server that keeps what the client sent and answers with whatever the test says.
///
/// <para>
/// The counterpart to <see cref="RawNtsKeClient"/>, and the half that was missing. Everything
/// else in this suite observes Norn's <em>server</em>: a hand-built record stream goes in, the
/// reply is decoded, and the assertion is on what came back. Nothing terminated TLS on the far
/// side of Norn's <em>client</em>, so no test could say what the client actually put on the wire
/// — only what a server happened to make of it. That gap has bitten once already: the claim that
/// Norn's client omits IANA record 1024 when it is not offering AES-128-GCM-SIV had to be dropped
/// from the conformance suite, because a server must ignore that record under another algorithm
/// anyway and a client that sent it always would have looked identical.
/// </para>
/// <para>
/// Built on <see cref="SslStream"/>, which puts SChannel on the other end of a BouncyCastle
/// handshake. That is the same reason <see cref="RawNtsKeClient"/> uses it, and it has earned its
/// keep before: every TLS stack in this suite has at some point refused something the others
/// accepted.
/// </para>
/// <para>
/// It answers, rather than only listening, because a client that gets no usable reply stops
/// before the interesting part. <see cref="Mirror"/> is the default and is a plausible server:
/// it agrees to the client's first offered algorithm, echoes record 1024 when asked for it, and
/// hands out one cookie — enough for Norn's client to accept the exchange and report what it
/// negotiated. A test that wants an error, a warning or a malformed reply supplies its own.
/// </para>
/// </summary>
public sealed class ScriptedNtsKeServer : IAsyncDisposable
{

    #region Data

    /// <summary>
    /// The ALPN protocol RFC 8915 § 4 assigns to NTS-KE.
    /// </summary>
    public static readonly SslApplicationProtocol NtsKeAlpn = new ("ntske/1");

    private readonly TcpListener                                            listener;
    private readonly System.Security.Cryptography.X509Certificates.X509Certificate2 certificate;
    private readonly Func<CapturedNtsKeRequest, Byte[]?>                    respond;
    private readonly CancellationTokenSource                                shutdown = new ();
    private readonly Lock                                                   requestLock = new ();
    private readonly List<CapturedNtsKeRequest>                             requests = [];
    private readonly List<String>                                           failures = [];
    private readonly Task                                                   acceptLoop;
    private readonly Boolean                                                offerAlpn;
    private readonly SslProtocols                                           enabledSslProtocols;
    private          Int32                                                  connectionsClosedWithoutRequest;

    #endregion

    #region Properties

    /// <summary>
    /// The port it actually bound, on the loopback address.
    /// </summary>
    public IPPort Port { get; }

    /// <summary>
    /// Every request received, in order.
    /// </summary>
    public IReadOnlyList<CapturedNtsKeRequest> Requests
    {
        get
        {
            lock (requestLock)
                return [ .. requests ];
        }
    }

    /// <summary>
    /// The most recent request, or null when none has arrived.
    /// </summary>
    public CapturedNtsKeRequest? LastRequest
    {
        get
        {
            lock (requestLock)
                return requests.Count > 0 ? requests[^1] : null;
        }
    }

    /// <summary>
    /// Handshake and I/O failures, which a test needs when no request arrived: a client that
    /// refused the certificate and a client that never connected look the same from the
    /// <see cref="Requests"/> list alone.
    /// </summary>
    public IReadOnlyList<String> Failures
    {
        get
        {
            lock (requestLock)
                return [ .. failures ];
        }
    }

    /// <summary>
    /// Connections whose TLS handshake completed and on which the client then sent nothing.
    /// </summary>
    /// <remarks>
    /// The shape of a client that inspected the handshake and walked away — which is what one
    /// should do when the server never selected <c>ntske/1</c>. It is deliberately not in
    /// <see cref="Requests"/>: a test asserting that nothing was sent must be able to fail.
    /// </remarks>
    public Int32 ConnectionsClosedWithoutRequest
    {
        get
        {
            lock (requestLock)
                return connectionsClosedWithoutRequest;
        }
    }

    #endregion

    #region Constructor(s)

    private ScriptedNtsKeServer(TcpListener                                                          Listener,
                                System.Security.Cryptography.X509Certificates.X509Certificate2       Certificate,
                                Func<CapturedNtsKeRequest, Byte[]?>                                  Respond,
                                Boolean                                                              OfferAlpn,
                                SslProtocols                                                         EnabledSslProtocols)
    {

        this.listener             = Listener;
        this.certificate          = Certificate;
        this.respond              = Respond;
        this.offerAlpn            = OfferAlpn;
        this.enabledSslProtocols  = EnabledSslProtocols;
        this.Port         = IPPort.Parse(((IPEndPoint) Listener.LocalEndpoint).Port);
        this.acceptLoop   = Task.Run(AcceptLoop);

    }

    #endregion

    #region (static) Start(...)

    /// <summary>
    /// Bind a loopback port and start accepting.
    /// </summary>
    /// <param name="Certificate">
    /// The certificate to present. Left null a fresh one for <c>nts-ke.test</c> is generated,
    /// which is all a test needs unless the certificate itself is the subject.
    /// </param>
    /// <param name="Respond">
    /// What to reply with, given the request. Returning null closes the connection without
    /// sending anything — the shape of a server that detects a bad request and hangs up.
    /// Defaults to <see cref="Mirror"/>.
    /// </param>
    /// <param name="OfferAlpn">
    /// Whether to select <c>ntske/1</c>. Off lets a test see what Norn's client does with a
    /// server that completes the handshake without naming the protocol.
    /// </param>
    /// <param name="EnabledSslProtocols">
    /// Which TLS versions to accept. Defaults to TLS 1.3, which is the only one RFC 8915 § 3
    /// permits; naming an older one is how a test finds out whether a client will be talked down
    /// to it.
    /// </param>
    public static ScriptedNtsKeServer Start(TestCertificate?                      Certificate           = null,
                                            Func<CapturedNtsKeRequest, Byte[]?>?  Respond               = null,
                                            Boolean                               OfferAlpn             = true,
                                            SslProtocols?                         EnabledSslProtocols   = null)
    {

        // Port 0 and read back what was bound. Norn's server cannot do this — hence FreePort and
        // its retry loop — but a TcpListener can, so there is no window for another process to
        // take the port in between.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        return new ScriptedNtsKeServer(
                   listener,
                   (Certificate ?? TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ])).ToDotNetWithPrivateKey(),
                   Respond ?? Mirror,
                   OfferAlpn,
                   EnabledSslProtocols ?? SslProtocols.Tls13
               );

    }

    #endregion

    #region Mirror(Request)

    /// <summary>
    /// A plausible answer: the protocol and the client's first offered algorithm agreed, record
    /// 1024 echoed if the client claimed it and algorithm 30 was chosen, and one cookie.
    /// </summary>
    /// <remarks>
    /// Enough for Norn's client to accept the exchange, which is the point — the assertion under
    /// test is on the request, and a client that abandons the exchange never finishes sending
    /// one. The cookie is sixteen fixed octets and decrypts to nothing; a test that wants to go
    /// on and query the time wants a real Norn server, not this.
    /// </remarks>
    public static Byte[] Mirror(CapturedNtsKeRequest Request)
    {

        var offered    = Request.UInt16Body(RawNtsKeRecordTypes.AeadAlgorithmNegotiation);
        var algorithm  = offered.Length > 0 ? offered[0] : (UInt16) 15;

        var records    = new List<RawNtsKeRecord> {
                             RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                             RawNtsKeRecord.AeadAlgorithmNegotiation(algorithm)
                         };

        if (algorithm == 30 &&
            Request.Contains(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext))
        {
            records.Add(RawNtsKeRecord.CompliantAes128GcmSivExporterContext());
        }

        records.Add(RawNtsKeRecord.NewCookieForNtpv4([ 0x4E, 0x54, 0x53, 0x43, 0x4F, 0x4F, 0x4B, 0x49,
                                                       0x45, 0x50, 0x4C, 0x41, 0x43, 0x45, 0x48, 0x4F ]));
        records.Add(RawNtsKeRecord.EndOfMessage());

        return RawNtsKeCodec.Encode(records);

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
                return;
            }

            // Not awaited: a second connection must not wait on the first, and a client that
            // opens one and abandons it must not stop the listener.
            _ = Task.Run(() => Serve(client));

        }

    }


    private async Task Serve(TcpClient Client)
    {

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));

        try
        {

            using (Client)
            await using (var tlsStream = new SslStream(Client.GetStream(), leaveInnerStreamOpen: false))
            {

                var options = new SslServerAuthenticationOptions {
                                  ServerCertificate     = certificate,
                                  EnabledSslProtocols   = enabledSslProtocols,
                                  ClientCertificateRequired = false
                              };

                if (offerAlpn)
                    options.ApplicationProtocols = [ NtsKeAlpn ];

                await tlsStream.AuthenticateAsServerAsync(options, timeout.Token);

                var negotiatedAlpn = tlsStream.NegotiatedApplicationProtocol.Protocol.Length > 0
                                         ? tlsStream.NegotiatedApplicationProtocol.ToString()
                                         : null;

                var received = new MemoryStream();
                var buffer   = new Byte[4096];

                while (true)
                {

                    var read = await tlsStream.ReadAsync(buffer, timeout.Token);

                    if (read == 0)
                        break;

                    received.Write(buffer, 0, read);

                    // RFC 8915 § 4 ends a message at End of Message; waiting past it would block
                    // until the timeout, because the client is waiting for the reply.
                    if (ContainsEndOfMessage(received.ToArray()))
                        break;

                }

                var bytes = received.ToArray();

                // A connection that carried no octet at all is not a request, and recording it as
                // an empty one would be worse than useless: a test asserting that a client sent
                // nothing would fail against a client that did exactly that. Counted separately,
                // because "connected and hung up" and "never connected" are different diagnoses.
                if (bytes.Length == 0)
                {

                    lock (requestLock)
                        connectionsClosedWithoutRequest++;

                    return;

                }

                var decoded  = RawNtsKeCodec.TryDecode(bytes, out var records, out var decodeError);

                var request  = new CapturedNtsKeRequest(
                                   decoded ? records : null,
                                   bytes,
                                   decoded ? null : decodeError,
                                   negotiatedAlpn
                               );

                lock (requestLock)
                    requests.Add(request);

                var response = respond(request);

                if (response is not null)
                {
                    await tlsStream.WriteAsync(response, timeout.Token);
                    await tlsStream.FlushAsync(timeout.Token);
                }

            }

        }
        catch (Exception e)
        {
            lock (requestLock)
                failures.Add($"{e.GetType().Name}: {e.Message}");
        }

    }


    /// <summary>
    /// Whether a complete NTS-KE message has arrived, i.e. an End of Message record.
    /// </summary>
    private static Boolean ContainsEndOfMessage(Byte[] Buffer)
    {

        var offset = 0;

        while (offset + 4 <= Buffer.Length)
        {

            var recordType = (UInt16) (((Buffer[offset] << 8) | Buffer[offset + 1]) & 0x7FFF);
            var bodyLength = (UInt16)  ((Buffer[offset + 2] << 8) | Buffer[offset + 3]);

            if (recordType == RawNtsKeRecordTypes.EndOfMessage)
                return true;

            offset += 4 + bodyLength;

        }

        return false;

    }

    #endregion

    #region IAsyncDisposable

    public async ValueTask DisposeAsync()
    {

        await shutdown.CancelAsync();

        try
        {
            listener.Stop();
        }
        catch
        { }

        try
        {
            await acceptLoop.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch
        {
            // A teardown must not mask the failure actually under investigation.
        }

        certificate.Dispose();
        shutdown.Dispose();

    }

    #endregion

}
