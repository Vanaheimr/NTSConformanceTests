using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// The outcome of one raw NTS-KE exchange.
/// </summary>
/// <param name="Records">
/// The records the server sent back, or null when it sent nothing at all.
/// </param>
/// <param name="ClosedWithoutResponse">
/// True when the TLS handshake completed but the server closed the connection without
/// sending a single record. This is the shape of a server that detects a bad request and
/// simply hangs up instead of saying why.
/// </param>
public sealed record RawNtsKeExchange(Boolean                    HandshakeSucceeded,
                                      String?                    NegotiatedAlpn,
                                      SslProtocols               TlsVersion,
                                      List<RawNtsKeRecord>?      Records,
                                      Boolean                    ClosedWithoutResponse,
                                      String?                    Diagnosis)
{

    /// <summary>
    /// The records of the given type, or an empty sequence.
    /// </summary>
    public IEnumerable<RawNtsKeRecord> RecordsOfType(UInt16 recordType)
        => Records?.Where(record => record.RecordType == recordType) ?? [];

    public RawNtsKeRecord? FirstRecordOfType(UInt16 recordType)
        => Records?.FirstOrDefault(record => record.RecordType == recordType);

    /// <summary>
    /// The Error record's code, or null when the server sent no Error record.
    /// </summary>
    public UInt16? ErrorCode
    {
        get
        {

            var error = FirstRecordOfType(RawNtsKeRecordTypes.Error);

            return error is not null && error.Body.Length >= 2
                       ? (UInt16) ((error.Body[0] << 8) | error.Body[1])
                       : null;

        }
    }


    /// <summary>
    /// A readable summary for a failure message.
    /// </summary>
    public override String ToString()
    {

        var builder = new StringBuilder();

        builder.AppendLine($"handshake: {(HandshakeSucceeded ? "completed" : "failed")}" +
                           (NegotiatedAlpn is not null ? $", ALPN {NegotiatedAlpn}" : ", no ALPN") +
                           $", {TlsVersion}");

        if (Diagnosis is not null)
            builder.AppendLine($"diagnosis: {Diagnosis}");

        if (ClosedWithoutResponse)
            builder.AppendLine("the server closed the connection without sending any record");

        if (Records is not null)
        {
            builder.AppendLine($"records received ({Records.Count}):");
            foreach (var record in Records)
                builder.AppendLine($"  {record}" +
                                   (record.Body.Length > 0 ? $" = {Bytes.ToHex(record.Body)}" : ""));
        }

        return builder.ToString();

    }

}


/// <summary>
/// A minimal NTS-KE client that sends a caller-supplied record stream and reports what came
/// back — including "nothing at all", which is a distinct and important outcome.
///
/// Built on .NET's <see cref="SslStream"/> rather than BouncyCastle. That is possible because
/// these tests never need the TLS exporter (the reason Norn uses BouncyCastle at all), and it
/// is desirable because it puts a completely independent TLS stack on the other end of the
/// handshake.
/// </summary>
public static class RawNtsKeClient
{

    /// <summary>
    /// The ALPN protocol RFC 8915 §4 assigns to NTS-KE.
    /// </summary>
    public static readonly SslApplicationProtocol NtsKeAlpn = new ("ntske/1");


    /// <summary>
    /// Connect, hand over <paramref name="requestRecords"/> verbatim, and read the reply.
    /// </summary>
    /// <param name="requestRecords">
    /// Raw octets, so a test can send a stream no conformant encoder would produce.
    /// </param>
    /// <param name="offerAlpn">
    /// Whether to advertise ntske/1. Off lets a test check what the server does without it.
    /// </param>
    public static async Task<RawNtsKeExchange> ExchangeAsync(String             host,
                                                             IPPort             port,
                                                             Byte[]             requestRecords,
                                                             TimeSpan?          timeout        = null,
                                                             Boolean            offerAlpn      = true,
                                                             CancellationToken  cancellationToken = default)
    {

        var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(15);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(effectiveTimeout);

        using var tcpClient = new TcpClient();

        try
        {
            await tcpClient.ConnectAsync(host, port.ToUInt16(), timeoutCts.Token);
        }
        catch (Exception e)
        {
            return new RawNtsKeExchange(false, null, SslProtocols.None, null, false,
                                        $"could not connect to {host}:{port}: {e.Message}");
        }

        await using var sslStream = new SslStream(tcpClient.GetStream(), leaveInnerStreamOpen: false);

        var options = new SslClientAuthenticationOptions {
                          TargetHost                      = host,
                          EnabledSslProtocols             = SslProtocols.Tls13,
                          // The tests drive a self-signed certificate; the PKI is not what is
                          // under test here. Revocation checking has to be switched off as
                          // well as validated away — SChannel otherwise fails the handshake
                          // with CRYPT_E_REVOCATION_OFFLINE (0x80092013) before the callback
                          // gets a say, because a self-signed certificate names no CRL.
                          CertificateRevocationCheckMode  = X509RevocationMode.NoCheck,
                          RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true
                      };

        if (offerAlpn)
            options.ApplicationProtocols = [ NtsKeAlpn ];

        try
        {
            await sslStream.AuthenticateAsClientAsync(options, timeoutCts.Token);
        }
        catch (Exception e)
        {
            return new RawNtsKeExchange(false, null, SslProtocols.None, null, false,
                                        $"the TLS handshake failed: {Describe(e)}");
        }

        var negotiatedAlpn = sslStream.NegotiatedApplicationProtocol.Protocol.Length > 0
                                 ? sslStream.NegotiatedApplicationProtocol.ToString()
                                 : null;

        var tlsVersion     = sslStream.SslProtocol;

        try
        {

            await sslStream.WriteAsync(requestRecords, timeoutCts.Token);
            await sslStream.FlushAsync(timeoutCts.Token);

            var received = new MemoryStream();
            var buffer   = new Byte[4096];

            while (true)
            {

                var read = await sslStream.ReadAsync(buffer, timeoutCts.Token);

                if (read == 0)
                {
                    // The server hung up. With nothing received that is the "logs it and
                    // drops the connection" behaviour; with a partial message it is a
                    // truncated reply.
                    if (received.Length == 0)
                        return new RawNtsKeExchange(true, negotiatedAlpn, tlsVersion, null, true,
                                                    "the server closed the connection without sending anything");

                    break;

                }

                received.Write(buffer, 0, read);

                // Stop as soon as a complete message has arrived; RFC 8915 §4 ends a message
                // at End of Message, and waiting past it would block until the timeout.
                if (ContainsEndOfMessage(received.ToArray()))
                    break;

            }

            var bytes = received.ToArray();

            if (!RawNtsKeCodec.TryDecode(bytes, out var records, out var decodeError))
                return new RawNtsKeExchange(true, negotiatedAlpn, tlsVersion, null, false,
                                            $"the reply could not be decoded: {decodeError}\n{Bytes.Dump(bytes)}");

            return new RawNtsKeExchange(true, negotiatedAlpn, tlsVersion, records, false, null);

        }
        catch (OperationCanceledException)
        {
            return new RawNtsKeExchange(true, negotiatedAlpn, tlsVersion, null, false,
                                        $"the server sent no complete reply within {effectiveTimeout}");
        }
        catch (Exception e)
        {
            return new RawNtsKeExchange(true, negotiatedAlpn, tlsVersion, null, false,
                                        $"the exchange failed: {e.Message}");
        }

    }


    /// <summary>
    /// Flatten an exception chain. TLS failures surface as a terse outer message with the
    /// actual SChannel or OpenSSL cause nested inside, and the outer one alone is useless.
    /// </summary>
    private static String Describe(Exception exception)
    {

        var parts   = new List<String>();
        Exception? e = exception;

        while (e is not null)
        {
            parts.Add($"{e.GetType().Name}: {e.Message}");
            e = e.InnerException;
        }

        return String.Join(" -> ", parts);

    }


    /// <summary>
    /// Whether a complete NTS-KE message has arrived, i.e. an End of Message record.
    /// </summary>
    private static Boolean ContainsEndOfMessage(Byte[] buffer)
    {

        var offset = 0;

        while (offset + 4 <= buffer.Length)
        {

            var recordType = (UInt16) (((buffer[offset] << 8) | buffer[offset + 1]) & 0x7FFF);
            var bodyLength = (UInt16)  ((buffer[offset + 2] << 8) | buffer[offset + 3]);

            if (recordType == RawNtsKeRecordTypes.EndOfMessage)
                return true;

            offset += 4 + bodyLength;

        }

        return false;

    }

}
