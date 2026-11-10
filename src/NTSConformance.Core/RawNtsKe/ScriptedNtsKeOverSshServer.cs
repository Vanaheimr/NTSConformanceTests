using System.Collections.Concurrent;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// One request a <see cref="ScriptedNtsKeOverSshServer"/> received in its NTS-KE subsystem.
/// </summary>
/// <param name="Bytes">The octets as they arrived, up to End of Message.</param>
/// <param name="Records">The records, decoded by this suite's codec, or null where they could not be.</param>
/// <param name="DecodeError">Why they could not be decoded, or null.</param>
/// <param name="Session">The SSH session the request came in on — with the exporter of its connection.</param>
public sealed record CapturedNtsKeOverSshRequest(Byte[]                  Bytes,
                                                 List<RawNtsKeRecord>?   Records,
                                                 String?                 DecodeError,
                                                 SshSessionInfo          Session)
{

    /// <summary>
    /// The records of the given type, or an empty sequence.
    /// </summary>
    public IEnumerable<RawNtsKeRecord> RecordsOfType(UInt16 recordType)
        => Records?.Where(record => record.RecordType == recordType) ?? [];

}


/// <summary>
/// An NTS-KE server over SSH that answers whatever it is told to: Hermod's SSH server, serving
/// the NTS-KE subsystem with a script instead of Norn's key exchange — the SSH counterpart of
/// <see cref="ScriptedNtsKeServer"/>.
///
/// It keeps every request, so a test can read what a client sends, and answers each with the
/// octets <c>respond</c> returns for it, as they are: a test can send a response no conformant
/// server would. One client key may log in, and the server's host key is a fresh Ed25519 key
/// that <see cref="ConnectAsync"/> pins.
/// </summary>
public sealed class ScriptedNtsKeOverSshServer : IAsyncDisposable
{

    private readonly SshServer                                     server;
    private readonly ConcurrentQueue<CapturedNtsKeOverSshRequest>  requests;


    private ScriptedNtsKeOverSshServer(SshServer                                     server,
                                       IPPort                                        port,
                                       ISshHostKey                                   hostKey,
                                       ISshHostKey                                   clientKey,
                                       ConcurrentQueue<CapturedNtsKeOverSshRequest>  requests)
    {
        this.server    = server;
        this.requests  = requests;
        Port           = port;
        HostKey        = hostKey.PublicKeyBlob;
        ClientKey      = clientKey;
    }


    /// <summary>
    /// The TCP port the SSH server listens on, on loopback.
    /// </summary>
    public IPPort       Port       { get; }

    /// <summary>
    /// The public key blob of the server's host key.
    /// </summary>
    public Byte[]       HostKey    { get; }

    /// <summary>
    /// The key a client logs in with.
    /// </summary>
    public ISshHostKey  ClientKey  { get; }

    /// <summary>
    /// Every request received so far, in the order they arrived.
    /// </summary>
    public IReadOnlyList<CapturedNtsKeOverSshRequest> Requests
        => [ .. requests ];


    /// <summary>
    /// Start a server on a free loopback port that answers every request in its NTS-KE
    /// subsystem with what <paramref name="respond"/> returns for it — nothing where it
    /// returns null — and then ends the channel.
    /// </summary>
    public static async Task<ScriptedNtsKeOverSshServer> StartAsync(Func<CapturedNtsKeOverSshRequest, Byte[]?>  respond,
                                                                    Int32                                       maxAttempts = 5)
    {

        var hostKey   = SshHostKey.GenerateEd25519();
        var clientKey = SshHostKey.GenerateEd25519();
        var requests  = new ConcurrentQueue<CapturedNtsKeOverSshRequest>();

        async ValueTask Serve(SshSubsystemContext context, CancellationToken cancellationToken)
        {

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

            var bytes     = await RawNtsKeOverSsh.ReadMessageAsync(context.Channel.Input, timeoutCts.Token);
            var decoded   = RawNtsKeCodec.TryDecode(bytes, out var records, out var decodeError);
            var captured  = new CapturedNtsKeOverSshRequest(bytes, decoded ? records : null, decodeError, context.Session);

            requests.Enqueue(captured);

            var response  = respond(captured);

            if (response is not null)
                await context.Channel.SendDataAsync(response, cancellationToken);

        }

        for (var attempt = 1; ; attempt++)
        {

            IPPort port;

            using (var reservation = FreePort.ReserveTcp())
                port = reservation.Port;

            var server = new SshServer(
                             new SshServerOptions {
                                 HostKeys       = [ hostKey ],
                                 Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob),
                                 Subsystems     = (session, name, cancellationToken) => ValueTask.FromResult<SshSubsystemHandler?>(
                                                                                            name == RawNtsKeOverSsh.SubsystemName
                                                                                                ? Serve
                                                                                                : null
                                                                                        )
                             }
                         );

            try
            {
                await server.StartAsync(new IPSocket(IPv4Address.Localhost, port));
                return new ScriptedNtsKeOverSshServer(server, port, hostKey, clientKey, requests);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse &&
                                            attempt < maxAttempts)
            {
                await server.DisposeAsync();
                await Task.Delay(TimeSpan.FromMilliseconds(50 * attempt));
            }

        }

    }


    /// <summary>
    /// A server that answers every request with the given records, whatever it was asked.
    /// </summary>
    public static Func<CapturedNtsKeOverSshRequest, Byte[]?> Reply(params RawNtsKeRecord[] records)
        => _ => RawNtsKeCodec.Encode(records);


    /// <summary>
    /// An SSH connection to this server with <see cref="ClientKey"/>, its host key pinned.
    /// </summary>
    public ValueTask<SshClient> ConnectAsync(CancellationToken cancellationToken = default)
    {

        var hostKey = HostKey;

        return SshClient.ConnectAsync("127.0.0.1",
                                      Port.ToUInt16(),
                                      new SshClientOptions {
                                          Username       = "ntske",
                                          Credentials    = [ ClientKey ],
                                          VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey)
                                      },
                                      cancellationToken);

    }


    public ValueTask DisposeAsync()
        => server.DisposeAsync();

}
