using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Core.Fixtures;

/// <summary>
/// Runs a real Norn <c>NTSServer</c> on loopback for the duration of a fixture, and hands
/// out clients wired to it.
///
/// Two details worth knowing:
///
/// <para>
/// <c>NTSServer</c> takes its ports as constructor arguments and exposes no "actually
/// bound port" property, so it cannot bind port 0 and report back. Ports are therefore
/// pre-reserved and the whole start sequence is retried if the reservation is lost — see
/// <see cref="FreePort"/>.
/// </para>
///
/// <para>
/// <c>MasterKeysFilePath</c> is always null. Left at its default the server appends its
/// rotating cookie master keys to <c>masterKeys.json</c> in the working directory, which
/// would leak state between test runs and, worse, persist secrets from a test process.
/// </para>
/// </summary>
public sealed class NornServerFixture : IAsyncDisposable
{

    private NornServerFixture(NTSServer server, IPPort ntsKePort, IPPort ntpPort)
    {
        Server     = server;
        NTSKEPort  = ntsKePort;
        NTPPort    = ntpPort;
    }


    public NTSServer Server    { get; }
    public IPPort    NTSKEPort { get; }
    public IPPort    NTPPort   { get; }


    /// <summary>The certificate the NTS-KE endpoint presents, when one was injected.</summary>
    public TestCertificate? Certificate { get; private init; }


    /// <summary>Start a server on free ports.</summary>
    /// <param name="masterKeyLifetime">Shorten to exercise rotation.</param>
    /// <param name="masterKeyRotationGracePeriod">How long superseded keys stay acceptable.</param>
    /// <param name="certificate">
    /// A stable certificate for the NTS-KE endpoint. Without one Norn mints a fresh
    /// self-signed certificate per connection, which no external client can be told to trust
    /// in advance.
    /// </param>
    /// <param name="externalHostName">
    /// The host name to advertise in the NTPv4 Server Negotiation record. Defaults to
    /// localhost; interop clients outside this machine need a name or address they can reach.
    /// </param>
    /// <param name="advertisedNTPPort">
    /// The port to advertise in the NTPv4 Port Negotiation record, when it should differ from
    /// the port the server actually listens on. Only a divergence between the two makes it
    /// observable whether a client follows the record or ignores it.
    /// </param>
    /// <param name="listenIPAddress">
    /// The local address to listen on. Left null the server picks its own default, which is
    /// IPv4 0.0.0.0; <c>IPvXAddress.Any</c> serves both address families.
    /// </param>
    /// <param name="timeProvider">
    /// The clock the server reads and reports. Left null it reads the real one.
    /// </param>
    /// <param name="clockResolution">
    /// The clock granularity to report, overriding what the server measures.
    /// </param>
    public static Task<NornServerFixture> StartAsync(TimeSpan?        masterKeyLifetime            = null,
                                                    TimeSpan?        masterKeyRotationGracePeriod  = null,
                                                    TestCertificate? certificate                   = null,
                                                    String?          externalHostName              = null,
                                                    IPPort?          advertisedNTPPort             = null,
                                                    IIPAddress?      listenIPAddress               = null,
                                                    TimeProvider?    timeProvider                  = null,
                                                    TimeSpan?        clockResolution               = null)

        => FreePort.WithFreePorts(async (tcpPort, udpPort) => {

               var host   = externalHostName  ?? "localhost";
               var port   = advertisedNTPPort ?? udpPort;

               var server = new NTSServer(
                                NTSKEPort:                     tcpPort,
                                NTSPort:                       udpPort,
                                ExternalURLs:                  [ URL.Parse($"udp://{host}:{port}") ],
                                MasterKeysFilePath:            null,
                                MasterKeyLifetime:             masterKeyLifetime,
                                MasterKeyRotationGracePeriod:  masterKeyRotationGracePeriod,
                                TLSCertificate:                certificate?.Certificate,
                                TLSPrivateKey:                 certificate?.PrivateKey,
                                ListenIPAddress:               listenIPAddress,
                                TimeProvider:                  timeProvider,
                                ClockResolution:               clockResolution
                            );

               await server.Start();

               return new NornServerFixture(server, tcpPort, udpPort) { Certificate = certificate };

           });


    /// <summary>
    /// A client pointed at this server, accepting its self-signed certificate.
    ///
    /// IPv4 is forced: the client prefers IPv6 by default, and the server's default
    /// <c>ListenIPAddress</c> is the IPv4 wildcard.
    /// </summary>
    /// <param name="timeout">How long the client waits for each leg.</param>
    /// <param name="timeProvider">
    /// The clock the client stamps its requests from — independent of the server's, which is
    /// how a client-side clock can be checked against a server that keeps correct time.
    /// </param>
    public NTSClient CreateClient(TimeSpan?      timeout        = null,
                                  TimeProvider?  timeProvider   = null)

        => new (DomainName.Localhost,
                NTSKE_Port:                  NTSKEPort,
                NTP_Port:                    NTPPort,
                IPVersionPreference:         IPVersionPreference.IPv4Only,
                Timeout:                     timeout,
                RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                 => TLSValidationResult.Success(),
                TimeProvider:                timeProvider);


    /// <summary>The measured system clock resolution, for diagnostics.</summary>
    public static String DescribeClockResolution()
        => $"{NTSServer.SystemClockResolution.TotalMilliseconds:F4} ms";


    public async ValueTask DisposeAsync()
    {
        try
        {
            await Server.ShutdownAsync();
        }
        catch
        {
            // A fixture teardown must not mask the failure that is actually under investigation.
        }
    }

}
