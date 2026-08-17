using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core.Fixtures;

/// <summary>
/// Runs <c>chronyd</c> inside WSL as an NTS server, so Norn's client can be tested against
/// an independent implementation of RFC 8915 rather than against itself.
///
/// The server lives in WSL and the client on Windows deliberately: WSL2's NAT lets Windows
/// reach the VM on both TCP and UDP, whereas the reverse direction is blocked by Windows
/// Firewall by default. Putting the reference implementation on the reachable side means
/// this works with no firewall changes.
///
/// chronyd is given <c>local stratum 10</c> so it serves time immediately without waiting to
/// synchronise against an upstream source.
/// </summary>
public sealed class ChronyNtsServerFixture : IAsyncDisposable
{

    private const String WorkingDirectory = "/tmp/nts-interop";

    private ChronyNtsServerFixture(String vmAddress, IPPort ntpPort, IPPort ntsKePort, String certificatePath)
    {
        VmAddress        = vmAddress;
        NTPPort          = ntpPort;
        NTSKEPort        = ntsKePort;
        CertificatePath  = certificatePath;
    }


    /// <summary>
    /// The WSL VM's address, reachable from Windows for both TCP and UDP.
    /// </summary>
    public String VmAddress       { get; }

    public IPPort NTPPort         { get; }
    public IPPort NTSKEPort       { get; }

    /// <summary>
    /// Path, inside WSL, of the PEM certificate chronyd presents.
    /// </summary>
    public String CertificatePath { get; }


    /// <summary>
    /// Generate a certificate, write a chronyd configuration and start the daemon.
    /// Returns null when the prerequisites are missing, so callers can Assert.Ignore.
    /// </summary>
    public static async Task<ChronyNtsServerFixture?> StartAsync(TimeSpan? startupTimeout = null)
    {

        if (!Wsl.IsAvailable || !Wsl.HasTool("chronyd") || !Wsl.HasTool("openssl"))
            return null;

        var vmAddress = Wsl.VmAddress;

        if (vmAddress is null)
            return null;

        // chronyd binds inside the VM, so the ports only have to be free there. Picked high
        // and at random to avoid colliding with a system chronyd or a parallel test run.
        var random    = new Random();
        var ntpPort   = random.Next(20000, 30000);
        var ntsKePort = ntpPort + 1;

        var setup = Wsl.Run(
            $"set -e; " +
            $"mkdir -p {WorkingDirectory}; cd {WorkingDirectory}; " +
            $"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes " +
            $"  -keyout key.pem -out cert.pem -days 30 -subj '/CN=chrony-nts.test' " +
            $"  -addext 'subjectAltName=DNS:chrony-nts.test,IP:{vmAddress}' >/dev/null 2>&1; " +
            $"chmod 644 cert.pem; chmod 640 key.pem; chmod 755 {WorkingDirectory}; " +
            // chronyd is built with +PRIVDROP and switches to the _chrony user after start,
            // at which point a root-owned 0600 key is unreadable — it then runs with no TLS
            // credentials and every handshake fails with handshake_failure(40) rather than
            // any error the client can interpret. 'user root' keeps it able to read the key.
            $"(chown _chrony:_chrony cert.pem key.pem {WorkingDirectory} 2>/dev/null || true); " +
            $"printf '%s\\n' " +
            $"  'port {ntpPort}' " +
            $"  'ntsport {ntsKePort}' " +
            $"  'ntsservercert {WorkingDirectory}/cert.pem' " +
            $"  'ntsserverkey {WorkingDirectory}/key.pem' " +
            $"  'ntsdumpdir {WorkingDirectory}' " +
            $"  'user root' " +
            $"  'local stratum 10' " +
            $"  'allow all' " +
            $"  'bindaddress 0.0.0.0' " +
            $"  'driftfile {WorkingDirectory}/drift' " +
            $"  > {WorkingDirectory}/chrony.conf; " +
            $"echo SETUP_OK",
            TimeSpan.FromSeconds(60),
            asRoot: true);

        if (!setup.StdOut.Contains("SETUP_OK"))
            return null;

        // -L 0 keeps chronyd in the foreground with logging, so the detached process stays
        // alive for the fixture's lifetime and its output is available on failure.
        Wsl.StartDetached($"/usr/sbin/chronyd -f {WorkingDirectory}/chrony.conf -L 0");

        var deadline = DateTime.UtcNow + (startupTimeout ?? TimeSpan.FromSeconds(20));

        while (DateTime.UtcNow < deadline)
        {

            var listening = Wsl.Run($"ss -lntu 2>/dev/null | grep -c -E ':({ntpPort}|{ntsKePort})' || true",
                                    TimeSpan.FromSeconds(15));

            if (Int32.TryParse(listening.StdOut.Trim(), out var count) && count >= 2)
                return new ChronyNtsServerFixture(vmAddress,
                                                  IPPort.Parse(ntpPort),
                                                  IPPort.Parse(ntsKePort),
                                                  $"{WorkingDirectory}/cert.pem");

            await Task.Delay(TimeSpan.FromMilliseconds(500));

        }

        await StopChronydAsync();
        return null;

    }


    /// <summary>
    /// chronyd's own view of its NTS server state — useful in failure messages.
    /// </summary>
    public String ServerStats()
        => Wsl.Run($"chronyc -h {VmAddress} -p {NTPPort} serverstats 2>&1 || true",
                   TimeSpan.FromSeconds(15)).StdOut;


    private static Task StopChronydAsync()
    {
        Wsl.Run($"pkill -f 'chronyd -f {WorkingDirectory}' || true", TimeSpan.FromSeconds(20), asRoot: true);
        return Task.CompletedTask;
    }


    public async ValueTask DisposeAsync()
    {
        await StopChronydAsync();
        Wsl.Run($"rm -rf {WorkingDirectory} || true", TimeSpan.FromSeconds(20), asRoot: true);
    }

}
