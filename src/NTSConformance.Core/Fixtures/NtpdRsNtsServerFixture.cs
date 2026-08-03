using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core.Fixtures;

/// <summary>
/// Runs <c>ntpd-rs</c> inside WSL as an NTS server, for Norn's client to talk to.
///
/// The counterpart to <see cref="ChronyNtsServerFixture"/>, and worth having alongside it
/// rather than instead of it: chrony and ntpd-rs are separate implementations in separate
/// languages, and Norn agreeing with one says nothing about the other. ntpd-rs serves its
/// NTS-KE through rustls, so this also puts Norn's client in front of a TLS stack it has not
/// otherwise met.
///
/// Runs in the direction that always works — Norn on Windows dialling into the VM — because
/// WSL2's NAT forwards outbound traffic without any firewall involvement.
/// </summary>
public sealed class NtpdRsNtsServerFixture : IAsyncDisposable
{

    private const String WorkingDirectory = "/tmp/norn-ntpd-rs-server";


    private NtpdRsNtsServerFixture(String vmAddress,
                                   IPPort ntpPort,
                                   IPPort ntsKePort,
                                   String certificatePath)
    {
        VmAddress        = vmAddress;
        NTPPort          = ntpPort;
        NTSKEPort        = ntsKePort;
        CertificatePath  = certificatePath;
    }


    /// <summary>The VM's address, as reachable from Windows.</summary>
    public String VmAddress       { get; }

    public IPPort NTPPort         { get; }
    public IPPort NTSKEPort       { get; }

    /// <summary>The self-signed certificate ntpd-rs presents, inside the VM.</summary>
    public String CertificatePath { get; }


    /// <summary>
    /// Generate a certificate, write an ntpd-rs configuration and start the daemon.
    /// Returns null when the prerequisites are missing, so callers can Assert.Ignore.
    /// </summary>
    public static async Task<NtpdRsNtsServerFixture?> StartAsync(TimeSpan? startupTimeout = null)
    {

        if (!Wsl.IsAvailable || !Wsl.HasTool("ntp-daemon") || !Wsl.HasTool("openssl"))
            return null;

        var vmAddress = Wsl.VmAddress;

        if (vmAddress is null)
            return null;

        // Bound inside the VM, so the ports only have to be free there. High and random to
        // avoid colliding with a system daemon or a parallel run.
        var random    = new Random();
        var ntpPort   = random.Next(30000, 40000);
        var ntsKePort = ntpPort + 1;

        var setup = Wsl.Run(
            $"set -e; " +
            $"mkdir -p {WorkingDirectory}; cd {WorkingDirectory}; " +
            $"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes " +
            $"  -keyout key.pem -out cert.pem -days 30 -subj '/CN=ntpd-rs.test' " +
            $"  -addext 'subjectAltName=DNS:ntpd-rs.test,IP:{vmAddress}' >/dev/null 2>&1; " +
            $"chmod 644 cert.pem key.pem; " +
            $"printf '%s\\n' " +
            $"  '[observability]' " +
            $"  'log-level = \"info\"' " +
            $"  '' " +
            // ntpd-rs is configured with no sources at all, so it never touches the VM's
            // clock. local-stratum lets it serve that clock anyway, which is what chronyd's
            // "local stratum 10" does and what makes an isolated test server useful.
            $"  '[synchronization]' " +
            $"  'local-stratum = 10' " +
            $"  '' " +
            $"  '[[server]]' " +
            $"  'listen = \"0.0.0.0:{ntpPort}\"' " +
            $"  '' " +
            $"  '[[nts-ke-server]]' " +
            $"  'listen = \"0.0.0.0:{ntsKePort}\"' " +
            $"  'certificate-chain-path = \"{WorkingDirectory}/cert.pem\"' " +
            $"  'private-key-path = \"{WorkingDirectory}/key.pem\"' " +
            // Without this the key exchange advertises the default 123 and the client's time
            // query goes to a port nothing is listening on — an NTS-KE that succeeds followed
            // by a query that times out, which reads like a protocol fault and is not one.
            $"  'ntp-port = {ntpPort}' " +
            $"  > {WorkingDirectory}/ntp.toml; " +
            $"ntp-ctl validate -c {WorkingDirectory}/ntp.toml >/dev/null 2>&1; " +
            $"echo SETUP_OK",
            TimeSpan.FromSeconds(60),
            asRoot: true);

        if (!setup.StdOut.Contains("SETUP_OK"))
            return null;

        Wsl.StartDetached($"ntp-daemon -c {WorkingDirectory}/ntp.toml");

        var deadline = DateTime.UtcNow + (startupTimeout ?? TimeSpan.FromSeconds(20));

        while (DateTime.UtcNow < deadline)
        {

            var listening = Wsl.Run($"ss -lntu 2>/dev/null | grep -c -E ':({ntpPort}|{ntsKePort})' || true",
                                    TimeSpan.FromSeconds(15));

            if (Int32.TryParse(listening.StdOut.Trim(), out var count) && count >= 2)
                return new NtpdRsNtsServerFixture(vmAddress,
                                                  IPPort.Parse(ntpPort),
                                                  IPPort.Parse(ntsKePort),
                                                  $"{WorkingDirectory}/cert.pem");

            await Task.Delay(TimeSpan.FromMilliseconds(500));

        }

        await StopDaemonAsync();
        return null;

    }


    /// <summary>The daemon's own log, for when a failure needs explaining.</summary>
    public String DaemonLog()

        => Wsl.Run($"cat {WorkingDirectory}/daemon.log 2>/dev/null || true",
                   TimeSpan.FromSeconds(15)).StdOut;


    private static async Task StopDaemonAsync()
    {

        Wsl.Run($"pkill -f 'ntp-daemon -c {WorkingDirectory}' || true",
                TimeSpan.FromSeconds(20),
                asRoot: true);

        await Task.Delay(TimeSpan.FromMilliseconds(300));

    }


    public async ValueTask DisposeAsync()
    {

        await StopDaemonAsync();

        Wsl.Run($"rm -rf {WorkingDirectory} || true", TimeSpan.FromSeconds(20), asRoot: true);

    }

}
