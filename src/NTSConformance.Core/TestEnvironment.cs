using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

namespace NTSConformance.Core;

/// <summary>
/// One-time capability probing (network / WSL) with Assert.Ignore-based gating
/// so prerequisite-less environments skip instead of fail.
/// </summary>
public static class TestEnvironment
{

    #region Network (UDP/123)

    /// <summary>
    /// Public NTP servers used only to decide whether outbound NTP works at all.
    /// </summary>
    private static readonly String[] probeServers = [ "time.cloudflare.com", "ptbtime1.ptb.de" ];

    private static readonly Lazy<Boolean> hasNetwork = new(() => {

        // A minimal RFC 5905 client packet: LI 0, VN 4, Mode 3, everything else zero.
        // Built inline rather than via RawNtpWriter so the capability gate never
        // depends on code the suite is testing.
        var probe     = new Byte[48];
        probe[0]      = 0x23;

        foreach (var server in probeServers)
        {
            try
            {

                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 3000;
                udp.Connect(server, 123);
                udp.Send(probe);

                var receiveTask = udp.ReceiveAsync();

                if (receiveTask.Wait(TimeSpan.FromSeconds(3)) && receiveTask.Result.Buffer.Length >= 48)
                    return true;

            }
            catch
            {
                // try next server
            }
        }

        return false;

    });

    /// <summary>
    /// True when a public NTP server answers a raw UDP probe on port 123.
    /// </summary>
    public static Boolean HasNetwork
        => hasNetwork.Value;

    public static void RequireNetwork()
    {
        if (!HasNetwork)
            Assert.Ignore($"No outbound NTP connectivity (probed {String.Join(" and ", probeServers)} on UDP/123) — skipping Online test.");
    }

    #endregion

    #region Network (TCP/4460 — NTS-KE)

    private static readonly Lazy<Boolean> hasNtsKeReachability = new(() => {
        try
        {

            using var tcp = new TcpClient();

            return tcp.ConnectAsync("time.cloudflare.com", 4460).Wait(TimeSpan.FromSeconds(5)) &&
                   tcp.Connected;

        }
        catch
        {
            return false;
        }
    });

    /// <summary>
    /// True when an outbound NTS-KE TCP connection to a public server succeeds.
    /// </summary>
    public static Boolean HasNtsKeReachability
        => hasNtsKeReachability.Value;

    public static void RequireNtsKeReachability()
    {
        if (!HasNtsKeReachability)
            Assert.Ignore("Cannot reach time.cloudflare.com:4460 (NTS-KE) — skipping Online test. Corporate firewalls commonly block TCP/4460.");
    }

    #endregion

    #region WSL

    public static void RequireWsl(params String[] tools)
    {

        if (!Wsl.IsAvailable)
            Assert.Ignore(Wsl.UsesWslBridge
                              ? "WSL is not available — skipping. Install WSL and: apt-get install chrony ntpd-rs gnutls-bin"
                              : "No POSIX shell available — skipping.");

        foreach (var tool in tools)
            if (!Wsl.HasTool(tool))
                Assert.Ignore(Wsl.UsesWslBridge
                                  ? $"'{tool}' not found inside WSL — skipping. Install it, e.g.: wsl -u root apt-get install -y chrony ntpd-rs gnutls-bin"
                                  : $"'{tool}' not found on this host — skipping. Install it, e.g.: apt-get install -y chrony ntpd-rs gnutls-bin");

    }


    /// <summary>
    /// chrony must be built with NTS support (Debian's is). Reported in the
    /// chronyd version banner as '+NTS'; a '-NTS' build cannot exercise any of this.
    /// </summary>
    private static readonly Lazy<Boolean> chronyHasNts = new(() => {

        if (!Wsl.IsAvailable || !Wsl.HasTool("chronyd"))
            return false;

        var version = Wsl.Run("/usr/sbin/chronyd --version 2>&1 || chronyd --version 2>&1", TimeSpan.FromSeconds(15));

        return version.StdOut.Contains("+NTS", StringComparison.Ordinal);

    });

    public static void RequireChronyWithNts()
    {

        RequireWsl("chronyd", "chronyc");

        if (!chronyHasNts.Value)
            Assert.Ignore("The WSL chronyd was built without NTS support ('-NTS' in its version banner) — skipping.");

    }

    /// <summary>
    /// ntpd-rs must be present, and recent enough to speak NTS.
    ///
    /// It matters here for a reason chrony cannot cover: ntpd-rs is written in Rust and does its
    /// TLS with rustls, so it validates Norn's NTS-KE certificate through a stack that shares
    /// nothing with BouncyCastle, SChannel or GnuTLS. rustls is also the strictest of the four —
    /// it ignores the certificate's Common Name entirely and requires a matching subject
    /// alternative name.
    /// </summary>
    public static void RequireNtpdRs()
    {

        RequireWsl("ntp-daemon", "ntp-ctl");

        // Both streams: ntp-daemon writes its version banner to stderr, and checking only
        // stdout made this skip on a machine where ntpd-rs was installed and working.
        var version = Wsl.Run("ntp-daemon --version", TimeSpan.FromSeconds(15));
        var banner  = version.StdOut + version.StdErr;

        if (!banner.Contains("ntp-daemon", StringComparison.Ordinal))
            Assert.Ignore($"Could not determine the ntpd-rs version — skipping. {banner}");

    }

    #endregion

    #region NTPv5 peers (chrony-ntp5, ntp5-exp)

    /// <summary>
    /// Where interop/setup-ntpv5-peers.sh installs the two NTPv5 peers, inside WSL or on the
    /// GNU/Linux host - $NTPV5_PEERS there, if it was set.
    /// </summary>
    public const String NTPv5PeersDirectory = "/opt/ntpv5-interop";

    /// <summary>
    /// chronyd of chrony-ntp5, the NTPv5 branch of chrony by the draft's author.
    /// </summary>
    public const String ChronyNtp5Daemon    = NTPv5PeersDirectory + "/chrony-ntp5/sbin/chronyd";

    /// <summary>
    /// chronyc of chrony-ntp5, which reads the NTP version a source was spoken to in.
    /// </summary>
    public const String ChronyNtp5Control   = NTPv5PeersDirectory + "/chrony-ntp5/bin/chronyc";

    /// <summary>
    /// ntpnode.py of ntp5-exp, the draft author's experimental NTPv5+NTPv4 client and server.
    /// </summary>
    public const String Ntp5ExpNode         = NTPv5PeersDirectory + "/ntp5-exp/ntpnode.py";

    private const String NTPv5PeersHint     = "Build them with: wsl -u root sh interop/setup-ntpv5-peers.sh";

    private static readonly Lazy<Boolean> hasChronyNtp5 = new(() =>
        Wsl.IsAvailable &&
        Wsl.Run($"test -x {ChronyNtp5Daemon} && test -x {ChronyNtp5Control} && {ChronyNtp5Daemon} --version 2>&1", TimeSpan.FromSeconds(15)).
            StdOut.Contains("+NTS", StringComparison.Ordinal));

    private static readonly Lazy<Boolean> hasNtp5Exp = new(() =>
        Wsl.IsAvailable &&
        Wsl.Run($"test -f {Ntp5ExpNode} && python3 {Ntp5ExpNode} --help 2>&1", TimeSpan.FromSeconds(15)).
            StdOut.Contains("NTPv5", StringComparison.Ordinal));

    /// <summary>
    /// chrony-ntp5 must be built, with NTS, where interop/setup-ntpv5-peers.sh puts it.
    /// </summary>
    public static void RequireChronyNtp5()
    {

        RequireWsl();

        if (!hasChronyNtp5.Value)
            Assert.Ignore($"chrony-ntp5 is not built in {NTPv5PeersDirectory} — skipping. {NTPv5PeersHint}");

    }

    /// <summary>
    /// ntp5-exp must be installed where interop/setup-ntpv5-peers.sh puts it, with a python3
    /// to run it.
    /// </summary>
    public static void RequireNtp5Exp()
    {

        RequireWsl();

        if (!hasNtp5Exp.Value)
            Assert.Ignore($"ntp5-exp is not installed in {NTPv5PeersDirectory} — skipping. {NTPv5PeersHint}");

    }

    #endregion

    #region Inbound UDP reachability (Windows-hosted server ← WSL client)

    /// <summary>
    /// Whether a WSL process can reach a UDP socket bound on the Windows host.
    /// Windows Firewall blocks this by default, which would otherwise look like a
    /// protocol failure in the interop tests.
    /// </summary>
    public static Boolean CanWslReachWindowsUdp(out String diagnosis)
    {

        diagnosis = "";

        if (!Wsl.IsAvailable)
        {
            diagnosis = "WSL is not available.";
            return false;
        }

        var hostAddress = Wsl.WindowsHostAddress;

        if (hostAddress is null)
        {
            diagnosis = "Could not determine the Windows host address as seen from WSL.";
            return false;
        }

        try
        {

            using var listener = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            var       port     = ((IPEndPoint) listener.Client.LocalEndPoint!).Port;
            var       received = listener.ReceiveAsync();

            // /dev/udp is a bash feature and must be invoked through bash explicitly: Wsl.Run
            // uses sh, which is dash on Debian, and there the redirect just fails. Getting this
            // wrong makes the probe report a blocked network path when nothing is blocked.
            var send = Wsl.Run($"timeout 5 bash -c 'printf probe > /dev/udp/{hostAddress}/{port}'",
                               TimeSpan.FromSeconds(15));

            if (!send.Success)
            {
                diagnosis = $"WSL could not send to {hostAddress}:{port} — {send.StdErr.Trim()}";
                return false;
            }

            if (!received.Wait(TimeSpan.FromSeconds(5)))
            {
                diagnosis = $"No UDP datagram arrived from WSL at {hostAddress}:{port}. " +
                             "Windows Firewall most likely blocks inbound UDP for dotnet.exe — " +
                             "allow it, or run these tests with the Norn server inside WSL instead.";
                return false;
            }

            return true;

        }
        catch (Exception e)
        {
            diagnosis = $"Probe failed: {e.Message}";
            return false;
        }

    }

    private static readonly Lazy<(Boolean ok, String diagnosis)> wslInboundUdp =
        new(() => {
            var ok = CanWslReachWindowsUdp(out var diagnosis);
            return (ok, diagnosis);
        });

    public static void RequireWslInboundUdp()
    {

        var (ok, diagnosis) = wslInboundUdp.Value;

        if (!ok)
            Assert.Ignore($"WSL cannot reach a UDP socket on the Windows host — skipping. {diagnosis}");

    }


    /// <summary>
    /// Whether a WSL process can open a TCP connection to a listener on the Windows host.
    /// Windows Firewall blocks inbound connections from the WSL subnet by default, and it
    /// drops rather than refuses them, so an unguarded test hangs until its timeout instead
    /// of failing quickly.
    /// </summary>
    private static readonly Lazy<(Boolean ok, String diagnosis)> wslInboundTcp = new(() => {

        if (!Wsl.IsAvailable)
            return (false, "WSL is not available.");

        var hostAddress = Wsl.WindowsHostAddress;

        if (hostAddress is null)
            return (false, "Could not determine the Windows host address as seen from WSL.");

        try
        {

            using var listener = new TcpListener(IPAddress.Any, 0);
            listener.Start();

            var port     = ((IPEndPoint) listener.LocalEndpoint).Port;
            var accepted = listener.AcceptTcpClientAsync();

            // Bash's /dev/tcp avoids needing netcat, and the timeout keeps a dropped
            // connection from stalling the probe.
            Wsl.Run($"timeout 5 bash -c 'exec 3<>/dev/tcp/{hostAddress}/{port}' 2>/dev/null || true",
                    TimeSpan.FromSeconds(15));

            if (!accepted.Wait(TimeSpan.FromSeconds(3)))
                return (false,
                        $"No TCP connection arrived from WSL at {hostAddress}:{port}. Windows Firewall " +
                         "most likely blocks inbound TCP from the WSL subnet. To enable these tests, allow " +
                         "inbound TCP/UDP for the test host from the WSL interface, e.g. from an elevated " +
                         "PowerShell: New-NetFirewallRule -DisplayName 'WSL inbound' -Direction Inbound " +
                         "-InterfaceAlias 'vEthernet (WSL*)' -Action Allow");

            return (true, "");

        }
        catch (Exception e)
        {
            return (false, $"Probe failed: {e.Message}");
        }

    });

    public static void RequireWslInboundTcp()
    {

        var (ok, diagnosis) = wslInboundTcp.Value;

        if (!ok)
            Assert.Ignore($"WSL cannot reach a TCP listener on the Windows host — skipping. {diagnosis}");

    }

    #endregion

}
