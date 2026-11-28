using System.Text.RegularExpressions;

using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core.Fixtures;

/// <summary>
/// The two NTPv5 peers of draft-ietf-ntp-ntpv5-10 § 14 that run here, built from source by
/// interop/setup-ntpv5-peers.sh: chrony-ntp5 and ntp5-exp, both by the draft's author. Each is
/// used as a client against Norn, through what it reports itself - chronyc's ntpdata, and
/// ntpnode.py's log - so that a test learns what the peer made of Norn, not what Norn thinks
/// it sent.
/// </summary>
public static partial class NTPv5Peers
{

    #region chrony-ntp5 as a client

    /// <summary>
    /// What chronyc of chrony-ntp5 reported of its one source: its ntpdata, field by field.
    /// </summary>
    /// <param name="NtpData">The fields of <c>chronyc ntpdata</c>, by name.</param>
    /// <param name="Output">Everything that was printed, for failure messages.</param>
    public sealed record ChronyNtp5Report(IReadOnlyDictionary<String, String> NtpData,
                                          String                              Output)
    {

        /// <summary>
        /// The NTP version chronyd spoke to the source in - 5 where it negotiated NTPv5.
        /// </summary>
        public Int32?   Version
            => NtpData.TryGetValue("Version", out var version) && Int32.TryParse(version, out var number) ? number : null;

        /// <summary>
        /// How many responses chronyd took as valid.
        /// </summary>
        public Int32    ValidResponses
            => NtpData.TryGetValue("Total valid RX", out var valid) && Int32.TryParse(valid, out var number) ? number : 0;

        /// <summary>
        /// Whether the last response was in the interleaved mode.
        /// </summary>
        public Boolean  Interleaved
            => NtpData.TryGetValue("Interleaved", out var interleaved) && interleaved == "Yes";

        /// <summary>
        /// Whether the source was authenticated, by NTS.
        /// </summary>
        public Boolean  Authenticated
            => NtpData.TryGetValue("Authenticated", out var authenticated) && authenticated == "Yes";

        /// <summary>
        /// The offset chronyd measured, in seconds.
        /// </summary>
        public Double?  OffsetSeconds
            => NtpData.TryGetValue("Offset", out var offset) &&
               Double.TryParse(offset.Split(' ')[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var seconds)
                   ? seconds
                   : null;

        public override String ToString()
            => Output;

    }

    /// <summary>
    /// Run chronyd of chrony-ntp5 against one server for the given time, without touching the
    /// clock (<c>-x</c>), and read what <c>chronyc ntpdata</c> says of it.
    /// </summary>
    /// <param name="ServerDirective">The <c>server</c> line, as chrony.conf has it.</param>
    /// <param name="Duration">How long to let it poll.</param>
    /// <param name="ExtraDirectives">Further lines of chrony.conf, such as <c>ntstrustedcerts</c>.</param>
    public static ChronyNtp5Report QueryWithChronyNtp5(String                ServerDirective,
                                                       TimeSpan?             Duration         = null,
                                                       IEnumerable<String>?  ExtraDirectives  = null)
    {

        // A directory of its own per run, 0700 as chronyd wants it for its command socket, so
        // that no run reads another's ntpdata or NTS cookies.
        var directory  = $"/tmp/norn-chrony-ntp5-{Guid.NewGuid():N}";
        var seconds    = (Int32) Math.Ceiling((Duration ?? TimeSpan.FromSeconds(8)).TotalSeconds);

        var lines      = new List<String> {
                             ServerDirective,
                             "cmdport 0",
                             $"bindcmdaddress {directory}/chronyd.sock",
                             $"pidfile {directory}/chronyd.pid",
                             $"driftfile {directory}/drift",
                             $"ntsdumpdir {directory}",
                             "user root"
                         };

        lines.AddRange(ExtraDirectives ?? []);

        var printf     = String.Join(" ", lines.Select(line => $"'{line}'"));

        var result     = Wsl.Run($"mkdir -p {directory} && chmod 700 {directory} && " +
                                 $"printf '%s\\n' {printf} > {directory}/chrony.conf && " +
                                 $"{TestEnvironment.ChronyNtp5Daemon} -x -f {directory}/chrony.conf -l {directory}/chronyd.log && " +
                                 $"sleep {seconds}; " +
                                 $"echo '--- ntpdata'; {TestEnvironment.ChronyNtp5Control} -h {directory}/chronyd.sock -n ntpdata 2>&1; " +
                                 $"echo '--- sources'; {TestEnvironment.ChronyNtp5Control} -h {directory}/chronyd.sock -n sources 2>&1; " +
                                 $"echo '--- log'; cat {directory}/chronyd.log 2>&1; " +
                                 $"kill $(cat {directory}/chronyd.pid) 2>/dev/null; sleep 1; rm -rf {directory}",
                                 TimeSpan.FromSeconds(seconds + 30),
                                 asRoot: true);

        var ntpData    = new Dictionary<String, String>();

        foreach (var line in result.StdOut.Split('\n'))
        {

            var colon = line.IndexOf(':');

            if (colon > 0 && !line.StartsWith("20", StringComparison.Ordinal))
            {
                var name = line[..colon].Trim();
                if (name.Length > 0 && !ntpData.ContainsKey(name))
                    ntpData[name] = line[(colon + 1)..].Trim();
            }

        }

        return new ChronyNtp5Report(ntpData, $"{result.StdOut}\n{result.StdErr}");

    }

    #endregion

    #region ntp5-exp as a client

    /// <summary>
    /// What ntpnode.py of ntp5-exp logged while it polled one server.
    /// </summary>
    /// <param name="Log">Its log.</param>
    public sealed partial record Ntp5ExpReport(String Log)
    {

        /// <summary>
        /// How many NTPv5 responses it received, valid or not.
        /// </summary>
        public Int32 NTPv5Responses
            => Count("Received NTPv5 response");

        /// <summary>
        /// How many NTPv4 responses it received.
        /// </summary>
        public Int32 NTPv4Responses
            => Count("Received NTPv4 response");

        /// <summary>
        /// How many responses it threw away as not matching its request.
        /// </summary>
        public Int32 BogusResponses
            => Count("Bogus response");

        /// <summary>
        /// The lines it logged as errors - a message it could not parse among them.
        /// </summary>
        public IReadOnlyList<String> Errors
            => [.. Log.Split('\n').Where(line => line.StartsWith("ERROR", StringComparison.Ordinal) ||
                                                 line.Contains("Invalid", StringComparison.Ordinal) ||
                                                 line.Contains("Unexpected", StringComparison.Ordinal))];

        /// <summary>
        /// The measurements it made, by mode ("Basic" or "Interleaved"), offset and delay in seconds.
        /// </summary>
        public IReadOnlyList<(String Mode, Double Offset, Double Delay)> Measurements
            => [.. MeasurementLine().Matches(Log).
                       Select(match => (match.Groups["mode"].Value,
                                        Double.Parse(match.Groups["offset"].Value, System.Globalization.CultureInfo.InvariantCulture),
                                        Double.Parse(match.Groups["delay"]. Value, System.Globalization.CultureInfo.InvariantCulture)))];

        /// <summary>
        /// Whether its source selection took the server: valid samples, a root distance within
        /// its limit, and the whole list of reference IDs without its own in it.
        /// </summary>
        public Boolean Selected
            => Log.Contains("Selected #1", StringComparison.Ordinal);

        private Int32 Count(String Text)
            => Log.Split('\n').Count(line => line.Contains(Text, StringComparison.Ordinal));

        [GeneratedRegex(@"(?<mode>Basic|Interleaved) mode offset=(?<offset>[-+]?\d+\.\d+) delay=(?<delay>\d+\.\d+)")]
        private static partial Regex MeasurementLine();

        public override String ToString()
            => Log;

    }

    /// <summary>
    /// Run ntpnode.py of ntp5-exp as a client of one server for the given time.
    /// </summary>
    /// <param name="Server">The server, as HOST:PORT.</param>
    /// <param name="Version">The NTP version to speak, or null for its negotiation (§ 12).</param>
    /// <param name="Interleaved">Whether to ask for the interleaved mode.</param>
    /// <param name="Duration">How long to let it poll, once a second.</param>
    public static Ntp5ExpReport QueryWithNtp5Exp(String     Server,
                                                 Int32?     Version      = 5,
                                                 Boolean    Interleaved  = false,
                                                 TimeSpan?  Duration     = null)
    {

        var seconds  = (Int32) Math.Ceiling((Duration ?? TimeSpan.FromSeconds(8)).TotalSeconds);

        // It is a server too, on a port of its own, which nobody here asks.
        var ownPort  = Random.Shared.Next(30000, 40000);

        var options  = (Version is Int32 version ? $"-v {version} " : "") +
                       (Interleaved ? "-x " : "");

        var result   = Wsl.Run($"timeout {seconds} python3 {TestEnvironment.Ntp5ExpNode} -p {ownPort} -i 0 {options}{Server} 2>&1; true",
                               TimeSpan.FromSeconds(seconds + 20));

        return new Ntp5ExpReport($"{result.StdOut}\n{result.StdErr}");

    }

    #endregion

}


/// <summary>
/// ntpnode.py of ntp5-exp as a server inside WSL, for Norn's client to ask - an NTPv5 and
/// NTPv4 server with a local reference, at stratum 1.
/// </summary>
public sealed class Ntp5ExpServerFixture : IAsyncDisposable
{

    private Ntp5ExpServerFixture(String VmAddress, IPPort Port)
    {
        this.VmAddress = VmAddress;
        this.Port      = Port;
    }

    /// <summary>
    /// The WSL VM's address, reachable from Windows.
    /// </summary>
    public String VmAddress { get; }

    /// <summary>
    /// The UDP port it serves on.
    /// </summary>
    public IPPort Port      { get; }

    /// <summary>
    /// Start it, or null where WSL or ntp5-exp is missing.
    /// </summary>
    public static async Task<Ntp5ExpServerFixture?> StartAsync(TimeSpan? StartupTimeout = null)
    {

        if (!Wsl.IsAvailable || Wsl.VmAddress is not String vmAddress)
            return null;

        var port = Random.Shared.Next(20000, 30000);

        using var started = Wsl.StartDetached($"exec python3 {TestEnvironment.Ntp5ExpNode} -p {port} -l > /tmp/ntp5-exp-server-{port}.log 2>&1", asRoot: false);

        var deadline = DateTime.UtcNow + (StartupTimeout ?? TimeSpan.FromSeconds(15));

        while (DateTime.UtcNow < deadline)
        {

            var listening = Wsl.Run($"ss -lnu 2>/dev/null | grep -c ':{port} ' || true", TimeSpan.FromSeconds(10));

            if (Int32.TryParse(listening.StdOut.Trim(), out var count) && count >= 1)
                return new Ntp5ExpServerFixture(vmAddress, IPPort.Parse((UInt16) port));

            await Task.Delay(TimeSpan.FromMilliseconds(300));

        }

        Stop(port);
        return null;

    }

    /// <summary>
    /// What it logged, for failure messages.
    /// </summary>
    public String Log()
        => Wsl.Run($"tail -50 /tmp/ntp5-exp-server-{Port}.log 2>&1 || true", TimeSpan.FromSeconds(10)).StdOut;

    // The pattern in brackets, so that it does not match the shell running pkill.
    private static void Stop(Int32 Port)
        => Wsl.Run($"pkill -f '[n]tpnode.py -p {Port} ' || true; rm -f /tmp/ntp5-exp-server-{Port}.log", TimeSpan.FromSeconds(15));

    public ValueTask DisposeAsync()
    {
        Stop(Port.ToUInt16());
        return ValueTask.CompletedTask;
    }

}
