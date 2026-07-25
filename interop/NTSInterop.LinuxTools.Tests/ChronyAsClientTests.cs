using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// <c>chronyd</c> as a client against Norn's NTP server — the reverse of
/// <see cref="ChronyNtsServerTests"/>, and the direction that matters for anyone deploying
/// Norn to serve time.
///
/// chronyd is a strict client: it applies the RFC 5905 §11 selection and sanity rules and
/// simply reports "no suitable source" for a server it will not use, without saying why. That
/// makes it a good judge of whether the header fields are coherent, and a poor one to debug
/// against — the server's own request counters are what distinguish "rejected my reply" from
/// "never received it".
///
/// This direction found a real regression. The NTS NAK for an unusable cookie keyed on "no valid
/// cookie", which is also true of every plain NTP request, so the server answered chronyd's
/// plain requests with a Kiss-o'-Death and chronyd refused it outright.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class ChronyAsClientTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireChronyWithNts();

        // chronyd runs inside WSL and has to reach a socket on the Windows host, which Windows
        // Firewall blocks by default. Probed up front so a blocked path skips rather than
        // looking like a protocol failure.
        TestEnvironment.RequireWslInboundUdp();

        fixture = await NornServerFixture.StartAsync();

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// Run chronyd in query-only mode against the server and return what it logged.
    /// <c>-Q</c> measures and reports without touching the system clock.
    /// </summary>
    private Wsl.Result QueryWithChronyd(String extraServerOptions = "")
    {

        var host   = Wsl.WindowsHostAddress
                         ?? throw new InvalidOperationException("no Windows host address");

        var config = $"server {host} port {fixture!.NTPPort} iburst {extraServerOptions}\\n";

        return Wsl.Run($"printf '{config}' > /tmp/norn-interop.conf && " +
                       $"/usr/sbin/chronyd -Q -t 12 -f /tmp/norn-interop.conf 2>&1 || true",
                       TimeSpan.FromSeconds(45),
                       asRoot: true);

    }


    /// <summary>
    /// chronyd must accept Norn as a time source and produce a measurement.
    ///
    /// "System clock wrong by N seconds" is chronyd reporting a successful measurement under
    /// <c>-Q</c>; "No suitable source for synchronisation" means it took the replies and
    /// refused them.
    /// </summary>
    [Test]
    public void Chronyd_AcceptsNornAsATimeSource()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result  = QueryWithChronyd();
        var metrics = fixture.Server.Metrics;

        // Distinguishing a rejected reply from an undelivered one is the whole difficulty here.
        if (metrics.NTPRequestsReceived == 0)
            Assert.Ignore($"chronyd's requests never reached the server, so nothing can be " +
                          $"concluded about the replies.\n{result}");

        Assert.That(result.StdOut,
                    Does.Contain("System clock wrong by"),
                    $"chronyd took {metrics.NTPRequestsReceived} reply/replies and did not accept any of them.\n" +
                    $"server sent {metrics.NTPResponsesSent} response(s).\n{result}");

        Assert.That(result.StdOut,
                    Does.Not.Contain("No suitable source"),
                    $"chronyd rejected the server as unusable.\n{result}");

    }


    /// <summary>
    /// The measured offset must be small. A wildly wrong offset would mean the timestamps are
    /// being encoded or ordered incorrectly even though the packet is otherwise acceptable —
    /// exactly the kind of error that survives a self-test.
    /// </summary>
    [Test]
    public void Chronyd_MeasuresAPlausibleOffset()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result = QueryWithChronyd();

        if (fixture.Server.Metrics.NTPRequestsReceived == 0)
            Assert.Ignore($"chronyd's requests never reached the server.\n{result}");

        var line = result.StdOut.Split('\n').
                       FirstOrDefault(l => l.Contains("System clock wrong by"));

        if (line is null)
        {
            Assert.Ignore($"chronyd produced no measurement to check.\n{result}");
            return;
        }

        // "System clock wrong by 0.000381 seconds (ignored)"
        var words  = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var index  = Array.IndexOf(words, "by");

        Assert.That(index, Is.GreaterThan(-1).And.LessThan(words.Length - 1), $"unexpected format: {line}");

        Assert.That(Double.TryParse(words[index + 1],
                                    System.Globalization.NumberStyles.Float,
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    out var offsetSeconds),
                    Is.True,
                    $"could not read the offset from: {line}");

        Assert.That(Math.Abs(offsetSeconds),
                    Is.LessThan(5.0),
                    $"chronyd measured an implausible offset of {offsetSeconds} s against a server " +
                    $"reading the same machine's clock — the timestamps are likely mis-encoded.\n{result}");

    }

}
