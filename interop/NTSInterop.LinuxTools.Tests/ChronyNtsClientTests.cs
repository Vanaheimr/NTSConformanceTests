using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// <c>chronyd</c> as an NTS client against Norn's server — the last of the four combinations,
/// and the one that puts the reference implementation on the demanding side of the exchange.
///
/// The other chrony fixtures cover Norn's client against chronyd's NTS server, and chronyd as a
/// plain NTP client. Neither makes chronyd validate Norn's certificate, negotiate NTS-KE with
/// it, or authenticate an NTS-protected reply from it. This does, through GnuTLS — a third TLS
/// stack alongside rustls and SChannel, all three of which have now refused something the
/// others accepted at some point in this suite's history.
///
/// chrony is also the implementation most public NTS servers run, so it is the closest thing
/// available to "would the internet accept this server".
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class ChronyNtsClientTests
{

    private const String WorkingDirectory = "/tmp/norn-chrony-nts-client";

    private NornServerFixture?  fixture;
    private String?             hostAddress;
    private String?             configurationPathInWsl;
    private String?             gcmSivConfigurationPathInWsl;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireChronyWithNts();

        // chronyd runs inside WSL and has to reach both legs on the Windows host: NTS-KE over
        // TCP and the time query over UDP.
        TestEnvironment.RequireWslInboundTcp();
        TestEnvironment.RequireWslInboundUdp();

        hostAddress = Wsl.WindowsHostAddress
                          ?? throw new InvalidOperationException("no Windows host address");

        // chronyd verifies the certificate against the address it was told to connect to, so
        // that address has to appear as an IP subject alternative name.
        var certificate = TestCertificate.Generate(
                              subjectCommonName:  "Norn NTS-KE interop",
                              ipAddresses:        [ hostAddress ]
                          );

        var directory       = Path.Combine(Path.GetTempPath(), "norn-chrony-nts-client");
        var certificatePath = Wsl.ToWslPath(certificate.WritePem(directory));

        fixture = await NornServerFixture.StartAsync(
                            certificate:       certificate,
                            externalHostName:  hostAddress
                        );

        // certset 1 rather than the default 0: set 0 is the system's trusted CAs, so a dedicated
        // set means Norn's certificate is the only one that can satisfy this connection. If the
        // certificate were wrong, chronyd could not fall back to a public CA and quietly pass.
        String WriteConfiguration(String fileName, String? aeadAlgorithms)
        {

            // A dump directory of its own per configuration. chronyd caches cookies there, and a
            // shared one would let a later run reuse an earlier run's session — which is exactly
            // the kind of accident that makes a negotiation test pass without negotiating.
            var workingDirectory = aeadAlgorithms is null
                                       ? WorkingDirectory
                                       : $"{WorkingDirectory}-{aeadAlgorithms}";

            var lines = new List<String> {
                            $"server {hostAddress} port {fixture.NTPPort} nts ntsport {fixture.NTSKEPort} certset 1 iburst",
                            $"ntstrustedcerts 1 {certificatePath}",
                            $"ntsdumpdir {workingDirectory}",
                            $"driftfile {workingDirectory}/drift"
                        };

            if (aeadAlgorithms is not null)
                lines.Add($"ntsaeads {aeadAlgorithms}");

            var path = Path.Combine(directory, fileName);
            File.WriteAllText(path, String.Join(Environment.NewLine, lines) + Environment.NewLine);

            return Wsl.ToWslPath(path);

        }

        configurationPathInWsl        = WriteConfiguration("chrony-nts.conf",        null);
        gcmSivConfigurationPathInWsl  = WriteConfiguration("chrony-nts-gcmsiv.conf", "30");

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {

        if (fixture is not null)
            await fixture.DisposeAsync();

        Wsl.Run($"rm -rf {WorkingDirectory} {WorkingDirectory}-30 || true", TimeSpan.FromSeconds(20), asRoot: true);

    }


    /// <summary>
    /// Run chronyd in query-only mode against Norn and return what it logged. <c>-Q</c> measures
    /// and reports without touching the system clock.
    /// </summary>
    private Wsl.Result QueryWithChronyd(String? configuration = null)

        => Wsl.Run($"mkdir -p {WorkingDirectory} {WorkingDirectory}-30 && " +
                   $"/usr/sbin/chronyd -Q -t 15 -f {configuration ?? configurationPathInWsl} 2>&1 || true",
                   TimeSpan.FromSeconds(60),
                   asRoot: true);


    /// <summary>
    /// chronyd completes NTS-KE with Norn, accepts the certificate, and takes an authenticated
    /// measurement.
    ///
    /// "System clock wrong by N seconds" is chronyd reporting a successful measurement under
    /// <c>-Q</c>. Anything else — a TLS failure, a certificate it will not trust, records it will
    /// not parse — leaves it with no source, and the server's own counters say which side of the
    /// exchange got that far.
    /// </summary>
    [Test]
    public void Chronyd_CompletesNtsAgainstNorn()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result  = QueryWithChronyd();
        var metrics = fixture.Server.Metrics;

        if (metrics.NTSKEConnectionsAccepted == 0)
            Assert.Ignore($"chronyd never reached the NTS-KE port, so nothing can be concluded " +
                          $"about what Norn sent.\n{result}");

        Assert.Multiple(() => {

            Assert.That(metrics.NTSKEResponsesSent,
                        Is.GreaterThan(0),
                        $"Norn accepted the TLS connection but sent no NTS-KE response.\n{result}");

            Assert.That(metrics.NTPRequestsReceived,
                        Is.GreaterThan(0),
                        $"chronyd did not go on to query the time, so it refused the NTS-KE " +
                        $"exchange — most likely the certificate.\nserver metrics: {metrics}\n{result}");

            Assert.That(result.StdOut,
                        Does.Contain("System clock wrong by"),
                        $"chronyd took the NTS-protected reply and did not accept it.\n" +
                        $"server metrics: {metrics}\n{result}");

        });

    }


    /// <summary>
    /// The same exchange pinned to AES-128-GCM-SIV, which is the direction the exporter-context
    /// defect broke that Norn's own client cannot check.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ntsaeads 30</c> leaves chronyd nothing else to offer, so a measurement here means
    /// Norn's <em>server</em> derived algorithm 30's keys the way chronyd expects — echoing IANA
    /// record 1024 and using RFC 8915 § 5.1's exporter context because chronyd asked for it. Get
    /// that wrong and the key exchange still completes, the cookies are still well-formed, and
    /// chronyd silently discards every reply.
    /// </para>
    /// <para>
    /// The test above does not cover this even now that both default to algorithm 30: it asserts
    /// that a measurement happened, not which primitive carried it, and a future default would
    /// move it without anything going red.
    /// </para>
    /// </remarks>
    [Test]
    public void Chronyd_CompletesNtsAgainstNorn_OnGcmSiv()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var before  = fixture.Server.Metrics.NTPRequestsReceived;
        var result  = QueryWithChronyd(gcmSivConfigurationPathInWsl);
        var metrics = fixture.Server.Metrics;

        if (metrics.NTSKEConnectionsAccepted == 0)
            Assert.Ignore($"chronyd never reached the NTS-KE port, so nothing can be concluded " +
                          $"about what Norn sent.\n{result}");

        Assert.Multiple(() => {

            Assert.That(metrics.NTPRequestsReceived,
                        Is.GreaterThan(before),
                        $"chronyd would not query the time after a key exchange pinned to " +
                        $"AES-128-GCM-SIV.\nserver metrics: {metrics}\n{result}");

            Assert.That(result.StdOut,
                        Does.Contain("System clock wrong by"),
                        $"chronyd took Norn's AES-128-GCM-SIV reply and could not authenticate it, " +
                        $"which is what a mismatched § 5.1 exporter context looks like.\n" +
                        $"server metrics: {metrics}\n{result}");

        });

    }


    /// <summary>
    /// The measured offset must be small. A wildly wrong offset would mean the timestamps are
    /// mis-encoded even though the packet authenticates — the kind of error that survives every
    /// test that only asks whether the exchange completed.
    /// </summary>
    [Test]
    public void Chronyd_MeasuresAPlausibleOffsetOverNts()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result = QueryWithChronyd();

        var line   = result.StdOut.Split('\n').
                         FirstOrDefault(line => line.Contains("System clock wrong by"));

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
                    $"chronyd measured an implausible offset of {offsetSeconds} s over NTS against " +
                    $"a server reading the same machine's clock.\n{result}");

    }

}
