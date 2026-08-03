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
        var configuration   = String.Join(
                                  Environment.NewLine,
                                  $"server {hostAddress} port {fixture.NTPPort} nts ntsport {fixture.NTSKEPort} certset 1 iburst",
                                  $"ntstrustedcerts 1 {certificatePath}",
                                  $"ntsdumpdir {WorkingDirectory}",
                                  "driftfile " + WorkingDirectory + "/drift",
                                  ""
                              );

        var configurationPath = Path.Combine(directory, "chrony-nts.conf");
        File.WriteAllText(configurationPath, configuration);
        configurationPathInWsl = Wsl.ToWslPath(configurationPath);

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {

        if (fixture is not null)
            await fixture.DisposeAsync();

        Wsl.Run($"rm -rf {WorkingDirectory} || true", TimeSpan.FromSeconds(20), asRoot: true);

    }


    /// <summary>
    /// Run chronyd in query-only mode against Norn and return what it logged. <c>-Q</c> measures
    /// and reports without touching the system clock.
    /// </summary>
    private Wsl.Result QueryWithChronyd()

        => Wsl.Run($"mkdir -p {WorkingDirectory} && " +
                   $"/usr/sbin/chronyd -Q -t 15 -f {configurationPathInWsl} 2>&1 || true",
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
