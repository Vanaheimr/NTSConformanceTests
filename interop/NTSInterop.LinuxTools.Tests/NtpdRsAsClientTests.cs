using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// <c>ntpd-rs</c> as an NTS client against Norn's server — the first test in this suite where
/// somebody else's code validates Norn's certificate and completes a full NTS exchange against it.
///
/// That is the point of it. chrony covers the opposite direction (Norn's client against chronyd's
/// NTS server), and the chronyd-as-client tests speak plain NTP, so until now no external
/// implementation had ever run NTS-KE against Norn. ntpd-rs is written in Rust and does its TLS
/// with rustls, a fourth stack sharing nothing with BouncyCastle, SChannel or GnuTLS — and every
/// high-value defect this suite found came from exactly that kind of independence: SChannel
/// rejected a certificate the other three accepted, and chrony noticed a missing ALPN that Norn's
/// own client never checked.
///
/// rustls is also the strictest of the four about identity: it ignores the Common Name entirely
/// and requires a subject alternative name matching the address it dialled. Norn is therefore
/// given a certificate carrying the Windows host's address as an IP SAN, and ntpd-rs is pointed
/// at that certificate as its trust anchor.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class NtpdRsAsClientTests
{

    private NornServerFixture?  fixture;
    private String?             hostAddress;
    private String?             configurationPathInWsl;
    private String?             plainConfigurationPathInWsl;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireNtpdRs();

        // ntpd-rs runs inside WSL and has to reach both legs on the Windows host: NTS-KE over
        // TCP and the time query over UDP. Probed up front so a blocked path skips rather than
        // looking like a protocol failure.
        TestEnvironment.RequireWslInboundTcp();
        TestEnvironment.RequireWslInboundUdp();

        hostAddress = Wsl.WindowsHostAddress
                          ?? throw new InvalidOperationException("no Windows host address");

        // The address ntpd-rs dials, as an IP SAN — rustls matches the name it connected to
        // against the SAN entries and nothing else.
        var certificate = TestCertificate.Generate(
                              subjectCommonName:  "Norn NTS-KE interop",
                              ipAddresses:        [ hostAddress ]
                          );

        var directory         = Path.Combine(Path.GetTempPath(), "norn-ntpd-rs-interop");
        var certificatePath   = Wsl.ToWslPath(certificate.WritePem(directory));

        // ExternalURLs decides where the NTS-KE response tells the client to send its NTP
        // query. Left at the default it advertises "localhost", which inside WSL means the WSL
        // VM itself — the query would leave and never arrive.
        fixture = await NornServerFixture.StartAsync(
                            certificate:       certificate,
                            externalHostName:  hostAddress
                        );

        // Written as a file and handed over by path, rather than echoed into place by the
        // shell: TOML is full of quotes, and getting them through a shell command line intact
        // is a fight that produces silently malformed configuration when lost.
        //
        // The observation socket has to live on the Linux filesystem — a unix socket cannot be
        // created under /mnt/c — while the configuration and certificate are read from there
        // quite happily.
        var configuration     = String.Join(
                                    Environment.NewLine,
                                    "[observability]",
                                    "log-level = \"info\"",
                                    "observation-path = \"/tmp/norn-ntpd-rs/observe\"",
                                    "",
                                    "[[source]]",
                                    "mode = \"nts\"",
                                    $"address = \"{hostAddress}:{fixture.NTSKEPort}\"",
                                    $"certificate-authority = \"{certificatePath}\"",
                                    ""
                                );

        var configurationPath = Path.Combine(directory, "ntp.toml");
        File.WriteAllText(configurationPath, configuration);
        configurationPathInWsl = Wsl.ToWslPath(configurationPath);

        // The same client without NTS, straight at the NTP port. Its observation socket has to
        // differ from the one above, or the two runs fight over the same path.
        var plainConfiguration = String.Join(
                                     Environment.NewLine,
                                     "[observability]",
                                     "log-level = \"info\"",
                                     "observation-path = \"/tmp/norn-ntpd-rs/observe-plain\"",
                                     "",
                                     "[[source]]",
                                     "mode = \"server\"",
                                     $"address = \"{hostAddress}:{fixture.NTPPort}\"",
                                     ""
                                 );

        var plainConfigurationPath = Path.Combine(directory, "ntp-plain.toml");
        File.WriteAllText(plainConfigurationPath, plainConfiguration);
        plainConfigurationPathInWsl = Wsl.ToWslPath(plainConfigurationPath);

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// Run ntpd-rs against Norn for a few seconds and return what it reported.
    ///
    /// ntpd-rs has no one-shot query tool, so the daemon is started with a single source, given
    /// time to complete NTS-KE and take a measurement, and then asked for its status. One source
    /// is below its agreement threshold, so it observes without ever stepping the WSL clock.
    /// </summary>
    private Wsl.Result RunNtpdRs(String? configuration = null)
    {

        var configurationPath = configuration ?? configurationPathInWsl;

        return Wsl.Run(
                   "mkdir -p /tmp/norn-ntpd-rs && "                                          +
                   $"ntp-daemon -c {configurationPath} > /tmp/norn-ntpd-rs/log 2>&1 & "      +
                   "DAEMON=$!; "                                                             +
                   "sleep 12; "                                                              +
                   "echo '===== ntp-ctl status ====='; "                                     +
                   $"ntp-ctl status -c {configurationPath} 2>&1 || true; "                   +
                   "kill $DAEMON 2>/dev/null; "                                              +
                   "echo '===== daemon log ====='; "                                         +
                   "cat /tmp/norn-ntpd-rs/log",
                   TimeSpan.FromSeconds(60),
                   asRoot: true
               );

    }


    /// <summary>
    /// Pull the offset out of an ntp-ctl source line, which reads
    /// <c>172.17.80.1:34567/172.17.80.1:34567 (1): +0.003586±0.102581(±0.010523)s</c>. Returns
    /// null when the source produced no measurement at all, which is what an unusable server
    /// looks like.
    ///
    /// The sign is explicit in that output and may be either — a pattern that only allowed a
    /// minus matched the negative offset it was written against and then read a perfectly good
    /// positive measurement as "no measurement at all".
    /// </summary>
    private static Double? MeasuredOffsetSeconds(String status)
    {

        var match = System.Text.RegularExpressions.Regex.Match(
                        status,
                        @"\(\d+\):\s*([+-]?\d+\.\d+)±"
                    );

        return match.Success &&
               Double.TryParse(match.Groups[1].Value,
                               System.Globalization.NumberStyles.Float,
                               System.Globalization.CultureInfo.InvariantCulture,
                               out var offset)
                   ? offset
                   : null;

    }


    /// <summary>
    /// ntpd-rs as a plain NTPv4 client — no NTS anywhere in it.
    ///
    /// A second opinion on the path that broke once already: the NTS NAK added for the
    /// unusable-cookie case also caught every plain NTP request, and chronyd was the only client
    /// that noticed. Norn's plain answers now have to satisfy a Rust implementation's sanity
    /// rules as well as chrony's C ones.
    ///
    /// The assertion is on the measurement rather than on the traffic. Norn's counters only show
    /// that requests arrived and answers went out — exactly what happened when chronyd was
    /// refusing every one of those answers as a Kiss-o'-Death. An offset in ntp-ctl's output
    /// means ntpd-rs took the reply and used it.
    /// </summary>
    [Test]
    public void NtpdRs_AcceptsNornOverPlainNtp()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var before   = fixture.Server.Metrics.NTPRequestsReceived;
        var result   = RunNtpdRs(plainConfigurationPathInWsl);
        var received = fixture.Server.Metrics.NTPRequestsReceived - before;

        if (received == 0)
            Assert.Ignore($"ntpd-rs's plain NTP requests never reached the server, so nothing " +
                          $"can be concluded about the replies.\n{result.StdOut}");

        var offset = MeasuredOffsetSeconds(result.StdOut);

        Assert.That(offset,
                    Is.Not.Null,
                    $"ntpd-rs took {received} reply/replies from Norn and produced no measurement " +
                    $"from any of them — it received answers and refused them.\n" +
                    $"server metrics: {fixture.Server.Metrics}\n{result.StdOut}");

        Assert.That(Math.Abs(offset!.Value),
                    Is.LessThan(5.0),
                    $"ntpd-rs measured an offset of {offset} s against a server reading the same " +
                    $"machine's clock — the timestamps are likely mis-encoded.\n{result.StdOut}");

    }


    /// <summary>
    /// ntpd-rs completes NTS-KE against Norn and accepts it as a source.
    ///
    /// The failure this is really watching for is a certificate rustls will not accept, or an
    /// NTS-KE response it will not parse — either shows up as the source never becoming usable.
    /// The server's own counters distinguish "refused what Norn sent" from "never reached Norn",
    /// which is the distinction that makes a red result actionable.
    /// </summary>
    [Test]
    public void NtpdRs_CompletesNtsAgainstNorn()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result   = RunNtpdRs();
        var metrics  = fixture.Server.Metrics;

        if (metrics.NTSKEConnectionsAccepted == 0)
            Assert.Ignore($"ntpd-rs never reached the NTS-KE port, so nothing can be concluded " +
                          $"about what Norn sent.\n{result.StdOut}\n{result.StdErr}");

        Assert.Multiple(() => {

            Assert.That(metrics.NTSKEResponsesSent,
                        Is.GreaterThan(0),
                        $"Norn accepted the connection but sent no NTS-KE response.\n{result.StdOut}");

            Assert.That(metrics.NTPRequestsReceived,
                        Is.GreaterThan(0),
                        $"ntpd-rs did not go on to query the time, which means it refused the " +
                        $"NTS-KE response — a certificate rustls rejected, or records it would " +
                        $"not accept.\nserver metrics: {metrics}\n{result.StdOut}");

            Assert.That(metrics.NTPResponsesSent,
                        Is.GreaterThan(0),
                        $"Norn received the NTS-protected query but answered nothing.\n{result.StdOut}");

        });

    }


    /// <summary>
    /// The exchange is authenticated, not merely completed: Norn counts a request as valid only
    /// after unsealing the cookie and verifying the authenticator, so a reply sent at all means
    /// ntpd-rs produced a cookie and a MAC that Norn accepted under keys both sides derived
    /// independently from the TLS exporter.
    /// </summary>
    [Test]
    public void TheExchange_IsAuthenticated_NotJustCompleted()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result   = RunNtpdRs();
        var metrics  = fixture.Server.Metrics;

        if (metrics.NTPRequestsReceived == 0)
            Assert.Ignore($"ntpd-rs sent no NTP query.\n{result.StdOut}");

        Assert.Multiple(() => {

            Assert.That(metrics.NTPRequestsInvalid,
                        Is.Zero,
                        $"Norn could not parse or authenticate what ntpd-rs sent.\n" +
                        $"server metrics: {metrics}\n{result.StdOut}");

            Assert.That(metrics.NTPRequestsRejected,
                        Is.Zero,
                        $"Norn rejected requests from ntpd-rs.\nserver metrics: {metrics}\n{result.StdOut}");

        });

    }

}
