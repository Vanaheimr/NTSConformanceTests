using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// <c>chronyd</c> as an RFC 9769 interleaved client against Norn's server.
///
/// <para>
/// The conformance tests in this suite drive the interleaved mode from a codec written against
/// the same RFC as the implementation, by the same person, in the same week. That catches
/// misreadings of the text but not misreadings shared between the two sides — and interleaved
/// mode is unusually exposed to exactly that, because nothing on the wire announces it. There
/// is no extension field to get wrong, no negotiation to fail: two implementations that agree
/// on a wrong reading of which timestamp goes where will interoperate happily and produce
/// measurements that are quietly incorrect.
/// </para>
/// <para>
/// chrony is the implementation RFC 9769 was written alongside — Miroslav Lichvar is its
/// maintainer and the RFC's first author, and chrony has had <c>xleave</c> since version 4.0,
/// years before publication. If Norn's server and chronyd agree, the reading is right.
/// </para>
/// <para>
/// Plain NTP, no NTS: the interleaved mode is a property of the header timestamps and has
/// nothing to do with authentication, so this needs only inbound UDP and no certificate.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class ChronyInterleavedTests
{

    private const String WorkingDirectory  = "/tmp/norn-chrony-xleave";

    private NornServerFixture?  fixture;
    private String?             hostAddress;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireWsl("chronyd");

        // chronyd runs inside WSL and queries the Windows host, so the firewall has to allow
        // inbound UDP from the WSL subnet.
        TestEnvironment.RequireWslInboundUdp();

        hostAddress = Wsl.WindowsHostAddress
                          ?? throw new InvalidOperationException("no Windows host address");

        fixture = await NornServerFixture.StartAsync(externalHostName: hostAddress);

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {

        StopChronyd();

        if (fixture is not null)
            await fixture.DisposeAsync();

    }


    /// <summary>
    /// Stop chronyd, matched on the executable name and never on the command line.
    /// </summary>
    /// <remarks>
    /// <c>pkill -f chronyd</c> would match the shell running this very command, because that
    /// command line contains the word — so the cleanup kills the process collecting the output
    /// and the test reports nothing rather than what happened.
    /// </remarks>
    private static void StopChronyd()
    {
        Wsl.Run($"pkill -x chronyd || true; rm -rf {WorkingDirectory} || true",
                TimeSpan.FromSeconds(20),
                asRoot: true);
    }


    /// <summary>
    /// Run chronyd as a daemon against Norn for long enough to get past the opening exchange,
    /// then ask it what it made of the source.
    /// </summary>
    /// <remarks>
    /// A daemon rather than <c>chronyd -Q</c>, because the interleaved mode cannot show up in a
    /// single exchange: RFC 9769 § 2 — "The first request from a client is always in the basic
    /// mode ... Only when the client receives a valid response from the server will it be able
    /// to send a request in the interleaved mode." A one-shot measurement would always report
    /// the basic mode, whatever the server supports.
    ///
    /// <c>minpoll 0 maxpoll 0</c> pins the poll interval to one second so the handful of
    /// exchanges needed fit in the time this test is prepared to wait.
    /// </remarks>
    private Wsl.Result QueryWithChronyd(Boolean interleaved)
    {

        var configuration = String.Join(
                                " ",
                                $"'server {hostAddress} port {fixture!.NTPPort} minpoll 0 maxpoll 0 iburst" +
                                    (interleaved ? " xleave'" : "'"),
                                // Never bind the NTP server port: this chronyd is a client, and
                                // 123 may well be busy.
                                "'port 0'",
                                $"'driftfile {WorkingDirectory}/drift'"
                            );

        return Wsl.Run(
                   $"pkill -x chronyd || true; "                                             +
                   $"mkdir -p {WorkingDirectory} && "                                        +
                   $"printf '%s\\n' {configuration} > {WorkingDirectory}/chrony.conf && "    +
                   // -x so it never touches the VM's clock: what is under test is the
                   // measurement, not the discipline.
                   //
                   // -u root so chronyd keeps the privileges to create its command socket.
                   // Left to drop to _chrony it starts, answers nothing, and logs nothing —
                   // chronyc then reports only "Could not open connection to daemon".
                   //
                   // The socket is the compiled-in default rather than a path of our choosing:
                   // a bindcmdaddress pointing elsewhere is accepted and silently ignored on
                   // Debian, which looks exactly like the privilege problem above.
                   $"chronyd -f {WorkingDirectory}/chrony.conf -x -u root; "                 +
                   "sleep 12; "                                                              +
                   "echo '===== ntpdata ====='; "                                            +
                   $"chronyc ntpdata {hostAddress} 2>&1 || true; "                            +
                   "echo '===== sources ====='; "                                            +
                   "chronyc -n sources 2>&1 || true; "                                       +
                   "pkill -x chronyd || true",
                   TimeSpan.FromSeconds(90),
                   asRoot: true
               );

    }


    /// <summary>
    /// Read one field out of <c>chronyc ntpdata</c>, whose output is "Name : Value" a line.
    /// </summary>
    private static String? Field(String output, String name)

        => output.Split('\n').
               Select(line => line.Trim()).
               Where (line => line.StartsWith(name, StringComparison.OrdinalIgnoreCase)).
               Select(line => line.Split(':', 2).Length == 2 ? line.Split(':', 2)[1].Trim() : null).
               FirstOrDefault(value => value is not null);


    /// <summary>
    /// chronyd, told to use the interleaved mode, reports that it is in it.
    ///
    /// <c>Interleaved : Yes</c> in <c>chronyc ntpdata</c> is chronyd's own verdict on the last
    /// valid response it received: it set that flag because the origin timestamp coming back
    /// matched the receive timestamp it sent, which is the one thing that cannot happen unless
    /// Norn recognized the request and answered accordingly.
    /// </summary>
    [Test]
    public void Chronyd_EntersTheInterleavedModeWithNorn()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result = QueryWithChronyd(interleaved: true);

        if (fixture.Server.Metrics.NTPRequestsReceived == 0)
            Assert.Ignore($"chronyd's requests never reached the server, so nothing can be " +
                          $"concluded.\n{result.StdOut}");

        Assert.That(Field(result.StdOut, "Interleaved"),
                    Is.EqualTo("Yes"),
                    $"chronyd was configured with xleave and exchanged packets with Norn, but " +
                    $"did not end up in the interleaved mode.\n" +
                    $"server metrics: {fixture.Server.Metrics}\n{result.StdOut}");

    }


    /// <summary>
    /// The sensitivity check, and the one that makes the test above mean something: the same
    /// chronyd against the same server, without <c>xleave</c>, must report the basic mode.
    ///
    /// Without this a test asserting "Yes" could be passing because chronyd says "Yes" to
    /// everything, or because the field was misread.
    /// </summary>
    [Test]
    public void WithoutXleave_ChronydStaysInTheBasicMode()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result = QueryWithChronyd(interleaved: false);

        if (fixture.Server.Metrics.NTPRequestsReceived == 0)
            Assert.Ignore($"chronyd's requests never reached the server.\n{result.StdOut}");

        Assert.That(Field(result.StdOut, "Interleaved"),
                    Is.EqualTo("No"),
                    $"a client that never asked for the interleaved mode must not be put into " +
                    $"it.\n{result.StdOut}");

    }


    /// <summary>
    /// And the measurement has to be usable, not merely interleaved.
    ///
    /// A server can satisfy every mode-switching rule and still report a transmit timestamp
    /// that is wrong, at which point chronyd computes an offset from it and believes the
    /// answer. An implausible offset against a server reading the same machine's clock is what
    /// that looks like from outside.
    /// </summary>
    [Test]
    public void TheInterleavedMeasurement_IsPlausible()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result  = QueryWithChronyd(interleaved: true);
        var offset  = Field(result.StdOut, "Offset");

        if (offset is null)
            Assert.Ignore($"chronyd produced no offset to check.\n{result.StdOut}");

        // "Offset          : +0.000014487 seconds"
        var number  = offset!.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

        Assert.That(Double.TryParse(number,
                                    System.Globalization.NumberStyles.Float,
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    out var offsetSeconds),
                    Is.True,
                    $"could not read the offset from '{offset}'\n{result.StdOut}");

        Assert.That(Math.Abs(offsetSeconds),
                    Is.LessThan(1.0),
                    $"chronyd measured {offsetSeconds} s against a server reading the same " +
                    $"machine's clock, so the interleaved timestamps are being mis-assembled " +
                    $"somewhere.\n{result.StdOut}");

    }

}
