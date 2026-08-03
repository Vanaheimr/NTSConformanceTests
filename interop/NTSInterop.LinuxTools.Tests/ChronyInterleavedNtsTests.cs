using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// <c>chronyd</c> against Norn with RFC 9769 interleaved mode and RFC 8915 NTS at once.
///
/// <para>
/// The two features are independent in the specifications and not independent in the code. An
/// interleaved response carries the transmit timestamp of the previous response in its header,
/// and under NTS that header is covered by the authenticator — so the header has to be final
/// before the authenticator is computed over it. It is, because the interleaved timestamp is a
/// past value known before the packet is built, which is precisely why the mode is compatible
/// with authentication at all. But "it is, because" is reasoning, and reasoning about the order
/// of two operations inside one method is the kind of thing that survives a refactor by
/// accident.
/// </para>
/// <para>
/// There is a second thing only this combination reaches. Under
/// <see cref="org.GraphDefined.Vanaheimr.Norn.NTS.InterleavedModePolicy.AuthenticatedOnly"/> the
/// interleaved mode is reserved for clients carrying a verified authenticator, and nothing but
/// a real NTS client can show that the reservation admits the clients it is meant to admit
/// rather than turning the mode off for everybody.
/// </para>
/// <para>
/// Both legs run inbound from WSL to the Windows host — NTS-KE over TCP and the time query over
/// UDP — so this needs more of the firewall open than the plain interleaved tests, and probes
/// for it first.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class ChronyInterleavedNtsTests
{

    private const String WorkingDirectory = "/tmp/norn-chrony-xleave-nts";

    private NornServerFixture?  fixture;
    private String?             hostAddress;
    private String?             certificatePathInWsl;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireChronyWithNts();
        TestEnvironment.RequireWslInboundTcp();
        TestEnvironment.RequireWslInboundUdp();

        hostAddress = Wsl.WindowsHostAddress
                          ?? throw new InvalidOperationException("no Windows host address");

        // chronyd validates the certificate against the address it dials, so that address has
        // to appear as an IP subject alternative name.
        var certificate = TestCertificate.Generate(
                              subjectCommonName:  "Norn NTS-KE interop",
                              ipAddresses:        [ hostAddress ]
                          );

        var directory        = Path.Combine(Path.GetTempPath(), "norn-chrony-xleave-nts");
        certificatePathInWsl = Wsl.ToWslPath(certificate.WritePem(directory));

        fixture = await NornServerFixture.StartAsync(
                            certificate:       certificate,
                            externalHostName:  hostAddress
                        );

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {

        Wsl.Run($"pkill -x chronyd || true; rm -rf {WorkingDirectory} || true",
                TimeSpan.FromSeconds(20),
                asRoot: true);

        if (fixture is not null)
            await fixture.DisposeAsync();

    }


    /// <summary>
    /// Run chronyd as an NTS client with <c>xleave</c> and report what it made of the source.
    /// </summary>
    /// <remarks>
    /// A daemon rather than <c>chronyd -Q</c>: the interleaved mode cannot appear in a single
    /// exchange, because the first request of an association is always basic.
    ///
    /// <c>certset 1</c> rather than the default 0, so Norn's certificate is the only one that
    /// can satisfy this connection — set 0 is the system's trusted CAs, and a wrong certificate
    /// could otherwise be rescued by a public one and pass unnoticed.
    /// </remarks>
    private Wsl.Result QueryWithChronyd()

        => Wsl.Run(
               "pkill -x chronyd || true; "                                                  +
               $"mkdir -p {WorkingDirectory} && "                                            +
               "printf '%s\\n' "                                                             +
               $"  'server {hostAddress} port {fixture!.NTPPort} nts ntsport {fixture.NTSKEPort} certset 1 xleave minpoll 0 maxpoll 0 iburst' " +
               $"  'ntstrustedcerts 1 {certificatePathInWsl}' "                              +
               $"  'ntsdumpdir {WorkingDirectory}' "                                         +
               "  'port 0' "                                                                 +
               $"  'driftfile {WorkingDirectory}/drift' "                                    +
               $"  > {WorkingDirectory}/chrony.conf && "                                     +
               // -x never to touch the VM's clock; -u root so chronyd keeps the privileges to
               // create its command socket, which is how chronyc reaches it at all.
               $"chronyd -f {WorkingDirectory}/chrony.conf -x -u root; "                     +
               "sleep 14; "                                                                  +
               "echo '===== ntpdata ====='; "                                                +
               $"chronyc ntpdata {hostAddress} 2>&1 || true; "                                +
               "pkill -x chronyd || true",
               TimeSpan.FromSeconds(90),
               asRoot: true
           );


    private static String? Field(String output, String name)

        => output.Split('\n').
               Select(line => line.Trim()).
               Where (line => line.StartsWith(name, StringComparison.OrdinalIgnoreCase)).
               Select(line => line.Split(':', 2).Length == 2 ? line.Split(':', 2)[1].Trim() : null).
               FirstOrDefault(value => value is not null);


    /// <summary>
    /// Both at once: chronyd reports the source as interleaved <em>and</em> authenticated.
    ///
    /// Either flag alone would be satisfied by the tests that already exist. Together they say
    /// the interleaved timestamps travelled inside a header whose authenticator chronyd
    /// verified — that Norn fixed the header before sealing it, and that the timestamp it put
    /// there was still the right one.
    /// </summary>
    [Test]
    public void Chronyd_UsesInterleavedModeAndNtsTogether()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result = QueryWithChronyd();

        if (fixture.Server.Metrics.NTPRequestsReceived == 0)
            Assert.Ignore($"chronyd's requests never reached the server, so nothing can be " +
                          $"concluded.\n{result.StdOut}");

        Assert.Multiple(() => {

            Assert.That(Field(result.StdOut, "Authenticated"),
                        Is.EqualTo("Yes"),
                        $"chronyd did not authenticate the responses.\n" +
                        $"server metrics: {fixture.Server.Metrics}\n{result.StdOut}");

            Assert.That(Field(result.StdOut, "Interleaved"),
                        Is.EqualTo("Yes"),
                        $"chronyd authenticated the responses but never entered the interleaved " +
                        $"mode, so the two features do not compose.\n{result.StdOut}");

        });

    }


    /// <summary>
    /// And the resulting measurement is usable.
    ///
    /// The combination is where a mis-assembled timestamp is easiest to hide: the packet
    /// authenticates, chronyd accepts it, and only the arithmetic is wrong. An implausible
    /// offset against a server reading the same machine's clock is how that looks from outside.
    /// </summary>
    [Test]
    public void TheAuthenticatedInterleavedMeasurement_IsPlausible()
    {

        if (fixture is null)
        {
            Assert.Ignore("the server fixture did not start");
            return;
        }

        var result  = QueryWithChronyd();
        var offset  = Field(result.StdOut, "Offset");

        if (offset is null)
        {
            Assert.Ignore($"chronyd produced no offset to check.\n{result.StdOut}");
            return;
        }

        var number  = offset.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

        Assert.That(Double.TryParse(number,
                                    System.Globalization.NumberStyles.Float,
                                    System.Globalization.CultureInfo.InvariantCulture,
                                    out var offsetSeconds),
                    Is.True,
                    $"could not read the offset from '{offset}'\n{result.StdOut}");

        Assert.That(Math.Abs(offsetSeconds),
                    Is.LessThan(1.0),
                    $"chronyd measured {offsetSeconds} s over authenticated interleaved NTS " +
                    $"against a server reading the same machine's clock.\n{result.StdOut}");

    }

}
