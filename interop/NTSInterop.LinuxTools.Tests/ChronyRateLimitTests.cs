using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Hermod;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// <c>chronyd</c> against a rate-limited Norn: does a real client believe the "RATE" kiss, and
/// does it do what RFC 5905 § 7.4 b says to do about it?
///
/// <para>
/// This is the only test in the suite that can answer that. Norn's own client is written from the
/// same reading of the same paragraphs as Norn's server, so the two agreeing proves they agree
/// and nothing more. A kiss that echoes a timestamp no independent client compares against, or
/// that carries a poll value in a form only Norn reads, would pass every hermetic test here and
/// change nothing in the field — which is the whole failure mode a rate limit has, since a limit
/// nobody heeds is just packet loss.
/// </para>
/// <para>
/// The observable is the poll interval chronyd settles on, which it reports as a number. That is
/// a stronger claim than "it sent fewer packets": chronyd backs off on its own when a source goes
/// quiet, so a reduced rate proves nothing, but adopting the <em>specific</em> exponent Norn put
/// in the kiss can only happen if chronyd read it, believed it and acted on it.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class ChronyRateLimitTests
{

    private const String WorkingDirectory = "/tmp/norn-chrony-ratelimit";

    /// <summary>
    /// How long chronyd runs. Long enough for it to get past <c>iburst</c>, be limited, receive a
    /// kiss and act on it — and short enough that two runs of it are a tolerable test.
    /// </summary>
    private static readonly TimeSpan RunTime = TimeSpan.FromSeconds(25);

    private String? hostAddress;


    [OneTimeSetUp]
    public void RequireTheEnvironment()
    {

        TestEnvironment.RequireWsl("chronyd", "chronyc");
        TestEnvironment.RequireWslInboundUdp();

        hostAddress = Wsl.WindowsHostAddress
                          ?? throw new InvalidOperationException("no Windows host address");

    }


    [OneTimeTearDown]
    public void StopChronyd()

        => Wsl.Run($"pkill -x chronyd || true; rm -rf {WorkingDirectory} || true",
                   TimeSpan.FromSeconds(20),
                   asRoot: true);


    /// <summary>
    /// Run chronyd against one Norn server for <see cref="RunTime"/> and report what it did.
    /// </summary>
    /// <remarks>
    /// <c>minpoll 0</c> pins chronyd to a request every second unless something tells it
    /// otherwise, which is what makes the count meaningful: left at the default it would poll
    /// every 64 seconds and send almost nothing either way. <c>maxpoll 10</c> leaves it room to
    /// back off as far as it likes.
    /// </remarks>
    private Wsl.Result RunChronyd(IPPort Port)

        => Wsl.Run(
               "pkill -x chronyd || true; "                                                +
               $"mkdir -p {WorkingDirectory} && "                                          +
               "printf '%s\\n' "                                                           +
               $"  'server {hostAddress} port {Port} minpoll 0 maxpoll 10 iburst' "  +
               "  'port 0' "                                                               +
               $"  'driftfile {WorkingDirectory}/drift' "                                  +
               $"  > {WorkingDirectory}/chrony.conf && "                                   +
               // -x never to touch the VM's clock; -u root so the command socket can be
               // created, which is how chronyc reaches it at all.
               $"chronyd -f {WorkingDirectory}/chrony.conf -x -u root; "                   +
               $"sleep {(Int32) RunTime.TotalSeconds}; "                                   +
               "echo '===== sources ====='; "                                              +
               "chronyc -N sources 2>&1 || true; "                                         +
               "echo '===== ntpdata ====='; "                                              +
               $"chronyc ntpdata {hostAddress} 2>&1 || true; "                             +
               "pkill -x chronyd || true",
               RunTime + TimeSpan.FromSeconds(45),
               asRoot: true
           );


    /// <summary>
    /// The interval the server is willing to serve, chosen so that the poll exponent it implies
    /// is unmistakable.
    /// </summary>
    /// <remarks>
    /// 200 seconds means exponent 8, the smallest power of two that covers it. Eight is neither
    /// the <c>minpoll 0</c> chronyd is configured with nor the 6 it would use by default, so
    /// chronyd arriving at exactly 8 cannot be anything but the number out of Norn's kiss.
    /// </remarks>
    private static readonly TimeSpan ServedInterval = TimeSpan.FromSeconds(200);

    private const Int32 ExpectedPollExponent = 8;


    /// <summary>
    /// A limiter tight enough that chronyd polling once a second is refused almost every time.
    /// </summary>
    /// <param name="withKisses">
    /// Whether the refusals are explained. This is the whole experiment: the two runs differ in
    /// nothing but whether the server sends the RATE kiss.
    /// </param>
    private static NTPRateLimiter Limiter(Boolean withKisses)

        => new (MinimumInterval:     ServedInterval,
                Burst:               2,
                // Short, so chronyd hears it more than once inside the run. On a real server this
                // would be far longer; here the point is to give the client every chance to obey.
                KissInterval:        TimeSpan.FromSeconds(4),
                MaxKissesPerSecond:  withKisses ? 8 : 0);


    private async Task<(Int32? Poll, Int64 Kisses, String Output)> Measure(Boolean withKisses)
    {

        await using var fixture = await NornServerFixture.StartAsync(
                                            externalHostName:  hostAddress,
                                            rateLimiter:       Limiter(withKisses)
                                        );

        var result = RunChronyd(fixture.NTPPort);

        return (PollInterval(result.StdOut),
                fixture.Server.Metrics.NTPKissesOfDeathSent,
                result.StdOut);

    }


    /// <summary>
    /// The poll exponent out of <c>chronyc ntpdata</c>, whose line reads
    /// <c>Poll interval   : 8 (256 seconds)</c>.
    /// </summary>
    private static Int32? PollInterval(String Output)
    {

        var line = Output.Split('\n').
                       Select(line => line.Trim()).
                       FirstOrDefault(line => line.StartsWith("Poll interval", StringComparison.OrdinalIgnoreCase));

        var value = line?.Split(':', 2).ElementAtOrDefault(1)?.
                        Split(' ', StringSplitOptions.RemoveEmptyEntries).
                        FirstOrDefault();

        return Int32.TryParse(value, out var exponent)
                   ? exponent
                   : null;

    }


    /// <summary>
    /// chronyd adopts the exact poll interval the RATE kiss asks for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The strongest statement this suite can make about the kiss: an independent implementation,
    /// reading the packet with none of Norn's code, arrives at the number Norn put in it. That
    /// rules out the whole family of failures where the kiss is well-formed but not believed —
    /// RFC 8633 § 5.4 makes the echoed origin timestamp the price of being believed, and a client
    /// that rejected it would keep polling at the rate it chose.
    /// </para>
    /// <para>
    /// The second run is the control, identical but for the kisses being switched off. chronyd
    /// backs off on its own when a source goes quiet, so without it a slower poll would be
    /// evidence of nothing.
    /// </para>
    /// </remarks>
    [Test]
    public async Task Chronyd_AdoptsThePollIntervalTheRateKissAsksFor()
    {

        var kissed = await Measure(withKisses: true);

        if (kissed.Kisses == 0)
            Assert.Ignore($"chronyd never provoked a kiss, so there is nothing to observe.\n{kissed.Output}");

        var silent = await Measure(withKisses: false);

        await TestContext.Out.WriteLineAsync(
            $"with kisses: poll {kissed.Poll}, {kissed.Kisses} kisses\n{kissed.Output}\n" +
            $"silent:      poll {silent.Poll}\n{silent.Output}");

        Assert.Multiple(() => {

            Assert.That(silent.Kisses,
                        Is.Zero,
                        "the control run must not have sent any");

            Assert.That(kissed.Poll,
                        Is.EqualTo(ExpectedPollExponent),
                        $"chronyd settled on poll {kissed.Poll} rather than the {ExpectedPollExponent} " +
                        $"Norn's kiss asked for. Either the kiss is not being believed, or the " +
                        $"poll value in it is not the one the server means.");

            Assert.That(silent.Poll,
                        Is.LessThan(ExpectedPollExponent),
                        $"and the control run reached poll {silent.Poll} without being told " +
                        $"anything, so the number above has to come from somewhere else to mean " +
                        $"anything");

        });

    }


    /// <summary>
    /// And chronyd keeps the source rather than discarding the server.
    /// </summary>
    /// <remarks>
    /// The failure this guards against is a server being too helpful. "RATE" asks a client to
    /// come back less often; "DENY" tells it to go away. A limiter that reached for the wrong
    /// code, or a client that read the kiss as a refusal of service, would lose the association —
    /// and a client that drops a server it merely polled too fast has lost a time source over a
    /// misunderstanding.
    /// </remarks>
    [Test]
    public async Task AfterTheKiss_ChronydStillKeepsTheSource()
    {

        var (poll, kisses, output) = await Measure(withKisses: true);

        if (kisses == 0)
            Assert.Ignore($"chronyd never provoked a kiss.\n{output}");

        Assert.That(poll,
                    Is.Not.Null,
                    $"chronyd should still hold a poll interval for this server, meaning it is " +
                    $"still an association: a dropped source has none.\n{output}");

        Assert.That(output,
                    Does.Contain(hostAddress!),
                    $"the source should still be listed after the kiss, not dropped.\n{output}");

    }

}
