using Newtonsoft.Json.Linq;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.CLI.Tests;

/// <summary>
/// The tool against a real Norn server, over real sockets.
///
/// <para>
/// Everything the three commands do was already covered by the rest of this suite, at the level
/// of the library. What is new here, and what these tests are for, is the layer above it: that
/// the options reach the code they name, that a failure becomes a non-zero exit, and that
/// <c>--json</c> produces something a script can read on stdout with nothing else mixed in.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class AgainstAServerTests
{

    private NornServerFixture? fixture;


    [SetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync();


    [TearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// The options that point the tool at the fixture.
    /// </summary>
    /// <remarks>
    /// <c>--insecure</c> because the fixture mints a self-signed certificate that nothing has
    /// been told to trust, and <c>--ipv4</c> because it listens on the IPv4 wildcard while the
    /// client prefers IPv6.
    /// </remarks>
    private String[] Against(params String[] arguments)

        => [ .. arguments,
             "--ke-port", fixture!.NTSKEPort.ToString(),
             // Only 'query' speaks NTP, so only it takes --port. Adding it unconditionally
             // would make every 'ke' test a usage error instead of the thing it meant to check.
             .. arguments[0] == "query" ? new[] { "--port", fixture!.NTPPort.ToString() } : [],
             "--insecure",
             "--ipv4",
             // The CLI's defaults are sized for humans on healthy machines. A starved CI
             // runner has taken more than the default 5 s over a loopback TLS handshake,
             // and a slow green tells the truth where a fast red does not.
             "--timeout", "30",
             "localhost" ];


    #region query

    /// <summary>
    /// A query against a working server succeeds and reports a measurement.
    /// </summary>
    [Test]
    public void Query_MeasuresAWorkingServer()
    {

        var run = Norn.Run(Against("query"));

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.Zero, run.Transcript);

            Assert.That(run.StdOut, Does.Contain("Offset").And.Contain("Stratum"),
                        "a measurement is the point of the command");

            Assert.That(run.StdOut, Does.Not.Contain("Kiss-o'-Death"));

        });

    }


    /// <summary>
    /// <c>--plain</c> skips the key exchange entirely.
    /// </summary>
    /// <remarks>
    /// Observed from the server's side rather than from the output, because the output of a
    /// plain query and an NTS one differ only in details a test could match by accident. The
    /// server's key-exchange counter cannot be mistaken.
    /// </remarks>
    [Test]
    public void QueryPlain_DoesNoKeyExchange()
    {

        var run = Norn.Run(Against("query", "--plain"));

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.Zero, run.Transcript);

            Assert.That(fixture!.Server.Metrics.NTSKEConnectionsAccepted,
                        Is.Zero,
                        $"--plain must not open a key exchange: {fixture.Server.Metrics}");

            Assert.That(fixture.Server.Metrics.NTPRequestsReceived,
                        Is.EqualTo(1),
                        $"but it must still ask the time: {fixture.Server.Metrics}");

        });

    }


    /// <summary>
    /// <c>--count</c> sends that many queries and summarizes them.
    /// </summary>
    [Test]
    public void QueryCount_SendsThatMany()
    {

        var run = Norn.Run(Against("query", "--count", "3", "--interval", "0.1"));

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.Zero, run.Transcript);

            Assert.That(fixture!.Server.Metrics.NTPRequestsReceived,
                        Is.EqualTo(3),
                        $"three were asked for: {fixture.Server.Metrics}");

            Assert.That(run.StdOut, Does.Contain("Answered").And.Contain("3 of 3"));

            Assert.That(run.StdOut, Does.Contain("median"),
                        "several measurements deserve a summary, or the reader does the " +
                        "arithmetic themselves");

        });

    }


    /// <summary>
    /// A server that is not there is a failure, not a usage error and not a success.
    /// </summary>
    [Test]
    public void Query_AgainstNothing_Fails()
    {

        // RFC 2606 reserves .invalid, so this cannot resolve and cannot accidentally reach a
        // real server belonging to somebody else.
        var run = Norn.Run([ "query", "--plain", "--timeout", "1", "norn-cli.invalid" ]);

        Assert.Multiple(() => {
            Assert.That(run.ExitCode, Is.EqualTo(1), run.Transcript);
            Assert.That(run.StdErr,   Is.Not.Empty, "and it has to say why");
        });

    }


    /// <summary>
    /// A rate-limited query reports the kiss, and reports it once.
    /// </summary>
    /// <remarks>
    /// The exit code is the interesting half. A Kiss-o'-Death is not a measurement, so a run
    /// that draws nothing but kisses has to fail — otherwise a monitoring script watching a
    /// server that has stopped answering it sees nothing wrong.
    /// </remarks>
    [Test]
    public async Task Query_ReportsARateKiss()
    {

        await fixture!.DisposeAsync();

        fixture = await NornServerFixture.StartAsync(
                            rateLimiter: new NTPRateLimiter(
                                             MinimumInterval:  TimeSpan.FromMinutes(10),
                                             Burst:            1
                                         )
                        );

        var run = Norn.Run(Against("query", "--count", "2", "--interval", "0.1"));

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.Zero,
                        $"one of the two was answered, so the run learned the time.\n{run.Transcript}");

            Assert.That(run.StdOut, Does.Contain("RATE"));

            Assert.That(run.StdOut, Does.Contain("rate-limiting"),
                        "and it should say what the code means rather than leaving four letters " +
                        "to be looked up");

        });

        var refused = Norn.Run(Against("query", "--count", "2", "--interval", "0.1"));

        Assert.That(refused.ExitCode,
                    Is.EqualTo(1),
                    $"the bucket is empty by now, so nothing came back and the run failed.\n{refused.Transcript}");

    }

    #endregion


    #region ke

    /// <summary>
    /// The key exchange reports what was negotiated.
    /// </summary>
    [Test]
    public void KeyExchange_ReportsWhatWasNegotiated()
    {

        var run = Norn.Run(Against("ke"));

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.Zero, run.Transcript);

            Assert.That(run.StdOut, Does.Contain("TLS 1.3"),
                        "RFC 8915 § 4 requires it, and an operator wants to see it");

            Assert.That(run.StdOut, Does.Contain("ntske/1"),
                        "the ALPN protocol identifier of § 4");

            Assert.That(run.StdOut, Does.Contain("Cookies"),
                        "how many cookies came back is the thing that decides how long a client " +
                        "can keep asking the time");

            Assert.That(run.StdOut, Does.Contain("EndOfMessage"),
                        "the records themselves, since diagnosing a key exchange means looking " +
                        "at them");

        });

    }


    /// <summary>
    /// A key exchange that cannot happen fails, and says which stage failed.
    /// </summary>
    /// <remarks>
    /// Naming the stage is the whole reason <c>ke</c> exists separately from <c>query</c>: "the
    /// query timed out" is what an NTS client says when a certificate does not validate, and it
    /// sends the reader looking at the wrong protocol.
    /// </remarks>
    [Test]
    public void KeyExchange_AgainstNothing_Fails()
    {

        var run = Norn.Run([ "ke", "--ke-port", fixture!.NTSKEPort.ToString(),
                             "--timeout", "2", "--insecure", "--ipv4", "norn-cli.invalid" ]);

        Assert.Multiple(() => {
            Assert.That(run.ExitCode, Is.EqualTo(1), run.Transcript);
            Assert.That(run.StdErr,   Does.Contain("key exchange"));
        });

    }

    #endregion


    #region --json

    /// <summary>
    /// In JSON mode, stdout is a JSON document and nothing else.
    /// </summary>
    /// <remarks>
    /// The rule that makes the mode worth having. A single line of progress on stdout turns
    /// every consumer into a parse error, and the error appears nowhere near its cause — so this
    /// parses the whole stream rather than searching it for a JSON-looking part.
    /// </remarks>
    [TestCase("query")]
    [TestCase("ke")]
    public void Json_PutsNothingButJsonOnStandardOutput(String Command)
    {

        var run = Norn.Run(Against(Command, "--json"));

        Assert.That(run.ExitCode, Is.Zero, run.Transcript);

        JObject document = null!;

        Assert.That(() => document = JObject.Parse(run.StdOut),
                    Throws.Nothing,
                    $"stdout was not one JSON object:\n{run.StdOut}");

        Assert.That(document["success"]?.Value<Boolean>(), Is.True, run.Transcript);
        Assert.That(document["host"]?.Value<String>(),     Is.EqualTo("localhost"));

    }


    /// <summary>
    /// The warning that <c>--insecure</c> prints goes to standard error, not into the document.
    /// </summary>
    /// <remarks>
    /// The test above would pass even if it did not, as long as the warning came after the
    /// document. This one pins the stream it goes to.
    /// </remarks>
    [Test]
    public void Json_KeepsDiagnosticsOffStandardOutput()
    {

        var run = Norn.Run(Against("query", "--json"));

        Assert.Multiple(() => {

            Assert.That(run.StdErr, Does.Contain("insecure"),
                        "the warning still has to be made");

            Assert.That(run.StdOut, Does.Not.Contain("insecure"),
                        "but not where a parser is reading");

        });

    }


    /// <summary>
    /// A failure produces a document too, saying what failed.
    /// </summary>
    /// <remarks>
    /// A machine-readable mode that stops being machine-readable on failure is one that a script
    /// can only use on the happy path — which is not the path anybody is watching for.
    /// </remarks>
    [Test]
    public void Json_DescribesAFailureToo()
    {

        var run = Norn.Run([ "query", "--plain", "--timeout", "1", "--json", "norn-cli.invalid" ]);

        Assert.That(run.ExitCode, Is.EqualTo(1), run.Transcript);

        JObject document = null!;

        Assert.That(() => document = JObject.Parse(run.StdOut),
                    Throws.Nothing,
                    $"stdout was not one JSON object:\n{run.StdOut}");

        Assert.Multiple(() => {
            Assert.That(document["success"]?.Value<Boolean>(), Is.False);
            Assert.That(document["measurements"]?[0]?["error"]?.Value<String>(), Is.Not.Empty);
        });

    }

    #endregion

}
