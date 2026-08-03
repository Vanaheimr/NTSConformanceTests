using NUnit.Framework;

namespace NTSConformance.CLI.Tests;

/// <summary>
/// The command line itself: what the tool accepts, what it refuses, and what it returns.
///
/// <para>
/// A command-line tool's contract is its arguments and its exit codes, and both are consumed by
/// scripts that cannot read prose. The two failures that matter here are silent ones: an option
/// that is accepted and then ignored, and an exit code of zero after something went wrong. Each
/// turns a script that looks like it is checking something into one that is not.
/// </para>
/// </summary>
[TestFixture]
public class CommandLineTests
{

    #region Exit codes say what happened

    /// <summary>
    /// Help is a success, and goes to standard output.
    /// </summary>
    /// <remarks>
    /// Both halves are conventions worth keeping: <c>norn --help | less</c> has to work, and a
    /// non-zero exit from an explicit request for help makes any script that runs it look
    /// broken.
    /// </remarks>
    [Test]
    public void Help_SucceedsAndGoesToStandardOutput()
    {

        var run = Norn.Run([ "--help" ]);

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.Zero, run.Transcript);

            Assert.That(run.StdOut, Does.Contain("query").And.Contain("ke").And.Contain("serve"),
                        "the help should name the commands");

            Assert.That(run.StdErr, Is.Empty,
                        "help is not a diagnostic");

        });

    }


    /// <summary>
    /// Every command has its own help, reachable even beside options that would be refused.
    /// </summary>
    /// <remarks>
    /// The second half is the point. Somebody reaches for <c>--help</c> precisely when the rest
    /// of what they typed is wrong, and a tool that answers the mistake instead of the question
    /// has picked the least useful of the two things it could say.
    /// </remarks>
    [TestCase("query")]
    [TestCase("ke")]
    [TestCase("serve")]
    public void EachCommandHasItsOwnHelp(String Command)
    {

        var plain    = Norn.Run([ Command, "--help" ]);
        var alongside = Norn.Run([ Command, "--nonsense", "--help" ]);

        Assert.Multiple(() => {

            Assert.That(plain.ExitCode,  Is.Zero, plain.Transcript);
            Assert.That(plain.StdOut,    Does.Contain($"norn {Command}"));
            Assert.That(plain.StdOut,    Does.Contain("Exit codes"),
                        "a tool meant for scripts has to document what it returns");

            Assert.That(alongside.ExitCode, Is.Zero, alongside.Transcript);
            Assert.That(alongside.StdOut,   Does.Contain($"norn {Command}"));

        });

    }


    /// <summary>
    /// A mistyped option is refused rather than ignored.
    /// </summary>
    /// <remarks>
    /// This is the failure that matters most and shows least. A tool that shrugs at
    /// <c>--tiemout 30</c> waits five seconds instead of thirty, succeeds, and never mentions
    /// it — so a monitoring script tuned over months is quietly running with none of its
    /// settings.
    /// </remarks>
    [Test]
    public void AMistypedOption_IsAUsageError()
    {

        var run = Norn.Run([ "query", "--tiemout", "30", "localhost" ]);

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.EqualTo(2), run.Transcript);

            Assert.That(run.StdErr, Does.Contain("--tiemout"),
                        "and it has to name the option, or the reader is left comparing their " +
                        "command line against the manual by eye");

        });

    }


    /// <summary>
    /// Usage errors are 2, distinct from the 1 that means the work failed.
    /// </summary>
    /// <remarks>
    /// A script needs to tell "your server is unreachable" from "you invoked me wrongly": the
    /// first is worth retrying and alerting on, the second never is.
    /// </remarks>
    [TestCase("frobnicate",                               TestName = "UsageErrorsAreTwo(unknown command)")]
    [TestCase("query",                                    TestName = "UsageErrorsAreTwo(no host)")]
    [TestCase("query|a|b",                                TestName = "UsageErrorsAreTwo(two hosts)")]
    [TestCase("query|--ipv4|--ipv6|localhost",            TestName = "UsageErrorsAreTwo(contradictory families)")]
    [TestCase("query|--port|0|localhost",                 TestName = "UsageErrorsAreTwo(port zero)")]
    [TestCase("query|--port|99999|localhost",             TestName = "UsageErrorsAreTwo(port too large)")]
    [TestCase("query|--count|-1|localhost",               TestName = "UsageErrorsAreTwo(negative count)")]
    [TestCase("query|--timeout|localhost",                TestName = "UsageErrorsAreTwo(option eats the host)")]
    [TestCase("query|not a hostname",                     TestName = "UsageErrorsAreTwo(not a host name)")]
    [TestCase("serve|--stratum|99",                       TestName = "UsageErrorsAreTwo(stratum out of range)")]
    [TestCase("serve|--refid|TOOLONG",                    TestName = "UsageErrorsAreTwo(reference identifier too long)")]
    [TestCase("serve|--cert|x.pem",                       TestName = "UsageErrorsAreTwo(certificate without key)")]
    [TestCase("serve|--no-interleaved|--auth-interleaved",TestName = "UsageErrorsAreTwo(contradictory interleaved policies)")]
    [TestCase("serve|somewhere",                          TestName = "UsageErrorsAreTwo(serve takes no host)")]
    public void UsageErrorsAreTwo(String CommandLine)
    {

        var run = Norn.Run(CommandLine.Split('|'));

        Assert.That(run.ExitCode,
                    Is.EqualTo(2),
                    $"'norn {CommandLine.Replace('|', ' ')}' should have been a usage error.\n{run.Transcript}");

    }


    /// <summary>
    /// No arguments prints the help and reports a usage error.
    /// </summary>
    /// <remarks>
    /// Both, deliberately. The help is what a person wants; the non-zero exit is what stops a
    /// script from treating an empty argument list — usually an unset variable — as a success.
    /// </remarks>
    [Test]
    public void NoArguments_PrintsHelpAndFailsAsUsage()
    {

        var run = Norn.Run([]);

        Assert.Multiple(() => {
            Assert.That(run.ExitCode, Is.EqualTo(2), run.Transcript);
            Assert.That(run.StdOut,   Does.Contain("Usage: norn"));
        });

    }


    /// <summary>
    /// An option given twice is refused rather than one of them silently winning.
    /// </summary>
    [Test]
    public void ARepeatedOption_IsAUsageError()
    {

        var run = Norn.Run([ "query", "--port", "123", "--port", "456", "localhost" ]);

        Assert.Multiple(() => {
            Assert.That(run.ExitCode, Is.EqualTo(2), run.Transcript);
            Assert.That(run.StdErr,   Does.Contain("--port"));
        });

    }


    /// <summary>
    /// A flag given a value is refused, rather than the value becoming the host name.
    /// </summary>
    /// <remarks>
    /// <c>norn query --plain=yes localhost</c> would otherwise be read as a flag plus two
    /// positional arguments, and the complaint would be about the host count — which is not
    /// where the mistake is.
    /// </remarks>
    [Test]
    public void AFlagWithAValue_IsAUsageError()
    {

        var run = Norn.Run([ "query", "--plain=yes", "localhost" ]);

        Assert.Multiple(() => {
            Assert.That(run.ExitCode, Is.EqualTo(2), run.Transcript);
            Assert.That(run.StdErr,   Does.Contain("--plain"));
        });

    }

    #endregion


    #region The forms of an option

    /// <summary>
    /// <c>--name=value</c> and <c>--name value</c> mean the same thing.
    /// </summary>
    /// <remarks>
    /// Asserted through a port number, because the two spellings taking different code paths
    /// through the parser is the sort of divergence nothing else would notice: both are accepted
    /// either way, and only the value differs.
    /// </remarks>
    [Test]
    public void BothSpellingsOfAnOption_AreTheSame()
    {

        // Port 1 on loopback answers nothing, so both of these fail — the point is that they
        // fail the same way, and neither as a usage error.
        var separate = Norn.Run([ "query", "--plain", "--port", "1", "--timeout", "1", "127.0.0.1" ]);
        var joined   = Norn.Run([ "query", "--plain", "--port=1", "--timeout=1", "127.0.0.1" ]);

        Assert.Multiple(() => {
            Assert.That(separate.ExitCode, Is.EqualTo(1), separate.Transcript);
            Assert.That(joined.ExitCode,   Is.EqualTo(1), joined.Transcript);
        });

    }


    /// <summary>
    /// The version is a bare version and nothing else.
    /// </summary>
    /// <remarks>
    /// Because something will parse it. A line of prose around the number is a line somebody has
    /// to strip, and they will strip it with a regular expression that breaks on the next
    /// release.
    /// </remarks>
    [Test]
    public void Version_IsJustTheVersion()
    {

        var run = Norn.Run([ "--version" ]);

        Assert.Multiple(() => {

            Assert.That(run.ExitCode, Is.Zero, run.Transcript);

            Assert.That(run.StdOut.Trim(),
                        Does.Match(@"^\d+\.\d+\.\d+"),
                        $"expected a version number, got '{run.StdOut.Trim()}'");

        });

    }

    #endregion

}
