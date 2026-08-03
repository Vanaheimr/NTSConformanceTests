using System.Diagnostics;
using System.Reflection;
using System.Text;

using NUnit.Framework;

namespace NTSConformance.CLI.Tests;

/// <summary>
/// One run of the <c>norn</c> executable: what it printed, and what it returned.
/// </summary>
/// <param name="ExitCode">The process exit code.</param>
/// <param name="StdOut">Everything on standard output.</param>
/// <param name="StdErr">Everything on standard error.</param>
public sealed record NornRun(Int32 ExitCode, String StdOut, String StdErr)
{

    /// <summary>Both streams together, for a failure message that shows everything.</summary>
    public String Transcript

        => $"exit {ExitCode}\n--- stdout ---\n{StdOut}\n--- stderr ---\n{StdErr}";

}


/// <summary>
/// Runs the built <c>norn</c> executable.
/// </summary>
/// <remarks>
/// <para>
/// As a process, not as a library call. A command-line tool is an interface made of argument
/// strings, exit codes and two output streams, and none of those four is exercised by calling
/// the method behind it. The failures a CLI actually has — an option that parses as something
/// else, an exit code that says success after a failure, diagnostics written to the stream a
/// pipe is reading — are invisible from inside the process.
/// </para>
/// <para>
/// That is also why this project references NornCLI with
/// <c>ReferenceOutputAssembly="false"</c>: there is deliberately no way to reach past the
/// command line from here.
/// </para>
/// </remarks>
public static class Norn
{

    private static readonly Lazy<String> executable = new (Locate);


    /// <summary>The path to the built tool.</summary>
    public static String Executable
        => executable.Value;


    private static String Locate()
    {

        var directory = typeof(Norn).Assembly.
                            GetCustomAttributes<AssemblyMetadataAttribute>().
                            FirstOrDefault(attribute => attribute.Key == "NornCLIDirectory")?.Value
                                ?? throw new InvalidOperationException(
                                       "the build did not record where the norn executable is");

        foreach (var name in new[] { "norn.exe", "norn" })
        {

            var path = Path.GetFullPath(Path.Combine(directory, name));

            if (File.Exists(path))
                return path;

        }

        throw new FileNotFoundException(
            $"the norn executable is not in '{Path.GetFullPath(directory)}'. " +
             "It is a ProjectReference of this test project, so a successful build should have " +
             "put it there.");

    }


    /// <summary>
    /// Run the tool and wait for it.
    /// </summary>
    /// <param name="arguments">The command line, already split into arguments.</param>
    /// <param name="timeout">How long to wait before giving up and killing it.</param>
    public static NornRun Run(IEnumerable<String>  arguments,
                              TimeSpan?            timeout = null)
    {

        var startInfo = new ProcessStartInfo(Executable) {
                            RedirectStandardOutput  = true,
                            RedirectStandardError   = true,
                            UseShellExecute         = false,
                            // The tool prints ASCII, but a server certificate's subject need not
                            // be, and a mangled one should look mangled here rather than being
                            // repaired by the reader.
                            StandardOutputEncoding  = Encoding.UTF8,
                            StandardErrorEncoding   = Encoding.UTF8
                        };

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo)
                                ?? throw new InvalidOperationException($"could not start '{Executable}'");

        // Read both streams while the process runs. Waiting first and reading afterwards
        // deadlocks as soon as either pipe fills, which for these commands is a page or two of
        // output away.
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError. ReadToEndAsync();

        if (!process.WaitForExit((Int32) (timeout ?? TimeSpan.FromSeconds(60)).TotalMilliseconds))
        {

            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // It may have exited between the timeout and here.
            }

            Assert.Fail($"'norn {String.Join(' ', arguments)}' did not finish in time.\n" +
                        $"stdout so far:\n{stdout.Result}");

        }

        return new NornRun(process.ExitCode,
                           stdout.GetAwaiter().GetResult(),
                           stderr.GetAwaiter().GetResult());

    }


    /// <summary>
    /// Start the tool and leave it running, for <c>serve</c>.
    /// </summary>
    /// <remarks>
    /// Output is drained in the background, because a server that fills its stdout pipe stops
    /// serving — and it would do so several seconds in, which is exactly when a test has
    /// stopped watching.
    /// </remarks>
    public static NornProcess Start(IEnumerable<String> arguments)
    {

        var startInfo = new ProcessStartInfo(Executable) {
                            RedirectStandardOutput  = true,
                            RedirectStandardError   = true,
                            UseShellExecute         = false,
                            StandardOutputEncoding  = Encoding.UTF8,
                            StandardErrorEncoding   = Encoding.UTF8
                        };

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        var process = Process.Start(startInfo)
                          ?? throw new InvalidOperationException($"could not start '{Executable}'");

        return new NornProcess(process);

    }

}


/// <summary>
/// A running <c>norn</c> process, drained and disposable.
/// </summary>
public sealed class NornProcess : IDisposable
{

    private readonly Process        process;
    private readonly StringBuilder  output   = new ();
    private readonly Lock           padlock  = new ();

    internal NornProcess(Process Process)
    {

        process = Process;

        Drain(Process.StandardOutput);
        Drain(Process.StandardError);

    }


    /// <summary>
    /// Accumulate one stream as it arrives.
    /// </summary>
    /// <remarks>
    /// Chunk by chunk rather than with ReadToEnd, which is the whole point: ReadToEnd completes
    /// at end of stream, so against a server — a process that does not exit — it never yields
    /// anything at all, and a test waiting for a line of its output waits forever. Both streams
    /// go into one buffer because a caller looking for "is it listening yet" does not care which
    /// of the two carried it.
    /// </remarks>
    private void Drain(StreamReader Reader)

        => _ = Task.Run(async () => {

               var buffer = new Char[1024];

               try
               {

                   while (true)
                   {

                       var read = await Reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);

                       if (read <= 0)
                           break;

                       lock (padlock)
                           output.Append(buffer, 0, read);

                   }

               }
               catch
               {
                   // The pipe closes when the process is killed, which is how these end.
               }

           });


    /// <summary>Whether it is still running.</summary>
    public Boolean IsRunning
        => !process.HasExited;


    /// <summary>
    /// Wait until the output contains the given text, or give up.
    /// </summary>
    public Boolean WaitForOutput(String Fragment, TimeSpan? Timeout = null)
    {

        var deadline = DateTime.UtcNow + (Timeout ?? TimeSpan.FromSeconds(20));

        while (true)
        {

            if (Snapshot.Contains(Fragment, StringComparison.Ordinal))
                return true;

            // One more look after it exits: the last of its output may still be in flight
            // between the pipe and the buffer.
            if (process.HasExited)
            {
                Thread.Sleep(100);
                return Snapshot.Contains(Fragment, StringComparison.Ordinal);
            }

            if (DateTime.UtcNow >= deadline)
                return false;

            Thread.Sleep(50);

        }

    }


    /// <summary>Everything both streams have produced so far.</summary>
    public String Snapshot
    {
        get
        {
            lock (padlock)
                return output.ToString();
        }
    }


    /// <summary>Everything printed so far, for a failure message.</summary>
    public String Transcript
        => Snapshot;


    public void Dispose()
    {

        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Teardown must not mask the failure under investigation.
        }

        try
        {
            process.WaitForExit(5000);
        }
        catch
        { }

        process.Dispose();

    }

}
