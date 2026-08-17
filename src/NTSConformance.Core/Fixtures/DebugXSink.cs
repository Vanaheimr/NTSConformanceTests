using System.Diagnostics;
using System.Text;

namespace NTSConformance.Core.Fixtures;

/// <summary>
/// Captures everything Styx's <c>DebugX</c> writes, so a test can assert what does
/// <em>not</em> appear in it.
///
/// <c>DebugX.Log</c> forwards to <see cref="Debug.WriteLine(String)"/>, which
/// <see cref="Trace.Listeners"/> receives. Note that <see cref="Debug"/> is
/// <c>[Conditional("DEBUG")]</c>: these assertions are only meaningful when the library
/// under test was compiled in Debug configuration, which is exactly the configuration a
/// developer runs — and therefore exactly where leaked key material would end up.
/// </summary>
public sealed class DebugXSink : IDisposable
{

    private readonly CapturingTraceListener listener;

    public DebugXSink()
    {
        listener = new CapturingTraceListener();
        Trace.Listeners.Add(listener);
    }


    /// <summary>
    /// Everything captured since construction, one entry per write.
    /// </summary>
    public IReadOnlyList<String> Entries
        => listener.Entries;

    /// <summary>
    /// All captured output as a single string.
    /// </summary>
    public String Text
        => String.Concat(listener.Entries);


    /// <summary>
    /// True when the captured output contains the given hex string, case-insensitively.
    /// </summary>
    public Boolean ContainsHex(Byte[] value)
    {

        if (value.Length == 0)
            return false;

        var lower = Convert.ToHexStringLower(value);
        var upper = Convert.ToHexString(value);

        return Text.Contains(lower, StringComparison.Ordinal) ||
               Text.Contains(upper, StringComparison.Ordinal);

    }


    /// <summary>
    /// The captured entries that contain the given hex string — for failure messages.
    /// </summary>
    public IEnumerable<String> EntriesContainingHex(Byte[] value)
    {

        var lower = Convert.ToHexStringLower(value);
        var upper = Convert.ToHexString(value);

        return listener.Entries.Where(entry => entry.Contains(lower, StringComparison.Ordinal) ||
                                               entry.Contains(upper, StringComparison.Ordinal));

    }


    public void Clear()
        => listener.Clear();


    public void Dispose()
    {
        Trace.Listeners.Remove(listener);
        listener.Dispose();
    }


    private sealed class CapturingTraceListener : TraceListener
    {

        private readonly List<String>  entries = [];
        private readonly Lock          guard   = new();
        private readonly StringBuilder pending = new();

        public IReadOnlyList<String> Entries
        {
            get
            {
                lock (guard)
                    return [ .. entries ];
            }
        }

        public override void Write(String? message)
        {

            if (message is null)
                return;

            lock (guard)
                pending.Append(message);

        }

        public override void WriteLine(String? message)
        {
            lock (guard)
            {

                pending.Append(message);
                entries.Add(pending.ToString());
                pending.Clear();

            }
        }

        public void Clear()
        {
            lock (guard)
            {
                entries.Clear();
                pending.Clear();
            }
        }

    }

}
