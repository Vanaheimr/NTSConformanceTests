namespace NTSConformance.Core;

/// <summary>
/// A clock a test controls, for servers that take a <see cref="TimeProvider"/>.
///
/// Hand-rolled rather than taken from Microsoft.Extensions.TimeProvider.Testing: two factory
/// methods are all this suite needs, and the point of injecting a clock here is to avoid
/// process-wide time manipulation, not to schedule timers.
/// </summary>
public sealed class TestClock : TimeProvider
{

    private readonly Func<DateTimeOffset> read;

    private TestClock(Func<DateTimeOffset> read)
    {
        this.read = read;
    }


    public override DateTimeOffset GetUtcNow()
        => read();


    /// <summary>
    /// A clock stopped at the given instant. It never advances, however long the test takes,
    /// which is also what makes it useful for asserting an exact reported time.
    /// </summary>
    public static TestClock FrozenAt(DateTimeOffset instant)
        => new (() => instant);


    /// <summary>
    /// The real clock, displaced. It still advances, so timestamps keep ordering correctly and
    /// only their absolute value is wrong — the way a genuinely misconfigured host behaves.
    /// </summary>
    public static TestClock ShiftedBy(TimeSpan offset)
        => new (() => DateTimeOffset.UtcNow + offset);

}
