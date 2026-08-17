namespace NTSConformance.Core;

/// <summary>
/// A clock that only moves when a test moves it — both the wall clock and the monotonic one,
/// together, the way a real machine's do.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TestClock"/> covers the wall clock alone, which is enough for anything that reads
/// <see cref="TimeProvider.GetUtcNow"/>. It is not enough for code that measures elapsed time
/// through <see cref="TimeProvider.GetTimestamp"/>, because the base implementation of that
/// ignores the override and returns real monotonic ticks — so a test using
/// <see cref="TestClock.FrozenAt"/> against such code would silently be measuring wall-clock
/// time, and would pass or fail depending on how busy the machine was.
/// </para>
/// <para>
/// Rate limiting is precisely that kind of code, and for a good reason: a rate limiter on a time
/// server must not read the clock it serves, since that one can be stepped. So the test needs a
/// monotonic clock it controls, which is this.
/// </para>
/// </remarks>
public sealed class ManualClock : TimeProvider
{

    private DateTimeOffset  now;
    private Int64           ticks;


    public ManualClock(DateTimeOffset? start = null)
    {
        now    = start ?? new DateTimeOffset(2030, 6, 1, 12, 0, 0, TimeSpan.Zero);
        ticks  = 0;
    }


    public override DateTimeOffset GetUtcNow()
        => now;

    public override Int64 GetTimestamp()
        => ticks;

    /// <summary>
    /// One tick per 100 ns, so that <see cref="TimeProvider.GetElapsedTime(Int64, Int64)"/>
    /// converts exactly rather than through a floating-point scale factor.
    /// </summary>
    public override Int64 TimestampFrequency
        => TimeSpan.TicksPerSecond;


    /// <summary>
    /// Move both clocks forward by the same amount.
    /// </summary>
    public void Advance(TimeSpan delta)
    {
        now    += delta;
        ticks  += delta.Ticks;
    }

}
