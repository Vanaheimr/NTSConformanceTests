namespace NTSConformance.Core.RawNtp;

/// <summary>
/// NTP 64-bit timestamps (RFC 5905 §6): 32 bits of seconds since the prime epoch
/// 1900-01-01T00:00:00Z, then 32 bits of binary fraction.
///
/// Conversions here use exact integer arithmetic. Norn's <c>NTPPacket</c> routes the
/// fraction through a <c>Double</c>, which costs precision, so an independent exact
/// implementation is what makes that measurable.
/// </summary>
public static class RawNtpTimestamp
{

    /// <summary>
    /// The NTP prime epoch — start of era 0.
    /// </summary>
    public static readonly DateTime Epoch = new (1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>
    /// The instant the 32-bit seconds field wraps and era 1 begins:
    /// 2036-02-07T06:28:16Z. RFC 5905 §6 requires era-aware handling around it.
    /// </summary>
    public static readonly DateTime EraRollover = Epoch.AddSeconds(4294967296.0);

    /// <summary>
    /// Seconds per era (2^32).
    /// </summary>
    public const Int64 SecondsPerEra = 4294967296L;


    /// <summary>
    /// Convert a UTC instant to a 64-bit NTP timestamp within the given era.
    /// </summary>
    public static UInt64 FromDateTime(DateTime utc, Int32 era = 0)
    {

        var ticks         = (utc - Epoch).Ticks - era * SecondsPerEra * TimeSpan.TicksPerSecond;

        var seconds       = ticks / TimeSpan.TicksPerSecond;
        var remainder     = ticks % TimeSpan.TicksPerSecond;

        if (remainder < 0)
        {
            seconds   -= 1;
            remainder += TimeSpan.TicksPerSecond;
        }

        // fraction = remainder / TicksPerSecond * 2^32, exactly, in integer arithmetic.
        var fraction      = (UInt64) remainder * 4294967296UL / (UInt64) TimeSpan.TicksPerSecond;

        return ((UInt64) (UInt32) seconds << 32) | (UInt32) fraction;

    }


    /// <summary>
    /// Convert a 64-bit NTP timestamp back to UTC. <paramref name="era"/> selects the
    /// 136-year window: era 0 covers 1900-2036, era 1 covers 2036-2172.
    /// </summary>
    public static DateTime ToDateTime(UInt64 timestamp, Int32 era = 0)
    {

        var seconds   = (Int64) (timestamp >> 32) + era * SecondsPerEra;
        var fraction  = (UInt64) (UInt32) timestamp;

        var ticks     = seconds * TimeSpan.TicksPerSecond +
                        (Int64) (fraction * (UInt64) TimeSpan.TicksPerSecond / 4294967296UL);

        return Epoch.AddTicks(ticks);

    }


    /// <summary>
    /// Resolve the era for a timestamp given roughly when it is expected to have been
    /// generated — the disambiguation RFC 5905 §6 requires and Norn does not implement.
    /// </summary>
    public static Int32 EraFor(DateTime approximateUtc)
    {

        var secondsSinceEpoch = (Int64) (approximateUtc - Epoch).TotalSeconds;

        return (Int32) Math.Floor((Double) secondsSinceEpoch / SecondsPerEra);

    }


    /// <summary>
    /// The 32-bit seconds half.
    /// </summary>
    public static UInt32 Seconds(UInt64 timestamp)
        => (UInt32) (timestamp >> 32);

    /// <summary>
    /// The 32-bit binary-fraction half.
    /// </summary>
    public static UInt32 Fraction(UInt64 timestamp)
        => (UInt32) timestamp;


    /// <summary>
    /// A 16.16 fixed-point "short format" value (RFC 5905 §6) as used by
    /// Root Delay and Root Dispersion, converted to seconds.
    /// </summary>
    public static Double ShortToSeconds(UInt32 shortFormat)
        => shortFormat / 65536.0;

    /// <summary>
    /// Seconds to the 16.16 fixed-point short format.
    /// </summary>
    public static UInt32 SecondsToShort(Double seconds)
        => (UInt32) Math.Round(seconds * 65536.0);

}
