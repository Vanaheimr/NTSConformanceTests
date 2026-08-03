using System.Diagnostics;
using System.Net;

using NUnit.Framework;

using NTSConformance.Core;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// The server side of RFC 8633 § 5.4, exercised directly rather than over a socket.
///
/// <para>
/// § 5.4 asks two things of a server, and only one of them is "limit the rate". The other is in
/// the same paragraph and easier to miss: "Kiss-o'-Death (KoD) packets can be used in
/// denial-of-service attacks", so the courtesy of telling a client it is being limited is itself
/// a packet somebody else can be made to receive. A limiter that answers every refused request
/// with a kiss has turned a server that was being flooded into one that floods.
/// </para>
/// <para>
/// So most of what is checked here is restraint rather than limiting: that the kisses are rarer
/// than the drops, that they stay rare when the source addresses are forged — the case where
/// per-client throttling is worth nothing — and that the state behind all of it is capped in
/// memory and in the work of enforcing the cap.
/// </para>
/// </summary>
[TestFixture]
public class RateLimiterTests
{

    private static IPAddress Address(Int32 index)
        => IPAddress.Parse($"198.51.{index / 256}.{index % 256}");


    #region The limit itself

    /// <summary>
    /// A burst up to the bucket depth is answered, and the request after it is not.
    /// </summary>
    /// <remarks>
    /// The burst is deliberately allowed. A client following RFC 5905's <c>iburst</c> opens with
    /// a volley of requests precisely so it can start serving time quickly, and a limiter that
    /// refused it would punish the best-behaved clients on the network.
    /// </remarks>
    [Test]
    public void ABurstUpToTheBucketDepth_IsAnswered()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:  TimeSpan.FromSeconds(2),
                                          Burst:            4,
                                          TimeProvider:     clock);

        var address  = Address(0);

        var answered = 0;

        for (var i = 0; i < 4; i++)
        {
            if (limiter.Check(address) == RateLimitDecision.Answer)
                answered++;
        }

        Assert.Multiple(() => {

            Assert.That(answered,
                        Is.EqualTo(4),
                        "a bucket four deep has to admit four requests before it is empty");

            Assert.That(limiter.Check(address),
                        Is.Not.EqualTo(RateLimitDecision.Answer),
                        "and the fifth, with no tokens left and no time elapsed, cannot be");

        });

    }


    /// <summary>
    /// Tokens come back with time, so a client polling at the permitted rate is never limited.
    /// </summary>
    [Test]
    public void AClientPollingAtThePermittedRate_IsNeverLimited()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:  TimeSpan.FromSeconds(2),
                                          Burst:            1,
                                          TimeProvider:     clock);

        var address  = Address(0);

        // Deliberately with a bucket of one, so nothing is being carried over: each of these is
        // answered only because the time for it has passed.
        for (var i = 0; i < 20; i++)
        {

            Assert.That(limiter.Check(address),
                        Is.EqualTo(RateLimitDecision.Answer),
                        $"request {i + 1} came a full interval after the last one and must be answered");

            clock.Advance(TimeSpan.FromSeconds(2));

        }

    }


    /// <summary>
    /// The bucket does not fill past its depth, however long the client was quiet.
    /// </summary>
    /// <remarks>
    /// Otherwise a client could bank an hour of silence and spend it in one second, which is the
    /// flood the limiter exists to stop — arriving with an alibi.
    /// </remarks>
    [Test]
    public void SilenceDoesNotAccumulateBeyondTheBurst()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:  TimeSpan.FromSeconds(2),
                                          Burst:            4,
                                          TimeProvider:     clock);

        var address  = Address(0);

        // The address has to be known and its bucket empty before the silence, or the hour is
        // never accrued at all: an address seen for the first time simply starts full, and the
        // refill this test is about does not run.
        for (var i = 0; i < 4; i++)
            limiter.Check(address);

        clock.Advance(TimeSpan.FromHours(1));

        var answered = 0;

        for (var i = 0; i < 50; i++)
        {
            if (limiter.Check(address) == RateLimitDecision.Answer)
                answered++;
        }

        Assert.That(answered,
                    Is.EqualTo(4),
                    "an hour of silence must be worth one bucket, not an hour of requests");

    }


    /// <summary>
    /// One address exhausting its bucket does not limit another.
    /// </summary>
    [Test]
    public void OneFloodingAddress_DoesNotLimitTheOthers()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:  TimeSpan.FromSeconds(2),
                                          Burst:            2,
                                          TimeProvider:     clock);

        for (var i = 0; i < 100; i++)
            limiter.Check(Address(0));

        Assert.That(limiter.Check(Address(1)),
                    Is.EqualTo(RateLimitDecision.Answer),
                    "the budget is per address, or one noisy client would take the server down " +
                    "for everybody — which is the attack, not the defence");

    }

    #endregion


    #region The kisses are rarer than the drops

    /// <summary>
    /// A limited client is told once, then met with silence until the kiss interval has passed.
    /// </summary>
    [Test]
    public void ALimitedClient_IsKissedOnceAndThenDropped()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:  TimeSpan.FromSeconds(2),
                                          Burst:            1,
                                          KissInterval:     TimeSpan.FromSeconds(30),
                                          TimeProvider:     clock);

        var address  = Address(0);

        limiter.Check(address);   // spends the only token

        var decisions = new List<RateLimitDecision>();

        for (var i = 0; i < 10; i++)
            decisions.Add(limiter.Check(address));

        Assert.Multiple(() => {

            Assert.That(decisions.Count(decision => decision == RateLimitDecision.KissOfDeath),
                        Is.EqualTo(1),
                        "ten refusals in an instant are worth exactly one explanation");

            Assert.That(decisions[0],
                        Is.EqualTo(RateLimitDecision.KissOfDeath),
                        "and it should come first, so a client that heeds it stops before the rest");

            Assert.That(decisions.Skip(1),
                        Is.All.EqualTo(RateLimitDecision.Drop));

        });

    }


    /// <summary>
    /// After the kiss interval, a still-limited client is told again.
    /// </summary>
    /// <remarks>
    /// Not merely symmetry with the test above. A client that was restarted, or that lost the
    /// first kiss to the network, has no way to learn it is being limited except by being told
    /// again — and RFC 5905 § 7.4 b expects a client to keep backing off "each time it receives
    /// a RATE kiss code", which presupposes there is a next time.
    /// </remarks>
    [Test]
    public void AfterTheKissInterval_ALimitedClientIsToldAgain()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:  TimeSpan.FromMinutes(10),
                                          Burst:            1,
                                          KissInterval:     TimeSpan.FromSeconds(30),
                                          TimeProvider:     clock);

        var address  = Address(0);

        limiter.Check(address);
        Assert.That(limiter.Check(address), Is.EqualTo(RateLimitDecision.KissOfDeath));

        clock.Advance(TimeSpan.FromSeconds(29));
        Assert.That(limiter.Check(address),
                    Is.EqualTo(RateLimitDecision.Drop),
                    "one second early is still early");

        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.That(limiter.Check(address),
                    Is.EqualTo(RateLimitDecision.KissOfDeath),
                    "past the interval the client may be told again");

    }


    /// <summary>
    /// A flood from forged source addresses cannot make the server spray kisses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the test the whole design is arranged around, and the one a per-client throttle
    /// alone would fail. Every address in this flood is new, so every one arrives with an unused
    /// kiss allowance of its own; the per-client interval never triggers. What holds the line is
    /// the global budget, and nothing else does.
    /// </para>
    /// <para>
    /// What it prevents is concrete: each kiss is a packet sent to an address the attacker chose,
    /// so without the budget a flood of 10,000 forged requests is 10,000 packets aimed at
    /// whomever the attacker named.
    /// </para>
    /// </remarks>
    [Test]
    public void AFloodOfForgedAddresses_CannotMakeTheServerSprayKisses()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:     TimeSpan.FromSeconds(2),
                                          // Zero depth per address, so that every single request
                                          // in this flood is refused and every one of them is a
                                          // candidate for a kiss.
                                          Burst:               1,
                                          MaxKissesPerSecond:  4,
                                          TimeProvider:        clock);

        var kisses   = 0;

        // 10,000 requests from 10,000 distinct addresses, all inside one instant.
        for (var i = 0; i < 10000; i++)
        {

            limiter.Check(Address(i));   // spends that address's single token

            if (limiter.Check(Address(i)) == RateLimitDecision.KissOfDeath)
                kisses++;

        }

        Assert.That(kisses,
                    Is.LessThanOrEqualTo(4),
                    $"no time passed, so the global budget of 4 kisses per second was never " +
                    $"refilled and at most its initial contents may be spent — {kisses} kisses " +
                    $"means a spoofed flood is being reflected at whatever address it names");

    }


    /// <summary>
    /// The global budget refills, so kisses are scarce rather than exhaustible.
    /// </summary>
    [Test]
    public void TheGlobalKissBudget_Refills()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:     TimeSpan.FromMinutes(10),
                                          Burst:               1,
                                          KissInterval:        TimeSpan.Zero,
                                          MaxKissesPerSecond:  4,
                                          TimeProvider:        clock);

        var address  = Address(0);

        limiter.Check(address);

        // Drain whatever the budget currently holds. Bounded, and by much more than four: no
        // time passes in this loop, so a limiter that keeps handing out kisses has no budget at
        // all, and that is a failure to report rather than a loop to sit in.
        var drained = 0;

        while (limiter.Check(address) == RateLimitDecision.KissOfDeath && drained < 1000)
            drained++;

        Assert.That(drained,
                    Is.LessThan(1000),
                    "the budget never ran out, so there is no budget");

        clock.Advance(TimeSpan.FromSeconds(1));

        Assert.That(limiter.Check(address),
                    Is.EqualTo(RateLimitDecision.KissOfDeath),
                    "a second's worth of budget should have come back");

    }


    /// <summary>
    /// A budget of zero switches the kisses off entirely and leaves the limiting intact.
    /// </summary>
    /// <remarks>
    /// The configuration for an operator who would rather a limited client saw nothing at all —
    /// RFC 8633 § 5.4 recommends the kiss but a server on a hostile network is entitled to
    /// decline, and silence is never worse than a packet an attacker chose the destination of.
    /// </remarks>
    [Test]
    public void AZeroKissBudget_LimitsSilently()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:     TimeSpan.FromSeconds(2),
                                          Burst:               1,
                                          MaxKissesPerSecond:  0,
                                          TimeProvider:        clock);

        var address  = Address(0);

        limiter.Check(address);

        Assert.That(limiter.Check(address),
                    Is.EqualTo(RateLimitDecision.Drop),
                    "still limited, just not explaining itself");

    }

    #endregion


    #region The poll value it asks for

    /// <summary>
    /// The kiss asks for a poll exponent that would actually stop the client being limited.
    /// </summary>
    [Test]
    public void TheKissPollExponent_CoversTheMinimumInterval()
    {

        Assert.Multiple(() => {

            // 2^6 = 64 s ≥ 60 s, and 2^5 = 32 s would not be.
            Assert.That(new NTPRateLimiter(MinimumInterval: TimeSpan.FromSeconds(60)).KissPollExponent,
                        Is.EqualTo(6));

            Assert.That(new NTPRateLimiter(MinimumInterval: TimeSpan.FromSeconds(64)).KissPollExponent,
                        Is.EqualTo(6),
                        "an exact power of two must not be rounded up to the next one");

            Assert.That(new NTPRateLimiter(MinimumInterval: TimeSpan.FromSeconds(65)).KissPollExponent,
                        Is.EqualTo(7));

        });

    }


    /// <summary>
    /// And it stays inside the range a conformant client would accept.
    /// </summary>
    /// <remarks>
    /// RFC 8633 § 5.4 tells the client not to accept a poll value above 13, because a huge one is
    /// a denial of service dressed as politeness. A server asking for more is therefore asking
    /// for something no careful client will grant; at the other end, RFC 5905's minimum poll
    /// exponent is 4, and a server whose limit is looser than that has nothing to ask for.
    /// </remarks>
    [Test]
    public void TheKissPollExponent_StaysWithinWhatAClientMayAccept()
    {

        Assert.Multiple(() => {

            Assert.That(new NTPRateLimiter(MinimumInterval: TimeSpan.FromDays(7)).KissPollExponent,
                        Is.EqualTo(NTPRateLimiter.MaxPollExponent),
                        "a week is poll exponent 20, and no conformant client will go past 13");

            Assert.That(new NTPRateLimiter(MinimumInterval: TimeSpan.FromMilliseconds(50)).KissPollExponent,
                        Is.EqualTo(4),
                        "a server that permits twenty requests a second cannot ask a client to " +
                        "poll faster than the protocol's own floor");

        });

    }

    #endregion


    #region The state behind it is bounded

    /// <summary>
    /// The client table never grows past its cap, however many addresses turn up.
    /// </summary>
    [Test]
    public void TheClientTable_NeverExceedsItsCap()
    {

        var limiter = new NTPRateLimiter(MaxClients:    8,
                                         TimeProvider:  new ManualClock());

        for (var i = 0; i < 500; i++)
            limiter.Check(Address(i));

        Assert.That(limiter.TrackedClients,
                    Is.EqualTo(8),
                    "the table an attacker fills has to be a fixed-length one");

    }


    /// <summary>
    /// And the address used longest ago is the one evicted.
    /// </summary>
    /// <remarks>
    /// Which way round this goes matters more here than for a cache. Evicting a tracked address
    /// forgets that it was being limited, so evicting the wrong one — the busy address rather
    /// than the idle one — would hand a full bucket back to the flood that caused the eviction.
    /// </remarks>
    [Test]
    public void TheLeastRecentlyUsedAddress_IsTheOneEvicted()
    {

        var clock    = new ManualClock();
        var limiter  = new NTPRateLimiter(MinimumInterval:  TimeSpan.FromMinutes(10),
                                          Burst:            1,
                                          MaxClients:       3,
                                          TimeProvider:     clock);

        var keeper   = Address(0);

        limiter.Check(keeper);        // spends the keeper's token
        limiter.Check(Address(1));
        limiter.Check(Address(2));
        limiter.Check(keeper);        // and uses it again, so it is no longer the oldest

        limiter.Check(Address(3));    // must push out Address(1)

        Assert.That(limiter.Check(keeper),
                    Is.Not.EqualTo(RateLimitDecision.Answer),
                    "the keeper's empty bucket should have survived the eviction; if it did " +
                    "not, a flood of fresh addresses is a way to reset one's own limit");

    }


    /// <summary>
    /// Checking stays constant-time as the table fills.
    /// </summary>
    /// <remarks>
    /// The same property, and the same reasoning, as the interleaved-mode store: the table is
    /// keyed by a source address the sender chooses, so an implementation that scans to find the
    /// least recently used entry does O(n) work per spoofed packet once full. Bounded memory
    /// without bounded work is not a defence.
    ///
    /// The two sizes are sixty-four times apart because sixteen was not enough. A scan of a
    /// 4096-entry table measured only about five times the cost of a 256-entry one — the
    /// per-entry cost is not constant across those sizes — which left almost no daylight above a
    /// threshold that also has to sit above scheduling noise. At sixty-four times the table a
    /// scan is an order of magnitude, and a constant-time implementation is still one.
    /// </remarks>
    [Test]
    [Category(TestCategories.Slow)]
    public void Eviction_DoesNotGetSlowerAsTheTableGrows()
    {

        static Double ChecksPerSecond(Int32 maxClients)
        {

            var limiter    = new NTPRateLimiter(MaxClients:    maxClients,
                                                TimeProvider:  new ManualClock());
            const Int32 n  = 20000;

            // Fill first, so every measured check is one that has to evict.
            for (var i = 0; i < maxClients; i++)
                limiter.Check(Address(i));

            var watch = Stopwatch.StartNew();

            for (var i = 0; i < n; i++)
                limiter.Check(Address(maxClients + i));

            watch.Stop();

            return n / watch.Elapsed.TotalSeconds;

        }

        // Warm up, so JIT compilation does not land inside the first measurement.
        ChecksPerSecond(64);

        var small = ChecksPerSecond(256);
        var large = ChecksPerSecond(16384);

        Assert.That(small / large,
                    Is.LessThan(4.0),
                    $"a sixty-fourfold larger table cost {small / large:F1}× per check, which is " +
                    $"the signature of a scan: {small:F0}/s at 256 entries against {large:F0}/s " +
                    $"at 16384. The size of that table is what a flood of forged addresses " +
                    $"controls.");

    }

    #endregion

}
