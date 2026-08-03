using System.Diagnostics;
using System.Net;

using NUnit.Framework;

using NTSConformance.Core;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// The bounds on RFC 9769's server-side state, exercised directly rather than over a socket.
///
/// <para>
/// § 2 asks a server to "discard old timestamps to limit the amount of memory used for the
/// interleaved mode, e.g., by using a fixed-length queue". That is the only thing the RFC says
/// about resources, and it is worth more attention than one sentence suggests: this is state a
/// server keeps per client address, on a protocol where the source address is whatever the
/// sender wrote in it. Every packet of a spoofed flood arrives as a new client.
/// </para>
/// <para>
/// So the caps are load-bearing, and so is what they cost to enforce. A table that stays
/// bounded but takes longer to evict from as it fills is not bounded in the way that matters —
/// the first version here scanned for the least recently used entry, which turned each spoofed
/// packet into a pass over the whole table.
/// </para>
/// </summary>
[TestFixture]
public class InterleavedTimestampStoreTests
{

    private static NTPPacket Request(UInt64 origin, UInt64 receive, UInt64 transmit)

        => new (OriginateTimestamp:  origin,
                ReceiveTimestamp:    receive,
                TransmitTimestamp:   transmit);


    private static IPAddress Address(Int32 index)
        => IPAddress.Parse($"198.51.{index / 256}.{index % 256}");


    /// <summary>
    /// An exchange, completed as the server completes one: the response is built, sent, and the
    /// transmit timestamp recorded afterwards.
    /// </summary>
    private static InterleavedExchange Complete(InterleavedTimestamps  Store,
                                                IPAddress              From,
                                                NTPPacket              RequestPacket,
                                                UInt64                 ReceivedAt,
                                                Boolean                Authenticated = false)
    {

        var exchange = Store.BeginExchange(From,
                                           ReceivedAt,
                                           RequestPacket,
                                           TimeProvider.System,
                                           Authenticated);

        exchange.RecordTransmission(ReceivedAt + 1000);

        return exchange;

    }


    #region The caps hold

    /// <summary>
    /// The client table never grows past its cap, however many addresses turn up.
    /// </summary>
    [Test]
    public void TheClientTable_NeverExceedsItsCap()
    {

        var store = new InterleavedTimestamps(MaxClients: 8);

        for (var i = 0; i < 500; i++)
            Complete(store, Address(i), Request(0, 0, (UInt64) (i + 1)), (UInt64) (i + 1) << 32);

        Assert.That(store.TrackedClients,
                    Is.EqualTo(8),
                    "the table is a fixed-length structure, not a cache that grows under load");

    }


    /// <summary>
    /// And the address used longest ago is the one that goes.
    ///
    /// The alternative — refusing new clients once full — would let whoever arrived first keep
    /// the mode to themselves indefinitely, which on a public server means whoever probed it
    /// first after a restart.
    /// </summary>
    [Test]
    public void TheLeastRecentlyUsedAddress_IsTheOneEvicted()
    {

        var store  = new InterleavedTimestamps(MaxClients: 3);
        var keeper = Address(0);

        // Three addresses, then the first one used again so it is no longer the oldest.
        var first  = Complete(store, keeper,     Request(0, 0, 1), 1UL << 32);
        Complete(store, Address(1), Request(0, 0, 2), 2UL << 32);
        Complete(store, Address(2), Request(0, 0, 3), 3UL << 32);
        Complete(store, keeper,     Request(0, 0, 4), 4UL << 32);

        // A fourth address must now push out Address(1), not the keeper.
        Complete(store, Address(3), Request(0, 0, 5), 5UL << 32);

        var stillThere = store.BeginExchange(keeper,
                                             6UL << 32,
                                             Request(first.ReceiveTimestamp, 0xAAAA, 6),
                                             TimeProvider.System);

        Assert.That(stillThere.IsInterleaved,
                    Is.True,
                    "the address used most recently should have survived the eviction");

    }


    /// <summary>
    /// Evicting stays constant-time as the table fills.
    ///
    /// <para>
    /// This is the one test here that measures rather than asserts a value, which is worth
    /// justifying. The property is not "eviction is fast" — it is that the cost of one insertion
    /// does not grow with the size of the table, because the size is what an attacker sending
    /// forged source addresses controls. A scan-based implementation is O(n) per insertion and
    /// therefore O(n) work per spoofed packet; that is the shape being ruled out, and only a
    /// comparison across sizes can see the shape.
    /// </para>
    /// <para>
    /// Sixteen times the table for four times the work is a deliberately loose threshold. A
    /// linear implementation is off by the full factor of sixteen and fails wide; the slack is
    /// there so that scheduling noise on a busy machine cannot fail a correct one.
    /// </para>
    /// </summary>
    [Test]
    [Category(TestCategories.Slow)]
    public void Eviction_DoesNotGetSlowerAsTheTableGrows()
    {

        static Double InsertionsPerSecond(Int32 maxClients)
        {

            var store       = new InterleavedTimestamps(MaxClients: maxClients);
            const Int32 n   = 20000;

            // Fill first, so every measured insertion is one that has to evict.
            for (var i = 0; i < maxClients; i++)
                Complete(store, Address(i), Request(0, 0, (UInt64) (i + 1)), (UInt64) (i + 1) << 32);

            var watch = Stopwatch.StartNew();

            for (var i = 0; i < n; i++)
                Complete(store, Address(maxClients + i), Request(0, 0, (UInt64) (i + 1)), (UInt64) (i + 1) << 32);

            watch.Stop();

            return n / watch.Elapsed.TotalSeconds;

        }

        // Warm up, so JIT compilation does not land inside the first measurement.
        InsertionsPerSecond(64);

        var small = InsertionsPerSecond(256);
        var large = InsertionsPerSecond(4096);

        Assert.That(small / large,
                    Is.LessThan(4.0),
                    $"a sixteenfold larger table cost {small / large:F1}× per insertion, which is " +
                    $"the signature of a scan: {small:F0}/s at 256 entries against {large:F0}/s " +
                    $"at 4096. Eviction has to be independent of the table size, because the " +
                    $"table size is what a flood of forged source addresses controls.");

    }


    /// <summary>
    /// Per address, only a fixed number of exchanges is remembered — the "fixed-length queue"
    /// of § 2. Without it a single client could pin unbounded state by never completing an
    /// interleaved exchange.
    /// </summary>
    [Test]
    public void OneAddress_CannotRememberUnboundedExchanges()
    {

        var store    = new InterleavedTimestamps(MaxExchangesPerClient: 2);
        var address  = Address(0);

        var oldest   = Complete(store, address, Request(0, 0, 1), 1UL << 32);
        Complete(store, address, Request(0, 0, 2), 2UL << 32);
        Complete(store, address, Request(0, 0, 3), 3UL << 32);

        // The first exchange has been pushed out of a two-deep queue, so echoing its receive
        // timestamp can no longer select the interleaved mode.
        var tooOld = store.BeginExchange(address,
                                         4UL << 32,
                                         Request(oldest.ReceiveTimestamp, 0xAAAA, 4),
                                         TimeProvider.System);

        Assert.That(tooOld.IsInterleaved,
                    Is.False,
                    "a timestamp the server no longer holds must fall back to the basic mode, " +
                    "which § 2 explicitly allows: the client will get an interleaved answer to " +
                    "its next request instead");

    }

    #endregion


    #region The policy

    /// <summary>
    /// Under <see cref="InterleavedModePolicy.AuthenticatedOnly"/>, an unauthenticated request
    /// leaves nothing behind. That is the entire point of the policy: not that the answer is
    /// basic — it would be anyway, for want of a matching timestamp — but that the address never
    /// occupies a slot.
    /// </summary>
    [Test]
    public void AuthenticatedOnly_RemembersNothingAboutUnauthenticatedClients()
    {

        var store = new InterleavedTimestamps(InterleavedModePolicy.AuthenticatedOnly);

        for (var i = 0; i < 100; i++)
            Complete(store, Address(i), Request(0, 0, (UInt64) (i + 1)), (UInt64) (i + 1) << 32);

        Assert.That(store.TrackedClients,
                    Is.Zero,
                    "a flood of unauthenticated addresses must not be able to occupy the table");

    }


    /// <summary>
    /// And an authenticated client under the same policy gets the mode in full.
    /// </summary>
    [Test]
    public void AuthenticatedOnly_StillServesAuthenticatedClients()
    {

        var store    = new InterleavedTimestamps(InterleavedModePolicy.AuthenticatedOnly);
        var address  = Address(0);

        var first    = Complete(store, address, Request(0, 0, 1), 1UL << 32, Authenticated: true);

        var second   = store.BeginExchange(address,
                                           2UL << 32,
                                           Request(first.ReceiveTimestamp, 0xAAAA, 2),
                                           TimeProvider.System,
                                           Authenticated: true);

        Assert.Multiple(() => {

            Assert.That(second.IsInterleaved, Is.True);

            Assert.That(second.TransmitTimestamp,
                        Is.EqualTo((1UL << 32) + 1000),
                        "and it carries the transmit timestamp recorded after the first " +
                        "response went out");

        });

    }

    #endregion

}
