using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSConformance.Client.Tests;

/// <summary>
/// RFC 5905 § 6: an NTP timestamp carries only the low 32 bits of the seconds since 1900, so it
/// wraps every 136 years, first on 2036-02-07T06:28:16Z, and the era has to come from context.
/// The context a client has is its own clock - and the clock asking NTP for the time is the one
/// that may be wrong.
///
/// The device the 2036 discussion is about (IETF 127, "The 2036 rollover in practice") is
/// embedded gear without a battery-backed clock, which boots at the Unix epoch and asks NTP what
/// time it is. A server's time after 2036 has to come out after 2036 for it, not 136 years
/// earlier, or it sets itself to the early 1900s. The era nearest 1970 does exactly that for
/// every time after 2038-01-19. The decoder-level test of the same rule is
/// TimestampTests.Norn_ResolvesTheEra_EvenWithItsClockResetTo1970; this one runs the whole
/// exchange, because what a client does with the answer is its measured offset.
///
/// Both clocks are frozen, so T1 = T4 and T2 = T3, and the offset has to be exactly the server's
/// time minus the client's: what the client would step its clock by. The client's clock is a
/// TimeProvider, and the era has to be resolved against it, not against the machine running the
/// test - the case of a client in 2060 and a server in 2100 is wrong when resolved against a
/// machine in 2026. The cases the nearest-era rule always got right are here too, so that a fix
/// for the reset clock cannot break them.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class EraRolloverWithAWrongClockTests
{

    /// <summary>
    /// Both clocks are frozen, so the offset is exact up to the fraction and its rounding.
    /// </summary>
    private static readonly TimeSpan tolerance = TimeSpan.FromSeconds(1);

    private static readonly DateTimeOffset unixEpoch      = new (1970,  1,  1,  0,  0,  0, TimeSpan.Zero);
    private static readonly DateTimeOffset y2k            = new (2000,  1,  1,  0,  0,  0, TimeSpan.Zero);
    private static readonly DateTimeOffset beforeRollover = new (2036,  2,  7,  6, 28,  0, TimeSpan.Zero);
    private static readonly DateTimeOffset afterRollover  = new (2036,  2,  7,  6, 28, 30, TimeSpan.Zero);


    // The client's clock, the server's, and what the case is about.
    private static readonly Object[] Cases = [

        // A clock reset to the Unix epoch, which is what the test is for.
        new Object[] { unixEpoch,      new DateTimeOffset(2026, 11, 27, 12, 0, 0, TimeSpan.Zero), "clock reset to 1970, server in era 0 (today)"                               },
        new Object[] { unixEpoch,      new DateTimeOffset(2036,  6,  1, 12, 0, 0, TimeSpan.Zero), "clock reset to 1970, server just into era 1, still nearer 1970 than 1900"  },
        new Object[] { unixEpoch,      new DateTimeOffset(2038,  6,  1, 12, 0, 0, TimeSpan.Zero), "clock reset to 1970, server past 2038-01-19, its era-0 reading (1902) is nearer" },
        new Object[] { unixEpoch,      new DateTimeOffset(2040,  1,  1,  0, 0, 0, TimeSpan.Zero), "clock reset to 1970, server in 2040"                                        },
        new Object[] { unixEpoch,      new DateTimeOffset(2060,  1,  1,  0, 0, 0, TimeSpan.Zero), "clock reset to 1970, server in 2060"                                        },

        // A clock reset to 2000, the other common default of real-time clock chips.
        new Object[] { y2k,            new DateTimeOffset(2040,  1,  1,  0, 0, 0, TimeSpan.Zero), "clock reset to 2000, server in 2040"                                        },

        // Clocks that are roughly right, across the boundary in both directions.
        new Object[] { beforeRollover, afterRollover,                                             "client 30 s before the rollover, server 30 s after"                        },
        new Object[] { afterRollover,  beforeRollover,                                            "client 30 s after the rollover, server 30 s before"                        },

        // Resolved against the client's clock, not the machine's: against 2026, the server's
        // 2100 is nearer its era-0 reading of 1964.
        new Object[] { new DateTimeOffset(2060, 1, 1, 0, 0, 0, TimeSpan.Zero),
                                       new DateTimeOffset(2100,  1,  1,  0, 0, 0, TimeSpan.Zero), "client in 2060, server in 2100: the era comes from the client's clock"      }

    ];


    [TestCaseSource(nameof(Cases))]
    public async Task TheOffset_IsTheServersTimeMinusTheClients(DateTimeOffset  ClientClock,
                                                                DateTimeOffset  ServerClock,
                                                                String          Why)
    {

        await using var fixture = await NornServerFixture.StartAsync(timeProvider: TestClock.FrozenAt(ServerClock));

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10),
                                               TestClock.FrozenAt(ClientClock));

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"{Why}: NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                 Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success, Is.True, $"{Why}: the query failed: {queryResult.ErrorMessage}");

        var expected = ServerClock - ClientClock;
        var measured = queryResult.Response!.ClockOffset;

        Assert.That(measured, Is.Not.Null, $"{Why}: the client reported no offset");

        Assert.That(measured!.Value,
                    Is.EqualTo(expected).Within(tolerance),
                    $"{Why}: with its clock at {ClientClock:O} the client must correct itself to the server's " +
                    $"{ServerClock:O}, an offset of {expected.TotalDays / 365.2425:F2} years, but it measured " +
                    $"{measured.Value.TotalDays / 365.2425:F2} years and would set itself to {(ClientClock + measured.Value):O}");

    }

}
