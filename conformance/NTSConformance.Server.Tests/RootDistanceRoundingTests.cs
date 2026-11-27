using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.Server.Tests;

/// <summary>
/// RFC 5905 §7.3 and §11.3: Root Delay and Root Dispersion travel in the 16.16 short format,
/// and a client adds both into the root distance, its bound on the error of the server's time.
///
/// A bound made smaller on the way to the wire is no bound. So a value that does not fit the
/// format exactly has to be rounded up, never down or to the nearest: 30 ms are 1966.08 units
/// and go out as 1967, and 100 ns are 0.0066 units and go out as 1, not as the "perfect clock"
/// of 0. Whole units stay whole, and a value the field cannot hold saturates at its largest
/// value instead of wrapping round to a small one.
///
/// Read on the wire, from the raw reply, so that no client-side conversion can hide what the
/// server sent. The server is redescribed between the cases rather than made anew: the
/// rounding is the server's encoding of whatever it is told, not a matter of how it started.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class RootDistanceRoundingTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync();


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// 65536 s, the first value the field cannot hold: 2^32 units.
    /// </summary>
    private static readonly Int64 SixtyFiveThousandFiveHundredThirtySixSeconds = 65536L * TimeSpan.TicksPerSecond;


    // Ticks, the 16.16 value the server must send, and why. Ticks because the interesting
    // values are a tick either side of a boundary, which a double in milliseconds cannot say.
    private static readonly Object[] Cases = [

        new Object[] { 0L,                                                    0x00000000U, "zero stays zero"                                   },
        new Object[] { 1L,                                                    0x00000001U, "100 ns, 0.0066 units, rounds up to 1 and not to 0" },
        new Object[] { 30L * TimeSpan.TicksPerMillisecond,                    1967U,       "30 ms, 1966.08 units, rounds up to 1967"           },
        new Object[] { TimeSpan.TicksPerSecond / 8,                           0x00002000U, "125 ms, exactly 8192 units, stays 8192"            },
        new Object[] { TimeSpan.TicksPerSecond,                               0x00010000U, "1 s, exactly 65536 units, stays 65536"             },
        new Object[] { 16L * TimeSpan.TicksPerSecond + 1,                     0x00100001U, "16 s (MAXDISP) and one tick, one unit above 16 s"  },
        new Object[] { SixtyFiveThousandFiveHundredThirtySixSeconds - 1,      0xFFFFFFFFU, "a tick under 65536 s rounds up past the field and saturates" },
        new Object[] { SixtyFiveThousandFiveHundredThirtySixSeconds,          0xFFFFFFFFU, "65536 s saturates"                                 },
        new Object[] { SixtyFiveThousandFiveHundredThirtySixSeconds * 2,      0xFFFFFFFFU, "131072 s saturates"                                }

    ];


    private RawNtpPacket AskWith(TimeSpan RootDelay, TimeSpan RootDispersion)
    {

        if (fixture is null)
            throw new InvalidOperationException("the server fixture did not start");

        fixture.Server.Redescribe(RootDelay:       RootDelay,
                                  RootDispersion:  RootDispersion);

        return RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(), "127.0.0.1", fixture.NTPPort);

    }


    /// <summary>
    /// Root Delay, on the plain path.
    /// </summary>
    [TestCaseSource(nameof(Cases))]
    public void RootDelay_IsRoundedUp_AndSaturates(Int64 Ticks, UInt32 Expected, String Why)
    {

        var response = AskWith(RootDelay:       TimeSpan.FromTicks(Ticks),
                               RootDispersion:  TimeSpan.FromMilliseconds(1));

        Assert.That(response.RootDelay, Is.EqualTo(Expected),
                    $"{Why}: a root delay of {TimeSpan.FromTicks(Ticks)} went out as 0x{response.RootDelay:X8}, " +
                    $"{RawNtpTimestamp.ShortToSeconds(response.RootDelay):R} s");

    }


    /// <summary>
    /// Root Dispersion, on the plain path. The one where rounding down matters most: a
    /// dispersion that reaches the wire as 0 claims a perfect clock.
    /// </summary>
    [TestCaseSource(nameof(Cases))]
    public void RootDispersion_IsRoundedUp_AndSaturates(Int64 Ticks, UInt32 Expected, String Why)
    {

        var response = AskWith(RootDelay:       TimeSpan.Zero,
                               RootDispersion:  TimeSpan.FromTicks(Ticks));

        Assert.That(response.RootDispersion, Is.EqualTo(Expected),
                    $"{Why}: a root dispersion of {TimeSpan.FromTicks(Ticks)} went out as 0x{response.RootDispersion:X8}, " +
                    $"{RawNtpTimestamp.ShortToSeconds(response.RootDispersion):R} s");

    }


    /// <summary>
    /// The NTS-protected reply encodes the same description the same way: a client applies the
    /// same root-distance arithmetic whether or not it used NTS.
    /// </summary>
    [Test]
    public async Task NtsReply_RoundsUpAsThePlainOneDoes()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        fixture.Server.Redescribe(RootDelay:       TimeSpan.FromMilliseconds(30),
                                  RootDispersion:  TimeSpan.FromTicks(1));

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                 Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success, Is.True, $"the query failed: {queryResult.ErrorMessage}");

        var response = queryResult.Response as NTPResponse;

        Assert.That(response, Is.Not.Null, "the reply is not an NTP response");

        Assert.Multiple(() => {
            Assert.That(response!.RootDelay,      Is.EqualTo(1967U), "30 ms, 1966.08 units, rounds up to 1967");
            Assert.That(response!.RootDispersion, Is.EqualTo(1U),    "100 ns, 0.0066 units, rounds up to 1 and not to 0");
        });

    }

}
