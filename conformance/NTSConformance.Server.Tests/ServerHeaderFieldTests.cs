using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.Server.Tests;

/// <summary>
/// RFC 5905 §7.3 header fields in the server's responses.
///
/// A response that authenticates perfectly can still be unusable: a client applies the
/// clock-selection rules of RFC 5905 §10-§11 to the stratum, root delay, root dispersion,
/// reference identifier and reference timestamp, and a server that leaves them unset is
/// claiming a perfectly accurate clock with no upstream — which is what a malicious server
/// would also claim.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ServerHeaderFieldTests
{

    private NornServerFixture? fixture;
    private NTPResponse?       response;


    [OneTimeSetUp]
    public async Task CaptureAResponse()
    {

        fixture = await NornServerFixture.StartAsync();

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success, Is.True, $"the query failed: {queryResult.ErrorMessage}");

        response = queryResult.Response as NTPResponse;

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>The fields the server does set correctly, as a regression guard.</summary>
    [Test]
    public void ModeStratumAndTimestamps_AreSet()
    {

        if (response is null)
        {
            Assert.Fail("no response was captured");
            return;
        }

        Assert.Multiple(() => {

            Assert.That(response.Mode,    Is.EqualTo(4), "a server response is mode 4");
            Assert.That(response.VN,      Is.EqualTo(4), "NTPv4");
            Assert.That(response.Stratum, Is.InRange((Byte) 1, (Byte) 15), "a usable stratum");

            Assert.That(response.ReceiveTimestamp,  Is.Not.EqualTo(0UL), "the receive timestamp");
            Assert.That(response.TransmitTimestamp, Is.Not.EqualTo(0UL), "the transmit timestamp");

            Assert.That(response.ReceiveTimestamp,
                        Is.LessThanOrEqualTo(response.TransmitTimestamp),
                        "a packet cannot be sent before it was received");

        });

    }


    /// <summary>
    /// F9 — RFC 5905 §7.3: the Reference Identifier at stratum 2 or above identifies the
    /// server's upstream source. Norn leaves it at 0.0.0.0, so a client cannot detect a
    /// timing loop (§11.2 relies on this to avoid syncing to itself through a cycle).
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public void ReferenceIdentifier_IdentifiesTheUpstreamSource()
    {

        if (response is null)
        {
            Assert.Fail("no response was captured");
            return;
        }

        Assert.That(response.ReferenceIdentifier.Integer,
                    Is.Not.EqualTo(0U),
                    $"at stratum {response.Stratum} the reference identifier should name the upstream source, " +
                    $"but it is {response.ReferenceIdentifier.AsIPv4Address?.ToString() ?? "0.0.0.0"}");

    }


    /// <summary>
    /// F9 — RFC 5905 §7.3: the Reference Timestamp is "the time when the system clock was
    /// last set or corrected". Norn sets it to the transmit time, which claims the clock was
    /// corrected at the instant of every reply and makes the field useless for judging how
    /// stale the server's synchronisation is.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public void ReferenceTimestamp_IsTheLastClockCorrection()
    {

        if (response is null)
        {
            Assert.Fail("no response was captured");
            return;
        }

        var reference = RawNtpTimestamp.ToDateTime(response.ReferenceTimestamp);
        var transmit  = RawNtpTimestamp.ToDateTime(response.TransmitTimestamp ?? 0);

        Assert.That((transmit - reference).Duration(),
                    Is.GreaterThan(TimeSpan.FromMilliseconds(1)),
                    $"the reference timestamp ({reference:O}) equals the transmit timestamp ({transmit:O}), " +
                     "so it does not record when the clock was last set");

    }


    /// <summary>
    /// F9 — RFC 5905 §7.3: Root Dispersion is the maximum error relative to the primary
    /// reference. Zero asserts a perfect clock, which no real server has; §11.3's root
    /// distance calculation then understates the true uncertainty, and a client cannot tell
    /// this server apart from one deliberately claiming false precision.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public void RootDispersion_IsNotZero()
    {

        if (response is null)
        {
            Assert.Fail("no response was captured");
            return;
        }

        Assert.That(response.RootDispersion,
                    Is.Not.EqualTo(0U),
                    $"at stratum {response.Stratum} a root dispersion of exactly zero claims a perfect clock");

    }

}
