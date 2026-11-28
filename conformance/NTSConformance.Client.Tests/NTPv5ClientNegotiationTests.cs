using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;

namespace NTSConformance.Client.Tests;

/// <summary>
/// The client half of draft-ietf-ntp-ntpv5-10 § 12, against a scripted server that speaks
/// NTPv4 and, where the test says so, NTPv5.
///
/// <para>
/// § 12: a client that supports both versions and uses no NTS "SHOULD start with the previous
/// version and set the reference timestamp" to the magic - for a draft implementation
/// 0x4E54503544524654, "NTP5DRFT". "If the server responds with the same reference timestamp,
/// the client SHOULD switch to NTPv5. If no valid response is received for a number of
/// requests (e.g. 2), the client SHOULD switch back to the orignal NTP version and stick with it
/// for a larger number of requests (e.g. 256) before trying NTPv5 again."
/// </para>
/// <para>
/// Why the reference timestamp and not an extension field: NTPv4 implementations "are also known
/// to not respond to requests with an unknown extension field", and a client that asked in one
/// would lose its time from every server that does not speak NTPv5.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientNegotiationTests
{

    #region Data

    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(300);

    #endregion

    #region (private) Server(Echo, AnswerNTPv5)

    /// <summary>
    /// A script for a server that answers NTPv4 with the reference timestamp the given function
    /// makes of the request's - the same one, to echo it, or 0 for a reference time of its own,
    /// a minute ago - and NTPv5 where it is to.
    /// </summary>
    /// <remarks>
    /// Its own reference time, because an NTPv4 client takes a zero reference timestamp for a
    /// server that was never synchronized; and a transmit timestamp a microsecond later in each
    /// response, because the client's clock stands still and an NTPv4 client refuses a transmit
    /// timestamp it has seen before as a replay. Neither is what these tests are about.
    /// </remarks>
    private static Func<ReceivedNtpV5Request, IEnumerable<ScriptedDatagram>> Server(NTPv5ClientHarness  Harness,
                                                                                   Func<UInt64, UInt64> ReferenceTimestamp,
                                                                                   Func<Boolean>        AnswerNTPv5)

    {

        var responses = 0;

        return request => {

               var version = (request.Octets[0] >> 3) & 0x7;

               if (version == 5)
                   return AnswerNTPv5()
                              ? NTPv5ClientHarness.Send(Harness.Plain(request, TimeSpan.Zero))
                              : [];

               if (!RawNtpReader.TryRead(request.Octets, out var v4, out _))
                   return [];

               var now        = RawNtpTimestamp.FromDateTime(Harness.Now);
               var transmit   = RawNtpTimestamp.FromDateTime(Harness.Now + TimeSpan.FromTicks(10 * Interlocked.Increment(ref responses)));
               var reference  = ReferenceTimestamp(v4.ReferenceTimestamp);

               if (reference == 0)
                   reference = RawNtpTimestamp.FromDateTime(Harness.Now - TimeSpan.FromMinutes(1));

               return NTPv5ClientHarness.Send(RawNtpWriter.Write(new RawNtpPacket {
                                                                     Version             = 4,
                                                                     Mode                = RawNtpMode.Server,
                                                                     Stratum             = 1,
                                                                     Poll                = 6,
                                                                     Precision           = -20,
                                                                     RootDelay           = 0x10,
                                                                     RootDispersion      = 0x10,
                                                                     ReferenceTimestamp  = reference,
                                                                     OriginTimestamp     = v4.TransmitTimestamp,
                                                                     ReceiveTimestamp    = now,
                                                                     TransmitTimestamp   = transmit
                                                                 }.WithReferenceIdentifier("GPS")));

           };

    }


    /// <summary>
    /// The versions of the requests the server received, in order.
    /// </summary>
    private static Int32[] Versions(NTPv5ClientHarness Harness)
        => Harness.Server.Requests.Select(request => (request.Octets[0] >> 3) & 0x7).ToArray();


    /// <summary>
    /// The reference timestamps of the NTPv4 requests, in order.
    /// </summary>
    private static UInt64[] ReferenceTimestamps(NTPv5ClientHarness Harness)
        => Harness.Server.Requests.
                   Where (request => ((request.Octets[0] >> 3) & 0x7) == 4).
                   Select(request => RawNtpReader.ReadUInt64(request.Octets, 16)).
                   ToArray();

    #endregion


    /// <summary>
    /// § 12: the client starts with NTPv4 and the magic in the reference timestamp - the
    /// draft's: "Implementations of a draft of this specification SHOULD use 0x4E54503544524654
    /// ("NTP5DRFT" in ASCII) instead of 0x4E5450354E545035."
    /// </summary>
    [Test]
    public async Task TheFirstRequest_IsNTPv4_WithNTP5DRFTInTheReferenceTimestamp()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = Server(harness, _ => 0, () => false);

        var result = await harness.Client.QueryNegotiated(new NTPv5VersionNegotiation(), Timeout: TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {
            Assert.That(result.Success,                Is.True,                                       result.NTPv4?.ErrorMessage);
            Assert.That(Versions(harness),             Is.EqualTo(new[] { 4 }),                       "the versions sent");
            Assert.That(ReferenceTimestamps(harness),  Is.EqualTo(new[] { RawNtpV5Draft.NegotiationMagic }),
                        "the reference timestamp");
        });

    }


    /// <summary>
    /// § 12: "If the server responds with the same reference timestamp, the client SHOULD switch
    /// to NTPv5." The next request is NTPv5, and it is answered.
    /// </summary>
    [Test]
    public async Task AnEcho_SwitchesTheClientToNTPv5()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = Server(harness, echo => echo, () => true);

        var negotiation = new NTPv5VersionNegotiation();

        var first   = await harness.Client.QueryNegotiated(negotiation, Timeout: TimeSpan.FromSeconds(2));
        var second  = await harness.Client.QueryNegotiated(negotiation, Timeout: TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {
            Assert.That(first.NTPv4?.Success,   Is.True,                      first.NTPv4?.ErrorMessage);
            Assert.That(first.NextVersion,      Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));
            Assert.That(second.NTPv5?.Success,  Is.True,                      second.NTPv5?.ErrorMessage);
            Assert.That(Versions(harness),      Is.EqualTo(new[] { 4, 5 }),  "the versions sent");
        });

    }


    /// <summary>
    /// A server that answers NTPv4 without echoing - one that does not speak NTPv5, the case
    /// § 12 is there for - keeps the client in NTPv4, still asking.
    /// </summary>
    [Test]
    public async Task WithoutAnEcho_TheClientStaysWithNTPv4()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = Server(harness, _ => 0, () => true);

        var negotiation = new NTPv5VersionNegotiation();

        for (var i = 0; i < 3; i++)
            Assert.That((await harness.Client.QueryNegotiated(negotiation, Timeout: TimeSpan.FromSeconds(2))).Success, Is.True, $"query {i}");

        Assert.Multiple(() => {
            Assert.That(Versions(harness),             Is.EqualTo(new[] { 4, 4, 4 }));
            Assert.That(ReferenceTimestamps(harness),  Is.All.EqualTo(RawNtpV5Draft.NegotiationMagic));
        });

    }


    /// <summary>
    /// "the same reference timestamp": a server that answers a draft client's NTP5DRFT with the
    /// final NTP5NTP5 speaks the published protocol, not the draft this client implements, and
    /// switching would have it send requests the server reads by another specification.
    /// </summary>
    [Test]
    public async Task TheFinalMagicInAnswerToTheDraftOne_DoesNotSwitch()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = Server(harness, _ => RawNtpV5Draft.FinalNegotiationMagic, () => true);

        var result = await harness.Client.QueryNegotiated(new NTPv5VersionNegotiation(), Timeout: TimeSpan.FromSeconds(2));

        Assert.That(result.NextVersion, Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Advertising));

    }


    /// <summary>
    /// § 12: "If no valid response is received for a number of requests (e.g. 2), the client
    /// SHOULD switch back to the orignal NTP version and stick with it for a larger number of
    /// requests (e.g. 256) before trying NTPv5 again." With those numbers configured as 2 and 3:
    /// an echo, two NTPv5 requests unanswered, then three NTPv4 ones, then the magic again, and
    /// NTPv5 again. The server answers every NTPv4 request with the magic, asked or not: while
    /// the client sticks with NTPv4, that must not take it back to NTPv5.
    /// </summary>
    [Test]
    public async Task UnansweredNTPv5_FallsBackToNTPv4_ForAWhile()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = Server(harness, _ => RawNtpV5Draft.NegotiationMagic, () => false);

        var negotiation = new NTPv5VersionNegotiation(MaxFailures: 2, BackoffRequests: 3);

        for (var i = 0; i < 8; i++)
            await harness.Client.QueryNegotiated(negotiation, Timeout: Short);

        Assert.That(Versions(harness),
                    Is.EqualTo(new[] { 4, 5, 5, 4, 4, 4, 4, 5 }),
                    "advertise, switch, fail twice, stick with NTPv4 three times, advertise, switch");

    }


    /// <summary>
    /// And one unanswered NTPv5 request of the two allowed does not: a lost datagram is not a
    /// server that does not speak the version.
    /// </summary>
    [Test]
    public async Task OneUnansweredNTPv5Request_DoesNotFallBack()
    {

        await using var harness = new NTPv5ClientHarness();

        var answer = false;

        harness.Script = Server(harness, echo => echo, () => answer);

        var negotiation = new NTPv5VersionNegotiation(MaxFailures: 2);

        await harness.Client.QueryNegotiated(negotiation, Timeout: Short);          // NTPv4, echoed
        await harness.Client.QueryNegotiated(negotiation, Timeout: Short);          // NTPv5, lost

        answer = true;

        var third = await harness.Client.QueryNegotiated(negotiation, Timeout: TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {
            Assert.That(Versions(harness),     Is.EqualTo(new[] { 4, 5, 5 }));
            Assert.That(third.NTPv5?.Success,  Is.True, third.NTPv5?.ErrorMessage);
        });

    }

}
