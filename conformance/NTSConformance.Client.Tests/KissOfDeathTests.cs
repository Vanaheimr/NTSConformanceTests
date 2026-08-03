using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// The client half of RFC 5905 § 7.4 and RFC 8633 § 5.4: reading a kiss code, and obeying it
/// without letting it be used as a weapon.
///
/// <para>
/// Both halves are needed and they pull in opposite directions. § 7.4 says MUST — demobilize on
/// "DENY" or "RSTR", slow down on "RATE" — and a client that ignores that is the misbehaving
/// client the BCP is written about. But § 5.4 also says "Kiss-o'-Death (KoD) packets can be used
/// in denial-of-service attacks", because a KoD is an unauthenticated packet whose entire content
/// is an instruction to stop. Obeying it fully and obeying it safely are two different designs,
/// and the difference is what is tested here.
/// </para>
/// <para>
/// Two defences make the difference. A kiss is only believed if it echoes the request, so an
/// off-path attacker who cannot see the request cannot forge one. And the poll value inside it is
/// read as a suggestion with a ceiling, so the worst a kiss that does get through can do is halve
/// the polling rate — not stop it.
/// </para>
/// </summary>
[TestFixture]
public class KissOfDeathTests
{

    #region Reading a kiss

    private const UInt64 RequestTransmit  = 0xE300_0000_0000_0001UL;
    private const UInt64 RequestReceive   = 0xE300_0000_0000_0002UL;


    private static NTPPacket Request()

        => new (Mode:                3,
                OriginateTimestamp:  0,
                ReceiveTimestamp:    RequestReceive,
                TransmitTimestamp:   RequestTransmit);


    private static NTPPacket Kiss(String   Code,
                                  UInt64?  Origin  = null,
                                  Byte?    Poll    = null,
                                  Byte?    Stratum = null)

        => new (Mode:                 4,
                Stratum:              Stratum ?? 0,
                Poll:                 Poll    ?? 10,
                ReferenceIdentifier:  ReferenceIdentifier.From(Code),
                OriginateTimestamp:   Origin  ?? RequestTransmit,
                ReceiveTimestamp:     0xE300_0000_0000_0010UL,
                TransmitTimestamp:    0xE300_0000_0000_0011UL);


    /// <summary>
    /// A well-formed RATE kiss answering this client's own request is read, with the code and the
    /// poll value the server sent.
    /// </summary>
    [Test]
    public void AKissAnsweringOurRequest_IsRead()
    {

        Assert.That(NTPKissOfDeath.TryRead(Kiss("RATE"), Request(), out var kiss), Is.True);

        Assert.Multiple(() => {
            Assert.That(kiss.Code,         Is.EqualTo("RATE"));
            Assert.That(kiss.PollExponent, Is.EqualTo(10));
            Assert.That(kiss.Action,       Is.EqualTo(NTPKissAction.ReducePollingRate));
        });

    }


    /// <summary>
    /// A kiss that does not echo the request is not believed.
    /// </summary>
    /// <remarks>
    /// RFC 8633 § 5.4: "a client MUST only accept a KoD packet if it has a valid origin
    /// timestamp." This is the whole defence. An off-path attacker can send a client any packet
    /// it likes and can guess the address, the port and the server it talks to — what it cannot
    /// do without seeing the request is know the 64-bit timestamp inside it. Drop this check and
    /// a single forged datagram takes a client off its time source.
    /// </remarks>
    [Test]
    public void AKissThatDoesNotEchoTheRequest_IsNotBelieved()
    {

        Assert.That(NTPKissOfDeath.TryRead(Kiss("DENY", Origin: 0xDEAD_BEEF_DEAD_BEEFUL),
                                           Request(),
                                           out _),
                    Is.False,
                    "a stratum-0 packet with the wrong origin timestamp is a forgery attempt, " +
                    "and 'DENY' is what a forger would send");

    }


    /// <summary>
    /// Nor is one that cannot be checked at all.
    /// </summary>
    /// <remarks>
    /// Without the request there is nothing to compare the origin timestamp against, and
    /// "unverifiable" has to fail the same way "wrong" does — otherwise the check is one lost
    /// reference away from not being there.
    /// </remarks>
    [Test]
    public void AKissWithNoRequestToCheckItAgainst_IsNotBelieved()
    {

        Assert.That(NTPKissOfDeath.TryRead(Kiss("RATE"), null, out _),
                    Is.False);

    }


    /// <summary>
    /// An interleaved-mode kiss is believed: it echoes the request's receive timestamp instead.
    /// </summary>
    /// <remarks>
    /// RFC 9769 § 2 changes which of the request's timestamps a valid response echoes, and a
    /// client in an interleaved association that applied only RFC 5905's test would find every
    /// kiss from its server unverifiable — and so would obey none of them.
    /// </remarks>
    [Test]
    public void AnInterleavedKiss_IsBelieved()
    {

        Assert.That(NTPKissOfDeath.TryRead(Kiss("RATE", Origin: RequestReceive),
                                           Request(),
                                           out var kiss),
                    Is.True);

        Assert.That(kiss.Code, Is.EqualTo("RATE"));

    }


    /// <summary>
    /// A packet with a usable stratum is not a kiss, whatever its reference identifier says.
    /// </summary>
    /// <remarks>
    /// § 7.4 makes stratum 0 the thing that turns the reference identifier from a clock source
    /// into a message. A stratum-1 server whose reference identifier happens to read "RATE" is
    /// describing where its time comes from.
    /// </remarks>
    [Test]
    public void AStratum1Response_IsNotAKiss()
    {

        Assert.That(NTPKissOfDeath.TryRead(Kiss("RATE", Stratum: 1), Request(), out _),
                    Is.False);

    }


    /// <summary>
    /// Each defined code maps to what § 7.4 says to do about it.
    /// </summary>
    [TestCase("DENY", NTPKissAction.Demobilize)]
    [TestCase("RSTR", NTPKissAction.Demobilize)]
    [TestCase("RATE", NTPKissAction.ReducePollingRate)]
    [TestCase("NTSN", NTPKissAction.RenegotiateNTS)]
    // § 7.4 d: "Other than the above conditions, KoD packets have no protocol significance."
    [TestCase("INIT", NTPKissAction.Ignore)]
    [TestCase("AUTH", NTPKissAction.Ignore)]
    // § 7.4 c: experimental codes "MUST be ignored if not recognized". RFC 9748 later reserved
    // the whole X… space in the IANA registry for exactly this.
    [TestCase("XDNY", NTPKissAction.Ignore)]
    [TestCase("ZZZZ", NTPKissAction.Ignore)]
    public void EachCode_MapsToWhatTheRfcSaysToDoAboutIt(String Code, NTPKissAction Expected)
    {

        Assert.That(NTPKissOfDeath.TryRead(Kiss(Code), Request(), out var kiss), Is.True);

        Assert.That(kiss.Action, Is.EqualTo(Expected), $"kiss code '{Code}'");

    }


    /// <summary>
    /// An experimental code that looks like a real one is still ignored.
    /// </summary>
    /// <remarks>
    /// The case § 7.4 c is actually about. "XRATE" cannot fit, but "XRAT" can, and a client that
    /// pattern-matched loosely would obey it. The rule is that the X prefix wins.
    /// </remarks>
    [Test]
    public void AnExperimentalCode_IsIgnoredEvenWhenItResemblesARealOne()
    {

        Assert.That(NTPKissOfDeath.TryRead(Kiss("XRAT"), Request(), out var kiss), Is.True);

        Assert.Multiple(() => {
            Assert.That(kiss.IsExperimental, Is.True);
            Assert.That(kiss.Action,         Is.EqualTo(NTPKissAction.Ignore));
        });

    }


    /// <summary>
    /// A stratum-0 packet whose reference identifier is not text is not a kiss code.
    /// </summary>
    [Test]
    public void AStratum0PacketWithoutAReadableCode_IsNotAKiss()
    {

        var notText = new NTPPacket(Mode:                 4,
                                    Stratum:              0,
                                    ReferenceIdentifier:  ReferenceIdentifier.From(0x01, 0x02, 0x03, 0x04),
                                    OriginateTimestamp:   RequestTransmit,
                                    TransmitTimestamp:    1);

        Assert.That(NTPKissOfDeath.TryRead(notText, Request(), out _),
                    Is.False,
                    "four arbitrary octets are not a message this client can read, and guessing " +
                    "at them is how an unrelated stratum-0 packet becomes an instruction");

    }

    #endregion


    #region Obeying it

    private static readonly DateTimeOffset Now = new (2030, 6, 1, 12, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// A RATE kiss slows this client down, and by the amount the server asked for.
    /// </summary>
    [Test]
    public void ARateKiss_SlowsTheClientToWhatTheServerAskedFor()
    {

        var state = new NTPServerAccessState();

        Assert.That(state.MayQuery(Now), Is.True, "nothing has been said yet");

        state.Apply(new NTPKissOfDeath("RATE", 9), Now);

        Assert.Multiple(() => {

            Assert.That(state.PollExponent, Is.EqualTo(9));

            Assert.That(state.PollInterval, Is.EqualTo(TimeSpan.FromSeconds(512)));

            Assert.That(state.MayQuery(Now + TimeSpan.FromSeconds(511)),
                        Is.False,
                        "§ 7.4 b: the reduction has to be immediate, not from the next round");

            Assert.That(state.MayQuery(Now + TimeSpan.FromSeconds(513)),
                        Is.True,
                        "and it is a slower rate, not a shutdown");

        });

    }


    /// <summary>
    /// A RATE kiss carrying an enormous poll value is obeyed only as far as the ceiling.
    /// </summary>
    /// <remarks>
    /// RFC 8633 § 5.4: "If the client uses the poll interval value sent by the server in the RATE
    /// packet, it MUST NOT simply accept any value. Using large interval values may create a
    /// vector for a denial-of-service attack that causes the client to stop querying its server."
    ///
    /// Poll 255 is 2^255 seconds. A client that took it literally would be told to come back well
    /// after the heat death of the universe, by a packet anybody able to see one request could
    /// send.
    /// </remarks>
    [Test]
    public void ARateKissAskingForTheImpossible_IsObeyedOnlyToTheCeiling()
    {

        var state = new NTPServerAccessState();

        state.Apply(new NTPKissOfDeath("RATE", 255), Now);

        Assert.Multiple(() => {

            Assert.That(state.PollExponent,
                        Is.EqualTo(NTPServerAccessState.DefaultMaximumPollExponent),
                        "13, the value RFC 8633 § 5.4 names");

            Assert.That(state.MayQuery(Now + TimeSpan.FromHours(3)),
                        Is.True,
                        "two hours later at the very worst, whatever the packet demanded");

        });

    }


    /// <summary>
    /// Every RATE kiss slows the client further, even one asking for a rate it already keeps.
    /// </summary>
    /// <remarks>
    /// § 7.4 b: "continue to reduce it each time it receives a RATE kiss code". Without the
    /// step, a client already polling at the rate the server names would keep being limited and
    /// keep not changing — obeying the letter of the kiss and none of its point.
    /// </remarks>
    [Test]
    public void EachRateKiss_SlowsTheClientFurther()
    {

        var state = new NTPServerAccessState();

        var exponents = new List<Byte>();

        for (var i = 0; i < 12; i++)
        {
            // Deliberately asking for less than the client has already reached.
            state.Apply(new NTPKissOfDeath("RATE", 4), Now);
            exponents.Add(state.PollExponent);
        }

        Assert.Multiple(() => {

            Assert.That(exponents.Take(9),
                        Is.EqualTo(new Byte[] { 5, 6, 7, 8, 9, 10, 11, 12, 13 }).AsCollection,
                        "one step per kiss, up to the ceiling");

            Assert.That(exponents[^1],
                        Is.EqualTo(NTPServerAccessState.DefaultMaximumPollExponent),
                        "and no further, however many arrive");

        });

    }


    /// <summary>
    /// "DENY" and "RSTR" stop this client talking to the server at all.
    /// </summary>
    /// <remarks>
    /// § 7.4 a: "the client MUST demobilize any associations to that server and stop sending
    /// packets to that server". Not back off — stop. The server has said the client is not
    /// welcome, and continuing to ask is the behaviour operators send these to end.
    /// </remarks>
    [TestCase("DENY")]
    [TestCase("RSTR")]
    public void DenyAndRstr_StopTheClientEntirely(String Code)
    {

        var state = new NTPServerAccessState();

        state.Apply(new NTPKissOfDeath(Code, 4), Now);

        Assert.Multiple(() => {

            Assert.That(state.Demobilized, Is.True);

            Assert.That(state.MayQuery(Now + TimeSpan.FromDays(365)),
                        Is.False,
                        "a year is not long enough: nothing the client can observe without " +
                        "sending packets will change the answer, so this ends when an operator " +
                        "says it does");

        });

    }


    /// <summary>
    /// A code with no protocol significance changes nothing.
    /// </summary>
    /// <remarks>
    /// The measurement is lost either way — the packet carries no usable time. What must not
    /// happen is the association changing because of a code the client does not understand,
    /// which is exactly what § 7.4 c and d are guarding against.
    /// </remarks>
    [Test]
    public void AnIgnoredCode_ChangesNothing()
    {

        var state = new NTPServerAccessState();

        state.Apply(new NTPKissOfDeath("XDNY", 255), Now);

        Assert.Multiple(() => {
            Assert.That(state.Demobilized,  Is.False);
            Assert.That(state.PollExponent, Is.EqualTo(NTPServerAccessState.DefaultMinimumPollExponent));
            Assert.That(state.MayQuery(Now), Is.True);
        });

    }


    /// <summary>
    /// An NTS NAK is not a statement about access or rate.
    /// </summary>
    /// <remarks>
    /// RFC 8915 § 5.7's NAK borrows the Kiss-o'-Death form to say the cookie could not be used.
    /// It is answered by running NTS-KE again, not by backing off — a client that slowed down on
    /// every NAK would take the longest possible time to recover from a key rotation.
    /// </remarks>
    [Test]
    public void AnNtsNak_DoesNotSlowTheClientDown()
    {

        var state = new NTPServerAccessState();

        state.Apply(new NTPKissOfDeath("NTSN", 13), Now);

        Assert.Multiple(() => {
            Assert.That(state.MayQuery(Now), Is.True);
            Assert.That(state.Demobilized,   Is.False);
            Assert.That(state.PollExponent,  Is.EqualTo(NTPServerAccessState.DefaultMinimumPollExponent));
        });

    }


    /// <summary>
    /// A reset puts the association back, which is how an operator overrides a demobilization.
    /// </summary>
    [Test]
    public void Reset_RestoresTheAssociation()
    {

        var state = new NTPServerAccessState();

        state.Apply(new NTPKissOfDeath("DENY", 4), Now);
        state.Reset();

        Assert.Multiple(() => {
            Assert.That(state.Demobilized,   Is.False);
            Assert.That(state.MayQuery(Now), Is.True);
            Assert.That(state.LastKiss,      Is.Null);
        });

    }

    #endregion


    #region Against a real rate-limited server

    /// <summary>
    /// A Norn client querying a rate-limited Norn server reads the RATE kiss off the wire.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything above is the client reasoning about packets handed to it. This is the join:
    /// the kiss the server builds from an unparsed datagram, carried over a real socket, has to
    /// be one the client's own origin-timestamp check accepts. Each side is conformant on its
    /// own without that being true — the server could echo a timestamp the client does not
    /// compare against, and both test suites would still be green.
    /// </para>
    /// <para>
    /// A burst of one, so the second query is the limited one and no test spends a poll interval
    /// waiting.
    /// </para>
    /// </remarks>
    [Test]
    [Category(TestCategories.Loopback)]
    public async Task TheClient_ReadsARateKissFromARateLimitedServer()
    {

        await using var fixture = await NornServerFixture.StartAsync(
                                            rateLimiter: new NTPRateLimiter(
                                                             MinimumInterval:  TimeSpan.FromMinutes(10),
                                                             Burst:            1
                                                         )
                                        );

        var client = fixture.CreateClient(timeout: TimeSpan.FromSeconds(2));

        var first  = await client.QueryTime();

        Assert.That(first.KissOfDeath,
                    Is.Null,
                    $"the first query is inside the burst: {first.ErrorMessage}");

        var second = await client.QueryTime();

        Assert.That(second.KissOfDeath,
                    Is.Not.Null,
                    $"the second query was rate-limited and the kiss should have been read: " +
                    $"{second.ErrorCategory} / {second.ErrorMessage}");

        Assert.Multiple(() => {

            Assert.That(second.KissOfDeath!.Value.Code,
                        Is.EqualTo("RATE"));

            Assert.That(second.KissOfDeath!.Value.Action,
                        Is.EqualTo(NTPKissAction.ReducePollingRate));

            Assert.That(second.ErrorCategory,
                        Is.EqualTo(NTSQueryErrorCategory.KissOfDeath),
                        "and the query is reported as failed, because no time came back");

        });

    }

    #endregion

}
