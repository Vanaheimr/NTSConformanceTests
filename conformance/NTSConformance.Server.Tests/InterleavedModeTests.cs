using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// RFC 9769 § 2, the interleaved client/server mode, driven against Norn's server.
///
/// <para>
/// The problem it solves: a server cannot know when a response left until after it has left.
/// Reading the clock, building the header, encrypting the extension fields and writing into the
/// socket all happen between the timestamp the client is told and the transmission it actually
/// measured, and every bit of that lands in the client's delay estimate as if it were network.
/// So the interleaved mode has the server report the transmit timestamp of the
/// <em>previous</em> response, captured after that one was gone, and the client completes the
/// earlier measurement with it.
/// </para>
/// <para>
/// What makes it delicate is that nothing on the wire says which mode a packet is in. There is
/// no extension field, no header change, no negotiation — only which of the server's own
/// earlier timestamps the client echoed in the origin field. A server that gets the bookkeeping
/// wrong answers an ordinary basic-mode request with a transmit timestamp belonging to some
/// other exchange, and the client has no way to know.
/// </para>
/// <para>
/// These tests are written with <see cref="RawNtpPacket"/> rather than Norn's client, because
/// the whole subject is the exact contents of three header fields. The reference codec can put
/// anything in them, including the combinations no conformant client would ever send, which is
/// what the negative cases need.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class InterleavedModeTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
    {
        fixture = await NornServerFixture.StartAsync();
    }


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    #region helpers

    /// <summary>
    /// A plain NTPv4 client request with the three timestamp fields set exactly as given.
    /// </summary>
    private static RawNtpPacket Request(UInt64 origin,
                                        UInt64 receive,
                                        UInt64 transmit)

        => new () {
               LeapIndicator      = RawNtpLeapIndicator.NoWarning,
               Version            = 4,
               Mode               = RawNtpMode.Client,
               Poll               = 6,
               OriginTimestamp    = origin,
               ReceiveTimestamp   = receive,
               TransmitTimestamp  = transmit
           };


    private RawNtpPacket Exchange(RawNtpPacket request)

        => RawNtpExchange.Exchange(request,
                                   "127.0.0.1",
                                   fixture!.NTPPort,
                                   timeout: TimeSpan.FromSeconds(10));


    /// <summary>
    /// A timestamp of this machine's own making, distinct on every call. What it means is
    /// irrelevant to the server — a client's transmit timestamp is a cookie to be echoed, not a
    /// time the server reads — but it has to be unique, or two exchanges become
    /// indistinguishable.
    /// </summary>
    private static UInt64 clientTimestampCounter = 0xE800_0000_0000_0001;

    private static UInt64 ClientTimestamp()
        => Interlocked.Increment(ref clientTimestampCounter);


    /// <summary>
    /// The opening exchange of any association: RFC 9769 § 2 — "The first request from a client
    /// is always in the basic mode, and so is the server response. It has a zero origin
    /// timestamp and zero receive timestamp."
    /// </summary>
    private RawNtpPacket BasicExchange()
        => Exchange(Request(origin: 0, receive: 0, transmit: ClientTimestamp()));

    #endregion


    #region The basic mode is unchanged

    /// <summary>
    /// A first request must draw a basic-mode response, recognizable by its origin timestamp
    /// echoing the request's <em>transmit</em> timestamp.
    ///
    /// Everything else here depends on this: if the server answered the opening exchange in some
    /// other way, no client could ever get as far as an interleaved request.
    /// </summary>
    [Test]
    public void TheFirstExchange_IsInTheBasicMode()
    {

        var transmit  = ClientTimestamp();
        var response  = Exchange(Request(origin: 0, receive: 0, transmit: transmit));

        Assert.Multiple(() => {

            Assert.That(response.OriginTimestamp,
                        Is.EqualTo(transmit),
                        "a basic-mode response echoes the request's transmit timestamp");

            Assert.That(response.ReceiveTimestamp,  Is.Not.Zero, "the server must report when it received the request");
            Assert.That(response.TransmitTimestamp, Is.Not.Zero, "and when it answered");

        });

    }


    /// <summary>
    /// RFC 9769 § 2: "Both servers and clients that support the interleaved mode MUST NOT send a
    /// packet that has a transmit timestamp equal to the receive timestamp in order to reliably
    /// detect whether received packets conform to the interleaved mode."
    ///
    /// If the two were equal, a client could not tell which of them a later origin timestamp was
    /// echoing, and the two modes would become indistinguishable.
    ///
    /// <para>
    /// Run against a <em>stopped</em> clock, and that is the whole point of the test. On a
    /// machine whose clock advances between any two reads this rule can never be violated, so a
    /// test on the real clock passes whether the server enforces anything or not — as this one
    /// did until a mutation showed it would pass with the enforcement deleted. A clock that
    /// never advances is the honest model of the case the rule exists for: a coarse system clock
    /// where two reads microseconds apart return the same value.
    /// </para>
    /// </summary>
    [Test]
    public async Task AResponse_NeverHasEqualReceiveAndTransmitTimestamps()
    {

        await using var stopped = await NornServerFixture.StartAsync(
                                            timeProvider: TestClock.FrozenAt(
                                                              new DateTimeOffset(2031, 3, 14, 15, 9, 26, TimeSpan.Zero)));

        Assert.Multiple(() => {

            for (var i = 0; i < 5; i++)
            {

                var response = RawNtpExchange.Exchange(Request(0, 0, ClientTimestamp()),
                                                       "127.0.0.1", stopped.NTPPort,
                                                       timeout: TimeSpan.FromSeconds(10));

                Assert.That(response.TransmitTimestamp,
                            Is.Not.EqualTo(response.ReceiveTimestamp),
                            $"exchange {i + 1}: receive and transmit timestamps are both " +
                            $"0x{response.ReceiveTimestamp:X16}");

            }

        });

    }


    /// <summary>
    /// RFC 9769 § 2: "the server SHOULD check that the transmit and receive timestamps are not
    /// already saved as a receive timestamp of a previous request ... and generate a new
    /// timestamp if necessary, to prevent an incorrect interleaved response later."
    ///
    /// A duplicate receive timestamp is what lets one exchange be mistaken for another: the next
    /// interleaved request echoing it would be answered with the transmit timestamp of whichever
    /// exchange the server happened to find first.
    ///
    /// Against a stopped clock again, for the same reason — a clock that advances hands out
    /// distinct values without the server doing anything, and proves nothing.
    /// </summary>
    [Test]
    public async Task ReceiveTimestamps_AreUniqueEvenWhenTheClockDoesNotAdvance()
    {

        await using var stopped = await NornServerFixture.StartAsync(
                                            timeProvider: TestClock.FrozenAt(
                                                              new DateTimeOffset(2031, 3, 14, 15, 9, 26, TimeSpan.Zero)));

        var seen = new List<UInt64>();

        for (var i = 0; i < 5; i++)
            seen.Add(RawNtpExchange.Exchange(Request(0, 0, ClientTimestamp()),
                                             "127.0.0.1", stopped.NTPPort,
                                             timeout: TimeSpan.FromSeconds(10)).ReceiveTimestamp);

        Assert.That(seen.Distinct().Count(),
                    Is.EqualTo(seen.Count),
                    $"the clock never moved, so every receive timestamp came back the same " +
                    $"unless the server made them unique: " +
                    $"{String.Join(", ", seen.Select(timestamp => $"0x{timestamp:X16}"))}");

    }

    #endregion


    #region An interleaved request draws an interleaved response

    /// <summary>
    /// The second exchange of Figure 1. Having seen a response, the client echoes that
    /// response's <em>receive</em> timestamp as its origin — RFC 9769 § 2: "A client request in
    /// the interleaved mode has an origin timestamp equal to the receive timestamp from the last
    /// valid server response."
    ///
    /// The server must recognize it and answer in kind: "A server response in the interleaved
    /// mode has an origin timestamp equal to the receive timestamp from the client request."
    /// That echo is the only thing telling the client which mode it is looking at, and so the
    /// only thing telling it whether the transmit timestamp beside it belongs to this response
    /// or the one before.
    /// </summary>
    [Test]
    public void ARequestEchoingTheReceiveTimestamp_IsAnsweredInTheInterleavedMode()
    {

        var first          = BasicExchange();

        var clientReceive  = ClientTimestamp();
        var clientTransmit = ClientTimestamp();

        var second         = Exchange(Request(origin:    first.ReceiveTimestamp,
                                              receive:   clientReceive,
                                              transmit:  clientTransmit));

        Assert.That(second.OriginTimestamp,
                    Is.EqualTo(clientReceive),
                    $"the response should be interleaved, echoing the request's receive " +
                    $"timestamp 0x{clientReceive:X16}; echoing the transmit timestamp " +
                    $"0x{clientTransmit:X16} instead would mean the server answered in the " +
                    $"basic mode and did not recognize the request");

    }


    /// <summary>
    /// The point of the whole mechanism, and the one assertion that would still fail if
    /// everything else here passed.
    ///
    /// A server can implement the mode-switching perfectly and still gain nothing, by putting
    /// the same estimate in the interleaved response that it already sent. What must arrive is
    /// the transmit timestamp captured <em>after</em> the previous response went out — later, by
    /// exactly the time the server spent building, encrypting and writing it, which is the error
    /// the basic mode charges to the network.
    ///
    /// Strictly later, and by a plausible amount: a value indistinguishable from the one already
    /// reported means the timestamp was never re-taken.
    /// </summary>
    [Test]
    public void TheInterleavedTransmitTimestamp_IsTakenAfterThePreviousResponseWentOut()
    {

        var first    = BasicExchange();

        var second   = Exchange(Request(origin:    first.ReceiveTimestamp,
                                        receive:   ClientTimestamp(),
                                        transmit:  ClientTimestamp()));

        Assert.That(second.TransmitTimestamp,
                    Is.GreaterThan(first.TransmitTimestamp),
                    "the interleaved transmit timestamp must be the moment the previous " +
                    "response actually left, which is necessarily after the estimate that " +
                    "response carried");

        // 2^32 units to the second, per RFC 5905 §6.
        var difference = (second.TransmitTimestamp - first.TransmitTimestamp) / 4294967296.0;

        Assert.That(difference,
                    Is.LessThan(1.0),
                    $"the two timestamps describe the same transmission, so they should differ " +
                    $"by the cost of sending one packet, not by {difference:F6} s");

    }


    /// <summary>
    /// And the interleaved transmit timestamp must be the previous response's, not this one's.
    /// A server that simply re-read its clock would produce something later than its own receive
    /// timestamp for this exchange; a genuine interleaved answer is older than that, because the
    /// transmission it describes happened before this request arrived.
    /// </summary>
    [Test]
    public void TheInterleavedTransmitTimestamp_PredatesTheCurrentExchange()
    {

        var first   = BasicExchange();

        // That timestamp is captured after the send, so on a loaded machine the capture can
        // lose a microsecond race against this next request arriving — the first nightly's
        // referee lost it by 19 µs. A real client cannot ask faster than its own network
        // turnaround; granting the capture that head start keeps the assertion below strict
        // where it discriminates.
        Thread.Sleep(50);

        var second  = Exchange(Request(origin:    first.ReceiveTimestamp,
                                       receive:   ClientTimestamp(),
                                       transmit:  ClientTimestamp()));

        Assert.That(second.TransmitTimestamp,
                    Is.LessThan(second.ReceiveTimestamp),
                    "an interleaved response reports a transmission that happened before this " +
                    "request was received; a timestamp after it is this response's own, which " +
                    "is the basic mode wearing the interleaved mode's clothes");

    }

    #endregion


    #region ...and only when it is allowed to

    /// <summary>
    /// RFC 9769 § 2, condition 1: "The request does not have a receive timestamp equal to the
    /// transmit timestamp."
    ///
    /// The client's half of the rule the server obeys above. A request whose two timestamps are
    /// equal gives the client no way to read the answer — whichever the server echoed, the
    /// client would see both — so the server must refuse to interleave rather than send
    /// something ambiguous.
    /// </summary>
    [Test]
    public void ARequestWithEqualReceiveAndTransmitTimestamps_IsNotAnsweredInterleaved()
    {

        var first      = BasicExchange();
        var ambiguous  = ClientTimestamp();

        var second     = Exchange(Request(origin:    first.ReceiveTimestamp,
                                          receive:   ambiguous,
                                          transmit:  ambiguous));

        Assert.That(second.TransmitTimestamp,
                    Is.GreaterThan(second.ReceiveTimestamp),
                    "the request was ambiguous, so the answer must be an ordinary basic-mode " +
                    "response reporting its own transmission");

    }


    /// <summary>
    /// RFC 9769 § 2, condition 2: the origin timestamp must match "the local receive timestamp
    /// of a previous request that the server has saved".
    ///
    /// A value the server never issued matches nothing, and the request is an ordinary one. This
    /// is the case § 5 warns about — a buggy client putting an arbitrary value in the origin
    /// field must not be able to talk a server into the interleaved mode by accident.
    /// </summary>
    [Test]
    public void ARequestWithAnUnrecognizedOriginTimestamp_IsAnsweredInTheBasicMode()
    {

        BasicExchange();

        var transmit  = ClientTimestamp();

        var response  = Exchange(Request(origin:    0x1234_5678_9ABC_DEF0,
                                         receive:   ClientTimestamp(),
                                         transmit:  transmit));

        Assert.That(response.OriginTimestamp,
                    Is.EqualTo(transmit),
                    "an origin timestamp this server never issued cannot select the " +
                    "interleaved mode");

    }


    /// <summary>
    /// A client's own transmit timestamp echoed back — which is what a conformant
    /// <em>basic</em>-mode client sends after its first exchange, per § 2: "A client request in
    /// the basic mode has an origin timestamp equal to the transmit timestamp from the last
    /// valid server response."
    ///
    /// This is the case that costs an implementation dearly if it gets it wrong, because it is
    /// the normal traffic of every ordinary client. The server's transmit timestamps must never
    /// be mistakable for its receive timestamps, or half the internet's NTP clients would start
    /// receiving interleaved responses they never asked for and cannot interpret.
    /// </summary>
    [Test]
    public void ARequestEchoingTheTransmitTimestamp_IsAnsweredInTheBasicMode()
    {

        var first     = BasicExchange();
        var transmit  = ClientTimestamp();

        var second    = Exchange(Request(origin:    first.TransmitTimestamp,
                                         receive:   ClientTimestamp(),
                                         transmit:  transmit));

        Assert.That(second.OriginTimestamp,
                    Is.EqualTo(transmit),
                    "echoing the server's transmit timestamp is what a basic-mode client does, " +
                    "and it must be answered in the basic mode");

    }


    /// <summary>
    /// RFC 9769 § 2: "The receive timestamp MUST NOT be used again to detect a request
    /// conforming to the interleaved mode."
    ///
    /// One receive timestamp buys one interleaved answer. Without that, a replayed request would
    /// draw the same transmit timestamp a second time, and an attacker able to replay could keep
    /// a client anchored to an old measurement.
    /// </summary>
    [Test]
    public void AReceiveTimestamp_SatisfiesAtMostOneInterleavedRequest()
    {

        var first     = BasicExchange();

        var request   = Request(origin:    first.ReceiveTimestamp,
                                receive:   ClientTimestamp(),
                                transmit:  ClientTimestamp());

        var accepted  = Exchange(request);

        Assert.That(accepted.OriginTimestamp,
                    Is.EqualTo(request.ReceiveTimestamp),
                    "the first attempt should be answered in the interleaved mode");

        // Byte for byte the same request, as a replay would be.
        var replayed  = Exchange(Request(origin:    request.OriginTimestamp,
                                         receive:   request.ReceiveTimestamp,
                                         transmit:  request.TransmitTimestamp));

        Assert.That(replayed.OriginTimestamp,
                    Is.EqualTo(request.TransmitTimestamp),
                    "the second attempt must fall back to the basic mode, because the receive " +
                    "timestamp it echoes has already been spent");

    }


    /// <summary>
    /// A zero origin timestamp is how a client says it has no association — § 2: the first
    /// request "has a zero origin timestamp and zero receive timestamp". It can never select
    /// the interleaved mode, however many exchanges came before it.
    /// </summary>
    [Test]
    public void AZeroOriginTimestamp_IsNeverInterleaved()
    {

        BasicExchange();

        var transmit  = ClientTimestamp();

        var response  = Exchange(Request(origin:    0,
                                         receive:   ClientTimestamp(),
                                         transmit:  transmit));

        Assert.That(response.OriginTimestamp,
                    Is.EqualTo(transmit),
                    "a client with no association gets the basic mode");

    }

    #endregion


    #region The mode can be switched off

    /// <summary>
    /// A server built with the interleaved mode disabled must answer the very sequence that
    /// works above in the basic mode throughout.
    ///
    /// Which is also the sensitivity check for this whole fixture: it proves the interleaved
    /// assertions above are detecting the server's behaviour rather than something inherent in
    /// the exchange.
    /// </summary>
    [Test]
    public async Task WithTheModeDisabled_EveryResponseIsBasic()
    {

        await using var plain = await NornServerFixture.StartAsync(interleavedMode: InterleavedModePolicy.Disabled);

        var first     = RawNtpExchange.Exchange(Request(0, 0, ClientTimestamp()),
                                                "127.0.0.1", plain.NTPPort,
                                                timeout: TimeSpan.FromSeconds(10));

        var transmit  = ClientTimestamp();

        var second    = RawNtpExchange.Exchange(Request(origin:    first.ReceiveTimestamp,
                                                        receive:   ClientTimestamp(),
                                                        transmit:  transmit),
                                                "127.0.0.1", plain.NTPPort,
                                                timeout: TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {

            Assert.That(second.OriginTimestamp,
                        Is.EqualTo(transmit),
                        "with the mode off, even a well-formed interleaved request is answered " +
                        "in the basic mode");

            Assert.That(second.TransmitTimestamp,
                        Is.GreaterThan(second.ReceiveTimestamp),
                        "and the transmit timestamp is this response's own");

        });

    }

    /// <summary>
    /// RFC 9769 § 2: "The server MAY restrict the interleaved mode to specific IP addresses
    /// and/or authenticated clients."
    ///
    /// The reason to want that is resources rather than protocol correctness. Interleaved mode
    /// obliges a server to remember something per client address, and on a UDP service the
    /// source address is whatever the sender wrote there — so every packet of a spoofed flood
    /// arrives as a new client. Under <c>AuthenticatedOnly</c> nothing is remembered about a
    /// request without a verified authenticator, so such a flood cannot occupy the table at all.
    ///
    /// These requests are plain NTP, so under this policy they must be answered in the basic
    /// mode however well formed their interleaved bid is.
    /// </summary>
    [Test]
    public async Task UnderAuthenticatedOnly_APlainRequestIsNotAnsweredInterleaved()
    {

        await using var restricted = await NornServerFixture.StartAsync(
                                               interleavedMode: InterleavedModePolicy.AuthenticatedOnly);

        var first     = RawNtpExchange.Exchange(Request(0, 0, ClientTimestamp()),
                                                "127.0.0.1", restricted.NTPPort,
                                                timeout: TimeSpan.FromSeconds(10));

        var transmit  = ClientTimestamp();

        var second    = RawNtpExchange.Exchange(Request(origin:    first.ReceiveTimestamp,
                                                        receive:   ClientTimestamp(),
                                                        transmit:  transmit),
                                                "127.0.0.1", restricted.NTPPort,
                                                timeout: TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {

            Assert.That(second.OriginTimestamp,
                        Is.EqualTo(transmit),
                        "a plain NTP client must not be answered in the interleaved mode when " +
                        "the mode is reserved for authenticated ones");

            Assert.That(restricted.Server.InterleavedTimestamps?.TrackedClients,
                        Is.Zero,
                        "and nothing may be remembered about it, or the restriction would save " +
                        "no resources at all — which is the only reason to impose it");

        });

    }

    #endregion

}
