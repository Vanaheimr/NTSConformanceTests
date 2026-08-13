using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// The "RATE" Kiss-o'-Death of RFC 5905 § 7.4 as it appears on the wire, read by this suite's own
/// packet reader rather than by Norn's.
///
/// <para>
/// <see cref="RateLimiterTests"/> covers the decision — who is limited, and who is told. This
/// covers the packet, which is a separate question with its own way of going wrong: the kiss is
/// built from the unparsed datagram, deliberately, so that a flood costs the server nothing to
/// refuse. That shortcut is exactly the kind that produces a well-formed packet no client
/// believes, because the two fields that make a kiss credible — the echoed origin timestamp and
/// the echoed Unique Identifier — are the two the shortcut skips over.
/// </para>
/// <para>
/// A fresh server per test. The limiter is stateful by definition, and a fixture shared across
/// tests would make each one depend on which of the others had run first.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class RateKissOnTheWireTests
{

    /// <summary>
    /// Long enough that the poll exponent it implies — 2^7 = 128 s ≥ 100 s — is neither the
    /// default nor whatever the request carried, so an assertion on it cannot pass by accident.
    /// </summary>
    private static readonly TimeSpan MinimumInterval = TimeSpan.FromSeconds(100);

    private const Int32 Burst = 2;

    private NornServerFixture? fixture;


    [SetUp]
    public async Task StartServer()

        => fixture = await NornServerFixture.StartAsync(
                               rateLimiter: new NTPRateLimiter(
                                                MinimumInterval:  MinimumInterval,
                                                Burst:            Burst,
                                                KissInterval:     TimeSpan.FromMinutes(5)
                                            )
                           );


    [TearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    private RawNtpPacket? Exchange(RawNtpPacket request, TimeSpan? timeout = null)
    {

        if (fixture is null)
            throw new InvalidOperationException("the server fixture did not start");

        return RawNtpExchange.TryExchange(request, "127.0.0.1", fixture.NTPPort, timeout: timeout);

    }


    /// <summary>Spend the bucket, so the next request is a limited one.</summary>
    private void DrainTheBucket()
    {
        for (var i = 0; i < Burst; i++)
            Exchange(RawNtpPacket.ClientRequest());
    }


    #region The kiss arrives, and is a kiss

    /// <summary>
    /// The burst is answered normally and the request after it draws a RATE kiss.
    /// </summary>
    [Test]
    public void PastTheBurst_TheServerAnswersWithARateKiss()
    {

        for (var i = 0; i < Burst; i++)
        {

            var answer = Exchange(RawNtpPacket.ClientRequest());

            Assert.That(answer?.IsKissOfDeath,
                        Is.False,
                        $"request {i + 1} of {Burst} is inside the burst and must be answered " +
                        $"normally, or the limiter is refusing the clients it exists to protect");

        }

        var kiss = Exchange(RawNtpPacket.ClientRequest());

        Assert.That(kiss, Is.Not.Null, "the first refusal should be explained, not silent");

        // The kiss is on the wire before the server's counter moves — the worker sends first
        // and increments after — so on a loaded machine this client can hold the datagram
        // while the count still reads zero. Wait for the counter rather than reading it
        // mid-step; the assertion below still demands exactly one.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        while (fixture!.Server.Metrics.NTPKissesOfDeathSent == 0 && DateTime.UtcNow < deadline)
            Thread.Sleep(10);

        Assert.Multiple(() => {

            Assert.That(kiss!.Mode,          Is.EqualTo(RawNtpMode.Server), "a server reply is mode 4");
            Assert.That(kiss.Stratum,        Is.EqualTo(0),                 "a Kiss-o'-Death is stratum 0");
            Assert.That(kiss.KissCode,       Is.EqualTo("RATE"),            "RFC 5905 § 7.4's rate-exceeded code");

            Assert.That(fixture!.Server.Metrics.NTPKissesOfDeathSent,
                        Is.EqualTo(1),
                        $"and the server should say so too: {fixture.Server.Metrics}");

        });

    }


    /// <summary>
    /// The kiss echoes the request's transmit timestamp, which is the whole reason a client may
    /// believe it.
    /// </summary>
    /// <remarks>
    /// RFC 8633 § 5.4: "a client MUST only accept a KoD packet if it has a valid origin
    /// timestamp." A conformant client discards a kiss without one, so a server that omits it has
    /// built a packet that costs bandwidth and changes nothing — and has done so on the path it
    /// takes when it is already under load.
    /// </remarks>
    [Test]
    public void TheRateKiss_EchoesTheRequestsTransmitTimestamp()
    {

        DrainTheBucket();

        var request = RawNtpPacket.ClientRequest();
        var kiss    = Exchange(request);

        Assert.That(kiss, Is.Not.Null);

        Assert.That(kiss!.OriginTimestamp,
                    Is.EqualTo(request.TransmitTimestamp),
                    "without the echo the kiss is indistinguishable from a forgery, and a client " +
                    "following RFC 8633 § 5.4 will treat it as one");

    }


    /// <summary>
    /// The kiss asks for the poll interval the server is actually willing to serve.
    /// </summary>
    /// <remarks>
    /// The number is the point: 2^7 = 128 seconds, the smallest power of two covering the
    /// configured limit of 100. A kiss that echoed the request's poll, or carried a default, would
    /// tell a client to keep doing exactly what got it limited.
    /// </remarks>
    [Test]
    public void TheRateKiss_AsksForAPollIntervalThatWouldStopTheLimiting()
    {

        DrainTheBucket();

        var request = RawNtpPacket.ClientRequest();
        var kiss    = Exchange(request);

        Assert.That(kiss, Is.Not.Null);

        Assert.Multiple(() => {

            Assert.That(kiss!.Poll,
                        Is.EqualTo(7),
                        $"2^7 = 128 s is the smallest poll exponent covering the server's " +
                        $"{MinimumInterval.TotalSeconds:0} s limit");

            Assert.That(kiss.Poll,
                        Is.Not.EqualTo(request.Poll),
                        "and it must be the server's number, not the client's echoed back");

        });

    }


    /// <summary>
    /// An NTS client's kiss carries its Unique Identifier back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The NTS analogue of the origin timestamp, and needed for the same reason. RFC 8915 § 5.7
    /// has the client discard any response whose Unique Identifier does not match an outstanding
    /// request, so a kiss without one reaches every client except the ones that authenticate.
    /// </para>
    /// <para>
    /// What makes this worth a test of its own is where the identifier has to come from. The
    /// kiss is built without parsing the request — that is the saving the limiter exists for — so
    /// the identifier is found by walking the raw extension fields, and a walk that is subtly
    /// wrong produces a kiss that is subtly useless.
    /// </para>
    /// </remarks>
    [Test]
    public void TheRateKissToAnNtsClient_EchoesTheUniqueIdentifier()
    {

        DrainTheBucket();

        var request       = RawNtpPacket.ClientRequest();
        var uniqueId      = RawNtsExtensionFields.RandomUniqueIdentifier();

        // The identifier deliberately second. With it first the walk finds it at the first field
        // it looks at and never has to step, so a walk that advanced by a fixed amount instead of
        // by each field's length would pass — as one did, until this test was written this way
        // round. RFC 7822 fixes no order between these two fields, so a server has to read the
        // chain rather than assume one.
        request.ExtensionFields.Add(RawNtsExtensionFields.NtsCookiePlaceholder(100));
        request.ExtensionFields.Add(uniqueId);

        var kiss          = Exchange(request);

        Assert.That(kiss, Is.Not.Null);

        var echoed        = kiss!.ExtensionFields.
                                FirstOrDefault(field => field.FieldType == RawExtensionFieldTypes.UniqueIdentifier);

        Assert.That(echoed,
                    Is.Not.Null,
                    "the kiss carried no Unique Identifier, so an NTS client will discard it: " +
                    String.Join(", ", kiss.ExtensionFields.Select(f => RawExtensionFieldTypes.Describe(f.FieldType))));

        Assert.That(echoed!.Value,
                    Is.EqualTo(uniqueId.Value).AsCollection,
                    "and it has to be the client's own identifier");

    }


    /// <summary>
    /// An identifier that is not a plausible RFC 8915 § 5.3 one is not echoed back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// § 5.3 puts a floor on it — "the string MUST be at least 32 octets long" — so anything
    /// shorter did not come from a conformant NTS client, and echoing it would only be doing an
    /// unknown sender's work.
    /// </para>
    /// <para>
    /// The ceiling is the one that matters. The whole reason the kiss is throttled is that its
    /// destination is whatever address the sender wrote down; copying an arbitrary length of the
    /// sender's choosing into it lets that sender decide how big the packet aimed at somebody
    /// else is. The kiss stays a fixed size, so it cannot be grown from outside.
    /// </para>
    /// </remarks>
    [TestCase(  8, TestName = "AnImplausibleUniqueIdentifier_IsNotEchoed(too short for RFC 8915 § 5.3)")]
    [TestCase(512, TestName = "AnImplausibleUniqueIdentifier_IsNotEchoed(long enough to size the reply from outside)")]
    public void AnImplausibleUniqueIdentifier_IsNotEchoed(Int32 identifierLength)
    {

        DrainTheBucket();

        var request = RawNtpPacket.ClientRequest();

        request.ExtensionFields.Add(
            RawNtsExtensionFields.UniqueIdentifier(
                Enumerable.Range(0, identifierLength).Select(i => (Byte) i).ToArray()
            )
        );

        var kiss = Exchange(request);

        Assert.That(kiss?.KissCode,
                    Is.EqualTo("RATE"),
                    "the request is still refused; only the echo is in question");

        Assert.That(kiss!.ExtensionFields,
                    Is.Empty,
                    $"a {identifierLength}-octet identifier was echoed back. Below 32 octets it " +
                    $"is not one RFC 8915 § 5.3 permits; above 64 it lets whoever sent the " +
                    $"request choose the size of a packet addressed to somebody else.");

    }


    /// <summary>
    /// The kiss carries no cookie and no authenticator.
    /// </summary>
    /// <remarks>
    /// It cannot: the S2C key is sealed inside the cookie, and unsealing it is precisely the work
    /// the limiter declined to do. An extension field claiming otherwise would be one the client
    /// cannot verify — the same reasoning as RFC 8915 § 5.7's unauthenticated NAK.
    /// </remarks>
    [Test]
    public void TheRateKiss_CarriesNothingItCannotAuthenticate()
    {

        DrainTheBucket();

        var request = RawNtpPacket.ClientRequest();
        request.ExtensionFields.Add(RawNtsExtensionFields.RandomUniqueIdentifier());

        var kiss    = Exchange(request);

        Assert.That(kiss, Is.Not.Null);

        Assert.That(kiss!.ExtensionFields.Where(field => field.FieldType != RawExtensionFieldTypes.UniqueIdentifier),
                    Is.Empty,
                    "only the Unique Identifier may travel unauthenticated: " +
                    String.Join(", ", kiss.ExtensionFields.Select(f => RawExtensionFieldTypes.Describe(f.FieldType))));

    }

    #endregion


    #region And then silence

    /// <summary>
    /// Later refusals are silent, so the kiss cannot be amplified into a flood.
    /// </summary>
    /// <remarks>
    /// RFC 8633 § 5.4 warns that KoD packets are themselves a denial-of-service vector, and on
    /// UDP the destination of every one of them is whatever the sender wrote in the source
    /// address. A server that explains itself every time has volunteered to be the flood.
    /// </remarks>
    [Test]
    public void AfterTheFirstKiss_FurtherRefusalsAreSilent()
    {

        DrainTheBucket();

        Assert.That(Exchange(RawNtpPacket.ClientRequest())?.KissCode,
                    Is.EqualTo("RATE"),
                    "the first refusal");

        // Short, because the expected outcome here is nothing at all and waiting the full
        // default for each of them would dominate the run.
        var later = new List<RawNtpPacket?>();

        for (var i = 0; i < 5; i++)
            later.Add(Exchange(RawNtpPacket.ClientRequest(), timeout: TimeSpan.FromMilliseconds(400)));

        Assert.Multiple(() => {

            Assert.That(later,
                        Is.All.Null,
                        "the kiss interval has not passed, so these must be dropped without a word");

            Assert.That(fixture!.Server.Metrics.NTPRequestsRateLimited,
                        Is.EqualTo(6),
                        $"all six were refused: {fixture.Server.Metrics}");

            Assert.That(fixture.Server.Metrics.NTPKissesOfDeathSent,
                        Is.EqualTo(1),
                        $"and exactly one of them was explained: {fixture.Server.Metrics}");

        });

    }

    #endregion


    #region Without a limiter

    /// <summary>
    /// With no limiter configured, nothing is refused — which is the default, and what every
    /// other fixture in this suite depends on.
    /// </summary>
    /// <remarks>
    /// Not a tautology: it is what makes the assertions above evidence of the limiter rather than
    /// of some burst behaviour a Norn server has anyway.
    /// </remarks>
    [Test]
    public async Task WithoutALimiter_ABurstIsAnsweredInFull()
    {

        await using var unlimited = await NornServerFixture.StartAsync();

        for (var i = 0; i < Burst + 5; i++)
        {

            var answer = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(),
                                                    "127.0.0.1",
                                                    unlimited.NTPPort);

            Assert.That(answer?.IsKissOfDeath,
                        Is.False,
                        $"request {i + 1} drew a kiss from a server with no rate limiter");

        }

        Assert.That(unlimited.Server.Metrics.NTPRequestsRateLimited,
                    Is.Zero,
                    "a server without a limiter cannot rate-limit anything");

    }

    #endregion

}
