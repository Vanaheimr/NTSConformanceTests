using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's NTS client must refuse.
///
/// A time client is only as trustworthy as the responses it rejects: a client that accepts
/// an unauthenticated reply, a replayed one, or one answering a different request gives an
/// attacker control of the clock even though NTS is nominally in use. RFC 8915 §5.7 lists
/// these checks, and they are the client's entire security contribution.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ClientResponseValidationTests
{

    private NornServerFixture? fixture;

    /// <summary>A genuine NTS exchange, captured once and then mutated per test.</summary>
    private NTSKE_Response? ntsKeResponse;
    private NTPResponse?    goodResponse;
    private NTPRequest?     goodRequest;


    [OneTimeSetUp]
    public async Task CaptureAGenuineExchange()
    {

        fixture = await NornServerFixture.StartAsync();

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        ntsKeResponse   = ntsKeResult.Response!;

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResponse,
                                                Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success, Is.True, $"the reference query failed: {queryResult.ErrorMessage}");

        // NTSQueryResult exposes these as the NTPPacket base type, so narrow them explicitly
        // rather than casting blind — a change of concrete type should fail here, loudly.
        if (queryResult.Response is not NTPResponse response)
        {
            Assert.Fail($"expected an NTPResponse, got {queryResult.Response?.GetType().Name ?? "null"}");
            return;
        }

        if (response.Request is not NTPRequest request)
        {
            Assert.Fail($"expected the response to carry an NTPRequest, got {response.Request?.GetType().Name ?? "null"}");
            return;
        }

        goodResponse    = response;
        goodRequest     = request;

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>The unmodified exchange must validate — otherwise every negative test below is vacuous.</summary>
    [Test]
    public void GenuineResponse_Validates()
    {

        if (goodResponse is null || goodRequest is null)
        {
            Assert.Fail("no reference exchange was captured");
            return;
        }

        var result = NTSResponseValidator.Validate(goodResponse, goodRequest, NTSKey: ntsKeResponse!.S2CKey);

        Assert.That(result.IsValid, Is.True, $"a genuine response should validate: {result.ErrorMessage}");

    }


    /// <summary>
    /// RFC 8915 §5.7: the response's Unique Identifier must match the request's. Without
    /// this check an attacker could replay any previously captured, correctly authenticated
    /// response in answer to a later request.
    /// </summary>
    [Test]
    public void ResponseWithMismatchedUniqueIdentifier_IsRejected()
    {

        if (goodResponse is null || goodRequest is null)
        {
            Assert.Fail("no reference exchange was captured");
            return;
        }

        // A request that is identical except for its Unique Identifier.
        var otherRequest = new NTPRequest(
                               Extensions: [
                                   new UniqueIdentifierExtension(Enumerable.Repeat((Byte) 0x99, 32).ToArray())
                               ],
                               TransmitTimestamp: goodResponse.OriginateTimestamp
                           );

        var result = NTSResponseValidator.Validate(goodResponse, otherRequest, NTSKey: ntsKeResponse!.S2CKey);

        Assert.Multiple(() => {
            Assert.That(result.IsValid,      Is.False, "a response whose Unique Identifier does not match the request must be rejected");
            Assert.That(result.ErrorMessage, Is.Not.Null.And.Not.Empty);
        });

    }


    /// <summary>
    /// A Kiss-o'-Death must be surfaced as such rather than accepted as a time reading:
    /// stratum 0 carries no usable timestamp, and RFC 8915 §5.7's "NTSN" kiss code tells
    /// the client its cookie is no longer good.
    /// </summary>
    [Test]
    public void KissOfDeath_IsRejectedAsATimeSource()
    {

        if (goodResponse is null || goodRequest is null)
        {
            Assert.Fail("no reference exchange was captured");
            return;
        }

        var kodBytes = RawNtpWriter.Write(new RawNtpPacket {
                           Mode                = RawNtpMode.Server,
                           Version             = 4,
                           Stratum             = 0,
                           OriginTimestamp     = goodResponse.OriginateTimestamp,
                           ReceiveTimestamp    = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                           TransmitTimestamp   = RawNtpTimestamp.FromDateTime(DateTime.UtcNow)
                       }.WithReferenceIdentifier("NTSN"));

        if (!NTPResponse.TryParse(kodBytes, out var kod, out var parseError))
        {
            Assert.Fail($"a KoD packet should parse: {parseError}");
            return;
        }

        var result = NTSResponseValidator.Validate(kod, goodRequest, RequireNTS: false);

        Assert.Multiple(() => {

            Assert.That(result.IsValid, Is.False, "a Kiss-o'-Death is not a usable time reading");

            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.KissOfDeath),
                        "the client should report a KoD distinctly, so a caller can re-run NTS-KE");

        });

    }


    /// <summary>
    /// RFC 5905 §7.3: a client must only accept mode 4 (server). Accepting other modes
    /// opens the door to reflected or symmetric-mode traffic being read as an answer.
    /// </summary>
    [TestCase((Byte) 0)]
    [TestCase((Byte) 1)]
    [TestCase((Byte) 2)]
    [TestCase((Byte) 3)]
    [TestCase((Byte) 5)]
    [TestCase((Byte) 6)]
    [TestCase((Byte) 7)]
    public void ResponseWithWrongMode_IsRejected(Byte mode)
    {

        if (goodResponse is null || goodRequest is null)
        {
            Assert.Fail("no reference exchange was captured");
            return;
        }

        var bytes = RawNtpWriter.Write(new RawNtpPacket {
                        Mode                = mode,
                        Version             = 4,
                        Stratum             = 2,
                        OriginTimestamp     = goodResponse.OriginateTimestamp,
                        ReferenceTimestamp  = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        ReceiveTimestamp    = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        TransmitTimestamp   = RawNtpTimestamp.FromDateTime(DateTime.UtcNow)
                    });

        if (!NTPResponse.TryParse(bytes, out var response, out var parseError))
        {
            Assert.Fail($"the packet should parse: {parseError}");
            return;
        }

        Assert.That(NTSResponseValidator.Validate(response, goodRequest, RequireNTS: false).IsValid,
                    Is.False,
                    $"mode {mode} is not a server response and must be rejected");

    }


    /// <summary>
    /// RFC 5905 §7.3: the Originate Timestamp must echo the request's Transmit Timestamp.
    /// This is what binds a response to the request that provoked it; without it an
    /// off-path attacker's guess needs only to arrive first.
    /// </summary>
    [Test]
    public void ResponseWithWrongOriginateTimestamp_IsRejected()
    {

        if (goodResponse is null || goodRequest is null)
        {
            Assert.Fail("no reference exchange was captured");
            return;
        }

        var bytes = RawNtpWriter.Write(new RawNtpPacket {
                        Mode                = RawNtpMode.Server,
                        Version             = 4,
                        Stratum             = 2,
                        OriginTimestamp     = (goodResponse.OriginateTimestamp) ^ 0xFFFF,
                        ReferenceTimestamp  = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        ReceiveTimestamp    = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        TransmitTimestamp   = RawNtpTimestamp.FromDateTime(DateTime.UtcNow)
                    });

        if (!NTPResponse.TryParse(bytes, out var response, out var parseError))
        {
            Assert.Fail($"the packet should parse: {parseError}");
            return;
        }

        Assert.That(NTSResponseValidator.Validate(response, goodRequest, RequireNTS: false).IsValid,
                    Is.False,
                    "a response that does not echo the request's transmit timestamp must be rejected");

    }


    /// <summary>
    /// RFC 5905 §7.3: leap indicator 3 means the server is not synchronised, so its time is
    /// not usable no matter how well authenticated the packet is.
    /// </summary>
    [Test]
    public void UnsynchronizedServer_IsRejected()
    {

        if (goodResponse is null || goodRequest is null)
        {
            Assert.Fail("no reference exchange was captured");
            return;
        }

        var bytes = RawNtpWriter.Write(new RawNtpPacket {
                        LeapIndicator       = RawNtpLeapIndicator.Unsynchronized,
                        Mode                = RawNtpMode.Server,
                        Version             = 4,
                        Stratum             = 2,
                        OriginTimestamp     = goodResponse.OriginateTimestamp,
                        ReferenceTimestamp  = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        ReceiveTimestamp    = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        TransmitTimestamp   = RawNtpTimestamp.FromDateTime(DateTime.UtcNow)
                    });

        if (!NTPResponse.TryParse(bytes, out var response, out var parseError))
        {
            Assert.Fail($"the packet should parse: {parseError}");
            return;
        }

        Assert.That(NTSResponseValidator.Validate(response, goodRequest, RequireNTS: false).IsValid,
                    Is.False,
                    "leap indicator 3 marks the server as unsynchronised");

    }


    /// <summary>
    /// An NTS-protected request must be answered by an NTS-protected response. A reply
    /// stripped of its Authenticator field is unauthenticated, and accepting it would let
    /// an attacker downgrade the association to plain NTP.
    /// </summary>
    [Test]
    public void ResponseWithoutAuthenticator_IsRejected()
    {

        if (goodResponse?.Request is null || ntsKeResponse is null)
        {
            Assert.Fail("no reference exchange was captured");
            return;
        }

        // The genuine response, minus its Authenticator, with the Unique Identifier kept so
        // only the authentication is missing.
        var uniqueIdentifier = goodResponse.UniqueIdentifier()!;

        var bytes = RawNtpWriter.Write(new RawNtpPacket {
                        Mode                = RawNtpMode.Server,
                        Version             = 4,
                        Stratum             = 2,
                        OriginTimestamp     = goodResponse.OriginateTimestamp,
                        ReferenceTimestamp  = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        ReceiveTimestamp    = RawNtpTimestamp.FromDateTime(DateTime.UtcNow),
                        TransmitTimestamp   = RawNtpTimestamp.FromDateTime(DateTime.UtcNow)
                    }.WithExtensionField(RawNtsExtensionFields.UniqueIdentifier(uniqueIdentifier)));

        if (!NTPResponse.TryParse(bytes, out var response, out var parseError))
        {
            Assert.Fail($"the packet should parse: {parseError}");
            return;
        }

        Assert.That(NTSResponseValidator.Validate(response, goodRequest, NTSKey: ntsKeResponse!.S2CKey).IsValid,
                    Is.False,
                    $"a response with no Authenticator extension field must be rejected (validator said: {NTSResponseValidator.Validate(response, goodRequest, NTSKey: ntsKeResponse!.S2CKey).ErrorMessage})");

    }

}
