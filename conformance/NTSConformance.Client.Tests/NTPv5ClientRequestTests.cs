using System.Text;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's NTPv5 client sends, read by this suite's own reader: the request of
/// draft-ietf-ntp-ntpv5-10 § 9 step 2, with the header of § 6, the Draft Identification of
/// § 7.1, the Reference IDs Request of § 7.4 and § 9, the Correction of § 7.7, and the NTS
/// fields of § 11 - RFC 8915 § 5.7's, which "are compatible with NTPv5".
///
/// <para>
/// A request is the half of the protocol a server cannot repair. One whose header is not zero
/// where § 9 step 2 has it zero leaks what it should not, and § 9 step 2 makes it zero for a
/// reason: § 6 has a request carry no timestamps at all, which is what keeps NTPv5's client
/// from handing an on-path observer its clock. One whose client cookie repeats is one whose
/// answers can be replayed.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientRequestTests
{

    #region (private) Capture(...)

    /// <summary>
    /// One query of the client, answered validly, and the request it sent.
    /// </summary>
    private static async Task<(ReceivedNtpV5Request Request, NTPv5ClientHarness Harness)> Capture(Boolean         NTS                   = false,
                                                                                                  NTPv5Timescale  Timescale             = NTPv5Timescale.UTC,
                                                                                                  Boolean         AcceptUnsynchronized  = false,
                                                                                                  Boolean         RequestCorrection     = false,
                                                                                                  Int32           CookieCount           = 8,
                                                                                                  UInt64?         OwnReferenceId        = null)
    {

        var harness = new NTPv5ClientHarness(CookieCount: CookieCount, OwnReferenceId: OwnReferenceId);

        harness.Script = request => NTPv5ClientHarness.Send(NTS
                                                                ? harness.Sealed(request, TimeSpan.Zero)
                                                                : harness.Plain (request, TimeSpan.Zero));

        var result = await harness.Query(NTS:                   NTS,
                                         Timescale:             Timescale,
                                         AcceptUnsynchronized:  AcceptUnsynchronized,
                                         RequestCorrection:     RequestCorrection);

        var captured = harness.FirstRequest;

        Assert.That(captured.Packet, Is.Not.Null,
                    $"the request does not read as an NTPv5 message by § 6 and § 7: {captured.Error}\n{Convert.ToHexString(captured.Octets)}");

        Assert.That(result.Success, Is.True,
                    $"the control: the query should get its valid answer: {result.ErrorMessage}");

        return (captured, harness);

    }

    #endregion


    #region § 6 and § 9 step 2: the header

    /// <summary>
    /// § 9 step 2: "Version is set to 5." "Mode is set to 3." And § 6: the header "has 48
    /// octets, which is the minimum length of a valid NTPv5 message", and "the length MUST be
    /// divisible by 4 octets".
    /// </summary>
    [TestCase(false, TestName = "TheRequest_IsAnNTPv5ClientMessage_Plain")]
    [TestCase(true,  TestName = "TheRequest_IsAnNTPv5ClientMessage_NTS")]
    public async Task TheRequest_IsAnNTPv5ClientMessage(Boolean NTS)
    {

        var (request, harness) = await Capture(NTS: NTS);
        await using var owner = harness;

        Assert.Multiple(() => {
            Assert.That(request.Packet!.Version,  Is.EqualTo(5),                      "the version");
            Assert.That(request.Packet!.Mode,     Is.EqualTo(3),                      "the mode");
            Assert.That(request.Octets.Length,    Is.GreaterThanOrEqualTo(48),        "the length");
            Assert.That(request.Octets.Length % 4, Is.Zero,                           "the length modulo 4");
        });

    }


    /// <summary>
    /// § 9 step 2: a request with "the fields in the header all zero except" version, mode,
    /// timescale, flags, server cookie and client cookie - and the server cookie "is set only
    /// in the interleaved mode", which this is not. § 6 says it of each field again: stratum,
    /// poll, root delay, root dispersion, era, receive and transmit timestamp are "always 0" in
    /// requests, and so is precision, since requests "do not contain any timestamps".
    /// </summary>
    [TestCase(false, TestName = "TheHeader_IsZero_ButWhereStep2SaysOtherwise_Plain")]
    [TestCase(true,  TestName = "TheHeader_IsZero_ButWhereStep2SaysOtherwise_NTS")]
    public async Task TheHeader_IsZero_ButWhereStep2SaysOtherwise(Boolean NTS)
    {

        var (request, harness) = await Capture(NTS: NTS);
        await using var owner = harness;

        var packet = request.Packet!;

        Assert.Multiple(() => {
            Assert.That(packet.Reserved,           Is.Zero, "the two reserved bits");
            Assert.That(packet.Stratum,            Is.Zero, "the stratum");
            Assert.That(packet.Poll,               Is.Zero, "the poll");
            Assert.That(packet.Precision,          Is.Zero, "the precision");
            Assert.That(packet.RootDelay,          Is.Zero, "the root delay");
            Assert.That(packet.RootDispersion,     Is.Zero, "the root dispersion");
            Assert.That(packet.Era,                Is.Zero, "the era");
            Assert.That(packet.ServerCookie,       Is.Zero, "the server cookie, in the basic mode");
            Assert.That(packet.ReceiveTimestamp,   Is.Zero, "the receive timestamp");
            Assert.That(packet.TransmitTimestamp,  Is.Zero, "the transmit timestamp");
        });

    }


    /// <summary>
    /// § 9 step 2: "Timescale is set to the timescale in which the client wants to operate."
    /// </summary>
    [TestCase(NTPv5Timescale.UTC, RawNtpV5Draft.UTC)]
    [TestCase(NTPv5Timescale.TAI, RawNtpV5Draft.TAI)]
    [TestCase(NTPv5Timescale.UT1, RawNtpV5Draft.UT1)]
    public async Task TheTimescale_IsTheOneAskedFor(NTPv5Timescale Timescale, Byte Expected)
    {

        var (request, harness) = await Capture(Timescale: Timescale);
        await using var owner = harness;

        Assert.That(request.Packet!.Timescale, Is.EqualTo(Expected));

    }


    /// <summary>
    /// § 9 step 2: "Flags are set according to the requested mode." § 6 has 0x1 say the client
    /// "wants to receive a response even when the server's clock is not synchronized", and 0x4
    /// that it wants one "even when the server fails to authenticate the request" - which a
    /// plain request has nothing to fail, and an NTS one asks for so that a server that can no
    /// longer read its cookie says so rather than keeping silent. Nothing else is set.
    /// </summary>
    [TestCase(false, false, (UInt16) 0x0000)]
    [TestCase(true,  false, (UInt16) 0x0001)]
    [TestCase(false, true,  (UInt16) 0x0004)]
    [TestCase(true,  true,  (UInt16) 0x0005)]
    public async Task TheFlags_AreThoseOfTheModeAskedFor(Boolean AcceptUnsynchronized, Boolean NTS, UInt16 Expected)
    {

        var (request, harness) = await Capture(NTS: NTS, AcceptUnsynchronized: AcceptUnsynchronized);
        await using var owner = harness;

        Assert.That(request.Packet!.Flags, Is.EqualTo(Expected), $"flags 0x{request.Packet!.Flags:x4}");

    }


    /// <summary>
    /// § 9 step 1: every request "Generates a new random cookie", and § 6 has the client cookie
    /// "a random number generated by the client". It is all a client has to tell its answer from
    /// a replayed or forged one (§ 9 step 4), and so a cookie that repeats, or that counts, lets
    /// an attacker who saw one exchange answer the next. Twenty requests of one client, all
    /// different and none zero - zero being what an NTPv4 server's answer carries (§ 12).
    /// </summary>
    [Test]
    public async Task EveryRequest_HasANewRandomClientCookie()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(harness.Plain(request, TimeSpan.Zero));

        for (var i = 0; i < 20; i++)
            Assert.That((await harness.Query()).Success, Is.True, $"query {i}");

        var cookies = harness.Server.Requests.Select(request => request.Packet!.ClientCookie).ToArray();

        Assert.Multiple(() => {
            Assert.That(cookies,          Has.Length.EqualTo(20));
            Assert.That(cookies,          Is.Unique,          "a client cookie repeated");
            Assert.That(cookies,          Has.None.Zero,      "a client cookie of zero");
            Assert.That(cookies.Zip(cookies.Skip(1), (a, b) => b - a).Distinct().Count(),
                        Is.GreaterThan(1),
                        "the client cookies go up in equal steps: a counter, not a random number");
        });

    }

    #endregion

    #region § 7.1: the Draft Identification

    /// <summary>
    /// § 7.1: the Draft Identification "MUST be included in NTPv5 requests produced by an
    /// implementation based on a draft of this specification", its contents "MUST be the full
    /// name, including version number, of the draft", and "MUST NOT be null-terminated". Norn
    /// implements -10, so it is exactly that, once.
    /// </summary>
    [TestCase(false, TestName = "ADraftImplementation_NamesItsDraft_Plain")]
    [TestCase(true,  TestName = "ADraftImplementation_NamesItsDraft_NTS")]
    public async Task ADraftImplementation_NamesItsDraft(Boolean NTS)
    {

        var (request, harness) = await Capture(NTS: NTS);
        await using var owner = harness;

        var drafts = request.Packet!.ExtensionFields.Where(field => field.Type == RawNtpV5Draft.DraftIdentification).ToArray();

        Assert.That(drafts, Has.Length.EqualTo(1), "Draft Identification fields");

        Assert.Multiple(() => {
            Assert.That(Encoding.ASCII.GetString(drafts[0].Data), Is.EqualTo(RawNtpV5Draft.Identification));
            Assert.That(drafts[0].Data,                           Has.Length.EqualTo(RawNtpV5Draft.Identification.Length),
                        "the field is longer than the name: a terminating zero, or padding counted in its length");
        });

    }

    #endregion

    #region § 7.4 and § 9: the reference IDs of a client that serves time

    /// <summary>
    /// § 9: "A client which operates as a server for other clients MUST include the Reference
    /// IDs Request Extension Field in its requests in order to track reference IDs of its
    /// sources." § 7.4: "The length of data MUST be at least 8 octets and be divisible by 8
    /// octets", and the index is "the first requested reference ID in the server's list,
    /// starting at 0" - which a client that asks once, for the whole list, starts at.
    /// </summary>
    [Test]
    public async Task AClientThatServesTime_AsksForTheReferenceIdsOfItsSources()
    {

        var (request, harness) = await Capture(OwnReferenceId: 0x0123_4567_89AB_CDEFUL);
        await using var owner = harness;

        var field = request.Packet!.Find(RawNtpV5Draft.ReferenceIDsRequest);

        Assert.That(field, Is.Not.Null, "no Reference IDs Request");

        Assert.Multiple(() => {
            Assert.That(field!.Data.Length,     Is.GreaterThanOrEqualTo(8), "the length of its data");
            Assert.That(field!.Data.Length % 8, Is.Zero,                    "the length of its data modulo 8");
            Assert.That(field!.Data[0],         Is.Zero,                    "the index");
        });

    }


    /// <summary>
    /// § 7.4: "The client SHOULD use requests of a constant length for the association to avoid
    /// adding a variation to the measured NTP delay." Five requests of a client that serves
    /// time, all of one length.
    /// </summary>
    [Test]
    public async Task TheRequestsOfAnAssociation_AreOfOneLength()
    {

        await using var harness = new NTPv5ClientHarness(OwnReferenceId: 0x0123_4567_89AB_CDEFUL);

        harness.Script = request => NTPv5ClientHarness.Send(harness.Plain(request, TimeSpan.Zero));

        for (var i = 0; i < 5; i++)
            Assert.That((await harness.Query()).Success, Is.True, $"query {i}");

        Assert.That(harness.Server.Requests.Select(request => request.Octets.Length).Distinct(),
                    Has.Exactly(1).Items,
                    String.Join(", ", harness.Server.Requests.Select(request => request.Octets.Length)));

    }

    #endregion

    #region § 7.7: the Correction

    /// <summary>
    /// § 7.7: a client with support for network corrections "SHOULD add the Correction Extension
    /// Field to its requests, with all fields of the extension field set to zero". Its length
    /// "is 28 octets", and "It MUST be the last extension field in the NTP message" - under NTS
    /// after the authenticator, outside it: the network fills it in on the way, so it cannot be
    /// covered by a seal the client made.
    /// </summary>
    [TestCase(false, TestName = "ACorrection_IsTheLastField_AndAllZero_Plain")]
    [TestCase(true,  TestName = "ACorrection_IsTheLastField_AndAllZero_NTS")]
    public async Task ACorrection_IsTheLastField_AndAllZero(Boolean NTS)
    {

        var (request, harness) = await Capture(NTS: NTS, RequestCorrection: true);
        await using var owner = harness;

        var fields = request.Packet!.ExtensionFields;
        var last   = fields[^1];

        Assert.Multiple(() => {
            Assert.That(last.Type,   Is.EqualTo(RawNtpV5Draft.Correction), $"the last field is 0x{last.Type:X4}");
            Assert.That(last.Length, Is.EqualTo(28),                       "its length");
            Assert.That(last.Data,   Is.All.Zero,                          "its fields");
            Assert.That(fields.Count(field => field.Type == RawNtpV5Draft.Correction), Is.EqualTo(1), "Correction fields");
        });

    }


    /// <summary>
    /// And a client that was not asked to use corrections does not ask for them: § 7.7 makes the
    /// field the client's to add "with enabled support for network corrections", and a server
    /// that sees none has none to answer.
    /// </summary>
    [Test]
    public async Task WithoutCorrections_TheRequestCarriesNoCorrection()
    {

        var (request, harness) = await Capture();
        await using var owner = harness;

        Assert.That(request.Packet!.Find(RawNtpV5Draft.Correction), Is.Null);

    }

    #endregion

    #region § 11 and RFC 8915 § 5.7: the NTS fields

    /// <summary>
    /// § 11: "The NTS extension fields specified for NTPv4 are compatible with NTPv5." RFC 8915
    /// § 5.7 has an NTS request carry exactly one Unique Identifier of at least 32 octets,
    /// exactly one NTS Cookie - one the key exchange gave - and exactly one authenticator, the
    /// first two authenticated by it. That the authenticator opens under the C2S key, over
    /// exactly the octets before it, is checked with this suite's own AEAD.
    /// </summary>
    [Test]
    public async Task AnNTSRequest_CarriesOneIdentifierOneCookieAndOneAuthenticator_ThatOpens()
    {

        var (request, harness) = await Capture(NTS: true);
        await using var owner = harness;

        var packet          = request.Packet!;
        var fields          = packet.ExtensionFields;
        var authenticators  = fields.Count(field => field.Type == RawNtpV5Nts.NtsAuthenticator);

        Assert.That(authenticators, Is.EqualTo(1), "NTS Authenticator fields");

        var index           = fields.FindIndex(field => field.Type == RawNtpV5Nts.NtsAuthenticator);
        var before          = fields.Take(index).ToArray();
        var identifiers     = before.Where(field => field.Type == RawNtpV5Nts.UniqueIdentifier).ToArray();
        var cookies         = before.Where(field => field.Type == RawNtpV5Nts.NtsCookie).ToArray();

        Assert.Multiple(() => {

            Assert.That(fields.Count(field => field.Type == RawNtpV5Nts.UniqueIdentifier), Is.EqualTo(1), "Unique Identifier fields");
            Assert.That(fields.Count(field => field.Type == RawNtpV5Nts.NtsCookie),        Is.EqualTo(1), "NTS Cookie fields");

            Assert.That(identifiers, Has.Length.EqualTo(1), "a Unique Identifier before the authenticator");
            Assert.That(cookies,     Has.Length.EqualTo(1), "a cookie before the authenticator");

        });

        Assert.Multiple(() => {

            Assert.That(identifiers[0].Data.Length, Is.GreaterThanOrEqualTo(RawNtpV5Nts.MinimumUniqueIdentifierLength),
                        "the Unique Identifier");

            Assert.That(harness.Cookies.Any(cookie => cookie.AsSpan().SequenceEqual(cookies[0].Data)), Is.True,
                        "the cookie is none the key exchange gave");

            Assert.That(RawNtsExtensionFields.TryParseAuthenticatorValue(fields[index].Data, out var nonce, out var ciphertext, out var error),
                        Is.True, $"the authenticator does not read: {error}");

            Assert.That(RawNtpV5Nts.TryOpen(NTPv5ClientHarness.Aead,
                                            harness.C2SKey,
                                            request.Octets[..RawNtpV5Nts.OffsetOf(packet, index)],
                                            nonce!,
                                            ciphertext!,
                                            out _,
                                            out var openError),
                        Is.True, $"the authenticator does not open under the C2S key over the octets before it: {openError}");

        });

    }


    /// <summary>
    /// RFC 8915 § 5.7: a client that wants more cookies back adds placeholders, and § 5.5 has
    /// each as long as the cookie it sends, so that the request is as long as the response the
    /// server will send - the amplification RFC 8915 exists to rule out. A client with one cookie
    /// left asks for more, so there are placeholders to measure.
    /// </summary>
    [Test]
    public async Task ThePlaceholders_AreAsLongAsTheCookie()
    {

        var (request, harness) = await Capture(NTS: true, CookieCount: 1);
        await using var owner = harness;

        var fields        = request.Packet!.ExtensionFields;
        var cookie        = fields.Single(field => field.Type == RawNtpV5Nts.NtsCookie);
        var placeholders  = fields.Where(field => field.Type == RawNtpV5Nts.NtsCookiePlaceholder).ToArray();
        var index         = fields.FindIndex(field => field.Type == RawNtpV5Nts.NtsAuthenticator);

        Assert.That(placeholders, Is.Not.Empty, "a client with its last cookie in hand asks for none");

        Assert.Multiple(() => {
            Assert.That(placeholders.Select(field => field.Data.Length), Is.All.EqualTo(cookie.Data.Length), "the placeholders' lengths");
            Assert.That(fields.Take(index).Count(field => field.Type == RawNtpV5Nts.NtsCookiePlaceholder),
                        Is.EqualTo(placeholders.Length),
                        "a placeholder after the authenticator, which a server would not count");
        });

    }


    /// <summary>
    /// RFC 8915 § 5.7: a Unique Identifier must not repeat one of an earlier request, and every
    /// request spends a cookie of its own - a cookie spent twice links the two requests for an
    /// observer, which is what NTS's cookies exist to prevent (RFC 8915 § 9.1). Four NTS
    /// requests of one client: four identifiers, four cookies.
    /// </summary>
    [Test]
    public async Task EveryNTSRequest_HasAnIdentifierAndACookieOfItsOwn()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(harness.Sealed(request, TimeSpan.Zero));

        for (var i = 0; i < 4; i++)
            Assert.That((await harness.Query(NTS: true)).Success, Is.True, $"query {i}");

        var requests = harness.Server.Requests;

        Assert.Multiple(() => {
            Assert.That(requests.Select(request => Convert.ToHexString(request.Packet!.Find(RawNtpV5Nts.UniqueIdentifier)!.Data)), Is.Unique, "Unique Identifiers");
            Assert.That(requests.Select(request => Convert.ToHexString(request.Packet!.Find(RawNtpV5Nts.NtsCookie)!.Data)),        Is.Unique, "cookies");
        });

    }

    #endregion

}
