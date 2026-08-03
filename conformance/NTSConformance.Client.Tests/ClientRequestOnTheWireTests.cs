using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's client actually puts into an NTS-KE request, read off the wire by a server that
/// keeps it.
///
/// <para>
/// Every other client-side test in this suite infers the request from how a server answered,
/// which is weaker than it sounds: a server ignores what it does not need, so a client can send
/// the wrong thing, the right thing twice, or the right things in the wrong order, and the reply
/// looks the same. <see cref="ScriptedNtsKeServer"/> terminates TLS and keeps the octets, which
/// makes the request itself assertable for the first time.
/// </para>
/// <para>
/// RFC 8915 § 4 is short about what a request must contain and exact about how: records are
/// type, length, body, the critical bit is the top bit of the type, and End of Message is
/// critical and last. § 4.1.2 and § 4.1.5 add that the protocol and algorithm lists are
/// preference-ordered, which is only meaningful if the order survives to the wire.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ClientRequestOnTheWireTests
{

    #region (private) Capture(...)

    /// <summary>
    /// Run one key exchange against a capturing server and return what it received.
    /// </summary>
    /// <remarks>
    /// A server per test rather than one for the fixture: the assertion is on a single request,
    /// and a shared server would make each test depend on how many ran before it.
    /// </remarks>
    private static async Task<CapturedNtsKeRequest> Capture(IEnumerable<AEADAlgorithms>?  AEADAlgorithms             = null,
                                                            Boolean                       CompliantExporterContext   = true)
    {

        await using var server = ScriptedNtsKeServer.Start();

        var client = new NTSClient(
                         DomainName.Localhost,
                         NTSKE_Port:                  server.Port,
                         IPVersionPreference:         IPVersionPreference.IPv4Only,
                         Timeout:                     TimeSpan.FromSeconds(10),
                         RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                          => TLSValidationResult.Success(),
                         OfferedAEADAlgorithms:       AEADAlgorithms,
                         CompliantAES128GCMSIVExporterContext: CompliantExporterContext
                     );

        var result  = await client.GetNTSKERecords();
        var request = server.LastRequest;

        Assert.That(request,
                    Is.Not.Null,
                    $"the client sent no NTS-KE request that this server could read. " +
                    $"Client said: {result.ErrorMessage ?? "(nothing)"}\n" +
                    $"Server failures: {String.Join("; ", server.Failures)}");

        return request!;

    }

    #endregion


    #region The ALPN identifier, which is the only agreement to speak NTS-KE at all

    /// <summary>
    /// A server that completes the handshake without selecting <c>ntske/1</c> is refused, and
    /// refused before a single record is sent to it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 8915 § 3: the ALPN extension is "integral to NTS" and support for it is "REQUIRED for
    /// interoperability". § 4 describes the exchange as one the server accepts <c>ntske/1</c> in.
    /// Neither spells out the client's obligation when it does not, and Norn's client used to
    /// record the negotiated protocol and never look at it — it completed the exchange and
    /// reported success against a peer that had agreed to nothing.
    /// </para>
    /// <para>
    /// "Before a single record" is the half worth asserting separately. Detecting this after the
    /// exchange would still return the right verdict, and would have handed NTS-KE records, and
    /// the shape of this client's offers, to something that never said it was an NTS-KE server.
    /// </para>
    /// <para>
    /// One thing this cannot reach: the check compares against <c>ntske/1</c> by name, and
    /// weakening it to "any protocol at all" changes nothing observable. Norn's client offers
    /// exactly one protocol, RFC 7301 lets a server select only from what the client offered, and
    /// BouncyCastle rejects a selection outside that list before this code runs — so "some other
    /// protocol was selected" is not a state any peer can put this client into. The comparison
    /// stays by name because it says what is meant and stays correct if the offer ever grows.
    /// </para>
    /// </remarks>
    [Test]
    public async Task AServerThatDoesNotSelectNtske1_IsRefused()
    {

        await using var server = ScriptedNtsKeServer.Start(OfferAlpn: false);

        var result = await new NTSClient(
                               DomainName.Localhost,
                               NTSKE_Port:                  server.Port,
                               IPVersionPreference:         IPVersionPreference.IPv4Only,
                               Timeout:                     TimeSpan.FromSeconds(10),
                               RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                                => TLSValidationResult.Success()
                           ).GetNTSKERecords();

        // The client's return and the server's bookkeeping are on different threads. Waiting for
        // the server to account for the connection one way or the other is what makes the two
        // assertions below mean something: asked too early, "nothing was sent" is true of a
        // request still in flight.
        var deadline = DateTime.UtcNow.AddSeconds(5);

        while (server.ConnectionsClosedWithoutRequest == 0 &&
               server.Requests.Count                  == 0 &&
               DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.False,
                        "the server never agreed to speak NTS-KE");

            Assert.That(result.ErrorCategory, Is.EqualTo(NTSKEErrorCategory.TLSHandshake),
                        "the disagreement is in the handshake, not in the records — there are none");

            Assert.That(result.ErrorMessage, Does.Contain("ntske/1"),
                        $"and the message has to name what was missing: {result.ErrorMessage}");

            Assert.That(server.Requests, Is.Empty,
                        $"nothing may be sent to a peer that has not agreed to read it, and " +
                        $"{server.Requests.Count} request(s) were");

            Assert.That(server.ConnectionsClosedWithoutRequest, Is.GreaterThan(0),
                        $"and the client did get that far — it completed the handshake and then " +
                        $"walked away, rather than never arriving. Server failures: " +
                        $"{String.Join("; ", server.Failures)}");

        });

    }

    #endregion


    /// <summary>
    /// The handshake itself: TLS 1.3 with <c>ntske/1</c>, and a request that decodes.
    /// </summary>
    /// <remarks>
    /// The precondition for everything below, and not a formality — this is BouncyCastle
    /// negotiating with SChannel, the two stacks that have disagreed most often in this suite,
    /// with the roles reversed from every other test here.
    /// </remarks>
    [Test]
    public async Task TheRequest_ArrivesOverNtskeAlpn()
    {

        var request = await Capture();

        Assert.Multiple(() => {

            Assert.That(request.NegotiatedAlpn, Is.EqualTo("ntske/1"),
                        "RFC 8915 § 4 assigns NTS-KE this ALPN identifier");

            Assert.That(request.DecodeError, Is.Null,
                        $"the request did not decode: {request}");

        });

    }


    /// <summary>
    /// A request carries exactly one Next Protocol record, naming NTPv4, with the critical bit.
    /// </summary>
    /// <remarks>
    /// § 4.1.2 requires the record and requires it critical: a server that does not understand
    /// protocol negotiation must fail the exchange rather than guess. Exactly one, because the
    /// record carries a list and a second one would leave the server to decide which list is the
    /// client's preference.
    /// </remarks>
    [Test]
    public async Task TheRequest_NamesNtpv4AsTheNextProtocol()
    {

        var request = await Capture();
        var records = request.RecordsOfType(RawNtsKeRecordTypes.NextProtocolNegotiation).ToArray();

        Assert.Multiple(() => {

            Assert.That(records, Has.Length.EqualTo(1), $"{request}");

            Assert.That(request.UInt16Body(RawNtsKeRecordTypes.NextProtocolNegotiation),
                        Is.EqualTo(new UInt16[] { 0 }).AsCollection,
                        "protocol id 0 is NTPv4");

            Assert.That(records[0].IsCritical, Is.True,
                        "§ 4.1.2: the Critical Bit MUST be set");

        });

    }


    /// <summary>
    /// The offered AEAD algorithms reach the wire, in the order the client was given them.
    /// </summary>
    /// <remarks>
    /// § 4.1.5 has the server choose from this list, and both chrony's server and Norn's take the
    /// client's first supported entry — so the order is the client's preference and reordering it
    /// silently changes which primitive every session runs on. Asserted in both directions
    /// because a client that sorted, reversed or deduplicated the list would satisfy one of them.
    /// </remarks>
    [Test]
    public async Task TheOfferedAlgorithms_ReachTheWireInOrder()
    {

        var gcmSivFirst = await Capture([ AEADAlgorithms.AES_128_GCM_SIV, AEADAlgorithms.AES_SIV_CMAC_256 ]);
        var aesSivFirst = await Capture([ AEADAlgorithms.AES_SIV_CMAC_256, AEADAlgorithms.AES_128_GCM_SIV ]);

        Assert.Multiple(() => {

            Assert.That(gcmSivFirst.UInt16Body(RawNtsKeRecordTypes.AeadAlgorithmNegotiation),
                        Is.EqualTo(new UInt16[] { 30, 15 }).AsCollection,
                        $"{gcmSivFirst}");

            Assert.That(aesSivFirst.UInt16Body(RawNtsKeRecordTypes.AeadAlgorithmNegotiation),
                        Is.EqualTo(new UInt16[] { 15, 30 }).AsCollection,
                        $"{aesSivFirst}");

        });

    }


    /// <summary>
    /// End of Message is present, last, critical, and empty.
    /// </summary>
    /// <remarks>
    /// <para>
    /// § 4.1.1. It is how the peer knows the message is complete — without it a server reads
    /// until its timeout, and the exchange fails as a timeout rather than as a protocol error.
    /// </para>
    /// <para>
    /// The last assertion compares octet counts rather than looking at the decoded list, and that
    /// is the only form of it that can fail. <see cref="RawNtsKeCodec.TryDecode"/> stops at End of
    /// Message, because § 4 says a message ends there and anything after it is not part of it —
    /// so "the last decoded record is End of Message" is a statement about the decoder and holds
    /// however much the client appended. Re-encoding what was decoded and comparing against what
    /// arrived is what notices the difference.
    /// </para>
    /// </remarks>
    [Test]
    public async Task TheRequest_EndsWithEndOfMessage()
    {

        var request = await Capture();
        var records = request.Records!;

        Assert.Multiple(() => {

            Assert.That(records.Count(record => record.RecordType == RawNtsKeRecordTypes.EndOfMessage),
                        Is.EqualTo(1),
                        $"exactly one End of Message\n{request}");

            Assert.That(records[^1].RecordType, Is.EqualTo(RawNtsKeRecordTypes.EndOfMessage),
                        $"and it is the last record decoded\n{request}");

            Assert.That(records[^1].IsCritical, Is.True, "§ 4.1.1: the Critical Bit MUST be set");
            Assert.That(records[^1].Body,       Is.Empty, "and the body is empty");

            Assert.That(RawNtsKeCodec.Encode(records).Length,
                        Is.EqualTo(request.Bytes.Length),
                        $"and nothing at all follows it on the wire — {request.Bytes.Length} octets " +
                        $"arrived, the message accounts for {RawNtsKeCodec.Encode(records).Length}\n{request}");

        });

    }


    /// <summary>
    /// A client sends no cookie, no error and no warning in a request.
    /// </summary>
    /// <remarks>
    /// Not a rule anyone is likely to break deliberately, and exactly the kind a refactor breaks
    /// by accident — the records are built from one list, and a server ignores what it does not
    /// need. New Cookie for NTPv4 is a server-to-client record; Error and Warning are answers.
    /// </remarks>
    [Test]
    public async Task TheRequest_CarriesNoServerToClientRecords()
    {

        var request = await Capture();

        Assert.Multiple(() => {

            Assert.That(request.Contains(RawNtsKeRecordTypes.NewCookieForNtpv4), Is.False,
                        $"a cookie is something a server hands out\n{request}");

            Assert.That(request.Contains(RawNtsKeRecordTypes.Error),   Is.False, $"{request}");
            Assert.That(request.Contains(RawNtsKeRecordTypes.Warning), Is.False, $"{request}");

        });

    }


    #region IANA record 1024 — the claim that had no observer until now

    /// <summary>
    /// Offering AES-128-GCM-SIV, the client sends record 1024 — non-critical and empty.
    /// </summary>
    /// <remarks>
    /// Both properties are load-bearing. Empty because chrony's server treats a non-empty body as
    /// an error and refuses the exchange. Non-critical because a server that has never heard of
    /// the record must be able to ignore it: marked critical it would turn a request for the
    /// compliant exporter context into a demand, and RFC 8915 § 4 obliges every such server to
    /// answer with error code 0 instead of a session.
    /// </remarks>
    [Test]
    public async Task OfferingGcmSiv_TheClientSendsRecord1024()
    {

        var request = await Capture([ AEADAlgorithms.AES_128_GCM_SIV ]);
        var record  = request.FirstRecordOfType(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext);

        Assert.Multiple(() => {

            Assert.That(record, Is.Not.Null,
                        $"algorithm 30 was offered, so § 5.1's exporter context has to be claimed\n{request}");

            Assert.That(record?.IsCritical, Is.False,
                        "a server that does not know the record must be free to ignore it");

            Assert.That(record?.Body, Is.Empty,
                        "chrony's server refuses a non-empty body");

        });

    }


    /// <summary>
    /// Not offering AES-128-GCM-SIV, the client does not send it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The test this fixture was built for. It was written, found to be unfalsifiable, and
    /// deleted: a server must not echo record 1024 under any algorithm but 30, so a client that
    /// sent it always would have produced exactly the same answer, and the assertion would have
    /// passed forever regardless. Only a server that keeps the request can tell.
    /// </para>
    /// <para>
    /// The property itself is small — four ignored octets, and no peer would be harmed. It is
    /// worth stating because the record is a claim about a derivation, and claiming one for an
    /// algorithm that was never offered is a statement about nothing.
    /// </para>
    /// </remarks>
    [Test]
    public async Task NotOfferingGcmSiv_TheClientDoesNotSendRecord1024()
    {

        var request = await Capture([ AEADAlgorithms.AES_SIV_CMAC_256 ]);

        Assert.That(request.Contains(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext),
                    Is.False,
                    $"nothing was offered that the record has anything to say about\n{request}");

    }


    /// <summary>
    /// A client told to speak chrony's older dialect does not claim the compliant context.
    /// </summary>
    /// <remarks>
    /// The switch has to reach the wire and not merely the key selection. A client that kept
    /// sending the record while deriving keys the old way would be told "agreed" by a compliant
    /// server, derive under algorithm id 15 anyway, and fail every packet — the original defect,
    /// reintroduced from the other side.
    /// </remarks>
    [Test]
    public async Task SpeakingTheOlderDialect_TheClientDoesNotClaimTheCompliantContext()
    {

        var request = await Capture([ AEADAlgorithms.AES_128_GCM_SIV ],
                                    CompliantExporterContext: false);

        Assert.Multiple(() => {

            Assert.That(request.UInt16Body(RawNtsKeRecordTypes.AeadAlgorithmNegotiation),
                        Is.EqualTo(new UInt16[] { 30 }).AsCollection,
                        "the algorithm is still offered");

            Assert.That(request.Contains(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext),
                        Is.False,
                        $"but its exporter context is not claimed\n{request}");

        });

    }

    #endregion

}
