using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// IANA NTS-KE record type 1024, "Compliant AES-128-GCM-SIV Exporter Context" — the negotiation
/// that decides which of the two key derivations in the wild a session runs on.
///
/// <para>
/// RFC 8915 § 5.1 says the exporter context carries "the Numeric Identifier of the negotiated
/// AEAD Algorithm in network byte order". chrony writes 15 there for sessions running on 30, and
/// has since it first shipped the algorithm; the key length is taken from the real algorithm, so
/// only two octets differ. Two peers that both get it wrong agree with each other perfectly,
/// which is why this was invisible from inside either implementation and why Norn — which had it
/// right — could complete a key exchange with chronyd and then fail every single packet, in both
/// directions, with nothing in either to say why.
/// </para>
/// <para>
/// Correcting it outright would have broken every deployed pair, so chrony negotiates its way
/// out instead: a non-critical, empty-bodied record, sent by a client that can do it properly and
/// echoed by a server that agrees, and only then is § 5.1's context used. Registered rather than
/// squatted — 1024 is the first value in the registry's Specification Required range.
/// </para>
/// <para>
/// This fixture pins the rule from both ends against Norn, and the derivation itself against the
/// RFC. What it cannot show is which of the two contexts chronyd actually accepts; that needs
/// chronyd, and lives in the interop suite.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ExporterContextNegotiationTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(
                               certificate:     TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]),
                               aeadAlgorithms:  NTSAEAD.Implemented);


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    #region The derivation itself

    /// <summary>
    /// The five octets RFC 8915 § 5.1 specifies, for each algorithm and each direction.
    /// </summary>
    /// <remarks>
    /// Written out as literals rather than computed, because computing them here would be the
    /// same expression as the code under test and would agree with it however wrong it was. The
    /// protocol id is 0 for NTPv4, the algorithm id is two octets in network byte order, and the
    /// last octet is 0 for client-to-server and 1 for the other direction.
    /// </remarks>
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_256, false, new Byte[] { 0x00, 0x00, 0x00, 0x0F, 0x00 })]
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_256, true,  new Byte[] { 0x00, 0x00, 0x00, 0x0F, 0x01 })]
    [TestCase(AEADAlgorithms.AES_128_GCM_SIV,  false, new Byte[] { 0x00, 0x00, 0x00, 0x1E, 0x00 })]
    [TestCase(AEADAlgorithms.AES_128_GCM_SIV,  true,  new Byte[] { 0x00, 0x00, 0x00, 0x1E, 0x01 })]
    [TestCase(AEADAlgorithms.AES_256_GCM_SIV,  false, new Byte[] { 0x00, 0x00, 0x00, 0x1F, 0x00 })]
    public void TheExporterContext_IsTheFiveOctetsOfSection51(AEADAlgorithms  Algorithm,
                                                              Boolean         ServerToClient,
                                                              Byte[]          Expected)

        => Assert.That(NTSKE_ExportedKeys.Context(Algorithm, ServerToClient),
                       Is.EqualTo(Expected).AsCollection,
                       $"{Algorithm.AsText()} {(ServerToClient ? "S2C" : "C2S")} context");


    /// <summary>
    /// AES-128-GCM-SIV is the one algorithm whose context depends on the negotiation, and it is
    /// chrony's id 15 that goes in when nobody claimed the compliant one.
    /// </summary>
    /// <remarks>
    /// This is the whole defect in one assertion. Everything else about the two sessions is
    /// identical — same primitive, same sixteen-octet key, same twelve-octet nonce, same
    /// framing — and these two octets decide whether a peer can read a single packet.
    /// </remarks>
    [Test]
    public void WithoutTheRecord_GcmSivDerivesUnderTheAesSivAlgorithmId()

        => Assert.Multiple(() => {

            Assert.That(NTSKE_ExportedKeys.ExporterAlgorithmFor(AEADAlgorithms.AES_128_GCM_SIV, false),
                        Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256),
                        "unclaimed, algorithm 30's keys are derived under algorithm 15's id — chrony's way");

            Assert.That(NTSKE_ExportedKeys.ExporterAlgorithmFor(AEADAlgorithms.AES_128_GCM_SIV, true),
                        Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV),
                        "claimed, § 5.1's way");

        });


    /// <summary>
    /// And no other algorithm is touched by the record, whichever way it goes.
    /// </summary>
    /// <remarks>
    /// The quirk is chrony's and it is specific to algorithm 30. Applying it to AES-SIV-CMAC-256
    /// would break the one algorithm every implementation is required to have; applying it to
    /// AES-256-GCM-SIV would invent a dialect nobody speaks.
    /// </remarks>
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_256)]
    [TestCase(AEADAlgorithms.AES_256_GCM_SIV)]
    public void EveryOtherAlgorithm_HasOneContextRegardless(AEADAlgorithms Algorithm)

        => Assert.Multiple(() => {

            Assert.That(NTSKE_ExportedKeys.ExporterAlgorithmFor(Algorithm, false),
                        Is.EqualTo(Algorithm));

            Assert.That(NTSKE_ExportedKeys.ExporterAlgorithmFor(Algorithm, true),
                        Is.EqualTo(Algorithm));

        });

    #endregion

    #region What Norn's server does with the record

    /// <summary>
    /// The server echoes record 1024 when the client asked and AES-128-GCM-SIV was agreed.
    /// </summary>
    /// <remarks>
    /// Read off the wire by the suite's own decoder, because the echo is the entire signal: it is
    /// how the client learns which derivation the cookies it just received were built with. A
    /// server that used § 5.1's context and forgot to say so would hand out cookies no chrony
    /// client could use.
    /// </remarks>
    [Test]
    public async Task Asked_AndAgreedOnGcmSiv_TheServerEchoesTheRecord()
    {

        var exchange = await Exchange(
                                 RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                 RawNtsKeRecord.AeadAlgorithmNegotiation(30),
                                 RawNtsKeRecord.CompliantAes128GcmSivExporterContext(),
                                 RawNtsKeRecord.EndOfMessage()
                             );

        var echoed = exchange.FirstRecordOfType(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext);

        Assert.Multiple(() => {

            Assert.That(NegotiatedAlgorithm(exchange), Is.EqualTo(30),
                        $"only algorithm 30 was offered\n{exchange}");

            Assert.That(echoed, Is.Not.Null,
                        $"the client claimed § 5.1's context and the server did not confirm it\n{exchange}");

            Assert.That(echoed?.Body,       Is.Empty,   "the record carries no body");
            Assert.That(echoed?.IsCritical, Is.False,
                        "and is not critical, so a peer that does not know it may ignore it");

        });

    }


    /// <summary>
    /// Not asked, not echoed — even though the server could do it.
    /// </summary>
    /// <remarks>
    /// This is the half that keeps every deployed chrony client working. Such a client offers
    /// algorithm 30 without the record and is waiting for keys derived chrony's way; a server
    /// that answered with § 5.1's context anyway would negotiate a session neither side could
    /// use, which is precisely the failure this record exists to end.
    /// </remarks>
    [Test]
    public async Task NotAsked_TheServerDoesNotEchoTheRecord()
    {

        var exchange = await Exchange(
                                 RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                 RawNtsKeRecord.AeadAlgorithmNegotiation(30),
                                 RawNtsKeRecord.EndOfMessage()
                             );

        Assert.Multiple(() => {

            Assert.That(NegotiatedAlgorithm(exchange), Is.EqualTo(30),
                        $"the algorithm is still agreed\n{exchange}");

            Assert.That(exchange.FirstRecordOfType(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext),
                        Is.Null,
                        $"nothing was claimed, so nothing may be confirmed\n{exchange}");

        });

    }


    /// <summary>
    /// Asked, but a different algorithm was agreed — still not echoed.
    /// </summary>
    /// <remarks>
    /// The record says something only about algorithm 30's context. Echoing it under
    /// AES-SIV-CMAC-256 would be a claim about a derivation that has never been in doubt, and it
    /// would tell a client the server had agreed to something it was not asked about.
    /// </remarks>
    [Test]
    public async Task Asked_ButAnotherAlgorithmAgreed_TheServerDoesNotEchoTheRecord()
    {

        var exchange = await Exchange(
                                 RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                 RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                 RawNtsKeRecord.CompliantAes128GcmSivExporterContext(),
                                 RawNtsKeRecord.EndOfMessage()
                             );

        Assert.Multiple(() => {

            Assert.That(NegotiatedAlgorithm(exchange), Is.EqualTo(15),
                        $"only AES-SIV-CMAC-256 was offered\n{exchange}");

            Assert.That(exchange.FirstRecordOfType(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext),
                        Is.Null,
                        $"the record has nothing to say about algorithm 15\n{exchange}");

        });

    }


    /// <summary>
    /// The record does not fail a key exchange when it arrives with the critical bit set.
    /// </summary>
    /// <remarks>
    /// RFC 8915 § 4 makes an unrecognised critical record an error, and this one is recognised —
    /// so the answer must be a negotiated session rather than error code 0. Norn never sends it
    /// critical, but what a peer sends is not Norn's to choose, and refusing it would be refusing
    /// a record the server understands perfectly well.
    /// </remarks>
    [Test]
    public async Task ACriticalRecord_IsUnderstoodRatherThanRefused()
    {

        var exchange = await Exchange(
                                 RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                 RawNtsKeRecord.AeadAlgorithmNegotiation(30),
                                 RawNtsKeRecord.CompliantAes128GcmSivExporterContext(isCritical: true),
                                 RawNtsKeRecord.EndOfMessage()
                             );

        Assert.Multiple(() => {

            Assert.That(exchange.ErrorCode, Is.Null,
                        $"the server treated a record it knows as unrecognised\n{exchange}");

            Assert.That(exchange.FirstRecordOfType(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext),
                        Is.Not.Null,
                        $"and honoured it\n{exchange}");

        });

    }

    #endregion

    #region What Norn's client does with it

    /// <summary>
    /// Offering AES-128-GCM-SIV, Norn's client claims § 5.1's context and the two sides use it.
    /// </summary>
    /// <remarks>
    /// The server only ever echoes what it was asked, so the echo arriving is proof the client
    /// sent the record — and the session completing afterwards is proof both derived the same
    /// key from it.
    /// </remarks>
    [Test]
    public async Task OfferingGcmSiv_TheClientClaimsTheCompliantContext()
    {

        var client       = fixture!.CreateClient(TimeSpan.FromSeconds(10),
                                                 aeadAlgorithms: [ AEADAlgorithms.AES_128_GCM_SIV ]);

        var keyExchange  = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success, Is.True, keyExchange.ErrorMessage);

        var response = keyExchange.Response!;

        Assert.Multiple(() => {

            Assert.That(response.AEADAlgorithm, Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV));

            Assert.That(response.CompliantAES128GCMSIVExporterContext, Is.True,
                        "the server echoed, which it does only when asked");

        });

        var query = await client.QueryTime(NTSKEResponse: response,
                                           Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(query.Success, Is.True,
                    $"and both sides derived the same key from that context: {query.ErrorMessage}");

    }


    /// <summary>
    /// A client that does not claim it gets chrony's derivation, and the session still works.
    /// </summary>
    /// <remarks>
    /// Both halves matter. The record must not be echoed, or the negotiation is not a negotiation
    /// — and the session must still complete, because this is the dialect every chronyd older
    /// than record 1024 speaks and the only one that reaches those servers.
    /// </remarks>
    [Test]
    public async Task NotClaimingIt_BothSidesFallBackToChronysContext()
    {

        var client       = fixture!.CreateClient(TimeSpan.FromSeconds(10),
                                                 aeadAlgorithms:            [ AEADAlgorithms.AES_128_GCM_SIV ],
                                                 compliantExporterContext:  false);

        var keyExchange  = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success, Is.True, keyExchange.ErrorMessage);

        var response = keyExchange.Response!;

        Assert.Multiple(() => {

            Assert.That(response.AEADAlgorithm, Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV));

            Assert.That(response.CompliantAES128GCMSIVExporterContext, Is.False,
                        "nothing was claimed, so the server must not have confirmed anything");

        });

        var query = await client.QueryTime(NTSKEResponse: response,
                                           Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(query.Success, Is.True,
                    $"the older dialect has to keep working: {query.ErrorMessage}");

    }


    // Not asserted here, and the reason is worth recording rather than leaving as an apparent
    // oversight: that the client omits record 1024 when it is not offering AES-128-GCM-SIV is
    // not observable from anywhere in this suite. Nothing terminates TLS on the client's far
    // side and keeps the request, so the only evidence available is what a server echoes — and
    // a server must not echo the record under another algorithm anyway, so a client that sent
    // it always would look identical from here. A capturing NTS-KE server would settle it; the
    // property is cosmetic (four ignored octets), the test would not be, and a test that cannot
    // fail is worse than none.

    #endregion

    #region (private) helpers

    /// <summary>
    /// Send a hand-built record stream to Norn's NTS-KE server and read the reply.
    /// </summary>
    private async Task<RawNtsKeExchange> Exchange(params RawNtsKeRecord[] Records)
    {

        var exchange = await RawNtsKeClient.ExchangeAsync(
                                 "127.0.0.1",
                                 fixture!.NTSKEPort,
                                 RawNtsKeCodec.Encode(Records),
                                 TimeSpan.FromSeconds(10)
                             );

        Assert.That(exchange.Records, Is.Not.Null, $"no records came back\n{exchange}");

        return exchange;

    }


    /// <summary>
    /// The algorithm id in the response's AEAD Algorithm Negotiation record.
    /// </summary>
    private static Int32? NegotiatedAlgorithm(RawNtsKeExchange Exchange)
    {

        var record = Exchange.FirstRecordOfType(RawNtsKeRecordTypes.AeadAlgorithmNegotiation);

        return record is not null && record.Body.Length >= 2
                   ? (record.Body[0] << 8) | record.Body[1]
                   : null;

    }

    #endregion

}
