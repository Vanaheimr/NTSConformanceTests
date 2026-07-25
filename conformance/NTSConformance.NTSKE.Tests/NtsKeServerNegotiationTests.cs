using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// What Norn's NTS-KE <em>server</em> must do with a request it cannot satisfy —
/// RFC 8915 §4.1.2 (next protocol), §4.1.3 (errors) and §4.1.5 (AEAD).
///
/// These are driven by <see cref="RawNtsKeClient"/>, which speaks TLS through .NET's
/// <c>SslStream</c> and hands the server raw record octets. That matters twice over: no
/// conformant encoder would produce most of these requests, and Norn's own client would
/// never send them — so the server's behaviour here was previously unobservable.
///
/// The distinction the fixture is built around is "sent an Error record" versus "closed the
/// connection". Both leave a client without a session, but only the first tells it why, and
/// §4.1.3 requires the first.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsKeServerNegotiationTests
{

    private NornServerFixture? fixture;

    /// <summary>AEAD ids from the IANA registry: 15 is the one NTS mandates, 30 is not implemented here.</summary>
    private const UInt16 AeadAesSivCmac256 = 15;
    private const UInt16 AeadAes128GcmSiv  = 30;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(
                         certificate: TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]));


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    private async Task<RawNtsKeExchange> Exchange(Byte[] requestRecords)
    {

        if (fixture is null)
            throw new InvalidOperationException("the server fixture did not start");

        return await RawNtsKeClient.ExchangeAsync("127.0.0.1",
                                                 fixture.NTSKEPort,
                                                 requestRecords,
                                                 TimeSpan.FromSeconds(15));

    }


    #region The conformant baseline

    /// <summary>
    /// A conformant request must be answered with the records RFC 8915 §4 requires, and the
    /// negotiated values must be the ones the client offered. Without this passing, the
    /// negative tests below could be failing for the wrong reason.
    /// </summary>
    [Test]
    public async Task ConformantRequest_IsAnswered()
    {

        var exchange = await Exchange(RawNtsKeCodec.ClientRequest(AeadAesSivCmac256));

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        Assert.Multiple(() => {

            Assert.That(exchange.NegotiatedAlpn, Is.EqualTo("ntske/1"),
                        "RFC 8915 §4 runs NTS-KE under the ntske/1 ALPN protocol");

            Assert.That(exchange.ClosedWithoutResponse, Is.False, exchange.ToString());

            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NextProtocolNegotiation).Count(),
                        Is.EqualTo(1), $"exactly one Next Protocol Negotiation record\n{exchange}");

            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.AeadAlgorithmNegotiation).Count(),
                        Is.EqualTo(1), $"exactly one AEAD Algorithm Negotiation record\n{exchange}");

            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).Any(),
                        Is.True, $"at least one cookie\n{exchange}");

            Assert.That(exchange.Records?[^1].RecordType,
                        Is.EqualTo(RawNtsKeRecordTypes.EndOfMessage),
                        $"a message ends with End of Message\n{exchange}");

            Assert.That(exchange.ErrorCode, Is.Null, $"no Error record\n{exchange}");

        });

    }


    /// <summary>
    /// RFC 8915 §4.1.5: the algorithm the server selects must be one the client offered.
    /// Offering both a supported and an unsupported algorithm must yield the supported one.
    /// </summary>
    [Test]
    public async Task AeadSelection_ComesFromTheClientsList()
    {

        var request = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                          RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAes128GcmSiv, AeadAesSivCmac256),
                          RawNtsKeRecord.EndOfMessage()
                      ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.ClosedWithoutResponse, Is.False, exchange.ToString());

        var aead = exchange.FirstRecordOfType(RawNtsKeRecordTypes.AeadAlgorithmNegotiation);

        if (aead is null)
        {
            Assert.Fail($"the response carries no AEAD Algorithm Negotiation record\n{exchange}");
            return;
        }

        Assert.That(RawNtsKeCodec.ReadUInt16Body(aead),
                    Is.EqualTo(new UInt16[] { AeadAesSivCmac256 }).AsCollection,
                    $"the server should select AES-SIV-CMAC-256, which the client offered\n{exchange}");

    }

    #endregion

    #region F2 — the server must say why it refused

    /// <summary>
    /// F2 — RFC 8915 §4: "Implementations which receive a record with an unrecognized Record
    /// Type MUST ignore the record if the Critical Bit is 0 and MUST treat it as an error if
    /// the Critical Bit is 1", and §4.1.3 error code 0: "The server MUST respond with this
    /// error code if the request included a record that the server did not understand and
    /// that had its Critical Bit set."
    ///
    /// Norn logs the problem and closes the connection. The client is left unable to tell a
    /// rejected record from a network fault, and cannot learn that dropping the unknown
    /// record would let the handshake succeed.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task UnknownCriticalRecord_DrawsError0()
    {

        var request = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                          RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAesSivCmac256),
                          new RawNtsKeRecord(true, 0x3FFF, [ 0xDE, 0xAD ]),
                          RawNtsKeRecord.EndOfMessage()
                      ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        Assert.That(exchange.ErrorCode,
                    Is.EqualTo(RawNtsKeErrorCodes.UnrecognizedCriticalRecord),
                    $"an unrecognized record with the Critical Bit set must draw Error code 0\n{exchange}");

    }


    /// <summary>
    /// The other half of the same rule: with the Critical Bit clear, the very same
    /// unrecognized record MUST be ignored and the handshake must succeed.
    ///
    /// Kept separate from the test above so a server that rejected everything would not look
    /// conformant, and so this one can stay green while that one is open.
    /// </summary>
    [Test]
    public async Task UnknownNonCriticalRecord_IsIgnored()
    {

        var request = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                          RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAesSivCmac256),
                          new RawNtsKeRecord(false, 0x3FFF, [ 0xDE, 0xAD ]),
                          RawNtsKeRecord.EndOfMessage()
                      ]);

        var exchange = await Exchange(request);

        Assert.Multiple(() => {

            Assert.That(exchange.ClosedWithoutResponse, Is.False,
                        $"an unrecognized non-critical record must be ignored, not fatal\n{exchange}");

            Assert.That(exchange.ErrorCode, Is.Null, $"no Error record is warranted\n{exchange}");

            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).Any(),
                        Is.True, $"the handshake should complete normally\n{exchange}");

        });

    }


    /// <summary>
    /// F2 — RFC 8915 §4.1.3 error code 1: "The server MUST respond with this error if the
    /// request is not complete and syntactically well-formed."
    ///
    /// Here a record declares a body far longer than the octets that follow, so the stream
    /// cannot be parsed at all.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    // Slow by nature: with no Error record forthcoming, the only way to establish that the
    // server said nothing is to wait out its own NTSKERequestTimeout.
    [Category(TestCategories.Slow)]
    public async Task MalformedRecordStream_DrawsError1()
    {

        var request = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4)
                              with { LengthOverride = 4096 }
                      ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        Assert.That(exchange.ErrorCode,
                    Is.EqualTo(RawNtsKeErrorCodes.BadRequest),
                    $"a request that is not syntactically well-formed must draw Error code 1\n{exchange}");

    }


    /// <summary>
    /// F2 — RFC 8915 §4.1.2: "The request MUST list at least one protocol." A request with no
    /// Next Protocol Negotiation record at all is therefore not complete, and §4.1.3 error
    /// code 1 applies.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task RequestWithoutNextProtocolNegotiation_DrawsError1()
    {

        var request = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAesSivCmac256),
                          RawNtsKeRecord.EndOfMessage()
                      ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        Assert.That(exchange.ErrorCode,
                    Is.EqualTo(RawNtsKeErrorCodes.BadRequest),
                    $"a request without the mandatory Next Protocol Negotiation record must draw " +
                    $"Error code 1\n{exchange}");

    }


    /// <summary>
    /// F2 — RFC 8915 §4.1.2: an empty protocol list in a <em>request</em> violates "The
    /// request MUST list at least one protocol", so it too is a bad request.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task RequestWithEmptyProtocolList_DrawsError1()
    {

        var request = RawNtsKeCodec.Encode([
                          RawNtsKeRecord.NextProtocolNegotiation(),   // no protocol ids
                          RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAesSivCmac256),
                          RawNtsKeRecord.EndOfMessage()
                      ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        Assert.That(exchange.ErrorCode,
                    Is.EqualTo(RawNtsKeErrorCodes.BadRequest),
                    $"an empty protocol list in a request must draw Error code 1\n{exchange}");

    }

    #endregion

    #region F3 — the server must actually negotiate

    /// <summary>
    /// F3 — RFC 8915 §4.1.2: "Protocol IDs listed in the NTS-KE server's response MUST
    /// comprise a subset of those listed in the request."
    ///
    /// A client that offers only protocol 1 must not be told 0 (NTPv4). §4.1.2 allows the
    /// response list to be empty, so refusing is conformant — inventing a protocol the
    /// client never offered is not, and a client acting on it would derive keys for a
    /// protocol the two never agreed on.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task NextProtocolResponse_IsASubsetOfTheRequest()
    {

        const UInt16 protocolTheClientOffered = 1;

        var request  = RawNtsKeCodec.Encode([
                           RawNtsKeRecord.NextProtocolNegotiation(protocolTheClientOffered),
                           RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAesSivCmac256),
                           RawNtsKeRecord.EndOfMessage()
                       ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        // Refusing outright satisfies the rule.
        if (exchange.ErrorCode is not null)
            Assert.Pass($"the server refused the unsupported protocol with Error code {exchange.ErrorCode}");

        var nextProtocol = exchange.FirstRecordOfType(RawNtsKeRecordTypes.NextProtocolNegotiation);

        if (nextProtocol is null)
            Assert.Pass("the server sent no Next Protocol Negotiation record, so it claimed no protocol");

        var offered = RawNtsKeCodec.ReadUInt16Body(nextProtocol!);

        Assert.That(offered,
                    Is.SubsetOf(new UInt16[] { protocolTheClientOffered }),
                    $"the client offered only protocol {protocolTheClientOffered}, so the response " +
                    $"must be a subset of that (an empty list would be fine)\n{exchange}");

    }


    /// <summary>
    /// F3 — RFC 8915 §4.1.5: "When included in a response, this record denotes which
    /// algorithm the server chooses to use. It is empty if the server supports none of the
    /// algorithms offered."
    ///
    /// A client offering only AES-128-GCM-SIV (30), which Norn does not implement, must get
    /// back an empty AEAD record — not AES-SIV-CMAC-256 (15), which it never offered. A
    /// client told 15 would either fail or, worse, proceed with an algorithm the server
    /// picked unilaterally.
    ///
    /// Note this does not conflict with §4.1.5's requirement that the record not be empty
    /// when the client <em>does</em> offer 15: that case is covered by
    /// <see cref="AeadSelection_ComesFromTheClientsList"/>.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task UnsupportedAeadOnly_YieldsAnEmptyRecordOrAnError()
    {

        var request  = RawNtsKeCodec.Encode([
                           RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                           RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAes128GcmSiv),
                           RawNtsKeRecord.EndOfMessage()
                       ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        if (exchange.ErrorCode is not null)
            Assert.Pass($"the server refused the unsupported algorithm with Error code {exchange.ErrorCode}");

        var aead = exchange.FirstRecordOfType(RawNtsKeRecordTypes.AeadAlgorithmNegotiation);

        if (aead is null)
            Assert.Pass("the server sent no AEAD Algorithm Negotiation record, so it selected nothing");

        Assert.That(RawNtsKeCodec.ReadUInt16Body(aead!),
                    Is.SubsetOf(new UInt16[] { AeadAes128GcmSiv }),
                    $"the client offered only AEAD {AeadAes128GcmSiv}, so the server must either " +
                    $"select that or send an empty record — never an algorithm the client did not " +
                    $"offer\n{exchange}");

    }


    /// <summary>
    /// F3 — a server that never reads the client's offers will also hand out NTPv4 cookies to
    /// a client that never asked for NTPv4. Cookies are only meaningful once a protocol has
    /// been agreed, so issuing them alongside a protocol the client did not offer is the same
    /// defect seen from the other side.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task NoCookiesWhenNtpv4WasNotNegotiated()
    {

        var request  = RawNtsKeCodec.Encode([
                           RawNtsKeRecord.NextProtocolNegotiation(1),   // not NTPv4
                           RawNtsKeRecord.AeadAlgorithmNegotiation(AeadAesSivCmac256),
                           RawNtsKeRecord.EndOfMessage()
                       ]);

        var exchange = await Exchange(request);

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        if (exchange.ErrorCode is not null)
            Assert.Pass($"the server refused the request with Error code {exchange.ErrorCode}");

        Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).Any(),
                    Is.False,
                    $"NTPv4 cookies were issued although NTPv4 was never negotiated\n{exchange}");

    }

    #endregion

}
