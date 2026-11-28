using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// NTS for NTPv5, draft-ietf-ntp-ntpv5-10 § 11: the key exchange agreeing to NTPv5 under the
/// draft's Protocol ID 0x8001 for a client that names its draft in record 0x4001, keys from the
/// exporter context of that protocol (RFC 8915 § 5.1), and the extension fields of RFC 8915 § 5
/// in an NTPv5 message.
/// </summary>
/// <remarks>
/// <para>
/// Nothing on the NTPv5 side goes through Norn: the request is written and the response read and
/// decrypted by this suite's own codec and AEADs. The keys are this suite's own too. Over TLS
/// they would come from the TLS exporter, which .NET's TLS does not expose, so the key exchange
/// runs over Norn's SSH listener with the Transported Secret of NTS-KE over SSH: the server
/// hands over nts_ke_secret, and the keys are HKDF-Expand-SHA256 of it with RFC 8915 § 5.1's
/// context - and so the context with 0x8001 in front is a fact this side computes, not one it
/// is told. The key exchange over TLS is checked for what it agrees to.
/// </para>
/// <para>
/// Where the draft leaves a choice, what Norn chose is checked as Norn's: the Draft
/// Identification is not echoed, a failed request is answered only where it set the
/// Authentication NAK flag, and fields after the authenticator other than the Correction are not
/// answered.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5NtsTests
{

    #region Data

    private static readonly ISshHostKey ClientKey = SshHostKey.GenerateEd25519();

    private static readonly TimeSpan    Silence   = TimeSpan.FromMilliseconds(1500);

    private NornServerFixture? fixture;

    #endregion


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(ntpv5:           NTPv5Support.Draft,
                                                        aeadAlgorithms:  NTSAEAD.Implemented,
                                                        sshClientKey:    ClientKey);


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    #region Helpers

    private NornServerFixture Server
        => fixture ?? throw new InvalidOperationException("the server fixture did not start");


    /// <summary>
    /// § 11: the record a client of the draft names its draft in, non-critical, in ASCII.
    /// </summary>
    private static RawNtsKeRecord DraftRecord(String Identification = RawNtpV5Draft.Identification)
        => new (false, RawNtsKeRecordTypes.Ntpv5DraftIdentification, Encoding.ASCII.GetBytes(Identification));


    private static async Task<RawNtsKeExchange> OverTls(NornServerFixture Server, params RawNtsKeRecord[] Records)

        => await RawNtsKeClient.ExchangeAsync("127.0.0.1",
                                              Server.NTSKEPort,
                                              RawNtsKeCodec.Encode(Records),
                                              TimeSpan.FromSeconds(10));


    private static UInt16[]? NextProtocolOf(RawNtsKeExchange Exchange)
        => Exchange.FirstRecordOfType(RawNtsKeRecordTypes.NextProtocolNegotiation) is { } record
               ? RawNtsKeCodec.ReadUInt16Body(record)
               : null;


    /// <summary>
    /// The keys and cookies of one key exchange, derived on this side.
    /// </summary>
    private sealed record Session(UInt16                 Aead,
                                  Byte[]                 C2SKey,
                                  Byte[]                 S2CKey,
                                  IReadOnlyList<Byte[]>  Cookies);


    /// <summary>
    /// A key exchange over SSH, for the given protocol and algorithm, with the given method of
    /// the SSH Key Binding record alone on offer, and the keys under the context of
    /// <paramref name="ContextProtocol"/> - by default the protocol agreed, which is what § 5.1
    /// has them be.
    /// </summary>
    /// <remarks>
    /// The Transported Secret is HKDF-Expand-SHA256 of the secret the server sends, computed
    /// here. The SSH Exporter is Hermod's exporter of this side's end of the connection, under
    /// the context written here; its HKDF is checked against the specification's vectors on
    /// its own, in SshKeyBindingVectorTests and Hermod's tests.
    /// </remarks>
    private static async Task<Session> KeyExchange(NornServerFixture  Server,
                                                   UInt16             Aead             = 15,
                                                   UInt16             NextProtocol     = RawNtsKeNextProtocols.Ntpv5Draft,
                                                   UInt16?            ContextProtocol  = null,
                                                   UInt16             Method           = RawSshKeyBinding.MethodTransportedSecret)
    {

        await using var ssh = await Server.ConnectSshAsync(ClientKey);

        var exchange = await RawNtsKeOverSsh.ExchangeAsync(
                                 ssh,
                                 RawNtsKeCodec.Encode([
                                     RawNtsKeRecord.NextProtocolNegotiation(NextProtocol),
                                     RawNtsKeRecord.AeadAlgorithmNegotiation(Aead),
                                     .. (NextProtocol == RawNtsKeNextProtocols.Ntpv5Draft ? new[] { DraftRecord() } : []),
                                     RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(Method)),
                                     RawNtsKeRecord.EndOfMessage()
                                 ]));

        var keyBinding = exchange.FirstRecordOfType(RawNtsKeRecordTypes.SshKeyBinding);
        var cookies    = exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).Select(record => record.Body).ToArray();

        Assert.Multiple(() => {
            Assert.That(exchange.ErrorCode,                Is.Null,                          $"an Error record\n{exchange}");
            Assert.That(NextProtocolOf(exchange),          Is.EqualTo(new[] { NextProtocol }), $"the protocol agreed\n{exchange}");
            Assert.That(keyBinding?.Body.Length,           Is.EqualTo(2 + 32),               $"the method and its 32 octets of data\n{exchange}");
            Assert.That(keyBinding is null ? null : (UInt16?) ((keyBinding.Body[0] << 8) | keyBinding.Body[1]),
                        Is.EqualTo(Method),                                                  $"the method selected\n{exchange}");
            Assert.That(cookies,                           Is.Not.Empty,                     $"no cookie\n{exchange}");
        });

        var data       = keyBinding!.Body[2..];
        var keyLength  = RawNtpV5Nts.KeyLength(Aead);
        var context    = ContextProtocol ?? NextProtocol;

        Byte[] KeyFor(Byte Direction)
            => Method == RawSshKeyBinding.MethodTransportedSecret
                   ? RawSshKeyBinding.TransportedSecretKey(data, Aead, Direction, keyLength, context)
                   : ssh.Exporter.Export(data,
                                         RawSshKeyBinding.ExporterLabel,
                                         RawSshKeyBinding.Context(Aead, Direction, context),
                                         keyLength);

        return new Session(Aead,
                           KeyFor(RawSshKeyBinding.C2S),
                           KeyFor(RawSshKeyBinding.S2C),
                           cookies);

    }


    /// <summary>
    /// An NTS request of the session, sent; and its Unique Identifier and octets, for what the
    /// response must echo and how long it must be.
    /// </summary>
    private static (Byte[] UniqueIdentifier, Byte[] Request, Byte[]? Response) Send(NornServerFixture                     Server,
                                                                                   Session                               Session,
                                                                                   RawNtpV5Packet?                       Request             = null,
                                                                                   Byte[]?                               Cookie              = null,
                                                                                   Int32                                 Placeholders        = 0,
                                                                                   Int32?                                PlaceholderLength   = null,
                                                                                   IEnumerable<RawNtpV5ExtensionField>?  AfterAuthenticator  = null,
                                                                                   TimeSpan?                             Timeout             = null)
    {

        var uniqueIdentifier  = RandomNumberGenerator.GetBytes(RawNtpV5Nts.MinimumUniqueIdentifierLength);

        var request           = RawNtpV5Nts.Request(Request ?? RawNtpV5Packet.ClientRequest(),
                                                    Session.Aead,
                                                    Session.C2SKey,
                                                    Cookie ?? Session.Cookies[0],
                                                    uniqueIdentifier,
                                                    Placeholders,
                                                    PlaceholderLength,
                                                    AfterAuthenticator);

        return (uniqueIdentifier,
                request,
                RawUdpExchange.TryExchange(request, "127.0.0.1", Server.NTPPort, Timeout));

    }


    /// <summary>
    /// Verify the response as a client must, and what draft § 10 has every response be.
    /// </summary>
    private static RawNtpV5Nts.VerifiedResponse Verified(Session Session, (Byte[] UniqueIdentifier, Byte[] Request, Byte[]? Response) Exchange, String What)
    {

        Assert.That(Exchange.Response, Is.Not.Null, $"{What}: the server did not answer");

        Assert.That(RawNtpV5Nts.TryVerifyResponse(Exchange.Response!, Session.Aead, Session.S2CKey, Exchange.UniqueIdentifier, out var verified, out var error),
                    Is.True,
                    $"{What}: {error}\n{Bytes.Dump(Exchange.Response!)}");

        Assert.That(Exchange.Response!.Length, Is.EqualTo(Exchange.Request.Length), $"{What}: § 10 step 5, the response is as long as the request");

        return verified!;

    }


    /// <summary>
    /// The authenticator field of a request, with one octet of its ciphertext flipped.
    /// </summary>
    private static Byte[] WithABrokenAuthenticator(Byte[] Request)
    {

        Assert.That(RawNtpV5Packet.TryRead(Request, out var packet, out var error), Is.True, error);

        var index   = packet!.ExtensionFields.FindIndex(field => field.Type == RawNtpV5Nts.NtsAuthenticator);
        var broken  = Request.ToArray();

        broken[RawNtpV5Nts.OffsetOf(packet, index) + packet.ExtensionFields[index].Length - 1] ^= 0x01;

        return broken;

    }

    #endregion


    #region NTS-KE: agreeing to NTPv5 (§ 11)

    /// <summary>
    /// § 11: NTPv5 "can be indicated as the next protocol with identifier [[TBD]] (draft use
    /// 0x8001)", and a client of the draft names its draft in record 0x4001. Then the server
    /// agrees to 0x8001, with an algorithm and cookies, which § 11 takes over from NTPv4's
    /// records: "No new NTS-KE records are specified for NTPv5".
    /// </summary>
    [Test]
    public async Task TheDraftNamed_NTPv5IsAgreed()
    {

        var exchange = await OverTls(Server,
                                     RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv5Draft, RawNtsKeNextProtocols.Ntpv4),
                                     RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                     DraftRecord(),
                                     RawNtsKeRecord.EndOfMessage());

        Assert.Multiple(() => {
            Assert.That(exchange.ErrorCode,          Is.Null,                                                $"an Error record\n{exchange}");
            Assert.That(NextProtocolOf(exchange),    Is.EqualTo(new[] { RawNtsKeNextProtocols.Ntpv5Draft }), $"the protocol agreed\n{exchange}");
            Assert.That(exchange.FirstRecordOfType(RawNtsKeRecordTypes.AeadAlgorithmNegotiation) is { } aead ? RawNtsKeCodec.ReadUInt16Body(aead) : null,
                        Is.EqualTo(new UInt16[] { 15 }),                                                     $"the algorithm agreed\n{exchange}");
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4), Is.Not.Empty,          $"NTPv4's cookie records carry NTPv5's cookies\n{exchange}");
        });

    }


    /// <summary>
    /// § 11: "Servers that implement a draft MUST not accept NTPv5 as an option unless they
    /// support the specific draft version identified." No draft named, another draft, the right
    /// one with a trailing zero or in other case: NTPv4, which the client offered as well.
    /// </summary>
    [TestCase(null,                        TestName = "WithoutTheDraftRecord_NTPv4IsAgreed")]
    [TestCase("draft-ietf-ntp-ntpv5-09",   TestName = "WithAnotherDraft_NTPv4IsAgreed")]
    [TestCase("draft-ietf-ntp-ntpv5-10\0", TestName = "WithTheDraftAndATrailingZero_NTPv4IsAgreed")]
    [TestCase("DRAFT-IETF-NTP-NTPV5-10",   TestName = "WithTheDraftInUpperCase_NTPv4IsAgreed")]
    public async Task WithoutThisDraft_NTPv4IsAgreed(String? Identification)
    {

        var exchange = await OverTls(Server,
                                     [ RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv5Draft, RawNtsKeNextProtocols.Ntpv4),
                                       RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                       .. (Identification is null ? Array.Empty<RawNtsKeRecord>() : [ DraftRecord(Identification) ]),
                                       RawNtsKeRecord.EndOfMessage() ]);

        Assert.Multiple(() => {
            Assert.That(exchange.ErrorCode,       Is.Null,                                           $"an Error record\n{exchange}");
            Assert.That(NextProtocolOf(exchange), Is.EqualTo(new[] { RawNtsKeNextProtocols.Ntpv4 }), $"the protocol agreed\n{exchange}");
        });

    }


    /// <summary>
    /// The same with NTPv5 alone on offer: there is nothing to fall back on, and RFC 8915
    /// § 4.1.2 has the server say so with an empty Next Protocol Negotiation record - "the
    /// server MUST NOT ... include ... protocols which were not offered by the client" - and no
    /// cookies, since nothing was agreed for them to be cookies of.
    /// </summary>
    [Test]
    public async Task NTPv5Alone_WithoutTheDraftRecord_NothingIsAgreed()
    {

        var exchange = await OverTls(Server,
                                     RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv5Draft),
                                     RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                     RawNtsKeRecord.EndOfMessage());

        Assert.Multiple(() => {
            Assert.That(NextProtocolOf(exchange),                                       Is.Empty, $"a protocol agreed\n{exchange}");
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4), Is.Empty, $"cookies for nothing\n{exchange}");
        });

    }


    /// <summary>
    /// § 11 has the client name its draft, not the server: Norn says that it supports it by
    /// agreeing to 0x8001, and does not send record 0x4001 back.
    /// </summary>
    [Test]
    public async Task TheDraftRecord_IsNotEchoed()
    {

        var exchange = await OverTls(Server,
                                     RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv5Draft),
                                     RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                     DraftRecord(),
                                     RawNtsKeRecord.EndOfMessage());

        Assert.Multiple(() => {
            Assert.That(NextProtocolOf(exchange),                                              Is.EqualTo(new[] { RawNtsKeNextProtocols.Ntpv5Draft }), exchange.ToString());
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.Ntpv5DraftIdentification), Is.Empty,                                                exchange.ToString());
        });

    }


    /// <summary>
    /// A client of the draft sends record 0x4001 in every request, NTPv5 or not. Norn's NTS
    /// Public Key record used to have that type, and as a record only the server sends, a request
    /// with it was refused with Bad Request - every client of the draft was. Now the record is
    /// 0x4E01, and 0x4001 is no reason to refuse anything.
    /// </summary>
    [Test]
    public async Task TheDraftRecord_WithNTPv4Alone_IsNoBadRequest()
    {

        var exchange = await OverTls(Server,
                                     RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                     RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                     DraftRecord(),
                                     RawNtsKeRecord.EndOfMessage());

        Assert.Multiple(() => {
            Assert.That(exchange.ErrorCode,                                             Is.Null,                                           $"an Error record\n{exchange}");
            Assert.That(NextProtocolOf(exchange),                                       Is.EqualTo(new[] { RawNtsKeNextProtocols.Ntpv4 }), exchange.ToString());
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4), Is.Not.Empty,                                      exchange.ToString());
        });

    }


    /// <summary>
    /// Norn's NTS Public Key record, now 0x4E01, is one only the server sends, like the Error
    /// and Warning records of RFC 8915 § 4.1.3 and § 4.1.4 and the cookies of § 4.1.6: in a
    /// request it is a Bad Request.
    /// </summary>
    [Test]
    public async Task NornsPublicKeyRecord_InARequest_IsABadRequest()
    {

        var exchange = await OverTls(Server,
                                     RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                     RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                     new RawNtsKeRecord(false, 0x4E01, new Byte[32]),
                                     RawNtsKeRecord.EndOfMessage());

        Assert.That(exchange.ErrorCode, Is.EqualTo(RawNtsKeErrorCodes.BadRequest), exchange.ToString());

    }


    /// <summary>
    /// NTPv5 needs an AEAD algorithm as NTPv4 does, for the same extension fields, so a request
    /// offering it without an AEAD Algorithm Negotiation record is refused as RFC 8915 § 4.1.5
    /// has one for NTPv4 refused.
    /// </summary>
    [Test]
    public async Task NTPv5WithoutAnAeadRecord_IsABadRequest()
    {

        var exchange = await OverTls(Server,
                                     RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv5Draft),
                                     DraftRecord(),
                                     RawNtsKeRecord.EndOfMessage());

        Assert.That(exchange.ErrorCode, Is.EqualTo(RawNtsKeErrorCodes.BadRequest), exchange.ToString());

    }


    /// <summary>
    /// A server that does not answer NTPv5 does not agree to it, draft named or not.
    /// </summary>
    [Test]
    public async Task AServerWithoutNTPv5_AgreesToNTPv4()
    {

        await using var withoutNTPv5 = await NornServerFixture.StartAsync();

        var exchange = await OverTls(withoutNTPv5,
                                     RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv5Draft, RawNtsKeNextProtocols.Ntpv4),
                                     RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                     DraftRecord(),
                                     RawNtsKeRecord.EndOfMessage());

        Assert.Multiple(() => {
            Assert.That(exchange.ErrorCode,       Is.Null,                                           $"an Error record\n{exchange}");
            Assert.That(NextProtocolOf(exchange), Is.EqualTo(new[] { RawNtsKeNextProtocols.Ntpv4 }), exchange.ToString());
        });

    }

    #endregion

    #region The keys (RFC 8915 § 5.1)

    /// <summary>
    /// RFC 8915 § 5.1: the context is "the Protocol ID of the next protocol", then the algorithm,
    /// then the direction - so NTPv5's begins with 0x8001. Written out as literals, against
    /// Norn's context and this suite's.
    /// </summary>
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_256, false, new Byte[] { 0x80, 0x01, 0x00, 0x0F, 0x00 })]
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_256, true,  new Byte[] { 0x80, 0x01, 0x00, 0x0F, 0x01 })]
    [TestCase(AEADAlgorithms.AES_128_GCM_SIV,  false, new Byte[] { 0x80, 0x01, 0x00, 0x1E, 0x00 })]
    [TestCase(AEADAlgorithms.AES_256_GCM_SIV,  true,  new Byte[] { 0x80, 0x01, 0x00, 0x1F, 0x01 })]
    public void TheContextOfNTPv5_BeginsWithItsProtocolId(AEADAlgorithms Algorithm, Boolean ServerToClient, Byte[] Expected)

        => Assert.Multiple(() => {

               Assert.That(NTSKE_ExportedKeys.Context(Algorithm, ServerToClient, RawNtsKeNextProtocols.Ntpv5Draft),
                           Is.EqualTo(Expected).AsCollection,
                           "Norn's");

               Assert.That(RawSshKeyBinding.Context((UInt16) Algorithm,
                                                    ServerToClient ? RawSshKeyBinding.S2C : RawSshKeyBinding.C2S,
                                                    RawNtsKeNextProtocols.Ntpv5Draft),
                           Is.EqualTo(Expected).AsCollection,
                           "the suite's");

           });


    /// <summary>
    /// The keys of a session of NTPv5 are those of its context, whichever method of the SSH Key
    /// Binding record they come from (section 5.4 of its specification, 1.1): a request under
    /// the C2S key derived here with 0x8001 is answered, and the answer opens under the S2C key
    /// derived the same way.
    /// </summary>
    [TestCase(15, RawSshKeyBinding.MethodTransportedSecret, TestName = "TheKeysOfAnNTPv5Session_AreThoseOfItsProtocolId_TransportedSecret_AesSivCmac256")]
    [TestCase(30, RawSshKeyBinding.MethodTransportedSecret, TestName = "TheKeysOfAnNTPv5Session_AreThoseOfItsProtocolId_TransportedSecret_Aes128GcmSiv")]
    [TestCase(31, RawSshKeyBinding.MethodTransportedSecret, TestName = "TheKeysOfAnNTPv5Session_AreThoseOfItsProtocolId_TransportedSecret_Aes256GcmSiv")]
    [TestCase(15, RawSshKeyBinding.MethodSshExporter,       TestName = "TheKeysOfAnNTPv5Session_AreThoseOfItsProtocolId_SshExporter_AesSivCmac256")]
    [TestCase(30, RawSshKeyBinding.MethodSshExporter,       TestName = "TheKeysOfAnNTPv5Session_AreThoseOfItsProtocolId_SshExporter_Aes128GcmSiv")]
    [TestCase(31, RawSshKeyBinding.MethodSshExporter,       TestName = "TheKeysOfAnNTPv5Session_AreThoseOfItsProtocolId_SshExporter_Aes256GcmSiv")]
    public async Task TheKeysOfAnNTPv5Session_AreThoseOfItsProtocolId(Int32 Aead, UInt16 Method)
    {

        var session  = await KeyExchange(Server, (UInt16) Aead, Method: Method);
        var verified = Verified(session, Send(Server, session), $"AEAD {Aead}, method 0x{Method:x4}");

        Assert.That(verified.Cookies, Is.Not.Empty, "a new cookie for the one spent");

    }


    /// <summary>
    /// The control: the keys of the same key exchange under NTPv4's context, 0x0000, are not
    /// taken. Without it, a server that took any key would pass the test above as well.
    /// </summary>
    [TestCase(RawSshKeyBinding.MethodTransportedSecret, TestName = "TheKeysOfNTPv4_DoNotAuthenticateAnNTPv5Session_TransportedSecret")]
    [TestCase(RawSshKeyBinding.MethodSshExporter,       TestName = "TheKeysOfNTPv4_DoNotAuthenticateAnNTPv5Session_SshExporter")]
    public async Task TheKeysOfNTPv4_DoNotAuthenticateAnNTPv5Session(UInt16 Method)
    {

        var session = await KeyExchange(Server, ContextProtocol: RawNtsKeNextProtocols.Ntpv4, Method: Method);

        Assert.That(Send(Server, session, Timeout: Silence).Response, Is.Null,
                    $"method 0x{Method:x4}: a request under keys of NTPv4's context was answered");

    }


    /// <summary>
    /// And the cookies of either method are good for NTPv5 alone: the NTPv4 request of the same
    /// session draws an NTS NAK (RFC 8915 § 5.7), as a cookie of the Transported Secret does.
    /// </summary>
    [Test]
    public async Task ACookieOfTheSshExporter_ForNTPv5_IsAnNtsNakInNTPv4()
    {

        var session = await KeyExchange(Server, Method: RawSshKeyBinding.MethodSshExporter);
        var reply   = RawNtpExchange.TryExchange(RawNtsExtensionFields.BuildNtsRequest(session.C2SKey, session.Cookies[0]),
                                                 "127.0.0.1",
                                                 Server.NTPPort);

        Assert.That(reply,           Is.Not.Null,         "no answer at all");
        Assert.That(reply!.KissCode, Is.EqualTo("NTSN"), reply.ToString());

    }

    #endregion

    #region The response (RFC 8915 § 5.7, draft § 10)

    /// <summary>
    /// RFC 8915 § 5.7: the response "MUST include a Unique Identifier ... whose value is the same
    /// as the one in the request", and an authenticator over everything before it. And draft
    /// § 10: a response of the server's mode, the client cookie copied, a time that is set.
    /// </summary>
    [Test]
    public async Task TheResponse_IsAuthenticated_AndEchoesTheUniqueIdentifier()
    {

        var session   = await KeyExchange(Server);
        var request   = RawNtpV5Packet.ClientRequest();
        var verified  = Verified(session, Send(Server, session, request), "the request");
        var response  = verified.Packet;

        Assert.Multiple(() => {
            Assert.That(response.Version,                         Is.EqualTo(5),                    "the version");
            Assert.That(response.Mode,                            Is.EqualTo(4),                    "the mode of a response");
            Assert.That(response.ClientCookie,                    Is.EqualTo(request.ClientCookie), "§ 6: the client cookie is copied");
            Assert.That(response.Stratum,                         Is.Not.Zero,                      "an authenticated response is no NAK");
            Assert.That(response.Flags & RawNtpV5Draft.AuthenticationNAK, Is.Zero,                  "no Authentication NAK flag");
            Assert.That(response.TransmitTimestamp,               Is.Not.Zero,                      "a time to synchronize to");
            Assert.That(verified.AuthenticatorIndex,              Is.EqualTo(response.ExtensionFields.Count - 1),
                        "the authenticator is the last field where nothing goes after it");
            Assert.That(response.ExtensionFields.Take(verified.AuthenticatorIndex).Select(field => field.Type),
                        Has.No.Member(RawNtpV5Nts.NtsCookie),
                        "RFC 8915 § 5.7: new cookies go inside the authenticator, not in the clear");
        });

    }


    /// <summary>
    /// RFC 8915 § 5.7: the server "SHOULD include ... one cookie for the one spent plus one for
    /// each placeholder" - which fits, since each placeholder is as long as a cookie and an
    /// NTPv5 response must not be longer than its request (§ 10 step 5).
    /// </summary>
    [TestCase(0, 1)]
    [TestCase(1, 2)]
    [TestCase(3, 4)]
    public async Task EachPlaceholder_DrawsOneCookieMore(Int32 Placeholders, Int32 Cookies)
    {

        var session  = await KeyExchange(Server);
        var verified = Verified(session, Send(Server, session, Placeholders: Placeholders), $"{Placeholders} placeholder(s)");

        Assert.That(verified.Cookies, Has.Count.EqualTo(Cookies));

    }


    /// <summary>
    /// RFC 8915 § 5.5: a placeholder's "body MUST be the same length as the body of the NTS
    /// Cookie", and Norn counts one that is not as no placeholder at all. A shorter one would
    /// leave no room for a cookie anyway; a longer one would, and is the case that shows it.
    /// </summary>
    [TestCase(-4, TestName = "APlaceholderShorterThanTheCookie_DrawsNone")]
    [TestCase( 4, TestName = "APlaceholderLongerThanTheCookie_DrawsNone")]
    [TestCase(64, TestName = "APlaceholderMuchLongerThanTheCookie_DrawsNone")]
    public async Task APlaceholderOfAnotherLength_DrawsNone(Int32 LongerBy)
    {

        var session  = await KeyExchange(Server);
        var verified = Verified(session,
                                Send(Server, session, Placeholders: 1, PlaceholderLength: session.Cookies[0].Length + LongerBy),
                                $"a placeholder {LongerBy:+0;-0} octets longer than the cookie");

        Assert.That(verified.Cookies, Has.Count.EqualTo(1), "the one cookie for the one spent, none for the placeholder");

    }


    /// <summary>
    /// The cookies of a response are good for the next request, under the keys of the key
    /// exchange: RFC 8915 § 6 has the server seal the same keys into them.
    /// </summary>
    [Test]
    public async Task ACookieOfAResponse_IsGoodForTheNextRequest()
    {

        var session  = await KeyExchange(Server);
        var first    = Verified(session, Send(Server, session), "the first request");

        Assert.That(first.Cookies, Is.Not.Empty);

        Verified(session, Send(Server, session, Cookie: first.Cookies[0]), "the request with the cookie of the first response");

    }

    #endregion

    #region Failures: silence, or the Authentication NAK (draft § 6, § 7.3)

    public enum Defect
    {
        BrokenAuthenticator,
        ShortUniqueIdentifier,
        NoUniqueIdentifier,
        TwoCookies,
        TwoAuthenticators,
        UniqueIdentifierAfterTheAuthenticator,
        CookieOfAnotherServer
    }


    /// <summary>
    /// A request whose NTS fails, built by hand: RFC 8915 § 5.7's "exactly one" and "at least 32
    /// octets", an authenticator that does not verify, a cookie this server did not seal.
    /// </summary>
    private static Byte[] Defective(Session Session, Defect Defect, UInt16 Flags = 0)
    {

        var request  = RawNtpV5Packet.ClientRequest(Flags: Flags);
        var cookie   = Session.Cookies[0];

        RawNtpV5ExtensionField Uid(Int32 Length = RawNtpV5Nts.MinimumUniqueIdentifierLength)
            => new (RawNtpV5Nts.UniqueIdentifier, RandomNumberGenerator.GetBytes(Length));

        RawNtpV5ExtensionField Cookie(Byte[] Value)
            => new (RawNtpV5Nts.NtsCookie, Value);

        switch (Defect)
        {

            case Defect.BrokenAuthenticator:
                return WithABrokenAuthenticator(RawNtpV5Nts.Request(request, Session.Aead, Session.C2SKey, cookie));

            case Defect.ShortUniqueIdentifier:
                request.ExtensionFields.AddRange([ Uid(31), Cookie(cookie) ]);
                break;

            case Defect.NoUniqueIdentifier:
                request.ExtensionFields.Add(Cookie(cookie));
                break;

            case Defect.TwoCookies:
                request.ExtensionFields.AddRange([ Uid(), Cookie(cookie), Cookie(Session.Cookies.Count > 1 ? Session.Cookies[1] : cookie) ]);
                break;

            case Defect.CookieOfAnotherServer:
                request.ExtensionFields.AddRange([ Uid(), Cookie(RandomNumberGenerator.GetBytes(cookie.Length)) ]);
                break;

            case Defect.TwoAuthenticators:
                request.ExtensionFields.AddRange([ Uid(), Cookie(cookie) ]);
                request.ExtensionFields.Add(RawNtpV5Nts.Authenticator(Session.Aead, Session.C2SKey, request.Write()));
                request.ExtensionFields.Add(RawNtpV5Nts.Authenticator(Session.Aead, Session.C2SKey, request.Write()));
                return request.Write();

            case Defect.UniqueIdentifierAfterTheAuthenticator:
                request.ExtensionFields.Add(Cookie(cookie));
                request.ExtensionFields.Add(RawNtpV5Nts.Authenticator(Session.Aead, Session.C2SKey, request.Write()));
                request.ExtensionFields.Add(Uid());
                return request.Write();

        }

        request.ExtensionFields.Add(RawNtpV5Nts.Authenticator(Session.Aead, Session.C2SKey, request.Write()));

        return request.Write();

    }


    /// <summary>
    /// A request whose NTS fails and that did not ask to hear of it gets nothing: answering it
    /// in plain would hand an unauthenticated time to a client that asked for the other, and
    /// the draft's § 6 has the server tell of a failure only by the Authentication NAK flag.
    /// </summary>
    [TestCase(Defect.BrokenAuthenticator)]
    [TestCase(Defect.ShortUniqueIdentifier)]
    [TestCase(Defect.NoUniqueIdentifier)]
    [TestCase(Defect.TwoCookies)]
    [TestCase(Defect.TwoAuthenticators)]
    [TestCase(Defect.UniqueIdentifierAfterTheAuthenticator)]
    [TestCase(Defect.CookieOfAnotherServer)]
    public async Task AFailedRequest_NotAskingForANak_GetsNothing(Defect Defect)
    {

        var session = await KeyExchange(Server);

        Assert.That(RawUdpExchange.TryExchange(Defective(session, Defect), "127.0.0.1", Server.NTPPort, Silence),
                    Is.Null,
                    $"{Defect}: a request whose NTS failed was answered");

    }


    /// <summary>
    /// § 6: the Authentication NAK flag in a response says the request "failed authentication",
    /// and § 7.3 has a client set it in a request to ask for it. Such a response carries nothing
    /// to synchronize to: stratum 0, no timestamps, and no authenticator, since there is no key
    /// to make one with - only the Unique Identifier back, so that the client knows what it
    /// answers. It is as long as the request, as every response is (§ 10 step 5).
    /// </summary>
    [TestCase(Defect.BrokenAuthenticator)]
    [TestCase(Defect.CookieOfAnotherServer)]
    public async Task AFailedRequest_AskingForANak_GetsTheAuthenticationNak(Defect Defect)
    {

        var session  = await KeyExchange(Server);
        var request  = Defective(session, Defect, RawNtpV5Draft.AuthenticationNAK);
        var octets   = RawUdpExchange.TryExchange(request, "127.0.0.1", Server.NTPPort);

        Assert.That(octets, Is.Not.Null, $"{Defect}: no NAK");
        Assert.That(RawNtpV5Packet.TryRead(octets!, out var response, out var error), Is.True, error);
        Assert.That(RawNtpV5Packet.TryRead(request, out var sent,     out var sentError), Is.True, sentError);

        Assert.Multiple(() => {
            Assert.That(response!.Flags,             Is.EqualTo(RawNtpV5Draft.AuthenticationNAK), "the Authentication NAK flag, and no other");
            Assert.That(response.Stratum,            Is.Zero,                                     "stratum 0");
            Assert.That(response.ReceiveTimestamp,   Is.Zero,                                     "no receive timestamp");
            Assert.That(response.TransmitTimestamp,  Is.Zero,                                     "no transmit timestamp");
            Assert.That(response.ClientCookie,       Is.EqualTo(sent!.ClientCookie),              "§ 6: the client cookie is copied");
            Assert.That(octets!.Length,              Is.EqualTo(request.Length),                  "§ 10 step 5: as long as the request");
            Assert.That(response.Find(RawNtpV5Nts.NtsAuthenticator), Is.Null,                     "no authenticator");
            Assert.That(response.Find(RawNtpV5Nts.UniqueIdentifier)?.Data,
                        Is.EqualTo(sent.Find(RawNtpV5Nts.UniqueIdentifier)!.Data),                "the Unique Identifier back");
        });

    }


    /// <summary>
    /// The flag asks to hear of a failure, and a request that does not fail is answered as any:
    /// authenticated, the flag not set.
    /// </summary>
    [Test]
    public async Task AGoodRequest_AskingForANak_IsAnsweredAsAny()
    {

        var session  = await KeyExchange(Server);
        var verified = Verified(session,
                                Send(Server, session, RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.AuthenticationNAK)),
                                "a good request with the flag");

        Assert.That(verified.Packet.Flags & RawNtpV5Draft.AuthenticationNAK, Is.Zero);

    }


    /// <summary>
    /// The cookie of an NTPv4 key exchange in an NTPv5 request: its keys come from NTPv4's
    /// exporter context and are no keys of NTPv5, so the request fails - silently, or with the
    /// NAK where it asked for one.
    /// </summary>
    [Test]
    public async Task AnNTPv4Cookie_InAnNTPv5Request_IsNotTaken()
    {

        var session = await KeyExchange(Server, NextProtocol: RawNtsKeNextProtocols.Ntpv4);

        Assert.That(Send(Server, session, Timeout: Silence).Response, Is.Null,
                    "an NTPv5 request with an NTPv4 cookie was answered");

        var (_, _, nak) = Send(Server, session, RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.AuthenticationNAK));

        Assert.That(nak, Is.Not.Null, "no NAK for an NTPv4 cookie");
        Assert.That(RawNtpV5Packet.TryRead(nak!, out var response, out var error), Is.True, error);
        Assert.That(response!.Flags, Is.EqualTo(RawNtpV5Draft.AuthenticationNAK));

    }


    /// <summary>
    /// And the other way round: the cookie of an NTPv5 key exchange in an NTPv4 request, under
    /// NTPv5's keys, which NTPv4 does not have. RFC 8915 § 5.7 has the server answer a cookie it
    /// cannot use with an NTS NAK, kiss code NTSN.
    /// </summary>
    [Test]
    public async Task AnNTPv5Cookie_InAnNTPv4Request_IsAnNtsNak()
    {

        var session = await KeyExchange(Server);
        var request = RawNtsExtensionFields.BuildNtsRequest(session.C2SKey, session.Cookies[0]);
        var reply   = RawNtpExchange.TryExchange(request, "127.0.0.1", Server.NTPPort);

        Assert.That(reply, Is.Not.Null, "no answer at all");

        Assert.Multiple(() => {
            Assert.That(reply!.IsKissOfDeath, Is.True,             reply.ToString());
            Assert.That(reply.KissCode,       Is.EqualTo("NTSN"),  reply.ToString());
            Assert.That(reply.FirstFieldOfType(RawExtensionFieldTypes.NTSAuthenticatorAndEncrypted), Is.Null,
                        "an NTS NAK carries no authenticator");
        });

    }

    #endregion

    #region Fields after the authenticator

    /// <summary>
    /// § 7.7: the Correction is changed by the devices on the way, and so can never be
    /// authenticated. After the authenticator of a request it is answered all the same, after
    /// the authenticator of the response and last, the request's Delay Correction and Path ID
    /// going back as the Origin ones.
    /// </summary>
    [Test]
    public async Task ACorrectionAfterTheAuthenticator_IsAnsweredAfterTheResponsesAuthenticator()
    {

        var session   = await KeyExchange(Server);
        var verified  = Verified(session,
                                 Send(Server, session, AfterAuthenticator: [ RawNtpV5Fields.Correction(DelayCorrection: 4242, DelayPathId: 7) ]),
                                 "a request with a Correction after its authenticator");

        var fields     = verified.Packet.ExtensionFields;
        var correction = fields.LastOrDefault();

        Assert.That(correction?.Type, Is.EqualTo(RawNtpV5Draft.Correction), "the Correction is the last field");

        var (origin, originPathId, _, _, _) = RawNtpV5Fields.ReadCorrection(correction!);

        Assert.Multiple(() => {
            Assert.That(fields.Count - 1,  Is.GreaterThan(verified.AuthenticatorIndex), "after the authenticator");
            Assert.That(origin,            Is.EqualTo(4242));
            Assert.That(originPathId,      Is.EqualTo((UInt16) 7));
        });

    }


    /// <summary>
    /// Any other field after the authenticator could have been put there by anyone on the way,
    /// and Norn does not answer it: a Server Information request after the authenticator draws
    /// no Server Information, and the response is still as long as the request.
    /// </summary>
    [Test]
    public async Task AnotherFieldAfterTheAuthenticator_IsNotAnswered()
    {

        var session   = await KeyExchange(Server);
        var verified  = Verified(session,
                                 Send(Server, session, AfterAuthenticator: [ RawNtpV5ExtensionField.ServerInformationRequest() ]),
                                 "a request with Server Information after its authenticator");

        Assert.That(verified.Packet.Find(RawNtpV5Draft.ServerInformation), Is.Null,
                    "an unauthenticated request was answered");

    }


    /// <summary>
    /// And the same field before the authenticator is answered, inside what the response's
    /// authenticator covers: the control of the test above.
    /// </summary>
    [Test]
    public async Task TheSameFieldBeforeTheAuthenticator_IsAnswered()
    {

        var session = await KeyExchange(Server);
        var request = RawNtpV5Packet.ClientRequest();

        request.ExtensionFields.Add(RawNtpV5ExtensionField.ServerInformationRequest());

        var verified = Verified(session, Send(Server, session, request), "a request with Server Information before its authenticator");
        var index    = verified.Packet.ExtensionFields.FindIndex(field => field.Type == RawNtpV5Draft.ServerInformation);

        Assert.Multiple(() => {
            Assert.That(index, Is.Not.Negative,                             "no Server Information");
            Assert.That(index, Is.LessThan(verified.AuthenticatorIndex),    "outside what the authenticator covers");
        });

    }

    #endregion

    #region A server of NTS alone, and the interleaved mode for NTS alone

    /// <summary>
    /// A server of NTS alone ignores a plain NTPv5 request, and answers one of NTS.
    /// </summary>
    [Test]
    public async Task AServerOfNtsAlone_AnswersNtsAndNothingElse()
    {

        await using var ntsAlone = await NornServerFixture.StartAsync(ntpv5:         NTPv5Support.Draft,
                                                                      plainNtp:      false,
                                                                      sshClientKey:  ClientKey);

        Assert.That(RawUdpExchange.TryExchange(RawNtpV5Packet.ClientRequest().Write(), "127.0.0.1", ntsAlone.NTPPort, Silence),
                    Is.Null,
                    "a plain request was answered");

        var session = await KeyExchange(ntsAlone);

        Verified(session, Send(ntsAlone, session), "a request of NTS");

    }


    /// <summary>
    /// Under <see cref="InterleavedModePolicy.AuthenticatedOnly"/> the interleaved mode is
    /// served to requests of NTS alone: draft § 10 sets the Server Cookie where the mode is
    /// "requested and supported", and here it is supported for the one and not for the other.
    /// </summary>
    [Test]
    public async Task UnderAuthenticatedOnly_TheInterleavedModeIsForNtsAlone()
    {

        await using var server = await NornServerFixture.StartAsync(ntpv5:            NTPv5Support.Draft,
                                                                    interleavedMode:  InterleavedModePolicy.AuthenticatedOnly,
                                                                    sshClientKey:     ClientKey);

        var plain = RawUdpExchange.TryExchange(RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.InterleavedMode).Write(), "127.0.0.1", server.NTPPort);

        Assert.That(plain, Is.Not.Null, "the plain request was not answered");
        Assert.That(RawNtpV5Packet.TryRead(plain!, out var plainResponse, out var error), Is.True, error);

        var session  = await KeyExchange(server);
        var verified = Verified(session,
                                Send(server, session, RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.InterleavedMode)),
                                "the request of NTS");

        Assert.Multiple(() => {
            Assert.That(plainResponse!.ServerCookie, Is.Zero,    "a plain request was offered the interleaved mode");
            Assert.That(verified.Packet.ServerCookie, Is.Not.Zero, "a request of NTS was not offered the interleaved mode");
        });

    }

    #endregion

}
