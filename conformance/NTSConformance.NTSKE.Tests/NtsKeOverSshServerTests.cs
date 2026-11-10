using System.Security.Cryptography;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// What Norn's NTS-KE server must do over SSH with the SSH Key Binding record — Sections 3.4,
/// 4.1 and 5.1 of its specification, version 1.0
/// (https://github.com/OpenChargingTechnology/Whitepapers/blob/master/NTS-over-SSH/nts-ke-ssh-key-binding.md).
///
/// <para>
/// Every request is written by this suite's own codec and sent in the NTS-KE subsystem of an SSH
/// connection to the server's SSH listener (<see cref="RawNtsKeOverSsh"/>), so a test can send
/// what no conformant client would: a body its entries do not fill, data where a method takes
/// none, two records, or none.
/// </para>
/// <para>
/// Rule 6 is the one a client cannot see in the response: that the keys sealed into the cookies
/// are those Section 5 derives for the selected method. So the cookie is spent — an NTS request
/// under the C2S key this suite derives with <see cref="RawSshKeyBinding"/>, whose answer must be
/// authenticated under the S2C key. AES-SIV-CMAC-256 is this suite's own; for the GCM-SIV
/// algorithms the primitive is Norn's, checked against RFC 8452 in <c>AesGcmSivConformanceTests</c>,
/// and what is under test here is only the key. For method 0x0001 the keys come from the
/// exporter of the client end of the connection, which is Hermod's on both ends; that exporter
/// is held to the specification in <c>SshKeyBindingConformanceTests</c>.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsKeOverSshServerTests
{

    private const Int32 MethodDataLength = 32;

    private static readonly ISshHostKey ClientKey = SshHostKey.GenerateEd25519();

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(aeadAlgorithms:  NTSAEAD.Implemented,
                                                        sshClientKey:    ClientKey);

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    #region (private) helpers

    /// <summary>
    /// A request for NTPv4 and the given AEAD algorithm, with the given SSH Key Binding record —
    /// or none — and any further records before End of Message.
    /// </summary>
    private static Byte[] Request(RawNtsKeRecord?          keyBinding,
                                  UInt16                   aeadAlgorithm = 15,
                                  params RawNtsKeRecord[]  extra)

        => RawNtsKeCodec.Encode([
               RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
               RawNtsKeRecord.AeadAlgorithmNegotiation(aeadAlgorithm),
               .. extra,
               .. (keyBinding is null ? Array.Empty<RawNtsKeRecord>() : [ keyBinding ]),
               RawNtsKeRecord.EndOfMessage()
           ]);


    /// <summary>
    /// A request whose SSH Key Binding record has the body given in hex.
    /// </summary>
    private static Byte[] RequestWithBody(String bodyHex)
        => Request(RawNtsKeRecord.SshKeyBinding(Bytes.FromHex(bodyHex)));


    /// <summary>
    /// One exchange on a connection of its own.
    /// </summary>
    private async Task<RawNtsKeExchange> ExchangeAsync(Byte[] request)
    {
        await using var sshClient = await fixture!.ConnectSshAsync(ClientKey);
        return await RawNtsKeOverSsh.ExchangeAsync(sshClient, request);
    }


    /// <summary>
    /// The method and data the server selected, from the one SSH Key Binding record a response
    /// without an Error record must carry (Section 3.4) — critical, as Section 3.1 has it.
    /// </summary>
    private static (UInt16 MethodId, Byte[] Data) SelectionOf(RawNtsKeExchange exchange)
    {

        Assert.That(exchange.Records,   Is.Not.Null, exchange.ToString());
        Assert.That(exchange.ErrorCode, Is.Null,     $"an Error record{Environment.NewLine}{exchange}");

        var keyBindings = exchange.RecordsOfType(RawNtsKeRecordTypes.SshKeyBinding).ToArray();

        Assert.That(keyBindings,               Has.Length.EqualTo(1),          $"SSH Key Binding records in the response{Environment.NewLine}{exchange}");
        Assert.That(keyBindings[0].IsCritical, Is.True,                        $"the Critical Bit of the SSH Key Binding record{Environment.NewLine}{exchange}");
        Assert.That(keyBindings[0].Body,       Has.Length.GreaterThanOrEqualTo(2), exchange.ToString());

        var body = keyBindings[0].Body;

        return ((UInt16) ((body[0] << 8) | body[1]), body[2..]);

    }


    /// <summary>
    /// Error code 1, and nothing of a successful response: no SSH Key Binding record (Section
    /// 3.4) and no cookie.
    /// </summary>
    private static void AssertBadRequest(RawNtsKeExchange exchange, String because)

        => Assert.Multiple(() => {

               Assert.That(exchange.ErrorCode,
                           Is.EqualTo(RawNtsKeErrorCodes.BadRequest),
                           $"{because}{Environment.NewLine}{exchange}");

               Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.SshKeyBinding),
                           Is.Empty,
                           $"{because}: an error response carries no SSH Key Binding record{Environment.NewLine}{exchange}");

               Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4),
                           Is.Empty,
                           $"{because}: and no cookie{Environment.NewLine}{exchange}");

           });

    #endregion


    #region Section 3.4 — the response

    /// <summary>
    /// A request offering one method gets a response with one critical SSH Key Binding record:
    /// that method, and its 32 octets of data — the exporter_nonce of method 0x0001, the
    /// nts_ke_secret of 0x0002 — and cookies with it.
    /// </summary>
    [TestCase(RawSshKeyBinding.MethodSshExporter,       TestName = "AResponse_SelectingTheSshExporter_CarriesItsNonce")]
    [TestCase(RawSshKeyBinding.MethodTransportedSecret, TestName = "AResponse_SelectingTheTransportedSecret_CarriesTheSecret")]
    public async Task AResponse_CarriesTheSelectedMethodAndItsData(UInt16 methodId)
    {

        var exchange = await ExchangeAsync(Request(RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(methodId))));

        var (selected, data) = SelectionOf(exchange);

        Assert.Multiple(() => {
            Assert.That(selected,    Is.EqualTo(methodId),                 exchange.ToString());
            Assert.That(data,        Has.Length.EqualTo(MethodDataLength), exchange.ToString());
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4), Is.Not.Empty, exchange.ToString());
        });

    }

    #endregion

    #region Section 4.1, rule 1 — exactly one record, with entries that fill its body

    /// <summary>
    /// A request over SSH must carry the record: without it the server has no method to take
    /// the keys from, and a TLS exporter it does not have.
    /// </summary>
    [Test]
    public async Task ARequestWithoutAnSshKeyBinding_IsABadRequest()
        => AssertBadRequest(await ExchangeAsync(Request(keyBinding: null)),
                            "a request over SSH without an SSH Key Binding record");


    /// <summary>
    /// Exactly one: two records, even two that agree, are a Bad Request.
    /// </summary>
    [Test]
    public async Task ARequestWithTwoSshKeyBindings_IsABadRequest()
        => AssertBadRequest(await ExchangeAsync(Request(RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(RawSshKeyBinding.MethodTransportedSecret)),
                                                        15,
                                                        RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(RawSshKeyBinding.MethodTransportedSecret)))),
                            "a request with two SSH Key Binding records");


    /// <summary>
    /// A body with no entry, or whose entries do not fill it exactly.
    /// </summary>
    [TestCase("",                                  TestName = "AKeyBinding_WithoutAnEntry_IsABadRequest")]
    [TestCase("0002",                              TestName = "AKeyBinding_WithHalfAnEntryHeader_IsABadRequest")]
    [TestCase("00020000" + "00",                   TestName = "AKeyBinding_WithOneOctetAfterItsEntries_IsABadRequest")]
    [TestCase("00020000" + "000000",               TestName = "AKeyBinding_WithThreeOctetsAfterItsEntries_IsABadRequest")]
    [TestCase("80010005" + "abcd",                 TestName = "AKeyBinding_WhoseOnlyEntrySaysMoreDataThanItHas_IsABadRequest")]
    [TestCase("00020000" + "80010003" + "abcd",    TestName = "AKeyBinding_WhoseLastEntrySaysMoreDataThanItHas_IsABadRequest")]
    public async Task AKeyBindingWhoseEntriesDoNotFillItsBody_IsABadRequest(String bodyHex)
        => AssertBadRequest(await ExchangeAsync(RequestWithBody(bodyHex)),
                            $"the SSH Key Binding body {(bodyHex.Length == 0 ? "(empty)" : bodyHex)}");

    #endregion

    #region Section 4.1, rules 2 and 4 — the first method the server supports, unknown ones skipped

    /// <summary>
    /// The server selects the first method of the client's list it supports — the client's
    /// order decides, not the server's preference.
    /// </summary>
    [TestCase("00010000" + "00020000", RawSshKeyBinding.MethodSshExporter,       TestName = "TheSshExporterFirst_GetsTheSshExporter")]
    [TestCase("00020000" + "00010000", RawSshKeyBinding.MethodTransportedSecret, TestName = "TheTransportedSecretFirst_GetsTheTransportedSecret")]
    public async Task TheFirstMethodOfTheList_IsSelected(String bodyHex, UInt16 expectedMethodId)
    {

        var exchange      = await ExchangeAsync(RequestWithBody(bodyHex));
        var (selected, _) = SelectionOf(exchange);

        Assert.That(selected, Is.EqualTo(expectedMethodId), $"body {bodyHex}{Environment.NewLine}{exchange}");

    }


    /// <summary>
    /// An entry of a method the server does not know is skipped by its Data Length, data and
    /// all, and is not an error. The third case is the one that tells skipping from reading on:
    /// its data are the four octets of an entry for method 0x0001, so a server that read them as
    /// an entry would select the SSH Exporter.
    /// </summary>
    [TestCase("80010002" + "abcd"     + "00020000",              RawSshKeyBinding.MethodTransportedSecret, TestName = "APrivateMethodWithData_IsSkipped_AsInAppendixB")]
    [TestCase("00030003" + "010203"   + "00010000",              RawSshKeyBinding.MethodSshExporter,       TestName = "AnUnassignedMethodWithAnOddLengthOfData_IsSkipped")]
    [TestCase("80010004" + "00010000" + "00020000",              RawSshKeyBinding.MethodTransportedSecret, TestName = "DataThatReadAsAnEntry_AreSkippedAsData")]
    [TestCase("fffe0000"              + "00020000",              RawSshKeyBinding.MethodTransportedSecret, TestName = "APrivateMethodWithoutData_IsSkipped")]
    public async Task AnEntryOfAnUnknownMethod_IsSkippedByItsDataLength(String bodyHex, UInt16 expectedMethodId)
    {

        var exchange      = await ExchangeAsync(RequestWithBody(bodyHex));
        var (selected, _) = SelectionOf(exchange);

        Assert.That(selected, Is.EqualTo(expectedMethodId), $"body {bodyHex}{Environment.NewLine}{exchange}");

    }


    /// <summary>
    /// A request none of whose methods the server supports is a Bad Request — not an exchange
    /// with keys from nowhere.
    /// </summary>
    [TestCase("00030000" + "7fff0001" + "42", TestName = "OnlyUnassignedMethods_AreABadRequest")]
    [TestCase("80010000",                     TestName = "OnlyAPrivateMethod_IsABadRequest")]
    public async Task ARequestOfNoMethodTheServerSupports_IsABadRequest(String bodyHex)
        => AssertBadRequest(await ExchangeAsync(RequestWithBody(bodyHex)),
                            $"the SSH Key Binding body {bodyHex}");

    #endregion

    #region Section 4.1, rule 3 — methods 0x0001 and 0x0002 take no data

    /// <summary>
    /// An entry for method 0x0001 or 0x0002 with data is a Bad Request, wherever it stands in
    /// the list — also after the entry the server would otherwise have selected.
    /// </summary>
    [TestCase("00020002" + "aabb",                   TestName = "TheTransportedSecretWithData_IsABadRequest")]
    [TestCase("00010001" + "ff"   + "00020000",      TestName = "TheSshExporterWithData_IsABadRequest")]
    [TestCase("00020000" + "00010001" + "ff",        TestName = "TheSshExporterWithData_AfterTheTransportedSecret_IsABadRequest")]
    [TestCase("80010000" + "00020001" + "ff",        TestName = "TheTransportedSecretWithData_AfterAnUnknownMethod_IsABadRequest")]
    public async Task DataForMethod1Or2_IsABadRequest(String bodyHex)
        => AssertBadRequest(await ExchangeAsync(RequestWithBody(bodyHex)),
                            $"the SSH Key Binding body {bodyHex}");

    #endregion

    #region Section 4.1, rule 5 — new data for every exchange

    /// <summary>
    /// The Method Data is drawn anew for every exchange — here four on one connection, where
    /// for method 0x0001 the nonce is all that keeps their keys apart (Section 4.3).
    /// </summary>
    [TestCase(RawSshKeyBinding.MethodSshExporter,       TestName = "EveryExchangeOnAConnection_GetsANonceOfItsOwn")]
    [TestCase(RawSshKeyBinding.MethodTransportedSecret, TestName = "EveryExchangeOnAConnection_GetsASecretOfItsOwn")]
    public async Task EveryExchange_GetsMethodDataOfItsOwn(UInt16 methodId)
    {

        await using var sshClient = await fixture!.ConnectSshAsync(ClientKey);

        var data = new List<String>();

        for (var i = 0; i < 4; i++)
        {

            var exchange      = await RawNtsKeOverSsh.ExchangeAsync(sshClient, Request(RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(methodId))));
            var (selected, d) = SelectionOf(exchange);

            Assert.That(selected, Is.EqualTo(methodId), exchange.ToString());

            data.Add(Bytes.ToHex(d));

        }

        Assert.That(data, Is.Unique, String.Join(Environment.NewLine, data));

    }

    #endregion

    #region Section 4.1, rule 6, and Section 5.1 — the keys of the cookies

    /// <summary>
    /// The keys the server seals into its cookies are those Section 5 derives for the selected
    /// method and the negotiated algorithm: a request under the C2S key derived here is answered,
    /// and the answer is authenticated under the S2C key derived here.
    ///
    /// With record 1024, "Compliant AES-128-GCM-SIV Exporter Context", in the request as well,
    /// which has no meaning over SSH (Section 5.1): the server must not echo it, and the
    /// context stays the Numeric Identifier of the negotiated algorithm — which for
    /// AES-128-GCM-SIV it would be anyway with the record over TLS, so the cases without it are
    /// the ones that show the server does not fall back to chrony's 15 when it is missing.
    /// </summary>
    [TestCase(RawSshKeyBinding.MethodTransportedSecret, 15, false, TestName = "TheCookieKeys_OfTheTransportedSecret_AesSivCmac256")]
    [TestCase(RawSshKeyBinding.MethodTransportedSecret, 30, false, TestName = "TheCookieKeys_OfTheTransportedSecret_Aes128GcmSiv")]
    [TestCase(RawSshKeyBinding.MethodTransportedSecret, 30, true,  TestName = "TheCookieKeys_OfTheTransportedSecret_Aes128GcmSiv_WithRecord1024")]
    [TestCase(RawSshKeyBinding.MethodTransportedSecret, 31, false, TestName = "TheCookieKeys_OfTheTransportedSecret_Aes256GcmSiv")]
    [TestCase(RawSshKeyBinding.MethodSshExporter,       15, false, TestName = "TheCookieKeys_OfTheSshExporter_AesSivCmac256")]
    [TestCase(RawSshKeyBinding.MethodSshExporter,       30, false, TestName = "TheCookieKeys_OfTheSshExporter_Aes128GcmSiv")]
    [TestCase(RawSshKeyBinding.MethodSshExporter,       30, true,  TestName = "TheCookieKeys_OfTheSshExporter_Aes128GcmSiv_WithRecord1024")]
    public async Task TheKeysOfTheCookies_AreThoseOfSection5(UInt16 methodId, Int32 aead, Boolean withRecord1024)
    {

        var aeadAlgorithm = (UInt16) aead;
        var keyLength     = aead == 30 ? 16 : 32;

        await using var sshClient = await fixture!.ConnectSshAsync(ClientKey);

        var exchange = await RawNtsKeOverSsh.ExchangeAsync(
                           sshClient,
                           Request(RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(methodId)),
                                   aeadAlgorithm,
                                   withRecord1024
                                       ? [ RawNtsKeRecord.CompliantAes128GcmSivExporterContext() ]
                                       : [])
                       );

        var (selected, data) = SelectionOf(exchange);

        var agreed  = exchange.FirstRecordOfType(RawNtsKeRecordTypes.AeadAlgorithmNegotiation);
        var cookie  = exchange.FirstRecordOfType(RawNtsKeRecordTypes.NewCookieForNtpv4);

        Assert.Multiple(() => {
            Assert.That(selected, Is.EqualTo(methodId), exchange.ToString());
            Assert.That(agreed is null ? null : RawNtsKeCodec.ReadUInt16Body(agreed), Is.EqualTo(new[] { aeadAlgorithm }), $"the agreed AEAD algorithm{Environment.NewLine}{exchange}");
            Assert.That(cookie, Is.Not.Null, $"a cookie{Environment.NewLine}{exchange}");
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext), Is.Empty,
                        $"record 1024 echoed over SSH{Environment.NewLine}{exchange}");
        });

        Byte[] KeyFor(Byte direction)
            => methodId == RawSshKeyBinding.MethodTransportedSecret
                   ? RawSshKeyBinding.TransportedSecretKey(data, aeadAlgorithm, direction, keyLength)
                   : sshClient.Exporter.Export(data,
                                               RawSshKeyBinding.ExporterLabel,
                                               RawSshKeyBinding.Context(aeadAlgorithm, direction),
                                               keyLength);

        Assert.That(TryAuthenticate(cookie!.Body,
                                    aeadAlgorithm,
                                    KeyFor(RawSshKeyBinding.C2S),
                                    KeyFor(RawSshKeyBinding.S2C),
                                    out var diagnosis),
                    Is.True,
                    $"method 0x{methodId:x4}, AEAD {aead}{(withRecord1024 ? ", record 1024 sent" : "")}: {diagnosis}");

    }


    /// <summary>
    /// The control of <see cref="TheKeysOfTheCookies_AreThoseOfSection5"/>: keys derived with
    /// the context chrony writes for AES-128-GCM-SIV over TLS, 15 where the algorithm is 30, do
    /// not authenticate. Without it, a round trip that let anything through would pass the
    /// test above as well.
    /// </summary>
    [Test]
    public async Task TheCookieKeys_UnderChronysContext_DoNotAuthenticate()
    {

        var exchange = await ExchangeAsync(Request(RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(RawSshKeyBinding.MethodTransportedSecret)),
                                                   30));

        var (_, secret) = SelectionOf(exchange);
        var cookie      = exchange.FirstRecordOfType(RawNtsKeRecordTypes.NewCookieForNtpv4);

        Assert.That(cookie, Is.Not.Null, exchange.ToString());

        Assert.That(TryAuthenticate(cookie!.Body,
                                    30,
                                    RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.C2S, 16),
                                    RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.S2C, 16),
                                    out var diagnosis),
                    Is.False,
                    "keys under the context of algorithm 15 for a session on 30 were taken");

        Assert.That(diagnosis, Does.Contain("kiss").Or.Contain("did not answer").Or.Contain("not authenticated"), diagnosis);

    }


    /// <summary>
    /// Spend the cookie: an NTS request under <paramref name="c2sKey"/>, whose answer must carry
    /// an authenticator that opens under <paramref name="s2cKey"/>. A server that sealed other
    /// keys into the cookie answers with a NAK, or not at all.
    /// </summary>
    private Boolean TryAuthenticate(Byte[] cookie, UInt16 aeadAlgorithm, Byte[] c2sKey, Byte[] s2cKey, out String diagnosis)
    {

        var request = RawNtpPacket.ClientRequest();

        request.ExtensionFields.Add(RawNtsExtensionFields.RandomUniqueIdentifier());
        request.ExtensionFields.Add(RawNtsExtensionFields.NtsCookie(cookie));

        var nonce   = RandomNumberGenerator.GetBytes(aeadAlgorithm == 15 ? 16 : AES_GCM_SIV.NonceLength);

        request.ExtensionFields.Add(new RawExtensionField(
                                        RawExtensionFieldTypes.NTSAuthenticatorAndEncrypted,
                                        RawNtsExtensionFields.BuildAuthenticatorValue(
                                            nonce,
                                            Seal(aeadAlgorithm, c2sKey, RawNtsExtensionFields.AssociatedDataFor(request), nonce)
                                        )
                                    ));

        var reply         = RawNtpExchange.TryExchange(request, "127.0.0.1", fixture!.NTPPort, timeout: TimeSpan.FromSeconds(3));

        if (reply is null)
        {
            diagnosis = "the server did not answer the NTS request under the C2S key derived here";
            return false;
        }

        var authenticator = reply.FirstFieldOfType(RawExtensionFieldTypes.NTSAuthenticatorAndEncrypted);

        if (authenticator is null)
        {
            diagnosis = "the answer is not authenticated" +
                        (reply.Stratum == 0 ? $" — a kiss, {reply.KissCode}: the server did not take the C2S key derived here" : "");
            return false;
        }

        if (!RawNtsExtensionFields.TryParseAuthenticatorValue(authenticator.Value, out var replyNonce, out var ciphertext, out var parseError))
        {
            diagnosis = $"the authenticator of the answer cannot be read: {parseError}";
            return false;
        }

        if (!TryOpen(aeadAlgorithm, s2cKey, RawNtsExtensionFields.AssociatedDataFor(reply), replyNonce!, ciphertext!))
        {
            diagnosis = "the answer does not open under the S2C key derived here";
            return false;
        }

        diagnosis = "authenticated both ways";
        return true;

    }


    private static Byte[] Seal(UInt16 aeadAlgorithm, Byte[] key, Byte[] associatedData, Byte[] nonce)

        => aeadAlgorithm == 15
               ? new RawAesSiv(key).Encrypt([ associatedData ], nonce, [])
               : NTSAEAD.Create((AEADAlgorithms) aeadAlgorithm, key).Encrypt(associatedData, nonce, []);


    private static Boolean TryOpen(UInt16 aeadAlgorithm, Byte[] key, Byte[] associatedData, Byte[] nonce, Byte[] ciphertext)
    {

        if (aeadAlgorithm == 15)
            return new RawAesSiv(key).TryDecrypt([ associatedData ], nonce, ciphertext, out _, out _);

        try
        {
            NTSAEAD.Create((AEADAlgorithms) aeadAlgorithm, key).Decrypt(associatedData, nonce, ciphertext);
            return true;
        }
        catch (Exception)
        {
            return false;
        }

    }

    #endregion

    #region Section 4.1 — over TLS the record has no meaning

    /// <summary>
    /// Over TLS the keys come from the TLS exporter and nothing else (Section 6.5): the record is
    /// an unrecognized critical record there, Error code 0 — what every server that implements
    /// only RFC 8915 answers anyway. Sent through .NET's TLS, not Norn's.
    /// </summary>
    [Test]
    public async Task TheSshKeyBindingOverTls_IsAnUnrecognizedCriticalRecord()
    {

        var exchange = await RawNtsKeClient.ExchangeAsync("127.0.0.1",
                                                          fixture!.NTSKEPort,
                                                          Request(RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(RawSshKeyBinding.MethodTransportedSecret))));

        Assert.Multiple(() => {
            Assert.That(exchange.ErrorCode, Is.EqualTo(RawNtsKeErrorCodes.UnrecognizedCriticalRecord), exchange.ToString());
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.SshKeyBinding),     Is.Empty, exchange.ToString());
            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4), Is.Empty, exchange.ToString());
        });

    }

    #endregion

}
