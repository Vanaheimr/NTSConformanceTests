using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's NTS-KE client sends and accepts over SSH with the SSH Key Binding record —
/// Sections 3.3, 4.2 and 5 of its specification, version 1.0
/// (https://github.com/OpenChargingTechnology/Whitepapers/blob/master/NTS-over-SSH/nts-ke-ssh-key-binding.md).
///
/// <para>
/// The server is <see cref="ScriptedNtsKeOverSshServer"/>: Hermod's SSH server with a script in
/// the NTS-KE subsystem instead of Norn's key exchange. It keeps what the client sent, and answers
/// with octets this suite wrote — so a test can answer with what no conformant server would, and
/// compare the keys the client derived with those <see cref="RawSshKeyBinding"/> derives from the
/// same response.
/// </para>
/// <para>
/// Over TLS the record has no meaning, and the client must neither send it nor accept it; that
/// half runs against <see cref="ScriptedNtsKeServer"/> and .NET's TLS.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ClientNtsKeOverSshTests
{

    private const Int32 MethodDataLength = 32;


    #region (private) helpers

    /// <summary>
    /// The records of a response that is correct, with the given SSH Key Binding body, so a test
    /// can spoil exactly one thing.
    /// </summary>
    private static RawNtsKeRecord[] AGoodResponse(Byte[]?  keyBindingBody,
                                                  UInt16   aeadAlgorithm = 15)

        => [
               RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
               RawNtsKeRecord.AeadAlgorithmNegotiation(aeadAlgorithm),
               .. (keyBindingBody is null ? Array.Empty<RawNtsKeRecord>() : [ RawNtsKeRecord.SshKeyBinding(keyBindingBody) ]),
               RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
               RawNtsKeRecord.EndOfMessage()
           ];


    /// <summary>
    /// A response selecting the Transported Secret with a fresh secret.
    /// </summary>
    private static RawNtsKeRecord[] AGoodResponse()
        => AGoodResponse(RawSshKeyBinding.ResponseBody(RawSshKeyBinding.MethodTransportedSecret,
                                                       RandomNumberGenerator.GetBytes(MethodDataLength)));


    /// <summary>
    /// One key exchange of Norn's client over SSH against a server that answers with
    /// <paramref name="respond"/>; the server is handed back for what it received.
    /// </summary>
    private static async Task<(NTSKEResult Result, ScriptedNtsKeOverSshServer Server)>
        ExchangeAsync(Func<CapturedNtsKeOverSshRequest, Byte[]?>  respond,
                      Boolean                                     offerSshExporter  = true,
                      IEnumerable<AEADAlgorithms>?                aeadAlgorithms    = null,
                      Func<NTSKEResult, ScriptedNtsKeOverSshServer, Task>? whileConnected = null)
    {

        var server = await ScriptedNtsKeOverSshServer.StartAsync(respond);

        try
        {

            await using var sshClient = await server.ConnectAsync();

            var result = await new NTSClient(
                                   DomainName.Localhost,
                                   IPVersionPreference:    IPVersionPreference.IPv4Only,
                                   Timeout:                TimeSpan.FromSeconds(10),
                                   OfferedAEADAlgorithms:  aeadAlgorithms
                               ).GetNTSKERecordsOverSSH(sshClient,
                                                        OfferSSHExporter: offerSshExporter);

            if (whileConnected is not null)
                await whileConnected(result, server);

            return (result, server);

        }
        finally
        {
            await server.DisposeAsync();
        }

    }


    /// <summary>
    /// The client gave up, and for what the response says: not with the keys of a response it
    /// should not have used, not by blaming the server for an Error record it never sent, and
    /// not by a timeout or an exception that would pass this test for the wrong reason.
    /// </summary>
    private static void AssertAborted(NTSKEResult result, String because)

        => Assert.Multiple(() => {

               Assert.That(result.Success, Is.False, $"{because}: the client used the response");

               Assert.That(result.ErrorCategory,
                           Is.AnyOf(NTSKEErrorCategory.Protocol, NTSKEErrorCategory.MissingRequiredRecord),
                           $"{because}: refused, but as {result.ErrorCategory}: {result.ErrorMessage}");

           });

    #endregion


    #region Section 3.3 — the request

    /// <summary>
    /// Exactly one SSH Key Binding record, critical, whose entries fill its body, with Data
    /// Length 0 for methods 0x0001 and 0x0002, and 0x0002 among them. Where the client has the
    /// exporter of its connection it offers 0x0001 first, which is the first example of
    /// Appendix B; without it, 0x0002 alone.
    /// </summary>
    [TestCase(true,  "0001000000020000", TestName = "TheRequest_OffersTheSshExporterAndThenTheTransportedSecret")]
    [TestCase(false, "00020000",         TestName = "TheRequest_WithoutTheExporter_OffersTheTransportedSecretAlone")]
    public async Task TheRequest_CarriesOneCriticalKeyBinding(Boolean offerSshExporter, String expectedBodyHex)
    {

        var (_, server) = await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(AGoodResponse()), offerSshExporter);

        Assert.That(server.Requests, Has.Count.EqualTo(1));

        var request     = server.Requests[0];
        var keyBindings = request.RecordsOfType(RawNtsKeRecordTypes.SshKeyBinding).ToArray();

        Assert.That(request.Records, Is.Not.Null, request.DecodeError);
        Assert.That(keyBindings,     Has.Length.EqualTo(1), $"SSH Key Binding records in the request{Environment.NewLine}{Bytes.Dump(request.Bytes)}");

        Assert.That(RawSshKeyBinding.TryReadRequestBody(keyBindings[0].Body, out var entries, out var bodyError), Is.True, bodyError);

        Assert.Multiple(() => {

            Assert.That(keyBindings[0].IsCritical,        Is.True,                   "the Critical Bit of the SSH Key Binding record");
            Assert.That(Bytes.ToHex(keyBindings[0].Body), Is.EqualTo(expectedBodyHex), "the entries");

            Assert.That(entries!.Select(entry => entry.MethodId),
                        Does.Contain(RawSshKeyBinding.MethodTransportedSecret),
                        "the Transported Secret, which every server implements");

            Assert.That(entries!.Where(entry => entry.MethodId is RawSshKeyBinding.MethodSshExporter or RawSshKeyBinding.MethodTransportedSecret).
                                 Select (entry => entry.Data.Length),
                        Is.All.EqualTo(0),
                        "the Data Length of methods 0x0001 and 0x0002");

        });

    }


    /// <summary>
    /// Section 5.1: record 1024 has no meaning over SSH, and a client should not send it there —
    /// not even when it offers AES-128-GCM-SIV, where it would over TLS.
    /// </summary>
    [Test]
    public async Task TheRequest_OverSsh_CarriesNoRecord1024()
    {

        var (_, server) = await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(AGoodResponse()),
                                              aeadAlgorithms: [ AEADAlgorithms.AES_128_GCM_SIV ]);

        Assert.That(server.Requests[0].RecordsOfType(RawNtsKeRecordTypes.CompliantAes128GcmSivExporterContext),
                    Is.Empty,
                    Bytes.Dump(server.Requests[0].Bytes));

    }

    #endregion

    #region Section 5 — the keys the client derives

    /// <summary>
    /// Section 5.3: from the nts_ke_secret of the response, the client derives the keys this
    /// suite derives — HKDF-Expand-SHA256 with the secret as the PRK, and the context of the
    /// negotiated algorithm.
    /// </summary>
    [TestCase(15, 32, TestName = "TheKeysOfTheTransportedSecret_AreThoseOfSection53_AesSivCmac256")]
    [TestCase(30, 16, TestName = "TheKeysOfTheTransportedSecret_AreThoseOfSection53_Aes128GcmSiv")]
    [TestCase(31, 32, TestName = "TheKeysOfTheTransportedSecret_AreThoseOfSection53_Aes256GcmSiv")]
    public async Task TheKeysOfTheTransportedSecret_AreThoseOfSection53(Int32 aead, Int32 keyLength)
    {

        var secret      = RandomNumberGenerator.GetBytes(MethodDataLength);

        var (result, _) = await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(
                                                  AGoodResponse(RawSshKeyBinding.ResponseBody(RawSshKeyBinding.MethodTransportedSecret, secret),
                                                                (UInt16) aead)),
                                              aeadAlgorithms: [ (AEADAlgorithms) aead ]);

        Assert.That(result.Success, Is.True, result.ErrorMessage);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(result.Response!.C2SKey),
                        Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.TransportedSecretKey(secret, (UInt16) aead, RawSshKeyBinding.C2S, keyLength))),
                        $"C2S key, AEAD {aead}, nts_ke_secret {Bytes.ToHex(secret)}");
            Assert.That(Bytes.ToHex(result.Response!.S2CKey),
                        Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.TransportedSecretKey(secret, (UInt16) aead, RawSshKeyBinding.S2C, keyLength))),
                        $"S2C key, AEAD {aead}, nts_ke_secret {Bytes.ToHex(secret)}");
        });

    }


    /// <summary>
    /// Section 5.2: from the exporter_nonce of the response, the client derives the keys the
    /// server end of the same connection derives — Hermod's exporter on both ends, held to the
    /// specification in <c>SshKeyBindingConformanceTests</c>; what is under test here is that
    /// Norn's client takes the nonce of the response and the context of the negotiated algorithm.
    /// </summary>
    [TestCase(15, 32, TestName = "TheKeysOfTheSshExporter_AreThoseOfTheServerEnd_AesSivCmac256")]
    [TestCase(30, 16, TestName = "TheKeysOfTheSshExporter_AreThoseOfTheServerEnd_Aes128GcmSiv")]
    public async Task TheKeysOfTheSshExporter_AreThoseOfTheServerEnd(Int32 aead, Int32 keyLength)
    {

        var nonce = RandomNumberGenerator.GetBytes(MethodDataLength);

        await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(
                                AGoodResponse(RawSshKeyBinding.ResponseBody(RawSshKeyBinding.MethodSshExporter, nonce),
                                              (UInt16) aead)),
                            aeadAlgorithms: [ (AEADAlgorithms) aead ],
                            whileConnected: (result, server) => {

                                Assert.That(result.Success, Is.True, result.ErrorMessage);

                                var serverEnd = server.Requests[0].Session.Exporter;

                                Assert.That(serverEnd, Is.Not.Null, "the server end of the connection has no exporter");

                                Byte[] KeyFor(Byte direction)
                                    => serverEnd!.Export(nonce,
                                                         RawSshKeyBinding.ExporterLabel,
                                                         RawSshKeyBinding.Context((UInt16) aead, direction),
                                                         keyLength);

                                Assert.Multiple(() => {
                                    Assert.That(Bytes.ToHex(result.Response!.C2SKey), Is.EqualTo(Bytes.ToHex(KeyFor(RawSshKeyBinding.C2S))), $"C2S key, AEAD {aead}");
                                    Assert.That(Bytes.ToHex(result.Response!.S2CKey), Is.EqualTo(Bytes.ToHex(KeyFor(RawSshKeyBinding.S2C))), $"S2C key, AEAD {aead}");
                                });

                                return Task.CompletedTask;

                            });

    }

    #endregion

    #region Section 4.2 — the responses the client must abort on

    /// <summary>
    /// The control: everything below spoils exactly one thing about this response.
    /// </summary>
    [Test]
    public async Task TheControl_AGoodResponse_IsAccepted()
    {

        var (result, _) = await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(AGoodResponse()));

        Assert.That(result.Success, Is.True, result.ErrorMessage);

    }


    /// <summary>
    /// No SSH Key Binding record, and no Error record either: there is nothing to take the keys
    /// from, and a client that took them from somewhere else would have cookies whose keys the
    /// server never sealed into them.
    /// </summary>
    [Test]
    public async Task AResponseWithoutAnSshKeyBinding_IsAborted()
        => AssertAborted((await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(AGoodResponse(keyBindingBody: null)))).Result,
                         "a response without an SSH Key Binding record");


    /// <summary>
    /// Two SSH Key Binding records, even two that agree.
    /// </summary>
    [Test]
    public async Task AResponseWithTwoSshKeyBindings_IsAborted()
    {

        var body = RawSshKeyBinding.ResponseBody(RawSshKeyBinding.MethodTransportedSecret, RandomNumberGenerator.GetBytes(MethodDataLength));

        AssertAborted((await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply([
                                               RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                               RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                               RawNtsKeRecord.SshKeyBinding(body),
                                               RawNtsKeRecord.SshKeyBinding(body),
                                               RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                               RawNtsKeRecord.EndOfMessage()
                                           ]))).Result,
                      "a response with two SSH Key Binding records");

    }


    /// <summary>
    /// A method the client did not offer: the SSH Exporter to a client that offered the
    /// Transported Secret alone, and methods nobody offers.
    /// </summary>
    [TestCase(false, (UInt16) 0x0001, TestName = "TheSshExporter_ToAClientThatDidNotOfferIt_IsAborted")]
    [TestCase(true,  (UInt16) 0x0003, TestName = "AnUnassignedMethod_IsAborted")]
    [TestCase(true,  (UInt16) 0x8001, TestName = "APrivateMethod_IsAborted")]
    [TestCase(true,  (UInt16) 0x0000, TestName = "TheReservedMethod_IsAborted")]
    public async Task AResponseSelectingAMethodNotOffered_IsAborted(Boolean offerSshExporter, UInt16 methodId)
        => AssertAborted((await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(
                                                  AGoodResponse(RawSshKeyBinding.ResponseBody(methodId, RandomNumberGenerator.GetBytes(MethodDataLength)))),
                                              offerSshExporter)).Result,
                         $"a response selecting method 0x{methodId:x4}, the client having offered {(offerSshExporter ? "0x0001 and 0x0002" : "0x0002 alone")}");


    /// <summary>
    /// Method Data of a length other than the 32 octets the selected method defines.
    /// </summary>
    [TestCase((UInt16) 0x0002,  0, TestName = "TheTransportedSecret_WithoutItsSecret_IsAborted")]
    [TestCase((UInt16) 0x0002, 31, TestName = "TheTransportedSecret_With31Octets_IsAborted")]
    [TestCase((UInt16) 0x0002, 33, TestName = "TheTransportedSecret_With33Octets_IsAborted")]
    [TestCase((UInt16) 0x0001, 31, TestName = "TheSshExporter_With31Octets_IsAborted")]
    [TestCase((UInt16) 0x0001, 64, TestName = "TheSshExporter_With64Octets_IsAborted")]
    public async Task AResponseWithMethodDataOfAnotherLength_IsAborted(UInt16 methodId, Int32 dataLength)
        => AssertAborted((await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(
                                                  AGoodResponse(RawSshKeyBinding.ResponseBody(methodId, RandomNumberGenerator.GetBytes(dataLength)))))).Result,
                         $"a response selecting method 0x{methodId:x4} with {dataLength} octets of data");


    /// <summary>
    /// An error response carries no SSH Key Binding record (Section 3.4), and is the server's
    /// error — not a response the client aborts for its missing record.
    /// </summary>
    [Test]
    public async Task AnErrorResponse_IsTheServersError()
    {

        var (result, _) = await ExchangeAsync(ScriptedNtsKeOverSshServer.Reply(
                                                  RawNtsKeRecord.Error(RawNtsKeErrorCodes.BadRequest),
                                                  RawNtsKeRecord.EndOfMessage()));

        Assert.Multiple(() => {
            Assert.That(result.Success,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSKEErrorCategory.ServerError), result.ErrorMessage);
        });

    }

    #endregion

    #region Section 4.2 — over TLS

    /// <summary>
    /// Over TLS the keys come from the TLS exporter, and the client must not send the record.
    /// </summary>
    [Test]
    public async Task OverTls_TheRequestCarriesNoSshKeyBinding()
    {

        await using var server = ScriptedNtsKeServer.Start(Respond: _ => RawNtsKeCodec.Encode([
                                                                              RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                                                              RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                                                              RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                                                              RawNtsKeRecord.EndOfMessage()
                                                                          ]));

        await NewTlsClient(server).GetNTSKERecords();

        Assert.That(server.Requests, Has.Count.EqualTo(1));
        Assert.That(server.Requests[0].Records, Is.Not.Null, server.Requests[0].DecodeError);
        Assert.That(server.Requests[0].Records!.Where(record => record.RecordType == RawNtsKeRecordTypes.SshKeyBinding),
                    Is.Empty,
                    Bytes.Dump(server.Requests[0].Bytes));

    }


    /// <summary>
    /// And treat it in a response as an unrecognized record — with its Critical Bit set, that
    /// aborts the exchange (RFC 8915 §4).
    /// </summary>
    [Test]
    public async Task OverTls_AResponseWithAnSshKeyBinding_IsAnUnrecognizedCriticalRecord()
    {

        await using var server = ScriptedNtsKeServer.Start(Respond: _ => RawNtsKeCodec.Encode([
                                                                              RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                                                              RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                                                              RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.ResponseBody(RawSshKeyBinding.MethodTransportedSecret,
                                                                                                                                         RandomNumberGenerator.GetBytes(MethodDataLength))),
                                                                              RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                                                              RawNtsKeRecord.EndOfMessage()
                                                                          ]));

        var result = await NewTlsClient(server).GetNTSKERecords();

        Assert.Multiple(() => {
            Assert.That(result.Success,       Is.False, "the client used a response over TLS with an SSH Key Binding record");
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSKEErrorCategory.UnknownCriticalRecord), result.ErrorMessage);
        });

    }


    private static NTSClient NewTlsClient(ScriptedNtsKeServer server)

        => new (DomainName.Localhost,
                NTSKE_Port:                  server.Port,
                IPVersionPreference:         IPVersionPreference.IPv4Only,
                Timeout:                     TimeSpan.FromSeconds(10),
                RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                 => TLSValidationResult.Success());

    #endregion

}
