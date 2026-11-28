using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.Client.Tests;

/// <summary>
/// The key exchange of Norn's client for NTPv5, over TLS and over SSH: what it offers (draft-
/// ietf-ntp-ntpv5-10 § 11, RFC 8915 § 4.1.2), what it makes of what a server agrees to, and,
/// over SSH, that the keys it derives for NTPv5 are those an NTPv5 server derives too.
///
/// <para>
/// The servers are <see cref="ScriptedNtsKeServer"/> and <see cref="ScriptedNtsKeOverSshServer"/>,
/// answering with records this suite wrote, so that a test can answer with what Norn's server
/// never would: two protocols at once, as chrony-ntp5's does, none, or one never offered.
/// </para>
/// <para>
/// RFC 8915 § 4.1.2: the client's record lists "those protocols that the client wishes to
/// speak", the server's "MUST comprise a subset of those listed in the request", and "The client
/// MAY proceed with one or more of them. The request MUST list at least one protocol, but the
/// response MAY be empty."
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientNtsKeTests
{

    #region Data

    private const UInt16 V4 = RawNtsKeNextProtocols.Ntpv4;
    private const UInt16 V5 = RawNtsKeNextProtocols.Ntpv5Draft;

    #endregion

    #region (private) helpers

    /// <summary>
    /// One key exchange of Norn's client, and the request the server received. Over SSH the
    /// given callback runs while the connection is still open, for what needs its exporter.
    /// </summary>
    private sealed record Run(NTSKEResult            Result,
                              List<RawNtsKeRecord>?  Request,
                              NTSClient              Client);


    private static async Task<Run> Exchange(NtsKeTransport                                Transport,
                                            IEnumerable<RawNtsKeRecord>                   Reply,
                                            NTPv5Support                                  NTPv5              = NTPv5Support.Draft,
                                            Boolean                                       OfferSshExporter   = false,
                                            Func<NTSKEResult, SshSessionInfo, Task>?      WhileConnected     = null)
    {

        var octets = RawNtsKeCodec.Encode(Reply.ToArray());

        if (Transport == NtsKeTransport.Tls)
        {

            await using var server = ScriptedNtsKeServer.Start(Respond: _ => octets);

            var client = new NTSClient(DomainName.Localhost,
                                       NTSKE_Port:                  server.Port,
                                       IPVersionPreference:         IPVersionPreference.IPv4Only,
                                       Timeout:                     TimeSpan.FromSeconds(10),
                                       RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                                        => TLSValidationResult.Success()) {
                             NTPv5 = NTPv5
                         };

            var result = await client.GetNTSKERecords();

            return new Run(result, server.LastRequest?.Records, client);

        }

        var sshServer = await ScriptedNtsKeOverSshServer.StartAsync(_ => octets);

        try
        {

            await using var ssh = await sshServer.ConnectAsync();

            var client = new NTSClient(DomainName.Localhost,
                                       IPVersionPreference:  IPVersionPreference.IPv4Only,
                                       Timeout:              TimeSpan.FromSeconds(10)) {
                             NTPv5 = NTPv5
                         };

            var result = await client.GetNTSKERecordsOverSSH(ssh, OfferSSHExporter: OfferSshExporter);

            if (WhileConnected is not null)
                await WhileConnected(result, sshServer.Requests[0].Session);

            return new Run(result, sshServer.Requests.FirstOrDefault()?.Records, client);

        }
        finally
        {
            await sshServer.DisposeAsync();
        }

    }


    /// <summary>
    /// A response agreeing to the given protocols, with AES-SIV-CMAC-256 and a cookie - and over
    /// SSH the Transported Secret with the given secret - and whatever else is given.
    /// </summary>
    private static RawNtsKeRecord[] Reply(NtsKeTransport               Transport,
                                          UInt16[]                     Protocols,
                                          Byte[]?                      Secret  = null,
                                          params RawNtsKeRecord[]      More)

        => [
               RawNtsKeRecord.NextProtocolNegotiation(Protocols),
               RawNtsKeRecord.AeadAlgorithmNegotiation(15),
               .. (Transport == NtsKeTransport.Ssh
                       ? new[] { RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.ResponseBody(RawSshKeyBinding.MethodTransportedSecret,
                                                                                            Secret ?? RandomNumberGenerator.GetBytes(32))) }
                       : []),
               RawNtsKeRecord.NewCookieForNtpv4(RandomNumberGenerator.GetBytes(64)),
               .. More,
               RawNtsKeRecord.EndOfMessage()
           ];

    #endregion


    #region § 11 and RFC 8915 § 4.1.2: what the client offers

    /// <summary>
    /// § 11: NTPv5 "can be indicated as the next protocol with identifier [[TBD]] (draft use
    /// 0x8001)". A client of the draft offers it, and NTPv4 after it to fall back on - for a
    /// server without NTPv5, or one that does not support this draft and so "MUST not accept
    /// NTPv5". One record, critical: RFC 8915 § 4.1.2, "The Critical Bit MUST be set."
    /// </summary>
    [TestCase(NtsKeTransport.Tls, TestName = "AClientOfTheDraft_OffersNTPv5AndThenNTPv4_OverTls")]
    [TestCase(NtsKeTransport.Ssh, TestName = "AClientOfTheDraft_OffersNTPv5AndThenNTPv4_OverSsh")]
    public async Task AClientOfTheDraft_OffersNTPv5AndThenNTPv4(NtsKeTransport Transport)
    {

        var run      = await Exchange(Transport, Reply(Transport, [ V5 ]));
        using var owned = run.Result;

        var records  = run.Request?.Where(record => record.RecordType == RawNtsKeRecordTypes.NextProtocolNegotiation).ToArray();

        Assert.That(records, Is.Not.Null.And.Length.EqualTo(1), "Next Protocol Negotiation records in the request");

        Assert.Multiple(() => {
            Assert.That(records![0].IsCritical,                     Is.True,                         "its Critical Bit");
            Assert.That(RawNtsKeCodec.ReadUInt16Body(records![0]),  Is.EqualTo(new[] { V5, V4 }),    "the protocols offered");
        });

    }


    /// <summary>
    /// § 11: "Client implementations of a draft of this specification MUST provide the identity
    /// of the draft implemented as data in an NTS-KE record of type 0x4001, which does not have
    /// the critical bit set." "The draft identity MUST be encoded as ascii and MUST not contain
    /// any trailing 0 bytes." Once, exactly so.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, TestName = "AClientOfTheDraft_NamesItsDraftInRecord0x4001_OverTls")]
    [TestCase(NtsKeTransport.Ssh, TestName = "AClientOfTheDraft_NamesItsDraftInRecord0x4001_OverSsh")]
    public async Task AClientOfTheDraft_NamesItsDraftInRecord0x4001(NtsKeTransport Transport)
    {

        var run      = await Exchange(Transport, Reply(Transport, [ V5 ]));
        using var owned = run.Result;

        var records  = run.Request?.Where(record => record.RecordType == RawNtsKeRecordTypes.Ntpv5DraftIdentification).ToArray();

        Assert.That(records, Is.Not.Null.And.Length.EqualTo(1), "records 0x4001 in the request");

        Assert.Multiple(() => {
            Assert.That(records![0].IsCritical,                    Is.False,                                 "its Critical Bit");
            Assert.That(Encoding.ASCII.GetString(records![0].Body), Is.EqualTo(RawNtpV5Draft.Identification), "the draft named");
            Assert.That(records![0].Body,                          Has.Length.EqualTo(RawNtpV5Draft.Identification.Length),
                        "the body is longer than the name: trailing zeros");
        });

    }


    /// <summary>
    /// And a client without NTPv5 offers NTPv4 alone, as before, and names no draft.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, TestName = "AClientWithoutNTPv5_OffersNTPv4Alone_OverTls")]
    [TestCase(NtsKeTransport.Ssh, TestName = "AClientWithoutNTPv5_OffersNTPv4Alone_OverSsh")]
    public async Task AClientWithoutNTPv5_OffersNTPv4Alone(NtsKeTransport Transport)
    {

        var run      = await Exchange(Transport, Reply(Transport, [ V4 ]), NTPv5: NTPv5Support.Disabled);
        using var owned = run.Result;

        Assert.Multiple(() => {
            Assert.That(run.Request?.Where(record => record.RecordType == RawNtsKeRecordTypes.NextProtocolNegotiation).
                                     Select(RawNtsKeCodec.ReadUInt16Body),
                        Is.EqualTo(new[] { new[] { V4 } }),
                        "the protocols offered");
            Assert.That(run.Request?.Any(record => record.RecordType == RawNtsKeRecordTypes.Ntpv5DraftIdentification),
                        Is.False,
                        "a draft named by a client without NTPv5");
        });

    }

    #endregion

    #region RFC 8915 § 4.1.2: what the server agrees to

    /// <summary>
    /// Whatever subset of its offer the server agrees to, the client proceeds - NTPv5 where it
    /// is among them, which it offered first, and NTPv4 where it is not. Two at once is what
    /// chrony-ntp5's server answers, and "MAY proceed with one or more" makes it no error.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, new[] { V5 },     V5, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv5_OverTls")]
    [TestCase(NtsKeTransport.Tls, new[] { V4 },     V4, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv4_OverTls")]
    [TestCase(NtsKeTransport.Tls, new[] { V4, V5 }, V5, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv4AndNTPv5_OverTls")]
    [TestCase(NtsKeTransport.Tls, new[] { V5, V4 }, V5, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv5AndNTPv4_OverTls")]
    [TestCase(NtsKeTransport.Ssh, new[] { V5 },     V5, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv5_OverSsh")]
    [TestCase(NtsKeTransport.Ssh, new[] { V4 },     V4, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv4_OverSsh")]
    [TestCase(NtsKeTransport.Ssh, new[] { V4, V5 }, V5, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv4AndNTPv5_OverSsh")]
    [TestCase(NtsKeTransport.Ssh, new[] { V5, V4 }, V5, TestName = "WhatIsAgreed_IsWhatTheClientProceedsWith_NTPv5AndNTPv4_OverSsh")]
    public async Task WhatIsAgreed_IsWhatTheClientProceedsWith(NtsKeTransport Transport, UInt16[] Agreed, UInt16 Expected)
    {

        var run      = await Exchange(Transport, Reply(Transport, Agreed));
        using var owned = run.Result;

        Assert.Multiple(() => {
            Assert.That(run.Result.Success,                  Is.True,               run.Result.ErrorMessage);
            Assert.That(run.Result.Response?.NextProtocols,  Is.EqualTo(Agreed),    "the protocols agreed");
            Assert.That(run.Result.Response?.NextProtocol,   Is.EqualTo(Expected),  "the protocol proceeded with");
        });

    }


    /// <summary>
    /// "the response MAY be empty", and then nothing was agreed: there is no protocol to proceed
    /// with, and the key exchange fails as one that negotiated none - not with keys and cookies
    /// for a protocol nobody named.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, TestName = "NothingAgreed_FailsTheKeyExchange_OverTls")]
    [TestCase(NtsKeTransport.Ssh, TestName = "NothingAgreed_FailsTheKeyExchange_OverSsh")]
    public async Task NothingAgreed_FailsTheKeyExchange(NtsKeTransport Transport)
    {

        var run      = await Exchange(Transport, Reply(Transport, []));
        using var owned = run.Result;

        Assert.Multiple(() => {
            Assert.That(run.Result.Success,        Is.False, "the client proceeded with nothing");
            Assert.That(run.Result.ErrorCategory,  Is.EqualTo(NTSKEErrorCategory.UnsupportedProtocol), run.Result.ErrorMessage);
        });

    }


    /// <summary>
    /// RFC 8915 § 4.1.2: what the server agrees to "MUST comprise a subset of those listed in
    /// the request". A protocol the client did not offer - alone, or beside one it did - is a
    /// server that did not read the request, and its keys are for something else.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, new UInt16[] { 1 },              TestName = "AProtocolNotOffered_IsRefused_1_OverTls")]
    [TestCase(NtsKeTransport.Tls, new UInt16[] { 0x8002 },         TestName = "AProtocolNotOffered_IsRefused_0x8002_OverTls")]
    [TestCase(NtsKeTransport.Tls, new UInt16[] { V5, 1 },          TestName = "AProtocolNotOffered_IsRefused_NTPv5And1_OverTls")]
    [TestCase(NtsKeTransport.Tls, new UInt16[] { V4, 0x8002 },     TestName = "AProtocolNotOffered_IsRefused_NTPv4And0x8002_OverTls")]
    [TestCase(NtsKeTransport.Ssh, new UInt16[] { 1 },              TestName = "AProtocolNotOffered_IsRefused_1_OverSsh")]
    [TestCase(NtsKeTransport.Ssh, new UInt16[] { 0x8002 },         TestName = "AProtocolNotOffered_IsRefused_0x8002_OverSsh")]
    [TestCase(NtsKeTransport.Ssh, new UInt16[] { V5, 1 },          TestName = "AProtocolNotOffered_IsRefused_NTPv5And1_OverSsh")]
    [TestCase(NtsKeTransport.Ssh, new UInt16[] { V4, 0x8002 },     TestName = "AProtocolNotOffered_IsRefused_NTPv4And0x8002_OverSsh")]
    public async Task AProtocolNotOffered_IsRefused(NtsKeTransport Transport, UInt16[] Agreed)
    {

        var run      = await Exchange(Transport, Reply(Transport, Agreed));
        using var owned = run.Result;

        Assert.Multiple(() => {
            Assert.That(run.Result.Success,        Is.False, $"the client proceeded with [{String.Join(", ", Agreed.Select(protocol => $"0x{protocol:x4}"))}]");
            Assert.That(run.Result.ErrorCategory,  Is.EqualTo(NTSKEErrorCategory.UnsupportedProtocol), run.Result.ErrorMessage);
        });

    }


    /// <summary>
    /// Nor is NTPv5 to a client that did not offer it: a client without NTPv5 offers NTPv4
    /// alone, so 0x8001 in the response is a protocol it did not list.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, new[] { V5 },     TestName = "NTPv5ToAClientThatDidNotOfferIt_IsRefused_NTPv5_OverTls")]
    [TestCase(NtsKeTransport.Tls, new[] { V4, V5 }, TestName = "NTPv5ToAClientThatDidNotOfferIt_IsRefused_NTPv4AndNTPv5_OverTls")]
    [TestCase(NtsKeTransport.Ssh, new[] { V5 },     TestName = "NTPv5ToAClientThatDidNotOfferIt_IsRefused_NTPv5_OverSsh")]
    [TestCase(NtsKeTransport.Ssh, new[] { V4, V5 }, TestName = "NTPv5ToAClientThatDidNotOfferIt_IsRefused_NTPv4AndNTPv5_OverSsh")]
    public async Task NTPv5ToAClientThatDidNotOfferIt_IsRefused(NtsKeTransport Transport, UInt16[] Agreed)
    {

        var run      = await Exchange(Transport, Reply(Transport, Agreed), NTPv5: NTPv5Support.Disabled);
        using var owned = run.Result;

        Assert.Multiple(() => {
            Assert.That(run.Result.Success,        Is.False, "the client proceeded with a protocol it did not offer");
            Assert.That(run.Result.ErrorCategory,  Is.EqualTo(NTSKEErrorCategory.UnsupportedProtocol), run.Result.ErrorMessage);
        });

    }


    /// <summary>
    /// Record 0x4001 is the client's to send. A server that echoes it sends a record that is not
    /// critical, and RFC 8915 § 4 has a recipient ignore an unrecognized record whose Critical
    /// Bit is not set: the key exchange stands.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, TestName = "TheDraftRecordInAResponse_IsIgnored_OverTls")]
    [TestCase(NtsKeTransport.Ssh, TestName = "TheDraftRecordInAResponse_IsIgnored_OverSsh")]
    public async Task TheDraftRecordInAResponse_IsIgnored(NtsKeTransport Transport)
    {

        var run      = await Exchange(Transport,
                                      Reply(Transport,
                                            [ V5 ],
                                            More: new RawNtsKeRecord(false,
                                                                     RawNtsKeRecordTypes.Ntpv5DraftIdentification,
                                                                     Encoding.ASCII.GetBytes(RawNtpV5Draft.Identification))));
        using var owned = run.Result;

        Assert.Multiple(() => {
            Assert.That(run.Result.Success,                 Is.True,         run.Result.ErrorMessage);
            Assert.That(run.Result.Response?.NextProtocol,  Is.EqualTo(V5));
        });

    }

    #endregion

    #region Over SSH: the keys of NTPv5

    /// <summary>
    /// Section 5.4 of the SSH Key Binding specification, 1.2: the keys of every next protocol are
    /// derived under RFC 8915 § 5.1's context of NTPv4, 0x0000, as chrony-ntp5 derives those of
    /// NTPv5 over TLS. A key exchange over SSH that agreed to NTPv5, with the Transported Secret:
    /// the client's keys are those derived here from the secret under 0x0000 - and not those
    /// under 0x8001, the context of version 1.1.
    /// </summary>
    [Test]
    public async Task OverSsh_TheKeysOfNTPv5_AreThoseOfTheTransportedSecretUnderNTPv4sContext()
    {

        var secret   = RandomNumberGenerator.GetBytes(32);

        var run      = await Exchange(NtsKeTransport.Ssh, Reply(NtsKeTransport.Ssh, [ V5 ], secret));
        using var owned = run.Result;

        Assert.That(run.Result.Success, Is.True, run.Result.ErrorMessage);

        Assert.Multiple(() => {

            Assert.That(Bytes.ToHex(run.Result.Response!.C2SKey),
                        Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.C2S, 32))),
                        "the C2S key");

            Assert.That(Bytes.ToHex(run.Result.Response!.S2CKey),
                        Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.S2C, 32))),
                        "the S2C key");

            Assert.That(Bytes.ToHex(run.Result.Response!.C2SKey),
                        Is.Not.EqualTo(Bytes.ToHex(RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.C2S, 32, V5))),
                        "the C2S key is that of the context 0x8001");

        });

    }


    /// <summary>
    /// The same with the SSH Exporter: the keys are those of the server end's exporter of the
    /// connection, with the nonce of the response, under 0x0000.
    /// </summary>
    [Test]
    public async Task OverSsh_TheKeysOfNTPv5_AreThoseOfTheSshExporterUnderNTPv4sContext()
    {

        var nonce    = RandomNumberGenerator.GetBytes(32);

        var run      = await Exchange(NtsKeTransport.Ssh,
                                      [
                                          RawNtsKeRecord.NextProtocolNegotiation(V5),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.ResponseBody(RawSshKeyBinding.MethodSshExporter, nonce)),
                                          RawNtsKeRecord.NewCookieForNtpv4(RandomNumberGenerator.GetBytes(64)),
                                          RawNtsKeRecord.EndOfMessage()
                                      ],
                                      OfferSshExporter: true,
                                      WhileConnected: (result, session) => {

                                          Assert.That(result.Success,     Is.True,     result.ErrorMessage);
                                          Assert.That(session.Exporter,   Is.Not.Null, "the server end of the connection has no exporter");

                                          Byte[] KeyFor(Byte Direction)
                                              => session.Exporter!.Export(nonce,
                                                                          RawSshKeyBinding.ExporterLabel,
                                                                          RawSshKeyBinding.Context(15, Direction),
                                                                          32);

                                          Assert.Multiple(() => {
                                              Assert.That(Bytes.ToHex(result.Response!.C2SKey), Is.EqualTo(Bytes.ToHex(KeyFor(RawSshKeyBinding.C2S))), "the C2S key");
                                              Assert.That(Bytes.ToHex(result.Response!.S2CKey), Is.EqualTo(Bytes.ToHex(KeyFor(RawSshKeyBinding.S2C))), "the S2C key");
                                          });

                                          return Task.CompletedTask;

                                      });

        using var owned = run.Result;

    }


    /// <summary>
    /// And the client takes those keys for NTPv5: a key exchange over SSH that agreed to NTPv5
    /// and named a scripted NTPv5 server (RFC 8915 § 4.1.7 and § 4.1.8, which § 11 reuses), whose
    /// answer is sealed under the S2C key derived here, and which answers only a request whose
    /// authenticator opens under the C2S key derived here. The query is answered and authenticated -
    /// end to end, with nothing of the key exchange taken from Norn but what it sent.
    /// </summary>
    [Test]
    public async Task OverSsh_TheClientQueriesNTPv5_UnderTheKeysOfTheExchange()
    {

        var secret  = RandomNumberGenerator.GetBytes(32);
        var c2s     = RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.C2S, 32);
        var s2c     = RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.S2C, 32);
        var opened  = false;

        await using var ntp = new ScriptedNtpV5Server(request => {

            var packet  = request.Packet;
            var index   = packet?.ExtensionFields.FindIndex(field => field.Type == RawNtpV5Nts.NtsAuthenticator) ?? -1;

            if (packet is null || index < 0 ||
                !RawNtsExtensionFields.TryParseAuthenticatorValue(packet.ExtensionFields[index].Data, out var nonce, out var ciphertext, out _) ||
                !RawNtpV5Nts.TryOpen(15, c2s, request.Octets[..RawNtpV5Nts.OffsetOf(packet, index)], nonce!, ciphertext!, out _, out _))
                return [];

            opened = true;

            return [ new ScriptedDatagram(RawNtpV5Responses.Sealed(RawNtpV5Responses.Answer(packet, DateTime.UtcNow),
                                                                   packet.Find(RawNtpV5Nts.UniqueIdentifier)!.Data,
                                                                   15,
                                                                   s2c,
                                                                   [ RandomNumberGenerator.GetBytes(64) ])) ];

        });

        var run      = await Exchange(NtsKeTransport.Ssh,
                                      Reply(NtsKeTransport.Ssh,
                                            [ V5 ],
                                            secret,
                                            RawNtsKeRecord.Ntpv4ServerNegotiation("127.0.0.1"),
                                            RawNtsKeRecord.Ntpv4PortNegotiation(ntp.Port.ToUInt16())));
        using var owned = run.Result;

        Assert.That(run.Result.Success, Is.True, run.Result.ErrorMessage);

        var query = await run.Client.QueryNTPv5(NTSKEResponse: run.Result.Response, Timeout: TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {
            Assert.That(opened,                 Is.True, "no request of the client opened under the C2S key derived here");
            Assert.That(query.Success,          Is.True, query.ErrorMessage);
            Assert.That(query.IsAuthenticated,  Is.True);
            Assert.That(query.NewCookies,       Is.EqualTo(1));
        });

        await run.Client.DisposeAsync();

    }

    #endregion

}
