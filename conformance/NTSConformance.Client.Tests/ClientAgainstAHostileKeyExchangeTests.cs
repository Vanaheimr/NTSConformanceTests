using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's client does with a key exchange that is wrong, in each of the ways RFC 8915 § 4
/// allows a reply to be wrong.
///
/// <para>
/// Norn's own suite checks most of these against <c>NTSKERecordValidator</c> directly, which is
/// the right place for the decision and the wrong place to stop: a validator that returns false
/// and a client that goes on regardless both pass a unit test of the validator. What these assert
/// is that the refusal survives the whole pipeline — reader, parser, validator — and comes back
/// out of <c>GetNTSKERecords</c> as a failure a caller can act on, with the category that says
/// which kind of wrong it was.
/// </para>
/// <para>
/// Three of them cannot be expressed as a unit test at all, because they are not about records:
/// a peer that hangs up without answering, one that sends a body length running off the end of
/// the message, and one that never sends End of Message. Those need a server that will do it.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ClientAgainstAHostileKeyExchangeTests
{

    #region (private) helpers

    /// <summary>
    /// A server that always answers with the given records, whatever it was asked.
    /// </summary>
    private static Func<CapturedNtsKeRequest, Byte[]?> Reply(params RawNtsKeRecord[] Records)
        => _ => RawNtsKeCodec.Encode(Records);


    /// <summary>
    /// The records of a reply that is correct, so a test can spoil exactly one thing.
    /// </summary>
    private static RawNtsKeRecord[] AGoodReply()
        => [
               RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
               RawNtsKeRecord.AeadAlgorithmNegotiation(15),
               RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
               RawNtsKeRecord.EndOfMessage()
           ];


    /// <summary>
    /// Run one key exchange against a server that answers with <paramref name="Respond"/>.
    /// </summary>
    private static async Task<NTSKEResult> Exchange(Func<CapturedNtsKeRequest, Byte[]?>  Respond,
                                                    IEnumerable<AEADAlgorithms>?         AEADAlgorithms   = null,
                                                    TimeSpan?                            Timeout          = null)
    {

        await using var server = ScriptedNtsKeServer.Start(Respond: Respond);

        return await new NTSClient(
                         DomainName.Localhost,
                         NTSKE_Port:                  server.Port,
                         IPVersionPreference:         IPVersionPreference.IPv4Only,
                         Timeout:                     Timeout ?? TimeSpan.FromSeconds(10),
                         RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                          => TLSValidationResult.Success(),
                         OfferedAEADAlgorithms:       AEADAlgorithms
                     ).GetNTSKERecords();

    }


    private static void AssertRefused(NTSKEResult          Result,
                                      NTSKEErrorCategory   ExpectedCategory,
                                      String               Because)

        => Assert.Multiple(() => {

            Assert.That(Result.Success, Is.False, Because);

            Assert.That(Result.ErrorCategory,
                        Is.EqualTo(ExpectedCategory),
                        $"{Because} — refused, but as {Result.ErrorCategory}: {Result.ErrorMessage}");

        });

    #endregion


    /// <summary>
    /// The control. Everything below spoils exactly one thing about this reply, so if this one
    /// did not pass, none of the others would mean anything.
    /// </summary>
    [Test]
    public async Task AWellFormedReply_IsAccepted()
    {

        var result = await Exchange(Reply(AGoodReply()));

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.True, result.ErrorMessage);
            Assert.That(result.Response?.Cookies.Count(), Is.EqualTo(1));

        });

    }


    #region Error and Warning records (§ 4.1.3, § 4.1.4)

    /// <summary>
    /// An Error record ends the exchange, and its code reaches the caller.
    /// </summary>
    /// <remarks>
    /// § 4.1.3 defines three codes and makes the body two octets rather than text. The code is
    /// the only thing that distinguishes "you sent me something I could not parse" from "I broke,
    /// try again", so a client that reports the refusal without it has thrown away the half a
    /// caller can act on.
    /// </remarks>
    [TestCase((UInt16) 0)]
    [TestCase((UInt16) 1)]
    [TestCase((UInt16) 2)]
    public async Task AnErrorRecord_EndsTheExchange(UInt16 ErrorCode)
    {

        var result = await Exchange(Reply(RawNtsKeRecord.Error(ErrorCode),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.ServerError,
                      $"the server said error {ErrorCode}");

    }


    /// <summary>
    /// A Warning record ends it too, because no warning code has ever been registered.
    /// </summary>
    /// <remarks>
    /// § 4.1.4: "Unrecognized warning codes MUST be treated as errors", and IANA has assigned
    /// none — so every warning a conformant client can receive is unrecognized. Failing closed is
    /// the only reading that survives IANA assigning the first one.
    /// </remarks>
    [Test]
    public async Task AWarningRecord_EndsTheExchange()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.Warning(0),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.ServerWarning,
                      "a warning code that cannot be recognized");

    }


    /// <summary>
    /// Both at once are reported as the error, which is the one carrying a defined code.
    /// </summary>
    [Test]
    public async Task AnErrorAndAWarning_AreReportedAsTheError()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.Warning(0),
                                          RawNtsKeRecord.Error(1),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.ServerError,
                      "an Error record says something specific; a Warning record cannot");

    }

    #endregion

    #region The critical bit (§ 4)

    /// <summary>
    /// An unknown record with the critical bit set ends the exchange; the same record without it
    /// is ignored.
    /// </summary>
    /// <remarks>
    /// § 4: "Implementations which receive a record with an unrecognized Record Type MUST ignore
    /// the record if the Critical Bit is 0 and MUST treat it as an error if the Critical Bit is
    /// 1." Both halves in one test, because the rule is the difference between them — a client
    /// that refuses both is as wrong as one that accepts both, and either alone looks right.
    /// </remarks>
    [Test]
    public async Task AnUnknownRecord_EndsTheExchangeOnlyWhenCritical()
    {

        var critical    = await Exchange(Reply([ .. AGoodReply()[..^1],
                                                 new RawNtsKeRecord(true,  0x3FFF, []),
                                                 RawNtsKeRecord.EndOfMessage() ]));

        var nonCritical = await Exchange(Reply([ .. AGoodReply()[..^1],
                                                 new RawNtsKeRecord(false, 0x3FFF, []),
                                                 RawNtsKeRecord.EndOfMessage() ]));

        Assert.Multiple(() => {

            Assert.That(critical.Success, Is.False, "critical and unknown is an error");

            Assert.That(critical.ErrorCategory,
                        Is.EqualTo(NTSKEErrorCategory.UnknownCriticalRecord),
                        critical.ErrorMessage);

            Assert.That(nonCritical.Success, Is.True,
                        $"and the same record without the bit must be ignored: {nonCritical.ErrorMessage}");

        });

    }

    #endregion

    #region Next protocol negotiation (§ 4.1.2)

    /// <summary>
    /// A reply with no Next Protocol record at all.
    /// </summary>
    [Test]
    public async Task NoNextProtocolRecord_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.MissingRequiredRecord,
                      "nothing says what protocol the cookies are for");

    }


    /// <summary>
    /// A reply naming a protocol that is not NTPv4.
    /// </summary>
    /// <remarks>
    /// The only protocol id registered is 0. A client that accepted any other would be taking
    /// cookies for a protocol it cannot speak, and § 4.1.2 requires the response to be a subset
    /// of the request — which never contained this.
    /// </remarks>
    [Test]
    public async Task ANextProtocolOtherThanNtpv4_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(1),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.UnsupportedProtocol,
                      "protocol 1 is not NTPv4 and is not registered at all");

    }

    #endregion

    #region AEAD algorithm negotiation (§ 4.1.5)

    /// <summary>
    /// A reply with no AEAD Algorithm record.
    /// </summary>
    [Test]
    public async Task NoAeadRecord_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.MissingRequiredRecord,
                      "nothing says how to seal a packet");

    }


    /// <summary>
    /// A reply naming an algorithm this client cannot perform.
    /// </summary>
    /// <remarks>
    /// Algorithm 1 is AEAD_AES_128_GCM, registered with IANA and not implemented here. Accepting
    /// it would produce a session that authenticates nothing, discovered one packet later.
    /// </remarks>
    [Test]
    public async Task AnAeadAlgorithmThisClientCannotPerform_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(1),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.UnsupportedAlgorithm,
                      "AEAD_AES_128_GCM is registered and not implemented here");

    }


    /// <summary>
    /// A reply naming two algorithms.
    /// </summary>
    /// <remarks>
    /// § 4.1.5: the response body "MUST include at most one algorithm number". Two is not a
    /// choice offered back to the client — it is a reply the client cannot act on, because
    /// nothing says which one the cookies were built for.
    /// </remarks>
    [Test]
    public async Task AnAeadRecordNamingTwoAlgorithms_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15, 30),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.UnsupportedAlgorithm,
                      "§ 4.1.5 allows at most one algorithm in a response");

    }

    /// <summary>
    /// A reply naming an algorithm this client can perform but never offered.
    /// </summary>
    /// <remarks>
    /// <para>
    /// § 4.1.5 lets a server "select among any of the client's offered choices, even if they are
    /// able to support some other algorithm that the client prefers more" — the order is the
    /// server's to ignore, the list is not. Here the client offers only AES-128-GCM-SIV and the
    /// server answers AES-SIV-CMAC-256, which this client can perform perfectly well and did not
    /// ask for.
    /// </para>
    /// <para>
    /// Accepting it used to succeed, and the harm is not hypothetical: narrowing
    /// <c>OfferedAEADAlgorithms</c> is the only way to have a policy about which primitives a
    /// deployment will use, and a client that takes whatever comes back has no such policy
    /// however it is configured. It also silently undoes the one thing a test can do to pin a
    /// negotiation to a given algorithm.
    /// </para>
    /// </remarks>
    [Test]
    public async Task AnAeadAlgorithmThisClientDidNotOffer_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                          RawNtsKeRecord.EndOfMessage()),
                                    AEADAlgorithms: [ AEADAlgorithms.AES_128_GCM_SIV ]);

        AssertRefused(result, NTSKEErrorCategory.UnsupportedAlgorithm,
                      "only algorithm 30 was offered and the server answered 15");

    }


    /// <summary>
    /// The control: the same algorithm is accepted when it <em>was</em> offered.
    /// </summary>
    /// <remarks>
    /// Without it, the refusal above is satisfied by a client that has stopped accepting
    /// AES-SIV-CMAC-256 altogether — which would be a far worse bug and would look identical
    /// from the test above.
    /// </remarks>
    [Test]
    public async Task TheSameAlgorithm_IsAcceptedWhenItWasOffered()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100]),
                                          RawNtsKeRecord.EndOfMessage()),
                                    AEADAlgorithms: [ AEADAlgorithms.AES_128_GCM_SIV,
                                                      AEADAlgorithms.AES_SIV_CMAC_256 ]);

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.True, result.ErrorMessage);

            Assert.That(result.Response?.AEADAlgorithm,
                        Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256),
                        "the server may ignore the client's order, only not its list");

        });

    }

    #endregion

    #region Cookies (§ 4.1.6)

    /// <summary>
    /// A reply with no cookie.
    /// </summary>
    /// <remarks>
    /// A key exchange that agrees everything and hands over no cookie has achieved nothing: the
    /// client cannot make a single request. Better refused here than discovered at query time.
    /// </remarks>
    [Test]
    public async Task NoCookie_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.MissingRequiredRecord,
                      "no cookie means no query is possible");

    }


    /// <summary>
    /// A reply with a cookie of zero length.
    /// </summary>
    [Test]
    public async Task AnEmptyCookie_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.NewCookieForNtpv4([]),
                                          RawNtsKeRecord.EndOfMessage()));

        AssertRefused(result, NTSKEErrorCategory.Protocol,
                      "an empty cookie is a cookie record that carries no cookie");

    }

    #endregion

    #region Things that are not records at all

    /// <summary>
    /// A server that completes the handshake and then hangs up.
    /// </summary>
    /// <remarks>
    /// The shape of a server that decided the request was bad and could not be bothered to say
    /// so — which is what Norn's own server used to do before it learned to send Error records.
    /// There is nothing to parse, so the only question is whether the client says something
    /// useful or hangs until its timeout.
    /// </remarks>
    [Test]
    public async Task AServerThatSaysNothing_IsRefused()
    {

        var result = await Exchange(_ => null, Timeout: TimeSpan.FromSeconds(5));

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.False, "there was no reply to accept");

            Assert.That(result.ErrorMessage, Is.Not.Null.And.Not.Empty,
                        "and the caller has to be told something");

        });

    }


    /// <summary>
    /// A record whose declared body length runs off the end of the message.
    /// </summary>
    /// <remarks>
    /// The classic framing attack, and the one that decides whether a parser reads past its
    /// buffer. It has to be refused as a malformed message rather than by throwing — a parse
    /// failure that escapes as an exception is a denial of service against whatever called it.
    /// </remarks>
    [Test]
    public async Task ARecordClaimingMoreBodyThanItHas_IsRefused()
    {

        var result = await Exchange(_ => [
                                        // Next Protocol, claiming a 200-octet body it does not have
                                        0x80, 0x01, 0x00, 0xC8, 0x00, 0x00,
                                        // End of Message, so the reader stops waiting
                                        0x80, 0x00, 0x00, 0x00
                                    ]);

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.False, "the message does not decode");

            Assert.That(result.ErrorMessage, Is.Not.Null.And.Not.Empty,
                        "and it must say so rather than throw");

        });

    }


    /// <summary>
    /// A reply that never ends.
    /// </summary>
    /// <remarks>
    /// § 4.1.1 makes End of Message how a peer knows the message is complete. Without it there is
    /// no point at which the reply can be acted on, and a client that guessed would be acting on
    /// half a negotiation. The records here are otherwise perfectly good, so nothing but the
    /// missing terminator can be what refuses it.
    /// </remarks>
    [Test]
    public async Task AReplyWithoutEndOfMessage_IsRefused()
    {

        var result = await Exchange(Reply(RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
                                          RawNtsKeRecord.AeadAlgorithmNegotiation(15),
                                          RawNtsKeRecord.NewCookieForNtpv4(new Byte[100])),
                                    Timeout: TimeSpan.FromSeconds(5));

        Assert.Multiple(() => {

            Assert.That(result.Success, Is.False,
                        "a message without End of Message is not a message");

            Assert.That(result.ErrorMessage, Is.Not.Null.And.Not.Empty);

        });

    }

    #endregion

}
