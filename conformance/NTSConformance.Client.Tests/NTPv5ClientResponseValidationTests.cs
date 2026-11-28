using System.Buffers.Binary;
using System.Security.Cryptography;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's NTPv5 client must not believe: draft-ietf-ntp-ntpv5-10 § 9 step 4, under which
/// a response is valid only when "Version is 5", "Mode is 4", "Flags are all known and no flag
/// is set that was not also set in the request", "Client cookie is equal to the client cookie
/// from the request", and "Authentication checks pass if enabled for the server" - RFC 8915
/// § 5.7's, for NTS. "The client MUST ignore all invalid responses and accept only the first
/// valid response".
///
/// <para>
/// Ignore, not fail on: each test here sends the client the response it is about first, with
/// an offset of 1000 s, and a valid one after it, with 10 s. A client that believed the first
/// measures 1000 s; one that gave up on it measures nothing; only a client that ignored it and
/// kept waiting measures the 10 s. That is the behaviour § 9 step 4 asks for, and the one that
/// matters: a forged datagram is cheap, and a client that ended its query on the first one would
/// be kept from its time by anyone who can send it a packet.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientResponseValidationTests
{

    #region Data

    private static readonly TimeSpan Forged    = TimeSpan.FromSeconds(1000);
    private static readonly TimeSpan Genuine   = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan Short     = TimeSpan.FromMilliseconds(400);

    #endregion

    #region (private) IgnoredThenValid(Invalid, NTS = false, FromAnotherPort = false)

    /// <summary>
    /// The given response, then a valid one; the client must have measured the valid one.
    /// </summary>
    private static async Task<NTPv5QueryResult> IgnoredThenValid(Func<NTPv5ClientHarness, ReceivedNtpV5Request, Byte[]>  Invalid,
                                                                  Boolean                                                NTS              = false,
                                                                  Boolean                                                FromAnotherPort  = false)
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => [
                                        new ScriptedDatagram(Invalid(harness, request), FromAnotherPort),
                                        new ScriptedDatagram(NTS
                                                                 ? harness.Sealed(request, Genuine)
                                                                 : harness.Plain (request, Genuine))
                                    ];

        var result = await harness.Query(NTS: NTS);

        Assert.That(harness.Server.ScriptErrors, Is.Empty, "the script threw");

        Assert.That(result.Success, Is.True,
                    $"the client gave up on the first response instead of ignoring it and waiting for the valid one: {result.ErrorMessage}");

        Assert.That(result.Measurement?.Offset, Is.EqualTo(Genuine),
                    result.Measurement?.Offset == Forged
                        ? "the client believed the response it should have ignored"
                        : "the client measured neither response");

        return result;

    }

    #endregion

    #region (private) Alone(Response, NTS = false)

    /// <summary>
    /// The given response and nothing after it.
    /// </summary>
    private static async Task<NTPv5QueryResult> Alone(Func<NTPv5ClientHarness, ReceivedNtpV5Request, Byte[]>  Response,
                                                      Boolean                                                NTS          = false,
                                                      Action<NTPv5ClientHarness, NTPv5QueryResult>?          AndThen      = null)
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(Response(harness, request));

        var result = await harness.Query(NTS: NTS, Timeout: Short);

        Assert.That(harness.Server.ScriptErrors, Is.Empty, "the script threw");

        AndThen?.Invoke(harness, result);

        return result;

    }

    #endregion


    #region The controls

    /// <summary>
    /// The control of every test below: the valid response alone is accepted, and measured as
    /// the 10 s it carries - T1 and T4 are the client's clock, which stands still, and T2 and T3
    /// that clock plus 10 s.
    /// </summary>
    [TestCase(false, TestName = "AValidResponse_IsAccepted_AndMeasuredExactly_Plain")]
    [TestCase(true,  TestName = "AValidResponse_IsAccepted_AndMeasuredExactly_NTS")]
    public async Task AValidResponse_IsAccepted_AndMeasuredExactly(Boolean NTS)
    {

        var result = await Alone((harness, request) => NTS
                                                           ? harness.Sealed(request, Genuine)
                                                           : harness.Plain (request, Genuine),
                                 NTS);

        Assert.Multiple(() => {
            Assert.That(result.Success,              Is.True,  result.ErrorMessage);
            Assert.That(result.IsAuthenticated,      Is.EqualTo(NTS));
            Assert.That(result.Measurement?.Offset,  Is.EqualTo(Genuine));
            Assert.That(result.Measurement?.Delay,   Is.EqualTo(TimeSpan.Zero));
            Assert.That(result.IsUsable,             Is.True, result.Unusable.ToString());
        });

    }


    /// <summary>
    /// And no response at all ends the query when the timeout does, as a timeout.
    /// </summary>
    [Test]
    public async Task NoResponse_IsATimeout()
    {

        await using var harness = new NTPv5ClientHarness();

        var result = await harness.Query(Timeout: Short);

        Assert.Multiple(() => {
            Assert.That(result.Success,        Is.False);
            Assert.That(result.ErrorCategory,  Is.EqualTo(NTSQueryErrorCategory.NTPTimeout), result.ErrorMessage);
            Assert.That(harness.Server.Requests, Has.Count.EqualTo(1), "requests sent");
        });

    }

    #endregion

    #region § 9 step 4: version, mode, client cookie

    /// <summary>
    /// § 9 step 4: "Version is 5." An NTPv4 header with NTPv5's layout, and the versions above.
    /// </summary>
    [TestCase((Byte) 0)]
    [TestCase((Byte) 3)]
    [TestCase((Byte) 4)]
    [TestCase((Byte) 6)]
    [TestCase((Byte) 7)]
    public Task AResponseOfAnotherVersion_IsIgnored(Byte Version)

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged, response => response.Version = Version));


    /// <summary>
    /// § 9 step 4: "Mode is 4." Mode 3 is what a reflected request looks like.
    /// </summary>
    [TestCase((Byte) 0)]
    [TestCase((Byte) 1)]
    [TestCase((Byte) 2)]
    [TestCase((Byte) 3)]
    [TestCase((Byte) 5)]
    [TestCase((Byte) 6)]
    [TestCase((Byte) 7)]
    public Task AResponseInAnotherMode_IsIgnored(Byte Mode)

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged, response => response.Mode = Mode));


    /// <summary>
    /// § 9 step 4: "Client cookie is equal to the client cookie from the request." A cookie one
    /// bit off, and one of all bits flipped.
    /// </summary>
    [TestCase(0x0000_0000_0000_0001UL)]
    [TestCase(0x8000_0000_0000_0000UL)]
    [TestCase(0xFFFF_FFFF_FFFF_FFFFUL)]
    public Task AResponseWithAnotherClientCookie_IsIgnored(UInt64 Xor)

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged, response => response.ClientCookie ^= Xor));


    /// <summary>
    /// § 12: an NTPv4 server's responses to NTPv5 requests "have a zero client cookie, which
    /// causes them to fail validation on the NTPv5 client and be dropped".
    /// </summary>
    [Test]
    public Task AResponseWithAZeroClientCookie_IsIgnored()

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged, response => response.ClientCookie = 0));


    /// <summary>
    /// § 9 step 4: "accept only the first valid response if more than one were received (e.g.
    /// the request or response was duplicated in the network)". Two valid responses, the first
    /// with 10 s, the second with 1000 s: the first is the one measured.
    /// </summary>
    [Test]
    public async Task OfTwoValidResponses_TheFirstIsAccepted()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(harness.Plain(request, Genuine),
                                                            harness.Plain(request, Forged));

        var result = await harness.Query();

        Assert.That(result.Measurement?.Offset, Is.EqualTo(Genuine), result.ToString());

    }

    #endregion

    #region § 9 step 4: flags

    /// <summary>
    /// § 9 step 4: "Flags are all known". § 6 defines 0x1, 0x2 and 0x4; any other is one this
    /// client does not know.
    /// </summary>
    [TestCase((UInt16) 0x0008)]
    [TestCase((UInt16) 0x0100)]
    [TestCase((UInt16) 0x8000)]
    public Task AResponseWithAnUnknownFlag_IsIgnored(UInt16 Flag)

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged, response => response.Flags |= Flag));


    /// <summary>
    /// § 9 step 4: "no flag is set that was not also set in the request" - which a plain request
    /// in the basic mode, asking for a synchronized server, sets none of: neither the
    /// Unsynchronized flag, nor the interleaved mode, nor the Authentication NAK it has nothing
    /// to be refused for. § 10 step 6 has a server drop such a response itself, because "the
    /// client does not support or is not interested in receiving this response".
    /// </summary>
    [TestCase((UInt16) 0x0001)]
    [TestCase((UInt16) 0x0002)]
    [TestCase((UInt16) 0x0004)]
    public Task AResponseWithAFlagTheRequestDidNotSet_IsIgnored(UInt16 Flag)

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged, response => response.Flags |= Flag));

    #endregion

    #region § 6: the message

    /// <summary>
    /// § 6: "the length MUST be divisible by 4 octets", the header "has 48 octets, which is the
    /// minimum length of a valid NTPv5 message", and an extension field that runs past the end
    /// of the message is no field. A response whose octets are not an NTPv5 message.
    /// </summary>
    [TestCase("TwoOctetsMore")]
    [TestCase("ShorterThanTheHeader")]
    [TestCase("AFieldPastTheEnd")]
    public Task AMalformedResponse_IsIgnored(String How)

        => IgnoredThenValid((harness, request) => {

               var octets = harness.Plain(request, Forged);

               switch (How)
               {

                   case "TwoOctetsMore":
                       return [ .. octets, 0, 0 ];

                   case "ShorterThanTheHeader":
                       return octets[..44];

                   default:
                       // The first field after the header claims 64 octets more than there are.
                       BinaryPrimitives.WriteUInt16BigEndian(octets.AsSpan(RawNtpV5Draft.HeaderLength + 2),
                                                             (UInt16) (octets.Length - RawNtpV5Draft.HeaderLength + 64));
                       return octets;

               }

           });


    /// <summary>
    /// § 6: the two bits that were NTPv4's leap indicator are reserved, and "It MUST be ignored
    /// by the receiver". A response with them set is as valid as one without - a client that
    /// refused it would refuse every server of a later draft that gives them a meaning.
    /// </summary>
    [TestCase((Byte) 1)]
    [TestCase((Byte) 3)]
    public async Task TheReservedBits_AreIgnored(Byte Reserved)
    {

        var result = await Alone((harness, request) => harness.Plain(request, Genuine, response => response.Reserved = Reserved));

        Assert.Multiple(() => {
            Assert.That(result.Success,              Is.True, result.ErrorMessage);
            Assert.That(result.Measurement?.Offset,  Is.EqualTo(Genuine));
        });

    }


    /// <summary>
    /// § 7.2: the data of a Padding field "MUST be ignored by the receiver", and so is the field:
    /// a response carrying one is valid, whatever is in it.
    /// </summary>
    [Test]
    public async Task APaddingField_IsIgnored()
    {

        var result = await Alone((harness, request) => harness.Plain(request, Genuine, response =>
                                                           response.ExtensionFields.Add(new RawNtpV5ExtensionField(RawNtpV5Draft.Padding, RandomNumberGenerator.GetBytes(16)))));

        Assert.That(result.Success, Is.True, result.ErrorMessage);

    }


    /// <summary>
    /// § 9 step 4 does not ask for the Draft Identification in a response: a server answering
    /// without it - one that, as § 7 has it, does not echo a field it was not required to - is
    /// still answering validly.
    /// </summary>
    [Test]
    public async Task AResponseWithoutTheDraftIdentification_IsValid()
    {

        var result = await Alone((harness, request) => harness.Plain(request, Genuine, response =>
                                                           response.ExtensionFields.RemoveAll(field => field.Type == RawNtpV5Draft.DraftIdentification)));

        Assert.That(result.Success, Is.True, result.ErrorMessage);

    }

    #endregion

    #region § 9 steps 3 and 4: from the server

    /// <summary>
    /// § 9 step 3 sends the request "to the server", and step 4 waits "for a valid response from
    /// the server". A response that is valid in every field but comes from another port of the
    /// same host is not from the server the request went to - an off-path sender's, which needs
    /// nothing but the client's address and port and a guessed cookie.
    /// </summary>
    [Test]
    public Task AResponseFromAnotherPort_IsIgnored()

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged), FromAnotherPort: true);

    #endregion

    #region What an invalid response leaves behind

    /// <summary>
    /// An invalid response and nothing valid after it: the query fails - not with the invalid
    /// response's time, and not as though the server had said nothing, but as a protocol
    /// failure, with the response that was refused and why.
    /// </summary>
    [TestCase("Mode3")]
    [TestCase("AnotherClientCookie")]
    [TestCase("AnUnrequestedFlag")]
    public async Task AnInvalidResponseAlone_FailsTheQuery(String How)
    {

        var result = await Alone((harness, request) => harness.Plain(request, Forged, response => {
                                                           switch (How)
                                                           {
                                                               case "Mode3":                response.Mode           = 3;    break;
                                                               case "AnotherClientCookie":  response.ClientCookie  ^= 1;    break;
                                                               default:                     response.Flags         |= 0x2;  break;
                                                           }
                                                       }));

        Assert.Multiple(() => {
            Assert.That(result.Success,        Is.False,                                "the query succeeded");
            Assert.That(result.Measurement,    Is.Null,                                 "a measurement of an invalid response");
            Assert.That(result.ErrorCategory,  Is.EqualTo(NTSQueryErrorCategory.Protocol), result.ErrorMessage);
            Assert.That(result.Validation?.IsValid, Is.False,                           "the refused response");
        });

    }

    #endregion


    #region § 9 step 4 under NTS: "Authentication checks pass"

    /// <summary>
    /// The authenticator is all that makes an NTS response the server's. A plain response to an
    /// NTS request, valid in every other respect, is one anybody could have sent.
    /// </summary>
    [Test]
    public Task AnUnauthenticatedResponseToAnNTSRequest_IsIgnored()

        => IgnoredThenValid((harness, request) => harness.Plain(request, Forged), NTS: true);


    /// <summary>
    /// RFC 8915 § 5.7: the response's authenticator is under the server-to-client key. One under
    /// the client-to-server key - which the client has too, and a reflecting attacker might hope
    /// it checks against - does not authenticate.
    /// </summary>
    [Test]
    public Task AResponseUnderTheC2SKey_IsIgnored()

        => IgnoredThenValid((harness, request) => harness.Sealed(request, Forged, Key: harness.C2SKey), NTS: true);


    /// <summary>
    /// The authenticator covers the header: a response sealed with 10 s whose transmit timestamp
    /// was moved afterwards does not authenticate - which is what an on-path attacker who wanted
    /// to move the client's clock would do.
    /// </summary>
    [Test]
    public Task AResponseChangedAfterItWasSealed_IsIgnored()

        => IgnoredThenValid((harness, request) => {
               var octets = harness.Sealed(request, Genuine);
               octets[40] ^= 0x01;
               return octets;
           }, NTS: true);


    /// <summary>
    /// RFC 8915 § 5.7: the response echoes the request's Unique Identifier. A genuine response
    /// to another request - authenticated, under the right key, but echoing another identifier -
    /// is a replayed one, and its time is the time of then.
    /// </summary>
    [Test]
    public Task AResponseToAnotherRequest_IsIgnored()

        => IgnoredThenValid((harness, request) => harness.Sealed(request, Forged, UniqueIdentifier: RandomNumberGenerator.GetBytes(32)), NTS: true);


    /// <summary>
    /// Nor is one that echoes no identifier at all.
    /// </summary>
    [Test]
    public Task AResponseWithoutTheIdentifier_IsIgnored()

        => IgnoredThenValid((harness, request) => harness.Sealed(request, Forged, EchoTheIdentifier: false), NTS: true);


    /// <summary>
    /// Nor one that echoes it after the authenticator, where it is covered by nothing: whoever
    /// saw the request can append it to an old response.
    /// </summary>
    [Test]
    public Task AResponseWithTheIdentifierOutsideTheAuthenticator_IsIgnored()

        => IgnoredThenValid((harness, request) => harness.Sealed(request,
                                                                 Forged,
                                                                 EchoTheIdentifier:   false,
                                                                 AfterAuthenticator:  [ new RawNtpV5ExtensionField(RawNtpV5Nts.UniqueIdentifier,
                                                                                                                   NTPv5ClientHarness.UniqueIdentifierOf(request)) ]),
                            NTS: true);


    /// <summary>
    /// RFC 8915 § 5.7 has a server return the new cookies encrypted, inside the authenticator.
    /// The genuine response here carries none there, and three NTS Cookie fields after it, in
    /// the clear: they are anybody's, and a client that took them would spend its next requests
    /// on cookies the server never issued - or an attacker's, that tag the client for it.
    /// </summary>
    [Test]
    public async Task CookiesOutsideTheAuthenticator_AreNotTaken()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(
                                        harness.Sealed(request,
                                                       Genuine,
                                                       NewCookies:          0,
                                                       AfterAuthenticator:  Enumerable.Range(0, 3).
                                                                                Select(_ => new RawNtpV5ExtensionField(RawNtpV5Nts.NtsCookie,
                                                                                                                       RandomNumberGenerator.GetBytes(64))).
                                                                                ToArray()));

        var result = await harness.Query(NTS: true);

        Assert.Multiple(() => {
            Assert.That(result.Success,           Is.True,                         result.ErrorMessage);
            Assert.That(result.NewCookies,        Is.Zero,                         "cookies taken from outside the authenticator");
            Assert.That(result.RemainingCookies,  Is.EqualTo(harness.Cookies.Count - 1), "the pool after one was spent");
        });

    }


    /// <summary>
    /// And the cookies inside it are: three new ones, which the pool holds afterwards, besides
    /// the seven the request did not spend.
    /// </summary>
    [Test]
    public async Task CookiesInsideTheAuthenticator_AreTaken()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(harness.Sealed(request, Genuine, NewCookies: 3));

        var result = await harness.Query(NTS: true);

        Assert.Multiple(() => {
            Assert.That(result.Success,           Is.True,                               result.ErrorMessage);
            Assert.That(result.NewCookies,        Is.EqualTo(3));
            Assert.That(result.RemainingCookies,  Is.EqualTo(harness.Cookies.Count - 1 + 3));
        });

    }

    #endregion

    #region § 6 and § 11: the Authentication NAK

    /// <summary>
    /// § 6: an NTS request sets 0x4 because "the client wants to receive a response even when the
    /// server fails to authenticate the request", and a server "setting this bit SHOULD also set
    /// the stratum of the message to 0". Such a response carries no authenticator - the server
    /// could not read the cookie its keys are in - and so it is no time to believe: the query
    /// fails, and it fails as a NAK, which is what tells the client its cookies are gone.
    /// </summary>
    [Test]
    public async Task AnAuthenticationNAK_IsNoTime_ButIsReportedAsANAK()
    {

        var result = await Alone((harness, request) => Nak(harness, request), NTS: true);

        Assert.Multiple(() => {
            Assert.That(result.Success,              Is.False,                                          "the NAK was accepted as time");
            Assert.That(result.Measurement,          Is.Null,                                           "a measurement of the NAK");
            Assert.That(result.IsAuthenticationNAK,  Is.True,                                           result.ErrorMessage);
            Assert.That(result.ErrorCategory,        Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
        });

    }


    /// <summary>
    /// A NAK is unauthenticated, and all that ties it to the request is the Unique Identifier it
    /// echoes, which only those who saw the request know. One that echoes another identifier is
    /// an off-path sender's - and believing it would let anybody throw away a client's cookies
    /// with one datagram. It is not taken for a NAK, and the cookies stay.
    /// </summary>
    [Test]
    public async Task ANAKThatDoesNotEchoTheIdentifier_IsNotBelieved()
    {

        await Alone((harness, request) => Nak(harness, request, UniqueIdentifier: RandomNumberGenerator.GetBytes(32)),
                    NTS:      true,
                    AndThen:  (harness, result) => Assert.Multiple(() => {
                                                       Assert.That(result.Success,              Is.False);
                                                       Assert.That(result.IsAuthenticationNAK,  Is.False, "a NAK for another request was believed");
                                                       Assert.That(harness.Client.AvailableCookieCount,
                                                                   Is.EqualTo(harness.Cookies.Count - 1),
                                                                   "the forged NAK cost the client its cookies");
                                                   }));

    }


    /// <summary>
    /// And a NAK followed by a valid response is overtaken by it: the response authenticates, so
    /// whatever the NAK said, the server could read the request after all.
    /// </summary>
    [Test]
    public Task ANAKFollowedByAValidResponse_IsOvertakenByIt()

        => IgnoredThenValid((harness, request) => Nak(harness, request), NTS: true);


    /// <summary>
    /// An Authentication NAK as § 6 and § 7.3 describe one: the flag, stratum 0, no
    /// authenticator, and - as for NTPv4 in RFC 8915 § 5.7 - the Unique Identifier of the
    /// request.
    /// </summary>
    private static Byte[] Nak(NTPv5ClientHarness    Harness,
                              ReceivedNtpV5Request  Request,
                              Byte[]?               UniqueIdentifier = null)

        => Harness.Plain(Request, Forged, response => {
               response.Flags    = RawNtpV5Draft.AuthenticationNAK;
               response.Stratum  = 0;
               response.ExtensionFields.Add(new RawNtpV5ExtensionField(RawNtpV5Nts.UniqueIdentifier,
                                                                       UniqueIdentifier ?? NTPv5ClientHarness.UniqueIdentifierOf(Request)));
           });

    #endregion

}
