using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// The client half of the NTPv5 interleaved mode, draft-ietf-ntp-ntpv5-10 § 8, against a
/// scripted server that plays Figure 15 and the cases around it.
///
/// <para>
/// § 8: "In the basic mode, the transmit timestamp in the server response corresponds to the
/// message which contains the timestamp itself. In the interleaved mode it corresponds to a
/// previous response identified by the server cookie." What the mode asks of a client is
/// memory: it has to hold the T1, T2 and T4 of the previous exchange until the T3 that belongs
/// to them arrives one response later, and send back the server cookie that names it. Unlike
/// RFC 9769's NTPv4 mode, NTPv5 says which mode a response is in by its Interleaved flag.
/// </para>
/// <para>
/// The client's clock stands still within an exchange and moves 64 s between two, so that each
/// exchange has a T1 of its own and a measurement shows which exchange its timestamps are from.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientInterleavedTests
{

    #region Data

    private static readonly TimeSpan Offset   = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan Poll     = TimeSpan.FromSeconds(64);
    private static readonly TimeSpan Short    = TimeSpan.FromMilliseconds(300);

    private const UInt16 Interleaved = RawNtpV5Draft.InterleavedMode;

    #endregion

    #region (private) helpers

    /// <summary>
    /// A client in the interleaved mode against a server answering each request with the next
    /// of the given answers - null for none at all.
    /// </summary>
    private static NTPv5ClientHarness Harness(Int32? MaxUnansweredRequests = null)
        => new (Interleaved: new NTPv5InterleavedAssociation(MaxUnansweredRequests));


    /// <summary>
    /// A valid response to the request, received at the client's clock plus 10 s and sent at
    /// the given transmit time, with the given server cookie and flags.
    /// </summary>
    private static Byte[] Response(NTPv5ClientHarness    Harness,
                                   ReceivedNtpV5Request  Request,
                                   UInt64                ServerCookie,
                                   DateTime              Transmit,
                                   UInt16                Flags = 0)
    {

        var response = RawNtpV5Responses.Answer(Request.Packet!, Harness.Now + Offset, Transmit);

        response.ServerCookie  = ServerCookie;
        response.Flags         = Flags;

        return response.Write();

    }


    /// <summary>
    /// Queries in turn, the clock moving one poll after each; the script answers query i with
    /// <paramref name="Answers"/>[i].
    /// </summary>
    private static async Task<NTPv5QueryResult[]> Exchanges(NTPv5ClientHarness                                             Harness,
                                                            params Func<ReceivedNtpV5Request, Byte[]?>[]                   Answers)
    {

        var index = -1;

        Harness.Script = request => {
            var answer = Answers[Interlocked.Increment(ref index)](request);
            return answer is null ? [] : NTPv5ClientHarness.Send(answer);
        };

        var results = new List<NTPv5QueryResult>();

        foreach (var _ in Answers)
        {
            results.Add(await Harness.Query(Timeout: Short));
            Harness.Clock.Advance(Poll);
        }

        Assert.That(Harness.Server.ScriptErrors, Is.Empty, "the script threw");

        return results.ToArray();

    }

    #endregion


    #region § 9 step 2: the request

    /// <summary>
    /// § 9 step 2: "The interleaved mode flag requests the server to save the transmit timestamp
    /// of the response and provide the transmit timestamp of a previous response corresponding
    /// to the server cookie (if not zero)", and the server cookie is "zero if no such response
    /// was received yet". The first request of an interleaved association: flag 0x2, cookie 0.
    /// </summary>
    [Test]
    public async Task TheFirstRequest_AsksForTheInterleavedMode_WithAZeroServerCookie()
    {

        await using var harness = Harness();

        await Exchanges(harness, request => Response(harness, request, 0x5151, harness.Now + Offset));

        var request = harness.FirstRequest.Packet!;

        Assert.Multiple(() => {
            Assert.That(request.Flags & Interleaved,  Is.EqualTo(Interleaved), $"flags 0x{request.Flags:x4}");
            Assert.That(request.ServerCookie,         Is.Zero,                  "the server cookie");
        });

    }


    /// <summary>
    /// § 9 step 2: the server cookie "is set to the server cookie from the last valid response".
    /// Each request carries the cookie of the response before it.
    /// </summary>
    [Test]
    public async Task EachRequest_CarriesTheServerCookieOfTheLastValidResponse()
    {

        await using var harness = Harness();

        await Exchanges(harness,
                        request => Response(harness, request, 0x1111, harness.Now + Offset),
                        request => Response(harness, request, 0x2222, harness.Now + Offset, Interleaved),
                        request => Response(harness, request, 0x3333, harness.Now + Offset, Interleaved));

        Assert.That(harness.Server.Requests.Select(request => request.Packet!.ServerCookie),
                    Is.EqualTo(new UInt64[] { 0, 0x1111, 0x2222 }));

    }


    /// <summary>
    /// "the last valid response": the server cookie of a response the client had to ignore is
    /// not one it sends back - an off-path sender's cookie would otherwise decide which of the
    /// server's saved timestamps the client asks for.
    /// </summary>
    [Test]
    public async Task TheCookieOfAnInvalidResponse_IsNotSentBack()
    {

        await using var harness = Harness();

        harness.Script = request => {

            if (harness.Server.Requests.Count > 1)
                return [];

            var forged = RawNtpV5Responses.Answer(request.Packet!, harness.Now + Offset);
            forged.ServerCookie  = 0x6666;
            forged.ClientCookie ^= 1;

            return NTPv5ClientHarness.Send(forged.Write(),
                                           Response(harness, request, 0x1111, harness.Now + Offset));

        };

        Assert.That((await harness.Query()).Success, Is.True, "the first query");

        await harness.Query(Timeout: Short);

        Assert.That(harness.Server.Requests[1].Packet!.ServerCookie, Is.EqualTo(0x1111UL));

    }


    /// <summary>
    /// § 9 step 2: zero again where "the transmit timestamp of that response would no longer be
    /// useful to the client (e.g. after missing too many responses)". With two misses allowed:
    /// after two the cookie is still sent, after three it is zero.
    /// </summary>
    [Test]
    public async Task AfterTooManyMissedResponses_TheServerCookieIsZeroAgain()
    {

        await using var harness = Harness(MaxUnansweredRequests: 2);

        await Exchanges(harness,
                        request => Response(harness, request, 0x1111, harness.Now + Offset),
                        _       => null,
                        _       => null,
                        _       => null,
                        request => Response(harness, request, 0x5555, harness.Now + Offset));

        Assert.That(harness.Server.Requests.Select(request => request.Packet!.ServerCookie),
                    Is.EqualTo(new UInt64[] { 0, 0x1111, 0x1111, 0x1111, 0 }),
                    "the server cookies sent");

    }


    /// <summary>
    /// And outside the interleaved mode none at all: "Server cookie is set only in the
    /// interleaved mode", however many responses brought one.
    /// </summary>
    [Test]
    public async Task InTheBasicMode_NoServerCookieIsSentBack()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(Response(harness, request, 0x1111, harness.Now + Offset));

        await harness.Query();
        await harness.Query();

        Assert.Multiple(() => {
            Assert.That(harness.Server.Requests.Select(request => request.Packet!.ServerCookie), Is.All.Zero,         "the server cookies sent");
            Assert.That(harness.Server.Requests.Select(request => request.Packet!.Flags & Interleaved), Is.All.Zero, "the Interleaved flag");
        });

    }

    #endregion

    #region § 8 and Figure 15: the measurements

    /// <summary>
    /// Figure 15, the first two exchanges: a basic response with the software timestamp t3',
    /// measured as (t1, t2, t3', t4); then an interleaved one carrying t3, the accurate transmit
    /// time of that first response, measured as (t1, t2, t3, t4) - the first exchange's T1, T2
    /// and T4 with the T3 that belongs to them, and nothing of the second exchange's own.
    /// </summary>
    [Test]
    public async Task AnInterleavedResponse_CompletesThePreviousExchange()
    {

        await using var harness = Harness();

        var t1       = harness.Now;
        var t2       = t1 + Offset;
        var t3Soft   = t2 + TimeSpan.FromMilliseconds(3);
        var t3       = t2 + TimeSpan.FromMilliseconds(1);

        var results  = await Exchanges(harness,
                                       request => Response(harness, request, 0x1111, t3Soft),
                                       request => Response(harness, request, 0x2222, t3, Interleaved));

        Assert.That(results.Select(result => result.Success), Is.All.True, String.Join("; ", results.Select(result => result.ErrorMessage)));

        var first  = results[0].Measurement;
        var second = results[1].Measurement;

        Assert.Multiple(() => {

            Assert.That(first?.Interleaved,   Is.False,                                          "the first measurement");
            Assert.That(first?.T3,            Is.EqualTo(t3Soft),                                "the first T3");
            Assert.That(first?.Offset,        Is.EqualTo(Offset + TimeSpan.FromMilliseconds(1.5)), "the first offset");

            Assert.That(second?.Interleaved,  Is.True,                                           "the second measurement");
            Assert.That(second?.T1,           Is.EqualTo(t1),                                    "the second T1, which is the first exchange's");
            Assert.That(second?.T2,           Is.EqualTo(t2),                                    "the second T2, which is the first exchange's");
            Assert.That(second?.T3,           Is.EqualTo(t3),                                    "the second T3, the accurate one");
            Assert.That(second?.T4,           Is.EqualTo(t1),                                    "the second T4, which is the first exchange's");
            Assert.That(second?.Offset,       Is.EqualTo(Offset + TimeSpan.FromMilliseconds(0.5)), "the second offset");

        });

    }


    /// <summary>
    /// Figure 15, the third exchange: "the client request is in the interleaved mode, but the
    /// server response is in the basic mode, because the server no longer had the timestamp",
    /// and the client uses "(t9, t10, t11', t12)" - the exchange's own timestamps.
    /// </summary>
    [Test]
    public async Task ABasicResponseToAnInterleavedRequest_IsAMeasurementOfItsOwn()
    {

        await using var harness = Harness();

        var t9 = default(DateTime);

        var results = await Exchanges(harness,
                                      request => Response(harness, request, 0x1111, harness.Now + Offset),
                                      request => {
                                          t9 = harness.Now;
                                          return Response(harness, request, 0x2222, harness.Now + Offset + TimeSpan.FromMilliseconds(2));
                                      });

        var second = results[1].Measurement;

        Assert.Multiple(() => {
            Assert.That(results[1].Success,  Is.True,                                           results[1].ErrorMessage);
            Assert.That(second?.Interleaved, Is.False,                                          "the measurement");
            Assert.That(second?.T1,          Is.EqualTo(t9),                                    "its T1, the exchange's own");
            Assert.That(second?.Offset,      Is.EqualTo(Offset + TimeSpan.FromMilliseconds(1)), "its offset");
        });

    }


    /// <summary>
    /// A lost response between the two: the request after it still names the last valid
    /// response by its cookie, and the interleaved answer to it completes that exchange - not
    /// the lost one, whose T2 the client never had.
    /// </summary>
    [Test]
    public async Task AfterALostResponse_TheInterleavedAnswerCompletesTheLastValidExchange()
    {

        await using var harness = Harness();

        var t1       = harness.Now;
        var t3       = t1 + Offset + TimeSpan.FromMilliseconds(1);

        var results  = await Exchanges(harness,
                                       request => Response(harness, request, 0x1111, t1 + Offset + TimeSpan.FromMilliseconds(3)),
                                       _       => null,
                                       request => Response(harness, request, 0x3333, t3, Interleaved));

        var third = results[2].Measurement;

        Assert.Multiple(() => {
            Assert.That(results[1].Success,   Is.False,                                          "the lost one");
            Assert.That(results[2].Success,   Is.True,                                           results[2].ErrorMessage);
            Assert.That(third?.Interleaved,   Is.True,                                           "the measurement");
            Assert.That(third?.T1,            Is.EqualTo(t1),                                    "its T1, the first exchange's");
            Assert.That(third?.Offset,        Is.EqualTo(Offset + TimeSpan.FromMilliseconds(0.5)), "its offset");
        });

    }


    /// <summary>
    /// An interleaved answer to a request that named no previous response - the first one,
    /// with a server cookie of zero - completes nothing: § 10 has a server set the flag only
    /// where "a transmit timestamp is associated with the server cookie", and there is no
    /// exchange of this client's that its transmit timestamp could belong to. It is valid, as the
    /// request set the flag, and it is no measurement.
    /// </summary>
    [Test]
    public async Task AnInterleavedAnswerToTheFirstRequest_MeasuresNothing()
    {

        await using var harness = Harness();

        var results = await Exchanges(harness,
                                      request => Response(harness, request, 0x1111, harness.Now + Offset, Interleaved));

        Assert.Multiple(() => {
            Assert.That(results[0].Success,      Is.True,  results[0].ErrorMessage);
            Assert.That(results[0].Measurement,  Is.Null,  $"a measurement of {results[0].Measurement}");
            Assert.That(results[0].IsUsable,     Is.False);
        });

    }


    /// <summary>
    /// Nor does one after the cookie was given up: the request after too many misses sends
    /// zero again, and an interleaved answer to it cannot complete the exchange of long ago.
    /// </summary>
    [Test]
    public async Task AnInterleavedAnswerAfterTheCookieWasGivenUp_MeasuresNothing()
    {

        await using var harness = Harness(MaxUnansweredRequests: 1);

        var results = await Exchanges(harness,
                                      request => Response(harness, request, 0x1111, harness.Now + Offset),
                                      _       => null,
                                      _       => null,
                                      request => Response(harness, request, 0x4444, harness.Now + Offset, Interleaved));

        Assert.Multiple(() => {
            Assert.That(harness.Server.Requests[3].Packet!.ServerCookie, Is.Zero, "the cookie sent after two misses");
            Assert.That(results[3].Success,      Is.True, results[3].ErrorMessage);
            Assert.That(results[3].Measurement,  Is.Null, $"a measurement of {results[3].Measurement}");
        });

    }


    /// <summary>
    /// Under NTS the interleaved mode is the same, with the flags and the server cookie in the
    /// header the authenticator covers: two authenticated exchanges, the second completing the
    /// first.
    /// </summary>
    [Test]
    public async Task UnderNTS_AnInterleavedResponse_CompletesThePreviousExchange()
    {

        await using var harness = Harness();

        var t1  = harness.Now;
        var t3  = t1 + Offset + TimeSpan.FromMilliseconds(1);

        var index = -1;

        harness.Script = request => {

            var exchange = Interlocked.Increment(ref index);

            return NTPv5ClientHarness.Send(harness.Sealed(request,
                                                          Offset,
                                                          response => {
                                                              response.ServerCookie       = exchange == 0 ? 0x1111UL : 0x2222UL;
                                                              response.Flags              = exchange == 0 ? (UInt16) 0 : Interleaved;
                                                              response.TransmitTimestamp  = RawNtpV5Responses.ToTimestamp(exchange == 0
                                                                                                                              ? harness.Now + Offset + TimeSpan.FromMilliseconds(3)
                                                                                                                              : t3).Timestamp;
                                                          }));

        };

        var first   = await harness.Query(NTS: true);
        harness.Clock.Advance(Poll);
        var second  = await harness.Query(NTS: true);

        Assert.Multiple(() => {
            Assert.That(harness.Server.Requests[1].Packet!.Flags,         Is.EqualTo(Interleaved | RawNtpV5Draft.AuthenticationNAK), "the flags of the second request");
            Assert.That(harness.Server.Requests[1].Packet!.ServerCookie,  Is.EqualTo(0x1111UL),        "its server cookie");
            Assert.That(first.IsAuthenticated,                            Is.True,                     first.ErrorMessage);
            Assert.That(second.IsAuthenticated,                           Is.True,                     second.ErrorMessage);
            Assert.That(second.Measurement?.Interleaved,                  Is.True,                     "the second measurement");
            Assert.That(second.Measurement?.T1,                           Is.EqualTo(t1),              "its T1");
            Assert.That(second.Measurement?.T3,                           Is.EqualTo(t3),              "its T3");
        });

    }

    #endregion

}
