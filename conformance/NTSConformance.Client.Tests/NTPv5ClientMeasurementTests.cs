using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's NTPv5 client makes of a valid response: whether it is usable for
/// synchronization (draft-ietf-ntp-ntpv5-10 § 9 step 5), its timestamps placed in their era
/// (step 6), the offset and delay of § 8 (step 7) with the network's corrections of § 7.7 where
/// it asked for them, and the minimum polling interval of its poll field (§ 6, § 9).
///
/// <para>
/// Valid and usable are two different things, and § 9 keeps them apart on purpose: a valid
/// response from an unsynchronized server is the server's own, and still not time to set a
/// clock by. So every response here is valid, the query succeeds, and what is checked is what
/// the client says about it.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientMeasurementTests
{

    #region Data

    private static readonly TimeSpan Offset = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The first instant of era 1, 2036-02-07T06:28:16Z.
    /// </summary>
    private static readonly DateTimeOffset Era1 = new (RawNtpV5Responses.Epoch.AddSeconds(RawNtpV5Responses.SecondsPerEra), TimeSpan.Zero);

    #endregion

    #region (private) Answered(Change, ...)

    /// <summary>
    /// One query, answered with a valid response that has the given change.
    /// </summary>
    private static async Task<NTPv5QueryResult> Answered(Action<RawNtpV5Packet>?                Change                = null,
                                                         TimeSpan?                              Transmit              = null,
                                                         Boolean                                AcceptUnsynchronized  = false,
                                                         Boolean                                RequestCorrection     = false,
                                                         NTPv5UsabilityLimits?                  Limits                = null,
                                                         NTPv5CorrectionParameters?             CorrectionParameters  = null,
                                                         DateTimeOffset?                        Now                   = null,
                                                         DateTime?                              Receive               = null,
                                                         IEnumerable<RawNtpV5ExtensionField>?   Fields                = null)
    {

        await using var harness = new NTPv5ClientHarness(Now: Now);

        harness.Script = request => {

            var response = Receive is DateTime receive
                               ? RawNtpV5Responses.Answer(request.Packet!, receive, receive + (Transmit ?? TimeSpan.Zero))
                               : harness.Answer(request, Offset, Transmit: Transmit);

            Change?.Invoke(response);
            response.ExtensionFields.AddRange(Fields ?? []);

            return NTPv5ClientHarness.Send(response.Write());

        };

        var result = await harness.Query(AcceptUnsynchronized:  AcceptUnsynchronized,
                                         RequestCorrection:     RequestCorrection,
                                         Limits:                Limits,
                                         CorrectionParameters:  CorrectionParameters);

        Assert.That(result.Success, Is.True, $"the response should be valid: {result.ErrorMessage}");

        return result;

    }

    #endregion


    #region § 9 step 5: usable for synchronization

    /// <summary>
    /// The control: the response of <see cref="RawNtpV5Responses.Answer"/> - stratum 1, root
    /// delay and dispersion of a millisecond, the timescale asked for, both timestamps set - is
    /// usable.
    /// </summary>
    [Test]
    public async Task TheControl_IsUsable()
    {

        var result = await Answered();

        Assert.Multiple(() => {
            Assert.That(result.Unusable,  Is.EqualTo(NTPv5Unusable.None));
            Assert.That(result.IsUsable,  Is.True);
        });

    }


    /// <summary>
    /// § 9 step 5: "Unsynchronized flag is not set." A client that asked for an answer even from
    /// an unsynchronized server (§ 6, flag 0x1) gets one, valid - and not usable.
    /// </summary>
    [Test]
    public async Task AnUnsynchronizedServer_IsNotUsable()
    {

        var result = await Answered(response => response.Flags |= RawNtpV5Draft.Unsynchronized,
                                    AcceptUnsynchronized: true);

        Assert.Multiple(() => {
            Assert.That(result.Unusable,  Is.EqualTo(NTPv5Unusable.Unsynchronized));
            Assert.That(result.IsUsable,  Is.False);
        });

    }


    /// <summary>
    /// § 9 step 5: "Stratum is not equal to 0 and not larger than 15, or a different configured
    /// maximum value." Both ends of the range, and past either.
    /// </summary>
    [TestCase((Byte)   0, false)]
    [TestCase((Byte)   1, true)]
    [TestCase((Byte)  15, true)]
    [TestCase((Byte)  16, false)]
    [TestCase((Byte) 255, false)]
    public async Task TheStratum_IsUsableFrom1To15(Byte Stratum, Boolean Usable)
    {

        var result = await Answered(response => response.Stratum = Stratum);

        Assert.That(result.Unusable, Is.EqualTo(Usable ? NTPv5Unusable.None : NTPv5Unusable.Stratum));

    }


    /// <summary>
    /// "... or a different configured maximum value": with 3 configured, stratum 4 is not usable.
    /// </summary>
    [TestCase((Byte) 3, true)]
    [TestCase((Byte) 4, false)]
    public async Task TheStratum_IsUsableUpToAConfiguredMaximum(Byte Stratum, Boolean Usable)
    {

        var result = await Answered(response => response.Stratum = Stratum,
                                    Limits: new NTPv5UsabilityLimits(MaximumStratum: 3));

        Assert.That(result.Unusable, Is.EqualTo(Usable ? NTPv5Unusable.None : NTPv5Unusable.Stratum));

    }


    /// <summary>
    /// § 9 step 5: "Root delay is not larger than an implementation-specific or configured
    /// maximum acceptable value", and the same of the root dispersion. With a second
    /// configured: half a second usable, two not - and the infinity of § 6's time32, all bits
    /// set, never, whatever the maximum.
    /// </summary>
    [TestCase(true,  0.5,  true)]
    [TestCase(true,  2.0,  false)]
    [TestCase(true,  null, false)]
    [TestCase(false, 0.5,  true)]
    [TestCase(false, 2.0,  false)]
    [TestCase(false, null, false)]
    public async Task TheRootDelayAndDispersion_AreUsableUpToTheirMaximum(Boolean Delay, Double? Seconds, Boolean Usable)
    {

        var value  = Seconds is Double seconds
                         ? RawTime32.RoundedUp(TimeSpan.FromSeconds(seconds))
                         : RawTime32.Infinity;

        var result = await Answered(response => {
                                        if (Delay) response.RootDelay      = value;
                                        else       response.RootDispersion = value;
                                    },
                                    Limits: new NTPv5UsabilityLimits(MaximumRootDelay:       Seconds is null ? TimeSpan.FromDays(1) : TimeSpan.FromSeconds(1),
                                                                     MaximumRootDispersion:  Seconds is null ? TimeSpan.FromDays(1) : TimeSpan.FromSeconds(1)));

        Assert.That(result.Unusable,
                    Is.EqualTo(Usable ? NTPv5Unusable.None : Delay ? NTPv5Unusable.RootDelay : NTPv5Unusable.RootDispersion));

    }


    /// <summary>
    /// § 9 step 5: "Timescale is equal to the requested timescale. If the timescale is
    /// different, the client can switch to the provided timescale, convert the timestamps ...,
    /// or ignore the response." What it cannot do is take TAI for UTC: 37 seconds of error,
    /// silently. A response in TAI to a request in UTC is not usable as it is.
    /// </summary>
    [TestCase(RawNtpV5Draft.TAI)]
    [TestCase(RawNtpV5Draft.UT1)]
    [TestCase((Byte) 42)]
    public async Task AnotherTimescale_IsNotUsableAsItIs(Byte Timescale)
    {

        var result = await Answered(response => response.Timescale = Timescale);

        Assert.Multiple(() => {
            Assert.That(result.Unusable,  Is.EqualTo(NTPv5Unusable.Timescale));
            Assert.That(result.IsUsable,  Is.False);
        });

    }


    /// <summary>
    /// § 9 step 5: "Receive timestamp and transmit timestamp are both valid (i.e. not equal to 0)."
    /// </summary>
    [TestCase(true,  TestName = "AZeroTimestamp_IsNotUsable_Receive")]
    [TestCase(false, TestName = "AZeroTimestamp_IsNotUsable_Transmit")]
    public async Task AZeroTimestamp_IsNotUsable(Boolean Receive)
    {

        var result = await Answered(response => {
                                        if (Receive) response.ReceiveTimestamp  = 0;
                                        else         response.TransmitTimestamp = 0;
                                    });

        Assert.Multiple(() => {
            Assert.That(result.Unusable,  Is.EqualTo(NTPv5Unusable.MissingTimestamps));
            Assert.That(result.IsUsable,  Is.False);
        });

    }

    #endregion

    #region § 9 steps 6 and 7: the timestamps and what they measure

    /// <summary>
    /// § 9 step 7 and § 8: the offset is ((T2 - T1) + (T3 - T4)) / 2 and the delay
    /// |(T4 - T1) - (T3 - T2)|. With the client's clock standing still, T1 = T4, and a server
    /// that took 4 ms between T2 and T3: an offset of 10.002 s and a delay of 4 ms.
    /// </summary>
    [Test]
    public async Task TheOffsetAndDelay_AreThoseOfSection8()
    {

        var result = await Answered(Transmit: TimeSpan.FromMilliseconds(4));

        Assert.Multiple(() => {
            Assert.That(result.Measurement?.Offset, Is.EqualTo(Offset + TimeSpan.FromMilliseconds(2)));
            Assert.That(result.Measurement?.Delay,  Is.EqualTo(TimeSpan.FromMilliseconds(4)));
        });

    }


    /// <summary>
    /// § 9 step 6: a client that counts seconds in more than 32 bits "SHOULD expand the
    /// timestamps with the provided NTP era". A client in 2036, past the first rollover, and a
    /// server 10 s ahead of it, in era 1: 10 s, not the 136 years of an era taken for 0.
    /// </summary>
    [Test]
    public async Task InEra1_TheTimestampsAreExpandedByTheEra()
    {

        var now    = Era1 + TimeSpan.FromHours(1);
        var result = await Answered(Now: now, Receive: now.UtcDateTime + Offset);

        Assert.That(result.Measurement?.Offset, Is.EqualTo(Offset), result.ToString());

    }


    /// <summary>
    /// § 6 gives the era of the receive timestamp; the transmit timestamp is a moment later, and
    /// across a rollover it is in the next era with the same Era field. A server that received
    /// the request a millisecond before the rollover and answered a millisecond after it, to a
    /// client whose clock reads the rollover itself: an offset of 0 and a delay of 2 ms - not the
    /// 68 years of a transmit timestamp placed at the start of era 0.
    /// </summary>
    [Test]
    public async Task ATransmitTimestampAcrossTheRollover_IsInTheNextEra()
    {

        var result = await Answered(Now:      Era1,
                                    Receive:  Era1.UtcDateTime - TimeSpan.FromMilliseconds(1),
                                    Transmit: TimeSpan.FromMilliseconds(2));

        Assert.Multiple(() => {
            Assert.That(result.Measurement?.Offset, Is.EqualTo(TimeSpan.Zero),                 result.ToString());
            Assert.That(result.Measurement?.Delay,  Is.EqualTo(TimeSpan.FromMilliseconds(2)), result.ToString());
        });

    }

    #endregion

    #region § 7.7 and § 8: corrections

    /// <summary>
    /// § 7.7: a Correction field, its corrections signed nanoseconds in 48.16 fixed point.
    /// </summary>
    private static RawNtpV5ExtensionField Correction(TimeSpan Origin, TimeSpan Delay)

        => RawNtpV5Fields.Correction(OriginCorrection:  (Int64) (Origin.Ticks * 100) << 16,
                                     DelayCorrection:   (Int64) (Delay. Ticks * 100) << 16);


    /// <summary>
    /// The exchange the corrections below apply to: T3 10 ms after T2, so an offset of 10.005 s
    /// and a delay of 10 ms.
    /// </summary>
    private static readonly TimeSpan ServerTime = TimeSpan.FromMilliseconds(10);


    /// <summary>
    /// § 8: offset_c = offset + (Cd - Co) / 2 and delay_c = delay - (Cd + Co - Drx - Dtx) * (1 -
    /// FC), and "The client SHOULD use the corrected values". With an origin correction of 2 ms,
    /// a delay correction of 4 ms, and no frame times or frequency error: 10.006 s and 4 ms.
    /// </summary>
    [Test]
    public async Task TheCorrections_AreAppliedAsSection8Has()
    {

        var result = await Answered(Transmit:              ServerTime,
                                    RequestCorrection:     true,
                                    CorrectionParameters:  new NTPv5CorrectionParameters(FrequencyError: 0),
                                    Fields:                [ Correction(TimeSpan.FromMilliseconds(2), TimeSpan.FromMilliseconds(4)) ]);

        Assert.Multiple(() => {
            Assert.That(result.Measurement?.Offset,           Is.EqualTo(Offset + TimeSpan.FromMilliseconds(5)),  "the uncorrected offset");
            Assert.That(result.Measurement?.Delay,            Is.EqualTo(ServerTime),                              "the uncorrected delay");
            Assert.That(result.Measurement?.CorrectedOffset,  Is.EqualTo(Offset + TimeSpan.FromMilliseconds(6)),  "offset_c");
            Assert.That(result.Measurement?.CorrectedDelay,   Is.EqualTo(TimeSpan.FromMilliseconds(4)),           "delay_c");
            Assert.That(result.Measurement?.BestOffset,       Is.EqualTo(result.Measurement?.CorrectedOffset),    "the offset to synchronize to");
        });

    }


    /// <summary>
    /// § 8 again, with a frequency error of 100 ppm and a receive frame time of 2 µs, and no
    /// transmit frame time - which "If unknown, it SHOULD be set to Drx": delay_c = 10 ms -
    /// (6 ms - 4 µs) * 0.9999 = 4.0046 ms, to the 100 ns of a tick.
    /// </summary>
    [Test]
    public async Task TheFrameTimesAndTheFrequencyError_AreTakenIntoAccount()
    {

        var result = await Answered(Transmit:              ServerTime,
                                    RequestCorrection:     true,
                                    CorrectionParameters:  new NTPv5CorrectionParameters(FrequencyError:    100e-6,
                                                                                         ReceiveFrameTime:  TimeSpan.FromTicks(20)),
                                    Fields:                [ Correction(TimeSpan.FromMilliseconds(2), TimeSpan.FromMilliseconds(4)) ]);

        Assert.That(result.Measurement?.CorrectedDelay?.Ticks,
                    Is.EqualTo(40046).Within(1),
                    $"delay_c of {result.Measurement?.CorrectedDelay?.Ticks} ticks");

    }


    /// <summary>
    /// § 8: "The corrected values MUST NOT be accepted if any of delay_c, Co and Cd is negative",
    /// "to limit the error in case the corrections are provided by faulty devices or on-path
    /// attackers" - the Correction is outside any authentication, and § 7.7 has clients "validate
    /// the corrections before their application". A negative origin correction, a negative delay
    /// correction, and corrections of 20 ms each against a delay of 10 ms: the uncorrected values
    /// stand.
    /// </summary>
    [TestCase(-2.0,  4.0)]
    [TestCase( 2.0, -4.0)]
    [TestCase(20.0, 20.0)]
    public async Task CorrectionsThatWouldMakeAnythingNegative_AreNotAccepted(Double Origin, Double Delay)
    {

        var result = await Answered(Transmit:              ServerTime,
                                    RequestCorrection:     true,
                                    CorrectionParameters:  new NTPv5CorrectionParameters(FrequencyError: 0),
                                    Fields:                [ Correction(TimeSpan.FromMilliseconds(Origin), TimeSpan.FromMilliseconds(Delay)) ]);

        Assert.Multiple(() => {
            Assert.That(result.Measurement?.CorrectedOffset,  Is.Null,                                            "offset_c was accepted");
            Assert.That(result.Measurement?.CorrectedDelay,   Is.Null,                                            "delay_c was accepted");
            Assert.That(result.Measurement?.BestOffset,       Is.EqualTo(Offset + TimeSpan.FromMilliseconds(5)), "the offset to synchronize to");
        });

    }


    /// <summary>
    /// § 7.7: a delay correction of "one in all bits, except the most significant" says that the
    /// correction "is too big to be represented". It is no number of nanoseconds, and applying
    /// it as one would move the offset by 2^47 ns - a day and a half.
    /// </summary>
    /// <remarks>
    /// Taken as a number it would also make delay_c negative, which § 8 refuses on its own: a
    /// client without a check of the overflow passes this test too. It is here for the client
    /// that drops the check of delay_c, and for what the draft says the value means.
    /// </remarks>
    [Test]
    public async Task ACorrectionTooBigToBeRepresented_IsNotApplied()
    {

        var result = await Answered(Transmit:           ServerTime,
                                    RequestCorrection:  true,
                                    Fields:             [ RawNtpV5Fields.Correction(DelayCorrection: Int64.MaxValue) ]);

        Assert.That(result.Measurement?.CorrectedOffset, Is.Null, $"offset_c of {result.Measurement?.CorrectedOffset}");

    }


    /// <summary>
    /// § 7.7: "Clients MUST ignore an unexpected Correction Extension Field in the response, i.e.
    /// if it was not included in the request." A client that did not ask, and a response with
    /// corrections it could otherwise accept.
    /// </summary>
    [Test]
    public async Task AnUnexpectedCorrection_IsIgnored()
    {

        var result = await Answered(Transmit:  ServerTime,
                                    Fields:    [ Correction(TimeSpan.FromMilliseconds(2), TimeSpan.FromMilliseconds(4)) ]);

        Assert.Multiple(() => {
            Assert.That(result.Measurement?.Correction,       Is.Null, "the correction was read");
            Assert.That(result.Measurement?.CorrectedOffset,  Is.Null, "the correction was applied");
        });

    }


    /// <summary>
    /// Under NTS the Correction comes after the authenticator - it "MUST be the last extension
    /// field", and the network fills it in, so no seal can cover it. It is still the client's to
    /// apply: valid, checked by § 8, and not refused for being outside the authenticator.
    /// </summary>
    [Test]
    public async Task UnderNTS_TheCorrectionAfterTheAuthenticator_IsApplied()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(
                                        harness.Sealed(request,
                                                       Offset,
                                                       response => response.TransmitTimestamp = RawNtpV5Responses.ToTimestamp(harness.Now + Offset + ServerTime).Timestamp,
                                                       AfterAuthenticator: [ Correction(TimeSpan.FromMilliseconds(2), TimeSpan.FromMilliseconds(4)) ]));

        var result = await harness.Query(NTS:                   true,
                                         RequestCorrection:     true,
                                         CorrectionParameters:  new NTPv5CorrectionParameters(FrequencyError: 0));

        Assert.Multiple(() => {
            Assert.That(result.Success,                       Is.True, result.ErrorMessage);
            Assert.That(result.IsAuthenticated,               Is.True);
            Assert.That(result.Measurement?.CorrectedOffset,  Is.EqualTo(Offset + TimeSpan.FromMilliseconds(6)), "offset_c");
        });

    }

    #endregion

    #region § 6 and § 9: the poll field

    /// <summary>
    /// § 6: the poll of a response "is the server's value that the client is expected to
    /// follow", and § 9: "The client SHOULD respect the minimum allowed polling interval
    /// provided by the server in the poll field of the last valid response". A poll of 10: no
    /// query before 2^10 s from now, and the next one asked for is not sent.
    /// </summary>
    [Test]
    public async Task ThePollField_IsTheMinimumIntervalTheClientKeeps()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(harness.Plain(request, Offset, response => response.Poll = 10));

        var access  = new NTPServerAccessState();

        var first   = await harness.Query(AccessState: access);
        var second  = await harness.Query(AccessState: access);

        Assert.Multiple(() => {
            Assert.That(first.Success,               Is.True,                                        first.ErrorMessage);
            Assert.That(first.MayQueryAgain,         Is.True);
            Assert.That(access.NextQueryNotBefore,   Is.EqualTo(harness.Clock.GetUtcNow() + TimeSpan.FromSeconds(1024)));
            Assert.That(second.Success,              Is.False,                                       "the query within the interval was answered");
            Assert.That(harness.Server.Requests,     Has.Count.EqualTo(1),                          "the query within the interval was sent");
        });

    }


    /// <summary>
    /// § 6: "A value of 127 indicates the server does not want to hear from the client again",
    /// and "This field is valid even when stratum is 0" - so it holds in a response that is no
    /// time to synchronize to, too. The client sends nothing more.
    /// </summary>
    [TestCase((Byte) 1, TestName = "APollOf127_EndsTheAssociation_Stratum1")]
    [TestCase((Byte) 0, TestName = "APollOf127_EndsTheAssociation_Stratum0")]
    public async Task APollOf127_EndsTheAssociation(Byte Stratum)
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(harness.Plain(request, Offset, response => {
                                                                response.Poll     = 127;
                                                                response.Stratum  = Stratum;
                                                            }));

        var access  = new NTPServerAccessState();

        var first   = await harness.Query(AccessState: access);

        harness.Clock.Advance(TimeSpan.FromDays(400));

        var second  = await harness.Query(AccessState: access);

        Assert.Multiple(() => {
            Assert.That(first.Success,            Is.True,  first.ErrorMessage);
            Assert.That(first.MayQueryAgain,      Is.False, "the client may query again");
            Assert.That(harness.Server.Requests,  Has.Count.EqualTo(1), "a query was sent after the server said not to");
            Assert.That(second.Success,           Is.False);
        });

    }


    /// <summary>
    /// § 9: the minimum interval is respected "but only up to a reasonable maximum value to limit
    /// the impact of misconfigurations, bugs, and potential denial-of-service attacks", for
    /// example "2^15 (about 9 hours) if authentication is disabled, or 2^18 (about 3 days) if
    /// authentication is enabled". A poll of 120 - longer than the universe is old - keeps the
    /// client away for no more than the larger of the two examples.
    /// </summary>
    [Test]
    public async Task AnAbsurdPoll_IsFollowedOnlyUpToAMaximum()
    {

        await using var harness = new NTPv5ClientHarness();

        harness.Script = request => NTPv5ClientHarness.Send(harness.Plain(request, Offset, response => response.Poll = 120));

        var access  = new NTPServerAccessState();
        var result  = await harness.Query(AccessState: access);

        Assert.Multiple(() => {
            Assert.That(result.Success,              Is.True, result.ErrorMessage);
            Assert.That(result.MayQueryAgain,        Is.True, "a poll below 127 ended the association");
            Assert.That(access.NextQueryNotBefore,   Is.Not.Null);
            Assert.That(access.NextQueryNotBefore - harness.Clock.GetUtcNow(),
                        Is.LessThanOrEqualTo(TimeSpan.FromSeconds(1 << 18)),
                        "the client stays away longer than 2^18 s");
        });

    }

    #endregion

}
