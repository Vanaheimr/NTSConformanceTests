using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// RFC 9769 § 2 from the client's side.
///
/// <para>
/// What a client contributes to the interleaved mode is memory. The server's accurate transmit
/// timestamp arrives one exchange after the transmission it describes, so a client that treats
/// each query as self-contained can never use it: it has to still be holding the other three
/// timestamps of the previous exchange when the fourth turns up. Which is why the mode belongs
/// to a client instance rather than to a query, and why a program that builds a fresh client
/// per query gets nothing from switching it on.
/// </para>
/// <para>
/// The state machine is exercised directly through <see cref="InterleavedAssociation"/> where
/// that is enough, and end to end against a real server where it is not. The direct tests can
/// reach states a live exchange cannot be made to produce on demand — a lost response, an
/// association given up on — and they run in microseconds.
/// </para>
/// </summary>
[TestFixture]
public class InterleavedClientTests
{

    #region The association state machine

    /// <summary>
    /// RFC 9769 § 2: "The first request from a client is always in the basic mode ... It has a
    /// zero origin timestamp and zero receive timestamp. Only when the client receives a valid
    /// response from the server will it be able to send a request in the interleaved mode."
    ///
    /// A client that sent an interleaved request first would be echoing a timestamp the server
    /// never issued, which no server can match — so it would never get an interleaved answer
    /// and would never find out why.
    /// </summary>
    [Test]
    public void ANewAssociation_OpensInTheBasicMode()
    {

        var association = new InterleavedAssociation();

        Assert.Multiple(() => {

            Assert.That(association.CanSendInterleaved,
                        Is.False,
                        "nothing has been received yet, so there is no timestamp to echo");

            Assert.That(association.NextRequestOrigin(),
                        Is.EqualTo(0UL),
                        "a zero origin timestamp is what opens an association");

        });

    }


    /// <summary>
    /// Figure 1 of § 2, the third column: after a first response, the request's origin is the
    /// server's receive timestamp from it (t2). That is what lets the server find the exchange
    /// being referred to, and it is the only value in the request the server looks at.
    ///
    /// Figure 1 has the other two fields carry this client's own timestamps of the previous
    /// exchange — its arrival time for the response (t4) and its accurate transmit timestamp of
    /// the previous request (t1) — neither of which is a claim about the packet in hand. § 6
    /// then replaces both with random bits, so they are no longer produced here at all; see
    /// <see cref="NoncesAreUnpredictable_AndUsable"/>. The real values stay in the association,
    /// where the measurement is made from them.
    /// </summary>
    [Test]
    public void AfterAResponse_TheNextRequestEchoesTheServersReceiveTimestamp()
    {

        const UInt64 t1 = 0xAAAA_0000_0000_0001;   // our accurate transmit of request 1
        const UInt64 t2 = 0xBBBB_0000_0000_0002;   // the server's receive timestamp
        const UInt64 t4 = 0xDDDD_0000_0000_0004;   // our arrival time for response 1

        var association = new InterleavedAssociation();

        association.RecordValidResponse(
            new NTPPacket(ReceiveTimestamp:  t2,
                          TransmitTimestamp: 0xCCCC_0000_0000_0003),
            RequestTransmit:      t1,
            OwnReceiveTimestamp:  t4
        );

        Assert.Multiple(() => {

            Assert.That(association.CanSendInterleaved, Is.True);

            Assert.That(association.NextRequestOrigin(),
                        Is.EqualTo(t2),
                        "origin t2 — Figure 1's third column");

        });

    }


    /// <summary>
    /// RFC 9769 § 2, the modified bogus-packet test: "If the origin timestamp is equal to the
    /// transmit timestamp, the response is in the basic mode. If the origin timestamp is equal
    /// to the receive timestamp, the response is in the interleaved mode."
    ///
    /// Getting this backwards would be the worst possible bug and the hardest to see: the client
    /// would accept every packet and read the transmit timestamps of the wrong exchange, giving
    /// measurements that are plausible, self-consistent and off by a poll interval.
    /// </summary>
    [Test]
    public void TheOriginTimestamp_DecidesWhichModeAResponseIsIn()
    {

        const UInt64 requestReceive  = 0x1111_1111_1111_1111;
        const UInt64 requestTransmit = 0x2222_2222_2222_2222;

        Assert.Multiple(() => {

            Assert.That(InterleavedAssociation.Classify(new NTPPacket(OriginateTimestamp: requestTransmit),
                                                        requestReceive,
                                                        requestTransmit),
                        Is.EqualTo(InterleavedResponseMode.Basic),
                        "echoing the transmit timestamp is the basic mode");

            Assert.That(InterleavedAssociation.Classify(new NTPPacket(OriginateTimestamp: requestReceive),
                                                        requestReceive,
                                                        requestTransmit),
                        Is.EqualTo(InterleavedResponseMode.Interleaved),
                        "echoing the receive timestamp is the interleaved mode");

            Assert.That(InterleavedAssociation.Classify(new NTPPacket(OriginateTimestamp: 0x3333_3333_3333_3333),
                                                        requestReceive,
                                                        requestTransmit),
                        Is.EqualTo(InterleavedResponseMode.Bogus),
                        "and echoing neither is a packet that answers no request this client sent");

        });

    }


    /// <summary>
    /// A zero receive timestamp is what a basic-mode request carries, and a response echoing
    /// zero must not be read as interleaved. Without the guard, the opening exchange of every
    /// association — origin zero, receive zero — would classify as interleaved the moment a
    /// server echoed a zero origin.
    /// </summary>
    [Test]
    public void AZeroReceiveTimestamp_DoesNotMakeAResponseInterleaved()
    {

        Assert.That(InterleavedAssociation.Classify(new NTPPacket(OriginateTimestamp: 0),
                                                    RequestReceive:   0,
                                                    RequestTransmit:  0x2222_2222_2222_2222),
                    Is.EqualTo(InterleavedResponseMode.Bogus));

    }


    /// <summary>
    /// RFC 9769 § 2: "The protocol recovers from packet loss. When a client request or server
    /// response is lost, the client will use the same origin timestamp in the next request."
    ///
    /// So an unanswered request must not throw the association away — the server may well still
    /// hold the matching pair, and starting over would cost an exchange for nothing.
    /// </summary>
    [Test]
    public void ALostResponse_DoesNotEndTheAssociation()
    {

        var association = Established();

        var before = association.NextRequestOrigin();

        Assert.That(before, Is.Not.EqualTo(0UL), "there is an association to keep");
        Assert.That(association.RecordUnansweredRequest(), Is.True, "the association should hold");
        Assert.That(association.NextRequestOrigin(),
                    Is.EqualTo(before),
                    "and the next request repeats the same origin timestamp");

    }


    /// <summary>
    /// But not indefinitely — § 2: "The client SHOULD limit the number of requests in the
    /// interleaved mode between server responses to prevent the processing of very old
    /// timestamps in cases where a large number of consecutive requests are lost."
    ///
    /// Past that point the server has certainly dropped the pair, and a client that kept
    /// offering the same dead origin timestamp would never take another measurement.
    /// </summary>
    [Test]
    public void EnoughLostResponses_StartTheAssociationOver()
    {

        var association = Established();

        for (var i = 1; i < association.MaxUnansweredRequests; i++)
            Assert.That(association.RecordUnansweredRequest(),
                        Is.True,
                        $"loss {i} is within the limit of {association.MaxUnansweredRequests}");

        Assert.Multiple(() => {

            Assert.That(association.RecordUnansweredRequest(),
                        Is.False,
                        "the last one is over the limit");

            Assert.That(association.CanSendInterleaved,
                        Is.False,
                        "so the next request opens a new association in the basic mode");

        });

    }


    /// <summary>
    /// The measurement of § 2's first timestamp set, "RECOMMENDED for clients that filter
    /// measurements based on the delay": T1, T2 and T4 from the previous exchange, and T3 the
    /// accurate transmit timestamp that only arrived now.
    ///
    /// Checked with timestamps chosen so the right answer is not the answer any other pairing
    /// gives: a client that reached for this response's receive timestamp, or for the current
    /// request's transmit timestamp, produces a different offset and a different delay.
    /// </summary>
    [Test]
    public void AnInterleavedResponse_CompletesThePreviousExchangesMeasurement()
    {

        // One second per 2^32 units. The exchange below is deliberately asymmetric: two seconds
        // out, one second back, with the server one hour ahead.
        const UInt64 second = 4294967296UL;
        const UInt64 hour   = 3600UL * second;

        var t1 = 1000UL * second;
        var t2 = t1 + hour + 2 * second;
        var t3 = t2 + second;
        var t4 = t1 + 3 * second;

        var association = new InterleavedAssociation();

        association.RecordValidResponse(
            new NTPPacket(ReceiveTimestamp: t2, TransmitTimestamp: t3 - 1),   // t3~, the estimate
            RequestTransmit:      t1,
            OwnReceiveTimestamp:  t4
        );

        // The next response carries the accurate t3 that was not available before.
        var measurement = association.MeasurementFor(new NTPPacket(ReceiveTimestamp:  t4 + 10 * second,
                                                                   TransmitTimestamp: t3));

        Assert.That(measurement, Is.Not.Null, "the previous exchange's timestamps should still be held");

        Assert.Multiple(() => {

            Assert.That(measurement!.Value.T1, Is.EqualTo(t1), "T1 is the previous request's transmit timestamp");
            Assert.That(measurement!.Value.T2, Is.EqualTo(t2), "T2 is the previous response's receive timestamp");
            Assert.That(measurement!.Value.T3, Is.EqualTo(t3), "T3 is the latest response's transmit timestamp");
            Assert.That(measurement!.Value.T4, Is.EqualTo(t4), "T4 is the previous response's arrival time");

            // ((t2 - t1) + (t3 - t4)) / 2 = ((3602) + (3600 - 1 + 1 - 3 + 1... )) — worked out:
            // t2 - t1 = 3602 s, t3 - t4 = 3600 s, so the offset is 3601 s.
            Assert.That(measurement!.Value.ClockOffset.TotalSeconds,
                        Is.EqualTo(3601.0).Within(0.001),
                        "the server is an hour ahead, plus half the path asymmetry");

            // (t4 - t1) - (t3 - t2) = 3 - 1 = 2 s.
            Assert.That(measurement!.Value.RoundtripDelay.TotalSeconds,
                        Is.EqualTo(2.0).Within(0.001),
                        "three seconds of round trip less one second inside the server");

        });

    }


    /// <summary>
    /// An association that has just been reset holds nothing, so there is no measurement to
    /// complete. Returning a measurement built from missing timestamps would be worse than
    /// returning none: it would look like a reading.
    /// </summary>
    [Test]
    public void WithoutAPreviousExchange_ThereIsNoInterleavedMeasurement()
    {

        Assert.That(new InterleavedAssociation().MeasurementFor(
                        new NTPPacket(ReceiveTimestamp: 1, TransmitTimestamp: 2)),
                    Is.Null);

    }


    private static InterleavedAssociation Established()
    {

        var association = new InterleavedAssociation();

        association.RecordValidResponse(
            new NTPPacket(ReceiveTimestamp:  0xBBBB_0000_0000_0002,
                          TransmitTimestamp: 0xCCCC_0000_0000_0003),
            RequestTransmit:      0xAAAA_0000_0000_0001,
            OwnReceiveTimestamp:  0xDDDD_0000_0000_0004
        );

        return association;

    }

    #endregion


    #region End to end against a real server

    /// <summary>
    /// Norn's client and Norn's server, both in the interleaved mode, over loopback.
    ///
    /// The first query is necessarily basic; the second is where the mode starts, and by the
    /// third it should be established. What must come back is a completed measurement — proof
    /// that the client recognized the response, reached back for the timestamps it had kept,
    /// and assembled the four that RFC 9769 § 2 asks for.
    /// </summary>
    [Test]
    [Category(TestCategories.Loopback)]
    public async Task AClientAndServer_BothInterleaved_CompleteAMeasurement()
    {

        await using var server = await NornServerFixture.StartAsync();

        var client       = server.CreateClient(TimeSpan.FromSeconds(10), interleavedMode: true);
        var measurements = new List<InterleavedMeasurement>();

        for (var i = 0; i < 3; i++)
        {

            var result = await client.QueryTime(Timeout: TimeSpan.FromSeconds(10));

            Assert.That(result.Success, Is.True, $"query {i + 1}: {result.ErrorMessage}");

            if (result.InterleavedMeasurement is not null)
                measurements.Add(result.InterleavedMeasurement.Value);

        }

        Assert.That(measurements, Is.Not.Empty,
                    "three exchanges with both sides in the interleaved mode should have " +
                    "produced at least one interleaved measurement");

        Assert.That(measurements.Select(measurement => Math.Abs(measurement.ClockOffset.TotalSeconds)),
                    Has.All.LessThan(1.0),
                    "client and server read the same machine's clock, so every offset should " +
                    "be near zero");

    }


    /// <summary>
    /// The sensitivity check: the same client with the mode off must never report an
    /// interleaved measurement, however many times it queries.
    ///
    /// Without it, a test asserting "at least one measurement appeared" could be satisfied by a
    /// client that labels every ordinary response as interleaved.
    /// </summary>
    [Test]
    [Category(TestCategories.Loopback)]
    public async Task WithTheModeOff_NoInterleavedMeasurementIsEverReported()
    {

        await using var server = await NornServerFixture.StartAsync();

        var client = server.CreateClient(TimeSpan.FromSeconds(10));

        Assert.That(client.InterleavedAssociation, Is.Null, "the mode is off by default");

        for (var i = 0; i < 3; i++)
        {

            var result = await client.QueryTime(Timeout: TimeSpan.FromSeconds(10));

            Assert.That(result.Success, Is.True, $"query {i + 1}: {result.ErrorMessage}");
            Assert.That(result.InterleavedMeasurement, Is.Null, $"query {i + 1}");

        }

    }


    /// <summary>
    /// And against a server with the mode switched off, an interleaved client must keep working.
    ///
    /// RFC 9769 § 6: "Clients MUST NOT rely on servers to be able to respond in the interleaved
    /// mode." The server will answer every request in the basic mode, and the client has to take
    /// ordinary measurements from them rather than waiting for something that will never come.
    /// </summary>
    [Test]
    [Category(TestCategories.Loopback)]
    public async Task AgainstAServerWithoutTheMode_TheClientStillMeasures()
    {

        await using var server = await NornServerFixture.StartAsync(interleavedMode: InterleavedModePolicy.Disabled);

        var client = server.CreateClient(TimeSpan.FromSeconds(10), interleavedMode: true);

        for (var i = 0; i < 3; i++)
        {

            var result = await client.QueryTime(Timeout: TimeSpan.FromSeconds(10));

            Assert.Multiple(() => {

                Assert.That(result.Success,
                            Is.True,
                            $"query {i + 1} failed against a basic-mode server: {result.ErrorMessage}");

                Assert.That(result.InterleavedMeasurement,
                            Is.Null,
                            $"query {i + 1}: there is nothing interleaved to report");

            });

        }

    }

    #endregion

}
