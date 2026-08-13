using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Client.Tests;

/// <summary>
/// RFC 9769 § 6: "Clients using the interleaved mode SHOULD randomize all bits of receive and
/// transmit timestamps in their requests (i.e., provide a precision of 2^-32 seconds) to make it
/// more difficult for off-path attackers to guess the origin timestamp in the server response."
///
/// <para>
/// Both fields, because both come back as the origin: a server answering in the basic mode echoes
/// the request's transmit timestamp, one answering in the interleaved mode echoes its receive
/// timestamp, and an off-path attacker who can guess either can forge a response the client will
/// accept. Neither field is a claim about time even without § 6 — Figure 1 of § 2 has an
/// interleaved request carry the timestamps of the <em>previous</em> exchange — so nothing is
/// lost by filling them with random bits, and a clock reading is a poor secret.
/// </para>
/// <para>
/// The catch, and the reason this needed more than a random number generator: RFC 5905's offset
/// takes T1 from the response's origin timestamp, and once that is a nonce there is no T1 in the
/// packet at all. It has to come from what the client recorded when the request went out. That
/// was already true before § 6 and already wrong — see
/// <see cref="AnInterleavedRequestAnsweredInTheBasicMode_StillMeasuresCorrectly"/>.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class InterleavedNonceTests
{

    #region The nonces themselves

    /// <summary>
    /// Successive nonces differ, in both fields, and neither is ever zero or equal to the other.
    /// </summary>
    /// <remarks>
    /// The two exclusions are not fussiness. Zero is how § 2 marks a request as opening in the
    /// basic mode, so a zero receive timestamp would tell the server there is no earlier exchange
    /// to reach back to. Two equal timestamps make a response ambiguous: the origin would match
    /// both, and <see cref="InterleavedAssociation.Classify"/> could not say which mode it was
    /// in.
    /// </remarks>
    [Test]
    public void SuccessiveNonces_AreUnpredictableAndUsable()
    {

        var receives   = new HashSet<UInt64>();
        var transmits  = new HashSet<UInt64>();

        for (var i = 0; i < 200; i++)
        {

            var (receive, transmit) = InterleavedAssociation.NewRequestNonces();

            Assert.That(receive,  Is.Not.EqualTo(0UL),      "zero opens a basic-mode association");
            Assert.That(transmit, Is.Not.EqualTo(0UL));
            Assert.That(receive,  Is.Not.EqualTo(transmit), "equal timestamps make a response ambiguous");

            receives. Add(receive);
            transmits.Add(transmit);

        }

        Assert.Multiple(() => {

            Assert.That(receives,  Has.Count.EqualTo(200), "every receive nonce is its own value");
            Assert.That(transmits, Has.Count.EqualTo(200), "and so is every transmit nonce");

        });

    }


    /// <summary>
    /// The bits are spread across the whole 64, not just the low ones.
    /// </summary>
    /// <remarks>
    /// § 6 asks for "all bits", and the parenthetical says what that is for: "(i.e., provide a
    /// precision of 2^-32 seconds)". A client that randomized only the fraction and left a real
    /// seconds field would leak its clock to the second and leave an attacker 32 bits to guess
    /// rather than 64 — which is the whole difference between this being worth doing and not.
    /// The union of 200 samples must therefore have every bit position set at least once.
    /// </remarks>
    [Test]
    public void TheNonces_RandomizeAllSixtyFourBits()
    {

        UInt64 orOfReceives = 0, orOfTransmits = 0;

        for (var i = 0; i < 200; i++)
        {
            var (receive, transmit) = InterleavedAssociation.NewRequestNonces();
            orOfReceives  |= receive;
            orOfTransmits |= transmit;
        }

        Assert.Multiple(() => {

            Assert.That(orOfReceives,  Is.EqualTo(UInt64.MaxValue),
                        $"some bit of the receive nonce is never set: {orOfReceives:X16}");

            Assert.That(orOfTransmits, Is.EqualTo(UInt64.MaxValue),
                        $"some bit of the transmit nonce is never set: {orOfTransmits:X16}");

        });

    }

    #endregion

    #region On the wire

    /// <summary>
    /// An interleaved client's requests carry no reading of its clock, and never the same value
    /// twice.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read off the wire by the relay, because that is the only place the claim can be checked —
    /// an attacker sees the datagram, not the client's intentions.
    /// </para>
    /// <para>
    /// "No reading of its clock" is asserted as a distance: a real NTP timestamp for the moment
    /// the packet is sent is within seconds of now — the relay and the client share a host — and
    /// a random 64-bit value is a date somewhere in a 136-year era. The bound is one hour: no
    /// clock reading can be that far out, and a nonce lands inside it with probability about two
    /// in a million per draw. It was one year once, which a legitimate nonce hits one draw in
    /// seventy — with several draws per run, that turned a hosted runner red twice before the
    /// arithmetic was done.
    /// </para>
    /// </remarks>
    [Test]
    public async Task AnInterleavedClientsRequests_CarryNoClockReading()
    {

        // The relay has to exist before the server, so the server can advertise its port through
        // NTS-KE Port Negotiation and the client sends there; the forwarding target is only known
        // once the server has bound.
        using var relay = UdpRelayProbe.StartObserving();

        await using var fixture = await NornServerFixture.StartAsync(
                                            advertisedNTPPort: relay.Port);

        relay.RelayTo(fixture.NTPPort);

        var client = fixture.CreateClient(TimeSpan.FromSeconds(10), interleavedMode: true);
        var keys   = await client.GetNTSKERecords();

        Assert.That(keys.Success, Is.True, keys.ErrorMessage);

        // Two exchanges: the first opens the association in the basic mode, the second is the
        // interleaved one. Both must carry nonces.
        for (var i = 0; i < 2; i++)
        {
            var query = await client.QueryTime(NTSKEResponse: keys.Response!,
                                               Timeout:       TimeSpan.FromSeconds(10));
            Assert.That(query.Success, Is.True, $"exchange {i + 1}: {query.ErrorMessage}");
        }

        var requests = relay.Observations.
                           Select(observation => RawNtpReader.TryRead(observation.Payload,
                                                                      out var packet,
                                                                      out _,
                                                                      RawNtpReadOptions.Lenient)
                                                     ? packet
                                                     : null).
                           Where (packet => packet?.Mode == 3).
                           ToArray();

        Assert.That(requests, Has.Length.GreaterThanOrEqualTo(2),
                    $"the relay saw {requests.Length} client requests");

        var now       = RawNtpTimestamp.FromDateTime(DateTime.UtcNow);
        var oneHour   = 3600UL << 32;

        Assert.Multiple(() => {

            // § 2: "It has a zero origin timestamp and zero receive timestamp." The zero is not
            // decoration — it is what tells the server this request refers to no earlier
            // exchange, so it survives § 6 while the field beside it does not.
            Assert.That(requests[0]!.ReceiveTimestamp, Is.EqualTo(0UL),
                        "the opening request must carry a zero receive timestamp");

            Assert.That(requests[0]!.OriginTimestamp, Is.EqualTo(0UL),
                        "and a zero origin timestamp");

            foreach (var (request, index) in requests.Select((request, index) => (request!, index)))
            {

                Assert.That(Distance(request.TransmitTimestamp, now), Is.GreaterThan(oneHour),
                            $"request {index + 1}'s transmit timestamp is a plausible clock reading: " +
                            $"{request.TransmitTimestamp:X16}");

                // Every request after the opening one carries a nonce here instead.
                if (index > 0)
                    Assert.That(Distance(request.ReceiveTimestamp, now), Is.GreaterThan(oneHour),
                                $"request {index + 1}'s receive timestamp is a plausible clock reading: " +
                                $"{request.ReceiveTimestamp:X16}");

            }

            Assert.That(requests.Select(request => request!.TransmitTimestamp).Distinct().Count(),
                        Is.EqualTo(requests.Length),
                        "and no two requests carry the same transmit timestamp");

        });

    }


    /// <summary>The unsigned distance between two NTP timestamps, wrapping at the era boundary.</summary>
    private static UInt64 Distance(UInt64 A, UInt64 B)
    {
        var difference = unchecked(A - B);
        return difference > (UInt64.MaxValue / 2) ? unchecked(0UL - difference) : difference;
    }

    #endregion

    #region The offset survives it

    /// <summary>
    /// An interleaved request answered in the basic mode still yields a correct offset.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The case § 6 would otherwise break, and it was already broken before § 6. Figure 1's last
    /// column is exactly this: the client sends an interleaved request at t9 and the server
    /// answers in the basic mode, echoing the transmit field — which Figure 1 says carries t5,
    /// the transmit timestamp of the <em>previous</em> request. A client taking T1 from the
    /// origin is then measuring against a timestamp one poll interval old. Randomizing the field
    /// turns that stale value into a date centuries away, so what used to be a skewed offset
    /// becomes an absurd one.
    /// </para>
    /// <para>
    /// The server here has the interleaved mode switched off, which is how every one of its
    /// answers is guaranteed to be a basic-mode answer to a client that is asking for something
    /// else. That is not a contrived configuration: it is every server that has not implemented
    /// RFC 9769.
    /// </para>
    /// </remarks>
    [Test]
    public async Task AnInterleavedRequestAnsweredInTheBasicMode_StillMeasuresCorrectly()
    {

        await using var fixture = await NornServerFixture.StartAsync(
                                            interleavedMode: InterleavedModePolicy.Disabled);

        var client = fixture.CreateClient(TimeSpan.FromSeconds(10), interleavedMode: true);
        var keys   = await client.GetNTSKERecords();

        Assert.That(keys.Success, Is.True, keys.ErrorMessage);

        // The first exchange opens the association; the second is the interleaved request that
        // this server will answer in the basic mode.
        var first  = await client.QueryTime(NTSKEResponse: keys.Response!, Timeout: TimeSpan.FromSeconds(10));
        Assert.That(first.Success, Is.True, first.ErrorMessage);

        var second = await client.QueryTime(NTSKEResponse: keys.Response!, Timeout: TimeSpan.FromSeconds(10));
        Assert.That(second.Success, Is.True, second.ErrorMessage);

        var response = second.Response!;

        Assert.Multiple(() => {

            Assert.That(response.OriginateTimestamp, Is.Not.EqualTo(0UL),
                        "the server did echo something");

            Assert.That(response.ClockOffset, Is.Not.Null);

            // Client and server share this machine's clock, so the true offset is zero and
            // anything a second away is the wrong T1 rather than a slow network.
            Assert.That(response.ClockOffset!.Value.Duration(),
                        Is.LessThan(TimeSpan.FromSeconds(1)),
                        $"the offset was computed from the wrong T1: {response.ClockOffset}, " +
                        $"origin {response.OriginateTimestamp:X16}");

            Assert.That(response.RoundTripDelay!.Value.Duration(),
                        Is.LessThan(TimeSpan.FromSeconds(1)),
                        $"and so was the delay: {response.RoundTripDelay}");

        });

    }

    #endregion

}
