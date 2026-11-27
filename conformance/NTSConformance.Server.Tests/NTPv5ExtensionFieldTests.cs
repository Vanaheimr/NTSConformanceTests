using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// What an NTPv5 server of draft-ietf-ntp-ntpv5-10 does beyond the basic exchange: the
/// interleaved mode of § 8 and § 10, keyed by the server cookie; the Reference IDs of § 7.4; the
/// Correction of § 7.7; the Reference Timestamp of § 7.8; and the Monotonic Receive Timestamp
/// of § 7.9. Read on the wire with this suite's own codec, as in <see cref="NTPv5ServerTests"/>.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ExtensionFieldTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(ntpv5: NTPv5Support.Draft);


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    #region Helpers

    private NornServerFixture Server
        => fixture ?? throw new InvalidOperationException("the server fixture did not start");


    private static RawNtpV5Packet Read(Byte[]? Octets, String What)
    {

        Assert.That(Octets, Is.Not.Null, $"{What}: the server did not answer");

        Assert.That(RawNtpV5Packet.TryRead(Octets!, out var response, out var error), Is.True,
                    $"{What}: the response is no valid NTPv5 message: {error}\n{Bytes.Dump(Octets!)}");

        return response!;

    }


    private static RawNtpV5Packet Exchange(NornServerFixture Server, RawNtpV5Packet Request)
    {

        var requestOctets  = Request.Write();
        var responseOctets = RawUdpExchange.TryExchange(requestOctets, "127.0.0.1", Server.NTPPort)
                                 ?? throw new AssertionException("the server did not answer an NTPv5 request it should have answered");

        var response = Read(responseOctets, "the request");

        Assert.Multiple(() => {
            Assert.That(response.ClientCookie,           Is.EqualTo(Request.ClientCookie),   "§ 6: the client cookie is copied");
            Assert.That(responseOctets.Length,           Is.EqualTo(requestOctets.Length),   "§ 10 step 5: the response is as long as the request");
            Assert.That(response.Flags & ~Request.Flags, Is.Zero,                            "§ 10 step 6: no flag the request did not set");
        });

        return response;

    }

    #endregion


    #region § 8, § 10: the interleaved mode

    /// <summary>
    /// § 10: the Server Cookie is set when the interleaved mode is requested and supported,
    /// "even if the response cannot be in the requested mode due to the request having an
    /// unknown or zero server cookie" - and then the response is in the basic mode, without the
    /// Interleaved flag. Then the cookie draws the interleaved response: the flag set, and the
    /// transmit timestamp of the previous response, taken after it was formed and before the
    /// next request was received (§ 8, Figure 15).
    /// </summary>
    [Test]
    public void TheServerCookie_DrawsTheTransmitTimestampOfThePreviousResponse()
    {

        using var session = new RawUdpSession("127.0.0.1", Server.NTPPort);

        var first      = RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.InterleavedMode);
        var response1  = Read(session.TryExchange(first.Write()), "the first interleaved request");

        Assert.Multiple(() => {
            Assert.That(response1.ClientCookie,                         Is.EqualTo(first.ClientCookie), "§ 6: the client cookie is copied");
            Assert.That(response1.Flags & RawNtpV5Draft.InterleavedMode, Is.Zero,                       "§ 10: with a zero server cookie no interleaved response is possible, so the response is in the basic mode");
            Assert.That(response1.ServerCookie,                         Is.Not.Zero,                    "§ 10: the server cookie is set when the interleaved mode is requested and supported");
        });

        var second              = RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.InterleavedMode);
        second.ServerCookie     = response1.ServerCookie;
        var response2           = Read(session.TryExchange(second.Write()), "the second interleaved request");

        Assert.Multiple(() => {

            Assert.That(response2.ClientCookie,                          Is.EqualTo(second.ClientCookie), "§ 6: the client cookie is copied");
            Assert.That(response2.Flags & RawNtpV5Draft.InterleavedMode, Is.Not.Zero,                     "§ 10: a known server cookie draws a response in the interleaved mode");
            Assert.That(response2.ServerCookie,                          Is.Not.Zero.And.Not.EqualTo(response1.ServerCookie),
                        "§ 10: every response gets a new cookie, unique for long enough that no transmit timestamp is taken for another");

            Assert.That(response2.TransmitTimestamp, Is.GreaterThanOrEqualTo(response1.TransmitTimestamp),
                        "§ 8: the interleaved transmit timestamp is that of the previous response, taken after the less accurate one in it");

            Assert.That(response2.TransmitTimestamp, Is.LessThanOrEqualTo(response2.ReceiveTimestamp),
                        "§ 8: the previous response left before this request was received");

        });

    }


    /// <summary>
    /// § 10: an unknown server cookie cannot draw an interleaved response; the response is in
    /// the basic mode, with a new server cookie of its own.
    /// </summary>
    [Test]
    public void AnUnknownServerCookie_IsAnsweredInTheBasicMode()
    {

        var request           = RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.InterleavedMode);
        request.ServerCookie  = 0x0123456789ABCDEFUL;

        var response          = Exchange(Server, request);

        Assert.Multiple(() => {
            Assert.That(response.Flags & RawNtpV5Draft.InterleavedMode, Is.Zero,  "§ 10: an unknown cookie has no transmit timestamp, so the response is in the basic mode");
            Assert.That(response.ServerCookie,                         Is.Not.Zero.And.Not.EqualTo(request.ServerCookie), "§ 10: the server cookie is set, and is the server's own");
            Assert.That(response.TransmitTimestamp,                    Is.GreaterThanOrEqualTo(response.ReceiveTimestamp), "§ 10: in the basic mode the transmit timestamp is taken when the response is formed");
        });

    }


    /// <summary>
    /// § 7.6 against § 10: Server Information names the Interleaved flag exactly where the
    /// server can answer in the interleaved mode. Checked both ways, with the mode on and off.
    /// </summary>
    [TestCase(InterleavedModePolicy.Everyone, true)]
    [TestCase(InterleavedModePolicy.Disabled, false)]
    public async Task ServerInformation_AgreesWithTheInterleavedMode(InterleavedModePolicy Policy, Boolean Interleaves)
    {

        await using var server  = await NornServerFixture.StartAsync(ntpv5: NTPv5Support.Draft, interleavedMode: Policy);

        var request             = RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.InterleavedMode);
        request.ExtensionFields.Add(RawNtpV5ExtensionField.ServerInformationRequest());

        var response            = Exchange(server, request);
        var information         = response.Find(RawNtpV5Draft.ServerInformation);

        Assert.That(information, Is.Not.Null, "§ 7.6: the field MUST be supported");

        var supportedFlags      = (UInt16) (information!.Data[2] << 8 | information.Data[3]);

        Assert.That((supportedFlags & RawNtpV5Draft.InterleavedMode) != 0, Is.EqualTo(Interleaves),
                    $"§ 7.6: with the interleaved mode {Policy} Server Information says 0x{supportedFlags:X4}");

        Assert.That(response.ServerCookie != 0, Is.EqualTo(Interleaves),
                    "§ 10: the server cookie is set exactly when the interleaved mode is requested and supported");

    }

    #endregion

    #region § 7.4: Reference IDs

    /// <summary>
    /// § 7.4: the list has 32 entries; the first is the server's own non-zero 56-bit reference
    /// ID with a share of 100 % (0), unused ones have the minimum share (255) and a zero ID. A
    /// server with no NTPv5 sources has only its own. The response field is as long as the
    /// request field.
    /// </summary>
    [Test]
    public void TheWholeList_IsTheServersOwnIDAndUnusedEntries()
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5Fields.ReferenceIDsRequest(Index: 0, DataLength: 256));

        var response = Exchange(Server, request);
        var field    = response.Find(RawNtpV5Draft.ReferenceIDsResponse);

        Assert.That(field, Is.Not.Null, "§ 7.4: the Reference IDs Response for the request");
        Assert.That(field!.Length, Is.EqualTo(4 + 256), "§ 7.4: the response field has the same length as the request field");

        var entries = RawNtpV5Fields.ReferenceIDs(field);

        Assert.Multiple(() => {

            Assert.That(entries,                Has.Count.EqualTo(32), "§ 7.4: 32 entries");
            Assert.That(entries[0].Share,       Is.Zero,               "§ 7.4: the server's own entry has a share of 100 %, encoded as 0");
            Assert.That(entries[0].ReferenceId, Is.Not.Zero,           "§ 7.4: the server's own reference ID is non-zero");

            for (var i = 1; i < entries.Count; i++)
                Assert.That(entries[i], Is.EqualTo(((Byte) 255, 0UL)), $"§ 7.4: entry {i} of a server without sources is unused: share 255, ID 0");

        });

    }


    /// <summary>
    /// § 7.4: a fragment starts at the requested index and is as long as the request asked;
    /// the server's own ID is the same in every response.
    /// </summary>
    [TestCase((Byte)  0,   8)]
    [TestCase((Byte)  0,  64)]
    [TestCase((Byte) 16, 128)]
    [TestCase((Byte) 31,   8)]
    public void AFragment_StartsAtItsIndex(Byte Index, Int32 DataLength)
    {

        var whole    = RawNtpV5Packet.ClientRequest();
        whole.ExtensionFields.Add(RawNtpV5Fields.ReferenceIDsRequest(0, 256));
        var list     = RawNtpV5Fields.ReferenceIDs(Exchange(Server, whole).Find(RawNtpV5Draft.ReferenceIDsResponse)!);

        var request  = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5Fields.ReferenceIDsRequest(Index, DataLength));

        var field    = Exchange(Server, request).Find(RawNtpV5Draft.ReferenceIDsResponse);

        Assert.That(field, Is.Not.Null, $"§ 7.4: index {Index} with {DataLength / 8} entries fits the list and is answered");
        Assert.That(field!.Length, Is.EqualTo(4 + DataLength), "§ 7.4: the response field has the same length as the request field");

        Assert.That(RawNtpV5Fields.ReferenceIDs(field), Is.EqualTo(list.Skip(Index).Take(DataLength / 8)).AsCollection,
                    $"§ 7.4: the fragment from index {Index} is that part of the list");

    }


    /// <summary>
    /// § 7.4: "If the request contains an invalid index for the given length, the extension
    /// field MUST be ignored" - and § 7 has the server pad for it.
    /// </summary>
    [TestCase((Byte)  31,  16)]
    [TestCase((Byte)  16, 256)]
    [TestCase((Byte)  32,   8)]
    [TestCase((Byte) 255,   8)]
    public void AnIndexThatDoesNotFit_IsIgnored(Byte Index, Int32 DataLength)
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5Fields.ReferenceIDsRequest(Index, DataLength));

        var response = Exchange(Server, request);

        Assert.Multiple(() => {
            Assert.That(response.Find(RawNtpV5Draft.ReferenceIDsResponse), Is.Null,     $"§ 7.4: index {Index} with {DataLength / 8} entries runs past the 32 and is ignored");
            Assert.That(response.Find(RawNtpV5Draft.Padding),              Is.Not.Null, "§ 7: a left-out field is padded for");
        });

    }


    /// <summary>
    /// § 7.4 steps 1 to 3: the list of each source, its shares times one half and the source's
    /// normalized weight, combined, duplicates summed, sorted by decreasing share, after the
    /// server's own entry. Two sources weighted 3 : 1 - the first naming A, the second naming B
    /// and, at half its share, A again: A comes to 0.5 * 0.75 + 0.25 * 0.25 = 0.4375, encoded
    /// as 20, and B to 0.125, encoded as 48.
    /// </summary>
    [Test]
    public void TheListOfTheSources_IsCombinedAsSection74Has()
    {

        const UInt64 A = 0x00A1A2A3A4A5A6UL;
        const UInt64 B = 0x00B1B2B3B4B5B6UL;

        Server.Server.Redescribe(NTPv5Sources: [
                                     new NTPv5ReferenceIdSource(3, [ new NTPv5ReferenceIdEntry(0, A) ]),
                                     new NTPv5ReferenceIdSource(1, [ new NTPv5ReferenceIdEntry(0, B), new NTPv5ReferenceIdEntry(16, A) ])
                                 ]);

        try
        {

            var request = RawNtpV5Packet.ClientRequest();
            request.ExtensionFields.Add(RawNtpV5Fields.ReferenceIDsRequest(0, 32));

            var entries = RawNtpV5Fields.ReferenceIDs(Exchange(Server, request).Find(RawNtpV5Draft.ReferenceIDsResponse)!);

            Assert.Multiple(() => {
                Assert.That(entries[0].Share, Is.Zero,                                              "the server's own entry first, at 100 %");
                Assert.That(entries[1],       Is.EqualTo((RawNtpV5Fields.EncodeShare(0.4375), A)),  "A, from both sources summed: 0.4375, encoded as 20");
                Assert.That(entries[2],       Is.EqualTo((RawNtpV5Fields.EncodeShare(0.125),  B)),  "B, from the second source: 0.125, encoded as 48");
                Assert.That(entries[3],       Is.EqualTo(((Byte) 255, 0UL)),                        "then unused");
            });

            Assert.That(RawNtpV5Fields.EncodeShare(0.4375), Is.EqualTo(20), "the test's own premise: -16 * log2(0.4375) = 19.08, rounded up");

        }
        finally
        {
            Server.Server.Redescribe();
        }

    }

    #endregion

    #region § 7.7: Correction

    /// <summary>
    /// § 7.7: a server that supports the field copies the request's Delay Correction and Path
    /// ID into Origin Correction and Origin Path ID, sets its own Delay Correction and Path ID
    /// to zero, sends the Reserved field as zeros, and puts the field last - and it is 28
    /// octets long.
    /// </summary>
    [Test]
    public void TheCorrection_IsCopiedToTheOrigin_AndGoesLast()
    {

        const Int64  delayCorrection = 0x0000_1234_5678_9ABCL;
        const UInt16 pathId          = 0xBEEF;

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5ExtensionField.ServerInformationRequest());
        request.ExtensionFields.Add(RawNtpV5Fields.Correction(DelayCorrection: delayCorrection, DelayPathId: pathId));

        var response = Exchange(Server, request);
        var field    = response.Find(RawNtpV5Draft.Correction);

        Assert.That(field, Is.Not.Null, "§ 7.7: a server that supports the field SHOULD include it");

        var correction = RawNtpV5Fields.ReadCorrection(field!);

        Assert.Multiple(() => {
            Assert.That(field!.Length,                     Is.EqualTo(28),                  "§ 7.7: the field is 28 octets");
            Assert.That(response.ExtensionFields[^1].Type, Is.EqualTo(RawNtpV5Draft.Correction), "§ 7.7: it MUST be the last extension field");
            Assert.That(correction.OriginCorrection,       Is.EqualTo(delayCorrection),     "§ 7.7: the request's Delay Correction goes into Origin Correction");
            Assert.That(correction.OriginPathId,           Is.EqualTo(pathId),              "§ 7.7: the request's Path ID goes into Origin Path ID");
            Assert.That(correction.Reserved,               Is.Zero,                         "§ 7.7: the Reserved field is sent as zeros");
            Assert.That(correction.DelayCorrection,        Is.Zero,                         "§ 7.7: the server's own Delay Correction SHOULD be zero");
            Assert.That(correction.DelayPathId,            Is.Zero,                         "§ 7.7: the server's own Path ID SHOULD be zero");
        });

    }

    #endregion

    #region § 7.8: Reference Timestamp

    /// <summary>
    /// § 7.8: the time of the last update of the clock, 12 octets: before the request was
    /// received, never zero for a synchronized server, and the same as the NTPv4 reference
    /// timestamp of the same server, which says the same thing.
    /// </summary>
    [Test]
    public void TheReferenceTimestamp_IsWhenTheClockWasLastSet()
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5Fields.ReferenceTimestampRequest());

        var response = Exchange(Server, request);
        var field    = response.Find(RawNtpV5Draft.ReferenceTimestamp);

        Assert.That(field, Is.Not.Null, "§ 7.8: the Reference Timestamp field for the request");

        var reference = RawNtpV5Fields.ReadReferenceTimestamp(field!);
        var ntpv4     = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(), "127.0.0.1", Server.NTPPort);

        Assert.Multiple(() => {
            Assert.That(field!.Length, Is.EqualTo(12),                                    "§ 7.8: the field is 12 octets");
            Assert.That(reference,     Is.Not.Zero,                                       "a synchronized server's clock was set at some time");
            Assert.That(reference,     Is.LessThanOrEqualTo(response.ReceiveTimestamp),   "§ 7.8: the last update was before the request was received");
            Assert.That(reference,     Is.EqualTo(ntpv4.ReferenceTimestamp),              "the same server, the same last update, in NTPv5 and NTPv4");
        });

    }

    #endregion

    #region § 7.9: Monotonic Receive Timestamp

    /// <summary>
    /// § 7.9: 16 octets, an epoch ID and a receive timestamp of a clock that is not corrected
    /// in phase. Two from the same epoch can be compared: they keep the epoch, and they advance
    /// as the time between the two requests does.
    /// </summary>
    [Test]
    public async Task TheMonotonicReceiveTimestamp_KeepsItsEpoch_AndAdvances()
    {

        var request1 = RawNtpV5Packet.ClientRequest();
        request1.ExtensionFields.Add(RawNtpV5Fields.MonotonicReceiveTimestampRequest());
        var response1 = Exchange(Server, request1);

        await Task.Delay(TimeSpan.FromMilliseconds(300));

        var request2 = RawNtpV5Packet.ClientRequest();
        request2.ExtensionFields.Add(RawNtpV5Fields.MonotonicReceiveTimestampRequest());
        var response2 = Exchange(Server, request2);

        var field1 = response1.Find(RawNtpV5Draft.MonotonicReceiveTimestamp);
        var field2 = response2.Find(RawNtpV5Draft.MonotonicReceiveTimestamp);

        Assert.That(field1, Is.Not.Null, "§ 7.9: the Monotonic Receive Timestamp field for the request");
        Assert.That(field2, Is.Not.Null, "§ 7.9: the Monotonic Receive Timestamp field for the request");

        var (epoch1, monotonic1) = RawNtpV5Fields.ReadMonotonicReceiveTimestamp(field1!);
        var (epoch2, monotonic2) = RawNtpV5Fields.ReadMonotonicReceiveTimestamp(field2!);

        // Both differences in 2^-32 s, compared in milliseconds.
        var monotonicMs = (monotonic2 - monotonic1)                                 / 4294967296.0 * 1000;
        var receiveMs   = (response2.ReceiveTimestamp - response1.ReceiveTimestamp) / 4294967296.0 * 1000;

        Assert.Multiple(() => {
            Assert.That(field1!.Length, Is.EqualTo(16),     "§ 7.9: the field is 16 octets");
            Assert.That(epoch2,         Is.EqualTo(epoch1), "§ 7.9: nothing restarted the frequency transfer, so the epoch is the same");
            Assert.That(monotonic2,     Is.GreaterThan(monotonic1), "§ 7.9: a later reception has a later monotonic timestamp");
            Assert.That(monotonicMs,    Is.EqualTo(receiveMs).Within(50),
                        $"§ 7.9: the monotonic clock advanced {monotonicMs:F1} ms where the header's receive timestamps advanced {receiveMs:F1} ms");
        });

    }

    #endregion

    #region § 7, § 10: several fields at once

    /// <summary>
    /// § 7 and § 10: every requested field the server supports is answered, the Correction
    /// stays last, and the response is still exactly as long as the request.
    /// </summary>
    [Test]
    public void AllTheFieldsAtOnce_AreAnswered_AndTheLengthHolds()
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5ExtensionField.ServerInformationRequest());
        request.ExtensionFields.Add(RawNtpV5Fields.ReferenceIDsRequest(0, 64));
        request.ExtensionFields.Add(RawNtpV5Fields.ReferenceTimestampRequest());
        request.ExtensionFields.Add(RawNtpV5Fields.MonotonicReceiveTimestampRequest());
        request.ExtensionFields.Add(RawNtpV5Fields.Correction(DelayCorrection: 42));

        var response = Exchange(Server, request);

        Assert.Multiple(() => {

            foreach (var type in new[] { RawNtpV5Draft.DraftIdentification,
                                         RawNtpV5Draft.ServerInformation,
                                         RawNtpV5Draft.ReferenceIDsResponse,
                                         RawNtpV5Draft.ReferenceTimestamp,
                                         RawNtpV5Draft.MonotonicReceiveTimestamp,
                                         RawNtpV5Draft.Correction })
                Assert.That(response.Find(type), Is.Not.Null, $"the field 0x{type:X4} is answered");

            Assert.That(response.ExtensionFields[^1].Type, Is.EqualTo(RawNtpV5Draft.Correction), "§ 7.7: the Correction is the last extension field");

        });

    }

    #endregion

}
