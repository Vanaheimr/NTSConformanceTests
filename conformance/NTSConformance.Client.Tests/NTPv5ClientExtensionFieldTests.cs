using System.Buffers.Binary;
using System.Net;
using System.Text;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// What Norn's NTPv5 client reads from the extension fields of a response, written by this
/// suite: the reference IDs of draft-ietf-ntp-ntpv5-10 § 7.4 and the loop § 9 has a client
/// that serves time look for in them, the time sources of § 7.5, the Server Information of
/// § 7.6, and the secondary receive timestamps of § 7.10.
///
/// <para>
/// § 7: "Clients are not required to use or support any of these extension fields", and "A
/// client can interpret the absence of an expected extension field in a response as an
/// indication that the server does not support the extension field." A client that reads one
/// has to read it right, though: a loop it misses is a synchronization loop it joins, and a
/// timescale offset off by a second is a clock off by a second.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientExtensionFieldTests
{

    #region Data

    private static readonly TimeSpan  Offset          = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The client's own reference ID, 56 bits.
    /// </summary>
    private const UInt64              OwnReferenceId  = 0x0012_3456_789A_BCDEUL;

    #endregion

    #region (private) Answered(Fields, OwnReferenceId = null, ExtensionFields = null, Now = null)

    /// <summary>
    /// One query, answered validly with the given fields added to the response.
    /// </summary>
    private static async Task<NTPv5QueryResult> Answered(Func<ReceivedNtpV5Request, IEnumerable<RawNtpV5ExtensionField>>  Fields,
                                                         UInt64?                                                          OwnReferenceId   = null,
                                                         IEnumerable<NTPv5ExtensionField>?                                ExtensionFields  = null,
                                                         DateTimeOffset?                                                  Now              = null)
    {

        await using var harness = new NTPv5ClientHarness(Now: Now, OwnReferenceId: OwnReferenceId);

        harness.Script = request => NTPv5ClientHarness.Send(harness.Plain(request,
                                                                          Offset,
                                                                          response => response.ExtensionFields.AddRange(Fields(request))));

        var result = await harness.Query(ExtensionFields: ExtensionFields);

        Assert.That(harness.Server.ScriptErrors, Is.Empty,  "the script threw");
        Assert.That(result.Success,              Is.True,   result.ErrorMessage);

        return result;

    }

    #endregion


    #region § 7.4 and § 9: reference IDs and loops

    /// <summary>
    /// § 7.4: a Reference IDs Response of the given entries, each an 8-bit share and a 56-bit ID,
    /// filled up to 32 with unused ones - 255 and zero, as a server has them.
    /// </summary>
    private static RawNtpV5ExtensionField ReferenceIds(params (Byte Share, UInt64 Id)[] Entries)
    {

        var data = new Byte[32 * 8];

        for (var i = 0; i < 32; i++)
        {
            var (share, id) = i < Entries.Length ? Entries[i] : ((Byte) 255, 0UL);
            BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(i * 8), ((UInt64) share << 56) | (id & 0x00FF_FFFF_FFFF_FFFFUL));
        }

        return new RawNtpV5ExtensionField(RawNtpV5Draft.ReferenceIDsResponse, data);

    }


    /// <summary>
    /// § 9: "If the server's list of reference IDs contains the client's own reference ID, it
    /// SHOULD not select the server for synchronization to avoid a synchronization loop", and
    /// § 7.4 has such a client "assume it is in a synchronization loop, and stop using that
    /// server". A server whose list has the client's ID among its sources, at a share of 50 %:
    /// the response is valid, read as sent, and a loop - not usable.
    /// </summary>
    [Test]
    public async Task AServerThatListsTheClientsOwnId_IsALoop()
    {

        var result = await Answered(_ => [ ReferenceIds((0, 0x0000_AAAA_AAAA_AAAAUL), (16, OwnReferenceId), (32, 0x0000_BBBB_BBBB_BBBBUL)) ],
                                    OwnReferenceId: OwnReferenceId);

        Assert.Multiple(() => {
            Assert.That(result.ReferenceIds,                         Has.Count.EqualTo(32),                  "the entries read");
            Assert.That(result.ReferenceIds?[1],                     Is.EqualTo(new NTPv5ReferenceIdEntry(16, OwnReferenceId)), "the second entry");
            Assert.That(result.IsLoop,                               Is.True,                                "the loop");
            Assert.That(result.IsUsable,                             Is.False,                               "a loop is usable");
        });

    }


    /// <summary>
    /// § 9 names no share below which a listed ID would not count: the smallest share there is,
    /// 255, is a loop as well - a loop through a source the server barely uses is still one.
    /// </summary>
    [Test]
    public async Task TheClientsOwnIdAtTheSmallestShare_IsALoopAllTheSame()
    {

        var result = await Answered(_ => [ ReferenceIds((0, 0x0000_AAAA_AAAA_AAAAUL), (255, OwnReferenceId)) ],
                                    OwnReferenceId: OwnReferenceId);

        Assert.That(result.IsLoop, Is.True);

    }


    /// <summary>
    /// And a list without the client's ID is no loop: the response is usable.
    /// </summary>
    [Test]
    public async Task AServerThatDoesNotListIt_IsNoLoop()
    {

        var result = await Answered(_ => [ ReferenceIds((0, 0x0000_AAAA_AAAA_AAAAUL), (16, OwnReferenceId + 1)) ],
                                    OwnReferenceId: OwnReferenceId);

        Assert.Multiple(() => {
            Assert.That(result.IsLoop,   Is.False);
            Assert.That(result.IsUsable, Is.True, result.Unusable.ToString());
        });

    }


    /// <summary>
    /// § 7: "A client can interpret the absence of an expected extension field in a response as
    /// an indication that the server does not support the extension field." A server that sends
    /// no reference IDs is one that cannot say, and that is no loop.
    /// </summary>
    [Test]
    public async Task AServerThatSendsNoReferenceIds_IsNoLoop()
    {

        var result = await Answered(_ => [], OwnReferenceId: OwnReferenceId);

        Assert.Multiple(() => {
            Assert.That(result.ReferenceIds,  Is.Null);
            Assert.That(result.IsLoop,        Is.False);
            Assert.That(result.IsUsable,      Is.True, result.Unusable.ToString());
        });

    }


    /// <summary>
    /// § 7.4: the entries are 8 octets each. A response whose data is not a whole number of them
    /// is none to read - and reading it anyway would take the last, broken entry for an ID.
    /// </summary>
    [Test]
    public async Task AReferenceIdsResponseOfBrokenEntries_IsNotRead()
    {

        var result = await Answered(_ => [ new RawNtpV5ExtensionField(RawNtpV5Draft.ReferenceIDsResponse, new Byte[12]) ],
                                    OwnReferenceId: OwnReferenceId);

        Assert.That(result.ReferenceIds, Is.Null);

    }

    #endregion

    #region § 7.5: time sources

    /// <summary>
    /// § 7.5: a Time Sources Response, each source a share, flags, the kind of identifier, its
    /// length, and the identifier.
    /// </summary>
    private static RawNtpV5ExtensionField TimeSources(params (Byte Share, Byte Flags, Byte IdType, Byte[] Identifier)[] Sources)

        => new (RawNtpV5Draft.TimeSourcesResponse,
                Sources.SelectMany(source => (Byte[]) [ source.Share, source.Flags, source.IdType, (Byte) source.Identifier.Length, .. source.Identifier ]).
                        ToArray());


    private static readonly NTPv5ExtensionField[] AskForTimeSources = [ NTPv5TimeSources.Request(0, 64) ];


    /// <summary>
    /// § 7.5: four sources of the four kinds - an authenticated IPv4 server at 50 %, an IPv6 one
    /// at 25 %, a GPS reference clock at 12.5 % and an unidentified source at 6.25 % - read as
    /// they were sent: share, flag, kind, address or code.
    /// </summary>
    [Test]
    public async Task TheTimeSources_AreReadAsTheServerSentThem()
    {

        var result = await Answered(_ => [ TimeSources((16, RawNtpV5Fields.TimeSourceAuthenticated, RawNtpV5Fields.TimeSourceIPv4,  IPAddress.Parse("192.0.2.1").GetAddressBytes()),
                                                       (32, 0,                                      RawNtpV5Fields.TimeSourceIPv6,  IPAddress.Parse("2001:db8::123").GetAddressBytes()),
                                                       (48, 0,                                      RawNtpV5Fields.TimeSourceRefId, Encoding.ASCII.GetBytes("GPS\0")),
                                                       (64, 0,                                      RawNtpV5Fields.TimeSourceNone,  [])) ],
                                    ExtensionFields: AskForTimeSources);

        var sources = result.TimeSources;

        Assert.That(sources, Has.Count.EqualTo(4), "the sources read");

        Assert.Multiple(() => {

            Assert.That(sources!.Select(source => source.DecodedShare),    Is.EqualTo(new[] { 0.5, 0.25, 0.125, 0.0625 }), "the shares");
            Assert.That(sources!.Select(source => source.IsAuthenticated), Is.EqualTo(new[] { true, false, false, false }), "the Authenticated flag");
            Assert.That(sources!.Select(source => source.IdType),
                        Is.EqualTo(new[] { NTPv5TimeSourceIdType.IPv4Address, NTPv5TimeSourceIdType.IPv6Address, NTPv5TimeSourceIdType.ReferenceIdentifier, NTPv5TimeSourceIdType.None }),
                        "the kinds");

            Assert.That(sources![0].IPAddress,                Is.EqualTo(IPAddress.Parse("192.0.2.1")),     "the IPv4 address");
            Assert.That(sources![1].IPAddress,                Is.EqualTo(IPAddress.Parse("2001:db8::123")), "the IPv6 address");
            Assert.That(sources![2].ReferenceIdentifierCode,  Is.EqualTo("GPS"),                            "the reference clock");
            Assert.That(sources![3].Identifier,               Is.Empty,                                     "the unidentified source");

        });

    }


    /// <summary>
    /// § 7.5: "An invalid index gives an empty response field" - a server with no source at the
    /// index asked for. That is a list of none, not a server that did not answer.
    /// </summary>
    [Test]
    public async Task AnEmptyTimeSourcesResponse_IsNoSources()
    {

        var result = await Answered(_ => [ TimeSources() ], ExtensionFields: AskForTimeSources);

        Assert.That(result.TimeSources, Is.Not.Null.And.Empty);

    }


    /// <summary>
    /// § 7.5 gives each kind of identifier its length: 0, 4, 16 and 4 octets. A source that runs
    /// past the end of the field, or an IPv4 source with 16 octets, makes the field one that does
    /// not read - and none of it is taken, rather than the sources before the break as though
    /// they were all.
    /// </summary>
    [TestCase("PastTheEnd")]
    [TestCase("AnIPv4AddressOf16Octets")]
    [TestCase("AReferenceClockOf8Octets")]
    public async Task ATimeSourcesResponseThatDoesNotRead_IsNotTaken(String How)
    {

        var field = How switch {
                        "PastTheEnd"              => new RawNtpV5ExtensionField(RawNtpV5Draft.TimeSourcesResponse, [ 16, 0, RawNtpV5Fields.TimeSourceIPv4, 4, 192, 0, 2, 1,
                                                                                                                    32, 0, RawNtpV5Fields.TimeSourceIPv4, 4, 192, 0 ]),
                        "AnIPv4AddressOf16Octets" => TimeSources((16, 0, RawNtpV5Fields.TimeSourceIPv4,  new Byte[16])),
                        _                         => TimeSources((16, 0, RawNtpV5Fields.TimeSourceRefId, Encoding.ASCII.GetBytes("GPS\0\0\0\0\0")))
                    };

        var result = await Answered(_ => [ field ], ExtensionFields: AskForTimeSources);

        Assert.That(result.TimeSources, Is.Null, $"{result.TimeSources?.Count} sources read");

    }

    #endregion

    #region § 7.6: Server Information

    /// <summary>
    /// § 7.6: the Server Information of a response says which versions - bit 0 for version 1 -
    /// and which flags the server supports. NTPv4 and NTPv5, and all three flags of § 6.
    /// </summary>
    [Test]
    public async Task TheServerInformation_IsReadAsTheServerSentIt()
    {

        var result = await Answered(_ => [ new RawNtpV5ExtensionField(RawNtpV5Draft.ServerInformation, [ 0x00, 0x18, 0x00, 0x07 ]) ],
                                    ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);

        Assert.That(result.ServerInformation,
                    Is.EqualTo(((UInt16) 0x0018, NTPv5Flags.Unsynchronized | NTPv5Flags.InterleavedMode | NTPv5Flags.AuthenticationNAK)));

    }


    /// <summary>
    /// § 7.6 makes the field 8 octets. One of another length is not read as one.
    /// </summary>
    [Test]
    public async Task AServerInformationOfAnotherLength_IsNotRead()
    {

        var result = await Answered(_ => [ new RawNtpV5ExtensionField(RawNtpV5Draft.ServerInformation, [ 0x00, 0x18, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00 ]) ],
                                    ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);

        Assert.That(result.ServerInformation, Is.Null);

    }

    #endregion

    #region § 7.10: secondary receive timestamps

    /// <summary>
    /// A Secondary Receive Timestamp of the response: the receive timestamp of the request in the
    /// given timescale, the given time from the header's.
    /// </summary>
    private static RawNtpV5ExtensionField SecondaryReceiveTimestamp(ReceivedNtpV5Request  Request,
                                                                    DateTimeOffset        Now,
                                                                    Byte                  Timescale,
                                                                    TimeSpan?             Ahead)
    {

        var (era, timestamp) = Ahead is TimeSpan ahead
                                   ? RawNtpV5Responses.ToTimestamp(Now.UtcDateTime + Offset + ahead)
                                   : ((Byte) 0, 0UL);

        return RawNtpV5Fields.SecondaryReceiveTimestampRequest(Timescale, era, 0, timestamp);

    }


    /// <summary>
    /// § 7.10: the Secondary Receive Timestamp has the fields of the header's - "Timescale, Era,
    /// Reserved, Timestamp" - for another timescale. A server in UTC, asked for TAI too, 37 s
    /// ahead: the client has the offset between the two as exactly 37 s, and the TAI time.
    /// </summary>
    [Test]
    public async Task TheOffsetOfTAI_IsTheDifferenceOfTheTwoTimestamps()
    {

        var now     = NTPv5ClientHarness.DefaultNow;

        var result  = await Answered(request => [ SecondaryReceiveTimestamp(request, now, RawNtpV5Draft.TAI, TimeSpan.FromSeconds(37)) ],
                                     ExtensionFields: [ NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.TAI) ]);

        Assert.Multiple(() => {
            Assert.That(result.TimescaleOffset(NTPv5Timescale.TAI),      Is.EqualTo(TimeSpan.FromSeconds(37)));
            Assert.That(result.SecondaryReceiveTimes[NTPv5Timescale.TAI], Is.EqualTo(now.UtcDateTime + Offset + TimeSpan.FromSeconds(37)));
        });

    }


    /// <summary>
    /// The same across the rollover: a receive timestamp in UTC a few seconds before the end of
    /// era 0, and the TAI one, 37 s later, in era 1. Taken by its era, the offset is 37 s - and
    /// not the 136 years less 37 s of a TAI timestamp read in era 0.
    /// </summary>
    [Test]
    public async Task AcrossTheRollover_TheOffsetIsTakenByTheEra()
    {

        var now     = new DateTimeOffset(RawNtpV5Responses.Epoch.AddSeconds(RawNtpV5Responses.SecondsPerEra), TimeSpan.Zero) - Offset - TimeSpan.FromSeconds(5);

        var result  = await Answered(request => [ SecondaryReceiveTimestamp(request, now, RawNtpV5Draft.TAI, TimeSpan.FromSeconds(37)) ],
                                     ExtensionFields: [ NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.TAI) ],
                                     Now:             now);

        Assert.That(result.TimescaleOffset(NTPv5Timescale.TAI), Is.EqualTo(TimeSpan.FromSeconds(37)));

    }


    /// <summary>
    /// § 7.10: a timescale the server supports but has no value for is answered with a timestamp
    /// that "SHOULD be 0". That is no time and no offset.
    /// </summary>
    [Test]
    public async Task AZeroTimestamp_IsNoTimeAndNoOffset()
    {

        var result = await Answered(request => [ SecondaryReceiveTimestamp(request, NTPv5ClientHarness.DefaultNow, RawNtpV5Draft.UT1, null) ],
                                    ExtensionFields: [ NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.UT1) ]);

        Assert.Multiple(() => {
            Assert.That(result.SecondaryReceiveTimes.ContainsKey(NTPv5Timescale.UT1), Is.True,  "the timescale is not reported as answered");
            Assert.That(result.SecondaryReceiveTimes[NTPv5Timescale.UT1],             Is.Null,  "a time of zero");
            Assert.That(result.TimescaleOffset(NTPv5Timescale.UT1),                   Is.Null,  "an offset from zero");
        });

    }


    /// <summary>
    /// § 7.10: an unsupported timescale is ignored, the field left out and padded for. The
    /// response then carries no time in it, and the client reports none - not a zero, which
    /// would say the server knows the timescale.
    /// </summary>
    [Test]
    public async Task AnUnansweredTimescale_IsNotReported()
    {

        var result = await Answered(_ => [ RawNtpV5ExtensionField.Padding(12) ],
                                    ExtensionFields: [ NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.TAI) ]);

        Assert.Multiple(() => {
            Assert.That(result.SecondaryReceiveTimes.ContainsKey(NTPv5Timescale.TAI), Is.False);
            Assert.That(result.TimescaleOffset(NTPv5Timescale.TAI),                   Is.Null);
        });

    }

    #endregion

}
