using System.Net;
using System.Text;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// The Time Sources of draft-ietf-ntp-ntpv5-10 § 7.5 and the Secondary Receive Timestamp of
/// § 7.10, read on the wire with this suite's own codec, as in <see cref="NTPv5ExtensionFieldTests"/>.
/// The server is given four time sources - one of each kind of identifier - and the
/// timescales UTC, TAI at 37 seconds and UT1 without a value: Norn answers neither field unless
/// told what to answer, § 7.5 speaking of a request that is "supported and enabled".
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5TimeSourcesTests
{

    #region Data

    private NornServerFixture? fixture;

    /// <summary>
    /// The sources the server is given, in its order.
    /// </summary>
    private static readonly NTPv5TimeSource[] Sources = [
        NTPv5TimeSource.Of(IPAddress.Parse("192.0.2.1"),     0.5,  Authenticated: true),
        NTPv5TimeSource.Of(IPAddress.Parse("2001:db8::123"), 0.25),
        NTPv5TimeSource.OfReferenceClock("GPS",              0.125),
        NTPv5TimeSource.Unidentified(                        0.0625)
    ];

    /// <summary>
    /// The same sources as § 7.5 puts them on the wire, written out here by hand: Share, Flags,
    /// IdType, Length, Identifier - 8, 20, 8 and 4 octets.
    /// </summary>
    private static readonly (Byte Share, Byte Flags, Byte IdType, Byte[] Identifier)[] Expected = [
        (RawNtpV5Fields.EncodeShare(0.5),    RawNtpV5Fields.TimeSourceAuthenticated, RawNtpV5Fields.TimeSourceIPv4,  [ 192, 0, 2, 1 ]),
        (RawNtpV5Fields.EncodeShare(0.25),   0,                                      RawNtpV5Fields.TimeSourceIPv6,  IPAddress.Parse("2001:db8::123").GetAddressBytes()),
        (RawNtpV5Fields.EncodeShare(0.125),  0,                                      RawNtpV5Fields.TimeSourceRefId, Encoding.ASCII.GetBytes("GPS\0")),
        (RawNtpV5Fields.EncodeShare(0.0625), 0,                                      RawNtpV5Fields.TimeSourceNone,  [])
    ];

    private static readonly TimeSpan TAIOffset = TimeSpan.FromSeconds(37);

    private static readonly Dictionary<NTPv5Timescale, TimeSpan?> Timescales = new() {
        [NTPv5Timescale.UTC] = TimeSpan.Zero,
        [NTPv5Timescale.TAI] = TAIOffset,
        [NTPv5Timescale.UT1] = null
    };

    #endregion


    [OneTimeSetUp]
    public async Task StartServer()
    {
        fixture = await NornServerFixture.StartAsync(ntpv5: NTPv5Support.Draft);
        Describe();
    }


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    #region Helpers

    private NornServerFixture Server
        => fixture ?? throw new InvalidOperationException("the server fixture did not start");


    /// <summary>
    /// Give the server the sources and timescales of this fixture - again after a test that
    /// described it otherwise.
    /// </summary>
    private void Describe()
        => Server.Server.Redescribe(NTPv5TimeSources: Sources,
                                    NTPv5Timescales:  Timescales);


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


    private RawNtpV5Packet AskForTimeSources(Byte Index, Int32 DataLength)
    {
        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5Fields.TimeSourcesRequest(Index, DataLength));
        return Exchange(Server, request);
    }


    private RawNtpV5Packet AskForTimescales(params Byte[] Timescales)
    {

        var request = RawNtpV5Packet.ClientRequest();

        foreach (var timescale in Timescales)
            request.ExtensionFields.Add(RawNtpV5Fields.SecondaryReceiveTimestampRequest(timescale));

        return Exchange(Server, request);

    }


    private static IEnumerable<RawNtpV5ExtensionField> All(RawNtpV5Packet Packet, UInt16 Type)
        => Packet.ExtensionFields.Where(field => field.Type == Type);


    private static String Show((Byte Share, Byte Flags, Byte IdType, Byte[] Identifier) Entry)
        => $"share {Entry.Share}, flags 0x{Entry.Flags:X2}, type {Entry.IdType}, id {Convert.ToHexString(Entry.Identifier)}";


    private static void AssertEntries(IReadOnlyList<(Byte Share, Byte Flags, Byte IdType, Byte[] Identifier)>?  Actual,
                                      IEnumerable<(Byte Share, Byte Flags, Byte IdType, Byte[] Identifier)>     ExpectedEntries,
                                      String                                                                     What)
    {

        Assert.That(Actual, Is.Not.Null, $"{What}: the entries of the response run past its end");

        Assert.That(Actual!.Select(Show), Is.EqualTo(ExpectedEntries.Select(Show)).AsCollection, What);

    }

    #endregion


    #region § 7.5: Time Sources

    /// <summary>
    /// § 7.5: a request with room for all of them gets every source, each with its share as
    /// § 7.4 encodes it, its flags, its kind of identifier and the length that kind has - and
    /// the response field is no longer than the request field.
    /// </summary>
    [Test]
    public void TheWholeList_IsEverySourceAsTheServerHasIt()
    {

        var field = AskForTimeSources(Index: 0, DataLength: 64).Find(RawNtpV5Draft.TimeSourcesResponse);

        Assert.That(field, Is.Not.Null, "§ 7.5: a server that supports and enables the field MUST include the Time Sources Response");

        Assert.Multiple(() => {

            Assert.That(field!.Length, Is.EqualTo(4 + 8 + 20 + 8 + 4), "§ 7.5: four sources of 8, 20, 8 and 4 octets, and the header");
            Assert.That(field.Length,  Is.LessThanOrEqualTo(4 + 64),   "§ 7.5: the response field MUST NOT be longer than the request field");

            AssertEntries(RawNtpV5Fields.TimeSources(field), Expected, "§ 7.5: the sources in the server's order, as § 7.5 encodes them");

        });

    }


    /// <summary>
    /// § 7.5: the identifier of each kind has the length the table gives it - 0 for None, 4 for
    /// IPv4, 16 for IPv6 and 4 for a reference identifier - and the share of each is the
    /// encoding of § 7.4: -16 log2(s), rounded up.
    /// </summary>
    [Test]
    public void EachIdentifier_HasTheLengthOfItsKind_AndEachShareTheEncodingOf74()
    {

        var entries = RawNtpV5Fields.TimeSources(AskForTimeSources(0, 64).Find(RawNtpV5Draft.TimeSourcesResponse)!);

        Assert.That(entries, Is.Not.Null.And.Count.EqualTo(4));

        var lengths = new Dictionary<Byte, Int32> {
            [RawNtpV5Fields.TimeSourceNone]  =  0,
            [RawNtpV5Fields.TimeSourceIPv4]  =  4,
            [RawNtpV5Fields.TimeSourceIPv6]  = 16,
            [RawNtpV5Fields.TimeSourceRefId] =  4
        };

        Assert.Multiple(() => {

            foreach (var entry in entries!)
                Assert.That(entry.Identifier, Has.Length.EqualTo(lengths[entry.IdType]), $"§ 7.5: an identifier of type {entry.IdType}");

            Assert.That(entries.Select(entry => entry.Share), Is.EqualTo(new Byte[] { 16, 32, 48, 64 }).AsCollection,
                        "§ 7.4: shares of 1/2, 1/4, 1/8 and 1/16 encode as 16, 32, 48 and 64");

        });

    }


    /// <summary>
    /// § 7.5: the response starts at the requested index and holds as many sources as fit in
    /// the length of the request field - and "MUST NOT skip sources in its list" to fit a
    /// shorter one in: from index 0 with 20 octets the IPv4 source fits, the IPv6 source after
    /// it does not, and the reference clock that would still fit is not sent either.
    /// </summary>
    [TestCase((Byte) 0, 20, 1)]
    [TestCase((Byte) 0, 24, 1)]
    [TestCase((Byte) 0, 28, 2)]
    [TestCase((Byte) 0, 36, 3)]
    [TestCase((Byte) 0, 40, 4)]
    [TestCase((Byte) 1, 20, 1)]
    [TestCase((Byte) 1, 28, 2)]
    [TestCase((Byte) 2, 20, 2)]
    [TestCase((Byte) 3, 20, 1)]
    public void AFragment_StartsAtItsIndex_FitsTheRequest_AndSkipsNoSource(Byte Index, Int32 DataLength, Int32 Count)
    {

        var field = AskForTimeSources(Index, DataLength).Find(RawNtpV5Draft.TimeSourcesResponse);

        Assert.That(field, Is.Not.Null, $"§ 7.5: index {Index} is one of the server's sources and is answered");

        Assert.Multiple(() => {

            Assert.That(field!.Length, Is.LessThanOrEqualTo(4 + DataLength), "§ 7.5: the response field MUST NOT be longer than the request field");

            AssertEntries(RawNtpV5Fields.TimeSources(field), Expected.Skip(Index).Take(Count),
                          $"§ 7.5: from index {Index}, the {Count} sources that fit in {DataLength} octets, none skipped");

        });

    }


    /// <summary>
    /// § 7.5: "If the index in the request is not valid for the server's number of sources,
    /// the response extension field MUST be empty" - unlike § 7.4, whose field is ignored then.
    /// </summary>
    [TestCase((Byte)   4)]
    [TestCase((Byte)   5)]
    [TestCase((Byte) 255)]
    public void AnIndexThatIsNoSource_GetsAnEmptyResponseField(Byte Index)
    {

        var field = AskForTimeSources(Index, 20).Find(RawNtpV5Draft.TimeSourcesResponse);

        Assert.That(field, Is.Not.Null, $"§ 7.5: the request for index {Index} of 4 sources still gets a response field");
        Assert.That(field!.Data, Is.Empty, "§ 7.5: the response extension field MUST be empty");

    }


    /// <summary>
    /// § 7.5: a server whose list is empty has no valid index, and answers with an empty field.
    /// </summary>
    [Test]
    public void AServerWithoutSources_AnswersWithAnEmptyField()
    {

        Server.Server.Redescribe(NTPv5TimeSources: [], NTPv5Timescales: Timescales);

        try
        {

            var field = AskForTimeSources(0, 20).Find(RawNtpV5Draft.TimeSourcesResponse);

            Assert.That(field, Is.Not.Null, "§ 7.5: the field is enabled, with no source");
            Assert.That(field!.Data, Is.Empty, "§ 7.5: index 0 is not valid for no sources: the response field MUST be empty");

        }
        finally
        {
            Describe();
        }

    }


    /// <summary>
    /// § 7.5 and § 7: a server where the field is not enabled leaves it out of the response and
    /// pads for it, so that the response stays as long as the request.
    /// </summary>
    [Test]
    public void AServerWhereTheFieldIsNotEnabled_LeavesItOut_AndPadsForIt()
    {

        Server.Server.Redescribe();

        try
        {

            var response = AskForTimeSources(0, 20);

            Assert.Multiple(() => {
                Assert.That(response.Find(RawNtpV5Draft.TimeSourcesResponse), Is.Null,     "§ 7.5: only a server where the field is \"supported and enabled\" answers it");
                Assert.That(response.Find(RawNtpV5Draft.Padding),             Is.Not.Null, "§ 7: a left-out field is padded for");
            });

        }
        finally
        {
            Describe();
        }

    }


    /// <summary>
    /// § 7.5: the data of the request "MUST be at least 20 octets ... and be divisible by 4
    /// octets". The draft does not say what a server does with one that is not; § 10 step 3
    /// drops a request "if the format is not valid". Either way it gets no Time Sources
    /// Response - one with room for less than an IPv6 source, or of a length it was not asked
    /// for - and if it is answered at all, then as long as the request.
    /// </summary>
    [TestCase( 4)]
    [TestCase(16)]
    [TestCase(18)]
    [TestCase(22)]
    [TestCase(23)]
    public void ARequestOfTheWrongLength_GetsNoTimeSources(Int32 DataLength)
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5Fields.TimeSourcesRequest(0, DataLength));

        var requestOctets  = request.Write();
        var responseOctets = RawUdpExchange.TryExchange(requestOctets, "127.0.0.1", Server.NTPPort);

        if (responseOctets is null)
        {
            Assert.Pass($"§ 10 step 3: the request with {DataLength} octets of data was dropped");
            return;
        }

        var response = Read(responseOctets, $"the request with {DataLength} octets of data");

        Assert.Multiple(() => {
            Assert.That(response.Find(RawNtpV5Draft.TimeSourcesResponse), Is.Null,                             $"§ 7.5: {DataLength} octets of data is no valid Time Sources Request");
            Assert.That(responseOctets.Length,                            Is.EqualTo(requestOctets.Length),   "§ 10 step 5: the response is as long as the request");
        });

    }

    #endregion

    #region § 7.10: Secondary Receive Timestamp

    /// <summary>
    /// § 7.10: the fields of a response "have the same meaning as the Timescale, Era, and
    /// Receive Timestamp fields in the header" - for UTC, the timescale the header is in, the
    /// era and timestamp of the header itself. The field is 16 octets, its Reserved zero.
    /// </summary>
    [Test]
    public void UTC_IsTheReceiveTimestampOfTheHeader()
    {

        var response = AskForTimescales(RawNtpV5Draft.UTC);
        var field    = response.Find(RawNtpV5Draft.SecondaryReceiveTimestamp);

        Assert.That(field, Is.Not.Null, "§ 7.10: the server MUST include timestamps in all requested timescales it supports");

        var secondary = RawNtpV5Fields.ReadSecondaryReceiveTimestamp(field!);

        Assert.Multiple(() => {
            Assert.That(field!.Length,       Is.EqualTo(16),                         "§ 7.10: the field is 16 octets");
            Assert.That(response.Timescale,  Is.EqualTo(RawNtpV5Draft.UTC),          "the header is in UTC, as asked");
            Assert.That(secondary.Timescale, Is.EqualTo(RawNtpV5Draft.UTC),          "§ 7.10: the timescale asked for");
            Assert.That(secondary.Reserved,  Is.Zero,                                "§ 7.10: Reserved");
            Assert.That(secondary.Era,       Is.EqualTo(response.Era),               "§ 7.10: the era of the header, in the same timescale");
            Assert.That(secondary.Timestamp, Is.EqualTo(response.ReceiveTimestamp),  "§ 7.10: the receive timestamp of the header, in the same timescale");
        });

    }


    /// <summary>
    /// § 7.10: in TAI, the same reception 37 seconds later - exactly, era included, since a
    /// whole number of seconds is a whole number of 2^-32 s.
    /// </summary>
    [Test]
    public void TAI_IsTheReceiveTimestampOfTheHeader_ShiftedByTheOffset()
    {

        var response = AskForTimescales(RawNtpV5Draft.TAI);
        var field    = response.Find(RawNtpV5Draft.SecondaryReceiveTimestamp);

        Assert.That(field, Is.Not.Null, "§ 7.10: the server supports TAI and MUST include it");

        var secondary = RawNtpV5Fields.ReadSecondaryReceiveTimestamp(field!);

        Assert.Multiple(() => {

            Assert.That(secondary.Timescale, Is.EqualTo(RawNtpV5Draft.TAI), "§ 7.10: the timescale asked for");
            Assert.That(secondary.Reserved,  Is.Zero,                       "§ 7.10: Reserved");

            Assert.That(RawNtpV5Fields.Continuous(secondary.Era, secondary.Timestamp) - RawNtpV5Fields.Continuous(response.Era, response.ReceiveTimestamp),
                        Is.EqualTo((Int128) 37 << 32),
                        "§ 7.10: the reception of the header, in TAI: 37 s after UTC");

        });

    }


    /// <summary>
    /// § 7.10: "If the server supports the timescale, but ... is not able to convert another
    /// receive timestamp to this timescale, it SHOULD set the timestamp field to 0 to indicate
    /// the presence of the support" - UT1 here, which the server was given without an offset.
    /// </summary>
    [Test]
    public void ATimescaleWithoutAValue_IsAnsweredWithZero()
    {

        var field = AskForTimescales(RawNtpV5Draft.UT1).Find(RawNtpV5Draft.SecondaryReceiveTimestamp);

        Assert.That(field, Is.Not.Null, "§ 7.10: the server supports UT1 and MUST include it");

        var secondary = RawNtpV5Fields.ReadSecondaryReceiveTimestamp(field!);

        Assert.Multiple(() => {
            Assert.That(secondary.Timescale, Is.EqualTo(RawNtpV5Draft.UT1), "§ 7.10: the timescale asked for");
            Assert.That(secondary.Timestamp, Is.Zero,                       "§ 7.10: the timestamp field SHOULD be 0");
        });

    }


    /// <summary>
    /// § 7.10: "If the server does not support the requested timescale, it MUST ignore the
    /// extension field in the request" - and § 7 pads for it.
    /// </summary>
    [TestCase((Byte)   3)]
    [TestCase((Byte)  42)]
    [TestCase((Byte) 255)]
    public void AnUnsupportedTimescale_IsIgnored_AndPaddedFor(Byte Timescale)
    {

        var response = AskForTimescales(Timescale);

        Assert.Multiple(() => {
            Assert.That(response.Find(RawNtpV5Draft.SecondaryReceiveTimestamp), Is.Null,     $"§ 7.10: timescale {Timescale} is not supported and MUST be ignored");
            Assert.That(response.Find(RawNtpV5Draft.Padding),                   Is.Not.Null, "§ 7: a left-out field is padded for");
        });

    }


    /// <summary>
    /// § 7.10: a server described with no timescales but its own supports UTC alone - TAI and
    /// UT1 are ignored then.
    /// </summary>
    [Test]
    public void AServerWithUTCAlone_IgnoresTheOthers()
    {

        Server.Server.Redescribe();

        try
        {

            var response   = AskForTimescales(RawNtpV5Draft.UTC, RawNtpV5Draft.TAI, RawNtpV5Draft.UT1);
            var timescales = All(response, RawNtpV5Draft.SecondaryReceiveTimestamp).Select(field => RawNtpV5Fields.ReadSecondaryReceiveTimestamp(field).Timescale);

            Assert.That(timescales, Is.EqualTo(new[] { RawNtpV5Draft.UTC }).AsCollection,
                        "§ 7.10: UTC is answered, the timescales it does not support are ignored");

        }
        finally
        {
            Describe();
        }

    }


    /// <summary>
    /// § 7.10: "A request MAY contain multiple instances of this extension field" and "The server
    /// MUST include in its response timestamps in all requested timescales it supports" - each
    /// once, and the one it does not support not at all.
    /// </summary>
    [Test]
    public void SeveralTimescales_AreEachAnsweredOnce()
    {

        var response   = AskForTimescales(RawNtpV5Draft.UTC, RawNtpV5Draft.TAI, 42, RawNtpV5Draft.UT1);
        var timescales = All(response, RawNtpV5Draft.SecondaryReceiveTimestamp).Select(field => RawNtpV5Fields.ReadSecondaryReceiveTimestamp(field).Timescale);

        Assert.That(timescales, Is.EquivalentTo(new[] { RawNtpV5Draft.UTC, RawNtpV5Draft.TAI, RawNtpV5Draft.UT1 }),
                    "§ 7.10: every requested timescale the server supports, once each; 42 ignored");

    }


    /// <summary>
    /// § 7.10: the instances of a request "MUST request different timescales". One that asks for
    /// the same twice breaks that; whatever the server answers, it is no longer than the request
    /// (which <see cref="Exchange"/> checks) and still in that timescale.
    /// </summary>
    [Test]
    public void ATimescaleAskedForTwice_KeepsTheLength()
    {

        var response = AskForTimescales(RawNtpV5Draft.TAI, RawNtpV5Draft.TAI);
        var fields   = All(response, RawNtpV5Draft.SecondaryReceiveTimestamp).ToList();

        Assert.That(fields.Select(field => RawNtpV5Fields.ReadSecondaryReceiveTimestamp(field).Timescale), Is.All.EqualTo(RawNtpV5Draft.TAI),
                    "§ 7.10: an answer, if any, in the timescale asked for");

    }

    #endregion

    #region § 7, § 10: both at once

    /// <summary>
    /// § 7 and § 10: both fields in one request with the others of § 7 are each answered, and
    /// the response is still exactly as long as the request.
    /// </summary>
    [Test]
    public void BothFieldsWithTheOthers_AreAnswered_AndTheLengthHolds()
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5ExtensionField.ServerInformationRequest());
        request.ExtensionFields.Add(RawNtpV5Fields.TimeSourcesRequest(0, 64));
        request.ExtensionFields.Add(RawNtpV5Fields.SecondaryReceiveTimestampRequest(RawNtpV5Draft.TAI));
        request.ExtensionFields.Add(RawNtpV5Fields.ReferenceIDsRequest(0, 32));
        request.ExtensionFields.Add(RawNtpV5Fields.Correction(DelayCorrection: 42));

        var response = Exchange(Server, request);

        Assert.Multiple(() => {

            foreach (var type in new[] { RawNtpV5Draft.DraftIdentification,
                                         RawNtpV5Draft.ServerInformation,
                                         RawNtpV5Draft.TimeSourcesResponse,
                                         RawNtpV5Draft.SecondaryReceiveTimestamp,
                                         RawNtpV5Draft.ReferenceIDsResponse,
                                         RawNtpV5Draft.Correction })
                Assert.That(response.Find(type), Is.Not.Null, $"the field 0x{type:X4} is answered");

            AssertEntries(RawNtpV5Fields.TimeSources(response.Find(RawNtpV5Draft.TimeSourcesResponse)!), Expected, "§ 7.5: all four sources");

            Assert.That(response.ExtensionFields[^1].Type, Is.EqualTo(RawNtpV5Draft.Correction), "§ 7.7: the Correction is the last extension field");

        });

    }

    #endregion

}
