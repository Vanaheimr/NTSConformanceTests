using System.Buffers.Binary;
using System.Text;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpV5;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;

namespace NTSConformance.Server.Tests;

/// <summary>
/// A server answering NTPv5 as draft-ietf-ntp-ntpv5-10 has it, in the basic mode and without
/// authentication, checked on the wire with this suite's own reading of the draft
/// (<see cref="RawNtpV5Packet"/>) and no NTPv5 code of the server's.
///
/// The sections that bind a server: § 6 (the header and what a response carries in it), § 7
/// (extension fields: lengths without the message padding, requested fields echoed or padded
/// for), § 7.1 (a draft server answers only its own draft, and names it), § 7.6 (Server
/// Information), § 10 (what is dropped, what is answered, the response exactly as long as the
/// request), and § 12 (an NTPv4 client asking whether NTPv5 is there).
///
/// Many of the requirements are about silence: a server that is to drop a request must send
/// nothing at all, and the wait for nothing is kept short.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ServerTests
{

    private static readonly TimeSpan silence = TimeSpan.FromMilliseconds(750);

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


    private static Byte[]? Send(NornServerFixture Server, Byte[] Request, TimeSpan? Timeout = null)
        => RawUdpExchange.TryExchange(Request, "127.0.0.1", Server.NTPPort, Timeout);


    /// <summary>
    /// Send a request that has to be answered, and read the answer by § 6 and § 7.
    /// </summary>
    private static (RawNtpV5Packet Response, Byte[] Octets) Exchange(NornServerFixture Server, RawNtpV5Packet Request)
    {

        var octets = Send(Server, Request.Write())
                         ?? throw new AssertionException("the server did not answer an NTPv5 request it should have answered");

        Assert.That(RawNtpV5Packet.TryRead(octets, out var response, out var error), Is.True,
                    $"the response is no valid NTPv5 message: {error}\n{Bytes.Dump(octets)}");

        return (response!, octets);

    }


    /// <summary>
    /// § 9 step 4, a client's checks of a response, which any response has to pass to be one.
    /// </summary>
    private static void AssertAValidResponseTo(RawNtpV5Packet Request, RawNtpV5Packet Response, Byte[] RequestOctets, Byte[] ResponseOctets)
    {

        Assert.Multiple(() => {

            Assert.That(Response.Version,      Is.EqualTo(5),                    "§ 9: the version of a response is 5");
            Assert.That(Response.Mode,         Is.EqualTo(4),                    "§ 9: the mode of a response is 4");
            Assert.That(Response.ClientCookie, Is.EqualTo(Request.ClientCookie), "§ 6: the client cookie is a copy of the request's");

            Assert.That(Response.Flags & ~RawNtpV5Draft.KnownFlags, Is.Zero,
                        $"§ 9: every flag of a response is a known one, but 0x{Response.Flags:X4} has others");

            Assert.That(Response.Flags & ~Request.Flags, Is.Zero,
                        $"§ 10 step 6: no flag is set that the request did not set (request 0x{Request.Flags:X4}, response 0x{Response.Flags:X4})");

            Assert.That(ResponseOctets.Length, Is.EqualTo(RequestOctets.Length),
                        "§ 10 step 5: the response is exactly as long as the request");

        });

    }


    /// <summary>
    /// Silence, or at most a reply that no NTPv5 client could take for an answer to this request.
    /// </summary>
    private static void AssertNoNTPv5Answer(Byte[]? Reply, RawNtpV5Packet? Request, String Why)
    {

        if (Reply is null)
            return;

        if (RawNtpV5Packet.TryRead(Reply, out var response, out _) &&
            response!.Version == 5 &&
            response.Mode     == 4 &&
            (Request is null || response.ClientCookie == Request.ClientCookie))
        {
            Assert.Fail($"{Why}, but the server answered it in NTPv5:\n{Bytes.Dump(Reply)}");
        }

    }

    #endregion


    #region § 6 and § 9: a basic request and its response

    [Test]
    public void ABasicRequest_IsAnsweredInNTPv5()
    {

        var request             = RawNtpV5Packet.ClientRequest();
        var requestOctets       = request.Write();
        var (response, octets)  = Exchange(Server, request);

        AssertAValidResponseTo(request, response, requestOctets, octets);

        Assert.Multiple(() => {

            Assert.That(response.Reserved,          Is.Zero,                        "§ 6: the reserved bits contain 0");
            Assert.That(response.Stratum,           Is.InRange((Byte) 1, (Byte) 15), "a synchronized server's stratum");
            Assert.That(response.Precision,         Is.LessThan((SByte) 0),          "§ 6: the precision of the timestamps, a log2 of seconds");
            Assert.That(response.Timescale,         Is.EqualTo(RawNtpV5Draft.UTC),   "§ 10: the requested timescale, UTC, which every server has");
            Assert.That(response.ReceiveTimestamp,  Is.Not.Zero,                     "§ 9 step 5: a usable response has a receive timestamp");
            Assert.That(response.TransmitTimestamp, Is.Not.Zero,                     "§ 9 step 5: a usable response has a transmit timestamp");
            Assert.That(response.Flags & RawNtpV5Draft.Unsynchronized, Is.Zero,      "a synchronized server does not say it is not");

            Assert.That(response.TransmitTimestamp, Is.GreaterThanOrEqualTo(response.ReceiveTimestamp),
                        "§ 10: in the basic mode the transmit timestamp is taken when the response is formed, after the request was received");

        });

    }


    /// <summary>
    /// § 6: the Era is the NTP era of the receive timestamp, which matters from 2036 on - a
    /// server whose clock is past the rollover says era 1, and the 32 bits of seconds are then
    /// the ones of era 1.
    /// </summary>
    [TestCase(2026, 11, 28, 0)]
    [TestCase(2040,  1,  1, 1)]
    public async Task TheEra_IsTheEraOfTheReceiveTimestamp(Int32 Year, Int32 Month, Int32 Day, Byte Era)
    {

        var instant = new DateTimeOffset(Year, Month, Day, 12, 0, 0, TimeSpan.Zero);

        await using var server = await NornServerFixture.StartAsync(timeProvider: TestClock.FrozenAt(instant),
                                                                    ntpv5:        NTPv5Support.Draft);

        var (response, _) = Exchange(server, RawNtpV5Packet.ClientRequest());

        var seconds       = (Int64) (instant.UtcDateTime - RawNtpTimestamp.Epoch).TotalSeconds - Era * 4294967296L;

        Assert.Multiple(() => {
            Assert.That(response.Era,                                 Is.EqualTo(Era),             $"the era of {instant:O}");
            Assert.That((Int64) (response.ReceiveTimestamp >> 32),    Is.EqualTo(seconds),         "the seconds of the receive timestamp, in that era");
        });

    }


    /// <summary>
    /// § 6: root delay and dispersion are time32, 28 fractional bits, and SHOULD be rounded up
    /// to avoid underestimating the root distance. What does not fit, 16 s and more, is
    /// infinity: the largest finite value is just under 16 s, and sending it for 20 s would be
    /// the underestimate the rounding is there to prevent.
    /// </summary>
    // 20 ms and 1 ms are below the half, where rounding to the nearest goes down; 30 ms and
    // 100 ns are above it, where truncating does.
    [TestCase(20L * TimeSpan.TicksPerMillisecond,   "20 ms, 5368709.12 units")]
    [TestCase(TimeSpan.TicksPerMillisecond,         "1 ms, 268435.456 units")]
    [TestCase(30L * TimeSpan.TicksPerMillisecond,   "30 ms, 8053063.68 units")]
    [TestCase(1L,                                   "100 ns, 26.84 units")]
    [TestCase(TimeSpan.TicksPerSecond / 4,          "250 ms, exactly 2^26 units")]
    [TestCase(20L * TimeSpan.TicksPerSecond,        "20 s, more than the field holds")]
    public void RootDelayAndDispersion_AreRoundedUpInTime32(Int64 Ticks, String Why)
    {

        var value = TimeSpan.FromTicks(Ticks);

        Server.Server.Redescribe(RootDelay: value, RootDispersion: value);

        try
        {

            var (response, _) = Exchange(Server, RawNtpV5Packet.ClientRequest());
            var expected      = RawTime32.RoundedUp(value);

            Assert.Multiple(() => {
                Assert.That(response.RootDelay,      Is.EqualTo(expected), $"{Why}: root delay 0x{response.RootDelay:X8}, {RawTime32.ToSeconds(response.RootDelay):R} s");
                Assert.That(response.RootDispersion, Is.EqualTo(expected), $"{Why}: root dispersion 0x{response.RootDispersion:X8}, {RawTime32.ToSeconds(response.RootDispersion):R} s");
            });

        }
        finally
        {
            Server.Server.Redescribe();
        }

    }


    /// <summary>
    /// § 10: the timescale is the requested one if the server has it, and otherwise one it
    /// has - never one that is not defined.
    /// </summary>
    [TestCase(RawNtpV5Draft.TAI, "TAI")]
    [TestCase(RawNtpV5Draft.UT1, "UT1")]
    [TestCase((Byte) 200,        "an undefined timescale")]
    public void ATimescaleTheServerMayNotHave_IsAnsweredInOneItHas(Byte Timescale, String Why)
    {

        var (response, _) = Exchange(Server, RawNtpV5Packet.ClientRequest(Timescale: Timescale));

        Assert.That(response.Timescale, Is.AnyOf(RawNtpV5Draft.UTC, RawNtpV5Draft.TAI, RawNtpV5Draft.UT1),
                    $"asked for {Why}, the server answered in timescale {response.Timescale}, which is not defined");

    }

    #endregion

    #region § 7 and § 10: extension fields and the length of a response

    /// <summary>
    /// § 10 step 5: the response is exactly as long as the request, so that NTPv5 cannot
    /// amplify traffic - whatever the request is padded to.
    /// </summary>
    [TestCase(0)]
    [TestCase(4)]
    [TestCase(13)]
    [TestCase(200)]
    [TestCase(1000)]
    public void TheResponse_IsAsLongAsTheRequest(Int32 PaddingData)
    {

        var request = RawNtpV5Packet.ClientRequest();

        if (PaddingData > 0)
            request.ExtensionFields.Add(RawNtpV5ExtensionField.Padding(PaddingData));

        var requestOctets       = request.Write();
        var (response, octets)  = Exchange(Server, request);

        AssertAValidResponseTo(request, response, requestOctets, octets);

    }


    /// <summary>
    /// § 7.1: a draft server names its draft in the response to a request that named one - the
    /// same string, compared in full - and never a longer one than the client's.
    /// </summary>
    [Test]
    public void TheDraftIdentification_IsAnsweredWithTheSameDraft()
    {

        var (response, _) = Exchange(Server, RawNtpV5Packet.ClientRequest());

        var field = response.Find(RawNtpV5Draft.DraftIdentification);

        Assert.That(field, Is.Not.Null, "§ 7.1: a draft server uses the field when answering a request with it");

        Assert.That(Encoding.ASCII.GetString(field!.Data), Is.EqualTo(RawNtpV5Draft.Identification),
                    "§ 7.1: the server answers as the draft the client named, by its full name, not null-terminated");

    }


    /// <summary>
    /// § 7.1: a server does not respond to a draft it does not recognize, the strings compared
    /// in full length - a longer one containing the right name is not it, and neither is a
    /// shorter one it contains, nor the right one null-terminated.
    /// </summary>
    [TestCase("draft-ietf-ntp-ntpv5-09",       "the previous draft")]
    [TestCase("draft-ietf-ntp-ntpv5-1",        "a prefix of the draft")]
    [TestCase("draft-ietf-ntp-ntpv5-100",      "a longer name beginning with the draft")]
    [TestCase("draft-ietf-ntp-ntpv5-10\0",     "the draft null-terminated")]
    [TestCase("DRAFT-IETF-NTP-NTPV5-10",       "the draft in capitals")]
    public void AnUnrecognizedDraft_IsNotAnswered(String Identification, String Why)
    {

        var request = RawNtpV5Packet.ClientRequest(DraftIdentification: Identification);

        AssertNoNTPv5Answer(Send(Server, request.Write(), silence), request,
                            $"§ 7.1: a draft server must not respond to {Why}");

    }


    /// <summary>
    /// § 7.1: a draft server uses the Draft Identification field if and only if the request had
    /// it - so a request without one, which is how the final version will ask, is not one it
    /// can answer.
    /// </summary>
    [Test]
    public void ARequestWithoutADraftIdentification_IsNotAnswered()
    {

        var request = RawNtpV5Packet.ClientRequest(DraftIdentification: null);

        AssertNoNTPv5Answer(Send(Server, request.Write(), silence), request,
                            "§ 7.1: a draft server cannot answer a request that names no draft");

    }


    /// <summary>
    /// § 7.6: the Server Information field MUST be supported, 8 octets long, and says which NTP
    /// versions the server speaks (bit 0 for version 1) and which flags it supports.
    /// </summary>
    [Test]
    public void ServerInformation_SaysNTPv5IsSpoken()
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5ExtensionField.ServerInformationRequest());

        var requestOctets       = request.Write();
        var (response, octets)  = Exchange(Server, request);

        AssertAValidResponseTo(request, response, requestOctets, octets);

        var field = response.Find(RawNtpV5Draft.ServerInformation);

        Assert.That(field, Is.Not.Null, "§ 7.6: the field MUST be supported, and so be in the response");

        Assert.That(field!.Length, Is.EqualTo(8), "§ 7.6: the field is 8 octets long");

        var versions = BinaryPrimitives.ReadUInt16BigEndian(field.Data);
        var flags    = BinaryPrimitives.ReadUInt16BigEndian(field.Data.AsSpan(2));

        Assert.Multiple(() => {
            Assert.That(versions & 0x0010, Is.Not.Zero, $"§ 7.6: the server speaks NTPv5, so bit 4 is set (0x{versions:X4})");
            Assert.That(versions & 0x0008, Is.Not.Zero, $"§ 7.6: the server also speaks NTPv4, so bit 3 is set (0x{versions:X4})");
            Assert.That(flags & ~RawNtpV5Draft.KnownFlags, Is.Zero, $"§ 7.6: only flags NTPv5 defines can be supported (0x{flags:X4})");
        });

    }


    /// <summary>
    /// § 10 step 3: the server MUST ignore unknown extension fields - answer, but leave them
    /// out, and § 7 then has it make up their length with a Padding field.
    /// </summary>
    [Test]
    public void AnUnknownExtensionField_IsIgnored_AndPaddedFor()
    {

        const UInt16 unknown = 0xF5F0;

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(new RawNtpV5ExtensionField(unknown, new Byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }));

        var requestOctets       = request.Write();
        var (response, octets)  = Exchange(Server, request);

        AssertAValidResponseTo(request, response, requestOctets, octets);

        Assert.Multiple(() => {
            Assert.That(response.Find(unknown),               Is.Null,     "a field the server does not know is not one it can answer");
            Assert.That(response.Find(RawNtpV5Draft.Padding), Is.Not.Null, "§ 7: a server that leaves out a requested field MUST include a Padding field for it");
        });

    }


    /// <summary>
    /// § 7: the Length of a field excludes the message-level padding. The Draft Identification
    /// of draft -10 is 23 octets, a Length of 27, padded to 28 - a server that counted the
    /// padding, or wanted a multiple of 4, would not find the field at all. Checked here with a
    /// second odd-length field after it, which only parses if the first was skipped right.
    /// </summary>
    [Test]
    public void AnExtensionFieldLength_ExcludesThePadding()
    {

        var request = RawNtpV5Packet.ClientRequest();
        request.ExtensionFields.Add(RawNtpV5ExtensionField.Padding(5));
        request.ExtensionFields.Add(RawNtpV5ExtensionField.ServerInformationRequest());

        Assert.That(request.ExtensionFields[0].Length, Is.EqualTo(27), "the test's own premise: the draft name makes an odd length");

        var requestOctets       = request.Write();
        var (response, octets)  = Exchange(Server, request);

        AssertAValidResponseTo(request, response, requestOctets, octets);

        Assert.That(response.Find(RawNtpV5Draft.ServerInformation), Is.Not.Null,
                    "the Server Information field after two odd-length fields was not found, so their lengths were not read as § 7 has them");

    }

    #endregion

    #region § 6, § 10: flags

    /// <summary>
    /// § 10 step 3: the server MUST ignore unknown flags - answer, and not set them in turn,
    /// since a response may carry no flag the request did not set and none NTPv5 does not know.
    /// </summary>
    [TestCase((UInt16) 0x0008)]
    [TestCase((UInt16) 0x8000)]
    [TestCase((UInt16) 0xFFF8)]
    public void UnknownFlags_AreIgnored(UInt16 Flags)
    {

        var request             = RawNtpV5Packet.ClientRequest(Flags: Flags);
        var requestOctets       = request.Write();
        var (response, octets)  = Exchange(Server, request);

        AssertAValidResponseTo(request, response, requestOctets, octets);

    }


    /// <summary>
    /// § 10: a server not synchronized sets the Unsynchronized flag - and step 6 drops a
    /// response with a flag the request did not set, so only a client that asked with the flag
    /// hears from it at all.
    /// </summary>
    [Test]
    public void AnUnsynchronizedServer_AnswersOnlyAClientThatAccepts_ThatItIsNot()
    {

        Server.Server.Redescribe(Stratum: 16);

        try
        {

            var withoutTheFlag = RawNtpV5Packet.ClientRequest();

            AssertNoNTPv5Answer(Send(Server, withoutTheFlag.Write(), silence), withoutTheFlag,
                                "§ 10 step 6: an unsynchronized server drops the response to a request without the Unsynchronized flag");

            var withTheFlag             = RawNtpV5Packet.ClientRequest(Flags: RawNtpV5Draft.Unsynchronized);
            var requestOctets           = withTheFlag.Write();
            var (response, octets)      = Exchange(Server, withTheFlag);

            AssertAValidResponseTo(withTheFlag, response, requestOctets, octets);

            Assert.That(response.Flags & RawNtpV5Draft.Unsynchronized, Is.Not.Zero,
                        "§ 10: an unsynchronized server sets the Unsynchronized flag");

        }
        finally
        {
            Server.Server.Redescribe();
        }

    }

    #endregion

    #region § 6, § 10: what is dropped

    /// <summary>
    /// § 10 step 3: a request whose mode is not 3 is dropped.
    /// </summary>
    [TestCase((Byte) 0)]
    [TestCase((Byte) 1)]
    [TestCase((Byte) 2)]
    [TestCase((Byte) 4)]
    [TestCase((Byte) 5)]
    [TestCase((Byte) 6)]
    [TestCase((Byte) 7)]
    public void ARequestNotInMode3_IsDropped(Byte Mode)
    {

        var request  = RawNtpV5Packet.ClientRequest();
        request.Mode = Mode;

        AssertNoNTPv5Answer(Send(Server, request.Write(), silence), request,
                            $"§ 10 step 3: a request in mode {Mode} is dropped");

    }


    /// <summary>
    /// § 6 and § 10 step 3: a request that is not a valid NTPv5 message is dropped - one not
    /// divisible by 4, one whose extension field is shorter than its own header, and one whose
    /// extension field runs past the end.
    /// </summary>
    [TestCase("length not divisible by 4")]
    [TestCase("extension field length below 4")]
    [TestCase("extension field past the end")]
    public void AMalformedRequest_IsDropped(String What)
    {

        var request = RawNtpV5Packet.ClientRequest();
        var octets  = request.Write();

        switch (What)
        {

            case "length not divisible by 4":
                octets = [.. octets, 0, 0];
                break;

            case "extension field length below 4":
                octets = [.. octets, 0xF5, 0x01, 0x00, 0x02];
                break;

            case "extension field past the end":
                octets = [.. octets, 0xF5, 0x01, 0x00, 0x40];
                break;

        }

        AssertNoNTPv5Answer(Send(Server, octets, silence), request,
                            $"§ 6, § 10 step 3: a request with its {What} is not a valid message and is dropped");

    }

    #endregion

    #region § 12: NTPv5 negotiation in NTPv4

    /// <summary>
    /// § 12: a server that speaks NTPv5 and NTPv4 answers an NTPv4 request whose reference
    /// timestamp is the negotiation value with the same reference timestamp. A draft
    /// implementation uses "NTP5DRFT".
    /// </summary>
    [Test]
    public void AnNTPv4ClientAskingForNTPv5_IsToldItIsSpoken()
    {

        var request                 = RawNtpPacket.ClientRequest();
        request.ReferenceTimestamp  = RawNtpV5Draft.NegotiationMagic;

        var response = RawNtpExchange.Exchange(request, "127.0.0.1", Server.NTPPort);

        Assert.That(response.ReferenceTimestamp, Is.EqualTo(RawNtpV5Draft.NegotiationMagic),
                    $"§ 12: the reference timestamp \"NTP5DRFT\" is echoed, but came back as 0x{response.ReferenceTimestamp:X16}");

    }


    /// <summary>
    /// § 12: an ordinary NTPv4 request is not told anything of the kind - the reference
    /// timestamp of its response is the server's own.
    /// </summary>
    [Test]
    public void AnOrdinaryNTPv4Client_IsNotToldAnything()
    {

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(), "127.0.0.1", Server.NTPPort);

        Assert.That(response.ReferenceTimestamp, Is.Not.EqualTo(RawNtpV5Draft.NegotiationMagic),
                    "the negotiation value comes back only to a client that sent it");

    }

    #endregion

}


/// <summary>
/// A server that does not speak NTPv5 must not appear to - § 12: it has no business echoing the
/// negotiation value, and an NTPv5 request must get no NTPv5 answer from it.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5DisabledServerTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(ntpv5: NTPv5Support.Disabled);


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    [Test]
    public void AnNTPv5Request_GetsNoNTPv5Answer()
    {

        var request = RawNtpV5Packet.ClientRequest();
        var reply   = RawUdpExchange.TryExchange(request.Write(), "127.0.0.1", fixture!.NTPPort, TimeSpan.FromMilliseconds(750));

        if (reply is not null &&
            RawNtpV5Packet.TryRead(reply, out var response, out _) &&
            response!.Version      == 5 &&
            response.Mode          == 4 &&
            response.ClientCookie  == request.ClientCookie)
        {
            Assert.Fail($"a server without NTPv5 answered an NTPv5 request as NTPv5:\n{Bytes.Dump(reply)}");
        }

    }


    [Test]
    public void AnNTPv4ClientAskingForNTPv5_IsNotToldItIsSpoken()
    {

        var request                 = RawNtpPacket.ClientRequest();
        request.ReferenceTimestamp  = RawNtpV5Draft.NegotiationMagic;

        var response = RawNtpExchange.Exchange(request, "127.0.0.1", fixture!.NTPPort);

        Assert.That(response.ReferenceTimestamp, Is.Not.EqualTo(RawNtpV5Draft.NegotiationMagic),
                    "§ 12: a server that does not speak NTPv5 must not echo the negotiation value");

    }

}
