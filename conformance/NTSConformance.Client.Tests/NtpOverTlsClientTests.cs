using System.Security.Authentication;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTPOverTLS;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpOverTls;

namespace NTSConformance.Client.Tests;

/// <summary>
/// Norn's client of NTP over TLS after chapter 7 of BSI TR-03109-5, against a server of this
/// suite that keeps what it was sent and answers what a test tells it to - over the platform's
/// own TLS, not the BouncyCastle Norn runs on.
///
/// <para>
/// What the client sends is TA.NTP.BuildRequest (§ 7.3.1), what it believes TA.NTP.ProcessResponse
/// (§ 7.3.2): every requirement there that says a message is ignored has a response here that
/// breaks just it, and the client is held to ignoring that one and none of the correct ones.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtpOverTlsClientTests
{

    #region (private) helpers

    private static NTPOverTLSClient ClientOf(ScriptedNtpOverTlsServer                    server,
                                             String                                      host                = "127.0.0.1",
                                             Boolean                                     dataMinimization    = true,
                                             TestCertificate?                            clientCertificate   = null,
                                             TimeSpan?                                   timeout             = null)

        => new (host,
                IPPort.Parse(server.Port),
                (sender, certificate, chain, client, errors) => TLSValidationResult.Success(),
                clientCertificate?.Certificate,
                clientCertificate?.PrivateKey,
                Timeout:           timeout ?? TimeSpan.FromSeconds(10),
                DataMinimization:  dataMinimization);

    private static async Task<CapturedNtpOverTlsRequest> SettledRequestOf(ScriptedNtpOverTlsServer server)
    {

        var deadline = DateTime.UtcNow.AddSeconds(10);

        while (DateTime.UtcNow < deadline)
        {

            if (server.LastRequest is { ClosedByTheClient: true } request)
                return request;

            await Task.Delay(20);

        }

        return server.LastRequest ?? throw new AssertionException("The server saw no request. " + String.Join("; ", server.Failures));

    }

    private static async Task<NTPOverTLSResult> IgnoredFor(String                  requirement,
                                                           Action<RawNtpPacket>    tweak,
                                                           Boolean                 clockSynchronized = false,
                                                           TimeSpan?               serverClockOffset = null)
    {

        await using var server = ScriptedNtpOverTlsServer.Start(respond: request => ScriptedNtpOverTlsServer.Answer(request, tweak, serverClockOffset));

        var result = await ClientOf(server).QueryTime(clockSynchronized);

        Assert.That(result.Success,    Is.False, $"the response should have been ignored by {requirement}");
        Assert.That(result.IgnoredBy,  Is.EqualTo(requirement), result.ToString());

        return result;

    }

    #endregion


    #region TA.NTP.BuildRequest

    /// <summary>
    /// REQ.TA.NTP.BuildRequest.10, .20 and .30: an NTPv4 client request, without a UDP header,
    /// without extensions, 48 octets - and, from a client of one request per connection,
    /// nothing after it before it closes.
    /// </summary>
    [Test]
    public async Task TheRequest_IsA48OctetNtpV4ClientRequest([Values] Boolean dataMinimization)
    {

        await using var server = ScriptedNtpOverTlsServer.Start();

        var result  = await ClientOf(server, dataMinimization: dataMinimization).QueryTime();
        var request = await SettledRequestOf(server);

        Assert.That(result.Success,                   Is.True, result.ToString());
        Assert.That(request.Bytes,                    Has.Length.EqualTo(48));
        Assert.That(request.Packet!.Version,          Is.EqualTo(4));
        Assert.That(request.Packet.Mode,              Is.EqualTo(RawNtpMode.Client));
        Assert.That(request.Packet.ExtensionFields,   Is.Empty);
        Assert.That(request.OctetsAfterTheRequest,    Is.Zero, "nothing after the 48 octets");
        Assert.That(request.ClosedByTheClient,        Is.True, "the client closes once it has its response");

    }

    /// <summary>
    /// REQ.TA.NTP.BuildRequest.40, the column "Datenminimierung" of Table 7.1: leap 0, version 4,
    /// mode 3, stratum 0, poll 0, precision 32, and zero for root delay, root dispersion,
    /// reference ID and the reference, origin and receive timestamps - the transmit timestamp
    /// random.
    /// </summary>
    [Test]
    public async Task AMinimizedRequest_FollowsTable71()
    {

        await using var server = ScriptedNtpOverTlsServer.Start();

        Assert.That((await ClientOf(server).QueryTime()).Success, Is.True);
        Assert.That((await ClientOf(server).QueryTime()).Success, Is.True);

        var first   = server.Requests[0].Packet!;
        var second  = server.Requests[1].Packet!;

        Assert.That(first.LeapIndicator,        Is.Zero);
        Assert.That(first.Stratum,              Is.Zero);
        Assert.That(first.Poll,                 Is.Zero);
        Assert.That(first.Precision,            Is.EqualTo(32));
        Assert.That(first.RootDelay,            Is.Zero);
        Assert.That(first.RootDispersion,       Is.Zero);
        Assert.That(first.ReferenceIdentifier,  Is.All.Zero);
        Assert.That(first.ReferenceTimestamp,   Is.Zero);
        Assert.That(first.OriginTimestamp,      Is.Zero);
        Assert.That(first.ReceiveTimestamp,     Is.Zero);

        // Random, not this machine's clock: two requests a moment apart are not a moment apart.
        var asTime = RawNtpTimestamp.ToDateTime(first.TransmitTimestamp, RawNtpTimestamp.EraFor(DateTime.UtcNow));

        Assert.That(first.TransmitTimestamp,    Is.Not.Zero);
        Assert.That(first.TransmitTimestamp,    Is.Not.EqualTo(second.TransmitTimestamp));
        Assert.That((asTime - DateTime.UtcNow).Duration(), Is.GreaterThan(TimeSpan.FromMinutes(1)),
                    "a minimized transmit timestamp gives the client's clock away");

    }

    /// <summary>
    /// Without data minimization the transmit timestamp is the client's clock.
    /// </summary>
    [Test]
    public async Task AnOrdinaryRequest_CarriesTheClientsClock()
    {

        await using var server = ScriptedNtpOverTlsServer.Start();

        Assert.That((await ClientOf(server, dataMinimization: false).QueryTime()).Success, Is.True);

        var sent = RawNtpTimestamp.ToDateTime(server.LastRequest!.Packet!.TransmitTimestamp, RawNtpTimestamp.EraFor(DateTime.UtcNow));

        Assert.That((sent - DateTime.UtcNow).Duration(), Is.LessThan(TimeSpan.FromSeconds(5)));

    }

    #endregion

    #region TLS (chapter 6)

    /// <summary>
    /// REQ.TA.TLS.OpenHanSessionAsClient.30: the server is named by SNI, of type host_name,
    /// without a trailing dot - and RFC 6066 § 3 has no SNI for a literal address.
    /// </summary>
    [Test]
    public async Task TheServerIsNamedBySni()
    {

        await using var server = ScriptedNtpOverTlsServer.Start();

        Assert.That((await ClientOf(server, host: "localhost").QueryTime()).Success, Is.True);
        Assert.That(server.LastRequest!.TargetHostName, Is.EqualTo("localhost"));

        Assert.That((await ClientOf(server, host: "127.0.0.1").QueryTime()).Success, Is.True);
        Assert.That(server.LastRequest!.TargetHostName, Is.Empty, "no SNI for an address");

    }

    /// <summary>
    /// TLS 1.3 where the server has it (REQ.TA.TLS.OpenHanSessionAsClient.10), and the fallback
    /// to TLS 1.2 where it has not (REQ.TA.TLS.Handshake.190) - with no ALPN either way.
    /// </summary>
    [Test]
    public async Task TLS13_AndTheFallbackToTLS12([Values(SslProtocols.Tls12, SslProtocols.Tls13)] SslProtocols serverProtocol)
    {

        await using var server = ScriptedNtpOverTlsServer.Start(protocols: serverProtocol);

        var result = await ClientOf(server).QueryTime();

        Assert.That(result.Success,                        Is.True, result.ToString());
        Assert.That(server.LastRequest!.Protocol,          Is.EqualTo(serverProtocol));
        Assert.That(result.TLSVersion,                     Is.EqualTo(serverProtocol == SslProtocols.Tls13 ? "TLS 1.3" : "TLS 1.2"));
        Assert.That(server.LastRequest.NegotiatedAlpn,     Is.Null);

    }

    /// <summary>
    /// REQ.TA.TLS.Handshake.160: a server certificate that does not chain to a trusted root is
    /// refused where no validator of one's own says otherwise.
    /// </summary>
    [Test]
    public async Task AnUntrustedServerCertificate_IsRefused()
    {

        await using var server = ScriptedNtpOverTlsServer.Start();

        var result = await new NTPOverTLSClient("127.0.0.1", IPPort.Parse(server.Port), Timeout: TimeSpan.FromSeconds(10)).QueryTime();

        Assert.That(result.Success,          Is.False);
        Assert.That(server.Requests,         Is.Empty, "no request before the server is believed");

    }

    /// <summary>
    /// A server that asks for a client certificate is shown the one given.
    /// </summary>
    [Test]
    public async Task AClientCertificate_IsShownWhereTheServerAsks([Values(SslProtocols.Tls12, SslProtocols.Tls13)] SslProtocols protocol)
    {

        await using var server = ScriptedNtpOverTlsServer.Start(protocols: protocol, requireClientCertificate: true);

        var result = await ClientOf(server, clientCertificate: TestCertificate.Generate("cls-adapter.test", [ "cls-adapter.test" ])).QueryTime();

        Assert.That(result.Success,                                    Is.True, result + " / " + String.Join("; ", server.Failures));
        Assert.That(result.ClientCertificateSent,                      Is.True);
        Assert.That(server.LastRequest!.ClientCertificateSubject,      Is.EqualTo("CN=cls-adapter.test"));

    }

    #endregion

    #region TA.NTP.ProcessResponse

    /// <summary>
    /// A correct response is believed, and what the client reports of it is right: the offset
    /// of the server's clock, and the maximum error of § 7.3.2.1, "rootdelay/2+rootdisp".
    /// </summary>
    [Test]
    public async Task ACorrectResponse_IsBelieved_AndItsOffsetAndMaximumErrorAreRight([Values] Boolean dataMinimization)
    {

        var offset = TimeSpan.FromSeconds(5);

        await using var server = ScriptedNtpOverTlsServer.Start(respond: request => ScriptedNtpOverTlsServer.Answer(request, serverClockOffset: offset));

        var result = await ClientOf(server, dataMinimization: dataMinimization).QueryTime();

        Assert.That(result.Success,                                       Is.True, result.ToString());
        Assert.That((result.ClockOffset!.Value - offset).Duration(),      Is.LessThan(TimeSpan.FromMilliseconds(500)));
        Assert.That(result.MaximumError!.Value.TotalMilliseconds,         Is.EqualTo(10.0 / 2 + 2.0).Within(0.1), "10 ms root delay, 2 ms root dispersion");

    }

    /// <summary>REQ.TA.NTP.ProcessResponse.30: the origin timestamp is not the request's transmit timestamp.</summary>
    [Test]
    public Task AnOriginThatIsNotTheRequestsTransmitTimestamp_IsIgnored()
        => IgnoredFor("REQ.TA.NTP.ProcessResponse.30", response => response.OriginTimestamp ^= 1);

    /// <summary>REQ.TA.NTP.ProcessResponse.40: a transmit timestamp that cannot be converted to UTC.</summary>
    [Test]
    public Task AZeroTransmitTimestamp_IsIgnored()
        => IgnoredFor("REQ.TA.NTP.ProcessResponse.40", response => response.TransmitTimestamp = 0);

    /// <summary>REQ.TA.NTP.ProcessResponse.50: leap indicator 3, an unsynchronized server.</summary>
    [Test]
    public Task AnUnsynchronizedServer_IsIgnored()
        => IgnoredFor("REQ.TA.NTP.ProcessResponse.50", response => response.LeapIndicator = RawNtpLeapIndicator.Unsynchronized);

    /// <summary>REQ.TA.NTP.ProcessResponse.51: a version below 4.</summary>
    [Test]
    public Task AVersionBelow4_IsIgnored([Values(1, 2, 3)] Int32 version)
        => IgnoredFor("REQ.TA.NTP.ProcessResponse.51", response => response.Version = (Byte) version);

    /// <summary>REQ.TA.NTP.ProcessResponse.52: a mode other than 4.</summary>
    [Test]
    public Task AModeOtherThanServer_IsIgnored([Values(RawNtpMode.SymmetricPassive, RawNtpMode.Client, RawNtpMode.Broadcast)] Byte mode)
        => IgnoredFor("REQ.TA.NTP.ProcessResponse.52", response => response.Mode = mode);

    /// <summary>
    /// REQ.TA.NTP.ProcessResponse.110: where the client's clock is synchronized, a response more
    /// than 1000 s from it is ignored - and where it is not, § 7.1.1 has the first authentic
    /// time set the clock, so the same response is believed.
    /// </summary>
    [Test]
    public async Task AResponseFarFromASynchronizedClock_IsIgnored_AndBelievedByAnUnsynchronizedOne()
    {

        var offset = TimeSpan.FromSeconds(2000);

        await IgnoredFor("REQ.TA.NTP.ProcessResponse.110", _ => { }, clockSynchronized: true, serverClockOffset: offset);

        await using var server = ScriptedNtpOverTlsServer.Start(respond: request => ScriptedNtpOverTlsServer.Answer(request, serverClockOffset: offset));

        var result = await ClientOf(server).QueryTime(ClockSynchronized: false);

        Assert.That(result.Success,                                     Is.True, result.ToString());
        Assert.That((result.ClockOffset!.Value - offset).Duration(),    Is.LessThan(TimeSpan.FromSeconds(1)));

    }

    /// <summary>
    /// A kiss - stratum 0 - is not processed (§ 7.1.1 obliges no client to) and gives no time.
    /// </summary>
    [Test]
    public Task AKiss_IsIgnored()
        => IgnoredFor("RFC 5905 A.5.1.1", response => { response.Stratum = 0; response.WithReferenceIdentifier("RATE"); });

    /// <summary>
    /// REQ.TA.NTP.ProcessResponse.10: a response that took more than 9 seconds.
    /// </summary>
    [Test]
    [Category(TestCategories.Slow)]
    public async Task AResponseDelayedMoreThan9Seconds_IsIgnored()
    {

        await using var server = ScriptedNtpOverTlsServer.Start(delay: TimeSpan.FromSeconds(9.5));

        var result = await ClientOf(server, timeout: TimeSpan.FromSeconds(20)).QueryTime();

        Assert.That(result.Success,    Is.False);
        Assert.That(result.IgnoredBy,  Is.EqualTo("REQ.TA.NTP.ProcessResponse.10"), result.ToString());

    }

    /// <summary>
    /// A response cut short, or none at all, is no time.
    /// </summary>
    [Test]
    public async Task ATruncatedOrMissingResponse_IsNoTime([Values(0, 20, 47)] Int32 octets)
    {

        await using var server = ScriptedNtpOverTlsServer.Start(respond: request => ScriptedNtpOverTlsServer.Answer(request)[..octets]);

        var result = await ClientOf(server).QueryTime();

        Assert.That(result.Success,       Is.False);
        Assert.That(result.ErrorMessage,  Does.Contain("closed the connection"), result.ToString());

    }

    #endregion

}
