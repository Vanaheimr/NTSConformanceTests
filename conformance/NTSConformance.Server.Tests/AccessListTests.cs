using System.Net.Sockets;
using System.Security.Authentication;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtsKe;

using IPNetwork = System.Net.IPNetwork;

namespace NTSConformance.Server.Tests;

/// <summary>
/// Who may query the server at all: the access list of RFC 8633 § 5.1, "Minimizing Information
/// Leakage", observed on the wire by this suite's own packet reader, its own TLS client and its
/// own NTS-KE codec over SSH.
///
/// <para>
/// Every NTP response tells whoever asked the server's reference identifier, reference time,
/// stratum and root distance, and § 5.1 recommends access control lists to limit who learns
/// them. An address the list does not allow learns none of it, and not even that a server is
/// there: no answer, no kiss, no TLS handshake, no SSH version string.
/// </para>
/// <para>
/// One server and two client addresses in every test. The server listens on both address
/// families, so a client on 127.0.0.1 and one on ::1 reach the same listener from different
/// addresses: the denied one gets nothing, and the other one gets its answer from the same
/// server in the same test. Silence by itself would prove little, since a server that has
/// stopped is silent too.
/// </para>
/// <para>
/// A dual-stack socket reports the IPv4 client as ::ffff:127.0.0.1, so a list written in IPv4
/// also has to match that client by its IPv4 address. Each direction of this has a list of its
/// own below. If the match is missed where an IPv4 network allows, the operator's own clients
/// go unanswered. If it is missed where an IPv4 network denies, the clients the list was
/// written to keep out are let in.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class AccessListTests
{

    private static readonly ISshHostKey ClientKey = SshHostKey.GenerateEd25519();

    /// <summary>
    /// How long to listen for an answer that must not come. Over loopback, an answer that comes
    /// at all comes within milliseconds, and the server's own count of what it dropped backs
    /// every silence up.
    /// </summary>
    private static readonly TimeSpan Silence = TimeSpan.FromSeconds(1);


    #region The lists, and whom each of them lets in

    /// <summary>
    /// One of the two clients, known by the address it comes from.
    /// </summary>
    public sealed record Client(String Host, AddressFamily Family)
    {
        public override String ToString() => Host;
    }

    private static readonly Client IPv4 = new ("127.0.0.1", AddressFamily.InterNetwork);
    private static readonly Client IPv6 = new ("::1",       AddressFamily.InterNetworkV6);


    /// <summary>
    /// A list, the client it allows and the client it denies.
    /// </summary>
    public sealed record Case(NTPAccessList List, Client Allowed, Client Denied)
    {
        public override String ToString() => $"'{List}'";
    }


    private static IEnumerable<TestCaseData> Lists()
    {

        // Everything is denied, and the IPv4 loopback address is allowed inside it. The most
        // specific network decides, and 127.0.0.1/32 has to allow the IPv4 client although the
        // socket reports it as ::ffff:127.0.0.1, which ::/0 (denied) contains as well.
        yield return new TestCaseData(new Case(new NTPAccessList(Allow: [ IPNetwork.Parse("127.0.0.1/32") ],
                                                                 Deny:  [ IPNetwork.Parse("0.0.0.0/0"), IPNetwork.Parse("::/0") ]),
                                               Allowed: IPv4,
                                               Denied:  IPv6)).
                         SetArgDisplayNames("deny all, allow 127.0.0.1");

        // The IPv4 loopback network is denied and nothing else. An address that no network
        // contains is allowed, and 127.0.0.0/8 has to deny the IPv4 client in its IPv6 form,
        // which only an IPv4 network contains.
        yield return new TestCaseData(new Case(new NTPAccessList(Deny: [ IPNetwork.Parse("127.0.0.0/8") ]),
                                               Allowed: IPv6,
                                               Denied:  IPv4)).
                         SetArgDisplayNames("deny 127.0.0.0/8");

    }

    #endregion

    #region (private) helpers

    /// <summary>
    /// A server on both address families, with an SSH listener for NTS-KE over SSH.
    /// </summary>
    private static Task<NornServerFixture> StartAsync(NTPAccessList?   accessList,
                                                      NTPRateLimiter?  rateLimiter  = null)
    {

        // Without IPv6, a host offers loopback clients only one address family, and these
        // tests need two client addresses. That is a missing prerequisite, not a defect.
        if (!Socket.OSSupportsIPv6)
            Assert.Ignore("this host has no IPv6 support — skipping.");

        return NornServerFixture.StartAsync(listenIPAddress:  IPvXAddress.Any,
                                            accessList:       accessList,
                                            rateLimiter:      rateLimiter,
                                            sshClientKey:     ClientKey);

    }


    private static RawNtpPacket? AskTheTime(NornServerFixture  fixture,
                                            Client             client,
                                            TimeSpan?          timeout  = null)

        => RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(),
                                      client.Host,
                                      fixture.NTPPort,
                                      client.Family,
                                      timeout);


    private static String Describe(RawNtpPacket? packet)

        => packet is null
               ? "nothing"
               : packet.IsKissOfDeath
                     ? $"a {packet.KissCode} kiss"
                     : $"a mode {packet.Mode} packet of stratum {packet.Stratum}";


    /// <summary>
    /// A request for NTPv4 and AES-SIV-CMAC-256 over SSH, binding the keys to a secret the
    /// server sends along (method 0x0002), from which this suite can derive them by itself.
    /// </summary>
    private static Byte[] SshRequest()

        => RawNtsKeCodec.Encode([
               RawNtsKeRecord.NextProtocolNegotiation(RawNtsKeNextProtocols.Ntpv4),
               RawNtsKeRecord.AeadAlgorithmNegotiation(15),
               RawNtsKeRecord.SshKeyBinding(RawSshKeyBinding.RequestBody(RawSshKeyBinding.MethodTransportedSecret)),
               RawNtsKeRecord.EndOfMessage()
           ]);


    /// <summary>
    /// What the server's SSH listener says to a client that connects and says nothing. An SSH
    /// server speaks first, so that is its version string. A server that closes the connection
    /// instead, gracefully or with a reset, says nothing.
    /// </summary>
    private static async Task<String> FirstWordsOverSshAsync(NornServerFixture  fixture,
                                                             Client             client)
    {

        using var tcpClient  = new TcpClient(client.Family);
        using var timeout    = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await tcpClient.ConnectAsync(client.Host, fixture.SSHPort!.Value.ToUInt16(), timeout.Token);

        var buffer = new Byte[64];

        try
        {
            var read = await tcpClient.GetStream().ReadAsync(buffer, timeout.Token);
            return System.Text.Encoding.ASCII.GetString(buffer, 0, read);
        }
        catch (IOException)
        {
            return "";
        }

    }


    /// <summary>
    /// One NTS-KE exchange over SSH from the given client. A connection the server breaks off
    /// is a failed exchange, not an exception: some clients are expected to be turned away.
    /// </summary>
    private static async Task<RawNtsKeExchange> ExchangeOverSshAsync(NornServerFixture  fixture,
                                                                     Client             client)
    {

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        try
        {
            await using var sshClient = await fixture.ConnectSshAsync(ClientKey, client.Host, timeout.Token);
            return await RawNtsKeOverSsh.ExchangeAsync(sshClient, SshRequest(), TimeSpan.FromSeconds(5), timeout.Token);
        }
        catch (Exception e)
        {
            return new RawNtsKeExchange(false, null, SslProtocols.None, null, false,
                                        $"the SSH connection from {client} failed: {e.Message}");
        }

    }


    /// <summary>
    /// A counter of the server, read once it has caught up. A server sends first and counts
    /// afterwards, so a client can already hold the answer while the count is still one short.
    /// </summary>
    private static async Task<Int64> SettledAsync(Func<Int64> counter, Int64 expected)
    {

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);

        while (counter() != expected && DateTime.UtcNow < deadline)
            await Task.Delay(10);

        return counter();

    }

    #endregion


    #region Without a list

    /// <summary>
    /// Without a list, everyone is answered, from either address family.
    /// </summary>
    /// <remarks>
    /// § 5.1 tells operators to limit who may query. It cannot say whom to keep out, and only
    /// an operator can. A server that turned anybody away before being told to would only be
    /// guessing.
    /// </remarks>
    [Test]
    public async Task WithoutAList_EveryoneIsAnswered()
    {

        await using var fixture = await StartAsync(accessList: null);

        var answers = new[] { IPv4, IPv6 }.Select(client => (Client: client, Answer: AskTheTime(fixture, client))).
                                           ToArray();

        Assert.Multiple(() => {

            Assert.That(fixture.Server.AccessList.IsEveryone,
                        Is.True,
                        $"a server given no list should have the one that allows everyone, not '{fixture.Server.AccessList}'");

            foreach (var (client, answer) in answers)
            {

                Assert.That(answer?.Mode,
                            Is.EqualTo(RawNtpMode.Server),
                            $"{client} asked a server without a list and got {Describe(answer)}");

                Assert.That(answer?.IsKissOfDeath,
                            Is.False,
                            $"{client} asked a server without a list and got {Describe(answer)}");

            }

            Assert.That(fixture.Server.Metrics.NTPRequestsDenied,
                        Is.Zero,
                        fixture.Server.Metrics.ToString());

        });

    }

    #endregion

    #region NTP

    /// <summary>
    /// The denied address gets no NTP answer and no kiss either. The other address gets its
    /// answer from the same server.
    /// </summary>
    [TestCaseSource(nameof(Lists))]
    public async Task NTP_TheDeniedAddress_GetsNoAnswer(Case Case)
    {

        await using var fixture = await StartAsync(Case.List);

        var denied   = AskTheTime(fixture, Case.Denied, Silence);
        var allowed  = AskTheTime(fixture, Case.Allowed);

        Assert.Multiple(() => {

            Assert.That(denied,
                        Is.Null,
                        $"{Case.Denied} is denied by {Case} and got {Describe(denied)}");

            Assert.That(allowed?.Mode,
                        Is.EqualTo(RawNtpMode.Server),
                        $"{Case.Allowed} is allowed by {Case} and got {Describe(allowed)}");

            Assert.That(allowed?.IsKissOfDeath,
                        Is.False,
                        $"{Case.Allowed} is allowed by {Case} and got {Describe(allowed)}");

            Assert.That(fixture.Server.Metrics.NTPRequestsDenied,
                        Is.EqualTo(1),
                        $"the server should count the request it dropped: {fixture.Server.Metrics}");

        });

    }


    /// <summary>
    /// The list is asked before the rate limiter, so a denied address cannot draw a kiss no
    /// matter how much it sends. A kiss would tell it that a server is there. The allowed address
    /// sends the same and is kissed, which shows the limiter is there and would have answered.
    /// </summary>
    /// <remarks>
    /// A burst of one, so the second request of either client is one the limiter refuses,
    /// and the first refusal of an address draws a RATE kiss.
    /// </remarks>
    [TestCaseSource(nameof(Lists))]
    public async Task NTP_TheDeniedAddress_DrawsNoKiss_WhereTheOtherDoes(Case Case)
    {

        await using var fixture = await StartAsync(Case.List,
                                                   new NTPRateLimiter(MinimumInterval:  TimeSpan.FromSeconds(100),
                                                                      Burst:            1,
                                                                      KissInterval:     TimeSpan.FromMinutes(5)));

        var fromTheDenied   = Enumerable.Range(0, 2).Select(_ => AskTheTime(fixture, Case.Denied, Silence)).ToArray();
        var fromTheAllowed  = Enumerable.Range(0, 2).Select(_ => AskTheTime(fixture, Case.Allowed)).ToArray();

        var kisses          = await SettledAsync(() => fixture.Server.Metrics.NTPKissesOfDeathSent, 1);

        Assert.Multiple(() => {

            for (var i = 0; i < fromTheDenied.Length; i++)
                Assert.That(fromTheDenied[i],
                            Is.Null,
                            $"request {i + 1} from {Case.Denied}, which {Case} denies, got {Describe(fromTheDenied[i])}");

            Assert.That(fromTheAllowed[0]?.IsKissOfDeath,
                        Is.False,
                        $"the first request from {Case.Allowed} is inside the burst and got {Describe(fromTheAllowed[0])}");

            Assert.That(fromTheAllowed[1]?.KissCode,
                        Is.EqualTo("RATE"),
                        $"the second request from {Case.Allowed} is past the burst and got {Describe(fromTheAllowed[1])}");

            Assert.That(kisses,
                        Is.EqualTo(1),
                        $"one kiss, to the allowed address: {fixture.Server.Metrics}");

            Assert.That(fixture.Server.Metrics.NTPRequestsDenied,
                        Is.EqualTo(2),
                        $"both requests of the denied address are dropped by the list rather than by the limiter: {fixture.Server.Metrics}");

        });

    }

    #endregion

    #region NTS-KE over TLS

    /// <summary>
    /// The NTS-KE connection of the denied address is closed before the TLS handshake, so it
    /// never sees the server's certificate, which would name the server. The other address
    /// completes the key exchange with the same server.
    /// </summary>
    [TestCaseSource(nameof(Lists))]
    public async Task NTSKE_TheDeniedAddress_IsClosedBeforeTheHandshake(Case Case)
    {

        await using var fixture = await StartAsync(Case.List);

        var denied     = await RawNtsKeClient.ExchangeAsync(Case.Denied.Host,  fixture.NTSKEPort, RawNtsKeCodec.ClientRequest(), TimeSpan.FromSeconds(5));
        var allowed    = await RawNtsKeClient.ExchangeAsync(Case.Allowed.Host, fixture.NTSKEPort, RawNtsKeCodec.ClientRequest(), TimeSpan.FromSeconds(5));

        var responses  = await SettledAsync(() => fixture.Server.Metrics.NTSKEResponsesSent, 1);

        Assert.Multiple(() => {

            Assert.That(denied.HandshakeSucceeded,
                        Is.False,
                        $"{Case.Denied} is denied by {Case}: {denied}");

            Assert.That(allowed.ErrorCode,
                        Is.Null,
                        $"{Case.Allowed} is allowed by {Case}: {allowed}");

            Assert.That(allowed.FirstRecordOfType(RawNtsKeRecordTypes.NewCookieForNtpv4),
                        Is.Not.Null,
                        $"{Case.Allowed} is allowed by {Case}: {allowed}");

            Assert.That(responses,
                        Is.EqualTo(1),
                        $"one key exchange, the allowed one: {fixture.Server.Metrics}");

            Assert.That(fixture.Server.Metrics.NTSKEConnectionsDenied,
                        Is.EqualTo(1),
                        $"the server should count the connection it closed: {fixture.Server.Metrics}");

            Assert.That(fixture.Server.Metrics.NTSKEHandshakeFailures,
                        Is.Zero,
                        $"a connection closed before its handshake is not a failed handshake: {fixture.Server.Metrics}");

        });

    }

    #endregion

    #region NTS-KE over SSH

    /// <summary>
    /// The SSH connection of the denied address is closed before the version exchange, so it
    /// never sees the server's version string or its host key, which would name the server. The
    /// other address hears the version string and completes the key exchange with the same server.
    /// </summary>
    /// <remarks>
    /// An SSH server speaks first, so the version string reaches a client that has sent nothing
    /// yet. A server that decided only once the client had signed in would therefore show itself
    /// to every address, and its host key to every address that went on with the handshake.
    /// </remarks>
    [TestCaseSource(nameof(Lists))]
    public async Task SSH_TheDeniedAddress_IsClosedBeforeTheVersionExchange(Case Case)
    {

        await using var fixture = await StartAsync(Case.List);

        var deniedHears   = await FirstWordsOverSshAsync(fixture, Case.Denied);
        var allowedHears  = await FirstWordsOverSshAsync(fixture, Case.Allowed);

        var denied        = await ExchangeOverSshAsync(fixture, Case.Denied);
        var allowed       = await ExchangeOverSshAsync(fixture, Case.Allowed);

        var responses     = await SettledAsync(() => fixture.Server.Metrics.NTSKEResponsesSent, 1);

        Assert.Multiple(() => {

            Assert.That(deniedHears,
                        Is.Empty,
                        $"{Case.Denied} is denied by {Case}, and the server spoke to it");

            Assert.That(allowedHears,
                        Does.StartWith("SSH-2.0-"),
                        $"{Case.Allowed} is allowed by {Case}, and should hear the server's version string");

            Assert.That(denied.HandshakeSucceeded,
                        Is.False,
                        $"{Case.Denied} is denied by {Case}, and its NTS-KE subsystem opened: {denied}");

            Assert.That(denied.Records,
                        Is.Null,
                        $"{Case.Denied} is denied by {Case}: {denied}");

            Assert.That(allowed.ErrorCode,
                        Is.Null,
                        $"{Case.Allowed} is allowed by {Case}: {allowed}");

            Assert.That(allowed.FirstRecordOfType(RawNtsKeRecordTypes.NewCookieForNtpv4),
                        Is.Not.Null,
                        $"{Case.Allowed} is allowed by {Case}: {allowed}");

            Assert.That(responses,
                        Is.EqualTo(1),
                        $"one key exchange, the allowed one: {fixture.Server.Metrics}");

            Assert.That(fixture.Server.Metrics.NTSKEConnectionsDenied,
                        Is.EqualTo(2),
                        $"the server should count both connections it closed: {fixture.Server.Metrics}");

        });

    }

    #endregion

    #region Cookies

    /// <summary>
    /// Cookies are no way around the list. The key exchange runs from the address the list
    /// allows and its cookies are spent from the one it denies. That request is dropped
    /// although it would authenticate, as a cookie from the same exchange spent from the
    /// allowed address shows.
    /// </summary>
    /// <remarks>
    /// The key exchange runs over SSH with the secret the server sends along (method 0x0002).
    /// The keys are derived here with this suite's own HKDF, the requests are sealed with its own
    /// AES-SIV, and the answer is opened with it. Nothing on the client side of this test is
    /// Norn's.
    /// </remarks>
    [TestCaseSource(nameof(Lists))]
    public async Task NTS_CookiesFromTheAllowedAddress_DoNotLetTheDeniedOneIn(Case Case)
    {

        await using var fixture = await StartAsync(Case.List);

        var exchange    = await ExchangeOverSshAsync(fixture, Case.Allowed);

        var keyBinding  = exchange.FirstRecordOfType(RawNtsKeRecordTypes.SshKeyBinding);
        var cookies     = exchange.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).Select(record => record.Body).ToArray();

        Assert.That(keyBinding?.Body,
                    Has.Length.EqualTo(2 + RawSshKeyBinding.TransportedSecretLength),
                    $"the method and the secret the server selected: {exchange}");

        Assert.That((keyBinding!.Body[0] << 8) | keyBinding.Body[1],
                    Is.EqualTo(RawSshKeyBinding.MethodTransportedSecret),
                    $"the method the server selected: {exchange}");

        Assert.That(cookies,
                    Has.Length.GreaterThanOrEqualTo(2),
                    $"a cookie for each address: {exchange}");

        var secret          = keyBinding.Body[2..];
        var c2sKey          = RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.C2S, 32);
        var s2cKey          = RawSshKeyBinding.TransportedSecretKey(secret, 15, RawSshKeyBinding.S2C, 32);

        var fromTheDenied   = RawNtpExchange.TryExchange(RawNtsExtensionFields.BuildNtsRequest(c2sKey, cookies[0]),
                                                         Case.Denied.Host,
                                                         fixture.NTPPort,
                                                         Case.Denied.Family,
                                                         Silence);

        var fromTheAllowed  = RawNtpExchange.TryExchange(RawNtsExtensionFields.BuildNtsRequest(c2sKey, cookies[1]),
                                                         Case.Allowed.Host,
                                                         fixture.NTPPort,
                                                         Case.Allowed.Family);

        String? verification = null;

        var authenticated   = fromTheAllowed is not null &&
                              RawNtsExtensionFields.TryVerifyAuthenticator(fromTheAllowed, s2cKey, out _, out verification);

        var answers         = await SettledAsync(() => fixture.Server.Metrics.NTPResponsesSent, 1);

        Assert.Multiple(() => {

            Assert.That(fromTheDenied,
                        Is.Null,
                        $"{Case.Denied} is denied by {Case}, spent a cookie {Case.Allowed} was given and got {Describe(fromTheDenied)}");

            Assert.That(authenticated,
                        Is.True,
                        $"{Case.Allowed} is allowed by {Case}, spent its own cookie and got {Describe(fromTheAllowed)}" +
                        (verification is null ? "" : $": {verification}"));

            Assert.That(answers,
                        Is.EqualTo(1),
                        $"one answer, to the allowed address: {fixture.Server.Metrics}");

            Assert.That(fixture.Server.Metrics.NTPRequestsDenied,
                        Is.EqualTo(1),
                        $"the request with the cookie is dropped by the list: {fixture.Server.Metrics}");

        });

    }

    #endregion

}
