using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.Client.Tests;

/// <summary>
/// Norn's client against Norn's server, both with NTPv5, end to end: a key exchange over TLS or
/// over SSH that agrees to NTPv5, and then NTPv5 under its keys - and, where either side has no
/// NTPv5, NTPv4 under them instead.
///
/// <para>
/// Each side is tested against this suite's own codec elsewhere: the server in NTPv5NtsTests,
/// the client in NTPv5ClientNtsKeTests and the NTPv5Client tests. What only the two together
/// show is that they agree with each other on everything those tests leave to one side alone -
/// which next protocol, which keys, which cookies - on both transports.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NTPv5ClientAgainstNornTests
{

    #region Data

    private static readonly ISshHostKey ClientKey = SshHostKey.GenerateEd25519();

    private NornServerFixture? fixture;

    private NornServerFixture Server
        => fixture ?? throw new InvalidOperationException("the server fixture did not start");

    #endregion


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync(ntpv5:         NTPv5Support.Draft,
                                                        sshClientKey:  ClientKey);


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    #region (private) KeyExchange(Server, Client, Transport, OfferSshExporter = true)

    /// <summary>
    /// One key exchange of the client with the server, over the given transport.
    /// </summary>
    private static async Task<NTSKEResult> KeyExchange(NornServerFixture  Server,
                                                       NTSClient          Client,
                                                       NtsKeTransport     Transport,
                                                       Boolean            OfferSshExporter = true)
    {

        if (Transport == NtsKeTransport.Tls)
            return await Client.GetNTSKERecords();

        await using var ssh = await Server.ConnectSshAsync(ClientKey);

        return await Client.GetNTSKERecordsOverSSH(ssh, OfferSSHExporter: OfferSshExporter);

    }

    #endregion


    /// <summary>
    /// Both with NTPv5: NTPv5 is agreed, and two NTPv5 queries under its keys are answered and
    /// authenticated - the second with a cookie the first one brought. Over SSH with either
    /// method of the SSH Key Binding record: the SSH Exporter where the client offers it, which
    /// it offers first, and the Transported Secret where it does not.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, true,  TestName = "BothWithNTPv5_QueryNTPv5UnderTheKeysOfTheExchange_OverTls")]
    [TestCase(NtsKeTransport.Ssh, true,  TestName = "BothWithNTPv5_QueryNTPv5UnderTheKeysOfTheExchange_OverSsh_SshExporter")]
    [TestCase(NtsKeTransport.Ssh, false, TestName = "BothWithNTPv5_QueryNTPv5UnderTheKeysOfTheExchange_OverSsh_TransportedSecret")]
    public async Task BothWithNTPv5_QueryNTPv5UnderTheKeysOfTheExchange(NtsKeTransport Transport, Boolean OfferSshExporter)
    {

        await using var client = Server.CreateClient(TimeSpan.FromSeconds(10), ntpv5: NTPv5Support.Draft);

        using var exchange = await KeyExchange(Server, client, Transport, OfferSshExporter);

        Assert.That(exchange.Success, Is.True, exchange.ErrorMessage);
        Assert.That(exchange.Response!.NextProtocol, Is.EqualTo(NTPv5Draft.NTSNextProtocolId), "the protocol agreed");

        var first   = await client.QueryNTPv5(NTSKEResponse: exchange.Response, Timeout: TimeSpan.FromSeconds(5));
        var second  = await client.QueryNTPv5(NTSKEResponse: exchange.Response, Timeout: TimeSpan.FromSeconds(5));

        Assert.Multiple(() => {
            Assert.That(first.Success,            Is.True,  $"the first query: {first.ErrorMessage}");
            Assert.That(first.IsAuthenticated,    Is.True,  "the first query was not authenticated");
            Assert.That(first.NewCookies,         Is.GreaterThanOrEqualTo(1), "the first response brought no cookie");
            Assert.That(second.Success,           Is.True,  $"the second query: {second.ErrorMessage}");
            Assert.That(second.IsAuthenticated,   Is.True,  "the second query was not authenticated");
        });

    }


    /// <summary>
    /// A client without NTPv5 offers NTPv4 alone, and a server with NTPv5 agrees to NTPv4: its
    /// NTPv4 query is answered and authenticated, and an NTPv5 query under that key exchange is
    /// refused by the client before it sends one - its cookies are NTPv4's.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, TestName = "AClientWithoutNTPv5_GetsNTPv4_OverTls")]
    [TestCase(NtsKeTransport.Ssh, TestName = "AClientWithoutNTPv5_GetsNTPv4_OverSsh")]
    public async Task AClientWithoutNTPv5_GetsNTPv4(NtsKeTransport Transport)
    {

        await using var client = Server.CreateClient(TimeSpan.FromSeconds(10));

        using var exchange = await KeyExchange(Server, client, Transport);

        await AssertNTPv4(client, exchange);

    }


    /// <summary>
    /// And the other way round: a client with NTPv5, which offers NTPv4 after it, and a server
    /// without NTPv5, which agrees to NTPv4 - the fallback § 11 has the client offer NTPv4 for.
    /// </summary>
    [TestCase(NtsKeTransport.Tls, TestName = "AServerWithoutNTPv5_GivesAClientWithItNTPv4_OverTls")]
    [TestCase(NtsKeTransport.Ssh, TestName = "AServerWithoutNTPv5_GivesAClientWithItNTPv4_OverSsh")]
    public async Task AServerWithoutNTPv5_GivesAClientWithItNTPv4(NtsKeTransport Transport)
    {

        await using var withoutNTPv5 = await NornServerFixture.StartAsync(sshClientKey: ClientKey);
        await using var client       = withoutNTPv5.CreateClient(TimeSpan.FromSeconds(10), ntpv5: NTPv5Support.Draft);

        using var exchange = await KeyExchange(withoutNTPv5, client, Transport);

        await AssertNTPv4(client, exchange);

    }


    /// <summary>
    /// NTPv4 agreed, an NTPv4 query under it authenticated, and an NTPv5 one refused by the
    /// client as one of a key exchange that did not agree to NTPv5.
    /// </summary>
    private static async Task AssertNTPv4(NTSClient Client, NTSKEResult Exchange)
    {

        Assert.That(Exchange.Success, Is.True, Exchange.ErrorMessage);
        Assert.That(Exchange.Response!.NextProtocol, Is.EqualTo((UInt16) 0), "the protocol agreed");

        var v4 = await Client.QueryTime(NTSKEResponse: Exchange.Response, Timeout: TimeSpan.FromSeconds(5));
        var v5 = await Client.QueryNTPv5(NTSKEResponse: Exchange.Response, Timeout: TimeSpan.FromSeconds(5));

        Assert.Multiple(() => {
            Assert.That(v4.Success,                  Is.True,  $"the NTPv4 query: {v4.ErrorMessage}");
            Assert.That(v4.ResponseIsAuthenticated,  Is.True,  "the NTPv4 query was not authenticated");
            Assert.That(v5.Success,                  Is.False, "an NTPv5 query under a key exchange of NTPv4 was answered");
            Assert.That(v5.ErrorCategory,            Is.EqualTo(NTSQueryErrorCategory.NTSKE), v5.ErrorMessage);
            Assert.That(v5.Request,                  Is.Null,  "an NTPv5 request was sent under a key exchange of NTPv4");
        });

    }

}
