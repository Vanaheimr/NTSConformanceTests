using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

namespace NTSInterop.LinuxTools.Tests;

#region Norn's client against ntp5-exp

/// <summary>
/// Norn's NTPv5 client against ntp5-exp, the draft author's experimental NTPv5+NTPv4 server
/// (draft-ietf-ntp-ntpv5-10 § 14), built from source by interop/setup-ntpv5-peers.sh.
///
/// The first implementation of the draft that is not Norn's own on the other end, and so the
/// first that can say whether Norn and the draft's author read -10 the same way.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class NornClientAgainstNtp5ExpTests
{

    private Ntp5ExpServerFixture? ntp5exp;

    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireNtp5Exp();

        ntp5exp = await Ntp5ExpServerFixture.StartAsync();

        if (ntp5exp is null)
            Assert.Ignore("ntp5-exp did not start in WSL");

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (ntp5exp is not null)
            await ntp5exp.DisposeAsync();
    }

    private NTSClient Client(NTPv5InterleavedAssociation? Interleaved = null)

        => new (DomainName.Parse(ntp5exp!.VmAddress),
                NTP_Port:             ntp5exp.Port,
                IPVersionPreference:  IPVersionPreference.IPv4Only,
                Timeout:              TimeSpan.FromSeconds(5)) {
               NTPv5             = NTPv5Support.Draft,
               NTPv5Interleaved  = Interleaved
           };


    /// <summary>
    /// § 9: a basic request is answered in NTPv5 - valid (§ 9.4), usable (§ 9.5), as long as
    /// the request (§ 10), with a Server Information naming NTPv5 (§ 7.6), and an offset to a
    /// server on the same machine of next to nothing.
    /// </summary>
    [Test]
    public async Task TheBasicMode_IsAnswered_AndUsable()
    {

        using var client = Client();

        var result = await client.QueryNTPv5(ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);

        Assert.That(result.Success, Is.True, $"{result.ErrorMessage}\n{ntp5exp!.Log()}");

        Assert.Multiple(() => {
            Assert.That(result.IsUsable,                                         Is.True, result.Unusable.ToString());
            Assert.That(result.Response!.Stratum,                                Is.EqualTo(1), "ntp5-exp with a local reference");
            Assert.That(result.Response.Length,                                  Is.EqualTo(result.Request!.Datagram.Length), "§ 10");
            Assert.That(result.ServerInformation?.SupportedVersions & (1 << 4),  Is.Not.Zero, "NTPv5 among the versions");
            Assert.That(Math.Abs(result.Measurement!.Offset.TotalSeconds),       Is.LessThan(1.0));
        });

    }


    /// <summary>
    /// § 8: the second response of an interleaved association completes the first exchange
    /// with the transmit timestamp ntp5-exp took after sending it.
    /// </summary>
    [Test]
    public async Task TheInterleavedMode_CompletesThePreviousExchange()
    {

        using var client = Client(new NTPv5InterleavedAssociation());

        var first  = await client.QueryNTPv5();
        var second = await client.QueryNTPv5();

        Assert.That(first.Success,  Is.True, first.ErrorMessage);
        Assert.That(second.Success, Is.True, second.ErrorMessage);

        Assert.Multiple(() => {
            Assert.That(first. Measurement!.Interleaved, Is.False);
            Assert.That(second.Response!.Flags,          Is.EqualTo(NTPv5Flags.InterleavedMode));
            Assert.That(second.Measurement!.Interleaved, Is.True);
            Assert.That(second.Measurement.T1,           Is.EqualTo(first.Measurement.T1));
        });

    }


    /// <summary>
    /// § 12: ntp5-exp echoes the magic of an NTPv4 request, and the next query is NTPv5.
    /// </summary>
    [Test]
    public async Task TheNegotiation_SwitchesToNTPv5()
    {

        using var client   = Client();
        var negotiation    = new NTPv5VersionNegotiation();

        var first          = await client.QueryNegotiated(negotiation);
        var second         = await client.QueryNegotiated(negotiation);

        Assert.That(first.NTPv4?.ServerAdvertisesNTPv5, Is.True,  first.NTPv4?.ErrorMessage);
        Assert.That(second.NTPv5?.Success,              Is.True,  second.NTPv5?.ErrorMessage);
        Assert.That(second.NextVersion,                 Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));

    }


    /// <summary>
    /// § 7.4: reference IDs in fragments of eight - ntp5-exp's own first, at the full share,
    /// and the rest of its list unused.
    /// </summary>
    [Test]
    public async Task TheReferenceIds_ComeInFragments()
    {

        using var client = Client();

        var first  = await client.QueryNTPv5(ExtensionFields: [ NTPv5ReferenceIds.Request(0, 8) ]);
        var second = await client.QueryNTPv5(ExtensionFields: [ NTPv5ReferenceIds.Request(8, 8) ]);

        var head   = first. Response is { } a ? NTPv5Client.ReferenceIdsOf(a) : null;
        var tail   = second.Response is { } b ? NTPv5Client.ReferenceIdsOf(b) : null;

        Assert.Multiple(() => {
            Assert.That(head,                   Has.Count.EqualTo(8), first.ErrorMessage);
            Assert.That(head![0].Share,         Is.EqualTo(NTPv5ReferenceIds.FullShare));
            Assert.That(head[0].ReferenceId,    Is.Not.Zero);
            Assert.That(tail,                   Has.Count.EqualTo(8), second.ErrorMessage);
            Assert.That(tail!.All(entry => entry.IsUnused), Is.True, "a server with a local reference lists itself alone");
        });

    }

}

#endregion

#region Norn's client against chrony-ntp5

/// <summary>
/// Norn's NTPv5 client against chrony-ntp5, the NTPv5 branch of chrony by the draft's author,
/// built from source by interop/setup-ntpv5-peers.sh - plain, interleaved, and under NTS for
/// NTPv5 (§ 11), with chrony's own NTS-KE server and its GnuTLS.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class NornClientAgainstChronyNtp5Tests
{

    private ChronyNtsServerFixture? chrony;

    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireChronyNtp5();

        chrony = await ChronyNtsServerFixture.StartAsync(chronyd:           TestEnvironment.ChronyNtp5Daemon,
                                                         chronyc:           TestEnvironment.ChronyNtp5Control,
                                                         workingDirectory:  "/tmp/ntpv5-interop-chrony");

        if (chrony is null)
            Assert.Ignore("chrony-ntp5 did not start in WSL");

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (chrony is not null)
            await chrony.DisposeAsync();
    }

    private NTSClient Client(NTPv5InterleavedAssociation? Interleaved = null)

        => new (DomainName.Parse(chrony!.VmAddress),
                NTSKE_Port:                  chrony.NTSKEPort,
                NTP_Port:                    chrony.NTPPort,
                IPVersionPreference:         IPVersionPreference.IPv4Only,
                Timeout:                     TimeSpan.FromSeconds(15),
                RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors) => TLSValidationResult.Success()) {
               NTPv5             = NTPv5Support.Draft,
               NTPv5Interleaved  = Interleaved
           };


    /// <summary>
    /// § 9: a basic request is answered in NTPv5, valid and usable, at the stratum chronyd was
    /// given, with a Server Information naming NTPv5 and a Monotonic Receive Timestamp (§ 7.9).
    /// </summary>
    [Test]
    public async Task TheBasicMode_IsAnswered_AndUsable()
    {

        using var client = Client();

        var result = await client.QueryNTPv5(ExtensionFields: [ NTPv5ExtensionField.ServerInformation(),
                                                                NTPv5ExtensionField.MonotonicReceiveTimestamp() ]);

        Assert.That(result.Success, Is.True, $"{result.ErrorMessage}\n{chrony!.ServerStats()}");

        Assert.Multiple(() => {
            Assert.That(result.IsUsable,                                         Is.True, result.Unusable.ToString());
            Assert.That(result.Response!.Stratum,                                Is.EqualTo(10), "'local stratum 10'");
            Assert.That(result.Response.Length,                                  Is.EqualTo(result.Request!.Datagram.Length), "§ 10");
            Assert.That(result.ServerInformation?.SupportedVersions & (1 << 4),  Is.Not.Zero);
            Assert.That(result.Response.Find(NTPv5ExtensionTypes.MonotonicReceiveTimestamp), Is.Not.Null, "chrony-ntp5 answers § 7.9");
            Assert.That(Math.Abs(result.Measurement!.Offset.TotalSeconds),       Is.LessThan(1.0));
        });

    }


    /// <summary>
    /// § 8 against chronyd's interleaved mode.
    /// </summary>
    [Test]
    public async Task TheInterleavedMode_CompletesThePreviousExchange()
    {

        using var client = Client(new NTPv5InterleavedAssociation());

        var first  = await client.QueryNTPv5();
        var second = await client.QueryNTPv5();

        Assert.That(first.Success,  Is.True, first.ErrorMessage);
        Assert.That(second.Success, Is.True, second.ErrorMessage);
        Assert.That(second.Measurement!.Interleaved, Is.True);
        Assert.That(second.Measurement.T1,           Is.EqualTo(first.Measurement!.T1));

    }


    /// <summary>
    /// § 12 against chronyd.
    /// </summary>
    [Test]
    public async Task TheNegotiation_SwitchesToNTPv5()
    {

        using var client   = Client();
        var negotiation    = new NTPv5VersionNegotiation();

        var first          = await client.QueryNegotiated(negotiation);
        var second         = await client.QueryNegotiated(negotiation);

        Assert.That(first.NTPv4?.ServerAdvertisesNTPv5, Is.True, first.NTPv4?.ErrorMessage);
        Assert.That(second.NTPv5?.Success,              Is.True, second.NTPv5?.ErrorMessage);

    }


    /// <summary>
    /// § 11: offered first, NTS for NTPv5 is agreed by chrony-ntp5's NTS-KE server, and the
    /// NTPv5 queries under it authenticate both ways and keep the cookies coming.
    /// </summary>
    [Test]
    public async Task NTSForNTPv5_IsAgreed_AndAuthenticates()
    {

        using var client = Client();

        var ke = await client.GetNTSKERecords();

        Assert.That(ke.Success, Is.True, ke.ErrorMessage);
        Assert.That(ke.Response!.NextProtocol, Is.EqualTo(NTPv5Draft.NTSNextProtocolId), "§ 11: NTPv5 agreed");

        client.SeedCookies(ke.Response);

        for (var i = 0; i < 3; i++)
        {

            var result = await client.QueryNTPv5(NTSKEResponse: ke.Response);

            Assert.That(result.Success,          Is.True, $"query {i + 1}: {result.ErrorMessage}\n{chrony!.ServerStats()}");
            Assert.That(result.IsAuthenticated,  Is.True);
            Assert.That(result.IsUsable,         Is.True, result.Unusable.ToString());
            Assert.That(result.NewCookies,       Is.GreaterThanOrEqualTo(1));

        }

    }

}

#endregion

#region chrony-ntp5 and ntp5-exp against Norn's server

/// <summary>
/// The two NTPv5 peers as clients of Norn's server, which they reach on the Windows host -
/// and what they say of it themselves: chronyc's ntpdata for chrony-ntp5, the log of
/// ntpnode.py for ntp5-exp. The version they report is the one they spoke, so a peer that
/// quietly negotiated down to NTPv4 is caught.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class NTPv5PeersAgainstNornTests
{

    private NornServerFixture?  norn;
    private String?             host;
    private String?             certificatePath;

    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireWsl();

        // The peers run inside WSL and reach Norn on the Windows host, NTS-KE over TCP too.
        TestEnvironment.RequireWslInboundUdp();
        TestEnvironment.RequireWslInboundTcp();

        host = Wsl.WindowsHostAddress
                   ?? throw new InvalidOperationException("no Windows host address");

        // GnuTLS checks the certificate against the address chronyd was told to connect to.
        var certificate = TestCertificate.Generate(subjectCommonName:  "Norn NTPv5 interop",
                                                   ipAddresses:        [ host ]);

        certificatePath = Wsl.ToWslPath(certificate.WritePem(Path.Combine(Path.GetTempPath(), "norn-ntpv5-interop")));

        norn = await NornServerFixture.StartAsync(certificate:       certificate,
                                                  externalHostName:  host,
                                                  ntpv5:             NTPv5Support.Draft);

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (norn is not null)
            await norn.DisposeAsync();
    }

    private String ChronyServer(String Options)
        => $"server {host} port {norn!.NTPPort} iburst minpoll -1 maxpoll -1 {Options}";


    #region chrony-ntp5

    /// <summary>
    /// chrony-ntp5 told to speak NTPv5 does, takes Norn's responses as valid, and measures an
    /// offset of next to nothing.
    /// </summary>
    [Test]
    public void ChronyNtp5_SpeaksNTPv5_ToNorn()
    {

        TestEnvironment.RequireChronyNtp5();

        var report = NTPv5Peers.QueryWithChronyNtp5(ChronyServer("version 5"));

        Assert.Multiple(() => {
            Assert.That(report.Version,             Is.EqualTo(5), report.Output);
            Assert.That(report.ValidResponses,      Is.GreaterThanOrEqualTo(3), $"{report.Output}\n{norn!.Server.Metrics}");
            Assert.That(Math.Abs(report.OffsetSeconds ?? 99), Is.LessThan(1.0), report.Output);
        });

    }


    /// <summary>
    /// § 12: chrony-ntp5 left to negotiate starts in NTPv4 with the magic, and Norn's echo
    /// moves it to NTPv5.
    /// </summary>
    [Test]
    public void ChronyNtp5_NegotiatesNTPv5_WithNorn()
    {

        TestEnvironment.RequireChronyNtp5();

        var report = NTPv5Peers.QueryWithChronyNtp5(ChronyServer(""));

        Assert.That(report.Version,        Is.EqualTo(5), report.Output);
        Assert.That(report.ValidResponses, Is.GreaterThanOrEqualTo(3), report.Output);

    }


    /// <summary>
    /// § 8: chrony-ntp5 in the interleaved mode gets interleaved responses from Norn.
    /// </summary>
    [Test]
    public void ChronyNtp5_GetsInterleavedResponses_FromNorn()
    {

        TestEnvironment.RequireChronyNtp5();

        var report = NTPv5Peers.QueryWithChronyNtp5(ChronyServer("version 5 xleave"));

        Assert.That(report.Version,     Is.EqualTo(5), report.Output);
        Assert.That(report.Interleaved, Is.True,       report.Output);

    }


    /// <summary>
    /// § 11: chrony-ntp5 as an NTS client completes NTS-KE with Norn - GnuTLS validating Norn's
    /// certificate - and authenticates Norn's responses: in NTPv4.
    ///
    /// Because chrony-ntp5 offers NTPv5 (0x8001) without the Draft Identification record 0x4001
    /// that § 11 has a draft client provide ("MUST"), and a draft server "MUST not accept NTPv5
    /// as an option unless they support the specific draft version identified". None is, so
    /// Norn agrees to NTPv4 alone, which chrony-ntp5 offered too. Should chrony-ntp5 start
    /// sending the record, this test says so by failing.
    /// </summary>
    [Test]
    public void ChronyNtp5_AuthenticatesNorn_UnderNTS_InNTPv4_ForWantOfTheDraftRecord()
    {

        TestEnvironment.RequireChronyNtp5();

        var before = norn!.Server.Metrics;

        var report = NTPv5Peers.QueryWithChronyNtp5(ChronyServer($"nts ntsport {norn.NTSKEPort} certset 1"),
                                                    TimeSpan.FromSeconds(10),
                                                    [ $"ntstrustedcerts 1 {certificatePath}" ]);

        Assert.Multiple(() => {
            Assert.That(report.Authenticated,                                      Is.True,       $"{report.Output}\n{norn.Server.Metrics}");
            Assert.That(report.Version,                                            Is.EqualTo(4), report.Output);
            Assert.That(report.ValidResponses,                                     Is.GreaterThanOrEqualTo(3), report.Output);
            Assert.That(norn.Server.Metrics.NTSKEResponsesSent - before.NTSKEResponsesSent, Is.GreaterThanOrEqualTo(1));
        });

    }

    #endregion

    #region ntp5-exp

    /// <summary>
    /// ntp5-exp told to speak NTPv5 does, finds nothing bogus and nothing it cannot parse in
    /// Norn's responses, measures, and selects Norn - which takes the whole list of reference
    /// IDs, fetched in fragments, without its own in it.
    /// </summary>
    [Test]
    public void Ntp5Exp_SpeaksNTPv5_ToNorn_AndSelectsIt()
    {

        TestEnvironment.RequireNtp5Exp();

        var report = NTPv5Peers.QueryWithNtp5Exp($"{host}:{norn!.NTPPort}", Version: 5, Duration: TimeSpan.FromSeconds(9));

        Assert.Multiple(() => {
            Assert.That(report.NTPv5Responses,  Is.GreaterThanOrEqualTo(4), $"{report}\n{norn.Server.Metrics}");
            Assert.That(report.BogusResponses,  Is.Zero,  report.Log);
            Assert.That(report.Errors,          Is.Empty, report.Log);
            Assert.That(report.Measurements,    Is.Not.Empty, report.Log);
            Assert.That(report.Measurements.All(measurement => Math.Abs(measurement.Offset) < 1.0), Is.True, report.Log);
            Assert.That(report.Selected,        Is.True, report.Log);
        });

    }


    /// <summary>
    /// § 8: ntp5-exp in the interleaved mode measures in it against Norn.
    /// </summary>
    [Test]
    public void Ntp5Exp_MeasuresInTheInterleavedMode_AgainstNorn()
    {

        TestEnvironment.RequireNtp5Exp();

        var report = NTPv5Peers.QueryWithNtp5Exp($"{host}:{norn!.NTPPort}", Version: 5, Interleaved: true, Duration: TimeSpan.FromSeconds(6));

        Assert.That(report.Measurements.Select(measurement => measurement.Mode), Does.Contain("Interleaved"), report.Log);
        Assert.That(report.BogusResponses, Is.Zero,  report.Log);
        Assert.That(report.Errors,         Is.Empty, report.Log);

    }


    /// <summary>
    /// § 12: ntp5-exp left to negotiate starts in NTPv4, and Norn's echo moves it to NTPv5.
    /// </summary>
    [Test]
    public void Ntp5Exp_NegotiatesNTPv5_WithNorn()
    {

        TestEnvironment.RequireNtp5Exp();

        var report = NTPv5Peers.QueryWithNtp5Exp($"{host}:{norn!.NTPPort}", Version: null, Duration: TimeSpan.FromSeconds(6));

        Assert.That(report.NTPv4Responses, Is.GreaterThanOrEqualTo(1), report.Log);
        Assert.That(report.NTPv5Responses, Is.GreaterThanOrEqualTo(1), report.Log);
        Assert.That(report.Errors,         Is.Empty, report.Log);

    }

    #endregion

}

#endregion
