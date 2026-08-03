using NUnit.Framework;

using NTSConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSInterop.PublicServers.Tests;

/// <summary>
/// Norn's NTS client against public NTS servers run by other people, on other stacks.
///
/// Where the chrony tests prove interoperability against a known implementation in a
/// controlled setting, these prove it against deployments as they actually exist —
/// real certificate chains from public CAs, real NTPv4 Server/Port Negotiation, real
/// stratum-1 hardware, and whatever cookie format each operator happens to use.
///
/// Gated on <c>Online</c> because they need outbound TCP/4460 and UDP/123, which many
/// networks block, and because a public server being down is not a Norn defect.
/// </summary>
[TestFixture]
[Category(TestCategories.Online)]
[Category(TestCategories.Slow)]
public class PublicNtsServerTests
{

    /// <summary>
    /// Well-known NTS deployments, each on a different implementation:
    /// Cloudflare runs its own Go stack, PTB and Netnod run NTPsec/chrony variants.
    /// </summary>
    private static readonly String[] Servers = [
        "time.cloudflare.com",
        "ptbtime1.ptb.de",
        "nts.netnod.se",
        "ntppool1.time.nl"
    ];


    private static NTSClient CreateClient(String hostname)

        => new (DomainName.Parse(hostname),
                IPVersionPreference:  IPVersionPreference.IPv4Only,
                Timeout:              TimeSpan.FromSeconds(15),
                DNSClient:            new DNSClient(SearchForIPv6DNSServers: false));


    /// <summary>
    /// NTS-KE against a public server, with full certificate validation left switched on —
    /// no <c>RemoteCertificateValidator</c> override, so the real chain, hostname and
    /// revocation checks all have to pass.
    /// </summary>
    [Test]
    [TestCaseSource(nameof(Servers))]
    public async Task NtsKe_AgainstPublicServer(String hostname)
    {

        TestEnvironment.RequireNetwork();
        TestEnvironment.RequireNtsKeReachability();

        var result = await CreateClient(hostname).GetNTSKERecords();

        if (!result.Success && result.ErrorCategory is NTSKEErrorCategory.DNS
                                                    or NTSKEErrorCategory.TCPConnect
                                                    or NTSKEErrorCategory.Timeout)
        {
            Assert.Ignore($"{hostname} was unreachable ({result.ErrorCategory}): {result.ErrorMessage}");
        }

        Assert.That(result.Success, Is.True,
                    $"NTS-KE against {hostname} failed: {result.ErrorMessage} ({result.ErrorCategory})");

        var response = result.Response!;

        Assert.Multiple(() => {

            // Against the negotiated algorithm rather than a constant. This used to assert 32
            // octets outright, which was true only as long as this client offered nothing but
            // AES-SIV-CMAC-256 — it now prefers AES-128-GCM-SIV, and Cloudflare and time.nl take
            // it, so two of these servers hand back sixteen.
            Assert.That(response.C2SKey.Length,
                        Is.EqualTo(NTSAEAD.KeyLength(response.AEADAlgorithm)),
                        $"{hostname} agreed on {response.AEADAlgorithm.AsText()}, whose key is " +
                        $"{NTSAEAD.KeyLength(response.AEADAlgorithm)} octets");

            Assert.That(response.S2CKey.Length,
                        Is.EqualTo(NTSAEAD.KeyLength(response.AEADAlgorithm)));

            // Not required by anything, and worth recording: which of the two AES-128-GCM-SIV
            // exporter contexts a public server speaks. Echoing IANA record 1024 means RFC 8915
            // § 5.1's; silence means chrony's, with algorithm id 15 in the context. Norn follows
            // whichever it is told, so this assertion cannot fail — it is here to print the
            // answer in the run log, where a future change of heart by an operator would show up.
            if (response.AEADAlgorithm == AEADAlgorithms.AES_128_GCM_SIV)
                TestContext.Out.WriteLine(
                    $"{hostname}: AES-128-GCM-SIV on the " +
                    $"{(response.CompliantAES128GCMSIVExporterContext ? "§ 5.1" : "chrony")} exporter context");

            Assert.That(response.C2SKey, Is.Not.EqualTo(response.S2CKey).AsCollection,
                        "RFC 8915 §5.1 derives the two directions with different exporter contexts");

            Assert.That(response.Cookies.Count(), Is.GreaterThan(0), "at least one cookie");

            Assert.That(response.TLSInfo?.NegotiatedTLSVersion, Is.EqualTo("TLS 1.3"),
                        "RFC 8915 §4 requires TLS 1.3 or later");

        });

    }


    /// <summary>
    /// The full exchange against a public server: an authenticated time reading, with the
    /// Unique Identifier echoed and a fresh cookie returned.
    /// </summary>
    [Test]
    [TestCaseSource(nameof(Servers))]
    public async Task AuthenticatedQuery_AgainstPublicServer(String hostname)
    {

        TestEnvironment.RequireNetwork();
        TestEnvironment.RequireNtsKeReachability();

        var client      = CreateClient(hostname);

        var ntsKeResult = await client.GetNTSKERecords();

        if (!ntsKeResult.Success)
            Assert.Ignore($"NTS-KE against {hostname} did not complete ({ntsKeResult.ErrorCategory}): {ntsKeResult.ErrorMessage}");

        var result      = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(15));

        if (!result.Success && result.ErrorCategory is NTSQueryErrorCategory.NTPTimeout)
            Assert.Ignore($"{hostname} did not answer the NTP query in time — UDP/123 may be blocked.");

        Assert.That(result.Success, Is.True,
                    $"the NTS query to {hostname} failed: {result.ErrorMessage} ({result.ErrorCategory})");

        var response = result.Response!;

        Assert.Multiple(() => {

            Assert.That(response.Mode,    Is.EqualTo(4),          "a server reply is mode 4");
            Assert.That(response.VN,      Is.EqualTo(4),          "NTPv4");
            Assert.That(response.Stratum, Is.InRange((Byte) 1, (Byte) 15), "a usable stratum");

            Assert.That(response.UniqueIdentifier(), Is.Not.Null,
                        "RFC 8915 §5.7: the server echoes the Unique Identifier");

            Assert.That(response.Extensions.Any(extension => extension is AuthenticatorAndEncryptedExtension),
                        Is.True, "the response must be authenticated");

            Assert.That(response.Extensions.OfType<NTSCookieExtension>().Any(),
                        Is.True, "RFC 8915 §5.7: at least one fresh cookie");

            // Sanity: a public NTS server should agree with the local clock to within a
            // generous margin. A wild disagreement means the timestamps were misparsed.
            Assert.That(response.ClockOffset?.Duration() ?? TimeSpan.Zero,
                        Is.LessThan(TimeSpan.FromMinutes(5)),
                        $"the offset from {hostname} looks implausible: {response.ClockOffset}");

        });

    }


    /// <summary>
    /// A cookie spent once must not be reusable. Public servers enforce this, so a
    /// sequence of queries only keeps working if the client is correctly consuming a fresh
    /// cookie each time and banking the replacements.
    /// </summary>
    [Test]
    public async Task RepeatedQueries_ConsumeFreshCookies()
    {

        TestEnvironment.RequireNetwork();
        TestEnvironment.RequireNtsKeReachability();

        var client      = CreateClient("time.cloudflare.com");

        var ntsKeResult = await client.GetNTSKERecords();

        if (!ntsKeResult.Success)
            Assert.Ignore($"NTS-KE did not complete ({ntsKeResult.ErrorCategory}): {ntsKeResult.ErrorMessage}");

        var usedCookies = new List<String>();

        for (var i = 1; i <= 3; i++)
        {

            var result = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(15));

            if (!result.Success && result.ErrorCategory is NTSQueryErrorCategory.NTPTimeout)
                Assert.Ignore("UDP/123 appears to be blocked.");

            Assert.That(result.Success, Is.True, $"query {i} failed: {result.ErrorMessage}");

            usedCookies.Add(Convert.ToBase64String(result.UsedCookie ?? []));

        }

        Assert.That(usedCookies, Is.Unique, "each query must spend a different cookie");

    }

}
