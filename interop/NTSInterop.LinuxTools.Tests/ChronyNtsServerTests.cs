using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// Norn's NTS client against <c>chronyd</c> — the reference NTS implementation, and the one
/// most public NTS servers actually run.
///
/// This is the interop direction that matters most: Norn talking to Norn proves the two
/// halves agree with each other, not that either agrees with RFC 8915. Every wire detail
/// here — the NTS-KE record framing, the AEAD negotiation, the TLS 1.3 exporter labels, the
/// cookie opacity, the authenticator's associated data — has to match a completely separate
/// codebase for these to pass.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class ChronyNtsServerTests
{

    private ChronyNtsServerFixture? chrony;


    [OneTimeSetUp]
    public async Task StartChrony()
    {

        TestEnvironment.RequireChronyWithNts();
        TestEnvironment.RequireWsl("openssl");

        chrony = await ChronyNtsServerFixture.StartAsync();

        if (chrony is null)
            Assert.Ignore("Could not start chronyd as an NTS server inside WSL — skipping. " +
                          "Check: wsl -u root apt-get install -y chrony openssl");

    }


    [OneTimeTearDown]
    public async Task StopChrony()
    {
        if (chrony is not null)
            await chrony.DisposeAsync();
    }


    /// <summary>
    /// A client pointed at the WSL chronyd. Its certificate is self-signed, so validation is
    /// accepted explicitly rather than by disabling it — the point of the test is the NTS
    /// protocol, not the PKI.
    /// </summary>
    /// <param name="aeadAlgorithms">
    /// What to offer chronyd. Left null the client offers everything it can perform, in its own
    /// order, which is how it behaves in the field; naming one pins the negotiation.
    /// </param>
    /// <param name="compliantExporterContext">
    /// Whether to claim RFC 8915 § 5.1's exporter context for AES-128-GCM-SIV. False makes the
    /// client speak chrony's older dialect on purpose.
    /// </param>
    private NTSClient CreateClient(IEnumerable<AEADAlgorithms>?  aeadAlgorithms             = null,
                                   Boolean                       compliantExporterContext   = true)

        => new (DomainName.Parse(chrony!.VmAddress),
                NTSKE_Port:                  chrony.NTSKEPort,
                NTP_Port:                    chrony.NTPPort,
                IPVersionPreference:         IPVersionPreference.IPv4Only,
                Timeout:                     TimeSpan.FromSeconds(15),
                RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                 => TLSValidationResult.Success(),
                OfferedAEADAlgorithms:       aeadAlgorithms,
                CompliantAES128GCMSIVExporterContext: compliantExporterContext);


    /// <summary>
    /// Plain NTPv4 first: if this fails, nothing about the NTS layer can be concluded.
    /// chronyd is configured with <c>local stratum 10</c>, so it answers as a stratum-10
    /// server.
    /// </summary>
    [Test]
    public async Task PlainNtp_AgainstChronyd()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var result = await CreateClient().QueryTime(Timeout: TimeSpan.FromSeconds(15));

        Assert.That(result.Success, Is.True, $"a plain NTP query to chronyd failed: {result.ErrorMessage}");

        var response = result.Response!;

        Assert.Multiple(() => {
            Assert.That(response.Mode,    Is.EqualTo(4), "a server reply is mode 4");
            Assert.That(response.VN,      Is.EqualTo(4), "NTPv4");
            Assert.That(response.Stratum, Is.EqualTo(10), "chronyd is configured as 'local stratum 10'");
            Assert.That(response.TransmitTimestamp, Is.Not.Null.And.Not.EqualTo(0UL));
        });

    }


    /// <summary>
    /// NTS-KE against chronyd: TLS 1.3, ALPN <c>ntske/1</c>, the RFC 8915 §4.1 record framing
    /// and the §5.1 exporter labels all have to line up for two session keys and a set of
    /// cookies to come out.
    ///
    /// <para>
    /// The keys are asserted against the algorithm chronyd chose rather than a constant, which
    /// is not a loosening but the point: this test asserted 32 octets until Norn implemented
    /// AES-128-GCM-SIV, at which point chronyd — offered it — took it, and the exporter
    /// correctly produced 16. A test written to a constant would have called that a regression.
    /// </para>
    ///
    /// chronyd issues 8 cookies, which is the pool size RFC 8915 §5.7 suggests.
    /// </summary>
    [Test]
    public async Task NtsKe_AgainstChronyd()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var result = await CreateClient().GetNTSKERecords();

        Assert.That(result.Success, Is.True,
                    $"NTS-KE against chronyd failed: {result.ErrorMessage} ({result.ErrorCategory})");

        var response = result.Response!;

        Assert.Multiple(() => {

            var keyLength = NTSAEAD.KeyLength(response.AEADAlgorithm);

            Assert.That(keyLength,
                        Is.Not.Null,
                        $"chronyd chose {response.AEADAlgorithm.AsText()}, which Norn cannot perform");

            Assert.That(response.C2SKey.Length, Is.EqualTo(keyLength),
                        $"{response.AEADAlgorithm.AsText()} client-to-server key length");

            Assert.That(response.S2CKey.Length, Is.EqualTo(keyLength),
                        $"{response.AEADAlgorithm.AsText()} server-to-client key length");

            Assert.That(response.C2SKey, Is.Not.EqualTo(response.S2CKey).AsCollection,
                        "the two directions must use different keys — RFC 8915 §5.1 gives them different exporter contexts");

            Assert.That(response.Cookies.Count(), Is.GreaterThan(0),
                        "chronyd should hand out cookies");

        });

    }


    /// <summary>
    /// A full AES-128-GCM-SIV session with chronyd, on RFC 8915 § 5.1's exporter context.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The reason algorithm 30 was worth implementing. chrony has preferred it for years, and a
    /// Norn that offered only AES-SIV-CMAC-256 meant every chrony session quietly negotiated down
    /// to the mandatory algorithm — interoperable, and never once exercising the primitive the
    /// reference implementation actually reaches for.
    /// </para>
    /// <para>
    /// It also took a long time to get here, and the reason is worth keeping. § 5.1 puts the
    /// negotiated algorithm's id into the exporter context; chrony writes 15 there for sessions
    /// running on 30, and has since it shipped the algorithm. Both sides then derive a key the
    /// RFC does not describe — and agree on it perfectly, which is why no Norn-to-Norn test could
    /// ever see it and why the key exchange succeeded while every packet after it failed. IANA
    /// record type 1024 is how the two implementations agree to stop; this test is the compliant
    /// half of that negotiation, and <see cref="Chronyd_AcceptsTheOlderExporterContextToo"/> the
    /// other.
    /// </para>
    /// </remarks>
    [Test]
    public async Task Chronyd_AndGcmSiv_Interoperate()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var client  = CreateClient(aeadAlgorithms: [ AEADAlgorithms.AES_128_GCM_SIV ]);
        var result  = await client.GetNTSKERecords();

        Assert.That(result.Success, Is.True,
                    $"the key exchange failed: {result.ErrorMessage}");

        var response = result.Response!;

        Assert.Multiple(() => {

            Assert.That(response.AEADAlgorithm,
                        Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV),
                        "chronyd accepts the algorithm when it is the only one offered");

            Assert.That(response.CompliantAES128GCMSIVExporterContext,
                        Is.True,
                        "chronyd echoed record 1024, so both sides are on § 5.1's context");

            Assert.That(response.C2SKey.Length, Is.EqualTo(16),
                        "algorithm 30 takes a sixteen-octet key");

        });

        var query = await client.QueryTime(NTSKEResponse: response);

        Assert.That(query.Success,
                    Is.True,
                    $"chronyd agreed on AES-128-GCM-SIV and then could not read the query: {query.ErrorMessage}");

    }


    /// <summary>
    /// And the same session on chrony's older exporter context, which is what isolates the cause
    /// to those two octets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identical to the test above in every respect a packet can show — same algorithm, same
    /// sixteen-octet key length, same twelve-octet nonce, same framing, same associated data —
    /// except that the client does not send record 1024, so chronyd does not echo it and both
    /// sides write algorithm id 15 into the exporter context instead of 30. It works, and before
    /// record 1024 was implemented the other one did not. One variable, two outcomes.
    /// </para>
    /// <para>
    /// It is also not merely a diagnostic. Every chronyd that predates the record derives keys
    /// this way and there is no negotiating with it, so this is the dialect Norn must still speak
    /// to reach those servers at all.
    /// </para>
    /// </remarks>
    [Test]
    public async Task Chronyd_AcceptsTheOlderExporterContextToo()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var client  = CreateClient(aeadAlgorithms:           [ AEADAlgorithms.AES_128_GCM_SIV ],
                                   compliantExporterContext: false);

        var result  = await client.GetNTSKERecords();

        Assert.That(result.Success, Is.True,
                    $"the key exchange failed: {result.ErrorMessage}");

        var response = result.Response!;

        Assert.Multiple(() => {

            Assert.That(response.AEADAlgorithm,
                        Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV));

            Assert.That(response.CompliantAES128GCMSIVExporterContext,
                        Is.False,
                        "nothing was claimed, so chronyd must not have echoed record 1024");

        });

        var query = await client.QueryTime(NTSKEResponse: response);

        Assert.That(query.Success,
                    Is.True,
                    $"chronyd could not read a query keyed with algorithm id 15 in the exporter " +
                    $"context, which is the derivation it uses when nobody asks for the other: " +
                    $"{query.ErrorMessage}");

    }


    /// <summary>
    /// And chronyd still works when Norn insists on the mandatory algorithm.
    /// </summary>
    /// <remarks>
    /// The control for the test above, and worth having on its own: RFC 8915 § 5.1 makes
    /// AES-SIV-CMAC-256 the one every implementation must have, so a client pinned to it has to
    /// reach every server there is. It also shows that chronyd's choice above came from Norn's
    /// offer rather than from chronyd having only one option.
    /// </remarks>
    [Test]
    public async Task Chronyd_AlsoAcceptsTheMandatoryAlgorithm()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var client  = CreateClient(aeadAlgorithms: [ AEADAlgorithms.AES_SIV_CMAC_256 ]);
        var result  = await client.GetNTSKERecords();

        Assert.That(result.Success, Is.True,
                    $"NTS-KE against chronyd failed: {result.ErrorMessage}");

        Assert.Multiple(() => {

            Assert.That(result.Response!.AEADAlgorithm,
                        Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256),
                        "only one algorithm was offered, so nothing else may be agreed");

            Assert.That(result.Response.C2SKey.Length, Is.EqualTo(32));

        });

        var query = await client.QueryTime(NTSKEResponse: result.Response!);

        Assert.That(query.Success, Is.True, query.ErrorMessage);

    }


    /// <summary>
    /// The full exchange: an NTS-protected query answered and authenticated by chronyd.
    ///
    /// For this to pass, Norn must compute the authenticator's associated data exactly as
    /// chronyd does — the NTP header followed by every preceding extension field, as one
    /// contiguous string — and chronyd must accept the AES-SIV output Norn produced.
    /// </summary>
    [Test]
    public async Task AuthenticatedNtsQuery_AgainstChronyd()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var client      = CreateClient();

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var result      = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(15));

        Assert.That(result.Success, Is.True,
                    $"the NTS query to chronyd failed: {result.ErrorMessage} ({result.ErrorCategory})\n" +
                    $"chronyd server stats:\n{chrony.ServerStats()}");

        var response = result.Response!;

        Assert.Multiple(() => {

            Assert.That(response.Mode,    Is.EqualTo(4));
            Assert.That(response.Stratum, Is.EqualTo(10));

            Assert.That(response.UniqueIdentifier(), Is.Not.Null,
                        "RFC 8915 §5.7: the server echoes the Unique Identifier");

            Assert.That(response.Extensions.Any(extension => extension is AuthenticatorAndEncryptedExtension),
                        Is.True,
                        "the response must carry an NTS Authenticator extension field");

            Assert.That(response.Extensions.OfType<NTSCookieExtension>().Any(),
                        Is.True,
                        "RFC 8915 §5.7: the server returns at least one fresh cookie");

        });

    }


    /// <summary>
    /// Cookies issued by chronyd must survive several round trips: the client spends one per
    /// query and chronyd replaces it, so a sequence of queries should keep working without
    /// re-running NTS-KE.
    /// </summary>
    [Test]
    public async Task RepeatedNtsQueries_AgainstChronyd()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var client      = CreateClient();

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        for (var i = 1; i <= 4; i++)
        {

            var result = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(15));

            Assert.That(result.Success, Is.True,
                        $"NTS query {i} of 4 failed: {result.ErrorMessage} ({result.ErrorCategory})\n" +
                        $"chronyd server stats:\n{chrony.ServerStats()}");

        }

    }


    /// <summary>
    /// Norn must treat a chronyd cookie as the opaque blob RFC 8915 §6 says it is: stored and
    /// echoed back unchanged, never parsed. Any attempt to interpret a foreign server's
    /// cookie format would break against a server that changed it.
    /// </summary>
    [Test]
    public async Task ChronydCookies_AreEchoedUnchanged()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var client      = CreateClient();

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var issuedCookie = ntsKeResult.Response!.Cookies.First();

        Assert.That(issuedCookie, Is.Not.Empty, "chronyd should return a non-empty cookie");

        var result       = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                Timeout:       TimeSpan.FromSeconds(15));

        Assert.That(result.Success, Is.True, $"the NTS query failed: {result.ErrorMessage}");

        // chronyd only accepts a cookie it issued, byte for byte, so a successful query is
        // itself proof the cookie was carried through untouched.
        Assert.That(result.UsedCookie, Is.Not.Null, "the query should record which cookie it spent");

        Assert.That(result.UsedCookie, Is.EqualTo(issuedCookie).AsCollection,
                    "the cookie sent must be exactly the one chronyd issued");

    }

}
