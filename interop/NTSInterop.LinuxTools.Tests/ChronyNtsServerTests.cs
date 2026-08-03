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
    private NTSClient CreateClient(IEnumerable<AEADAlgorithms>? aeadAlgorithms = null)

        => new (DomainName.Parse(chrony!.VmAddress),
                NTSKE_Port:                  chrony.NTSKEPort,
                NTP_Port:                    chrony.NTPPort,
                IPVersionPreference:         IPVersionPreference.IPv4Only,
                Timeout:                     TimeSpan.FromSeconds(15),
                RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                 => TLSValidationResult.Success(),
                OfferedAEADAlgorithms:       aeadAlgorithms);


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
    /// AES-128-GCM-SIV does not yet interoperate with chronyd, in either direction.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Norn implements the algorithm and matches all twenty-four of RFC 8452's published
    /// vectors, encrypt and decrypt. A Norn client and a Norn server complete a full session on
    /// it, with sixteen-octet keys, a twelve-octet nonce and cookies thirty-two octets smaller
    /// than under AES-SIV-CMAC-256. Against chronyd, the key exchange agrees on the algorithm
    /// and then every NTP packet fails: chronyd answers Norn's queries with an NTS NAK, and
    /// Norn's server counts chronyd's requests as invalid. Under AES-SIV-CMAC-256 both
    /// directions work, before and after the change.
    /// </para>
    /// <para>
    /// What that pattern rules out is most of the surface. The primitive is right, or the
    /// vectors would fail. The framing is right, or Norn would not read its own. The associated
    /// data is right, or AES-SIV would fail too — it is the same code. What is left is the one
    /// thing the two algorithms do differently that no Norn-to-Norn test can see: the RFC 8915
    /// § 5.1 exporter is asked for sixteen octets instead of thirty-two, and a client and a
    /// server that both derive the same wrong key agree with each other perfectly.
    /// </para>
    /// <para>
    /// So the algorithm stays implemented and out of the default offer — see
    /// <see cref="NTSAEAD.Supported"/> — and this test is the record of why. It is expected to
    /// fail, and it is the thing that will say when the cause has been found.
    /// </para>
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task Chronyd_AndGcmSiv_DoNotYetInteroperate()
    {

        if (chrony is null)
        {
            Assert.Ignore("chronyd is not running");
            return;
        }

        var client  = CreateClient(aeadAlgorithms: [ AEADAlgorithms.AES_128_GCM_SIV ]);
        var result  = await client.GetNTSKERecords();

        Assert.That(result.Success, Is.True,
                    $"the key exchange itself works and agrees on the algorithm: {result.ErrorMessage}");

        Assert.That(result.Response!.AEADAlgorithm,
                    Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV),
                    "chronyd accepts the algorithm when it is the only one offered");

        var query = await client.QueryTime(NTSKEResponse: result.Response!);

        Assert.That(query.Success,
                    Is.True,
                    $"chronyd agreed on AES-128-GCM-SIV and then could not read the query. " +
                    $"This is the open defect: {query.ErrorMessage}");

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
