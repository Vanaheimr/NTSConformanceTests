using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// Norn's NTS client against an <c>ntpd-rs</c> NTS server — the second independent server this
/// client is held to, after chronyd.
///
/// Agreeing with one implementation is not the same as being correct: two implementations can
/// share a reading of a specification that the specification does not support, and chrony is
/// the reading most of the internet runs. ntpd-rs is a separate codebase in another language,
/// and it serves NTS-KE through rustls, so Norn's client also meets a TLS stack it has not
/// otherwise been exercised against.
///
/// <para>
/// One thing to know before reading the assertions. ntpd-rs is configured here without any
/// upstream source — it has no local-clock driver, its source modes are server, nts, pool and
/// sock — so it serves with the leap indicator set to 3, a zero reference timestamp and the
/// reference identifier "XNON": by its own declaration it is not synchronized. Norn refuses
/// such a server as a time source, which is what RFC 5905 § 7.3 asks of a client, so
/// <c>QueryTime</c> reports failure here however well the NTS layer works.
/// </para>
/// <para>
/// These tests therefore assert what is actually under test — that the NTS exchange completes
/// and authenticates — and assert separately that the refusal is about synchronization and
/// nothing else. Giving ntpd-rs a real upstream would make the naive assertion work, at the
/// cost of a second daemon and of letting it steer the VM's clock.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
[Category(TestCategories.Slow)]
public class NtpdRsNtsServerTests
{

    private NtpdRsNtsServerFixture? server;


    [OneTimeSetUp]
    public async Task StartNtpdRs()
    {

        TestEnvironment.RequireNtpdRs();
        TestEnvironment.RequireWsl("openssl");

        server = await NtpdRsNtsServerFixture.StartAsync();

    }


    [OneTimeTearDown]
    public async Task StopNtpdRs()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    /// <summary>
    /// A client pointed at the ntpd-rs in WSL. Its certificate is self-signed, so validation is
    /// accepted explicitly rather than switched off — what is under test is the NTS protocol,
    /// not the PKI.
    /// </summary>
    private NTSClient CreateClient()

        => new (DomainName.Parse(server!.VmAddress),
                NTSKE_Port:                  server.NTSKEPort,
                NTP_Port:                    server.NTPPort,
                IPVersionPreference:         IPVersionPreference.IPv4Only,
                Timeout:                     TimeSpan.FromSeconds(15),
                RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                 => TLSValidationResult.Success());


    /// <summary>
    /// Whatever Norn objected to, it must not have been the cryptography. A failure in the NTS
    /// layer — a cookie ntpd-rs would not accept, an authenticator that did not verify, keys
    /// derived differently on the two sides — arrives in one of these categories, and none of
    /// them may appear.
    /// </summary>
    private static void AssertTheNtsLayerAgreed(NTSQueryResult Result, String context)
    {

        var validation = Result.ResponseValidation;

        Assert.That(validation, Is.Not.Null, $"no validation result was produced ({context})");

        Assert.That(validation!.ErrorCategory,
                    Is.Not.EqualTo(NTSQueryErrorCategory.NTSAuthentication).
                       And.Not.EqualTo(NTSQueryErrorCategory.Cookie).
                       And.Not.EqualTo(NTSQueryErrorCategory.NTSKE),
                    $"the NTS layer disagreed with ntpd-rs: {validation.ErrorMessage} ({context})");

        foreach (var message in validation.ErrorMessages)
            Assert.That(message.ToLowerInvariant(),
                        Does.Not.Contain("authenticat").And.Not.Contain("cookie").And.Not.Contain("unique identifier"),
                        $"an NTS-level complaint appeared among the validation errors ({context})");

    }


    /// <summary>
    /// Plain NTPv4 first: if the packet does not even come back, nothing about the NTS layer can
    /// be concluded. ntpd-rs answers with the stratum it was configured for and, having no
    /// upstream, marks itself unsynchronized — so the interesting assertion is that Norn read
    /// the packet and refused it for that reason rather than any other.
    /// </summary>
    [Test]
    public async Task PlainNtp_AgainstNtpdRs_IsAnsweredButDeclaredUnsynchronized()
    {

        if (server is null)
        {
            Assert.Ignore("ntpd-rs did not start — skipping.");
            return;
        }

        var result = await CreateClient().QueryTime(Timeout: TimeSpan.FromSeconds(15));

        Assert.That(result.Response,
                    Is.Not.Null,
                    $"ntpd-rs sent no answer at all: {result.ErrorMessage}\n{server.DaemonLog()}");

        Assert.Multiple(() => {

            Assert.That(result.Response!.Mode,    Is.EqualTo(4), "a server reply is mode 4");
            Assert.That(result.Response!.Stratum, Is.EqualTo(10), "the configured local-stratum");

            Assert.That(result.Response!.LI,
                        Is.EqualTo(3),
                        "an ntpd-rs with no upstream declares itself unsynchronized — if this " +
                        "ever changes, the reasoning in this fixture's summary needs revisiting");

            Assert.That(result.Success,
                        Is.False,
                        "and a client must not accept an unsynchronized server as a time source");

        });

    }


    /// <summary>
    /// NTS-KE against rustls: TLS 1.3, the <c>ntske/1</c> ALPN, and a record set Norn's validator
    /// accepts. Both session keys must come out, and at least one cookie — the exporter label and
    /// context bytes of RFC 8915 § 5.1 have to match byte for byte across two implementations
    /// that share no code for deriving them.
    /// </summary>
    [Test]
    public async Task NtsKe_AgainstNtpdRs()
    {

        if (server is null)
        {
            Assert.Ignore("ntpd-rs did not start — skipping.");
            return;
        }

        var result = await CreateClient().GetNTSKERecords();

        Assert.That(result.Success,
                    Is.True,
                    $"NTS-KE against ntpd-rs failed: {result.ErrorMessage}\n{server.DaemonLog()}");

        var response = result.Response!;

        Assert.Multiple(() => {
            // Against whatever was negotiated. ntpd-rs and chronyd need not choose the same
            // algorithm from the same offer, and neither is wrong for it.
            var keyLength = NTSAEAD.KeyLength(response.AEADAlgorithm);

            Assert.That(keyLength,
                        Is.Not.Null,
                        $"ntpd-rs chose {response.AEADAlgorithm.AsText()}, which Norn cannot perform");

            Assert.That(response.C2SKey.Length, Is.EqualTo(keyLength),
                        $"{response.AEADAlgorithm.AsText()} C2S key length");

            Assert.That(response.S2CKey.Length, Is.EqualTo(keyLength),
                        $"{response.AEADAlgorithm.AsText()} S2C key length");
            Assert.That(response.C2SKey,        Is.Not.EqualTo(response.S2CKey).AsCollection,
                        "the two directions must derive different keys");
            Assert.That(response.Cookies.Any(), Is.True, "NTS-KE must return at least one cookie");
        });

    }


    /// <summary>
    /// The whole exchange: keys from rustls's TLS exporter, a cookie minted by ntpd-rs, and an
    /// NTS-protected query whose answer Norn can authenticate.
    ///
    /// This covers the most ground of anything in the suite — extension field framing, the AEAD's
    /// associated data, cookie handling — all against an implementation sharing no line of code
    /// with Norn. The response is refused as a time source, for the reason described above; what
    /// must hold is that the refusal is about the clock and not about the cryptography.
    /// </summary>
    [Test]
    public async Task AuthenticatedNtsQuery_AgainstNtpdRs()
    {

        if (server is null)
        {
            Assert.Ignore("ntpd-rs did not start — skipping.");
            return;
        }

        var client      = CreateClient();
        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success,
                    Is.True,
                    $"NTS-KE against ntpd-rs failed: {ntsKeResult.ErrorMessage}\n{server.DaemonLog()}");

        var result = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                            Timeout:       TimeSpan.FromSeconds(15));

        Assert.That(result.Response,
                    Is.Not.Null,
                    $"the NTS-protected query got no answer: {result.ErrorMessage}\n{server.DaemonLog()}");

        AssertTheNtsLayerAgreed(result, "authenticated query");

        Assert.That(result.Response!.TransmitTimestamp,
                    Is.Not.Null.And.Not.EqualTo(0UL),
                    "the answer must carry a usable transmit timestamp");

    }


    /// <summary>
    /// Cookies survive being used, byte for byte. RFC 8915 § 6 leaves the format entirely to the
    /// server, so a client that reads into one — or normalises it in passing — works against
    /// itself and fails here, where the cookies are ntpd-rs's own.
    /// </summary>
    [Test]
    public async Task NtpdRsCookies_AreEchoedUnchanged()
    {

        if (server is null)
        {
            Assert.Ignore("ntpd-rs did not start — skipping.");
            return;
        }

        var client      = CreateClient();
        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success, Is.True, ntsKeResult.ErrorMessage);

        var original    = ntsKeResult.Response!.Cookies.First().ToArray();

        var result      = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                 Timeout:       TimeSpan.FromSeconds(15));

        Assert.That(result.Response, Is.Not.Null, $"{result.ErrorMessage}\n{server.DaemonLog()}");

        AssertTheNtsLayerAgreed(result, "cookie round trip");

        Assert.That(ntsKeResult.Response!.Cookies.First().ToArray(),
                    Is.EqualTo(original).AsCollection,
                    "the cookie ntpd-rs issued must not be altered by using it");

    }

}
