using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSInterop.LinuxTools.Tests;

/// <summary>
/// Probes Norn's NTS-KE endpoint with GnuTLS's <c>gnutls-cli</c> — a TLS stack entirely
/// unrelated to the BouncyCastle one Norn uses on both sides.
///
/// RFC 8915 §4 pins the transport down tightly: TLS 1.3 or later, and ALPN
/// <c>ntske/1</c>. Norn talking to itself cannot demonstrate either, because both ends
/// share the same implementation and the same assumptions.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public class GnutlsNtsKeTests
{

    private NornServerFixture? fixture;
    private TestCertificate?   certificate;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireWsl("gnutls-cli");
        TestEnvironment.RequireWslInboundTcp();

        certificate = TestCertificate.Generate("nts-interop.test", [ "nts-interop.test" ]);
        fixture     = await NornServerFixture.StartAsync(certificate: certificate);

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// The Windows host as WSL sees it, or an Assert.Ignore if that cannot be worked out.
    /// </summary>
    private static String HostAddress()
    {

        var address = Wsl.WindowsHostAddress;

        if (address is null)
            Assert.Ignore("Could not determine the Windows host address as seen from WSL.");

        return address!;

    }


    /// <summary>
    /// RFC 8915 §4: the NTS-KE server must negotiate the <c>ntske/1</c> application protocol.
    /// A server that ignores ALPN would be indistinguishable from any other TLS service and
    /// a conformant client would refuse it.
    /// </summary>
    [Test]
    public void NtsKe_NegotiatesNtskeAlpn()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var result = Wsl.Run($"gnutls-cli --insecure --alpn=ntske/1 --port={fixture.NTSKEPort} " +
                             $"--no-ca-verification {HostAddress()} </dev/null 2>&1",
                             TimeSpan.FromSeconds(30));


        Assert.That(result.StdOut,
                    Does.Contain("ntske/1"),
                    $"gnutls-cli should report the negotiated ALPN protocol as ntske/1.\n{result}");

    }


    /// <summary>
    /// RFC 8915 §4 requires TLS 1.3 or later. Offering only TLS 1.2 must fail the handshake:
    /// NTS derives its session keys with the TLS 1.3 exporter, so an older version cannot
    /// carry the protocol at all.
    /// </summary>
    [Test]
    public void NtsKe_RefusesTls12()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var result = Wsl.Run($"gnutls-cli --insecure --no-ca-verification --priority=NORMAL:-VERS-ALL:+VERS-TLS1.2 " +
                             $"--alpn=ntske/1 --port={fixture.NTSKEPort} {HostAddress()} </dev/null 2>&1",
                             TimeSpan.FromSeconds(30));


        Assert.That(result.StdOut,
                    Does.Not.Contain("Handshake was completed"),
                    $"a TLS 1.2-only client must not complete an NTS-KE handshake.\n{result}");

    }


    /// <summary>
    /// The certificate the endpoint presents must be the one that was injected — proof that
    /// an operator-supplied certificate is actually used, and the precondition for any
    /// external client being able to trust it.
    /// </summary>
    [Test]
    public void NtsKe_PresentsTheConfiguredCertificate()
    {

        if (fixture is null || certificate is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var result = Wsl.Run($"gnutls-cli --insecure --no-ca-verification --print-cert --alpn=ntske/1 " +
                             $"--port={fixture.NTSKEPort} {HostAddress()} </dev/null 2>&1",
                             TimeSpan.FromSeconds(30));


        Assert.That(result.StdOut,
                    Does.Contain("nts-interop.test"),
                    $"the presented certificate should carry the configured subject.\n{result}");

    }

}
