using System.Net.Security;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// End-to-end NTS against a real in-process Norn server: NTS-KE over TLS, then an
/// authenticated NTP exchange over UDP on loopback.
///
/// This is the fixture the rest of the server conformance tests build on, so it asserts
/// only that the happy path works — and reports the server's own diagnostics when it does
/// not, since a silent UDP timeout otherwise says nothing about the cause.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsRoundTripTests
{

    private NornServerFixture? fixture;
    private DebugXSink?        sink;


    [OneTimeSetUp]
    public async Task StartServer()
    {
        sink    = new DebugXSink();
        fixture = await NornServerFixture.StartAsync();
    }


    [OneTimeTearDown]
    public async Task StopServer()
    {

        if (fixture is not null)
            await fixture.DisposeAsync();

        sink?.Dispose();

    }


    /// <summary>
    /// The full RFC 8915 exchange: key establishment yields two session keys and at least
    /// one cookie, then an NTS-protected query returns an authenticated time.
    /// </summary>
    [Test]
    public async Task NtsKeThenAuthenticatedQuery_Succeeds()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var ntsKeResponse = ntsKeResult.Response!;

        // Against the algorithm that was actually negotiated, rather than a constant. This used
        // to assert 32 octets outright, which was right for as long as AES-SIV-CMAC-256 was the
        // only algorithm on offer and became wrong the day a second one was implemented — while
        // still describing a session that works perfectly.
        var expectedKeyLength = NTSAEAD.KeyLength(ntsKeResponse.AEADAlgorithm);

        Assert.Multiple(() => {

            Assert.That(expectedKeyLength,
                        Is.Not.Null,
                        $"the server negotiated {ntsKeResponse.AEADAlgorithm.AsText()}, which this " +
                        $"client cannot perform");

            Assert.That(ntsKeResponse.C2SKey.Length,  Is.EqualTo(expectedKeyLength),
                        $"{ntsKeResponse.AEADAlgorithm.AsText()} C2S key length");

            Assert.That(ntsKeResponse.S2CKey.Length,  Is.EqualTo(expectedKeyLength),
                        $"{ntsKeResponse.AEADAlgorithm.AsText()} S2C key length");

            Assert.That(ntsKeResponse.Cookies.Any(),  Is.True,
                        "NTS-KE must return at least one cookie");

        });

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResponse,
                                                Timeout:       TimeSpan.FromSeconds(10));

        // A UDP timeout tells us nothing on its own; the server logs why it dropped a request.
        Assert.That(queryResult.Success,
                    Is.True,
                    $"the NTS query failed: {queryResult.ErrorMessage}\n" +
                    $"server metrics: {fixture.Server.Metrics}\n" +
                    $"server log:\n{sink?.Text}");

        Assert.That(queryResult.Response, Is.Not.Null);

    }


    /// <summary>
    /// End-to-end NTS over IPv6 loopback (<c>::1</c>): verifies TCP/TLS over IPv6, an unbracketed
    /// <c>::1</c> in NTPv4 Server Negotiation (RFC 8915 § 4.1.7), IP-SAN matching for <c>::1</c>,
    /// and an authenticated NTP exchange over IPv6 UDP.
    /// </summary>
    [Test]
    public async Task FullNtsExchange_OverIPv6Loopback_Succeeds()
    {

        var ipv6Cert = TestCertificate.Generate(
                           subjectCommonName:       "localhost",
                           subjectAlternativeNames: [ "localhost" ],
                           ipAddresses:             [ "::1" ]
                       );

        using var dotNetCert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(
                                   ipv6Cert.Certificate.GetEncoded()
                               );

        Assert.That(dotNetCert.MatchesIPAddress(System.Net.IPAddress.IPv6Loopback),
                    Is.True,
                    "Certificate with IP-SAN ::1 must match IPv6 loopback");

        Assert.That(dotNetCert.MatchesIPAddress(System.Net.IPAddress.Loopback),
                    Is.False,
                    "Certificate with IP-SAN ::1 must not match IPv4 loopback");

        await using var ipv6Fixture = await NornServerFixture.StartAsync(
                                                certificate:      ipv6Cert,
                                                externalHostName: "[::1]",
                                                listenIPAddress:  IPv6Address.Localhost
                                            );

        SslPolicyErrors? observedPolicyErrors = null;

        var client = new NTSClient(
                         DomainName.Localhost,
                         NTSKE_Port:                 ipv6Fixture.NTSKEPort,
                         NTP_Port:                   ipv6Fixture.NTPPort,
                         RemoteCertificateValidator: (_, _, _, _, errors) => {
                                                         observedPolicyErrors = errors;
                                                         var withoutChain = errors & ~SslPolicyErrors.RemoteCertificateChainErrors;
                                                         return withoutChain == SslPolicyErrors.None
                                                                    ? TLSValidationResult.Success()
                                                                    : TLSValidationResult.Failed($"Unexpected TLS policy errors: {errors}");
                                                     },
                         IPVersionPreference:        IPVersionPreference.IPv6Only,
                         Timeout:                    TimeSpan.FromSeconds(10)
                     );

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success,
                    Is.True,
                    $"IPv6 NTS-KE failed: {ntsKeResult.ErrorMessage} (policyErrors={observedPolicyErrors})");

        Assert.That(observedPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch,
                    Is.EqualTo(SslPolicyErrors.None),
                    $"Unexpected name mismatch on IPv6 loopback (got {observedPolicyErrors})");

        Assert.That(ntsKeResult.Response!.NTPv4ServerNames,
                    Contains.Item("::1"),
                    "NTPv4 Server Negotiation must advertise bare '::1' without brackets (RFC 8915 § 4.1.7)");

        var queryResult = await client.QueryTime(
                              NTSKEResponse: ntsKeResult.Response!,
                              Timeout:       TimeSpan.FromSeconds(10)
                          );

        Assert.That(queryResult.Success,
                    Is.True,
                    $"IPv6 authenticated NTS query failed: {queryResult.ErrorMessage}");

    }


    /// <summary>
    /// Connecting by literal IP address to a server whose certificate carries only an IP-SAN
    /// (and no DNS SAN) must match without <see cref="SslPolicyErrors.RemoteCertificateNameMismatch"/>.
    /// </summary>
    [Test]
    public async Task FullNtsExchange_WithIPv4LiteralAndIpSanCertificate_MatchesIpSanWithoutNameMismatch()
    {

        var ipCert = TestCertificate.Generate(
                         subjectCommonName:       "ipv4-loopback",
                         subjectAlternativeNames: [],
                         ipAddresses:             [ "127.0.0.1" ]
                     );

        await using var ipFixture = await NornServerFixture.StartAsync(
                                              certificate:      ipCert,
                                              externalHostName: "127.0.0.1",
                                              listenIPAddress:  IPv4Address.Localhost
                                          );

        SslPolicyErrors? observedPolicyErrors = null;

        var client = new NTSClient(
                         DomainName.Parse("127.0.0.1"),
                         NTSKE_Port:                 ipFixture.NTSKEPort,
                         NTP_Port:                   ipFixture.NTPPort,
                         RemoteCertificateValidator: (_, _, _, _, errors) => {
                                                         observedPolicyErrors = errors;
                                                         var withoutChain = errors & ~SslPolicyErrors.RemoteCertificateChainErrors;
                                                         return withoutChain == SslPolicyErrors.None
                                                                    ? TLSValidationResult.Success()
                                                                    : TLSValidationResult.Failed($"Unexpected TLS policy errors: {errors}");
                                                     },
                         IPVersionPreference:        IPVersionPreference.IPv4Only,
                         Timeout:                    TimeSpan.FromSeconds(10)
                     );

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success,
                    Is.True,
                    $"IP-SAN NTS-KE failed: {ntsKeResult.ErrorMessage} (policyErrors={observedPolicyErrors})");

        Assert.That(observedPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch,
                    Is.EqualTo(SslPolicyErrors.None),
                    $"IPv4 IP-SAN 127.0.0.1 must match without RemoteCertificateNameMismatch (got {observedPolicyErrors})");

        var queryResult = await client.QueryTime(
                              NTSKEResponse: ntsKeResult.Response!,
                              Timeout:       TimeSpan.FromSeconds(10)
                          );

        Assert.That(queryResult.Success,
                    Is.True,
                    $"IP-SAN authenticated NTS query failed: {queryResult.ErrorMessage}");

    }


    /// <summary>
    /// Connecting directly by IPv6 literal (<see cref="IPv6Address.Localhost"/>, <c>::1</c>) to a
    /// server whose certificate carries <em>only</em> an IPv6 IP-SAN (<c>::1</c>, no DNS SAN) must
    /// match without <see cref="SslPolicyErrors.RemoteCertificateNameMismatch"/> and complete an
    /// authenticated IPv6 UDP NTS exchange.
    /// </summary>
    [Test]
    public async Task FullNtsExchange_DirectIPv6LiteralWithPureIpSanCertificate_Succeeds()
    {

        var pureIpv6Cert = TestCertificate.Generate(
                               subjectCommonName:       "ipv6-loopback",
                               subjectAlternativeNames: [],
                               ipAddresses:             [ "::1" ]
                           );

        await using var ipv6Fixture = await NornServerFixture.StartAsync(
                                                certificate:      pureIpv6Cert,
                                                externalHostName: "[::1]",
                                                listenIPAddress:  IPv6Address.Localhost
                                            );

        SslPolicyErrors? observedPolicyErrors = null;

        var client = new NTSClient(
                         IPv6Address.Localhost,
                         NTSKE_Port:                 ipv6Fixture.NTSKEPort,
                         NTP_Port:                   ipv6Fixture.NTPPort,
                         RemoteCertificateValidator: (_, _, _, _, errors) => {
                                                         observedPolicyErrors = errors;
                                                         var withoutChain = errors & ~SslPolicyErrors.RemoteCertificateChainErrors;
                                                         return withoutChain == SslPolicyErrors.None
                                                                    ? TLSValidationResult.Success()
                                                                    : TLSValidationResult.Failed($"Unexpected TLS policy errors: {errors}");
                                                     },
                         IPVersionPreference:        IPVersionPreference.IPv6Only,
                         Timeout:                    TimeSpan.FromSeconds(10)
                     );

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success,
                    Is.True,
                    $"Direct IPv6 literal NTS-KE failed: {ntsKeResult.ErrorMessage} (policyErrors={observedPolicyErrors})");

        Assert.That(observedPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch,
                    Is.EqualTo(SslPolicyErrors.None),
                    $"IPv6 IP-SAN ::1 must match without RemoteCertificateNameMismatch (got {observedPolicyErrors})");

        var queryResult = await client.QueryTime(
                              NTSKEResponse: ntsKeResult.Response!,
                              Timeout:       TimeSpan.FromSeconds(10)
                          );

        Assert.That(queryResult.Success,
                    Is.True,
                    $"Direct IPv6 literal authenticated NTS query failed: {queryResult.ErrorMessage}");

    }

}
