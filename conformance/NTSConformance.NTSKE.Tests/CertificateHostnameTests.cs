using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using NTSConformance.Core.Fixtures;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// RFC 9525 § 6.3: which host names a server certificate speaks for.
///
/// <para>
/// This is the check that decides whether a client is talking to the server it meant to. TLS
/// proves the peer holds the private key for the certificate it presented; nothing about that
/// says the certificate was issued for the name the client dialled, and the only thing that
/// does is this comparison. Get it too strict and valid servers are refused; get it too loose
/// and an attacker with a certificate for any name at all — one they legitimately own — is
/// accepted as any other.
/// </para>
/// <para>
/// The wildcard is where "too loose" hides. A suffix match reads "*.example.com" as covering
/// "evil.attacker.example.com"; a match that allows zero labels reads it as covering the apex
/// it was not issued for. Both look reasonable written down, and neither shows up against the
/// exact-name certificates a test suite tends to generate — which is why every case below is a
/// certificate presenting a wildcard.
/// </para>
/// <para>
/// Asserted against the same decoder Norn's NTS-KE client uses on a live handshake, so a
/// regression here is a regression there.
/// </para>
/// </summary>
[TestFixture]
public class CertificateHostnameTests
{

    private static X509Certificate2 CertificateFor(params String[] subjectAlternativeNames)

        => TestCertificate.Generate(
               subjectCommonName:        "Norn conformance",
               subjectAlternativeNames:  subjectAlternativeNames
           ).ToDotNet();


    #region A wildcard certificate

    /// <summary>
    /// A "*.example.com" certificate covers one label below the anchor, and nothing else.
    /// </summary>
    [TestCase("www.example.com",       true,  TestName = "AWildcardCertificate_CoversOneLabel(the host it was issued for)")]
    [TestCase("api.example.com",       true,  TestName = "AWildcardCertificate_CoversOneLabel(any single label)")]
    [TestCase("WWW.EXAMPLE.COM",       true,  TestName = "AWildcardCertificate_CoversOneLabel(case-insensitive, RFC 4343)")]
    [TestCase("example.com",           false, TestName = "AWildcardCertificate_CoversOneLabel(not the apex)")]
    [TestCase("a.b.example.com",       false, TestName = "AWildcardCertificate_CoversOneLabel(not two levels)")]
    [TestCase("evil.attacker.example", false, TestName = "AWildcardCertificate_CoversOneLabel(not an unrelated host)")]
    [TestCase("wwwexample.com",        false, TestName = "AWildcardCertificate_CoversOneLabel(not without the label boundary)")]
    public void AWildcardCertificate_CoversOneLabel(String HostName, Boolean Expected)
    {

        var certificate = CertificateFor("*.example.com");

        Assert.That(certificate.MatchesHostName(DomainName.Parse(HostName)),
                    Is.EqualTo(Expected),
                    $"a certificate for '*.example.com' against '{HostName}'");

    }


    /// <summary>
    /// A certificate carrying several names is accepted for any of them.
    /// </summary>
    /// <remarks>
    /// The failure this replaces was real and quiet. The check used to fall back to
    /// <c>GetNameInfo</c>, which reports a single name, so a certificate valid for four hosts was
    /// judged on whichever one the platform happened to return — and the other three were
    /// refused with no indication why.
    /// </remarks>
    [Test]
    public void ACertificateWithSeveralNames_IsAcceptedForEachOfThem()
    {

        var certificate = CertificateFor("first.example.com",
                                         "second.example.com",
                                         "*.wild.example.com");

        Assert.Multiple(() => {

            Assert.That(certificate.MatchesHostName(DomainName.Parse("first.example.com")),      Is.True);
            Assert.That(certificate.MatchesHostName(DomainName.Parse("second.example.com")),     Is.True);
            Assert.That(certificate.MatchesHostName(DomainName.Parse("host.wild.example.com")),  Is.True);

            Assert.That(certificate.MatchesHostName(DomainName.Parse("third.example.com")),      Is.False);

        });

    }


    /// <summary>
    /// A name that is not a valid presented identifier is skipped, and the rest still work.
    /// </summary>
    /// <remarks>
    /// RFC 9525 § 6.3: an invalid presented identifier "MUST be ignored". Not "the certificate
    /// is invalid" — a reader that threw on the bad entry would take a usable certificate down
    /// with it, which is how the previous version behaved once names went through
    /// <c>DomainName.Parse</c>.
    /// </remarks>
    [Test]
    public void AnInvalidNameInTheCertificate_DoesNotDisqualifyTheOthers()
    {

        var certificate = CertificateFor("w*.example.com",       // partial wildcard, § 6.3 invalid
                                         "good.example.com");

        Assert.Multiple(() => {

            Assert.That(() => certificate.GetDNSNamePatterns().ToArray(),
                        Throws.Nothing,
                        "reading the names must not throw on the bad one");

            Assert.That(certificate.MatchesHostName(DomainName.Parse("good.example.com")),
                        Is.True,
                        "and the good name must still work");

            Assert.That(certificate.MatchesHostName(DomainName.Parse("ww.example.com")),
                        Is.False,
                        "while the partial wildcard covers nothing at all");

        });

    }

    #endregion


    #region What is not consulted

    /// <summary>
    /// The Common Name is not a fallback.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 9525 § 6.1 dropped it, and browsers stopped honouring it years before that. A client
    /// that still falls back accepts certificates that no certificate authority may issue any
    /// more, which means the only certificates it gains are the ones nobody else will take.
    /// </para>
    /// <para>
    /// The certificate here carries no subject alternative names at all, which is the only shape
    /// that tests this. A certificate that has both is no evidence either way:
    /// <c>GetNameInfo</c> — the fallback that used to be here — returns the alternative name
    /// when there is one, so a Common Name sitting beside a SAN is never consulted even by an
    /// implementation that means to.
    /// </para>
    /// </remarks>
    [Test]
    public void TheCommonName_IsNotConsulted()
    {

        var certificate = TestCertificate.Generate(
                              subjectCommonName:        "cn.example.com",
                              subjectAlternativeNames:  []
                          ).ToDotNet();

        Assert.Multiple(() => {

            Assert.That(certificate.GetDNSNamePatterns(),
                        Is.Empty,
                        "the fixture has to have no alternative names for this to mean anything");

            Assert.That(certificate.MatchesHostName(DomainName.Parse("cn.example.com")),
                        Is.False,
                        "the Common Name says 'cn.example.com', and that is not a name this " +
                        "certificate speaks for");

        });

    }


    /// <summary>
    /// A certificate with no DNS names at all matches no host name.
    /// </summary>
    /// <remarks>
    /// The IP-only certificates this suite uses for the WSL interop tests are exactly this case.
    /// They are matched by address (§ 6.4), never by name, and a hostname check that quietly
    /// succeeded on them would be succeeding for no reason.
    /// </remarks>
    [Test]
    public void ACertificateWithoutDNSNames_MatchesNoHostName()
    {

        var certificate = TestCertificate.Generate(
                              subjectCommonName:  "Norn conformance",
                              ipAddresses:        [ "127.0.0.1" ]
                          ).ToDotNet();

        Assert.Multiple(() => {

            Assert.That(certificate.GetDNSNamePatterns(),                                  Is.Empty);
            Assert.That(certificate.MatchesHostName(DomainName.Parse("localhost")),        Is.False);
            Assert.That(certificate.GetIIPAddresses().Select(address => address.ToString()),
                        Is.EqualTo(new[] { "127.0.0.1" }).AsCollection,
                        "and the address is still there to be matched by § 6.4");

        });

    }

    #endregion

}
