using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace NTSConformance.Core.Fixtures;

/// <summary>
/// A self-signed secp256r1 server certificate with caller-chosen subject, SANs and validity.
///
/// Norn's <c>NTSKE_TLSService</c> can generate its own, but it does so per connection and the
/// type is <c>internal</c>, so a certificate that stays the same across connections has to
/// come from outside. That matters for two things:
///
/// <list type="bullet">
/// <item>chrony verifies the NTS-KE certificate and has to be given one to trust up front,
/// which is impossible if it changes every handshake.</item>
/// <item>Hostname, expiry and SAN validation can only be tested against certificates built
/// to fail in a specific way.</item>
/// </list>
/// </summary>
public sealed record TestCertificate(X509Certificate         Certificate,
                                     ECPrivateKeyParameters  PrivateKey)
{

    /// <summary>Generate a self-signed certificate.</summary>
    /// <param name="subjectCommonName">The CN to place in the subject and issuer.</param>
    /// <param name="subjectAlternativeNames">DNS names to place in the SAN extension.</param>
    /// <param name="notBefore">Validity start; defaults to one day ago.</param>
    /// <param name="notAfter">Validity end; defaults to 30 days out.</param>
    public static TestCertificate Generate(String                subjectCommonName,
                                           IEnumerable<String>?  subjectAlternativeNames  = null,
                                           DateTime?             notBefore                = null,
                                           DateTime?             notAfter                 = null,
                                           IEnumerable<String>?  ipAddresses              = null)
    {

        var random     = new SecureRandom();

        var generator  = new ECKeyPairGenerator("ECDSA");
        generator.Init(new ECKeyGenerationParameters(
                           new DerObjectIdentifier("1.2.840.10045.3.1.7"),   // secp256r1 / P-256
                           random));

        var keyPair    = generator.GenerateKeyPair();

        var name       = new X509Name($"CN={subjectCommonName}");

        var builder    = new X509V3CertificateGenerator();

        builder.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.ValueOf(DateTime.UtcNow.Ticks & Int64.MaxValue));
        builder.SetIssuerDN(name);
        builder.SetSubjectDN(name);
        builder.SetNotBefore(notBefore ?? DateTime.UtcNow.AddDays(-1));
        builder.SetNotAfter (notAfter  ?? DateTime.UtcNow.AddDays(30));
        builder.SetPublicKey(keyPair.Public);

        builder.AddExtension(X509Extensions.BasicConstraints, true,  new BasicConstraints(false));
        builder.AddExtension(X509Extensions.KeyUsage,         true,  new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
        builder.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth));
        builder.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                             new SubjectKeyIdentifierStructure(keyPair.Public));

        var names = new List<GeneralName>();

        foreach (var dnsName in subjectAlternativeNames ?? [ subjectCommonName ])
            names.Add(new GeneralName(GeneralName.DnsName, dnsName));

        foreach (var ipAddress in ipAddresses ?? [])
            names.Add(new GeneralName(GeneralName.IPAddress, ipAddress));

        if (names.Count > 0)
            builder.AddExtension(X509Extensions.SubjectAlternativeName, false,
                                 new GeneralNames(names.ToArray()));

        var certificate = builder.Generate(
                              new Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private, random)
                          );

        return new TestCertificate(certificate, (ECPrivateKeyParameters) keyPair.Private);

    }


    /// <summary>The certificate as PEM, for tools that read a trust file (chrony's ntstrustedcerts).</summary>
    public String ToPem()
    {

        var builder = new StringBuilder();

        builder.AppendLine("-----BEGIN CERTIFICATE-----");

        var base64 = Convert.ToBase64String(Certificate.GetEncoded());

        for (var offset = 0; offset < base64.Length; offset += 64)
            builder.AppendLine(base64.Substring(offset, Math.Min(64, base64.Length - offset)));

        builder.AppendLine("-----END CERTIFICATE-----");

        return builder.ToString();

    }


    /// <summary>Write the certificate to a PEM file and return its path.</summary>
    public String WritePem(String directory, String fileName = "nts-ke.pem")
    {

        Directory.CreateDirectory(directory);

        var path = Path.Combine(directory, fileName);

        File.WriteAllText(path, ToPem());

        return path;

    }

}
