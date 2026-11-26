using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace NTSConformance.Core.Fixtures;

/// <summary>
/// Asymmetric key algorithm for generated test certificates.
/// </summary>
public enum TestCertificateKeyType
{
    EcP256,
    EcP384,
    Rsa2048,
    Ed25519
}


/// <summary>
/// A self-signed or CA-issued TLS server certificate with caller-chosen subject, SANs, key type,
/// optional intermediate chain, and validity.
///
/// Norn's <c>NTSKE_TLSService</c> can generate its own, but it does so per server instance and the
/// type is <c>internal</c>, so a certificate that stays the same across fixtures or exercises
/// specific key types / chains has to come from outside. That matters for two things:
///
/// <list type="bullet">
/// <item>chrony verifies the NTS-KE certificate and has to be given one to trust up front.</item>
/// <item>Hostname, expiry, SAN, chain, and multi-algorithm validation can only be tested against
/// certificates built with known properties.</item>
/// </list>
/// </summary>
public sealed record TestCertificate(X509Certificate                 Certificate,
                                     AsymmetricKeyParameter          PrivateKey,
                                     IReadOnlyList<X509Certificate>? IntermediateCertificates = null)
{

    /// <summary>
    /// Generate a self-signed certificate.
    /// </summary>
    /// <param name="subjectCommonName">The CN to place in the subject and issuer.</param>
    /// <param name="subjectAlternativeNames">DNS names to place in the SAN extension.</param>
    /// <param name="notBefore">Validity start; defaults to one day ago.</param>
    /// <param name="notAfter">Validity end; defaults to 30 days out.</param>
    /// <param name="ipAddresses">Optional IP SANs.</param>
    /// <param name="keyType">Key algorithm (default: ECDSA P-256).</param>
    public static TestCertificate Generate(String                  subjectCommonName,
                                           IEnumerable<String>?    subjectAlternativeNames  = null,
                                           DateTime?               notBefore                = null,
                                           DateTime?               notAfter                 = null,
                                           IEnumerable<String>?    ipAddresses              = null,
                                           TestCertificateKeyType  keyType                  = TestCertificateKeyType.EcP256)
    {

        var random  = new SecureRandom();
        var keyPair = GenerateKeyPair(keyType, random);
        var name    = new X509Name($"CN={subjectCommonName}");

        var certificate = BuildCertificate(
                              subjectName:              name,
                              issuerName:               name,
                              subjectPublicKey:         keyPair.Public,
                              issuerPrivateKey:         keyPair.Private,
                              issuerKeyType:            keyType,
                              isCa:                     false,
                              notBefore:                notBefore ?? DateTime.UtcNow.AddDays(-1),
                              notAfter:                 notAfter  ?? DateTime.UtcNow.AddDays(30),
                              subjectAlternativeNames:  subjectAlternativeNames ?? [ subjectCommonName ],
                              ipAddresses:              ipAddresses,
                              issuerPublicKey:          keyPair.Public,
                              random:                   random
                          );

        return new TestCertificate(certificate, keyPair.Private);

    }


    /// <summary>
    /// Generate a three-tier certificate hierarchy: Root CA -> Intermediate CA -> Leaf server cert.
    /// The returned <c>Leaf.IntermediateCertificates</c> contains the Intermediate CA (not the root).
    /// </summary>
    public static (TestCertificate Leaf, X509Certificate Intermediate, X509Certificate Root)
        GenerateChain(String                  subjectCommonName,
                      IEnumerable<String>?    subjectAlternativeNames  = null,
                      TestCertificateKeyType  leafKeyType              = TestCertificateKeyType.EcP256,
                      TestCertificateKeyType  caKeyType                = TestCertificateKeyType.EcP256,
                      DateTime?               notBefore                = null,
                      DateTime?               notAfter                 = null,
                      IEnumerable<String>?    ipAddresses              = null)
    {

        var random  = new SecureRandom();
        var start   = notBefore ?? DateTime.UtcNow.AddDays(-1);
        var end     = notAfter  ?? DateTime.UtcNow.AddDays(30);

        var rootKeyPair = GenerateKeyPair(caKeyType, random);
        var rootName    = new X509Name("CN=Norn Conformance Test Root CA");
        var rootCert    = BuildCertificate(
                              subjectName:              rootName,
                              issuerName:               rootName,
                              subjectPublicKey:         rootKeyPair.Public,
                              issuerPrivateKey:         rootKeyPair.Private,
                              issuerKeyType:            caKeyType,
                              isCa:                     true,
                              notBefore:                start.AddDays(-1),
                              notAfter:                 end.AddDays(30),
                              subjectAlternativeNames:  null,
                              ipAddresses:              null,
                              issuerPublicKey:          rootKeyPair.Public,
                              random:                   random
                          );

        var interKeyPair = GenerateKeyPair(caKeyType, random);
        var interName    = new X509Name("CN=Norn Conformance Test Intermediate CA");
        var interCert    = BuildCertificate(
                               subjectName:              interName,
                               issuerName:               rootName,
                               subjectPublicKey:         interKeyPair.Public,
                               issuerPrivateKey:         rootKeyPair.Private,
                               issuerKeyType:            caKeyType,
                               isCa:                     true,
                               notBefore:                start,
                               notAfter:                 end.AddDays(15),
                               subjectAlternativeNames:  null,
                               ipAddresses:              null,
                               issuerPublicKey:          rootKeyPair.Public,
                               random:                   random
                           );

        var leafKeyPair = GenerateKeyPair(leafKeyType, random);
        var leafName    = new X509Name($"CN={subjectCommonName}");
        var leafCert    = BuildCertificate(
                              subjectName:              leafName,
                              issuerName:               interName,
                              subjectPublicKey:         leafKeyPair.Public,
                              issuerPrivateKey:         interKeyPair.Private,
                              issuerKeyType:            caKeyType,
                              isCa:                     false,
                              notBefore:                start,
                              notAfter:                 end,
                              subjectAlternativeNames:  subjectAlternativeNames ?? [ subjectCommonName ],
                              ipAddresses:              ipAddresses,
                              issuerPublicKey:          interKeyPair.Public,
                              random:                   random
                          );

        var leaf = new TestCertificate(leafCert, leafKeyPair.Private, [ interCert ]);

        return (leaf, interCert, rootCert);

    }


    private static AsymmetricCipherKeyPair GenerateKeyPair(TestCertificateKeyType  keyType,
                                                           SecureRandom            random)
    {

        switch (keyType)
        {

            case TestCertificateKeyType.EcP256:
            {
                var gen = new ECKeyPairGenerator("ECDSA");
                gen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));
                return gen.GenerateKeyPair();
            }

            case TestCertificateKeyType.EcP384:
            {
                var gen = new ECKeyPairGenerator("ECDSA");
                gen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP384r1, random));
                return gen.GenerateKeyPair();
            }

            case TestCertificateKeyType.Rsa2048:
            {
                var gen = new RsaKeyPairGenerator();
                gen.Init(new KeyGenerationParameters(random, 2048));
                return gen.GenerateKeyPair();
            }

            case TestCertificateKeyType.Ed25519:
            {
                var gen = new Ed25519KeyPairGenerator();
                gen.Init(new Ed25519KeyGenerationParameters(random));
                return gen.GenerateKeyPair();
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(keyType), keyType, null);

        }

    }


    private static String SignatureAlgorithmFor(TestCertificateKeyType keyType)

        => keyType switch {
               TestCertificateKeyType.EcP256   => "SHA256WITHECDSA",
               TestCertificateKeyType.EcP384   => "SHA384WITHECDSA",
               TestCertificateKeyType.Rsa2048  => "SHA256WITHRSA",
               TestCertificateKeyType.Ed25519  => "Ed25519",
               _                               => throw new ArgumentOutOfRangeException(nameof(keyType), keyType, null)
           };


    private static X509Certificate BuildCertificate(X509Name                subjectName,
                                                    X509Name                issuerName,
                                                    AsymmetricKeyParameter  subjectPublicKey,
                                                    AsymmetricKeyParameter  issuerPrivateKey,
                                                    TestCertificateKeyType  issuerKeyType,
                                                    Boolean                 isCa,
                                                    DateTime                notBefore,
                                                    DateTime                notAfter,
                                                    IEnumerable<String>?    subjectAlternativeNames,
                                                    IEnumerable<String>?    ipAddresses,
                                                    AsymmetricKeyParameter  issuerPublicKey,
                                                    SecureRandom            random)
    {

        var builder = new X509V3CertificateGenerator();

        builder.SetSerialNumber(new BigInteger(128, random));
        builder.SetIssuerDN(issuerName);
        builder.SetSubjectDN(subjectName);
        builder.SetNotBefore(notBefore);
        builder.SetNotAfter (notAfter);
        builder.SetPublicKey(subjectPublicKey);

        builder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));

        builder.AddExtension(
            X509Extensions.KeyUsage,
            true,
            isCa
                ? new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign)
                : new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)
        );

        if (!isCa)
            builder.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth));

        builder.AddExtension(
            X509Extensions.SubjectKeyIdentifier,
            false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPublicKey)
            )
        );

        builder.AddExtension(
            X509Extensions.AuthorityKeyIdentifier,
            false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerPublicKey)
            )
        );

        var names = new List<GeneralName>();

        if (subjectAlternativeNames is not null)
        {
            foreach (var dnsName in subjectAlternativeNames)
                names.Add(new GeneralName(GeneralName.DnsName, dnsName));
        }

        if (ipAddresses is not null)
        {
            foreach (var ipAddress in ipAddresses)
                names.Add(new GeneralName(GeneralName.IPAddress, ipAddress));
        }

        if (names.Count > 0)
            builder.AddExtension(X509Extensions.SubjectAlternativeName, false,
                                 new GeneralNames(names.ToArray()));

        return builder.Generate(
                   new Asn1SignatureFactory(SignatureAlgorithmFor(issuerKeyType), issuerPrivateKey, random)
               );

    }


    /// <summary>
    /// The certificate as the BCL sees it, which is the form a TLS callback is handed.
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2 ToDotNet()

        => System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(
               Certificate.GetEncoded()
           );


    /// <summary>
    /// The certificate <em>and</em> its private key, in the form <c>SslStream</c> needs to act as
    /// a server.
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2 ToDotNetWithPrivateKey()
    {

        const String password = "nts-conformance";

        var store   = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder().Build();
        var entries = new List<Org.BouncyCastle.Pkcs.X509CertificateEntry> {
                          new (Certificate)
                      };

        if (IntermediateCertificates is not null)
        {
            foreach (var intermediate in IntermediateCertificates)
                entries.Add(new Org.BouncyCastle.Pkcs.X509CertificateEntry(intermediate));
        }

        store.SetKeyEntry(
            "nts-ke",
            new Org.BouncyCastle.Pkcs.AsymmetricKeyEntry(PrivateKey),
            [.. entries]
        );

        using var buffer = new MemoryStream();
        store.Save(buffer, password.ToCharArray(), new SecureRandom());

        // BouncyCastle emits indefinite-length BER, which .NET's PKCS#12 reader rejects.
        var pkcs12 = Org.BouncyCastle.Pkcs.Pkcs12Utilities.ConvertToDefiniteLength(
                         buffer.ToArray(),
                         password.ToCharArray()
                     );

        return System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(
                   pkcs12,
                   password,
                   System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
               );

    }


    /// <summary>
    /// The certificate (plus any intermediate certificates) as PEM, for tools that read a trust
    /// or fullchain file.
    /// </summary>
    public String ToPem()
    {

        var builder = new StringBuilder();

        AppendPem(builder, Certificate);

        if (IntermediateCertificates is not null)
        {
            foreach (var intermediate in IntermediateCertificates)
                AppendPem(builder, intermediate);
        }

        return builder.ToString();

    }


    private static void AppendPem(StringBuilder builder, X509Certificate cert)
    {

        builder.AppendLine("-----BEGIN CERTIFICATE-----");

        var base64 = Convert.ToBase64String(cert.GetEncoded());

        for (var offset = 0; offset < base64.Length; offset += 64)
            builder.AppendLine(base64.Substring(offset, Math.Min(64, base64.Length - offset)));

        builder.AppendLine("-----END CERTIFICATE-----");

    }


    /// <summary>
    /// Write the certificate to a PEM file and return its path.
    /// </summary>
    public String WritePem(String directory, String fileName = "nts-ke.pem")
    {

        Directory.CreateDirectory(directory);

        var path = Path.Combine(directory, fileName);

        File.WriteAllText(path, ToPem());

        return path;

    }

}
