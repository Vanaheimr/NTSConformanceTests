using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// TLS 1.3 server credentials in <c>NTSKE_TLSService</c> / <c>NTSServer</c>:
/// intermediate certificate chains (RFC 8446 § 4.4.2) and server signing keys beyond ECDSA P-256
/// — ECDSA P-384, RSA (RSASSA-PSS), and Ed25519 (RFC 8446 § 4.2.3).
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsKeTlsCredentialsTests
{

    /// <summary>
    /// ECDSA P-256, ECDSA P-384, and RSA-2048 must complete TLS 1.3 + ALPN <c>ntske/1</c> against
    /// both Norn's BouncyCastle <c>NTSClient</c> and .NET's independent <c>SslStream</c>
    /// (<see cref="RawNtsKeClient"/>), and finish a full authenticated NTP/NTS exchange.
    /// </summary>
    [TestCase(TestCertificateKeyType.EcP256)]
    [TestCase(TestCertificateKeyType.EcP384)]
    [TestCase(TestCertificateKeyType.Rsa2048)]
    public async Task ServerKeyType_CompletesTls13WithBothBouncyCastleAndSslStream(TestCertificateKeyType KeyType)
    {

        var cert = TestCertificate.Generate(
                       subjectCommonName:       "localhost",
                       subjectAlternativeNames: [ "localhost" ],
                       keyType:                 KeyType
                   );

        await using var fixture = await NornServerFixture.StartAsync(certificate: cert);

        // 1. Independent .NET SslStream (SChannel on Windows, OpenSSL on Linux)
        var raw = await RawNtsKeClient.ExchangeAsync(
                      "127.0.0.1",
                      fixture.NTSKEPort,
                      RawNtsKeCodec.ClientRequest(15),
                      TimeSpan.FromSeconds(10)
                  );

        Assert.That(raw.HandshakeSucceeded, Is.True, $"SslStream handshake failed for {KeyType}: {raw}");
        Assert.That(raw.NegotiatedAlpn,     Is.EqualTo("ntske/1"));
        Assert.That(raw.ErrorCode,          Is.Null, raw.ToString());
        Assert.That(raw.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).Any(), Is.True, raw.ToString());

        // 2. Norn's BouncyCastle NTSClient + authenticated UDP NTP query
        var client = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var keResult = await client.GetNTSKERecords();
        Assert.That(keResult.Success, Is.True, $"NTSClient NTS-KE failed for {KeyType}: {keResult.ErrorMessage}");

        var queryResult = await client.QueryTime(
                              NTSKEResponse: keResult.Response!,
                              Timeout:       TimeSpan.FromSeconds(10)
                          );
        Assert.That(queryResult.Success, Is.True, $"NTSClient QueryTime failed for {KeyType}: {queryResult.ErrorMessage}");

    }


    /// <summary>
    /// Ed25519 (RFC 8446 § 4.2.3 <c>ed25519</c>) must complete TLS 1.3 + ALPN <c>ntske/1</c> and
    /// full authenticated NTP/NTS against Norn's BouncyCastle <c>NTSClient</c>.
    /// </summary>
    [Test]
    public async Task ServerKeyType_Ed25519_CompletesTls13AndNtsRoundTrip()
    {

        var cert = TestCertificate.Generate(
                       subjectCommonName:       "localhost",
                       subjectAlternativeNames: [ "localhost" ],
                       keyType:                 TestCertificateKeyType.Ed25519
                   );

        await using var fixture = await NornServerFixture.StartAsync(certificate: cert);

        var client   = fixture.CreateClient(TimeSpan.FromSeconds(10));
        var keResult = await client.GetNTSKERecords();

        Assert.That(keResult.Success, Is.True, $"Ed25519 NTS-KE failed: {keResult.ErrorMessage}");

        var queryResult = await client.QueryTime(
                              NTSKEResponse: keResult.Response!,
                              Timeout:       TimeSpan.FromSeconds(10)
                          );

        Assert.That(queryResult.Success, Is.True, $"Ed25519 QueryTime failed: {queryResult.ErrorMessage}");

    }


    /// <summary>
    /// A server configured with a leaf certificate plus an intermediate CA certificate must send
    /// the intermediate in the TLS 1.3 <c>Certificate</c> message so a client trusting <em>only</em>
    /// the root CA can build and verify the complete chain.
    /// </summary>
    [TestCase(TestCertificateKeyType.EcP256)]
    [TestCase(TestCertificateKeyType.EcP384)]
    [TestCase(TestCertificateKeyType.Rsa2048)]
    [TestCase(TestCertificateKeyType.Ed25519)]
    public async Task IntermediateCertificateChain_IsPresentedAndValidatesAgainstRootOnly(TestCertificateKeyType LeafKeyType)
    {

        var (leaf, intermediate, root) = TestCertificate.GenerateChain(
                                             subjectCommonName:       "localhost",
                                             subjectAlternativeNames: [ "localhost" ],
                                             leafKeyType:             LeafKeyType
                                         );

        await using var fixture = await NornServerFixture.StartAsync(certificate: leaf);

        using var rootDotNet = X509CertificateLoader.LoadCertificate(root.GetEncoded());
        var leafThumbprint   = leaf.ToDotNet().Thumbprint;
        var interThumbprint  = X509CertificateLoader.LoadCertificate(intermediate.GetEncoded()).Thumbprint;

        var chainValidatedAgainstRootOnly = false;
        IReadOnlyList<X509Certificate2>? presentedChain = null;

        var client = new NTSClient(
                         DomainName.Localhost,
                         NTSKE_Port:                 fixture.NTSKEPort,
                         NTP_Port:                   fixture.NTPPort,
                         IPVersionPreference:        IPVersionPreference.IPv4Only,
                         Timeout:                    TimeSpan.FromSeconds(10),
                         RemoteCertificateValidator: (_, leafCert, _, tlsClient, policyErrors) => {

                             presentedChain = tlsClient.TLSInfo?.CertificateChain;

                             // Name must match cleanly.
                             if ((policyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                                 return TLSValidationResult.Failed($"Unexpected name mismatch: {policyErrors}");

                             // Verify chain using ONLY the root in CustomTrustStore + intermediates sent by the server.
                             using var customChain = new X509Chain();
                             customChain.ChainPolicy.TrustMode      = X509ChainTrustMode.CustomRootTrust;
                             customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                             customChain.ChainPolicy.CustomTrustStore.Add(rootDotNet);

                             if (presentedChain is not null)
                             {
                                 foreach (var extra in presentedChain.Skip(1))
                                     customChain.ChainPolicy.ExtraStore.Add(extra);
                             }

                             if (leafCert is null)
                                 return TLSValidationResult.Failed("No leaf certificate presented.");

                             chainValidatedAgainstRootOnly = customChain.Build(leafCert);

                             return chainValidatedAgainstRootOnly
                                        ? TLSValidationResult.Success()
                                        : TLSValidationResult.Failed(
                                              $"Chain did not validate against root: " +
                                              String.Join(", ", customChain.ChainStatus.Select(s => s.StatusInformation))
                                          );

                         }
                     );

        var keResult = await client.GetNTSKERecords();

        Assert.Multiple(() => {

            Assert.That(keResult.Success, Is.True, $"Chained NTS-KE failed for {LeafKeyType}: {keResult.ErrorMessage}");
            Assert.That(chainValidatedAgainstRootOnly, Is.True, "chain must validate against Root CA alone via server-sent intermediate");
            Assert.That(presentedChain, Is.Not.Null);
            Assert.That(presentedChain!.Count, Is.EqualTo(2), "server must send [leaf, intermediate]");
            Assert.That(presentedChain[0].Thumbprint, Is.EqualTo(leafThumbprint),  "first entry must be the leaf certificate");
            Assert.That(presentedChain[1].Thumbprint, Is.EqualTo(interThumbprint), "second entry must be the intermediate CA");

        });

        var queryResult = await client.QueryTime(
                              NTSKEResponse: keResult.Response!,
                              Timeout:       TimeSpan.FromSeconds(10)
                          );

        Assert.That(queryResult.Success, Is.True, $"Chained QueryTime failed for {LeafKeyType}: {queryResult.ErrorMessage}");

    }


    /// <summary>
    /// Passing a fullchain list that repeats the leaf certificate before the intermediate must
    /// deduplicate the leaf rather than sending it twice on the wire.
    /// </summary>
    [Test]
    public async Task DuplicateLeafInCertificateChain_IsDeduplicated()
    {

        var (leaf, intermediate, _) = TestCertificate.GenerateChain(
                                          subjectCommonName:       "localhost",
                                          subjectAlternativeNames: [ "localhost" ]
                                      );

        var withDuplicateLeaf = leaf with {
                                    IntermediateCertificates = [ leaf.Certificate, intermediate ]
                                };

        await using var fixture = await NornServerFixture.StartAsync(certificate: withDuplicateLeaf);

        var client   = fixture.CreateClient(TimeSpan.FromSeconds(10));
        var keResult = await client.GetNTSKERecords();

        Assert.That(keResult.Success, Is.True, keResult.ErrorMessage);
        Assert.That(keResult.TLSInfo?.CertificateChain.Count,
                    Is.EqualTo(2),
                    "leaf certificate must not be duplicated in the TLS Certificate message");

    }


    /// <summary>
    /// Invalid or unsupported TLS server keys must fail fast in the <c>NTSServer</c> constructor
    /// rather than failing silently during a live TLS handshake.
    /// </summary>
    [Test]
    public void UnsupportedCurveOrPublicKey_FailsFastInServerConstructor()
    {

        var cert = TestCertificate.Generate("localhost", [ "localhost" ]);

        // 1. Passing a public key instead of a private key must be rejected.
        Assert.That(
            () => new NTSServer(
                      MasterKeysFilePath: null,
                      TLSCertificate:     cert.Certificate,
                      TLSPrivateKey:      cert.Certificate.GetPublicKey()
                  ),
            Throws.TypeOf<ArgumentException>()
        );

        // 2. Passing an unsupported ECDSA curve (secp256k1) must be rejected.
        var secp256k1Gen = new ECKeyPairGenerator("ECDSA");
        secp256k1Gen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256k1, new SecureRandom()));
        var secp256k1Key = secp256k1Gen.GenerateKeyPair().Private;

        Assert.That(
            () => new NTSServer(
                      MasterKeysFilePath: null,
                      TLSCertificate:     cert.Certificate,
                      TLSPrivateKey:      secp256k1Key
                  ),
            Throws.TypeOf<NotSupportedException>()
        );

        // 3. Passing a certificate chain without a leaf cert + private key must be rejected.
        Assert.That(
            () => new NTSServer(
                      MasterKeysFilePath:  null,
                      TLSCertificateChain: [ cert.Certificate ]
                  ),
            Throws.TypeOf<ArgumentException>()
        );

    }

}
