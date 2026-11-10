using System.Security.Cryptography;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Crypto.Tests;

/// <summary>
/// The key derivation of NTS-KE over SSH as Norn and Hermod perform it, held against
/// <see cref="RawSshKeyBinding"/>: Section 5 of the specification of the NTS-KE record
/// "SSH Key Binding", version 1.0.
///
/// <see cref="SshKeyBindingVectorTests"/> shows that the reference and the vectors of Appendix A
/// say the same thing. This fixture shows that Norn and Hermod say it too — on the inputs of
/// Appendix A, and on random ones, which reach what the vectors leave out: K of other lengths,
/// an exporter_secret of SHA-512 length taken on from outside the connection, and secrets
/// nobody chose to look tidy in hex.
///
/// Each derivation is entered where Norn enters it over SSH: an <see cref="NTSKE_Exporter"/> of
/// the method the SSH Key Binding record selected, handed to <see cref="NTSKE_ExportedKeys.ExportAll(NTSKE_Exporter)"/>,
/// and the keys taken with RFC 8915 §5.1's context — which is what both NTSClient and NTSServer
/// do over SSH, where record 1024 has no meaning. The key lengths given to the reference are
/// those of the AEAD registry, not Norn's: 32 for 15 and 31, 16 for 30.
/// </summary>
[TestFixture]
public class SshKeyBindingConformanceTests
{

    private const Int32 RandomRounds = 16;

    private static readonly Byte[] A2Secret = Bytes.FromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private static readonly Byte[] A31Nonce = Bytes.FromHex(
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

    private static readonly Byte[] A32Nonce = Bytes.FromHex(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

    /// <summary>
    /// The AEAD algorithms Norn implements, with the key length the IANA registry gives each.
    /// </summary>
    private static readonly (UInt16 Id, Int32 KeyLength)[] AeadAlgorithms = [
        (15, 32),
        (30, 16),
        (31, 32)
    ];

    /// <summary>
    /// The four key exchanges of A.3.1: hash, K as the method encodes it, and H.
    /// </summary>
    private static readonly Object[] A31KeyExchanges = [
        new TestCaseData("SHA256",
                         "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").
            SetArgDisplayNames("A31_Curve25519_KAsMpint"),
        new TestCaseData("SHA256",
                         "0000002100c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                         "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf").
            SetArgDisplayNames("A31_Curve25519_KAsMpintWithLeadingZero"),
        new TestCaseData("SHA256",
                         "00000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                         "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f").
            SetArgDisplayNames("A31_MlKem768X25519_KAsString"),
        new TestCaseData("SHA512",
                         "00000040" +
                         "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                         "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
                         "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                         "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").
            SetArgDisplayNames("A31_Sntrup761X25519_Sha512")
    ];


    #region §5.1 — the context and the info

    /// <summary>
    /// §5.1: Norn's context, and the info Norn and Hermod each build from it, octet for octet
    /// the reference's — for every algorithm and both directions. Norn and Hermod build the info
    /// separately, Norn for method 0x0002 and Hermod for method 0x0001, so both are held to it.
    /// </summary>
    [Test]
    public void ContextAndInfo_AreTheReference()
    {

        Assert.Multiple(() => {

            foreach (var (aead, _) in AeadAlgorithms)
            {
                foreach (var direction in new[] { RawSshKeyBinding.C2S, RawSshKeyBinding.S2C })
                {

                    var where          = $"AEAD {aead}, {(direction == RawSshKeyBinding.C2S ? "C2S" : "S2C")}";
                    var referenceInfo  = RawSshKeyBinding.Info(aead, direction);
                    var nornContext    = NTSKE_ExportedKeys.Context((AEADAlgorithms) aead, ServerToClient: direction == RawSshKeyBinding.S2C);

                    Assert.That(Bytes.ToHex(nornContext),
                                Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.Context(aead, direction))),
                                $"Norn's context, {where}");

                    Assert.That(Bytes.ToHex(NTSKE_ExportedKeys.ExporterInfo(NTSKE_ExportedKeys.ExporterLabel, nornContext)),
                                Is.EqualTo(Bytes.ToHex(referenceInfo)),
                                $"Norn's info, {where}");

                    Assert.That(Bytes.ToHex(SshExporter.Info(NTSKE_ExportedKeys.ExporterLabel, nornContext)),
                                Is.EqualTo(Bytes.ToHex(referenceInfo)),
                                $"Hermod's info, {where}");

                }
            }

        });

    }

    #endregion

    #region §5.3 — method 0x0002, Transported Secret

    /// <summary>
    /// §5.3 on the secret of A.2: Norn's keys are the reference's, and so the vectors of A.2.
    /// </summary>
    [Test]
    public void TransportedSecret_OnTheSecretOfA2_IsTheReference()
        => AssertTransportedSecret(A2Secret);


    /// <summary>
    /// §5.3 on random secrets, as a server draws them for every exchange (§4.1, rule 5).
    /// </summary>
    [Test]
    public void TransportedSecret_OnRandomSecrets_IsTheReference()
    {
        for (var round = 0; round < RandomRounds; round++)
            AssertTransportedSecret(RandomNumberGenerator.GetBytes(RawSshKeyBinding.TransportedSecretLength));
    }


    private static void AssertTransportedSecret(Byte[] ntsKeSecret)
    {

        var nornKeys = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.TransportedSecretExporter(ntsKeSecret));

        Assert.Multiple(() => {
            foreach (var (aead, keyLength) in AeadAlgorithms)
            {

                var (c2s, s2c) = nornKeys.For((AEADAlgorithms) aead, CompliantExporterContext: true);
                var where      = $"AEAD {aead}, nts_ke_secret {Bytes.ToHex(ntsKeSecret)}";

                Assert.That(Bytes.ToHex(c2s),
                            Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.TransportedSecretKey(ntsKeSecret, aead, RawSshKeyBinding.C2S, keyLength))),
                            $"C2S key, {where}");

                Assert.That(Bytes.ToHex(s2c),
                            Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.TransportedSecretKey(ntsKeSecret, aead, RawSshKeyBinding.S2C, keyLength))),
                            $"S2C key, {where}");

            }
        });

    }

    #endregion

    #region §5.2 — method 0x0001, SSH Exporter

    /// <summary>
    /// §5.2 from the key exchanges of A.3.1: Hermod's exporter_secret is the reference's.
    /// </summary>
    [TestCaseSource(nameof(A31KeyExchanges))]
    public void HermodExporterSecret_OfTheKeyExchangesOfA31_IsTheReference(String hashName, String encodedK, String h)
    {

        var hash   = new HashAlgorithmName(hashName);
        var kBytes = Bytes.FromHex(encodedK);
        var hBytes = Bytes.FromHex(h);

        Assert.That(Bytes.ToHex(SshExporter.ComputeSecret(hash, kBytes, hBytes, hBytes)),
                    Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.ExporterSecret(hash, kBytes, hBytes, hBytes))),
                    $"exporter_secret, {hashName}");

    }


    /// <summary>
    /// §5.2 from the key exchanges of A.3.1 to the keys: a connection's exporter as Hermod
    /// creates it from K, H and the session id, with the nonce of A.3.1, handed to Norn as the
    /// client hands it over (<see cref="NTSKE_ExportedKeys.SSHExporter(SshExporter, Byte[])"/>).
    /// </summary>
    [TestCaseSource(nameof(A31KeyExchanges))]
    public void ExporterOfAConnection_OfTheKeyExchangesOfA31_IsTheReference(String hashName, String encodedK, String h)
    {

        var hash   = new HashAlgorithmName(hashName);
        var hBytes = Bytes.FromHex(h);

        AssertConnectionExporter(hash, Bytes.FromHex(encodedK), hBytes, hBytes, A31Nonce);

    }


    /// <summary>
    /// §5.2 on random key exchanges: K of the lengths the methods give it — 32 and 64 octets as
    /// a string, 33 as an mpint of 256 bits with its zero octet, 513 as one of 4096 — and
    /// session_id equal to H, as it is for the first key exchange, the only one §5.2 takes
    /// exporter_secret from.
    /// </summary>
    [TestCase("SHA256", 32)]
    [TestCase("SHA256", 33)]
    [TestCase("SHA512", 64)]
    [TestCase("SHA512", 513)]
    public void ExporterOfAConnection_OnRandomKeyExchanges_IsTheReference(String hashName, Int32 kLength)
    {

        var hash       = new HashAlgorithmName(hashName);
        var hashLength = hashName == "SHA512" ? 64 : 32;

        for (var round = 0; round < RandomRounds; round++)
        {

            // An odd length is an mpint whose top bit is set, so the encoding puts the zero octet
            // in front; an even one a string, as the hybrid methods send K.
            var encodedK = kLength % 2 == 1
                               ? RawSshKeyBinding.SshMpint([ (Byte) (0x80 | RandomNumberGenerator.GetBytes(1)[0]),
                                                             .. RandomNumberGenerator.GetBytes(kLength - 2) ])
                               : RawSshKeyBinding.SshString(RandomNumberGenerator.GetBytes(kLength));

            var h        = RandomNumberGenerator.GetBytes(hashLength);

            AssertConnectionExporter(hash,
                                     encodedK,
                                     h,
                                     sessionId: h,
                                     RandomNumberGenerator.GetBytes(RawSshKeyBinding.ExporterNonceLength));

        }

    }


    private static void AssertConnectionExporter(HashAlgorithmName  hash,
                                                 Byte[]             encodedK,
                                                 Byte[]             h,
                                                 Byte[]             sessionId,
                                                 Byte[]             exporterNonce)
    {

        var referencePrk  = RawSshKeyBinding.ExporterPrk(hash,
                                                         exporterNonce,
                                                         RawSshKeyBinding.ExporterSecret(hash, encodedK, h, sessionId));

        using var exporter = SshExporter.Create(hash, encodedK, h, sessionId);

        var nornKeys       = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(exporter, exporterNonce));

        AssertExporterKeys(hash, referencePrk, nornKeys,
                           $"{hash.Name}, K {Bytes.ToHex(encodedK)}, H {Bytes.ToHex(h)}, " +
                           $"session_id {Bytes.ToHex(sessionId)}, exporter_nonce {Bytes.ToHex(exporterNonce)}");

    }


    /// <summary>
    /// §5.2 from exporter_secret on, with the secret and nonce of A.3.2: Norn's exporter for a
    /// secret taken on from outside the connection is the reference's, and so A.3.2.
    /// </summary>
    [Test]
    public void ExporterFromItsSecret_OnTheInputsOfA32_IsTheReference()
        => AssertExporterFromItsSecret(HashAlgorithmName.SHA256, A2Secret, A32Nonce);


    /// <summary>
    /// §5.2 from exporter_secret on, with random secrets of both lengths a key exchange gives.
    /// </summary>
    [TestCase("SHA256", 32)]
    [TestCase("SHA512", 64)]
    public void ExporterFromItsSecret_OnRandomSecrets_IsTheReference(String hashName, Int32 secretLength)
    {
        for (var round = 0; round < RandomRounds; round++)
            AssertExporterFromItsSecret(new HashAlgorithmName(hashName),
                                        RandomNumberGenerator.GetBytes(secretLength),
                                        RandomNumberGenerator.GetBytes(RawSshKeyBinding.ExporterNonceLength));
    }


    private static void AssertExporterFromItsSecret(HashAlgorithmName  hash,
                                                    Byte[]             exporterSecret,
                                                    Byte[]             exporterNonce)
    {

        var referencePrk = RawSshKeyBinding.ExporterPrk(hash, exporterNonce, exporterSecret);
        var nornKeys     = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(exporterSecret, exporterNonce, hash));

        AssertExporterKeys(hash, referencePrk, nornKeys,
                           $"{hash.Name}, exporter_secret {Bytes.ToHex(exporterSecret)}, exporter_nonce {Bytes.ToHex(exporterNonce)}");

    }


    private static void AssertExporterKeys(HashAlgorithmName   hash,
                                           Byte[]              referencePrk,
                                           NTSKE_ExportedKeys  nornKeys,
                                           String              inputs)
    {

        Assert.Multiple(() => {
            foreach (var (aead, keyLength) in AeadAlgorithms)
            {

                var (c2s, s2c) = nornKeys.For((AEADAlgorithms) aead, CompliantExporterContext: true);

                Assert.That(Bytes.ToHex(c2s),
                            Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.ExporterKey(hash, referencePrk, aead, RawSshKeyBinding.C2S, keyLength))),
                            $"C2S key, AEAD {aead}, {inputs}");

                Assert.That(Bytes.ToHex(s2c),
                            Is.EqualTo(Bytes.ToHex(RawSshKeyBinding.ExporterKey(hash, referencePrk, aead, RawSshKeyBinding.S2C, keyLength))),
                            $"S2C key, AEAD {aead}, {inputs}");

            }
        });

    }

    #endregion

}
