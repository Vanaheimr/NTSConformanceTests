using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.Crypto.Tests;

/// <summary>
/// Recomputes every test vector of Appendix A of the specification of the NTS-KE record
/// "SSH Key Binding", version 1.0 of 2026-11-10
/// (https://github.com/OpenChargingTechnology/Whitepapers/blob/master/NTS-over-SSH/nts-ke-ssh-key-binding.md,
/// as of commit a2e0f23), with this suite's own key derivation of Section 5.
///
/// Why this exists: the record is to be registered by IANA under Specification Required
/// (RFC 8126 §4.6), which asks for a specification detailed enough for independent
/// implementations to interoperate — and the vectors in it were produced by the only
/// implementation there is, Norn on Hermod. A vector computed by the code it is meant to check
/// proves only that the code agrees with itself. <see cref="RawSshKeyBinding"/> is written from
/// the text of Section 5 alone, on an HKDF built from HMAC rather than the BCL class Norn and
/// Hermod both use, so a vector that matches here is evidence that the text and the vector say
/// the same thing; one that does not is a defect in the specification, whichever side it is on.
///
/// Norn's own suite checks that Norn produces A.2 and A.3.2, and Hermod's that its exporter
/// produces A.3.1. Where this fixture is green, all three agree on these inputs.
/// </summary>
[TestFixture]
public class SshKeyBindingVectorTests
{

    private static readonly Byte[] A2Secret = Bytes.FromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private static readonly Byte[] A31Nonce = Bytes.FromHex(
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

    private static readonly Byte[] A32Nonce = Bytes.FromHex(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");


    #region A.1 — the HKDF info

    /// <summary>
    /// A.1: info for algorithm 15, C2S — the label and the RFC 8915 §5.1 context, each as an
    /// SSH string with its four-octet length in front. A derivation that drops the lengths, as
    /// the TLS exporter has none, would still produce plausible keys; only the octets show it.
    /// </summary>
    [Test]
    public void A1_Info()
    {

        var info = RawSshKeyBinding.Info(15, RawSshKeyBinding.C2S);

        Assert.That(Bytes.ToHex(info),
                    Is.EqualTo("0000001e" + "4558504f525445522d6e6574776f726b2d74696d652d7365637572697479" +
                               "00000005" + "0000000f00"),
                    $"info = string(label) || string(context){Environment.NewLine}{Bytes.Dump(info)}");

    }

    #endregion

    #region A.2 — method 0x0002, Transported Secret

    /// <summary>
    /// A.2: HKDF-Expand-SHA256 with nts_ke_secret itself as the PRK — no Extract step — for
    /// every algorithm Norn can negotiate, in both directions.
    /// </summary>
    [TestCase(15, 32, "8a9424e3fd81e14cbc9731adff3ae5b6d2fe66349b4ad384f59a1f5bd7d552ec",
                      "2abf8475eda5bb1798b5d3d0f2fc413d62461c0bce93707fed97366193422713", TestName = "A2_TransportedSecret_AesSivCmac256")]
    [TestCase(30, 16, "e7961cb8c44fcc3d44d091c8574ad0f2",
                      "964988be02f188bbc3c96bd86bba825d",                                 TestName = "A2_TransportedSecret_Aes128GcmSiv")]
    [TestCase(31, 32, "5f32ede85ca7a7607baa1c2bf14057c9afb7458114e476f6a187f2f96da0aa2e",
                      "0b6576d8ee6e31e992f4821dac89ec44d1e575a0f1b69a4f64225dc6051ec128", TestName = "A2_TransportedSecret_Aes256GcmSiv")]
    public void A2_TransportedSecret(Int32 aeadAlgorithm, Int32 length, String c2sHex, String s2cHex)
    {

        var c2s = RawSshKeyBinding.TransportedSecretKey(A2Secret, (UInt16) aeadAlgorithm, RawSshKeyBinding.C2S, length);
        var s2c = RawSshKeyBinding.TransportedSecretKey(A2Secret, (UInt16) aeadAlgorithm, RawSshKeyBinding.S2C, length);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(c2s), Is.EqualTo(c2sHex), $"C2S key, AEAD {aeadAlgorithm}, L = {length}");
            Assert.That(Bytes.ToHex(s2c), Is.EqualTo(s2cHex), $"S2C key, AEAD {aeadAlgorithm}, L = {length}");
        });

    }

    #endregion

    #region A.3.1 — method 0x0001, from the key exchange

    /// <summary>
    /// A.3.1: the name hashed into exporter_secret, as an SSH string.
    /// </summary>
    [Test]
    public void A31_ExporterName()
    {

        Assert.That(Bytes.ToHex(RawSshKeyBinding.SshString(Encoding.ASCII.GetBytes(RawSshKeyBinding.ExporterName))),
                    Is.EqualTo("00000020" + "7373682d6578706f72746572406f70656e2e6368617267696e672e636c6f7564"),
                    "string(\"ssh-exporter@open.charging.cloud\")");

    }


    /// <summary>
    /// The two K of A.3.1 that claim to come from RFC 7748 do: the shared secret of its §6.1
    /// and the output of its first §5.2 vector, each encoded here as an mpint the way
    /// curve25519-sha256 (RFC 8731) encodes K. The second starts with 0xc3, so its mpint needs
    /// the leading zero octet a careless encoder leaves out — which is the reason that vector
    /// is in the specification at all.
    /// </summary>
    [Test]
    public void A31_K_IsWhatRfc7748Publishes_AsAnMpint()
    {

        var rfc7748Section61SharedSecret = Bytes.FromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        var rfc7748Section52Output       = Bytes.FromHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        Assert.Multiple(() => {

            Assert.That(Bytes.ToHex(RawSshKeyBinding.SshMpint(rfc7748Section61SharedSecret)),
                        Is.EqualTo("00000020" + "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
                        "K of the first vector = mpint(RFC 7748 §6.1 shared secret)");

            Assert.That(Bytes.ToHex(RawSshKeyBinding.SshMpint(rfc7748Section52Output)),
                        Is.EqualTo("00000021" + "00" + "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
                        "K of the second vector = mpint(RFC 7748 §5.2 output), with its leading zero octet");

        });

    }


    /// <summary>
    /// A.3.1, first vector: curve25519-sha256, K as an mpint.
    /// </summary>
    [Test]
    public void A31_Curve25519_KAsMpint()

        => AssertExporterVector(
               HashAlgorithmName.SHA256,
               encodedK:        "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
               h:               "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
               exporterSecret:  "ab559ef9a78c59a68f7be3063df264e2a7ccbe83a49f76ed2aed1327cf89776e",
               prk:             "a2d98772f94b8fb96dd30707c7c9ad0d278d0ff90a411ad709ce7069b1e4781f",
               (15, 32, "ea9163026944be623b625a50b8f59aa1daf843949e0f98634f178af6e248330a",
                        "d9376278448d5de12b0d3ebc3c06bf26c0ccc0c85ac869b6a23d10213b7fc402"),
               (30, 16, "339eabe19ea8469bbf993ac405a89417",
                        "26823c8acd419d57fd901749dc6d5d76")
           );


    /// <summary>
    /// A.3.1, second vector: curve25519-sha256, K as an mpint with a leading zero octet.
    /// </summary>
    [Test]
    public void A31_Curve25519_KAsMpintWithLeadingZero()

        => AssertExporterVector(
               HashAlgorithmName.SHA256,
               encodedK:        "0000002100c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
               h:               "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
               exporterSecret:  "8cd543f0ab53001f308b027ad13bd42ff218559a5d26d025a410a806ef7b9c77",
               prk:             "24e54cd9033daa7bb1e5047b90a6a0f53f24e62ad9b9e743a3dfb17a159e4ffb",
               (15, 32, "6d38e2ff8aaaab4842eb4cb3d66712d93d8675efc0cea721f3828f8de3fce947",
                        "3a177a3612e473add6c214cbdf858b59e7012e0e68676f57692998fb5192a208")
           );


    /// <summary>
    /// A.3.1, third vector: mlkem768x25519-sha256, which encodes K as a string.
    /// </summary>
    [Test]
    public void A31_MlKem768X25519_KAsString()

        => AssertExporterVector(
               HashAlgorithmName.SHA256,
               encodedK:        "00000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
               h:               "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
               exporterSecret:  "2d7dce6143d5be80605b07662a01e4735b32202106be64c66f8392dc51d887f6",
               prk:             "d4a0a37898cd1bf17500c5c0a6c9285d66087742df355873f912dd058fc94027",
               (15, 32, "10f3f639e505ca255ac1a51d235bac0d0ba15b078774e0c13f7f97a15b93df05",
                        "8a1e71fceb65e99f0d171f6472e8c9bd7f92f20ad8a5085d3bf9b1d7fec9c28f")
           );


    /// <summary>
    /// A.3.1, last vector: sntrup761x25519-sha512, K as a string, and SHA-512 for the hash,
    /// HKDF-Extract and HKDF-Expand alike — the only vector where HKDF runs on another hash.
    /// </summary>
    [Test]
    public void A31_Sntrup761X25519_Sha512()

        => AssertExporterVector(
               HashAlgorithmName.SHA512,
               encodedK:        "00000040" +
                                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
               h:               "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
               exporterSecret:  "2d3d49427d4a01a90e66867b65064c5ae726c4ceb833aa06cf03a8a54e1f667c" +
                                "36289f14bfd84e15d4a6793e1bbc7532f3ab4bdc68bab34b0aa471a5068ff4dd",
               prk:             "ac0a32957f57e5f41866387c4d8313183a6d93b8995d2c84acfe5070af261894" +
                                "80d5dd64e36838e2ac5af9ea77c5c5d8a6d8c207f556880fe5e6e251dbc31615",
               (15, 32, "d8df38f63a6c606738f00b416ee530c2c5b8d54881a72a73e983eac1968bf5b5",
                        "b611446e12a524681f9fd023eee1a57468a624a3f73b0dd7c6a6d45dd2297414"),
               (30, 16, "891071d4dcddf3ec6a2074d58ebe5059",
                        "423acfe0d50b1c0e571835f70cb4fef0")
           );


    /// <summary>
    /// One vector of A.3.1, step by step: exporter_secret from K and H, with session_id = H
    /// as on the first key exchange of a connection, then PRK under the common nonce, then
    /// both keys of every algorithm the vector lists. Each step is asserted on its own, so a
    /// mismatch says at which step the text and the vector part.
    /// </summary>
    private static void AssertExporterVector(HashAlgorithmName                                         hash,
                                             String                                                    encodedK,
                                             String                                                    h,
                                             String                                                    exporterSecret,
                                             String                                                    prk,
                                             params (Int32 Aead, Int32 Length, String C2S, String S2C)[] keys)
    {

        var hBytes             = Bytes.FromHex(h);
        var computedSecret     = RawSshKeyBinding.ExporterSecret(hash, Bytes.FromHex(encodedK), hBytes, sessionId: hBytes);
        var computedPrk        = RawSshKeyBinding.ExporterPrk(hash, A31Nonce, computedSecret);

        Assert.Multiple(() => {

            Assert.That(Bytes.ToHex(computedSecret), Is.EqualTo(exporterSecret), $"exporter_secret, {hash.Name}");
            Assert.That(Bytes.ToHex(computedPrk),    Is.EqualTo(prk),            $"PRK, {hash.Name}");

            foreach (var (aead, length, c2s, s2c) in keys)
            {
                Assert.That(Bytes.ToHex(RawSshKeyBinding.ExporterKey(hash, computedPrk, (UInt16) aead, RawSshKeyBinding.C2S, length)),
                            Is.EqualTo(c2s),
                            $"C2S key, AEAD {aead}, L = {length}");
                Assert.That(Bytes.ToHex(RawSshKeyBinding.ExporterKey(hash, computedPrk, (UInt16) aead, RawSshKeyBinding.S2C, length)),
                            Is.EqualTo(s2c),
                            $"S2C key, AEAD {aead}, L = {length}");
            }

        });

    }

    #endregion

    #region A.3.2 — method 0x0001, from exporter_secret on

    /// <summary>
    /// A.3.2: PRK for an implementation handed exporter_secret directly. The exporter_secret
    /// is the nts_ke_secret of A.2, so the keys below differ from A.2's only by the Extract
    /// step under the nonce.
    /// </summary>
    [Test]
    public void A32_Prk()
    {

        Assert.That(Bytes.ToHex(RawSshKeyBinding.ExporterPrk(HashAlgorithmName.SHA256, A32Nonce, A2Secret)),
                    Is.EqualTo("a27b86e7a70a029cba778d6f738d952696d6d8361b95103dd84ae9df6af063af"),
                    "PRK = HKDF-Extract(salt = exporter_nonce, IKM = exporter_secret)");

    }


    /// <summary>
    /// A.3.2: both keys of every algorithm, from that PRK.
    /// </summary>
    [TestCase(15, 32, "dcf81015c16cb4b955624949e824e89f45cac437995a873e938ec3c7adc0218b",
                      "6b91d1a3ad1eb448fa5010e20dd79b280f7c303aec2252b464a4642fb70ea12d", TestName = "A32_SshExporter_AesSivCmac256")]
    [TestCase(30, 16, "fd8733d215d9d3a79f0d95b86884ed28",
                      "f7fe123370cdd2ed478906c34bd6d7b8",                                 TestName = "A32_SshExporter_Aes128GcmSiv")]
    [TestCase(31, 32, "05d23579f0905080af0243173053808adad6d276ed0560a9fe64ef714b690554",
                      "d72234762b25d744d00016818b8f23ad65d1ac5c85009d1ada6215046c73ebcc", TestName = "A32_SshExporter_Aes256GcmSiv")]
    public void A32_SshExporter(Int32 aeadAlgorithm, Int32 length, String c2sHex, String s2cHex)
    {

        var prk = RawSshKeyBinding.ExporterPrk(HashAlgorithmName.SHA256, A32Nonce, A2Secret);

        var c2s = RawSshKeyBinding.ExporterKey(HashAlgorithmName.SHA256, prk, (UInt16) aeadAlgorithm, RawSshKeyBinding.C2S, length);
        var s2c = RawSshKeyBinding.ExporterKey(HashAlgorithmName.SHA256, prk, (UInt16) aeadAlgorithm, RawSshKeyBinding.S2C, length);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(c2s), Is.EqualTo(c2sHex), $"C2S key, AEAD {aeadAlgorithm}, L = {length}");
            Assert.That(Bytes.ToHex(s2c), Is.EqualTo(s2cHex), $"S2C key, AEAD {aeadAlgorithm}, L = {length}");
        });

    }

    #endregion

}
