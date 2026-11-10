using System.Security.Cryptography;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtsKe;

namespace NTSConformance.Crypto.Tests;

/// <summary>
/// Validates the suite's own HKDF against the published RFC 5869 test vectors.
///
/// This fixture tests the harness, not Norn. <c>SshKeyBindingVectorTests</c> recomputes the
/// keys of NTS-KE over SSH on this HKDF, and a vector it confirms or refutes means something
/// only if the HKDF underneath is right — which is why it is built from HMAC here rather than
/// taken from the BCL class Norn and Hermod use.
/// </summary>
[TestFixture]
public class RawHkdfReferenceTests
{

    /// <summary>
    /// RFC 5869 A.1: the basic case — a short salt and info, an output longer than one
    /// block, so T(2) is cut off after 10 octets.
    /// </summary>
    [Test]
    public void Rfc5869_A1_Basic()
    {

        var prk = RawHkdf.Extract(HashAlgorithmName.SHA256,
                                  Bytes.FromHex("000102030405060708090a0b0c"),
                                  Bytes.FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));

        var okm = RawHkdf.Expand(HashAlgorithmName.SHA256,
                                 prk,
                                 Bytes.FromHex("f0f1f2f3f4f5f6f7f8f9"),
                                 42);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(prk), Is.EqualTo("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), "PRK");
            Assert.That(Bytes.ToHex(okm), Is.EqualTo("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), "OKM");
        });

    }


    /// <summary>
    /// RFC 5869 A.2: 80-octet salt, IKM and info, and an output of three blocks — the case
    /// where the counter octet and the chaining of T(i-1) into T(i) both show.
    /// </summary>
    [Test]
    public void Rfc5869_A2_LongInputsAndOutput()
    {

        var prk = RawHkdf.Extract(HashAlgorithmName.SHA256,
                                  Bytes.FromHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                                                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                                                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                                  Bytes.FromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                                                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                                                "404142434445464748494a4b4c4d4e4f"));

        var okm = RawHkdf.Expand(HashAlgorithmName.SHA256,
                                 prk,
                                 Bytes.FromHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                                               "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                                               "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                                 82);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(prk), Is.EqualTo("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"), "PRK");
            Assert.That(Bytes.ToHex(okm), Is.EqualTo("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                                                     "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                                                     "cc30c58179ec3e87c14c01d5c1f3434f1d87"), "OKM");
        });

    }


    /// <summary>
    /// RFC 5869 A.3: no salt and no info. A salt not provided is HashLen zero octets (§2.2),
    /// and an empty info still leaves the counter octet in every block.
    /// </summary>
    [Test]
    public void Rfc5869_A3_NoSaltNoInfo()
    {

        var prk = RawHkdf.Extract(HashAlgorithmName.SHA256,
                                  [],
                                  Bytes.FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));

        var okm = RawHkdf.Expand(HashAlgorithmName.SHA256,
                                 prk,
                                 [],
                                 42);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(prk), Is.EqualTo("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), "PRK");
            Assert.That(Bytes.ToHex(okm), Is.EqualTo("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"), "OKM");
        });

    }


    /// <summary>
    /// RFC 5869 §2.3 takes a PRK of at least HashLen octets and gives at most 255 blocks;
    /// beyond either the reference refuses rather than returning something.
    /// </summary>
    [Test]
    public void Rfc5869_Expand_RefusesWhatTheRfcExcludes()
    {

        Assert.Multiple(() => {

            Assert.That(() => RawHkdf.Expand(HashAlgorithmName.SHA256, new Byte[31], [], 32),
                        Throws.ArgumentException,
                        "a PRK of 31 octets under SHA-256");

            Assert.That(() => RawHkdf.Expand(HashAlgorithmName.SHA256, new Byte[32], [], 255 * 32 + 1),
                        Throws.InstanceOf<ArgumentOutOfRangeException>(),
                        "an L of 255 * HashLen + 1");

            Assert.That(RawHkdf.Expand(HashAlgorithmName.SHA256, new Byte[32], [], 255 * 32),
                        Has.Length.EqualTo(255 * 32),
                        "an L of exactly 255 * HashLen");

        });

    }

}
