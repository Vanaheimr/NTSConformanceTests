using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Crypto.Tests;

/// <summary>
/// Validates the suite's own AES-SIV-CMAC-256 implementation against the published
/// RFC 4493 and RFC 5297 test vectors.
///
/// This fixture tests the harness, not Norn. It must pass before any differential result
/// against Norn's <c>AES_SIV</c> means anything: if the reference is wrong, every
/// comparison downstream is noise.
/// </summary>
[TestFixture]
public class RawAesSivReferenceTests
{

    #region RFC 4493 — AES-CMAC

    private static readonly Byte[] Rfc4493Key = Bytes.FromHex("2b7e1516 28aed2a6 abf71588 09cf4f3c");

    private static readonly Byte[] Rfc4493Message64 = Bytes.FromHex(
        "6bc1bee2 2e409f96 e93d7e11 7393172a" +
        "ae2d8a57 1e03ac9c 9eb76fac 45af8e51" +
        "30c81c46 a35ce411 e5fbc119 1a0a52ef" +
        "f69f2445 df4f9b17 ad2b417b e66c3710");


    /// <summary>RFC 4493 §4: AES-128(K, 0^128) and the two derived subkeys.</summary>
    [Test]
    public void Rfc4493_SubkeyGeneration()
    {

        var l  = RawAesSiv.AesEncryptBlock(Rfc4493Key, new Byte[16]);
        var k1 = RawAesSiv.Dbl(l);
        var k2 = RawAesSiv.Dbl(k1);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(l),  Is.EqualTo("7df76b0c1ab899b33e42f047b91b546f"), "AES-128(K, 0^128)");
            Assert.That(Bytes.ToHex(k1), Is.EqualTo("fbeed618357133667c85e08f7236a8de"), "subkey K1");
            Assert.That(Bytes.ToHex(k2), Is.EqualTo("f7ddac306ae266ccf90bc11ee46d513b"), "subkey K2");
        });

    }


    /// <summary>RFC 4493 §4, examples 1 to 4: CMAC over 0, 16, 40 and 64 octets.</summary>
    [TestCase( 0, "bb1d6929e95937287fa37d129b756746", TestName = "Rfc4493_Cmac_Example1_EmptyMessage")]
    [TestCase(16, "070a16b46b4d4144f79bdd9dd04a287c", TestName = "Rfc4493_Cmac_Example2_OneBlock")]
    [TestCase(40, "dfa66747de9ae63030ca32611497c827", TestName = "Rfc4493_Cmac_Example3_PartialBlock")]
    [TestCase(64, "51f0bebf7e3b9d92fc49741779363cfe", TestName = "Rfc4493_Cmac_Example4_FourBlocks")]
    public void Rfc4493_Cmac(Int32 messageLength, String expectedHex)
    {

        var mac = RawAesSiv.Cmac(Rfc4493Key, Rfc4493Message64[..messageLength]);

        Assert.That(Bytes.ToHex(mac),
                    Is.EqualTo(expectedHex),
                    $"CMAC over the first {messageLength} octets of the RFC 4493 message");

    }

    #endregion

    #region RFC 5297 §A.1 — deterministic authenticated encryption

    private static readonly Byte[] A1Key = Bytes.FromHex(
        "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff");

    private static readonly Byte[] A1AssociatedData = Bytes.FromHex(
        "10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");

    private static readonly Byte[] A1Plaintext = Bytes.FromHex(
        "11223344 55667788 99aabbcc ddee");

    private const String A1SyntheticIV = "85632d07c6e8f37f950acd320a2ecc93";
    private const String A1Output      = "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c";


    /// <summary>
    /// The A.1 vector has no nonce — SIV in its deterministic mode, where the S2V input
    /// vector is just the associated data followed by the plaintext.
    /// </summary>
    [Test]
    public void Rfc5297_A1_Encrypt()
    {

        var output = new RawAesSiv(A1Key).Encrypt([ A1AssociatedData ], nonce: null, A1Plaintext);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(output[..16]), Is.EqualTo(A1SyntheticIV), "the synthetic IV");
            Assert.That(Bytes.ToHex(output),       Is.EqualTo(A1Output),      "SIV || ciphertext");
        });

    }


    /// <summary>The S2V intermediates printed in A.1, checked one step at a time.</summary>
    [Test]
    public void Rfc5297_A1_S2V_Intermediates()
    {

        var macKey = A1Key[..16];

        var cmacZero = RawAesSiv.Cmac(macKey, new Byte[16]);
        var doubled  = RawAesSiv.Dbl(cmacZero);
        var cmacAd   = RawAesSiv.Cmac(macKey, A1AssociatedData);
        var xored    = RawAesSiv.Xor(doubled, cmacAd);
        var doubled2 = RawAesSiv.Dbl(xored);
        var padded   = RawAesSiv.Pad(A1Plaintext);
        var xored2   = RawAesSiv.Xor(doubled2, padded);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(cmacZero), Is.EqualTo("0e04dfafc1efbf040140582859bf073a"), "CMAC(<zero>)");
            Assert.That(Bytes.ToHex(doubled),  Is.EqualTo("1c09bf5f83df7e080280b050b37e0e74"), "double()");
            Assert.That(Bytes.ToHex(cmacAd),   Is.EqualTo("f1f922b7f5193ce64ff80cb47d93f23b"), "CMAC(ad)");
            Assert.That(Bytes.ToHex(xored),    Is.EqualTo("edf09de876c642ee4d78bce4ceedfc4f"), "xor");
            Assert.That(Bytes.ToHex(doubled2), Is.EqualTo("dbe13bd0ed8c85dc9af179c99ddbf819"), "double()");
            Assert.That(Bytes.ToHex(padded),   Is.EqualTo("112233445566778899aabbccddee8000"), "pad(plaintext)");
            Assert.That(Bytes.ToHex(xored2),   Is.EqualTo("cac30894b8eaf254035bc20540357819"), "xor");
        });

    }

    #endregion

    #region RFC 5297 §A.2 — nonce-based authenticated encryption

    private static readonly Byte[] A2Key = Bytes.FromHex(
        "7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f");

    private static readonly Byte[] A2AssociatedData1 = Bytes.FromHex(
        "00112233 44556677 8899aabb ccddeeff" +
        "deaddada deaddada ffeeddcc bbaa9988" +
        "77665544 33221100");

    private static readonly Byte[] A2AssociatedData2 = Bytes.FromHex("10203040 50607080 90a0");

    private static readonly Byte[] A2Nonce = Bytes.FromHex("09f91102 9d74e35b d84156c5 635688c0");

    private static readonly Byte[] A2Plaintext = Bytes.FromHex(
        "74686973 20697320 736f6d65 20706c61" +
        "696e7465 78742074 6f20656e 63727970" +
        "74207573 696e6720 5349562d 414553");

    private const String A2SyntheticIV = "7bdb6e3b432667eb06f4d14bff2fbd0f";

    private const String A2Output =
        "7bdb6e3b432667eb06f4d14bff2fbd0f" +
        "cb900f2fddbe404326601965c889bf17" +
        "dba77ceb094fa663b7a3f748ba8af829" +
        "ea64ad544a272e9c485b62a3fd5c0d";


    /// <summary>
    /// A.2 exercises the case NTS actually uses: several associated-data components with
    /// the nonce as the last one before the plaintext (RFC 5297 §3).
    /// </summary>
    [Test]
    public void Rfc5297_A2_Encrypt()
    {

        var output = new RawAesSiv(A2Key).Encrypt([ A2AssociatedData1, A2AssociatedData2 ], A2Nonce, A2Plaintext);

        Assert.Multiple(() => {
            Assert.That(Bytes.ToHex(output[..16]), Is.EqualTo(A2SyntheticIV), "the synthetic IV");
            Assert.That(Bytes.ToHex(output),       Is.EqualTo(A2Output),      "SIV || ciphertext");
        });

    }


    /// <summary>Decrypting the A.2 output must recover the plaintext exactly.</summary>
    [Test]
    public void Rfc5297_A2_Decrypt()
    {

        var succeeded = new RawAesSiv(A2Key).TryDecrypt(
                            [ A2AssociatedData1, A2AssociatedData2 ],
                            A2Nonce,
                            Bytes.FromHex(A2Output),
                            out var plaintext,
                            out var errorResponse
                        );

        Assert.That(succeeded, Is.True, $"decryption should succeed: {errorResponse}");
        Assert.That(Bytes.ToHex(plaintext!), Is.EqualTo(Bytes.ToHex(A2Plaintext)));

    }


    /// <summary>
    /// Flipping any single bit of the associated data must make authentication fail —
    /// SIV binds the associated data, which is the whole reason NTS uses it.
    /// </summary>
    [Test]
    public void Rfc5297_A2_TamperedAssociatedData_FailsAuthentication()
    {

        var tampered = (Byte[]) A2AssociatedData1.Clone();
        tampered[0] ^= 0x01;

        var succeeded = new RawAesSiv(A2Key).TryDecrypt(
                            [ tampered, A2AssociatedData2 ],
                            A2Nonce,
                            Bytes.FromHex(A2Output),
                            out var plaintext,
                            out var errorResponse
                        );

        Assert.Multiple(() => {
            Assert.That(succeeded,     Is.False, "a single flipped bit in the associated data must not authenticate");
            Assert.That(plaintext,     Is.Null,  "no plaintext may be released when authentication fails");
            Assert.That(errorResponse, Is.Not.Null);
        });

    }

    #endregion

    #region Structural properties

    /// <summary>
    /// RFC 5297 §2.1 defines pad(X) only for len(X) &lt; 128 bits, so a full block is
    /// out of contract and must be rejected rather than silently mishandled.
    /// </summary>
    [Test]
    public void Pad_RejectsFullAndOverlongBlocks()
    {

        Assert.Multiple(() => {

            Assert.That(Bytes.ToHex(RawAesSiv.Pad([])),
                        Is.EqualTo("80000000000000000000000000000000"),
                        "pad of the empty string is 0x80 followed by zeros");

            Assert.That(Bytes.ToHex(RawAesSiv.Pad(new Byte[15])),
                        Is.EqualTo("00000000000000000000000000000080"),
                        "pad of 15 zero octets sets the final octet");

            Assert.Throws<ArgumentException>(() => RawAesSiv.Pad(new Byte[16]),
                                             "a full 16-octet block needs no padding and is out of contract");

            Assert.Throws<ArgumentException>(() => RawAesSiv.Pad(new Byte[17]),
                                             "an overlong block is out of contract");

        });

    }


    /// <summary>Round-trip over a range of plaintext lengths, including the block boundaries.</summary>
    [TestCase(0)]
    [TestCase(1)]
    [TestCase(15)]
    [TestCase(16)]
    [TestCase(17)]
    [TestCase(31)]
    [TestCase(32)]
    [TestCase(33)]
    [TestCase(1024)]
    public void EncryptDecrypt_RoundTrip(Int32 plaintextLength)
    {

        var key        = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var nonce      = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var associated = System.Security.Cryptography.RandomNumberGenerator.GetBytes(48);
        var plaintext  = System.Security.Cryptography.RandomNumberGenerator.GetBytes(plaintextLength);

        var siv        = new RawAesSiv(key);
        var output     = siv.Encrypt([ associated ], nonce, plaintext);

        Assert.That(output.Length, Is.EqualTo(16 + plaintextLength), "SIV output is 16 octets longer than the plaintext");

        var succeeded  = siv.TryDecrypt([ associated ], nonce, output, out var recovered, out var errorResponse);

        Assert.That(succeeded, Is.True, $"round-trip should succeed: {errorResponse}");
        Assert.That(recovered, Is.EqualTo(plaintext).AsCollection);

    }


    /// <summary>
    /// S2V is not associative over its input vector: passing two components is not the
    /// same as passing their concatenation. RFC 8915 §5.6 depends on this — it specifies
    /// the associated data as one contiguous string, so an implementation that split it
    /// would not interoperate.
    /// </summary>
    [Test]
    public void S2V_IsSensitiveToComponentBoundaries()
    {

        var key       = Bytes.FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        var partA     = Bytes.FromHex("aabbccdd");
        var partB     = Bytes.FromHex("eeff0011");
        var plaintext = Bytes.FromHex("0102030405060708");

        var siv       = new RawAesSiv(key);

        var separate    = siv.Encrypt([ partA, partB ],              nonce: null, plaintext);
        var concatenated = siv.Encrypt([ Bytes.Concat(partA, partB) ], nonce: null, plaintext);

        Assert.That(Bytes.ToHex(separate),
                    Is.Not.EqualTo(Bytes.ToHex(concatenated)),
                    "if these matched, the associated-data framing would not be authenticated");

    }

    #endregion

}
