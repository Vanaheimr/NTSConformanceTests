using System.Security.Cryptography;

using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Crypto.Tests;

/// <summary>
/// RFC 5297 conformance of Norn's <c>AES_SIV</c>, the sole AEAD implementation behind
/// every NTS authenticator and (once fixed) every cookie.
///
/// Where possible each property is checked twice: against the published RFC vectors, and
/// differentially against <see cref="RawAesSiv"/>, which reaches the same specification
/// through entirely separate code.
/// </summary>
[TestFixture]
public class AesSivConformanceTests
{

    #region RFC 5297 test vectors

    private static readonly Byte[] A1Key = Bytes.FromHex(
        "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff");

    private static readonly Byte[] A1AssociatedData = Bytes.FromHex(
        "10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");

    private static readonly Byte[] A1Plaintext = Bytes.FromHex("11223344 55667788 99aabbcc ddee");

    private const String A1Output = "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c";


    private static readonly Byte[] A2Key = Bytes.FromHex(
        "7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f");

    private static readonly Byte[] A2AssociatedData1 = Bytes.FromHex(
        "00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100");

    private static readonly Byte[] A2AssociatedData2 = Bytes.FromHex("10203040 50607080 90a0");

    private static readonly Byte[] A2Nonce = Bytes.FromHex("09f91102 9d74e35b d84156c5 635688c0");

    private static readonly Byte[] A2Plaintext = Bytes.FromHex(
        "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553");

    private const String A2Output =
        "7bdb6e3b432667eb06f4d14bff2fbd0f" +
        "cb900f2fddbe404326601965c889bf17" +
        "dba77ceb094fa663b7a3f748ba8af829" +
        "ea64ad544a272e9c485b62a3fd5c0d";


    /// <summary>
    /// RFC 5297 §A.1, deterministic mode. Norn's S2V omits an empty nonce from the input
    /// vector, so passing one is how the deterministic case is reached.
    /// </summary>
    [Test]
    public void Rfc5297_A1_Vector()
    {

        var output = new AES_SIV(A1Key).Encrypt([ A1AssociatedData ], [], A1Plaintext);

        Assert.That(Bytes.ToHex(output), Is.EqualTo(A1Output), Bytes.Diff(Bytes.FromHex(A1Output), output));

    }


    /// <summary>
    /// RFC 5297 §A.2, nonce-based mode with two associated-data components.
    /// </summary>
    [Test]
    public void Rfc5297_A2_Vector()
    {

        var output = new AES_SIV(A2Key).Encrypt([ A2AssociatedData1, A2AssociatedData2 ], A2Nonce, A2Plaintext);

        Assert.That(Bytes.ToHex(output), Is.EqualTo(A2Output), Bytes.Diff(Bytes.FromHex(A2Output), output));

    }


    /// <summary>
    /// RFC 4493 CMAC vectors, through Norn's BouncyCastle-backed helper.
    /// </summary>
    [TestCase( 0, "bb1d6929e95937287fa37d129b756746")]
    [TestCase(16, "070a16b46b4d4144f79bdd9dd04a287c")]
    [TestCase(40, "dfa66747de9ae63030ca32611497c827")]
    [TestCase(64, "51f0bebf7e3b9d92fc49741779363cfe")]
    public void Rfc4493_Cmac(Int32 messageLength, String expectedHex)
    {

        var key     = Bytes.FromHex("2b7e1516 28aed2a6 abf71588 09cf4f3c");
        var message = Bytes.FromHex(
            "6bc1bee2 2e409f96 e93d7e11 7393172a" +
            "ae2d8a57 1e03ac9c 9eb76fac 45af8e51" +
            "30c81c46 a35ce411 e5fbc119 1a0a52ef" +
            "f69f2445 df4f9b17 ad2b417b e66c3710");

        Assert.That(Bytes.ToHex(AES_SIV.CMAC(key, message[..messageLength])), Is.EqualTo(expectedHex));

    }

    #endregion

    #region Differential against the independent reference

    /// <summary>
    /// Norn and the reference must agree bit for bit across a spread of associated-data,
    /// nonce and plaintext lengths — including the block boundaries where padding and
    /// xorend behaviour diverge.
    /// </summary>
    [TestCase(  0,  0,   0)]
    [TestCase( 48, 16,   0)]
    [TestCase( 48, 16,   1)]
    [TestCase( 48, 16,  15)]
    [TestCase( 48, 16,  16)]
    [TestCase( 48, 16,  17)]
    [TestCase( 48, 16, 100)]
    [TestCase(  1, 16,  32)]
    [TestCase( 15, 16,  32)]
    [TestCase( 16, 16,  32)]
    [TestCase(  0, 16,  32)]
    [TestCase( 48,  0,  32)]
    public void MatchesIndependentReference(Int32 associatedDataLength, Int32 nonceLength, Int32 plaintextLength)
    {

        var key             = RandomNumberGenerator.GetBytes(32);
        var associatedData  = RandomNumberGenerator.GetBytes(associatedDataLength);
        var nonce           = RandomNumberGenerator.GetBytes(nonceLength);
        var plaintext       = RandomNumberGenerator.GetBytes(plaintextLength);

        // The reference takes a null nonce for "no nonce"; Norn uses a zero-length array.
        var referenceOutput = new RawAesSiv(key).Encrypt(
                                  associatedDataLength == 0 ? [] : [ associatedData ],
                                  nonceLength == 0 ? null : nonce,
                                  plaintext
                              );

        var nornOutput      = new AES_SIV(key).Encrypt(
                                  associatedDataLength == 0 ? [] : [ associatedData ],
                                  nonce,
                                  plaintext
                              );

        Assert.That(Bytes.ToHex(nornOutput),
                    Is.EqualTo(Bytes.ToHex(referenceOutput)),
                    Bytes.Diff(referenceOutput, nornOutput));

    }


    /// <summary>
    /// Each implementation must be able to decrypt what the other produced.
    /// </summary>
    [Test]
    public void CrossDecrypts_WithTheReference()
    {

        var key             = RandomNumberGenerator.GetBytes(32);
        var nonce           = RandomNumberGenerator.GetBytes(16);
        var associatedData  = RandomNumberGenerator.GetBytes(64);
        var plaintext       = RandomNumberGenerator.GetBytes(40);

        var fromReference   = new RawAesSiv(key).Encrypt([ associatedData ], nonce, plaintext);
        var fromNorn        = new AES_SIV(key).  Encrypt([ associatedData ], nonce, plaintext);

        var nornReadsReference = new AES_SIV(key).Decrypt([ associatedData ], nonce, fromReference);

        var referenceReadsNorn = new RawAesSiv(key).TryDecrypt([ associatedData ], nonce, fromNorn,
                                                              out var recovered, out var errorResponse);

        Assert.Multiple(() => {
            Assert.That(nornReadsReference, Is.EqualTo(plaintext).AsCollection, "Norn must decrypt the reference's output");
            Assert.That(referenceReadsNorn, Is.True, $"the reference must decrypt Norn's output: {errorResponse}");
            Assert.That(recovered,          Is.EqualTo(plaintext).AsCollection);
        });

    }

    #endregion

    #region Authentication must fail closed

    /// <summary>
    /// A tampered ciphertext must be rejected rather than decrypted.
    /// </summary>
    [Test]
    public void TamperedCiphertext_IsRejected()
    {

        var key        = RandomNumberGenerator.GetBytes(32);
        var nonce      = RandomNumberGenerator.GetBytes(16);
        var associated = RandomNumberGenerator.GetBytes(48);

        var output     = new AES_SIV(key).Encrypt([ associated ], nonce, RandomNumberGenerator.GetBytes(32));

        output[^1] ^= 0x01;

        Assert.That(() => new AES_SIV(key).Decrypt([ associated ], nonce, output),
                    Throws.Exception,
                    "a flipped ciphertext bit must fail the synthetic-IV check");

    }


    /// <summary>
    /// Tampering with the associated data must fail authentication too — NTS relies on
    /// this to bind the NTP header and the preceding extension fields.
    /// </summary>
    [Test]
    public void TamperedAssociatedData_IsRejected()
    {

        var key        = RandomNumberGenerator.GetBytes(32);
        var nonce      = RandomNumberGenerator.GetBytes(16);
        var associated = RandomNumberGenerator.GetBytes(48);

        var output     = new AES_SIV(key).Encrypt([ associated ], nonce, RandomNumberGenerator.GetBytes(32));

        associated[0] ^= 0x01;

        Assert.That(() => new AES_SIV(key).Decrypt([ associated ], nonce, output),
                    Throws.Exception,
                    "the NTP header travels as associated data and must be covered");

    }


    /// <summary>
    /// A wrong key must not authenticate.
    /// </summary>
    [Test]
    public void WrongKey_IsRejected()
    {

        var nonce      = RandomNumberGenerator.GetBytes(16);
        var associated = RandomNumberGenerator.GetBytes(48);

        var output     = new AES_SIV(RandomNumberGenerator.GetBytes(32)).
                             Encrypt([ associated ], nonce, RandomNumberGenerator.GetBytes(32));

        Assert.That(() => new AES_SIV(RandomNumberGenerator.GetBytes(32)).Decrypt([ associated ], nonce, output),
                    Throws.Exception);

    }


    /// <summary>
    /// an AEAD authentication failure should surface as a
    /// <see cref="CryptographicException"/>. Norn throws a bare
    /// <see cref="Exception"/>, so a caller cannot separate "this message was forged"
    /// from "the library has a bug" without matching on the message text, and
    /// <c>catch (CryptographicException)</c> silently misses forgeries.
    /// </summary>
    [Test]
    public void AuthenticationFailure_ThrowsCryptographicException()
    {

        var key        = RandomNumberGenerator.GetBytes(32);
        var nonce      = RandomNumberGenerator.GetBytes(16);
        var associated = RandomNumberGenerator.GetBytes(48);

        var output     = new AES_SIV(key).Encrypt([ associated ], nonce, RandomNumberGenerator.GetBytes(32));

        output[^1] ^= 0x01;

        Assert.That(() => new AES_SIV(key).Decrypt([ associated ], nonce, output),
                    Throws.InstanceOf<CryptographicException>(),
                    "an authentication failure is a cryptographic condition, not a generic one");

    }

    #endregion

    #region Known deviations

    /// <summary>
    /// RFC 5297 §2.1 defines pad(X) only for len(X) &lt; 128 bits. Norn's
    /// <c>Pad</c> allocates a fixed 16-octet buffer and then writes <c>0x80</c> at
    /// <c>Data.Length</c>, so a full block indexes one past the end.
    ///
    /// Not currently reachable through <c>Encrypt</c> — the internal call site is guarded
    /// by a length check — but it is public API and a latent trap for any future caller.
    /// A conformant implementation rejects the input; it must not throw
    /// <see cref="IndexOutOfRangeException"/>.
    /// </summary>
    [Test]
    public void Pad_FullBlock_MustNotThrowIndexOutOfRange()
    {

        Assert.That(() => AES_SIV.Pad(new Byte[16]),
                    Throws.InstanceOf<ArgumentException>(),
                    "pad() of a full 16-octet block is out of contract and should be reported as a bad argument, " +
                    "not crash with IndexOutOfRangeException");

    }


    /// <summary>
    /// encrypting an empty plaintext with no associated data.
    ///
    /// RFC 5297 §2.6 always appends the plaintext to the S2V input vector, so this case
    /// gives S2V the one-element vector ("") and takes the padded-last-block branch. It is
    /// <em>not</em> the empty vector, whose CMAC(K, &lt;one&gt;) shortcut §2.4 describes.
    /// Conflating the two yields a synthetic IV no conformant peer would compute.
    /// </summary>
    [Test]
    public void EmptyPlaintextWithNoAssociatedData_MatchesReference()
    {

        var key = Bytes.FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

        var nornOutput      = new AES_SIV(key).  Encrypt([], [], []);
        var referenceOutput = new RawAesSiv(key).Encrypt([], null, []);

        Assert.That(Bytes.ToHex(nornOutput),
                    Is.EqualTo(Bytes.ToHex(referenceOutput)),
                    "the S2V vector here is (\"\"), not the empty vector");

    }


    /// <summary>
    /// AES-SIV must not write key material to the debug log. Norn's
    /// <c>Encrypt</c> unconditionally logs both halves of the split key, the synthetic
    /// IV, every associated-data component, the nonce and the ciphertext, on the hot path
    /// of every NTS request and response.
    /// </summary>
    [Test]
    public void Encrypt_DoesNotLogKeyMaterial()
    {

        var key        = RandomNumberGenerator.GetBytes(32);
        var nonce      = RandomNumberGenerator.GetBytes(16);
        var associated = RandomNumberGenerator.GetBytes(48);
        var plaintext  = RandomNumberGenerator.GetBytes(32);

        using var sink = new DebugXSink();

        new AES_SIV(key).Encrypt([ associated ], nonce, plaintext);

        var leakedFirstHalf   = sink.ContainsHex(key[..16]);
        var leakedSecondHalf  = sink.ContainsHex(key[16..]);

        Assert.Multiple(() => {

            Assert.That(leakedFirstHalf,
                        Is.False,
                        $"the CMAC half of the key was written to the debug log: {String.Join(" / ", sink.EntriesContainingHex(key[..16]))}");

            Assert.That(leakedSecondHalf,
                        Is.False,
                        $"the CTR half of the key was written to the debug log: {String.Join(" / ", sink.EntriesContainingHex(key[16..]))}");

        });

    }

    #endregion

}
