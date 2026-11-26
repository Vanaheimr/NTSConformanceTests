using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NTSConformance.Core.RawNtp;

/// <summary>
/// AES-GCM-SIV (RFC 8452) — both AEAD_AES_128_GCM_SIV (IANA AEAD id 30, 16-octet key) and
/// AEAD_AES_256_GCM_SIV (IANA AEAD id 31, 32-octet key).
///
/// Built solely on the BCL's raw AES-ECB block primitive: RFC 8452 key derivation, POLYVAL in
/// GF(2^128), tag computation, and 32-bit little-endian CTR mode are implemented directly from
/// the specification. Norn's <c>AES_GCM_SIV</c> wraps BouncyCastle's <c>GcmSivBlockCipher</c>,
/// so the two share no code and differential testing between them is genuinely independent.
/// </summary>
public sealed class RawAesGcmSiv
{

    private const Int32 BlockSize = 16;
    private const Int32 NonceSize = 12;
    private const Int32 TagSize   = 16;

    private readonly Byte[] key;


    public RawAesGcmSiv(Byte[] key)
    {

        if (key.Length is not (16 or 32))
            throw new ArgumentException($"An AES-GCM-SIV key is 16 or 32 octets long, got {key.Length}.", nameof(key));

        this.key = (Byte[]) key.Clone();

    }


    #region Encrypt / Decrypt

    /// <summary>
    /// RFC 8452 §4: returns <c>ciphertext || tag</c> (tag is the final 16 octets).
    /// </summary>
    public Byte[] Encrypt(Byte[] associatedData, Byte[] nonce, Byte[] plaintext)
    {

        ValidateNonce(nonce);

        var (msgAuthKey, msgEncKey) = DeriveKeys(key, nonce);

        var tag        = ComputeTag(msgAuthKey, msgEncKey, nonce, associatedData, plaintext);
        var ciphertext = Ctr32(msgEncKey, tag, plaintext);

        return [ .. ciphertext, .. tag ];

    }


    /// <summary>
    /// RFC 8452 §5: returns false (and never a partially-decrypted plaintext) when the tag
    /// fails verification.
    /// </summary>
    public Boolean TryDecrypt(Byte[]       associatedData,
                              Byte[]       nonce,
                              Byte[]       ciphertextAndTag,
                              out Byte[]?  plaintext,
                              out String?  errorResponse)
    {

        plaintext     = null;
        errorResponse = null;

        if (nonce.Length != NonceSize)
        {
            errorResponse = $"An AES-GCM-SIV nonce is {NonceSize} octets long, got {nonce.Length}.";
            return false;
        }

        if (ciphertextAndTag.Length < TagSize)
        {
            errorResponse = $"An AES-GCM-SIV ciphertext carries a {TagSize}-octet tag, but only {ciphertextAndTag.Length} octets were given.";
            return false;
        }

        var ciphertext = ciphertextAndTag[..^TagSize];
        var tag        = ciphertextAndTag[^TagSize..];

        var (msgAuthKey, msgEncKey) = DeriveKeys(key, nonce);

        var candidate   = Ctr32(msgEncKey, tag, ciphertext);
        var expectedTag = ComputeTag(msgAuthKey, msgEncKey, nonce, associatedData, candidate);

        if (!CryptographicOperations.FixedTimeEquals(expectedTag, tag))
        {
            errorResponse = "AES-GCM-SIV authentication failed: the tag does not match.";
            return false;
        }

        plaintext = candidate;
        return true;

    }


    public Byte[] Decrypt(Byte[] associatedData, Byte[] nonce, Byte[] ciphertextAndTag)
    {

        if (!TryDecrypt(associatedData, nonce, ciphertextAndTag, out var plaintext, out var errorResponse))
            throw new CryptographicException(errorResponse);

        return plaintext!;

    }

    #endregion


    #region Key derivation (RFC 8452 §4)

    private static (Byte[] MsgAuthKey, Byte[] MsgEncKey) DeriveKeys(Byte[] keyGeneratingKey, Byte[] nonce)
    {

        var encHalfBlocks = keyGeneratingKey.Length == 16 ? 2 : 4;
        var totalBlocks   = 2 + encHalfBlocks;
        var derived       = new Byte[totalBlocks * 8];
        var block         = new Byte[BlockSize];

        Buffer.BlockCopy(nonce, 0, block, 4, NonceSize);

        for (UInt32 counter = 0; counter < totalBlocks; counter++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(0, 4), counter);
            var encrypted = RawAesSiv.AesEncryptBlock(keyGeneratingKey, block);
            Buffer.BlockCopy(encrypted, 0, derived, (Int32) counter * 8, 8);
        }

        return (derived[..16], derived[16..]);

    }

    #endregion


    #region POLYVAL & Tag (RFC 8452 §3, §4, Appendix A)

    private static Byte[] ComputeTag(Byte[] msgAuthKey,
                                     Byte[] msgEncKey,
                                     Byte[] nonce,
                                     Byte[] associatedData,
                                     Byte[] plaintext)
    {

        var s = Polyval(msgAuthKey, associatedData, plaintext);

        for (var i = 0; i < NonceSize; i++)
            s[i] ^= nonce[i];

        // Clear the most significant bit of the last octet (RFC 8452 §4).
        s[15] &= 0x7F;

        return RawAesSiv.AesEncryptBlock(msgEncKey, s);

    }


    /// <summary>
    /// POLYVAL over zero-padded AAD, zero-padded plaintext, and the 16-octet little-endian
    /// bit-length block, implemented via the RFC 8452 Appendix A GHASH equivalence:
    /// <c>POLYVAL(H, X_1, ..., X_n) = byteReverse(GHASH(mulX_GHASH(byteReverse(H)), byteReverse(X_1), ...))</c>.
    /// </summary>
    public static Byte[] Polyval(Byte[] h, Byte[] associatedData, Byte[] plaintext)
    {

        var hGhash = MulXGhash(ByteReverse(h));
        var state  = new Byte[BlockSize];

        FeedPadded(state, hGhash, associatedData);
        FeedPadded(state, hGhash, plaintext);

        var lengthBlock = new Byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.AsSpan(0, 8), (UInt64) associatedData.Length * 8UL);
        BinaryPrimitives.WriteUInt64LittleEndian(lengthBlock.AsSpan(8, 8), (UInt64) plaintext.Length * 8UL);

        state = PolyvalUpdate(state, hGhash, lengthBlock);

        return ByteReverse(state);

    }


    private static void FeedPadded(Byte[] state, Byte[] hGhash, Byte[] data)
    {

        var fullLength = data.Length - (data.Length % BlockSize);

        for (var offset = 0; offset < fullLength; offset += BlockSize)
        {
            var next = PolyvalUpdate(state, hGhash, data.AsSpan(offset, BlockSize));
            Buffer.BlockCopy(next, 0, state, 0, BlockSize);
        }

        var remainder = data.Length - fullLength;

        if (remainder > 0)
        {
            var last = new Byte[BlockSize];
            Buffer.BlockCopy(data, fullLength, last, 0, remainder);
            var next = PolyvalUpdate(state, hGhash, last);
            Buffer.BlockCopy(next, 0, state, 0, BlockSize);
        }

    }


    private static Byte[] PolyvalUpdate(Byte[] state, Byte[] hGhash, ReadOnlySpan<Byte> block)
    {

        var xored = new Byte[BlockSize];

        for (var i = 0; i < BlockSize; i++)
            xored[i] = (Byte) (state[i] ^ block[BlockSize - 1 - i]);

        return GhashMultiply(xored, hGhash);

    }


    private static Byte[] ByteReverse(ReadOnlySpan<Byte> input)
    {

        var output = new Byte[BlockSize];

        for (var i = 0; i < BlockSize; i++)
            output[i] = input[BlockSize - 1 - i];

        return output;

    }


    private static Byte[] MulXGhash(Byte[] v)
    {

        var result = new Byte[BlockSize];
        var lsb    = (v[BlockSize - 1] & 0x01) != 0;

        for (var i = BlockSize - 1; i > 0; i--)
            result[i] = (Byte) ((v[i] >> 1) | ((v[i - 1] & 0x01) << 7));

        result[0] = (Byte) (v[0] >> 1);

        if (lsb)
            result[0] ^= 0xE1;

        return result;

    }


    private static Byte[] GhashMultiply(Byte[] x, Byte[] y)
    {

        var z = new Byte[BlockSize];
        var v = (Byte[]) y.Clone();

        for (var bit = 0; bit < 128; bit++)
        {
            if ((x[bit >> 3] & (0x80 >> (bit & 7))) != 0)
            {
                for (var i = 0; i < BlockSize; i++)
                    z[i] ^= v[i];
            }

            v = MulXGhash(v);
        }

        return z;

    }

    #endregion


    #region CTR32 (RFC 8452 §4)

    /// <summary>
    /// AES counter mode using the tag with bit 127 set as initial counter block, incrementing
    /// only the first 32 bits as a little-endian unsigned integer.
    /// </summary>
    private static Byte[] Ctr32(Byte[] msgEncKey, Byte[] tag, Byte[] data)
    {

        var result  = new Byte[data.Length];
        var counter = (Byte[]) tag.Clone();
        counter[15] |= 0x80;

        for (var offset = 0; offset < data.Length; offset += BlockSize)
        {

            var keyStream = RawAesSiv.AesEncryptBlock(msgEncKey, counter);
            var chunk     = Math.Min(BlockSize, data.Length - offset);

            for (var i = 0; i < chunk; i++)
                result[offset + i] = (Byte) (data[offset + i] ^ keyStream[i]);

            var next = unchecked(BinaryPrimitives.ReadUInt32LittleEndian(counter.AsSpan(0, 4)) + 1U);
            BinaryPrimitives.WriteUInt32LittleEndian(counter.AsSpan(0, 4), next);

        }

        return result;

    }

    #endregion


    private static void ValidateNonce(Byte[] nonce)
    {
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"An AES-GCM-SIV nonce is {NonceSize} octets long, got {nonce.Length}.", nameof(nonce));
    }

}
