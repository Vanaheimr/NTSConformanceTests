using System.Security.Cryptography;

namespace NTSConformance.Core.RawNtp;

/// <summary>
/// AES-SIV-CMAC-256 (RFC 5297), the AEAD algorithm NTS mandates (RFC 8915 §5.1,
/// IANA AEAD id 15).
///
/// Deliberately built on nothing but the BCL's raw AES block primitive: CMAC (RFC 4493),
/// CTR and S2V are implemented here from the specifications. Norn's <c>AES_SIV</c> instead
/// composes BouncyCastle's <c>CMac</c> and <c>SicBlockCipher</c>, so the two share no code
/// and a differential test between them is genuinely informative.
/// </summary>
public sealed class RawAesSiv
{

    private const Int32 BlockSize = 16;

    private static readonly Byte[] Zero = new Byte[BlockSize];

    private readonly Byte[] macKey;
    private readonly Byte[] ctrKey;


    /// <summary>
    /// RFC 5297 §2.2: the key is split in half — the leftmost half keys S2V/CMAC,
    /// the rightmost half keys CTR. A 32-octet key therefore means AES-128 twice,
    /// which is what "AES-SIV-CMAC-256" denotes.
    /// </summary>
    public RawAesSiv(Byte[] key)
    {

        if (key.Length is not (32 or 48 or 64))
            throw new ArgumentException($"An AES-SIV key is 32, 48 or 64 octets long, got {key.Length}.", nameof(key));

        macKey = key[..(key.Length / 2)];
        ctrKey = key[(key.Length / 2)..];

    }


    #region Encrypt / Decrypt

    /// <summary>
    /// RFC 5297 §2.6 SIV-ENCRYPT. Returns the 16-octet synthetic IV followed by the
    /// ciphertext.
    ///
    /// Per RFC 5297 §3, a nonce is simply the last associated-data component, which is how
    /// RFC 8915 §5.6 uses it for the NTS Authenticator extension field.
    /// </summary>
    public Byte[] Encrypt(IEnumerable<Byte[]> associatedData, Byte[]? nonce, Byte[] plaintext)
    {

        var components = BuildComponents(associatedData, nonce, plaintext);

        var syntheticIV  = S2V(components);
        var counterBlock = MaskForCounter(syntheticIV);
        var ciphertext   = Ctr(ctrKey, counterBlock, plaintext);

        return [ .. syntheticIV, .. ciphertext ];

    }


    /// <summary>
    /// RFC 5297 §2.7 SIV-DECRYPT. Returns false — never a partially-decrypted plaintext —
    /// when the synthetic IV does not verify.
    /// </summary>
    public Boolean TryDecrypt(IEnumerable<Byte[]>  associatedData,
                              Byte[]?              nonce,
                              Byte[]               sivAndCiphertext,
                              out Byte[]?          plaintext,
                              out String?          errorResponse)
    {

        plaintext      = null;
        errorResponse  = null;

        if (sivAndCiphertext.Length < BlockSize)
        {
            errorResponse = $"An AES-SIV ciphertext carries a {BlockSize}-octet synthetic IV, but only {sivAndCiphertext.Length} octets were given.";
            return false;
        }

        var syntheticIV   = sivAndCiphertext[..BlockSize];
        var ciphertext    = sivAndCiphertext[BlockSize..];

        var counterBlock  = MaskForCounter(syntheticIV);
        var candidate     = Ctr(ctrKey, counterBlock, ciphertext);

        var components    = BuildComponents(associatedData, nonce, candidate);
        var expectedIV    = S2V(components);

        if (!CryptographicOperations.FixedTimeEquals(expectedIV, syntheticIV))
        {
            errorResponse = "AES-SIV authentication failed: the synthetic IV does not match.";
            return false;
        }

        plaintext = candidate;
        return true;

    }


    /// <summary>
    /// Decrypt, throwing on authentication failure.
    /// </summary>
    public Byte[] Decrypt(IEnumerable<Byte[]> associatedData, Byte[]? nonce, Byte[] sivAndCiphertext)
    {

        if (!TryDecrypt(associatedData, nonce, sivAndCiphertext, out var plaintext, out var errorResponse))
            throw new CryptographicException(errorResponse);

        return plaintext!;

    }


    private static List<Byte[]> BuildComponents(IEnumerable<Byte[]> associatedData, Byte[]? nonce, Byte[] plaintext)
    {

        var components = new List<Byte[]>(associatedData);

        if (nonce is not null)
            components.Add(nonce);

        components.Add(plaintext);

        return components;

    }


    /// <summary>
    /// RFC 5297 §2.6: clear the 31st and 63rd bits counting from the right of the
    /// synthetic IV before using it as a CTR counter block, so the counter cannot
    /// carry past a 32-bit boundary on some implementations.
    /// </summary>
    private static Byte[] MaskForCounter(Byte[] syntheticIV)
    {

        var counterBlock = (Byte[]) syntheticIV.Clone();

        counterBlock[ 8] &= 0x7F;
        counterBlock[12] &= 0x7F;

        return counterBlock;

    }

    #endregion

    #region S2V (RFC 5297 §2.4)

    /// <summary>
    /// The S2V construction that turns a vector of strings into a single 16-octet value.
    /// </summary>
    public Byte[] S2V(IReadOnlyList<Byte[]> components)
    {

        if (components.Count == 0)
        {
            // S2V of the empty vector is CMAC over <one>.
            var one = new Byte[BlockSize];
            one[BlockSize - 1] = 0x01;
            return Cmac(macKey, one);
        }

        var d = Cmac(macKey, Zero);

        for (var i = 0; i < components.Count - 1; i++)
            d = Xor(Dbl(d), Cmac(macKey, components[i]));

        var last = components[^1];

        Byte[] t;

        if (last.Length >= BlockSize)
        {
            // T = last with D xored onto its final block ("xorend").
            t = (Byte[]) last.Clone();

            for (var i = 0; i < BlockSize; i++)
                t[t.Length - BlockSize + i] ^= d[i];
        }
        else
            t = Xor(Dbl(d), Pad(last));

        return Cmac(macKey, t);

    }


    /// <summary>
    /// RFC 5297 §2.3 dbl(): a left shift by one bit in GF(2^128), reducing with the
    /// polynomial 0x87 when the top bit was set.
    /// </summary>
    public static Byte[] Dbl(Byte[] block)
    {

        if (block.Length != BlockSize)
            throw new ArgumentException($"dbl() operates on {BlockSize}-octet blocks, got {block.Length}.", nameof(block));

        var carry   = (block[0] & 0x80) != 0;
        var doubled = new Byte[BlockSize];

        for (var i = 0; i < BlockSize; i++)
        {
            doubled[i] = (Byte) (block[i] << 1);

            if (i + 1 < BlockSize && (block[i + 1] & 0x80) != 0)
                doubled[i] |= 0x01;
        }

        if (carry)
            doubled[BlockSize - 1] ^= 0x87;

        return doubled;

    }


    /// <summary>
    /// RFC 5297 §2.1 pad(): append a 0x80 octet then zeros out to a full block.
    ///
    /// Note that a full 16-octet input has nothing to pad and is a caller error here —
    /// Norn's equivalent writes past the end of its buffer in that case instead.
    /// </summary>
    public static Byte[] Pad(Byte[] data)
    {

        if (data.Length >= BlockSize)
            throw new ArgumentException($"pad() takes fewer than {BlockSize} octets; a full block needs no padding. Got {data.Length}.", nameof(data));

        var padded = new Byte[BlockSize];

        Buffer.BlockCopy(data, 0, padded, 0, data.Length);
        padded[data.Length] = 0x80;

        return padded;

    }


    public static Byte[] Xor(Byte[] a, Byte[] b)
    {

        var length = Math.Min(a.Length, b.Length);
        var result = new Byte[length];

        for (var i = 0; i < length; i++)
            result[i] = (Byte) (a[i] ^ b[i]);

        return result;

    }

    #endregion

    #region CMAC (RFC 4493)

    /// <summary>
    /// AES-CMAC over an arbitrary-length message, per RFC 4493 §2.4.
    /// </summary>
    public static Byte[] Cmac(Byte[] key, Byte[] message)
    {

        // Subkey generation, RFC 4493 §2.3.
        var l  = AesEncryptBlock(key, Zero);
        var k1 = Dbl(l);
        var k2 = Dbl(k1);

        var blockCount = message.Length == 0
                             ? 1
                             : (message.Length + BlockSize - 1) / BlockSize;

        var lastBlockIsComplete = message.Length > 0 && message.Length % BlockSize == 0;

        var lastBlock = lastBlockIsComplete
                            ? Xor(message[((blockCount - 1) * BlockSize)..], k1)
                            : Xor(Pad(message[((blockCount - 1) * BlockSize)..]), k2);

        var x = new Byte[BlockSize];

        for (var i = 0; i < blockCount - 1; i++)
            x = AesEncryptBlock(key, Xor(x, message[(i * BlockSize)..((i + 1) * BlockSize)]));

        return AesEncryptBlock(key, Xor(x, lastBlock));

    }

    #endregion

    #region CTR

    /// <summary>
    /// AES in counter mode, incrementing the whole 128-bit counter block as a
    /// big-endian integer, as RFC 5297 §2.6 requires.
    /// </summary>
    public static Byte[] Ctr(Byte[] key, Byte[] counterBlock, Byte[] data)
    {

        var result   = new Byte[data.Length];
        var counter  = (Byte[]) counterBlock.Clone();

        for (var offset = 0; offset < data.Length; offset += BlockSize)
        {

            var keyStream = AesEncryptBlock(key, counter);
            var chunk     = Math.Min(BlockSize, data.Length - offset);

            for (var i = 0; i < chunk; i++)
                result[offset + i] = (Byte) (data[offset + i] ^ keyStream[i]);

            IncrementCounter(counter);

        }

        return result;

    }


    private static void IncrementCounter(Byte[] counter)
    {
        for (var i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }

    #endregion

    #region Raw AES block

    /// <summary>
    /// A single raw AES block encryption — the only primitive borrowed from elsewhere.
    /// </summary>
    public static Byte[] AesEncryptBlock(Byte[] key, Byte[] block)
    {

        if (block.Length != BlockSize)
            throw new ArgumentException($"AES operates on {BlockSize}-octet blocks, got {block.Length}.", nameof(block));

        using var aes = Aes.Create();

        aes.Key      = key;
        aes.Mode     = CipherMode.ECB;
        aes.Padding  = PaddingMode.None;

        return aes.EncryptEcb(block, PaddingMode.None);

    }

    #endregion

}
