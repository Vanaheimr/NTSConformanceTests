using System.Security.Cryptography;

namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// HKDF (RFC 5869): HKDF-Extract (§2.2) and HKDF-Expand (§2.3), built here on nothing but
/// the BCL's HMAC.
///
/// Norn and Hermod both derive the keys of NTS-KE over SSH with the BCL's <c>HKDF</c> class,
/// so this deliberately does not use it: a reference that shares the function it is meant to
/// check can only confirm it. It is held to the published RFC 5869 vectors
/// (<c>RawHkdfReferenceTests</c>) before anything is concluded from it, as
/// <see cref="RawNtp.RawAesSiv"/> is held to RFC 5297 and RFC 4493.
/// </summary>
public static class RawHkdf
{

    /// <summary>
    /// HashLen of RFC 5869 §2.1: the output length of the hash function, in octets.
    /// </summary>
    public static Int32 HashLength(HashAlgorithmName hash)

        => hash.Name switch {
               "SHA256"  => 32,
               "SHA384"  => 48,
               "SHA512"  => 64,
               _         => throw new ArgumentException($"No HMAC for hash function '{hash.Name}' in this reference.", nameof(hash))
           };


    /// <summary>
    /// HMAC-Hash(key, data) — the one primitive both steps are built on.
    /// </summary>
    public static Byte[] Hmac(HashAlgorithmName  hash,
                              Byte[]             key,
                              Byte[]             data)

        => hash.Name switch {
               "SHA256"  => HMACSHA256.HashData(key, data),
               "SHA384"  => HMACSHA384.HashData(key, data),
               "SHA512"  => HMACSHA512.HashData(key, data),
               _         => throw new ArgumentException($"No HMAC for hash function '{hash.Name}' in this reference.", nameof(hash))
           };


    /// <summary>
    /// RFC 5869 §2.2: PRK = HMAC-Hash(salt, IKM). A salt that is not provided is a string of
    /// HashLen zeros.
    /// </summary>
    public static Byte[] Extract(HashAlgorithmName  hash,
                                 Byte[]             salt,
                                 Byte[]             ikm)

        => Hmac(hash,
                salt.Length == 0
                    ? new Byte[HashLength(hash)]
                    : salt,
                ikm);


    /// <summary>
    /// RFC 5869 §2.3: T(0) is empty, T(i) = HMAC-Hash(PRK, T(i-1) | info | i) with i as a
    /// single octet, and OKM is the first L octets of T(1) | T(2) | ...
    /// </summary>
    /// <exception cref="ArgumentException">PRK is shorter than HashLen, which §2.3 requires as its minimum.</exception>
    /// <exception cref="ArgumentOutOfRangeException">L is negative or above 255 * HashLen.</exception>
    public static Byte[] Expand(HashAlgorithmName  hash,
                                Byte[]             prk,
                                Byte[]             info,
                                Int32              length)
    {

        var hashLength = HashLength(hash);

        if (prk.Length < hashLength)
            throw new ArgumentException($"RFC 5869 §2.3 needs a PRK of at least HashLen ({hashLength}) octets, got {prk.Length}.", nameof(prk));

        if (length < 0 || length > 255 * hashLength)
            throw new ArgumentOutOfRangeException(nameof(length), length, $"RFC 5869 §2.3 limits L to 255 * HashLen ({255 * hashLength}) octets.");

        var okm     = new Byte[length];
        var block   = Array.Empty<Byte>();
        var offset  = 0;

        for (var counter = 1; offset < length; counter++)
        {

            block = Hmac(hash, prk, [ .. block, .. info, (Byte) counter ]);

            var take = Math.Min(block.Length, length - offset);
            Array.Copy(block, 0, okm, offset, take);
            offset += take;

        }

        return okm;

    }

}
