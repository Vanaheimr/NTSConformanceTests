using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// The key derivation of NTS-KE over SSH: Section 5 of the specification of the NTS-KE record
/// "SSH Key Binding" (OpenChargingTechnology/Whitepapers, NTS-over-SSH/nts-ke-ssh-key-binding.md),
/// written from that text and from nothing of Norn's or Hermod's.
///
/// An SSH connection has no TLS exporter, so where RFC 8915 §5.1 calls the TLS exporter with a
/// label, a context and a length, NTS-KE over SSH calls the exporter of the method the SSH Key
/// Binding record selected. Both methods are HKDF-Expand under a pseudorandom key of their own
/// for every exchange, built here on <see cref="RawHkdf"/>:
///
///   method 0x0002, Transported Secret:  PRK = nts_ke_secret, and HKDF with SHA-256 always;
///   method 0x0001, SSH Exporter:        exporter_secret = HASH(K || H || string("ssh-exporter@open.charging.cloud") || session_id),
///                                       PRK = HKDF-Extract(salt = exporter_nonce, IKM = exporter_secret),
///                                       with HASH and HKDF over the hash of the SSH key exchange method.
/// </summary>
public static class RawSshKeyBinding
{

    /// <summary>
    /// The label of RFC 8915 §5.1, unchanged over SSH (Section 5.1).
    /// </summary>
    public const String ExporterLabel            = "EXPORTER-network-time-security";

    /// <summary>
    /// The name hashed into exporter_secret (Section 5.2), in the way RFC 4253 §7.2 hashes a
    /// letter into each of its keys.
    /// </summary>
    public const String ExporterName             = "ssh-exporter@open.charging.cloud";

    /// <summary>
    /// nts_ke_secret, the Method Data of a response selecting method 0x0002 (Section 3.2).
    /// </summary>
    public const Int32  TransportedSecretLength  = 32;

    /// <summary>
    /// exporter_nonce, the Method Data of a response selecting method 0x0001 (Section 3.2).
    /// </summary>
    public const Int32  ExporterNonceLength      = 32;

    /// <summary>
    /// The last octet of the RFC 8915 §5.1 context: the client-to-server key.
    /// </summary>
    public const Byte   C2S                      = 0x00;

    /// <summary>
    /// The last octet of the RFC 8915 §5.1 context: the server-to-client key.
    /// </summary>
    public const Byte   S2C                      = 0x01;


    #region SSH encodings — RFC 4251 §5

    /// <summary>
    /// string: a uint32 length, most significant octet first, followed by the octets.
    /// </summary>
    public static Byte[] SshString(ReadOnlySpan<Byte> data)
    {

        var result = new Byte[4 + data.Length];

        BinaryPrimitives.WriteUInt32BigEndian(result, (UInt32) data.Length);
        data.CopyTo(result.AsSpan(4));

        return result;

    }


    /// <summary>
    /// mpint of a non-negative integer given as unsigned big-endian octets: leading zero
    /// octets dropped, one zero octet put back in front where the most significant bit is
    /// set — otherwise the value would read as negative — and the whole as a string. Zero
    /// is the empty string.
    /// </summary>
    public static Byte[] SshMpint(ReadOnlySpan<Byte> unsignedBigEndian)
    {

        var value = unsignedBigEndian.TrimStart((Byte) 0x00);

        return value.Length > 0 && (value[0] & 0x80) != 0
                   ? SshString([ 0x00, .. value ])
                   : SshString(value);

    }

    #endregion

    #region Section 5.1 — common to all methods

    /// <summary>
    /// The five octets of RFC 8915 §5.1: 0x0000 for NTPv4, the Numeric Identifier of the
    /// negotiated AEAD algorithm, and 0x00 for the C2S key or 0x01 for the S2C key.
    /// </summary>
    public static Byte[] Context(UInt16  aeadAlgorithm,
                                 Byte    direction)
    {

        var context = new Byte[5];

        BinaryPrimitives.WriteUInt16BigEndian(context.AsSpan(0), 0x0000);
        BinaryPrimitives.WriteUInt16BigEndian(context.AsSpan(2), aeadAlgorithm);
        context[4] = direction;

        return context;

    }


    /// <summary>
    /// info = string(label) || string(context), each with its length in front, as SSH
    /// encodes a string (Section 5.1).
    /// </summary>
    public static Byte[] Info(UInt16  aeadAlgorithm,
                              Byte    direction)

        => [ .. SshString(Encoding.ASCII.GetBytes(ExporterLabel)),
             .. SshString(Context(aeadAlgorithm, direction)) ];

    #endregion

    #region Section 5.3 — method 0x0002, Transported Secret

    /// <summary>
    /// Exporter(label, context, L) = HKDF-Expand-SHA256(PRK = nts_ke_secret, info, L), with
    /// SHA-256 whatever the hash function of the SSH key exchange is.
    /// </summary>
    /// <exception cref="ArgumentException">nts_ke_secret is not 32 octets long.</exception>
    public static Byte[] TransportedSecretKey(Byte[]  ntsKeSecret,
                                              UInt16  aeadAlgorithm,
                                              Byte    direction,
                                              Int32   length)
    {

        if (ntsKeSecret.Length != TransportedSecretLength)
            throw new ArgumentException($"nts_ke_secret is {TransportedSecretLength} octets long (Section 3.2), got {ntsKeSecret.Length}.", nameof(ntsKeSecret));

        return RawHkdf.Expand(HashAlgorithmName.SHA256,
                              ntsKeSecret,
                              Info(aeadAlgorithm, direction),
                              length);

    }

    #endregion

    #region Section 5.2 — method 0x0001, SSH Exporter

    /// <summary>
    /// exporter_secret = HASH(K || H || string("ssh-exporter@open.charging.cloud") || session_id),
    /// with K already encoded as the key exchange method encodes it for its own key derivation
    /// (mpint for most methods, string for some), and H and session_id as plain octets, as in
    /// the key derivation of RFC 4253 §7.2.
    /// </summary>
    public static Byte[] ExporterSecret(HashAlgorithmName  hash,
                                        Byte[]             encodedK,
                                        Byte[]             h,
                                        Byte[]             sessionId)
    {

        Byte[] input = [ .. encodedK,
                         .. h,
                         .. SshString(Encoding.ASCII.GetBytes(ExporterName)),
                         .. sessionId ];

        return hash.Name switch {
                   "SHA256"  => SHA256.HashData(input),
                   "SHA384"  => SHA384.HashData(input),
                   "SHA512"  => SHA512.HashData(input),
                   _         => throw new ArgumentException($"No hash function '{hash.Name}' in this reference.", nameof(hash))
               };

    }


    /// <summary>
    /// PRK = HKDF-Extract(salt = exporter_nonce, IKM = exporter_secret): the nonce of the
    /// exchange is what keeps the keys of two exchanges on one connection apart.
    /// </summary>
    /// <exception cref="ArgumentException">exporter_nonce is not 32 octets long.</exception>
    public static Byte[] ExporterPrk(HashAlgorithmName  hash,
                                     Byte[]             exporterNonce,
                                     Byte[]             exporterSecret)
    {

        if (exporterNonce.Length != ExporterNonceLength)
            throw new ArgumentException($"exporter_nonce is {ExporterNonceLength} octets long (Section 3.2), got {exporterNonce.Length}.", nameof(exporterNonce));

        return RawHkdf.Extract(hash, exporterNonce, exporterSecret);

    }


    /// <summary>
    /// Exporter(label, context, L) = HKDF-Expand(PRK, info, L), with HMAC over the hash
    /// function of the SSH key exchange method.
    /// </summary>
    public static Byte[] ExporterKey(HashAlgorithmName  hash,
                                     Byte[]             prk,
                                     UInt16             aeadAlgorithm,
                                     Byte               direction,
                                     Int32              length)

        => RawHkdf.Expand(hash,
                          prk,
                          Info(aeadAlgorithm, direction),
                          length);

    #endregion

}
