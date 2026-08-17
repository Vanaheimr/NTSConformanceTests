using System.Security.Cryptography;

namespace NTSConformance.Core.RawNtp;

/// <summary>
/// The four NTS extension fields of RFC 8915 §5.3-§5.6, built and verified
/// independently of Norn.
/// </summary>
public static class RawNtsExtensionFields
{

    /// <summary>
    /// RFC 8915 §5.3 recommends 32 octets of Unique Identifier.
    /// </summary>
    public const Int32 DefaultUniqueIdentifierLength = 32;

    /// <summary>
    /// RFC 8915 §5.6 nonces are 16 octets for AES-SIV-CMAC-256.
    /// </summary>
    public const Int32 DefaultNonceLength = 16;


    #region Unique Identifier (§5.3)

    public static RawExtensionField UniqueIdentifier(Byte[] value)
        => new (RawExtensionFieldTypes.UniqueIdentifier, value);

    public static RawExtensionField RandomUniqueIdentifier(Int32 length = DefaultUniqueIdentifierLength)
        => new (RawExtensionFieldTypes.UniqueIdentifier, RandomNumberGenerator.GetBytes(length));

    #endregion

    #region NTS Cookie (§5.4) and Cookie Placeholder (§5.5)

    public static RawExtensionField NtsCookie(Byte[] cookie)
        => new (RawExtensionFieldTypes.NTSCookie, cookie);

    /// <summary>
    /// RFC 8915 §5.5: the placeholder's body length must equal the cookie length the
    /// client expects back, so the request and response are the same size. A placeholder
    /// whose length differs is not "valid" and does not oblige the server to add a cookie.
    /// </summary>
    public static RawExtensionField NtsCookiePlaceholder(Int32 cookieLength)
        => new (RawExtensionFieldTypes.NTSCookiePlaceholder, new Byte[cookieLength]);

    #endregion

    #region NTS Authenticator and Encrypted Extension Fields (§5.6)

    /// <summary>
    /// Assemble the authenticator field's value:
    /// <code>
    /// Nonce Length (2) | Ciphertext Length (2) | Nonce (padded to 4) | Ciphertext (padded to 4)
    /// </code>
    /// </summary>
    public static Byte[] BuildAuthenticatorValue(Byte[] nonce, Byte[] ciphertext)
    {

        var paddedNonceLength       = (nonce.Length      + 3) & ~3;
        var paddedCiphertextLength  = (ciphertext.Length + 3) & ~3;

        var value = new Byte[4 + paddedNonceLength + paddedCiphertextLength];

        value[0] = (Byte) (nonce.Length      >> 8);
        value[1] = (Byte)  nonce.Length;
        value[2] = (Byte) (ciphertext.Length >> 8);
        value[3] = (Byte)  ciphertext.Length;

        Buffer.BlockCopy(nonce,      0, value, 4,                     nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, value, 4 + paddedNonceLength, ciphertext.Length);

        return value;

    }


    /// <summary>
    /// Split an authenticator field's value back into nonce and ciphertext.
    /// </summary>
    public static Boolean TryParseAuthenticatorValue(Byte[]       value,
                                                     out Byte[]?  nonce,
                                                     out Byte[]?  ciphertext,
                                                     out String?  errorResponse)
    {

        nonce          = null;
        ciphertext     = null;
        errorResponse  = null;

        if (value.Length < 4)
        {
            errorResponse = $"An NTS Authenticator field's value needs at least 4 octets of length prefix, got {value.Length}.";
            return false;
        }

        var nonceLength       = (value[0] << 8) | value[1];
        var ciphertextLength  = (value[2] << 8) | value[3];

        var paddedNonce       = (nonceLength      + 3) & ~3;
        var paddedCiphertext  = (ciphertextLength + 3) & ~3;

        if (value.Length < 4 + paddedNonce + paddedCiphertext)
        {
            errorResponse = $"An NTS Authenticator field declaring a {nonceLength}-octet nonce and a " +
                            $"{ciphertextLength}-octet ciphertext needs {4 + paddedNonce + paddedCiphertext} octets of value, got {value.Length}.";
            return false;
        }

        nonce       = value[4..(4 + nonceLength)];
        ciphertext  = value[(4 + paddedNonce)..(4 + paddedNonce + ciphertextLength)];

        return true;

    }


    /// <summary>
    /// The associated data an NTS authenticator covers: RFC 8915 §5.6 defines it as the
    /// packet from the start of the header up to, but not including, the authenticator
    /// field. A single contiguous string — not a vector — which matters because
    /// S2V(K, A, B, P) and S2V(K, A‖B, P) differ.
    /// </summary>
    public static Byte[] AssociatedDataFor(RawNtpPacket packet)
    {

        using var stream = new MemoryStream();

        stream.Write(RawNtpWriter.WriteHeaderOnly(packet));

        foreach (var field in packet.ExtensionFields)
        {

            if (field.FieldType == RawExtensionFieldTypes.NTSAuthenticatorAndEncrypted)
                break;

            stream.Write(EncodeField(field));

        }

        return stream.ToArray();

    }


    /// <summary>
    /// Encode a single extension field exactly as the writer would.
    /// </summary>
    public static Byte[] EncodeField(RawExtensionField field)
    {

        using var stream = new MemoryStream();

        RawNtpWriter.WriteUInt16(stream, field.FieldType);
        RawNtpWriter.WriteUInt16(stream, field.LengthOverride ?? field.ConformantLength);

        stream.Write(field.Value);

        if (!field.SuppressPadding)
        {
            for (var i = 0; i < field.PaddedValueLength - field.Value.Length; i++)
                stream.WriteByte(0x00);
        }

        return stream.ToArray();

    }


    /// <summary>
    /// Append an authenticator field to <paramref name="packet"/>, encrypting
    /// <paramref name="plaintextFields"/> (the extension fields that travel encrypted)
    /// under <paramref name="key"/>.
    /// </summary>
    public static RawExtensionField AppendAuthenticator(RawNtpPacket                     packet,
                                                        Byte[]                           key,
                                                        IEnumerable<RawExtensionField>?  plaintextFields = null,
                                                        Byte[]?                          nonce           = null)
    {

        var effectiveNonce  = nonce ?? RandomNumberGenerator.GetBytes(DefaultNonceLength);
        var associatedData  = AssociatedDataFor(packet);

        var plaintext       = plaintextFields is null
                                  ? []
                                  : Bytes.Concat([ .. plaintextFields.Select(EncodeField) ]);

        var ciphertext      = new RawAesSiv(key).Encrypt([ associatedData ], effectiveNonce, plaintext);

        var field           = new RawExtensionField(
                                  RawExtensionFieldTypes.NTSAuthenticatorAndEncrypted,
                                  BuildAuthenticatorValue(effectiveNonce, ciphertext)
                              );

        packet.ExtensionFields.Add(field);

        return field;

    }


    /// <summary>
    /// Verify a packet's authenticator field and return the extension fields that were
    /// carried encrypted inside it.
    /// </summary>
    public static Boolean TryVerifyAuthenticator(RawNtpPacket                    packet,
                                                 Byte[]                          key,
                                                 out List<RawExtensionField>?    encryptedFields,
                                                 out String?                     errorResponse)
    {

        encryptedFields  = null;
        errorResponse    = null;

        var authenticator = packet.FirstFieldOfType(RawExtensionFieldTypes.NTSAuthenticatorAndEncrypted);

        if (authenticator is null)
        {
            errorResponse = "The packet carries no NTS Authenticator and Encrypted Extension Fields extension field.";
            return false;
        }

        if (!TryParseAuthenticatorValue(authenticator.Value, out var nonce, out var ciphertext, out errorResponse))
            return false;

        var associatedData = AssociatedDataFor(packet);

        if (!new RawAesSiv(key).TryDecrypt([ associatedData ], nonce, ciphertext!, out var plaintext, out errorResponse))
            return false;

        encryptedFields = [];

        var offset = 0;

        while (offset + 4 <= plaintext!.Length)
        {

            var fieldType    = RawNtpReader.ReadUInt16(plaintext, offset);
            var fieldLength  = RawNtpReader.ReadUInt16(plaintext, offset + 2);

            if (fieldLength < 4 || offset + fieldLength > plaintext.Length)
            {
                errorResponse = $"The encrypted extension field at offset {offset} declares a length of {fieldLength} octets, " +
                                $"which does not fit the {plaintext.Length}-octet plaintext.";
                return false;
            }

            encryptedFields.Add(new RawExtensionField(fieldType, plaintext[(offset + 4)..(offset + fieldLength)]));

            offset += fieldLength;

        }

        return true;

    }

    #endregion

    #region Complete NTS request / response helpers

    /// <summary>
    /// Build a conformant NTS-protected client request per RFC 8915 §5.7: exactly one
    /// Unique Identifier, exactly one NTS Cookie, the requested number of Cookie
    /// Placeholders, then exactly one Authenticator field.
    /// </summary>
    public static RawNtpPacket BuildNtsRequest(Byte[]     c2sKey,
                                               Byte[]     cookie,
                                               Byte[]?    uniqueIdentifier  = null,
                                               Int32      placeholders      = 0,
                                               Byte[]?    nonce             = null,
                                               DateTime?  transmitTime      = null)
    {

        var packet = RawNtpPacket.ClientRequest(transmitTime);

        packet.ExtensionFields.Add(UniqueIdentifier(uniqueIdentifier ?? RandomNumberGenerator.GetBytes(DefaultUniqueIdentifierLength)));
        packet.ExtensionFields.Add(NtsCookie(cookie));

        for (var i = 0; i < placeholders; i++)
            packet.ExtensionFields.Add(NtsCookiePlaceholder(cookie.Length));

        AppendAuthenticator(packet, c2sKey, plaintextFields: null, nonce: nonce);

        return packet;

    }

    #endregion

}
