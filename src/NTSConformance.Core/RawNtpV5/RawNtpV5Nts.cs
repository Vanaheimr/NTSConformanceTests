using System.Buffers.Binary;
using System.Security.Cryptography;

using NTSConformance.Core.RawNtp;

namespace NTSConformance.Core.RawNtpV5;

/// <summary>
/// NTS for NTPv5, draft-ietf-ntp-ntpv5-10 § 11: the four extension fields of RFC 8915 § 5 in an
/// NTPv5 message, written and read by this suite alone. The draft carries them over unchanged -
/// "NTS extension fields defined for NTPv4 can be used in NTPv5" - and so their types, their
/// order and what the authenticator covers are RFC 8915's.
/// </summary>
/// <remarks>
/// So are the keys: RFC 8915 § 5.1 is key extraction "for NTPv4", the draft specifies none of
/// its own, and chrony-ntp5 derives the keys of NTPv5 under NTPv4's exporter context, 0x0000 -
/// as Norn does since 92b48f4. The cookie, not the key, names the protocol it is good for.
/// </remarks>
public static class RawNtpV5Nts
{

    #region Codepoints, RFC 8915 § 7.5

    public const UInt16 UniqueIdentifier      = 0x0104;
    public const UInt16 NtsCookie             = 0x0204;
    public const UInt16 NtsCookiePlaceholder  = 0x0304;
    public const UInt16 NtsAuthenticator      = 0x0404;

    /// <summary>
    /// RFC 8915 § 5.3: "at least 32 octets long".
    /// </summary>
    public const Int32  MinimumUniqueIdentifierLength = 32;

    #endregion


    #region The AEAD of the key exchange, by its Numeric Identifier

    /// <summary>
    /// RFC 8915 § 5.6 with RFC 5297 for algorithm 15 and RFC 8452 for 30 and 31: the nonce the
    /// suite draws for each.
    /// </summary>
    public static Int32 NonceLength(UInt16 AeadAlgorithm)
        => AeadAlgorithm == 15 ? 16 : 12;

    public static Int32 KeyLength(UInt16 AeadAlgorithm)
        => AeadAlgorithm == 30 ? 16 : 32;

    public static Byte[] Seal(UInt16 AeadAlgorithm, Byte[] Key, Byte[] AssociatedData, Byte[] Nonce, Byte[] Plaintext)

        => AeadAlgorithm == 15
               ? new RawAesSiv   (Key).Encrypt([ AssociatedData ], Nonce, Plaintext)
               : new RawAesGcmSiv(Key).Encrypt(  AssociatedData,   Nonce, Plaintext);

    public static Boolean TryOpen(UInt16 AeadAlgorithm, Byte[] Key, Byte[] AssociatedData, Byte[] Nonce, Byte[] Ciphertext, out Byte[]? Plaintext, out String? Error)

        => AeadAlgorithm == 15
               ? new RawAesSiv   (Key).TryDecrypt([ AssociatedData ], Nonce, Ciphertext, out Plaintext, out Error)
               : new RawAesGcmSiv(Key).TryDecrypt(  AssociatedData,   Nonce, Ciphertext, out Plaintext, out Error);

    #endregion


    #region Offsets

    /// <summary>
    /// Where in the message the extension field of the given index begins.
    /// </summary>
    public static Int32 OffsetOf(RawNtpV5Packet Packet, Int32 Index)
        => RawNtpV5Draft.HeaderLength + Packet.ExtensionFields.Take(Index).Sum(field => field.PaddedLength);

    #endregion


    #region The authenticator

    /// <summary>
    /// RFC 8915 § 5.6: the authenticator over the given octets - the message up to it - with
    /// the given plaintext encrypted in it.
    /// </summary>
    public static RawNtpV5ExtensionField Authenticator(UInt16   AeadAlgorithm,
                                                       Byte[]   Key,
                                                       Byte[]   AssociatedData,
                                                       Byte[]?  Plaintext  = null,
                                                       Byte[]?  Nonce      = null)
    {

        var nonce = Nonce ?? RandomNumberGenerator.GetBytes(NonceLength(AeadAlgorithm));

        return new RawNtpV5ExtensionField(NtsAuthenticator,
                                          RawNtsExtensionFields.BuildAuthenticatorValue(nonce,
                                                                                        Seal(AeadAlgorithm, Key, AssociatedData, nonce, Plaintext ?? [])));

    }

    #endregion


    #region A request

    /// <summary>
    /// An NTS-protected NTPv5 request as RFC 8915 § 5.7 has a client form it: the given request
    /// with exactly one Unique Identifier, exactly one cookie and the placeholders after its own
    /// fields, then exactly one authenticator over the header and all of them, then whatever is
    /// to go unauthenticated after it.
    /// </summary>
    /// <param name="Request">The request without NTS; it is changed, and is the request sent.</param>
    /// <param name="AeadAlgorithm">The algorithm of the key exchange.</param>
    /// <param name="C2SKey">The client-to-server key.</param>
    /// <param name="Cookie">A cookie of the key exchange.</param>
    /// <param name="UniqueIdentifier">The Unique Identifier, by default 32 random octets.</param>
    /// <param name="Placeholders">How many placeholders, each as long as the cookie.</param>
    /// <param name="PlaceholderLength">Their length, when it is to be another than the cookie's.</param>
    /// <param name="AfterAuthenticator">Fields after the authenticator.</param>
    public static Byte[] Request(RawNtpV5Packet                         Request,
                                 UInt16                                 AeadAlgorithm,
                                 Byte[]                                 C2SKey,
                                 Byte[]                                 Cookie,
                                 Byte[]?                                UniqueIdentifier    = null,
                                 Int32                                  Placeholders        = 0,
                                 Int32?                                 PlaceholderLength   = null,
                                 IEnumerable<RawNtpV5ExtensionField>?   AfterAuthenticator  = null)
    {

        Request.ExtensionFields.Add(new RawNtpV5ExtensionField(RawNtpV5Nts.UniqueIdentifier,
                                                               UniqueIdentifier ?? RandomNumberGenerator.GetBytes(MinimumUniqueIdentifierLength)));

        Request.ExtensionFields.Add(new RawNtpV5ExtensionField(NtsCookie, Cookie));

        for (var i = 0; i < Placeholders; i++)
            Request.ExtensionFields.Add(new RawNtpV5ExtensionField(NtsCookiePlaceholder, new Byte[PlaceholderLength ?? Cookie.Length]));

        Request.ExtensionFields.Add(Authenticator(AeadAlgorithm, C2SKey, Request.Write()));
        Request.ExtensionFields.AddRange(AfterAuthenticator ?? []);

        return Request.Write();

    }

    #endregion


    #region A response

    /// <summary>
    /// What verifying an NTS response established.
    /// </summary>
    /// <param name="Packet">The response.</param>
    /// <param name="AuthenticatorIndex">Where among its fields the authenticator is.</param>
    /// <param name="Cookies">The new cookies the authenticator decrypted to, each the value of an NTS Cookie field.</param>
    public sealed record VerifiedResponse(RawNtpV5Packet          Packet,
                                          Int32                   AuthenticatorIndex,
                                          IReadOnlyList<Byte[]>   Cookies);


    /// <summary>
    /// Verify an NTS response as RFC 8915 § 5.7 has a client do before it believes a word of it:
    /// exactly one authenticator, which verifies under the server-to-client key over the header
    /// and every field before it, the Unique Identifier of the request among those fields, and
    /// the new cookies as NTS Cookie fields in what it decrypts to.
    /// </summary>
    public static Boolean TryVerifyResponse(Byte[]                                 Octets,
                                            UInt16                                 AeadAlgorithm,
                                            Byte[]                                 S2CKey,
                                            Byte[]                                 UniqueIdentifier,
                                            out VerifiedResponse?                  Response,
                                            out String?                            Error)
    {

        Response = null;

        if (!RawNtpV5Packet.TryRead(Octets, out var packet, out Error))
            return false;

        var authenticators = packet!.ExtensionFields.Count(field => field.Type == NtsAuthenticator);

        if (authenticators != 1)
        {
            Error = $"the response carries {authenticators} authenticators, not exactly one";
            return false;
        }

        var index = packet.ExtensionFields.FindIndex(field => field.Type == NtsAuthenticator);

        var uniqueIdentifiers = packet.ExtensionFields.Take(index).Where(field => field.Type == RawNtpV5Nts.UniqueIdentifier).ToArray();

        if (uniqueIdentifiers.Length != 1 || !uniqueIdentifiers[0].Data.AsSpan().SequenceEqual(UniqueIdentifier))
        {
            Error = "the authenticated part of the response does not echo the Unique Identifier of the request exactly once";
            return false;
        }

        if (!RawNtsExtensionFields.TryParseAuthenticatorValue(packet.ExtensionFields[index].Data, out var nonce, out var ciphertext, out Error))
            return false;

        if (!TryOpen(AeadAlgorithm, S2CKey, Octets[..OffsetOf(packet, index)], nonce!, ciphertext!, out var plaintext, out var openError))
        {
            Error = $"the authenticator does not open under the S2C key: {openError}";
            return false;
        }

        // RFC 8915 § 5.6: the plaintext is a sequence of NTPv4 extension fields, whose Length
        // (RFC 7822) counts the header and the padding.
        var cookies = new List<Byte[]>();
        var offset  = 0;

        while (offset < plaintext!.Length)
        {

            if (plaintext.Length - offset < 4)
            {
                Error = $"{plaintext.Length - offset} octets at offset {offset} of the plaintext are too short for a field";
                return false;
            }

            var type   = BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(offset));
            var length = BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(offset + 2));

            if (length < 4 || offset + length > plaintext.Length)
            {
                Error = $"the encrypted field 0x{type:X4} at offset {offset} has a length of {length}, which does not fit the {plaintext.Length}-octet plaintext";
                return false;
            }

            if (type == NtsCookie)
                cookies.Add(plaintext[(offset + 4)..(offset + length)]);

            offset += length;

        }

        Response = new VerifiedResponse(packet, index, cookies);
        return true;

    }

    #endregion

}
