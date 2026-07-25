using System.Security.Cryptography;

using NUnit.Framework;

using NTSConformance.Core;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Cookies.Tests;

/// <summary>
/// RFC 8915 §6 — NTS cookies.
///
/// A cookie is the server's own state, handed to the client and echoed back on every
/// request. It carries the C2S and S2C session keys, and it travels in the clear inside
/// every NTS request, so §6's requirements are not negotiable: the server encrypts and
/// authenticates the cookie with an AEAD under a secret master key known only to itself,
/// the cookie is opaque to the client, and the server can tell a cookie it issued from one
/// it did not.
///
/// These tests need no network — they exercise the cookie codec directly, which is where
/// the guarantee either exists or does not.
/// </summary>
[TestFixture]
public class CookieConfidentialityTests
{

    #region Fixtures

    private static MasterKey NewMasterKey(UInt64 id = 1)

        => new (Id:         id,
                Value:      RandomNumberGenerator.GetBytes(32),
                NotBefore:  DateTimeOffset.UtcNow.AddMinutes(-1),
                NotAfter:   DateTimeOffset.UtcNow.AddDays(1));


    /// <summary>Session keys with recognisable, non-random content so they are easy to spot on the wire.</summary>
    private static readonly Byte[] C2SKey = Enumerable.Repeat((Byte) 0xC2, 32).ToArray();
    private static readonly Byte[] S2CKey = Enumerable.Repeat((Byte) 0x5C, 32).ToArray();


    private static Byte[] SealedCookie(MasterKey masterKey)
        => NTSCookie.Create(masterKey, C2SKey, S2CKey, AEADAlgorithms.AES_SIV_CMAC_256).Encrypt(masterKey);

    #endregion

    #region Confidentiality

    /// <summary>
    /// The sealed cookie must not contain the session keys in the clear.
    ///
    /// This is the single most important assertion in the suite. The NTS Cookie extension
    /// field travels as plaintext inside every client request, and only the cookie's own
    /// encryption keeps the session keys secret. If the keys were recoverable from the
    /// cookie, a passive observer could decrypt all NTS traffic for that association and
    /// forge authenticated responses — NTS would provide no protection whatsoever.
    /// </summary>
    [Test]
    public void SealedCookie_DoesNotContainSessionKeys()
    {

        var sealedCookie = SealedCookie(NewMasterKey());

        Assert.Multiple(() => {

            Assert.That(Bytes.Contains(sealedCookie, C2SKey),
                        Is.False,
                        "the client-to-server key appears verbatim in the sealed cookie:\n" + Bytes.Dump(sealedCookie));

            Assert.That(Bytes.Contains(sealedCookie, S2CKey),
                        Is.False,
                        "the server-to-client key appears verbatim in the sealed cookie:\n" + Bytes.Dump(sealedCookie));

        });

    }


    /// <summary>
    /// Only the master key id may be readable from a sealed cookie without key material —
    /// the server needs it to choose a key before it can decrypt. Everything else,
    /// including the AEAD's own nonce region, must reveal no session key material.
    /// </summary>
    [Test]
    public void SealedCookie_ExposesOnlyTheMasterKeyId()
    {

        var masterKey    = NewMasterKey(id: 5);
        var sealedCookie = SealedCookie(masterKey);

        Assert.Multiple(() => {

            Assert.That(NTSCookie.TryReadMasterKeyId(sealedCookie, out var masterKeyId, out var errorResponse),
                        Is.True,
                        $"the server must be able to read the key id to select a key: {errorResponse}");

            Assert.That(masterKeyId, Is.EqualTo(masterKey.Id));

            Assert.That(Bytes.Contains(sealedCookie, C2SKey) || Bytes.Contains(sealedCookie, S2CKey),
                        Is.False,
                        "no session key material may be exposed alongside the key id");

        });

    }


    /// <summary>
    /// Two cookies minted for the same session must not be byte-identical: an identical
    /// cookie is a stable identifier that links every request in a session, which RFC 8915
    /// §6 and RFC 7384 §5.1 both set out to prevent.
    /// </summary>
    [Test]
    public void SuccessiveCookies_AreNotIdentical()
    {

        var masterKey = NewMasterKey();

        Assert.That(Bytes.ToHex(SealedCookie(masterKey)),
                    Is.Not.EqualTo(Bytes.ToHex(SealedCookie(masterKey))),
                    "successive cookies for one session are identical, so they act as a linkable session identifier");

    }

    #endregion

    #region Integrity and forgery

    /// <summary>
    /// The server must reject a cookie it did not issue.
    ///
    /// An attacker who has never seen the master key can pick their own session keys and
    /// wrap them in a cookie structure with any master key id — the id is a small integer
    /// and is readable from any cookie already on the wire. If the server accepted such a
    /// cookie it would adopt the attacker's keys, and the attacker's "authenticated"
    /// request would then verify perfectly: a complete authentication bypass.
    /// </summary>
    [Test]
    public void ForgedCookie_IsRejected()
    {

        var serverMasterKey  = NewMasterKey(id: 7);

        // Same id as the server's key, but a secret the attacker chose.
        var forgedMasterKey  = new MasterKey(Id:        serverMasterKey.Id,
                                             Value:     RandomNumberGenerator.GetBytes(32),
                                             NotBefore: DateTimeOffset.UtcNow.AddMinutes(-1),
                                             NotAfter:  DateTimeOffset.UtcNow.AddDays(1));

        var attackerC2SKey   = Enumerable.Repeat((Byte) 0xAA, 32).ToArray();
        var attackerS2CKey   = Enumerable.Repeat((Byte) 0xBB, 32).ToArray();

        var forgedCookie     = NTSCookie.Create(forgedMasterKey, attackerC2SKey, attackerS2CKey,
                                                AEADAlgorithms.AES_SIV_CMAC_256).
                                   Encrypt(forgedMasterKey);

        var accepted = NTSCookie.TryParse(forgedCookie, serverMasterKey, out var parsed, out var errorResponse);

        Assert.Multiple(() => {

            Assert.That(accepted, Is.False,
                        "the server accepted a cookie forged without the master key — RFC 8915 §6 requires " +
                        "the cookie to be authenticated under that key");

            Assert.That(parsed, Is.Null, "no cookie may be produced from a failed authentication");

            Assert.That(errorResponse, Is.Not.Null.And.Not.Empty);

        });

    }


    /// <summary>
    /// Flipping any single octet of a sealed cookie must invalidate it. Swept across the
    /// whole cookie so the key id, the nonce and the ciphertext are all covered.
    /// </summary>
    [Test]
    public void TamperedCookie_IsRejected()
    {

        var masterKey    = NewMasterKey();
        var sealedCookie = SealedCookie(masterKey);

        Assert.Multiple(() => {
            for (var offset = 0; offset < sealedCookie.Length; offset++)
            {

                var tampered = (Byte[]) sealedCookie.Clone();
                tampered[offset] ^= 0x01;

                Assert.That(NTSCookie.TryParse(tampered, masterKey, out var parsed, out _) &&
                            parsed.C2SKey.SequenceEqual(C2SKey),
                            Is.False,
                            $"a cookie with octet {offset} altered still yielded the original session keys");

            }
        });

    }


    /// <summary>
    /// Truncating a sealed cookie must be refused rather than read out of bounds, at every
    /// length.
    /// </summary>
    [Test]
    public void TruncatedCookie_IsRejected()
    {

        var masterKey    = NewMasterKey();
        var sealedCookie = SealedCookie(masterKey);

        Assert.Multiple(() => {
            for (var length = 0; length < sealedCookie.Length; length++)
            {

                Boolean accepted;

                try
                {
                    accepted = NTSCookie.TryParse(sealedCookie[..length], masterKey, out _, out _);
                }
                catch (Exception e)
                {
                    Assert.Fail($"TryParse threw {e.GetType().Name} for a {length}-octet cookie instead of returning false");
                    return;
                }

                Assert.That(accepted, Is.False, $"a {length}-octet cookie is truncated and must be refused");

            }
        });

    }

    #endregion

    #region Master-key binding

    /// <summary>
    /// A cookie must only be readable under the master key that issued it. If an unrelated
    /// key opened it too, the master key would play no cryptographic role and rotating it
    /// would protect nothing.
    /// </summary>
    [Test]
    public void CookieIsBoundToItsMasterKey()
    {

        var issuingKey   = NewMasterKey(id: 1);
        var unrelatedKey = NewMasterKey(id: 2);

        var sealedCookie = SealedCookie(issuingKey);

        Assert.That(NTSCookie.TryParse(sealedCookie, unrelatedKey, out var parsed, out var errorResponse) &&
                    parsed.C2SKey.SequenceEqual(C2SKey),
                    Is.False,
                    $"an unrelated master key recovered the session keys (error was: {errorResponse ?? "none"})");

    }


    /// <summary>
    /// The rotating 32-octet master-key secret must influence the cookie's bytes.
    ///
    /// Sealing one and the same cookie under two keys that share an id but hold different
    /// secrets isolates exactly that: timestamp, nonce and session keys are held constant,
    /// so any difference can only come from the secret. Identical output would mean
    /// <c>MasterKey.Value</c> never reaches the cipher and the rotation and persistence
    /// machinery built around it protects nothing.
    /// </summary>
    [Test]
    public void MasterKeyValue_AffectsTheCookieBytes()
    {

        var now    = DateTimeOffset.UtcNow;

        var keyA   = new MasterKey(1, RandomNumberGenerator.GetBytes(32), now.AddMinutes(-1), now.AddDays(1));
        var keyB   = new MasterKey(1, RandomNumberGenerator.GetBytes(32), now.AddMinutes(-1), now.AddDays(1));

        var cookie = NTSCookie.Create(keyA, C2SKey, S2CKey, AEADAlgorithms.AES_SIV_CMAC_256);

        Assert.That(Bytes.ToHex(cookie.Encrypt(keyA)),
                    Is.Not.EqualTo(Bytes.ToHex(cookie.Encrypt(keyB))),
                    "the same cookie sealed under two different master-key secrets produced identical bytes, " +
                    "so MasterKey.Value is never used and master-key rotation is cosmetic");

    }


    /// <summary>
    /// A cookie issued under a master key whose validity window has closed must be refused.
    /// RFC 8915 §6 relies on rotation to bound how long a compromised cookie stays useful,
    /// which only works if expiry is actually enforced.
    /// </summary>
    [Test]
    public void CookieUnderExpiredMasterKey_IsRejected()
    {

        var expiredKey   = new MasterKey(1,
                                         RandomNumberGenerator.GetBytes(32),
                                         DateTimeOffset.UtcNow.AddDays(-3),
                                         DateTimeOffset.UtcNow.AddDays(-2));

        var sealedCookie = NTSCookie.Create(expiredKey, C2SKey, S2CKey, AEADAlgorithms.AES_SIV_CMAC_256).
                               Encrypt(expiredKey);

        var masterKeys   = new Dictionary<UInt64, MasterKey> { [expiredKey.Id] = expiredKey };

        Assert.That(NTSCookie.TryParse(sealedCookie, masterKeys, out _, out var errorResponse),
                    Is.False,
                    "a cookie minted outside its master key's validity window must not be accepted");

        Assert.That(errorResponse, Does.Contain("validity window"));

    }


    /// <summary>
    /// A cookie naming a master key the server does not hold must be refused with a clear
    /// reason, not treated as a decryption failure or a crash.
    /// </summary>
    [Test]
    public void CookieWithUnknownMasterKeyId_IsRejected()
    {

        var knownKey     = NewMasterKey(id: 1);
        var strangerKey  = NewMasterKey(id: 99);

        var masterKeys   = new Dictionary<UInt64, MasterKey> { [knownKey.Id] = knownKey };

        Assert.That(NTSCookie.TryParse(SealedCookie(strangerKey), masterKeys, out _, out var errorResponse),
                    Is.False);

        Assert.That(errorResponse, Does.Contain("Unknown"));

    }


    /// <summary>
    /// Rotation must not invalidate cookies still in flight: a cookie issued under the
    /// previous key has to keep working while that key remains in its grace period, or
    /// every rotation would strand clients mid-session.
    /// </summary>
    [Test]
    public void CookieUnderPreviousMasterKey_IsStillAccepted()
    {

        var now         = DateTimeOffset.UtcNow;

        var previousKey = new MasterKey(1, RandomNumberGenerator.GetBytes(32), now.AddDays(-1), now.AddDays(6));
        var currentKey  = new MasterKey(2, RandomNumberGenerator.GetBytes(32), now.AddMinutes(-1), now.AddDays(1));

        var oldCookie   = SealedCookie(previousKey);

        var masterKeys  = new Dictionary<UInt64, MasterKey> {
                              [previousKey.Id] = previousKey,
                              [currentKey.Id]  = currentKey
                          };

        Assert.That(NTSCookie.TryParse(oldCookie, masterKeys, out var parsed, out var errorResponse),
                    Is.True,
                    $"a cookie from the previous master key must still be accepted during its grace period: {errorResponse}");

        Assert.That(parsed!.C2SKey, Is.EqualTo(C2SKey).AsCollection);

    }

    #endregion

    #region Round-trip under the correct key

    /// <summary>
    /// The legitimate path must work: a cookie sealed under a master key decrypts back to
    /// exactly the session keys, algorithm and key id that went in.
    /// </summary>
    [Test]
    public void CookieRoundTripsUnderItsOwnMasterKey()
    {

        var masterKey = NewMasterKey(id: 42);
        var original  = NTSCookie.Create(masterKey, C2SKey, S2CKey, AEADAlgorithms.AES_SIV_CMAC_256);

        if (!NTSCookie.TryParse(original.Encrypt(masterKey), masterKey, out var recovered, out var errorResponse))
        {
            Assert.Fail($"the server must be able to unseal its own cookie: {errorResponse}");
            return;
        }

        Assert.Multiple(() => {
            Assert.That(recovered.C2SKey,        Is.EqualTo(C2SKey).AsCollection, "the C2S key");
            Assert.That(recovered.S2CKey,        Is.EqualTo(S2CKey).AsCollection, "the S2C key");
            Assert.That(recovered.MasterKeyId,   Is.EqualTo(masterKey.Id),        "the master-key id");
            Assert.That(recovered.AEADAlgorithm, Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256), "the AEAD algorithm");
            Assert.That(recovered,               Is.EqualTo(original),            "the whole cookie");
        });

    }


    /// <summary>
    /// An unsupported AEAD algorithm id must be refused rather than silently treated as
    /// AES-SIV-CMAC-256, which would mean using key material of the wrong length.
    /// </summary>
    [Test]
    public void UnsupportedAeadAlgorithm_IsRejected()
    {

        var masterKey = NewMasterKey();
        var cookie    = NTSCookie.Create(masterKey, C2SKey, S2CKey, AEADAlgorithms.AES_128_GCM_SIV);

        Assert.That(NTSCookie.TryParse(cookie.Encrypt(masterKey), masterKey, out _, out var errorResponse),
                    Is.False,
                    "only AES-SIV-CMAC-256 is implemented, so any other algorithm id must be refused");

        Assert.That(errorResponse, Does.Contain("AEAD").IgnoreCase);

    }

    #endregion

}
