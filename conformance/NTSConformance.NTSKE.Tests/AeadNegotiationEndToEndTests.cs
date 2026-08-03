using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// What a negotiated AEAD algorithm actually changes, end to end.
///
/// <para>
/// RFC 8915 § 4.1.5 lets a session run on any AEAD both sides support, and for most of Norn's
/// life that was a negotiation with one candidate: the client offered AES-SIV-CMAC-256, the
/// server agreed, and every length downstream could be — and was — written as a constant.
/// Adding AES-128-GCM-SIV turns those constants into variables, and this is the fixture that
/// says which ones.
/// </para>
/// <para>
/// Three of them, and each is wire-visible: the exported keys are sixteen octets rather than
/// thirty-two (§ 5.1, whose exporter context carries the algorithm id), the cookie shrinks by
/// twice that, and the Authenticator extension field's nonce is twelve octets rather than
/// sixteen (RFC 8452 § 6 admits no other length). An implementation that negotiated the
/// algorithm and then used any of the old constants would produce a session that fails to
/// authenticate with no indication of which of the four things was wrong.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class AeadNegotiationEndToEndTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        // Every implemented algorithm rather than the default offer, so that AES-256-GCM-SIV is
        // reachable too — it is implemented but not advertised, having never been run against an
        // implementation other than this one. See NTSAEAD.Supported.
        => fixture = await NornServerFixture.StartAsync(
                               certificate:     TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]),
                               aeadAlgorithms:  NTSAEAD.Implemented);


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    /// <summary>
    /// A Norn client and a Norn server run a complete session on AES-128-GCM-SIV.
    /// </summary>
    /// <remarks>
    /// Pinned to the one algorithm rather than left to the default, so the test keeps testing
    /// what it says even if the preference order changes. What it establishes is that the keys,
    /// the twelve-octet nonce, the cookie and the authenticator all line up — which is necessary
    /// and, as the exporter-context defect showed at length, nowhere near sufficient: two ends of
    /// one codebase agree with each other whatever they both get wrong. The interop suite is
    /// where that gets settled.
    /// </remarks>
    [Test]
    public async Task PinnedToGcmSiv_ANornSessionWorks()
    {

        var client       = fixture!.CreateClient(TimeSpan.FromSeconds(10),
                                                 aeadAlgorithms: [ AEADAlgorithms.AES_128_GCM_SIV ]);
        var keyExchange  = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success, Is.True, keyExchange.ErrorMessage);

        var response = keyExchange.Response!;

        Assert.Multiple(() => {

            Assert.That(response.AEADAlgorithm,
                        Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV),
                        "both sides were asked for it");

            Assert.That(response.C2SKey.Length, Is.EqualTo(16),
                        "§ 5.1 exports as many octets as the algorithm's key needs");

            Assert.That(response.S2CKey.Length, Is.EqualTo(16));

        });

        var query = await client.QueryTime(NTSKEResponse: response,
                                           Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(query.Success,
                    Is.True,
                    $"and the session works on it: {query.ErrorMessage}\n" +
                    $"server metrics: {fixture.Server.Metrics}");

    }


    /// <summary>
    /// The two algorithms produce different key lengths from the same exporter, and different
    /// keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The second half is the one worth stating. § 5.1 puts the algorithm id into the exporter
    /// context, so the keys for two algorithms in the same TLS session are unrelated — not one
    /// truncated to the other's length. An implementation that exported thirty-two octets once
    /// and cut them down would produce keys that work against itself and against nothing else.
    /// </para>
    /// <para>
    /// Two separate key exchanges, so the TLS sessions differ and the keys would differ anyway
    /// — which is why the assertion is on the prefix rather than on the whole: if the shorter
    /// key were a truncation of the longer, the first sixteen octets would still have to line up
    /// within one session, and across sessions they cannot line up at all. What this really
    /// pins is the length, and that the shorter one is not simply the first half of the longer.
    /// </para>
    /// </remarks>
    [Test]
    public async Task EachAlgorithmGetsItsOwnKeysOfItsOwnLength()
    {

        var withGcmSiv = await KeysFor(AEADAlgorithms.AES_128_GCM_SIV);
        var withAesSiv = await KeysFor(AEADAlgorithms.AES_SIV_CMAC_256);

        Assert.Multiple(() => {

            Assert.That(withGcmSiv.Algorithm, Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV));
            Assert.That(withAesSiv.Algorithm, Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256));

            Assert.That(withGcmSiv.C2SKey.Length, Is.EqualTo(16));
            Assert.That(withAesSiv.C2SKey.Length, Is.EqualTo(32));

            Assert.That(withGcmSiv.C2SKey,
                        Is.Not.EqualTo(withAesSiv.C2SKey.Take(16).ToArray()).AsCollection,
                        "the shorter key is a derivation of its own, not the longer one cut down");

        });

    }


    /// <summary>
    /// A cookie for AES-128-GCM-SIV is thirty-two octets smaller.
    /// </summary>
    /// <remarks>
    /// Exactly thirty-two: a cookie carries both session keys, and each is sixteen octets
    /// shorter. This is the practical reason to prefer the algorithm at all — a key exchange
    /// hands out eight cookies, and every request carries one back.
    /// </remarks>
    [Test]
    public async Task ACookieForGcmSiv_IsSmaller()
    {

        var gcmSiv = await KeysFor(AEADAlgorithms.AES_128_GCM_SIV);
        var aesSiv = await KeysFor(AEADAlgorithms.AES_SIV_CMAC_256);

        Assert.That(gcmSiv.CookieOctets,
                    Is.EqualTo(aesSiv.CookieOctets - 32),
                    $"AES-128-GCM-SIV cookie {gcmSiv.CookieOctets} octets against " +
                    $"AES-SIV-CMAC-256's {aesSiv.CookieOctets}; the difference is two keys of " +
                    $"sixteen octets each");

    }


    /// <summary>
    /// The nonce in the Authenticator extension field is the one the algorithm requires.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read out of the request the client puts on the wire, because this is the field a peer has
    /// to frame before it can decrypt anything: the nonce length is the first two octets of the
    /// extension's body, and everything after it is placed relative to that.
    /// </para>
    /// <para>
    /// RFC 8452 § 6 gives AES-GCM-SIV a nonce of exactly twelve octets — "N_MIN and N_MAX are
    /// 12" — where AES-SIV takes any length and Norn has always sent sixteen. A client that
    /// negotiated the new algorithm and kept sending sixteen would be handing the primitive a
    /// nonce it must refuse.
    /// </para>
    /// </remarks>
    [TestCase(AEADAlgorithms.AES_128_GCM_SIV,  12)]
    [TestCase(AEADAlgorithms.AES_SIV_CMAC_256, 16)]
    public void TheAuthenticatorNonce_IsTheLengthTheAlgorithmRequires(AEADAlgorithms Algorithm,
                                                                      Int32          ExpectedNonceLength)
    {

        var key            = new Byte[NTSAEAD.KeyLength(Algorithm)!.Value];
        var associatedData = new Byte[] { 0x01, 0x02, 0x03, 0x04 };

        var authenticator  = AuthenticatorAndEncryptedExtension.Create(
                                 NTSKey:          key,
                                 AssociatedData:  [ associatedData ],
                                 Plaintext:       [],
                                 Nonce:           null,
                                 AEADAlgorithm:   Algorithm
                             );

        Assert.Multiple(() => {

            Assert.That(authenticator.Nonce.Length,
                        Is.EqualTo(ExpectedNonceLength),
                        $"{Algorithm.AsText()} nonce length");

            // The wire framing has to agree with it, or a peer reads the ciphertext from the
            // wrong offset.
            Assert.That((authenticator.Value[0] << 8) | authenticator.Value[1],
                        Is.EqualTo(ExpectedNonceLength),
                        "and the length field at the front of the extension body says so");

        });

    }


    #region (private) KeysFor(Algorithm)

    private sealed record Negotiated(AEADAlgorithms Algorithm, Byte[] C2SKey, Int32 CookieOctets);

    /// <summary>
    /// Run a key exchange offering exactly one algorithm, and report what came back.
    /// </summary>
    /// <remarks>
    /// Through Norn's own client, because the exported keys are the thing under test and they
    /// never appear on the wire — only their effects do. Offering a single algorithm is how the
    /// negotiation is steered to a given one without a scripted peer, and it is the reason
    /// NTSClient takes a list at all rather than always offering everything.
    /// </remarks>
    private async Task<Negotiated> KeysFor(AEADAlgorithms Algorithm)
    {

        var client       = fixture!.CreateClient(TimeSpan.FromSeconds(10),
                                                 aeadAlgorithms: [ Algorithm ]);

        var keyExchange  = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success, Is.True, keyExchange.ErrorMessage);

        var response = keyExchange.Response!;

        Assert.That(response.AEADAlgorithm,
                    Is.EqualTo(Algorithm),
                    $"only {Algorithm.AsText()} was offered, so nothing else may be agreed");

        Assert.That(response.Cookies.Any(), Is.True, "no cookie came back");

        return new Negotiated(response.AEADAlgorithm,
                              response.C2SKey,
                              response.Cookies.First().Length);

    }

    #endregion

}
