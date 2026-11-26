using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Server.Tests;

/// <summary>
/// RFC 8915 §5.7 cookie replenishment.
///
/// "The number of NTS Cookie extension fields included SHOULD be equal to, and MUST NOT
/// exceed, one plus the number of valid NTS Cookie Placeholder extension fields included
/// in the request."
///
/// This is what keeps a client's cookie pool from draining: it spends one cookie per
/// request, so without a replacement plus one per placeholder it would have to re-run the
/// TLS handshake every few queries.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class CookieReplenishmentTests
{

    private NornServerFixture? fixture;


    [OneTimeSetUp]
    public async Task StartServer()
        => fixture = await NornServerFixture.StartAsync();


    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    private static Int32 CountOf(NTPPacket packet, ExtensionTypes extensionType)
        => packet.Extensions.Count(extension => extension.Type == extensionType);


    /// <summary>
    /// The response must carry exactly one cookie per spent cookie plus one per valid
    /// placeholder — no fewer (the pool drains) and no more (a request could be amplified
    /// into a much larger response).
    /// </summary>
    [Test]
    public async Task ResponseCookieCount_MatchesOnePlusPlaceholders()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var client       = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult  = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var queryResult  = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                 Timeout:       TimeSpan.FromSeconds(10));

        Assert.That(queryResult.Success, Is.True, $"the NTS query failed: {queryResult.ErrorMessage}");

        var response     = queryResult.Response!;
        var request      = response.Request;

        Assert.That(request, Is.Not.Null, "the response should carry the request it answered");

        var placeholders = CountOf(request!, ExtensionTypes.NTSCookiePlaceholder);
        var cookies      = CountOf(response,  ExtensionTypes.NTSCookie);

        Assert.That(cookies,
                    Is.EqualTo(1 + placeholders),
                    $"the request carried {placeholders} placeholder(s), so the response should carry " +
                    $"{1 + placeholders} cookie(s) but carried {cookies}.\n" +
                    $"request extensions:  {String.Join(", ", request!.Extensions.Select(e => $"{e.Type}({e.Value.Length})"))}\n" +
                    $"response extensions: {String.Join(", ", response.Extensions.Select(e => $"{e.Type}({e.Value.Length})"))}");

    }


    /// <summary>
    /// Across a run of queries the pool must not shrink. With replenishment working the
    /// client never has to re-run NTS-KE mid-session; without it, the count falls by one
    /// per query.
    /// </summary>
    [Test]
    public async Task CookiePool_DoesNotDrainAcrossRepeatedQueries()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();
        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var remaining   = new List<Int32>();

        for (var i = 0; i < 6; i++)
        {

            var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResult.Response!,
                                                     Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(queryResult.Success, Is.True, $"query {i + 1} failed: {queryResult.ErrorMessage}");

            remaining.Add(queryResult.RemainingCookiesAfterQuery);

        }

        Assert.That(remaining[^1],
                    Is.GreaterThanOrEqualTo(remaining[0]),
                    $"the cookie pool shrank over six queries: {String.Join(" -> ", remaining)}");

    }


    /// <summary>
    /// RFC 8915 §5.5 / §5.7: Cookie Placeholder fields whose body length does not equal the
    /// cookie length are invalid and MUST NOT cause the server to emit additional cookies or
    /// amplify the response beyond the request size.
    /// </summary>
    [Test]
    public async Task InvalidLengthCookiePlaceholders_DoNotMintExtraCookies()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var client = fixture.CreateClient(TimeSpan.FromSeconds(10),
                                          aeadAlgorithms: [ AEADAlgorithms.AES_SIV_CMAC_256 ]);

        var keResult = await client.GetNTSKERecords();
        Assert.That(keResult.Success, Is.True, $"NTS-KE failed: {keResult.ErrorMessage}");

        var keResponse = keResult.Response!;
        var cookie     = keResponse.Cookies.First();
        var uid        = RawNtsExtensionFields.RandomUniqueIdentifier();

        var requestPacket = new RawNtpPacket {
                                LeapIndicator     = RawNtpLeapIndicator.NoWarning,
                                Version           = 4,
                                Mode              = RawNtpMode.Client,
                                Poll              = 6,
                                TransmitTimestamp = 0xE800_0000_0000_1234UL
                            };

        requestPacket.ExtensionFields.Add(uid);
        requestPacket.ExtensionFields.Add(RawNtsExtensionFields.NtsCookie(cookie));
        requestPacket.ExtensionFields.Add(RawNtsExtensionFields.NtsCookiePlaceholder(cookie.Length - 4));
        requestPacket.ExtensionFields.Add(RawNtsExtensionFields.NtsCookiePlaceholder(cookie.Length + 4));
        RawNtsExtensionFields.AppendAuthenticator(requestPacket, keResponse.C2SKey);

        var requestBytes  = RawNtpWriter.Write(requestPacket);
        var parsed        = RawNtpExchange.Exchange(requestPacket, "127.0.0.1", fixture.NTPPort, timeout: TimeSpan.FromSeconds(10));
        var responseBytes = RawNtpWriter.Write(parsed);

        Assert.That(RawNtsExtensionFields.TryVerifyAuthenticator(parsed, keResponse.S2CKey, out var encryptedFields, out var err),
                    Is.True,
                    $"response authenticator failed: {err}");

        var returnedCookies = encryptedFields!.Count(field => field.FieldType == RawExtensionFieldTypes.NTSCookie);

        Assert.Multiple(() => {

            Assert.That(returnedCookies,
                        Is.EqualTo(1),
                        $"invalid-length placeholders must not draw extra cookies (expected 1 replacement, got {returnedCookies})");

            Assert.That(responseBytes.Length,
                        Is.LessThanOrEqualTo(requestBytes.Length),
                        $"response ({responseBytes.Length}B) must not amplify request ({requestBytes.Length}B)");

        });

    }


    /// <summary>
    /// RFC 8915 §5.7: An NTS request with a valid cookie but a corrupted C2S authenticator
    /// MUST be answered with an NTS NAK (Stratum 0, kiss code "NTSN") echoing the Unique ID.
    /// </summary>
    [Test]
    public async Task CorruptedAuthenticator_DrawsNtsNak()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var ke = await RawNtsKeClient.ExchangeAsync(
                     "127.0.0.1",
                     fixture.NTSKEPort,
                     RawNtsKeCodec.ClientRequest(15),
                     TimeSpan.FromSeconds(10)
                 );

        Assert.That(ke.HandshakeSucceeded, Is.True, ke.ToString());

        var cookie   = ke.RecordsOfType(RawNtsKeRecordTypes.NewCookieForNtpv4).First().Body;
        var wrongKey = Enumerable.Repeat((Byte) 0x5A, 32).ToArray();
        var request  = RawNtsExtensionFields.BuildNtsRequest(wrongKey, cookie);

        var response = RawNtpExchange.Exchange(request, "127.0.0.1", fixture.NTPPort, timeout: TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {

            Assert.That(response.IsKissOfDeath, Is.True, "corrupted authenticator must draw a Kiss-o'-Death");
            Assert.That(response.KissCode,      Is.EqualTo("NTSN"), "corrupted authenticator must draw NTSN NAK");

            Assert.That(response.UniqueIdentifier,
                        Is.EqualTo(request.UniqueIdentifier).AsCollection,
                        "NTS NAK must echo the request's Unique Identifier");

        });

    }

}
