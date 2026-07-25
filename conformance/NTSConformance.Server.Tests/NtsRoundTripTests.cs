using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSConformance.Server.Tests;

/// <summary>
/// End-to-end NTS against a real in-process Norn server: NTS-KE over TLS, then an
/// authenticated NTP exchange over UDP on loopback.
///
/// This is the fixture the rest of the server conformance tests build on, so it asserts
/// only that the happy path works — and reports the server's own diagnostics when it does
/// not, since a silent UDP timeout otherwise says nothing about the cause.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtsRoundTripTests
{

    private NornServerFixture? fixture;
    private DebugXSink?        sink;


    [OneTimeSetUp]
    public async Task StartServer()
    {
        sink    = new DebugXSink();
        fixture = await NornServerFixture.StartAsync();
    }


    [OneTimeTearDown]
    public async Task StopServer()
    {

        if (fixture is not null)
            await fixture.DisposeAsync();

        sink?.Dispose();

    }


    /// <summary>
    /// The full RFC 8915 exchange: key establishment yields two session keys and at least
    /// one cookie, then an NTS-protected query returns an authenticated time.
    /// </summary>
    [Test]
    public async Task NtsKeThenAuthenticatedQuery_Succeeds()
    {

        if (fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        var client      = fixture.CreateClient(TimeSpan.FromSeconds(10));

        var ntsKeResult = await client.GetNTSKERecords();

        Assert.That(ntsKeResult.Success, Is.True, $"NTS-KE failed: {ntsKeResult.ErrorMessage}");

        var ntsKeResponse = ntsKeResult.Response!;

        Assert.Multiple(() => {
            Assert.That(ntsKeResponse.C2SKey.Length,  Is.EqualTo(32), "AES-SIV-CMAC-256 uses a 32-octet C2S key");
            Assert.That(ntsKeResponse.S2CKey.Length,  Is.EqualTo(32), "AES-SIV-CMAC-256 uses a 32-octet S2C key");
            Assert.That(ntsKeResponse.Cookies.Any(),  Is.True,        "NTS-KE must return at least one cookie");
        });

        var queryResult = await client.QueryTime(NTSKEResponse: ntsKeResponse,
                                                Timeout:       TimeSpan.FromSeconds(10));

        // A UDP timeout tells us nothing on its own; the server logs why it dropped a request.
        Assert.That(queryResult.Success,
                    Is.True,
                    $"the NTS query failed: {queryResult.ErrorMessage}\n" +
                    $"server metrics: {fixture.Server.Metrics}\n" +
                    $"server log:\n{sink?.Text}");

        Assert.That(queryResult.Response, Is.Not.Null);

    }

}
