using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;

namespace NTSConformance.Client.Tests;

/// <summary>
/// RFC 9109: the source port a client sends from.
///
/// An off-path attacker forging a server's answer has to guess what the client will accept:
/// the transmit timestamp it used as the origin, and the four-tuple of the exchange. Three of
/// those four are known to anyone who knows which server the client uses, so the source port
/// is a share of the guessing work — which is why RFC 9109 has clients draw it from the
/// ephemeral range instead of using 123, as older implementations did on both ends.
///
/// Under NTS this is defence in depth rather than the defence itself: a forged packet still
/// has to carry an authenticator the client's S2C key verifies. It matters because a client
/// speaks plain NTP too, and because the cost of getting it right is zero — the operating
/// system assigns an ephemeral port unless something asks it not to.
///
/// Which is exactly the failure this guards against. Nothing in Norn requests port 123, and
/// nothing should ever start to; the observation is cheap and the regression would be silent.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ClientSourcePortTests
{

    private UdpRelayProbe?      probe;
    private NornServerFixture?  fixture;

    private static readonly TimeSpan queryTimeout = TimeSpan.FromSeconds(15);


    /// <summary>
    /// The server advertises the probe's port, so every time query passes through the probe
    /// and its source port can be read off the datagram. There is no other way to see it:
    /// the client neither reports nor exposes the socket it used.
    /// </summary>
    [OneTimeSetUp]
    public async Task StartServerBehindProbe()
    {

        probe    = UdpRelayProbe.StartObserving();

        fixture  = await NornServerFixture.StartAsync(
                             certificate:        TestCertificate.Generate("source-port.test", [ "source-port.test" ]),
                             advertisedNTPPort:  probe.Port
                         );

        probe.RelayTo(fixture.NTPPort);

    }


    [OneTimeTearDown]
    public async Task StopServer()
    {

        if (fixture is not null)
            await fixture.DisposeAsync();

        probe?.Dispose();

    }


    /// <summary>
    /// Four separate associations, four queries, and every source port observed must be an
    /// ephemeral one — never 123, and never a reserved port.
    ///
    /// Also that they are not all the same. Four independent clients drawing the same port
    /// would mean it is being pinned somewhere rather than assigned, which is the arrangement
    /// RFC 9109 exists to end. Four draws from the ephemeral range colliding by chance is not
    /// a possibility worth guarding against.
    /// </summary>
    [Test]
    public async Task EveryQuery_ComesFromAnUnpredictableEphemeralPort()
    {

        if (probe is null || fixture is null)
        {
            Assert.Fail("the server fixture did not start");
            return;
        }

        const Int32 associations = 4;

        for (var i = 0; i < associations; i++)
        {

            // A fresh client each time: what is under test is whether separate associations
            // draw separate ports, so they must not share a socket by construction.
            var client       = fixture.CreateClient(queryTimeout);
            var keyExchange  = await client.GetNTSKERecords();

            Assert.That(keyExchange.Success,
                        Is.True,
                        $"key exchange {i + 1} of {associations} failed: {keyExchange.ErrorMessage}");

            var result = await client.QueryTime(NTSKEResponse:  keyExchange.Response!,
                                                Timeout:        queryTimeout);

            Assert.That(result.Success,
                        Is.True,
                        $"query {i + 1} of {associations} failed, so there is no source port to " +
                        $"judge: {result.ErrorMessage}");

        }

        var sourcePorts = probe.SourcePorts;

        Assert.That(sourcePorts, Is.Not.Empty, "no datagram reached the probe");

        Assert.Multiple(() => {

            Assert.That(sourcePorts,
                        Has.None.EqualTo((UInt16) 123),
                        "a client must not send from port 123 — RFC 9109 replaced that habit");

            Assert.That(sourcePorts.Where(port => port < 1024),
                        Is.Empty,
                        $"source ports below 1024 are assigned, not ephemeral: " +
                        $"{String.Join(", ", sourcePorts)}");

            Assert.That(sourcePorts.Count,
                        Is.GreaterThan(1),
                        $"{associations} separate clients all sent from port {sourcePorts[0]}, " +
                        $"so the port is being pinned rather than drawn per association");

        });

    }

}
