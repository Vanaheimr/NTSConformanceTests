using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Server.Tests;

/// <summary>
/// Which local addresses the server listens on, and whether a client on each address family can
/// actually reach it.
///
/// The address is configured as a Hermod <see cref="IIPAddress"/>, so <c>IPvXAddress.Any</c>
/// expresses "both families" as one value rather than leaving the caller to know that
/// <c>IPv6Any</c> plus dual mode happens to mean that.
///
/// These tests are not about the type, though — they are about the socket layer underneath it.
/// An IPv6 listener has to be receiving through an IPv6 wildcard endpoint: the receive call
/// rejects an endpoint from the wrong family outright, so an IPv4 wildcard left over from an
/// IPv4-only server takes down the entire receive loop on the first datagram, and every request
/// simply times out with nothing in the log to say why.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ServerListenAddressTests
{

    /// <summary>
    /// A host without IPv6 cannot bind the listener at all, which is an absent prerequisite
    /// rather than a defect.
    /// </summary>
    private static void RequireIPv6()
    {
        if (!Socket.OSSupportsIPv6)
            Assert.Ignore("this host has no IPv6 support — skipping.");
    }


    /// <summary>
    /// Unconfigured, the server listens on the IPv4 wildcard. Serving both families needs a
    /// working IPv6 stack to bind at all, so it stays an explicit request.
    /// </summary>
    [Test]
    public async Task DefaultListenAddress_IsTheIPv4Wildcard()
    {

        await using var fixture = await NornServerFixture.StartAsync();

        Assert.Multiple(() => {
            Assert.That(fixture.Server.ListenIPAddress.IsAny,  Is.True,  "the default is a wildcard address");
            Assert.That(fixture.Server.ListenIPAddress.IsIPv4, Is.True,  "…in the IPv4 family");
            Assert.That(fixture.Server.ListenIPAddress.IsIPv6, Is.False, "…and not IPv6, which might not bind");
        });

    }


    /// <summary>
    /// A dual-stack listener answers an IPv4 client. Worth stating separately from the IPv6 case:
    /// if the receive loop dies on its wildcard endpoint, both families fail together, and only
    /// checking both shows the listener is genuinely serving two families rather than one.
    /// </summary>
    [Test]
    public async Task DualStackListener_AnswersAnIPv4Client()
    {

        RequireIPv6();

        await using var fixture = await NornServerFixture.StartAsync(listenIPAddress: IPvXAddress.Any);

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(),
                                               "127.0.0.1",
                                               fixture.NTPPort);

        Assert.Multiple(() => {
            Assert.That(response.Mode,          Is.EqualTo(RawNtpMode.Server));
            Assert.That(response.IsKissOfDeath, Is.False);
        });

    }


    /// <summary>
    /// The same listener answers an IPv6 client. This is the case that fails when the receive
    /// endpoint's family does not match the socket's.
    /// </summary>
    [Test]
    public async Task DualStackListener_AnswersAnIPv6Client()
    {

        RequireIPv6();

        await using var fixture = await NornServerFixture.StartAsync(listenIPAddress: IPvXAddress.Any);

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(),
                                               "::1",
                                               fixture.NTPPort,
                                               AddressFamily.InterNetworkV6);

        Assert.Multiple(() => {
            Assert.That(response.Mode,          Is.EqualTo(RawNtpMode.Server));
            Assert.That(response.IsKissOfDeath, Is.False);
        });

    }


    /// <summary>
    /// An explicit IPv6 wildcard behaves the same way — the dual-stack default lets it serve
    /// IPv4 too, so the distinction is which family the socket belongs to, not who may connect.
    /// </summary>
    [Test]
    public async Task IPv6WildcardListener_AnswersAnIPv6Client()
    {

        RequireIPv6();

        await using var fixture = await NornServerFixture.StartAsync(listenIPAddress: IPv6Address.Any);

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(),
                                               "::1",
                                               fixture.NTPPort,
                                               AddressFamily.InterNetworkV6);

        Assert.That(response.Mode, Is.EqualTo(RawNtpMode.Server));

    }


    /// <summary>
    /// Binding the loopback address only still serves loopback clients. The point is that a
    /// specific address is accepted and used, not just the wildcards.
    /// </summary>
    [Test]
    public async Task LoopbackListener_AnswersALoopbackClient()
    {

        await using var fixture = await NornServerFixture.StartAsync(listenIPAddress: IPv4Address.Localhost);

        var response = RawNtpExchange.Exchange(RawNtpPacket.ClientRequest(),
                                               "127.0.0.1",
                                               fixture.NTPPort);

        Assert.Multiple(() => {
            Assert.That(fixture.Server.ListenIPAddress.IsLocalhost, Is.True);
            Assert.That(response.Mode,                              Is.EqualTo(RawNtpMode.Server));
        });

    }

}
