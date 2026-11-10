using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.RawNtp;

using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.CLI.Tests;

/// <summary>
/// <c>norn serve</c>: a server started from the command line and asked the time by something
/// that is not Norn.
///
/// <para>
/// The rest of this suite starts servers by constructing <c>NTSServer</c> in-process, which
/// leaves everything between a command line and a listening socket untested — port options,
/// address binding, the policy flags, and whether the thing shuts down when interrupted. Those
/// are the parts an operator meets first.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class ServeTests
{

    /// <summary>
    /// Start the tool as a server on free ports and wait until it says it is listening.
    /// </summary>
    /// <remarks>
    /// Retried on a lost port race for the same reason <see cref="FreePort.WithFreePorts"/> is:
    /// the ports have to be chosen before the process starts and released before it binds them,
    /// and something else can take one in between.
    /// </remarks>
    private static (NornProcess Server, IPPort NTPPort, IPPort NTSKEPort) Serve(params String[] extraArguments)
    {

        for (var attempt = 1; ; attempt++)
        {

            IPPort kePort;
            IPPort ntpPort;

            using (var tcp = FreePort.ReserveTcp())
            using (var udp = FreePort.ReserveUdp())
            {
                kePort   = tcp.Port;
                ntpPort  = udp.Port;
            }

            var server = Norn.Start([ "serve",
                                      "--listen",  "127.0.0.1",
                                      "--port",    ntpPort.ToString(),
                                      "--ke-port", kePort.ToString(),
                                      .. extraArguments ]);

            if (server.WaitForOutput("Ctrl-C to stop."))
                return (server, ntpPort, kePort);

            var transcript = server.Snapshot;
            server.Dispose();

            if (attempt >= 5)
                Assert.Fail($"the server never reported itself listening:\n{transcript}");

            Thread.Sleep(50 * attempt);

        }

    }


    /// <summary>
    /// A server started from the command line answers a plain NTP request.
    /// </summary>
    /// <remarks>
    /// Asked by this suite's own raw client rather than by <c>norn query</c>, so that a mistake
    /// shared by both sides of Norn cannot make the test pass.
    /// </remarks>
    [Test]
    public void Serve_AnswersOnThePortItWasGiven()
    {

        var (server, ntpPort, _) = Serve();

        using (server)
        {

            var response = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(),
                                                      "127.0.0.1",
                                                      ntpPort,
                                                      timeout: TimeSpan.FromSeconds(5));

            Assert.That(response, Is.Not.Null,
                        $"nothing came back from 127.0.0.1:{ntpPort}\n{server.Snapshot}");

            Assert.Multiple(() => {
                Assert.That(response!.Mode,          Is.EqualTo(RawNtpMode.Server));
                Assert.That(response.IsKissOfDeath,  Is.False);
                Assert.That(response.Stratum,        Is.InRange((Byte) 1, (Byte) 15));
            });

        }

    }


    /// <summary>
    /// <c>--stratum</c> and <c>--refid</c> reach the packets.
    /// </summary>
    /// <remarks>
    /// Two options whose whole effect is four bytes on the wire, and which nothing else would
    /// notice going astray: a server reporting the wrong stratum still answers, still measures
    /// correctly, and is simply believed less than it should be — or more.
    /// </remarks>
    [Test]
    public void Serve_ReportsTheStratumAndReferenceItWasGiven()
    {

        var (server, ntpPort, _) = Serve("--stratum", "2", "--refid", "GPS");

        using (server)
        {

            var response = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(),
                                                      "127.0.0.1",
                                                      ntpPort,
                                                      timeout: TimeSpan.FromSeconds(5));

            Assert.That(response, Is.Not.Null, server.Snapshot);

            Assert.Multiple(() => {

                Assert.That(response!.Stratum, Is.EqualTo(2));

                Assert.That(System.Text.Encoding.ASCII.GetString(response.ReferenceIdentifier).TrimEnd('\0'),
                            Is.EqualTo("GPS"));

            });

        }

    }


    /// <summary>
    /// <c>--rate-limit</c> reaches the limiter.
    /// </summary>
    [Test]
    public void Serve_RateLimitsWhenAskedTo()
    {

        var (server, ntpPort, _) = Serve("--rate-limit", "600", "--burst", "1");

        using (server)
        {

            var first  = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(), "127.0.0.1", ntpPort,
                                                    timeout: TimeSpan.FromSeconds(5));

            var second = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(), "127.0.0.1", ntpPort,
                                                    timeout: TimeSpan.FromSeconds(5));

            Assert.Multiple(() => {

                Assert.That(first?.IsKissOfDeath, Is.False,
                            $"the first request is inside the burst\n{server.Snapshot}");

                Assert.That(second?.KissCode, Is.EqualTo("RATE"),
                            $"the second is not\n{server.Snapshot}");

            });

        }

    }


    /// <summary>
    /// Without a rate limit the server answers everything, which is the default.
    /// </summary>
    /// <remarks>
    /// The control for the test above: it shows the kiss came from the option rather than from
    /// something a Norn server does anyway.
    /// </remarks>
    [Test]
    public void Serve_WithoutARateLimit_AnswersEverything()
    {

        var (server, ntpPort, _) = Serve();

        using (server)
        {

            for (var i = 0; i < 5; i++)
            {

                var response = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(), "127.0.0.1", ntpPort,
                                                          timeout: TimeSpan.FromSeconds(5));

                Assert.That(response?.IsKissOfDeath, Is.False,
                            $"request {i + 1} drew a kiss from a server with no limiter\n{server.Snapshot}");

            }

        }

    }


    /// <summary>
    /// <c>--deny</c> and <c>--allow</c> reach the access list of RFC 8633 § 5.1. Of two loopback
    /// addresses, the one allowed inside everything denied is answered and the other gets
    /// nothing, not even a kiss. And the server says at startup whom it serves.
    /// </summary>
    /// <remarks>
    /// All of 127.0.0.0/8 is loopback, so a client bound to 127.0.0.2 reaches the server on
    /// 127.0.0.1 from an address of its own. The server listens on IPv4 only here, so both
    /// addresses arrive as IPv4 addresses. AccessListTests in the server tests covers the
    /// dual-stack socket, where they do not.
    /// </remarks>
    [Test]
    public void Serve_AnswersOnlyTheAddressesItIsToldTo()
    {

        var secondLoopbackAddress = System.Net.IPAddress.Parse("127.0.0.2");

        try
        {
            using var probe = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(secondLoopbackAddress, 0));
        }
        catch (System.Net.Sockets.SocketException)
        {
            Assert.Ignore("this host does not route 127.0.0.2 to loopback, and the test needs a second client address — skipping.");
        }

        var (server, ntpPort, _) = Serve("--deny", "all", "--allow", "127.0.0.1");

        using (server)
        {

            var denied   = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(), "127.0.0.1", ntpPort,
                                                      timeout:       TimeSpan.FromSeconds(1),
                                                      localAddress:  secondLoopbackAddress);

            var allowed  = RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(), "127.0.0.1", ntpPort,
                                                      timeout:       TimeSpan.FromSeconds(5),
                                                      localAddress:  System.Net.IPAddress.Loopback);

            Assert.Multiple(() => {

                Assert.That(server.Snapshot,
                            Does.Contain("Access: deny 0.0.0.0/0, ::/0; allow 127.0.0.1/32"),
                            "the server should say whom it serves, in the words of the networks it was given");

                Assert.That(denied,
                            Is.Null,
                            $"127.0.0.2 is denied, and got {(denied?.IsKissOfDeath == true ? $"a {denied.KissCode} kiss" : "an answer")}\n{server.Snapshot}");

                Assert.That(allowed?.IsKissOfDeath,
                            Is.False,
                            $"127.0.0.1 is allowed inside everything denied, and got {(allowed is null ? "nothing" : "a kiss")}\n{server.Snapshot}");

            });

        }

    }


    /// <summary>
    /// <c>--allow</c> without <c>--deny</c> is refused with the command line that was most
    /// likely meant.
    /// </summary>
    /// <remarks>
    /// By itself, an allowed network allows what every address is allowed anyway. An operator
    /// who writes <c>--allow 10.0.0.0/8</c> means to serve only that network. A server that took
    /// the option as written would serve everyone and look as if it served only that network.
    /// </remarks>
    [Test]
    public void Serve_AllowWithoutDeny_SaysWhatWasMeant()
    {

        var run = Norn.Run([ "serve", "--allow", "10.0.0.0/8" ], TimeSpan.FromSeconds(30));

        Assert.Multiple(() => {
            Assert.That(run.ExitCode, Is.EqualTo(2),                               run.Transcript);
            Assert.That(run.StdErr,   Does.Contain("--deny all --allow 10.0.0.0/8"), run.Transcript);
        });

    }


    /// <summary>
    /// The server reports what it is doing without being asked.
    /// </summary>
    /// <remarks>
    /// A server left running in a terminal that prints nothing at all cannot be distinguished
    /// from one that has stopped working — and the counters are what an operator would otherwise
    /// have to attach a packet capture to see.
    /// </remarks>
    [Test]
    public void Serve_ReportsItsCountersAsTheyChange()
    {

        var (server, ntpPort, _) = Serve();

        using (server)
        {

            RawNtpExchange.TryExchange(RawNtpPacket.ClientRequest(), "127.0.0.1", ntpPort,
                                       timeout: TimeSpan.FromSeconds(5));

            Assert.That(server.WaitForOutput("received:", TimeSpan.FromSeconds(10)),
                        Is.True,
                        $"the counters never appeared\n{server.Snapshot}");

        }

    }


    /// <summary>
    /// A port already in use is a clean failure, not a stack trace.
    /// </summary>
    [Test]
    public void Serve_OnATakenPort_FailsCleanly()
    {

        var (server, ntpPort, kePort) = Serve();

        using (server)
        {

            var second = Norn.Run([ "serve", "--listen", "127.0.0.1",
                                    "--port",    ntpPort.ToString(),
                                    "--ke-port", kePort.ToString() ],
                                  TimeSpan.FromSeconds(30));

            Assert.Multiple(() => {

                Assert.That(second.ExitCode, Is.EqualTo(1), second.Transcript);

                Assert.That(second.StdErr, Does.Contain("norn:"),
                            "and it should be a sentence rather than an exception");

                Assert.That(second.StdErr, Does.Not.Contain("   at "),
                            $"a stack trace is not an error message\n{second.Transcript}");

            });

        }

    }

}
