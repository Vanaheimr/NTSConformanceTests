using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.Client.Tests;

/// <summary>
/// A monitoring client obeying RFC 5905 § 7.4, which is the point at which obeying it costs
/// something.
///
/// <para>
/// Recognizing a kiss code changes nothing on its own. RFC 8633 § 5.4 is addressed to devices
/// that poll on a schedule — "It is RECOMMENDED that all NTP devices respect these packets and
/// back off when asked to do so by a server" — and a monitoring drone measuring a public server
/// every minute is precisely the client an operator sends a RATE kiss to. It is also the client
/// with the strongest reason to ignore one, since a skipped round is a gap in its own data.
/// </para>
/// <para>
/// So what has to be true is that the packets stop, not merely that the results are discarded.
/// A round that queried anyway and threw the answer away would look identical from inside and be
/// exactly the behaviour § 7.4 forbids.
/// </para>
/// </summary>
[TestFixture]
public class MeasurementEngineKissTests
{

    /// <summary>
    /// RFC 2606 reserves <c>.invalid</c>, so nothing here can resolve and no packet can leave
    /// this machine even if the engine were to try — which is itself part of what is asserted:
    /// a skip has to happen before the DNS lookup, not after it.
    /// </summary>
    private static readonly DomainName Unreachable = DomainName.Parse("norn-kiss-of-death.invalid");


    private static (MeasurementEngine Engine, NTSServerEndpoint Server) Engine(Boolean respectKissOfDeath = true)
    {

        var server  = new NTSServerEndpoint(Unreachable);

        var config  = new MonitoringConfig {
                          RespectKissOfDeath = respectKissOfDeath
                      };

        config.Servers.Add(server);

        return (new MeasurementEngine(config), server);

    }


    /// <summary>
    /// After a "DENY", the engine stops querying that server.
    /// </summary>
    [Test]
    public async Task AfterADenyKiss_TheEngineStopsQueryingThatServer()
    {

        var (engine, server) = Engine();

        engine.AccessStateFor(server.Hostname).
            Apply(new NTPKissOfDeath("DENY", 4), DateTimeOffset.UtcNow);

        var result = await engine.MeasureSingleServer(server, Guid.NewGuid(), new DNSClient());

        Assert.Multiple(() => {

            Assert.That(result.Skipped,
                        Is.True,
                        "the round has to record that it did not ask, rather than that the " +
                        "server did not answer");

            Assert.That(result.ErrorCategory,
                        Is.EqualTo(MonitoringErrorCategory.KissOfDeath));

            Assert.That(result.DNS,
                        Is.Null,
                        "and it has to stop before the name lookup — § 7.4 a says stop sending " +
                        "packets to that server, which starts earlier than the NTP query");

        });

    }


    /// <summary>
    /// After a "RATE", the engine waits out the interval the server asked for, then measures.
    /// </summary>
    /// <remarks>
    /// The second half is the interesting one. A back-off that never expires is a demobilization
    /// under another name, and "RATE" does not mean that: the server is asking for less, not for
    /// nothing.
    /// </remarks>
    [Test]
    public async Task AfterARateKiss_TheEngineWaitsOutTheIntervalAndThenMeasuresAgain()
    {

        var (engine, server) = Engine();

        var state  = engine.AccessStateFor(server.Hostname);

        // Poll 4 is sixteen seconds, so the wait is short enough to step over rather than sit
        // through: the state is driven from a time the caller supplies.
        state.Apply(new NTPKissOfDeath("RATE", 4), DateTimeOffset.UtcNow - TimeSpan.FromHours(1));

        var result = await engine.MeasureSingleServer(server, Guid.NewGuid(), new DNSClient());

        Assert.Multiple(() => {

            Assert.That(state.PollExponent,
                        Is.EqualTo(5),
                        "the kiss asked for 4 and the client was already there, so § 7.4 b's " +
                        "'continue to reduce' takes it one step further");

            Assert.That(result.Skipped,
                        Is.False,
                        "an hour has passed since a thirty-two second back-off, so this round " +
                        "should have gone ahead");

        });

    }


    /// <summary>
    /// A round inside the back-off is skipped.
    /// </summary>
    [Test]
    public async Task InsideTheBackoff_TheRoundIsSkipped()
    {

        var (engine, server) = Engine();

        engine.AccessStateFor(server.Hostname).
            Apply(new NTPKissOfDeath("RATE", 13), DateTimeOffset.UtcNow);

        var result = await engine.MeasureSingleServer(server, Guid.NewGuid(), new DNSClient());

        Assert.That(result.Skipped, Is.True);

    }


    /// <summary>
    /// With the behaviour switched off, the engine measures regardless.
    /// </summary>
    /// <remarks>
    /// Which is also what shows the assertions above are detecting the kiss handling rather than
    /// the engine failing for its own reasons: an unreachable host fails either way, and only
    /// <see cref="NTSMeasurementResult.Skipped"/> tells the two apart.
    /// </remarks>
    [Test]
    public async Task WithTheBehaviourSwitchedOff_TheEngineMeasuresAnyway()
    {

        var (engine, server) = Engine(respectKissOfDeath: false);

        engine.AccessStateFor(server.Hostname).
            Apply(new NTPKissOfDeath("DENY", 4), DateTimeOffset.UtcNow);

        var result = await engine.MeasureSingleServer(server, Guid.NewGuid(), new DNSClient());

        Assert.Multiple(() => {

            Assert.That(result.Skipped,
                        Is.False,
                        "an operator investigating their own server has said to measure anyway");

            Assert.That(result.Success,
                        Is.False,
                        "it still fails, because the host does not resolve — which is the point: " +
                        "a failure and a skip are different outcomes");

        });

    }

}
