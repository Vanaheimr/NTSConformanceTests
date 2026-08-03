using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtsKe;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

namespace NTSConformance.NTSKE.Tests;

/// <summary>
/// RFC 8915 §4.1.8: "If no record of this type is sent, the client SHALL assume a default of
/// 123 (the registered port number for NTP)."
///
/// <para>
/// One sentence, and the only rule in the key exchange that says what to do about something
/// that is <em>not</em> in the response — which is why it goes untested. Every fixture pointing
/// a client at a server on a test port has an explicit port everywhere, so the default never
/// runs; and a client that got it wrong would still work in every such fixture.
/// </para>
/// <para>
/// The wrong answer that matters is 4460. A client is holding a TLS connection to the key
/// exchange when it reads this response, and reusing that connection's port for the time query
/// is the natural mistake — natural enough that it produces a client which works perfectly
/// against every server that does send the record, and silently queries the wrong port on every
/// server that does not.
/// </para>
/// <para>
/// Nothing here binds port 123. What is asserted is where the client addressed its datagram,
/// which needs no privileges and does not depend on what happens to be listening on the machine
/// running the tests.
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class PortNegotiationDefaultTests
{

    private NornServerFixture? fixture;


    [TearDown]
    public async Task StopServer()
    {

        if (fixture is not null)
            await fixture.DisposeAsync();

        fixture = null;

    }


    #region What the server sends

    /// <summary>
    /// A server advertising a host without a port sends the Server Negotiation record and no
    /// Port Negotiation record.
    /// </summary>
    /// <remarks>
    /// Read off the wire by this suite's own record decoder rather than through Norn's client,
    /// because everything below depends on this response having the shape the rule is about.
    /// A test asserting the client's behaviour against a response that turned out to carry a
    /// port record after all would be asserting nothing.
    /// </remarks>
    [Test]
    public async Task AServerAdvertisingNoPort_SendsNoPortNegotiationRecord()
    {

        fixture = await NornServerFixture.StartAsync(
                            certificate:          TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]),
                            externalHostName:     "127.0.0.1",
                            omitPortNegotiation:  true
                        );

        var exchange = await RawNtsKeClient.ExchangeAsync(
                                 "127.0.0.1",
                                 fixture.NTSKEPort,
                                 RawNtsKeCodec.ClientRequest()
                             );

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        Assert.Multiple(() => {

            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.Ntpv4ServerNegotiation).Count(),
                        Is.EqualTo(1),
                        $"§4.1.7: the host is advertised, and \"servers MUST NOT send more than " +
                        $"one record of this type\".\n{exchange}");

            Assert.That(exchange.RecordsOfType(RawNtsKeRecordTypes.Ntpv4PortNegotiation),
                        Is.Empty,
                        $"and no port record, which is the case §4.1.8's default is for.\n{exchange}");

        });

    }


    /// <summary>
    /// And the control: advertising a port does send the record.
    /// </summary>
    /// <remarks>
    /// Otherwise the test above passes just as well against a server that never sends a port
    /// record at all, and the fixture option it rests on would be doing nothing.
    /// </remarks>
    [Test]
    public async Task AServerAdvertisingAPort_SendsThePortNegotiationRecord()
    {

        fixture = await NornServerFixture.StartAsync(
                            certificate:       TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]),
                            externalHostName:  "127.0.0.1"
                        );

        var exchange = await RawNtsKeClient.ExchangeAsync(
                                 "127.0.0.1",
                                 fixture.NTSKEPort,
                                 RawNtsKeCodec.ClientRequest()
                             );

        Assert.That(exchange.HandshakeSucceeded, Is.True, exchange.ToString());

        var port = exchange.FirstRecordOfType(RawNtsKeRecordTypes.Ntpv4PortNegotiation);

        Assert.That(port, Is.Not.Null, $"the port record is missing.\n{exchange}");

        Assert.Multiple(() => {

            Assert.That(port!.Body.Length,
                        Is.EqualTo(2),
                        "§4.1.8: the body is a 16-bit unsigned integer");

            Assert.That((UInt16) ((port.Body[0] << 8) | port.Body[1]),
                        Is.EqualTo(fixture!.NTPPort.ToUInt16()),
                        "in network byte order, and naming the port this server listens on");

        });

    }

    #endregion


    #region What the client does about it

    /// <summary>
    /// Given no port record, the client addresses its query to 123.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The client is built without an NTP port, which is the situation the rule describes: a
    /// client with nothing configured, told where to go but not on which port. It has just held
    /// a TLS connection to the key exchange on a high port, so 123 can only have come from
    /// §4.1.8.
    /// </para>
    /// <para>
    /// The query fails, and that is fine — nothing is listening on 123 here, and the assertion
    /// is on the address it was sent to rather than on an answer. Binding 123 would need
    /// privileges on most systems and would collide with whatever time service the machine
    /// already runs.
    /// </para>
    /// </remarks>
    [Test]
    public async Task WithNoPortRecord_TheClientQueriesPort123()
    {

        fixture = await NornServerFixture.StartAsync(
                            certificate:          TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]),
                            externalHostName:     "127.0.0.1",
                            omitPortNegotiation:  true
                        );

        var client       = new NTSClient(
                               DomainName.Parse("127.0.0.1"),
                               NTSKE_Port:                  fixture.NTSKEPort,
                               // No NTP_Port at all. Supplying one is what every other fixture
                               // does, and it is exactly what would hide this.
                               IPVersionPreference:         IPVersionPreference.IPv4Only,
                               Timeout:                     TimeSpan.FromSeconds(2),
                               RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                                => TLSValidationResult.Success()
                           );

        var keyExchange  = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success, Is.True,
                    $"the key exchange itself failed: {keyExchange.ErrorMessage}");

        var result       = await client.QueryTime(NTSKEResponse: keyExchange.Response!);

        Assert.That(result.RemoteEndPoint,
                    Is.Not.Null,
                    $"the client never settled on an address to query.\n{result.ErrorMessage}");

        Assert.Multiple(() => {

            Assert.That(result.RemoteEndPoint!.Port,
                        Is.EqualTo(123),
                        $"§4.1.8 makes 123 the assumption when no port record arrives, but the " +
                        $"client addressed {result.RemoteEndPoint}");

            Assert.That(result.RemoteEndPoint.Port,
                        Is.Not.EqualTo(fixture!.NTSKEPort.ToUInt16()),
                        "and in particular not the key exchange's own port, which is the port " +
                        "it had a connection to when it read the response");

        });

    }


    /// <summary>
    /// A port record moves the query off 123, which is what shows the test above is about the
    /// absence of the record rather than about the constant.
    /// </summary>
    [Test]
    public async Task WithAPortRecord_TheClientQueriesThatPortInstead()
    {

        fixture = await NornServerFixture.StartAsync(
                            certificate:       TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]),
                            externalHostName:  "127.0.0.1"
                        );

        var client       = new NTSClient(
                               DomainName.Parse("127.0.0.1"),
                               NTSKE_Port:                  fixture.NTSKEPort,
                               IPVersionPreference:         IPVersionPreference.IPv4Only,
                               Timeout:                     TimeSpan.FromSeconds(5),
                               RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, policyErrors)
                                                                => TLSValidationResult.Success()
                           );

        var keyExchange  = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success, Is.True, keyExchange.ErrorMessage);

        var result       = await client.QueryTime(NTSKEResponse: keyExchange.Response!);

        Assert.Multiple(() => {

            Assert.That(result.RemoteEndPoint?.Port,
                        Is.EqualTo(fixture!.NTPPort.ToUInt16()),
                        "the advertised port, not the default");

            Assert.That(result.Success,
                        Is.True,
                        $"and there really is a server there: {result.ErrorMessage}");

        });

    }


    /// <summary>
    /// A locally configured port wins over §4.1.8's default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read literally, §4.1.8 says SHALL and says nothing about local configuration, so this
    /// deviates from the letter. It is what every implementation does and the only reading that
    /// makes sense: chrony has an <c>ntpport</c> directive for precisely this, and a client that
    /// overrode its operator's explicit setting with a protocol default would be unusable
    /// against any server on a non-standard port — which is every server in a test rig, and
    /// most behind a NAT.
    /// </para>
    /// <para>
    /// Pinned rather than left to chance, because it is a judgement call and the next reader of
    /// §4.1.8 will wonder whether it was one. What the rule governs is a client with nothing
    /// configured, and that client is covered above.
    /// </para>
    /// </remarks>
    [Test]
    public async Task AConfiguredPort_WinsOverTheDefault()
    {

        fixture = await NornServerFixture.StartAsync(
                            certificate:          TestCertificate.Generate("nts-ke.test", [ "nts-ke.test" ]),
                            externalHostName:     "127.0.0.1",
                            omitPortNegotiation:  true
                        );

        var client       = fixture.CreateClient(TimeSpan.FromSeconds(5));

        var keyExchange  = await client.GetNTSKERecords();

        Assert.That(keyExchange.Success, Is.True, keyExchange.ErrorMessage);

        var result       = await client.QueryTime(NTSKEResponse: keyExchange.Response!);

        Assert.Multiple(() => {

            Assert.That(result.RemoteEndPoint?.Port,
                        Is.EqualTo(fixture!.NTPPort.ToUInt16()),
                        "the port the client was configured with");

            Assert.That(result.Success,
                        Is.True,
                        $"and the query works, which is the point of honouring it: " +
                        $"{result.ErrorMessage}");

        });

    }

    #endregion

}
