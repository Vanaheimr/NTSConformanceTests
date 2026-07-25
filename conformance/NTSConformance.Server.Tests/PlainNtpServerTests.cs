using NUnit.Framework;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;

namespace NTSConformance.Server.Tests;

/// <summary>
/// Plain NTPv4 against the NTS server — a client that never mentions NTS.
///
/// RFC 8915 §5.7's NTS NAK is for a request that <em>attempted</em> NTS and failed. A request
/// with no NTS extension field is an ordinary RFC 5905 request and must be answered as one.
///
/// This fixture exists because its absence hid a regression. The NAK was introduced for the
/// unusable-cookie case and keyed on "no valid cookie", which is also true of every plain NTP
/// request — so the server answered all of them with a Kiss-o'-Death and no plain NTP client
/// would use it. Nothing caught it: the chrony tests drove Norn's <em>client</em> against
/// chronyd's server, and no test had ever pointed a plain NTP client at Norn's.
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class PlainNtpServerTests
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


    /// <summary>Send raw octets and read the reply, with no Norn code on the client side.</summary>
    private RawNtpPacket Exchange(RawNtpPacket request)
    {

        if (fixture is null)
            throw new InvalidOperationException("the server fixture did not start");

        return RawNtpExchange.Exchange(request, "127.0.0.1", fixture.NTPPort);

    }


    /// <summary>
    /// A plain NTPv4 request must get a plain NTPv4 answer: mode 4, a usable stratum, and no
    /// Kiss-o'-Death. A KoD here tells the client the server is unusable and it will drop it.
    /// </summary>
    [Test]
    public void PlainRequest_IsAnsweredNormally()
    {

        var response = Exchange(RawNtpPacket.ClientRequest());

        Assert.Multiple(() => {

            Assert.That(response.Mode,    Is.EqualTo(RawNtpMode.Server), "a server reply is mode 4");
            Assert.That(response.Version, Is.EqualTo(4),                 "NTPv4");

            Assert.That(response.IsKissOfDeath,
                        Is.False,
                        $"a plain NTP request must not draw a Kiss-o'-Death — got stratum 0 " +
                        $"with kiss code '{response.KissCode}'. RFC 8915 §5.7's NAK is only for " +
                        "a request that attempted NTS.");

            Assert.That(response.Stratum, Is.InRange((Byte) 1, (Byte) 15), "a usable stratum");

        });

    }


    /// <summary>
    /// RFC 8915 §5.7: the NTS extension fields belong only to an NTS exchange. A plain reply
    /// must not carry a cookie or an authenticator — the client has no keys to read them with.
    /// </summary>
    [Test]
    public void PlainResponse_CarriesNoNtsExtensionFields()
    {

        var response = Exchange(RawNtpPacket.ClientRequest());

        Assert.That(response.ExtensionFields,
                    Is.Empty,
                    "a plain NTP response should carry no extension fields, but had: " +
                    String.Join(", ", response.ExtensionFields.Select(f => RawExtensionFieldTypes.Describe(f.FieldType))));

    }


    /// <summary>
    /// RFC 5905 §7.3: the Originate Timestamp must echo the request's Transmit Timestamp, and
    /// the receive and transmit timestamps must be set and ordered. This is what lets a client
    /// compute offset and delay at all.
    /// </summary>
    [Test]
    public void PlainResponse_CarriesUsableTimestamps()
    {

        var request  = RawNtpPacket.ClientRequest();
        var response = Exchange(request);

        Assert.Multiple(() => {

            Assert.That(response.OriginTimestamp,
                        Is.EqualTo(request.TransmitTimestamp),
                        "the origin timestamp must echo the request's transmit timestamp");

            Assert.That(response.ReceiveTimestamp,  Is.Not.EqualTo(0UL), "the receive timestamp");
            Assert.That(response.TransmitTimestamp, Is.Not.EqualTo(0UL), "the transmit timestamp");

            Assert.That(response.ReceiveTimestamp,
                        Is.LessThanOrEqualTo(response.TransmitTimestamp),
                        "a packet cannot be sent before it was received");

            Assert.That(response.ReferenceTimestamp,
                        Is.Not.EqualTo(0UL),
                        "RFC 5905 §7.3: a synchronized server reports when its clock was last set");

        });

    }


    /// <summary>
    /// The clock characteristics must be present on the plain path too. A client applies the
    /// same §11.3 root-distance arithmetic whether or not NTS was used, so the plain and
    /// NTS-protected replies have to describe the same clock.
    /// </summary>
    [Test]
    public void PlainResponse_DescribesTheServersClock()
    {

        var response = Exchange(RawNtpPacket.ClientRequest());

        Assert.Multiple(() => {

            Assert.That(response.ReferenceIdentifier,
                        Is.Not.EqualTo(new Byte[4]).AsCollection,
                        "the reference identifier should name where the time comes from");

            Assert.That(response.RootDispersion,
                        Is.Not.EqualTo(0U),
                        "a root dispersion of exactly zero claims a perfect clock");

            Assert.That(response.Precision,
                        Is.LessThan((SByte) 0),
                        "the precision exponent should describe a sub-second clock resolution");

        });

    }


    /// <summary>
    /// A request that does attempt NTS but carries no usable cookie must still draw the NAK —
    /// the plain-NTP path must not have swallowed that.
    /// </summary>
    [Test]
    public void RequestAttemptingNtsWithoutACookie_StillDrawsTheNak()
    {

        var request = RawNtpPacket.ClientRequest();
        request.ExtensionFields.Add(RawNtsExtensionFields.RandomUniqueIdentifier());

        var response = Exchange(request);

        Assert.Multiple(() => {

            Assert.That(response.IsKissOfDeath, Is.True,
                        "a request carrying an NTS extension field but no cookie must draw a NAK");

            Assert.That(response.KissCode, Is.EqualTo("NTSN"),
                        "RFC 8915 §5.7 specifies the kiss code NTSN");

        });

    }

}
