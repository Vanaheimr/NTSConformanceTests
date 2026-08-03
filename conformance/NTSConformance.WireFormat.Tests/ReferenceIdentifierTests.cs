using NUnit.Framework;

using NTSConformance.Core;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTP;

namespace NTSConformance.WireFormat.Tests;

/// <summary>
/// RFC 5905 §7.3, the Reference Identifier — four octets whose meaning depends entirely on
/// the stratum beside them.
///
/// At stratum 1 they are an ASCII name for the reference clock, at stratum 0 a Kiss-o'-Death
/// code, and from stratum 2 upwards they identify the server this one synchronizes to: the
/// IPv4 address verbatim, or for IPv6 "the first 32 bits of the MD5 hash of the IPv6 or NSAP
/// address".
///
/// The IPv6 case is the one worth testing. It is the only reference identifier that is
/// computed rather than copied, and its whole purpose — loop detection, so a server does not
/// end up synchronizing to something that synchronizes to it — depends on two independent
/// implementations deriving the same 32 bits from the same address. A digest over the textual
/// form, or over the address in the wrong order, produces a perfectly plausible-looking
/// identifier that agrees with nobody.
/// </summary>
[TestFixture]
public class ReferenceIdentifierTests
{

    #region IPv6 (RFC 5905 §7.3)

    /// <summary>
    /// Known answers, computed outside this codebase from the 16 binary octets of each
    /// address — <c>md5(inet_pton(AF_INET6, address))[0:4]</c> — rather than by running the
    /// code under test and recording what it said.
    /// </summary>
    private static readonly (String Address, Byte[] Expected)[] knownAnswers = [
        ("2001:db8::1",           [ 0x39, 0xAB, 0x9B, 0x37 ]),
        ("2001:db8::2",           [ 0x2D, 0x47, 0xFD, 0x05 ]),
        ("fe80::1",               [ 0x89, 0xE5, 0x30, 0x1F ]),
        ("::1",                   [ 0xCF, 0x40, 0x4D, 0xC8 ]),
        ("2001:4860:4860::8888",  [ 0x46, 0x91, 0x74, 0xC1 ])
    ];


    /// <summary>
    /// The identifier is the first four octets of the MD5 digest over the address's sixteen
    /// binary octets, in network order.
    /// </summary>
    [Test]
    public void IPv6ReferenceIdentifier_MatchesTheKnownAnswers()
    {

        Assert.Multiple(() => {

            foreach (var (address, expected) in knownAnswers)
            {

                var peerId = NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse(address)).ToArray();

                Assert.That(peerId,
                            Is.EqualTo(expected).AsCollection,
                            $"{address}: {Bytes.Diff(expected, peerId)}");

            }

        });

    }


    /// <summary>
    /// Four octets exactly. The field is 32 bits wide, and a digest truncated at the wrong
    /// end — or not truncated at all — would overrun the header.
    /// </summary>
    [Test]
    public void IPv6ReferenceIdentifier_IsFourOctets()
    {

        Assert.Multiple(() => {

            foreach (var (address, _) in knownAnswers)
                Assert.That(NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse(address)).Length,
                            Is.EqualTo(4),
                            $"{address} must yield exactly the 32 bits the field holds");

        });

    }


    /// <summary>
    /// The digest is taken over the address, not over the way it happens to be written.
    /// <c>2001:db8::1</c> and its fully expanded form are the same sixteen octets, and a
    /// server that hashed the string would identify the same peer two different ways —
    /// defeating the loop detection this identifier exists for.
    /// </summary>
    [Test]
    public void IPv6ReferenceIdentifier_IsIndependentOfHowTheAddressIsWritten()
    {

        var compressed = NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse("2001:db8::1")).ToArray();
        var expanded   = NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse("2001:0db8:0000:0000:0000:0000:0000:0001")).ToArray();

        Assert.That(expanded,
                    Is.EqualTo(compressed).AsCollection,
                    "the two spellings are the same address, so they are the same peer");

    }


    /// <summary>
    /// The whole address goes into the digest. Two addresses differing only in the final
    /// octet — the common case for neighbours in one subnet, which is precisely when loop
    /// detection is needed — must not collide.
    ///
    /// This is what catches a digest taken over a prefix, or over an address truncated to
    /// four or eight octets.
    /// </summary>
    [Test]
    public void IPv6ReferenceIdentifier_CoversTheWholeAddress()
    {

        var first  = NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse("2001:db8::1")).ToArray();
        var second = NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse("2001:db8::2")).ToArray();

        Assert.That(second,
                    Is.Not.EqualTo(first).AsCollection,
                    "two addresses in the same subnet must not share a reference identifier");

    }


    /// <summary>
    /// It is a digest, not a slice. An identifier that turned out to be the first or last four
    /// octets of the address itself would leak the peer's address into every packet and would
    /// collide across every host sharing a prefix — the failure that hashing prevents.
    /// </summary>
    [Test]
    public void IPv6ReferenceIdentifier_IsNotAPieceOfTheAddress()
    {

        const String address = "2001:4860:4860::8888";

        var peerId   = NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse(address)).ToArray();
        var octets   = IPv6Address.Parse(address).GetBytes();

        Assert.Multiple(() => {

            Assert.That(peerId,
                        Is.Not.EqualTo(octets.Take(4).ToArray()).AsCollection,
                        "the identifier is a digest, not the leading octets of the address");

            Assert.That(peerId,
                        Is.Not.EqualTo(octets.Skip(12).ToArray()).AsCollection,
                        "nor the trailing ones");

        });

    }


    /// <summary>
    /// The identifier travels in the header like any other, so whatever the digest produces
    /// has to survive the round trip through the four octets of the field.
    /// </summary>
    [Test]
    public void IPv6ReferenceIdentifier_SurvivesTheHeaderRoundTrip()
    {

        var peerId    = NTPPacketExtensions.GetNTPPeerId(IPv6Address.Parse("2001:db8::1")).ToArray();
        var recovered = ReferenceIdentifier.From(peerId);

        Assert.That(recovered.AsBytes,
                    Is.EqualTo(peerId).AsCollection,
                    Bytes.Diff(peerId, recovered.AsBytes));

    }

    #endregion

    #region IPv4 (RFC 5905 §7.3)

    /// <summary>
    /// The IPv4 case, for contrast: the address itself, in network order, not a digest of it.
    /// Kept here because the two rules are one sentence apart in §7.3 and confusing them
    /// yields an identifier that is well-formed and wrong.
    /// </summary>
    [Test]
    public void IPv4ReferenceIdentifier_IsTheAddressItself()
    {

        var referenceIdentifier = ReferenceIdentifier.From(192, 0, 2, 123);

        Assert.Multiple(() => {

            Assert.That(referenceIdentifier.AsBytes,
                        Is.EqualTo(new Byte[] { 192, 0, 2, 123 }).AsCollection,
                        "the four octets are the address, in network order");

            Assert.That(referenceIdentifier.AsIPv4Address?.ToString(),
                        Is.EqualTo("192.0.2.123"));

        });

    }

    #endregion

}
