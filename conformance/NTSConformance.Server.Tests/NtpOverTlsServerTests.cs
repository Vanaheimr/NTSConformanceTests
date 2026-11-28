using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using NTSConformance.Core;
using NTSConformance.Core.Fixtures;
using NTSConformance.Core.RawNtp;
using NTSConformance.Core.RawNtpOverTls;

namespace NTSConformance.Server.Tests;

/// <summary>
/// Norn's server of NTP over TLS after chapter 7 of BSI TR-03109-5, held to the guideline by
/// this suite's NTP codec over the platform's own TLS - SChannel or OpenSSL, not the
/// BouncyCastle both ends of Norn run on.
///
/// <para>
/// Chapter 7 says what is in the 48 octets, chapter 6 how the connection is made: TLS 1.2 a
/// MUST (REQ.TA.TLS.Handshake.10), 1.3 a SHOULD with the fallback to 1.2
/// (REQ.TA.TLS.OpenHanSessionAsServer.10, REQ.TA.TLS.Handshake.180). The requests here are
/// both kinds Table 7.1 describes: the ordinary one of RFC 5905, and the minimized one its
/// note says "RFC5905-konforme NTP-Server akzeptieren".
/// </para>
/// </summary>
[TestFixture]
[Category(TestCategories.Loopback)]
public class NtpOverTlsServerTests
{

    #region (private) Start(...)

    private static Task<NTSServer> Start(TestCertificate?                                         certificate                 = null,
                                         RemoteTLSClientCertificateValidationHandler<NTSServer>?  clientCertificateValidator  = null)

        => FreePort.WithFreePorts(async (tcpPort, udpPort) => {

               IPPort tlsPort;

               using (var reservation = FreePort.ReserveTcp())
                   tlsPort = reservation.Port;

               var cert   = certificate ?? TestCertificate.Generate("ntp-tls.test", [ "ntp-tls.test", "localhost" ]);

               var server = new NTSServer(NTSKEPort:                             tcpPort,
                                          NTSPort:                               udpPort,
                                          MasterKeysFilePath:                    null,
                                          TLSCertificate:                        cert.Certificate,
                                          TLSPrivateKey:                         cert.PrivateKey,
                                          TLSCertificateChain:                   cert.IntermediateCertificates,
                                          NTPOverTLSPort:                        tlsPort,
                                          NTPOverTLSClientCertificateValidator:  clientCertificateValidator);

               await server.Start();

               return server;

           });

    private static Byte[] OrdinaryRequest(out UInt64 transmit)
    {
        var request = RawNtpPacket.ClientRequest();
        transmit    = request.TransmitTimestamp;
        return RawNtpWriter.WriteHeaderOnly(request);
    }

    /// <summary>
    /// Table 7.1's column "Datenminimierung": version 4, mode 3, precision 32, a random transmit
    /// timestamp, and zero everywhere else.
    /// </summary>
    private static Byte[] MinimizedRequest(out UInt64 transmit)
    {

        transmit = BitConverter.ToUInt64(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)) | 1;

        return RawNtpWriter.WriteHeaderOnly(new RawNtpPacket {
                                                Version            = 4,
                                                Mode               = RawNtpMode.Client,
                                                Precision          = 32,
                                                TransmitTimestamp  = transmit
                                            });

    }

    private static RawNtpPacket Read(Byte[] response)
    {
        Assert.That(response, Has.Length.EqualTo(48), "a response of 48 octets");
        Assert.That(RawNtpReader.TryRead(response, out var packet, out var error), Is.True, error);
        return packet!;
    }

    #endregion


    #region AnOrdinaryAndAMinimizedRequest_AreAnswered(...)

    /// <summary>
    /// § 7.2.2 and Table 7.1: a response of 48 octets, of version 4 and mode 4, that echoes the
    /// request's transmit timestamp as its origin, from a synchronized server, with a receive
    /// timestamp no later than its transmit timestamp - and both near this machine's clock.
    /// </summary>
    [Test]
    public async Task AnOrdinaryAndAMinimizedRequest_AreAnswered([Values] Boolean minimized,
                                                                [Values(SslProtocols.Tls12, SslProtocols.Tls13)] SslProtocols protocol)
    {

        var server = await Start();

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16(), protocol);

            Assert.That(connection.Protocol, Is.EqualTo(protocol));

            var request  = minimized ? MinimizedRequest(out var transmit) : OrdinaryRequest(out transmit);
            var response = Read(await connection.ExchangeAsync(request));

            Assert.That(response.Version,             Is.EqualTo(4));
            Assert.That(response.Mode,                Is.EqualTo(RawNtpMode.Server));
            Assert.That(response.LeapIndicator,       Is.Not.EqualTo(RawNtpLeapIndicator.Unsynchronized));
            Assert.That(response.Stratum,             Is.InRange(1, 15));
            Assert.That(response.OriginTimestamp,     Is.EqualTo(transmit), "the origin is the request's transmit timestamp");
            Assert.That(response.ReceiveTimestamp,    Is.LessThanOrEqualTo(response.TransmitTimestamp));
            Assert.That(response.ExtensionFields,     Is.Empty);

            var serverTime = RawNtpTimestamp.ToDateTime(response.TransmitTimestamp, RawNtpTimestamp.EraFor(DateTime.UtcNow));

            Assert.That((serverTime - DateTime.UtcNow).Duration(), Is.LessThan(TimeSpan.FromSeconds(5)));

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

    #region OldTLS_IsRefused()

    /// <summary>
    /// Nothing below TLS 1.2: TR-03116-4, which chapter 6 refers to, allows 1.2 and 1.3 alone.
    /// </summary>
    [Test]
    public async Task OldTLS_IsRefused()
    {

        var server = await Start();

        try
        {

#pragma warning disable SYSLIB0039 // TLS 1.0 and 1.1 are obsolete - which is what is asked here
            Assert.That(async () => await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16(), SslProtocols.Tls11),
                        Throws.InstanceOf<Exception>());
#pragma warning restore SYSLIB0039

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

    #region NoApplicationProtocol_IsNeeded_AndNoneIsSelected()

    /// <summary>
    /// The guideline names no ALPN identifier. A client that offers none is answered, and one
    /// that offers some is not told one was selected.
    /// </summary>
    [Test]
    public async Task NoApplicationProtocol_IsNeeded_AndNoneIsSelected()
    {

        var server = await Start();

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16(),
                                                                                   alpn: [ new SslApplicationProtocol("ntp") ]);

            Assert.That(connection.Tls.NegotiatedApplicationProtocol.Protocol.Length, Is.Zero);
            Assert.That(Read(await connection.ExchangeAsync(OrdinaryRequest(out _))).Mode, Is.EqualTo(RawNtpMode.Server));

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

    #region AnRsaCertificate_IsServedOverTLS12AsWell()

    /// <summary>
    /// A server of an RSA key over TLS 1.2: an ECDHE_RSA suite, not one of ECDSA it could not
    /// sign for.
    /// </summary>
    [Test]
    public async Task AnRsaCertificate_IsServedOverTLS12AsWell()
    {

        var server = await Start(TestCertificate.Generate("ntp-tls.test", [ "ntp-tls.test", "localhost" ], keyType: TestCertificateKeyType.Rsa2048));

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16(), SslProtocols.Tls12);

            Assert.That(Read(await connection.ExchangeAsync(OrdinaryRequest(out _))).Mode, Is.EqualTo(RawNtpMode.Server));

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

    #region TheConfiguredCertificate_IsShown()

    [Test]
    public async Task TheConfiguredCertificate_IsShown()
    {

        var certificate = TestCertificate.Generate("smgw.ntp-tls.test", [ "smgw.ntp-tls.test" ]);
        var server      = await Start(certificate);

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16(), targetHost: "smgw.ntp-tls.test");

            Assert.That(connection.ServerCertificate?.Thumbprint, Is.EqualTo(certificate.ToDotNet().Thumbprint));

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

    #region OneConnection_CarriesSeveralRequests()

    [Test]
    public async Task OneConnection_CarriesSeveralRequests()
    {

        var server = await Start();

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16());

            for (var i = 0; i < 3; i++)
            {
                var response = Read(await connection.ExchangeAsync(MinimizedRequest(out var transmit)));
                Assert.That(response.OriginTimestamp, Is.EqualTo(transmit), $"request {i + 1}");
            }

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

    #region WhatIsNoClientRequest_IsNotAnswered(...)

    /// <summary>
    /// Only a client request is answered (RFC 5905 § 9.2), and no NTPv5: the guideline knows
    /// NTPv4 alone. A server's own response, a symmetric or a broadcast packet, or an NTPv5
    /// header get no answer, and the connection ends.
    /// </summary>
    [Test]
    public async Task WhatIsNoClientRequest_IsNotAnswered([Values(RawNtpMode.SymmetricActive, RawNtpMode.Server, RawNtpMode.Broadcast)] Byte mode)
    {

        var server = await Start();

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16());

            var packet   = RawNtpPacket.ClientRequest();
            packet.Mode  = mode;

            Assert.That(await connection.ExchangeAsync(RawNtpWriter.WriteHeaderOnly(packet)), Is.Empty);
            Assert.That(server.Metrics.NTPOverTLSResponsesSent, Is.Zero);

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    [Test]
    public async Task AnNtpV5Header_IsNotAnswered()
    {

        var server = await Start();

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16());

            var request = new Byte[48];
            request[0]  = (5 << 3) | 3;   // NTPv5, mode 3

            Assert.That(await connection.ExchangeAsync(request), Is.Empty);

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

    #region AClientCertificate_WhereOneIsRequired(...)

    /// <summary>
    /// A server told to judge client certificates answers a client that shows one it accepts,
    /// and no client that shows none.
    /// </summary>
    [Test]
    public async Task AClientWithoutCertificate_GetsNoTime_WhereOneIsRequired([Values(SslProtocols.Tls12, SslProtocols.Tls13)] SslProtocols protocol)
    {

        var server = await Start(clientCertificateValidator: (sender, certificate, chain, ntsServer, errors) => TLSValidationResult.Success());

        try
        {

            Byte[]? response = null;

            try
            {
                await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16(), protocol);
                response = await connection.ExchangeAsync(OrdinaryRequest(out _));
            }
            catch (Exception e) when (e is AuthenticationException or IOException)
            {
                // TLS 1.2 ends the handshake; TLS 1.3 may let the client think it is complete
                // and send the alert after its Finished - both are a refusal.
            }

            Assert.That(response ?? [], Is.Empty, "no NTP response without a client certificate");
            Assert.That(server.Metrics.NTPOverTLSResponsesSent, Is.Zero);

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    [Test]
    public async Task AClientWithACertificate_IsAnswered_WhereOneIsRequired([Values(SslProtocols.Tls12, SslProtocols.Tls13)] SslProtocols protocol)
    {

        var clientCertificate = TestCertificate.Generate("cls-adapter.test", [ "cls-adapter.test" ]);
        String? seen          = null;

        var server = await Start(clientCertificateValidator: (sender, certificate, chain, ntsServer, errors) => {
                                     seen = certificate?.Subject;
                                     return TLSValidationResult.Success();
                                 });

        try
        {

            await using var connection = await RawNtpOverTlsConnection.ConnectAsync(server.NTPOverTLSPort!.Value.ToUInt16(),
                                                                                   protocol,
                                                                                   clientCertificate: clientCertificate.ToDotNetWithPrivateKey());

            Assert.That(Read(await connection.ExchangeAsync(OrdinaryRequest(out _))).Mode, Is.EqualTo(RawNtpMode.Server));
            Assert.That(seen, Is.EqualTo("CN=cls-adapter.test"));

        }
        finally
        {
            await server.ShutdownAsync();
        }

    }

    #endregion

}
