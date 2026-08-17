using System.Net;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core.RawNtp;

/// <summary>
/// One plain UDP request/response against an NTP server, with no Norn code on the client side:
/// the packet leaves exactly as written and comes back as raw octets to be read by this suite's
/// own reader.
/// </summary>
public static class RawNtpExchange
{

    /// <summary>
    /// Send a packet and read the reply.
    /// </summary>
    /// <param name="request">The packet to send, malformed or not.</param>
    /// <param name="host">The server's address — a literal, so no name resolution is involved.</param>
    /// <param name="port">The server's UDP port.</param>
    /// <param name="addressFamily">
    /// Which family to send from. It has to be stated rather than inferred, because reaching an
    /// IPv6 listener needs an IPv6 socket even when the address is loopback.
    /// </param>
    /// <param name="timeout">How long to wait for the reply.</param>
    public static RawNtpPacket Exchange(RawNtpPacket    request,
                                        String          host,
                                        IPPort          port,
                                        AddressFamily?  addressFamily   = null,
                                        TimeSpan?       timeout         = null)

        => TryExchange(request, host, port, addressFamily, timeout)
               ?? throw new SocketException((Int32) SocketError.TimedOut);


    /// <summary>
    /// Send a packet and read the reply, or return null if none comes.
    /// </summary>
    /// <remarks>
    /// Silence is a result rather than a failure here, because for some of what this suite
    /// checks silence is the correct behaviour: a rate-limited request is meant to be dropped,
    /// and RFC 8633 § 5.4's advice to be sparing with Kiss-o'-Death packets means most refusals
    /// arrive as nothing at all. Waiting for a reply that should never come is slow, so keep the
    /// timeout short when that is the expected outcome.
    /// </remarks>
    public static RawNtpPacket? TryExchange(RawNtpPacket    request,
                                            String          host,
                                            IPPort          port,
                                            AddressFamily?  addressFamily   = null,
                                            TimeSpan?       timeout         = null)
    {

        var family    = addressFamily ?? AddressFamily.InterNetwork;

        using var udp = new UdpClient(family);

        udp.Client.ReceiveTimeout = (Int32) (timeout ?? TimeSpan.FromSeconds(5)).TotalMilliseconds;
        udp.Connect(host, port.ToUInt16());
        udp.Send(RawNtpWriter.Write(request));

        var remote    = new IPEndPoint(family == AddressFamily.InterNetworkV6
                                           ? IPAddress.IPv6Any
                                           : IPAddress.Any,
                                       0);

        Byte[] received;

        try
        {
            received = udp.Receive(ref remote);
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.TimedOut
                                                          or SocketError.ConnectionReset)
        {
            // ConnectionReset as well as TimedOut: on Windows a connected UDP socket surfaces an
            // ICMP port-unreachable as a receive error, which is the same "no answer" from this
            // side of the exchange.
            return null;
        }

        if (!RawNtpReader.TryRead(received, out var response, out var errorResponse, RawNtpReadOptions.Lenient))
            throw new InvalidOperationException($"the response could not be read: {errorResponse}\n{Bytes.Dump(received)}");

        return response!;

    }

}
