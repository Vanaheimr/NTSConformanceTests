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

    /// <summary>Send a packet and read the reply.</summary>
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

        var received  = udp.Receive(ref remote);

        if (!RawNtpReader.TryRead(received, out var response, out var errorResponse, RawNtpReadOptions.Lenient))
            throw new InvalidOperationException($"the response could not be read: {errorResponse}\n{Bytes.Dump(received)}");

        return response!;

    }

}
