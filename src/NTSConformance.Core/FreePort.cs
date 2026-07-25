using System.Net;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core;

/// <summary>
/// A held port reservation. The underlying socket stays bound until <see cref="Dispose"/>,
/// which narrows — but cannot fully close — the window in which another process could
/// steal the port. Use <see cref="FreePort.WithFreePorts{T}"/> to get retry-on-conflict too.
/// </summary>
public sealed class PortReservation : IDisposable
{

    private readonly Socket socket;

    public IPPort Port { get; }

    internal PortReservation(Socket socket, Int32 port)
    {
        this.socket  = socket;
        this.Port    = IPPort.Parse(port);
    }

    public void Dispose()
    {
        try
        {
            socket.Close();
            socket.Dispose();
        }
        catch { /* already gone */ }
    }

}


/// <summary>
/// Ephemeral-port allocation for fixtures.
///
/// Norn's <c>NTSServer</c> takes its ports as constructor arguments and exposes no
/// "actually bound port" property, so it cannot bind port 0 and report back. Tests must
/// therefore pick a port first and hand it over — a time-of-check-to-time-of-use race.
/// This helper keeps the reservation socket alive as long as possible and retries the
/// whole start sequence when the race is nevertheless lost.
/// </summary>
public static class FreePort
{

    /// <summary>Reserve a free TCP port, holding it until the reservation is disposed.</summary>
    public static PortReservation ReserveTcp()
    {

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        return new PortReservation(socket, ((IPEndPoint) socket.LocalEndPoint!).Port);

    }


    /// <summary>Reserve a free UDP port, holding it until the reservation is disposed.</summary>
    public static PortReservation ReserveUdp()
    {

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        return new PortReservation(socket, ((IPEndPoint) socket.LocalEndPoint!).Port);

    }


    /// <summary>
    /// Reserve a TCP port (NTS-KE) and a UDP port (NTP), release them, and invoke
    /// <paramref name="start"/>. If binding races with another process, retry with a
    /// fresh pair of ports.
    /// </summary>
    public static async Task<T> WithFreePorts<T>(Func<IPPort, IPPort, Task<T>> start,
                                                 Int32                         maxAttempts = 5)
    {

        for (var attempt = 1; ; attempt++)
        {

            IPPort tcpPort;
            IPPort udpPort;

            using (var tcp = ReserveTcp())
            using (var udp = ReserveUdp())
            {
                tcpPort = tcp.Port;
                udpPort = udp.Port;
            }

            try
            {
                return await start(tcpPort, udpPort);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse &&
                                            attempt < maxAttempts)
            {
                // Lost the race — another process grabbed the port between release and bind.
                await Task.Delay(TimeSpan.FromMilliseconds(50 * attempt));
            }

        }

    }

}
