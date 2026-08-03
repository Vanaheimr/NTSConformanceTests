using System.Net;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;

namespace NTSConformance.Core;

/// <summary>
/// A UDP socket on loopback that records every datagram it receives and, optionally,
/// forwards it to somewhere else and relays the answer back.
///
/// It exists to answer questions no assertion on a client's own return value can:
/// <em>where</em> did the query actually go, and what source port did it come from. A client
/// that ignores the NTS-KE server's redirect still returns a perfectly good measurement —
/// taken from the wrong host. Only a listener at the address it was supposed to use can tell
/// the difference.
///
/// In relaying mode the query still reaches the real server and the answer still reaches the
/// client, so the exchange succeeds end to end and the probe proves the path it took rather
/// than merely breaking it.
/// </summary>
public sealed class UdpRelayProbe : IDisposable
{

    /// <summary>One datagram, and who sent it.</summary>
    public readonly record struct Observation(IPEndPoint Source, Byte[] Payload);


    private readonly UdpClient                udpClient;
    private readonly CancellationTokenSource  cancellation  = new();
    private readonly List<Observation>        observations  = [];

    private volatile IPEndPoint?              forwardTo;


    private UdpRelayProbe(UdpClient   UDPClient,
                          Int32       Port,
                          IPEndPoint? ForwardTo)
    {

        udpClient  = UDPClient;
        forwardTo  = ForwardTo;
        this.Port  = IPPort.Parse(Port);

        _ = Task.Run(ReceiveLoopAsync);

    }


    /// <summary>The loopback port this probe is listening on.</summary>
    public IPPort Port { get; }


    /// <summary>Everything received so far, oldest first.</summary>
    public IReadOnlyList<Observation> Observations
    {
        get
        {
            lock (observations)
                return [.. observations];
        }
    }


    /// <summary>The distinct source ports datagrams arrived from, in order of first appearance.</summary>
    public IReadOnlyList<UInt16> SourcePorts

        => [.. Observations.Select(observation => (UInt16) observation.Source.Port).Distinct()];


    /// <summary>
    /// Listen on a free loopback port and record whatever arrives, without ever answering.
    /// A client querying this probe will time out — which is the point when the test is about
    /// where the packet went rather than what came back.
    /// </summary>
    public static UdpRelayProbe StartObserving()
        => Start(null);


    /// <summary>
    /// Listen on a free loopback port, record whatever arrives, and pass it on to
    /// <paramref name="ForwardTo"/> on loopback, relaying that answer back to the sender.
    /// </summary>
    public static UdpRelayProbe StartRelayingTo(IPPort ForwardTo)
        => Start(new IPEndPoint(IPAddress.Loopback, ForwardTo.ToUInt16()));


    /// <summary>
    /// Give an already-listening probe somewhere to forward to.
    ///
    /// Needed because the two ends have to be created in this order and no other: the probe
    /// must be bound before the server starts, since the server has to advertise the probe's
    /// port, and the server's own port only exists once it has started.
    /// </summary>
    public void RelayTo(IPPort Target)
    {
        forwardTo = new IPEndPoint(IPAddress.Loopback, Target.ToUInt16());
    }


    private static UdpRelayProbe Start(IPEndPoint? ForwardTo)
    {

        var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

        return new UdpRelayProbe(udpClient,
                                 ((IPEndPoint) udpClient.Client.LocalEndPoint!).Port,
                                 ForwardTo);

    }


    /// <summary>
    /// Wait until at least <paramref name="Count"/> datagrams have been seen, or give up.
    /// Returns whether the count was reached, so a caller can assert on it with its own message.
    /// </summary>
    public async Task<Boolean> WaitForDatagrams(Int32 Count, TimeSpan Timeout)
    {

        var deadline = DateTime.UtcNow + Timeout;

        while (DateTime.UtcNow < deadline)
        {

            if (Observations.Count >= Count)
                return true;

            await Task.Delay(TimeSpan.FromMilliseconds(25));

        }

        return Observations.Count >= Count;

    }


    private async Task ReceiveLoopAsync()
    {

        while (!cancellation.IsCancellationRequested)
        {

            UdpReceiveResult received;

            try
            {
                received = await udpClient.ReceiveAsync(cancellation.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                // Windows surfaces an ICMP port-unreachable from an earlier send as an error on
                // the next receive. It says nothing about this socket's ability to keep listening.
                continue;
            }

            lock (observations)
                observations.Add(new Observation(received.RemoteEndPoint, received.Buffer));

            // Read once: the target may be set while the loop is already running.
            var target = forwardTo;

            if (target is not null)
                _ = ForwardAsync(received, target);

        }

    }


    private async Task ForwardAsync(UdpReceiveResult Received, IPEndPoint Target)
    {

        try
        {

            // A fresh socket per datagram, so the answer comes back on a port that belongs to
            // this exchange alone and cannot be confused with the next one.
            using var upstream = new UdpClient();

            await upstream.SendAsync(Received.Buffer, Target, cancellation.Token);

            using var replyTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
            replyTimeout.CancelAfter(TimeSpan.FromSeconds(10));

            var reply = await upstream.ReceiveAsync(replyTimeout.Token);

            await udpClient.SendAsync(reply.Buffer, Received.RemoteEndPoint, cancellation.Token);

        }
        catch
        {
            // Swallowed deliberately: a relay that fails shows up as a client timeout and as
            // an observation the test can inspect. Throwing here would only lose that detail
            // on a pool thread.
        }

    }


    public void Dispose()
    {

        try
        {
            cancellation.Cancel();
            udpClient.Dispose();
            cancellation.Dispose();
        }
        catch
        {
            // Teardown must not mask the failure under investigation.
        }

    }

}
