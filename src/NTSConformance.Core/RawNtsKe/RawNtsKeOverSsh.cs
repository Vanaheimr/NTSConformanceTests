using System.Security.Authentication;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// NTS-KE over SSH, raw: a caller-supplied record stream sent in the NTS-KE subsystem of an SSH
/// connection, and what came back — the counterpart of <see cref="RawNtsKeClient"/>, with an
/// SSH channel where that has a TLS connection.
///
/// The records are this suite's own, encoded and decoded by <see cref="RawNtsKeCodec"/>; the SSH
/// underneath is Hermod's, there being no other SSH stack in .NET to put there. What is under
/// test is the record, not the transport.
/// </summary>
public static class RawNtsKeOverSsh
{

    /// <summary>
    /// The SSH subsystem of NTS-KE, section 3.2 of the white paper "NTS Key Establishment over
    /// SSH": one exchange per channel, as RFC 8915 has one per TLS connection.
    /// </summary>
    public const String SubsystemName = "ntske/1@open.charging.cloud";


    /// <summary>
    /// Open the subsystem on <paramref name="sshClient"/>, hand over
    /// <paramref name="requestRecords"/> verbatim, and read the reply.
    /// </summary>
    /// <remarks>
    /// The result is a <see cref="RawNtsKeExchange"/> as over TLS, with
    /// <see cref="RawNtsKeExchange.HandshakeSucceeded"/> standing for the subsystem having been
    /// opened, and neither ALPN nor a TLS version.
    /// </remarks>
    public static async Task<RawNtsKeExchange> ExchangeAsync(SshClient          sshClient,
                                                             Byte[]             requestRecords,
                                                             TimeSpan?          timeout            = null,
                                                             CancellationToken  cancellationToken  = default)
    {

        var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(15);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(effectiveTimeout);

        SshMuxChannel channel;

        try
        {
            channel = await sshClient.OpenSubsystemAsync(SubsystemName, timeoutCts.Token);
        }
        catch (Exception e)
        {
            return new RawNtsKeExchange(false, null, SslProtocols.None, null, false,
                                        $"the subsystem {SubsystemName} could not be opened: {e.Message}");
        }

        try
        {

            await channel.SendDataAsync(requestRecords, timeoutCts.Token);

            var bytes = await ReadMessageAsync(channel.Input, timeoutCts.Token);

            if (bytes.Length == 0)
                return new RawNtsKeExchange(true, null, SslProtocols.None, null, true,
                                            "the server closed the channel without sending anything");

            if (!RawNtsKeCodec.TryDecode(bytes, out var records, out var decodeError))
                return new RawNtsKeExchange(true, null, SslProtocols.None, null, false,
                                            $"the reply could not be decoded: {decodeError}\n{Bytes.Dump(bytes)}");

            return new RawNtsKeExchange(true, null, SslProtocols.None, records, false, null);

        }
        catch (OperationCanceledException)
        {
            return new RawNtsKeExchange(true, null, SslProtocols.None, null, false,
                                        $"the server sent no complete reply within {effectiveTimeout}");
        }
        catch (Exception e)
        {
            return new RawNtsKeExchange(true, null, SslProtocols.None, null, false,
                                        $"the exchange failed: {e.Message}");
        }
        finally
        {
            try { await channel.CloseAsync(CancellationToken.None); } catch { }
        }

    }


    /// <summary>
    /// Read one NTS-KE message: up to and including its End of Message record, or whatever
    /// arrived before the stream ended.
    /// </summary>
    public static async Task<Byte[]> ReadMessageAsync(Stream             input,
                                                      CancellationToken  cancellationToken)
    {

        var received = new MemoryStream();
        var buffer   = new Byte[4096];

        while (!RawNtsKeClient.ContainsEndOfMessage(received.ToArray()))
        {

            var read = await input.ReadAsync(buffer, cancellationToken);

            if (read == 0)
                break;

            received.Write(buffer, 0, read);

        }

        return received.ToArray();

    }

}
