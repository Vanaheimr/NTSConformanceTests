namespace NTSConformance.Core;

/// <summary>
/// NUnit category names used to gate tests on external prerequisites.
/// Default CI filter: TestCategory!=Online&amp;TestCategory!=WSL&amp;TestCategory!=KnownIssue.
/// </summary>
public static class TestCategories
{

    /// <summary>Needs outbound internet (public NTP/NTS servers).</summary>
    public const String Online      = "Online";

    /// <summary>Needs WSL with the GNU/Linux NTS tools installed (chronyd/chronyc/ntp-daemon/gnutls-cli).</summary>
    public const String Wsl         = "WSL";

    /// <summary>Longer-running tests (&gt; ~5 s) — master-key rotation, timeouts, concurrency.</summary>
    public const String Slow        = "Slow";

    /// <summary>Encodes an RFC requirement Norn is currently known to violate.</summary>
    public const String KnownIssue  = "KnownIssue";

    /// <summary>Drives a real in-process Norn NTSServer over loopback sockets.</summary>
    public const String Loopback    = "Loopback";

}
