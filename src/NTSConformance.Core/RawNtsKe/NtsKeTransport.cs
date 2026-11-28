namespace NTSConformance.Core.RawNtsKe;

/// <summary>
/// What an NTS key exchange runs over: TLS, as RFC 8915 § 4 has it, or the SSH subsystem of
/// NTS-KE over SSH, with the SSH Key Binding record in place of the TLS exporter. A test that
/// holds for both is run on both, since the records are parsed and answered on two paths.
/// </summary>
public enum NtsKeTransport
{

    /// <summary>
    /// TLS 1.3 with ALPN ntske/1.
    /// </summary>
    Tls,

    /// <summary>
    /// The SSH subsystem, with the SSH Key Binding record.
    /// </summary>
    Ssh

}
