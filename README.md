# Norn NTP/NTS Conformance & Interoperability Test Suite

An adversarial conformance suite for [Norn](libs/Norn), the Vanaheimr NTP/NTS
implementation, plus interoperability tests against independent implementations.

Covers **RFC 5905** (NTPv4), **RFC 7822** (extension fields), **RFC 8915** (Network Time
Security), **RFC 5297** (AES-SIV), **RFC 4493** (AES-CMAC) and **RFC 7384** (security
requirements for time protocols).

## Why a second implementation

The suite carries its own NTP/NTS codec in `src/NTSConformance.Core/RawNtp` and
`RawNtsKe`, written from the RFCs and sharing no code with Norn — not even a crypto
library: `RawAesSiv` builds CMAC, CTR and S2V on the BCL's raw AES block, where Norn
composes BouncyCastle primitives.

That matters because a suite built on the code under test can only prove self-consistency.
Here, a disagreement between the two is evidence, and the reference is itself held to the
published RFC 5297 and RFC 4493 vectors before anything is concluded from it
(`RawAesSivReferenceTests`, including every S2V intermediate from RFC 5297 Appendix A).

The reference codec is also deliberately capable of emitting **malformed** packets —
overstated lengths, missing padding, duplicate fields, trailing octets — which is what
makes the negative tests possible at all.

## Results

The suite found **16 RFC deviations**, including one critical: NTS cookies were neither
encrypted nor authenticated, exposing both session keys on the wire and allowing any forged
cookie to be accepted. Fourteen are fixed in `libs/Norn`; two remain open, each pinned by a
deliberately failing test.

Verified state: **234 tests green** in the hermetic gate, and four deliberately red across
the two open findings. Every finding — fixed or open — has a test.

See **[FINDINGS.md](FINDINGS.md)** for each one with chapter and verse.

Interoperability is confirmed against **chronyd 4.6.1** (full NTS-KE and authenticated
queries) and against **Cloudflare** and **PTB** with certificate validation switched on.

## Layout

```
build/CommonTestSettings.props           shared MSBuild settings for every test project
src/NTSConformance.Core/                 the harness
  RawNtp/                                independent RFC 5905 + 7822 codec, and AES-SIV
  RawNtsKe/                              independent RFC 8915 §4 record codec
  Fixtures/                              Norn and chronyd server fixtures, certificates, DebugX capture
  TestEnvironment.cs                     capability probing, Assert.Ignore gating
  Wsl.cs                                 WSL bridge, host↔VM addressing
conformance/
  NTSConformance.WireFormat.Tests/       RFC 5905 header, RFC 7822 framing, timestamps
  NTSConformance.Crypto.Tests/           RFC 5297 / 4493 vectors, differential vs reference
  NTSConformance.NTSKE.Tests/            RFC 8915 §4 records, server negotiation, certificates
  NTSConformance.Client.Tests/           what the client must refuse
  NTSConformance.Server.Tests/           end-to-end, cookie replenishment, header fields
  NTSConformance.Cookies.Tests/          RFC 8915 §6 — opacity, forgery, rotation
interop/
  NTSInterop.LinuxTools.Tests/           chronyd and gnutls-cli via WSL
  NTSInterop.PublicServers.Tests/        Cloudflare, PTB, Netnod, time.nl
```

`build/CommonTestSettings.props` is imported by a `Directory.Build.props` in each tier
rather than placed at the repository root, because a root-level file would also apply to the
Hermod, Norn and Styx submodule builds.

## Running

Everything that needs no network and no WSL — this is the gate, and it must stay green:

```bash
dotnet test NTSConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=KnownIssue"
```

Add the open deviations, which are expected to fail:

```bash
dotnet test NTSConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL"
```

GNU/Linux tool interop (needs WSL, see below):

```bash
dotnet test NTSConformanceTests.slnx --filter "TestCategory=WSL"
```

Public NTS servers (needs outbound TCP/4460 and UDP/123):

```bash
dotnet test NTSConformanceTests.slnx --filter "TestCategory=Online"
```

A single area:

```bash
dotnet test conformance/NTSConformance.Cookies.Tests/NTSConformance.Cookies.Tests.csproj
```

### Categories

| Category | Meaning |
|---|---|
| `Online` | Needs outbound internet to public NTS servers |
| `WSL` | Needs WSL with chrony / ntpsec / gnutls installed |
| `Loopback` | Drives a real in-process Norn server over loopback |
| `Slow` | Runs longer than about five seconds |
| `KnownIssue` | Pins an RFC requirement Norn currently violates — see [FINDINGS.md](FINDINGS.md) |

Tests whose prerequisites are missing call `Assert.Ignore` with the command needed to
satisfy them, rather than failing.

## Prerequisites

The .NET 10 SDK, and the three submodules checked out:

```bash
git submodule update --init --recursive
```

`libs/Norn` is the system under test; it depends on `libs/Hermod`, which depends on
`libs/Styx`. The existing relative `ProjectReference` paths resolve as-is with this layout.

For the WSL interop tests:

```bash
wsl -u root apt-get install -y chrony ntpsec-ntpdig gnutls-bin openssl
```

chrony must be built with NTS support — `chronyd --version` should show `+NTS`. Debian's is.

The chrony tests run **chronyd inside WSL as the NTS server** and connect Norn's client
outward to it. That direction is deliberate: WSL2's NAT lets Windows reach the VM on both TCP
and UDP, whereas Windows Firewall silently drops the reverse. The few tests that do need
inbound access probe for it first and explain the firewall rule required.

## Conventions

- NUnit 4 constraint model only (`Assert.That`, `Assert.Multiple`) — never `ClassicAssert`.
- Guard clauses over null-forgiving operators: `if (x is null) { Assert.Fail("…"); return; }`.
- Every fixture's doc comment names the RFC section it verifies and says why that rule
  exists — a test that only cites a section number does not survive its author.
- Failure messages carry the evidence: the reference decoder's verdict, a hex dump, the
  server's own log. A bare `Expected: True, But was: False` on a protocol test costs whoever
  reads it an afternoon.
- Server fixtures always pass `MasterKeysFilePath: null`. Left at its default, `NTSServer`
  appends rotating cookie master keys to `masterKeys.json` in the working directory, which
  would both leak state between runs and persist secrets from a test process.
