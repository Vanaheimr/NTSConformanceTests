# Norn NTP/NTS Conformance & Interoperability Test Suite

An adversarial conformance suite for [Norn](libs/Norn), the Vanaheimr NTP/NTS
implementation, plus interoperability tests against independent implementations.

Covers **RFC 5905** (NTPv4), **RFC 7822** (extension fields), **RFC 8915** (Network Time
Security), **RFC 5297** (AES-SIV), **RFC 4493** (AES-CMAC), **RFC 3686** (AES-CTR),
**RFC 8446** (TLS 1.3), **RFC 7301** (ALPN), **RFC 5480** (EC key encoding), **RFC 9109**
(port randomization), **RFC 9748** (the NTP registries), **RFC 9769** (interleaved modes),
**RFC 8633** (the NTP BCP), **RFC 9525** (service identity in TLS)
and **RFC 7384** (security requirements for time protocols) — see [RFC coverage](#rfc-coverage) for what is asserted,
what is planned, and what is deliberately out of scope.

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

The suite found **20 RFC deviations**, including one critical: NTS cookies were neither
encrypted nor authenticated, exposing both session keys on the wire and allowing any forged
cookie to be accepted. All of them are fixed in `libs/Norn`, each with a test that failed first
and now guards against regression; the reasoning for each is in the commit that fixed it.

Two were reachable only from outside Norn — its own client and GnuTLS were lenient in exactly
the places it was wrong — which is why the interop projects exist and not only the conformance
ones.

Verified state: **501 tests green** in the hermetic gate, and no open defect — the one
`KnownIssue` this suite has ever carried, AES-128-GCM-SIV against chronyd, was resolved and its
cause is described under [The AES-128-GCM-SIV exporter context](#the-aes-128-gcm-siv-exporter-context).

Interoperability is confirmed against three independent implementations, in every direction:

| | Norn as client | Norn as NTS server | Norn as plain NTP server |
|---|:--:|:--:|:--:|
| **chronyd 4.6.1** | yes | yes, incl. `xleave` + NTS together | yes, incl. RFC 9769 `xleave` and RFC 8633 `RATE` |
| **ntpd-rs 1.4** | yes | yes | yes |
| **gnutls-cli** | — | NTS-KE and ALPN | — |

Both external implementations validate Norn's certificate and authenticate its replies, through
GnuTLS and rustls respectively. Public servers — **Cloudflare**, **PTB**, **Netnod** — are
queried with certificate validation switched on.

That spread is deliberate rather than thorough-looking: Norn's own client, GnuTLS, SChannel and
rustls disagree about what to accept, and every high-value defect this suite found was visible to
exactly one of them.

### The AES-128-GCM-SIV exporter context

The clearest example of why a second implementation is the point, and worth writing down because
nothing in RFC 8915 will tell you.

RFC 8915 § 5.1 derives the two session keys from the TLS exporter under a five-octet context: the
protocol id, **the negotiated AEAD algorithm's id**, and the direction. chrony writes `15`
(AES-SIV-CMAC-256) there for sessions running on algorithm `30` (AES-128-GCM-SIV), and has since
it first shipped that algorithm. The key length is taken from the real algorithm, so exactly two
octets differ — and two peers that both get them wrong agree with each other perfectly.

That is what made it invisible. Norn implemented § 5.1 correctly, matched all 24 of RFC 8452's
published vectors in both directions, and completed whole sessions against itself. Against
chronyd the key exchange succeeded, the cookies were well-formed, and then every single NTP
packet failed — in *both* directions, with nothing in either to say why. No test with Norn on
both ends could ever have found it.

chrony negotiates its way out rather than breaking every deployed pair: **IANA NTS-KE record type
1024**, "Compliant AES-128-GCM-SIV Exporter Context" — non-critical, empty-bodied, sent by a
client that can do it and echoed by a server that agrees. Only when both have said so is § 5.1's
context used; silence still means chrony's. Norn implements both halves, so it interoperates with
chronyd old and new, and algorithm 30 is back in `NTSAEAD.Supported` as the preferred offer.

Two more implementations turned out to speak the same negotiation: **Cloudflare** and
**ntppool1.time.nl** both echo record 1024 and run on § 5.1's context, which the online suite
prints in its log rather than asserts.

## RFC coverage

What the suite asserts, RFC by RFC. The Focus column is what is actually checked, not what the
RFC says — a row is ✅ only when a test here would fail if the behaviour regressed.

| | meaning |
|---|---|
| ✅ | implemented in Norn **and** verified by a passing test in this suite |
| 🟡 | basics asserted here, or covered fully only by Norn's own test suite |
| ⬜ | implemented in Norn, no test in this suite yet |
| — | not implemented in Norn; see [Planned](#planned) or [Out of scope](#out-of-scope) |

### NTPv4 — RFC 5905, RFC 7822

| RFC | Focus | |
|---|---|:--:|
| 5905 §7.3 | Header layout, byte-exact: LI/VN/Mode packing, stratum, poll, signed precision, reference identifier, all four timestamps | ✅ |
| 5905 §6 | 64-bit timestamp format: exact integer conversion down to 233 ps, the 16.16 short format, era wrap at 2036-02-07, zero as "unspecified" | ✅ |
| 5905 §7.3 | Server clock characteristics: stratum 1 with `LOCL`, root delay and dispersion never falsely zero, precision from the server's own measured resolution | ✅ |
| 5905 §7.4 | Kiss-o'-Death: stratum 0 with a readable kiss code, and never in answer to a plain NTP request | ✅ |
| 5905 §7.4, 8633 §5.4 | Acting on a kiss code: `DENY` and `RSTR` demobilize the association, every `RATE` slows the client one step further, `X…` and unrecognized codes change nothing — and a kiss is believed only if it echoes the request | ✅ |
| 8633 §5.4 | Server-side rate limiting: a token bucket per address that admits an `iburst`, a `RATE` kiss carrying the poll interval the server will serve, the kisses throttled per address and globally so a spoofed flood cannot be reflected, and the state capped in memory and in the cost of enforcing the cap | ✅ |
| 8633 §5.4 | And chronyd adopts the exact poll exponent Norn's kiss asks for, having read the packet with none of Norn's code | ✅ |
| 5905 §8 | Offset and delay arithmetic, recovered from randomly displaced client and server clocks; Norn's own `ClockOffset` cross-checked against this suite's | ✅ |
| 5905 §11.3 | The root-distance inputs a client needs: dispersion non-zero, delay and dispersion surviving the short-format round trip | ✅ |
| 5905 §7.3 | Leap indicator 3 — an unsynchronized server must be refused as a time source | ✅ |
| 7822 | Extension field framing: length below 4, length not a multiple of 4, truncation, 1–3 trailing octets, unknown types, duplicate Unique Identifier, the 28- and 16-octet minimums | ✅ |
| 5905 §7.3 | IPv6 reference identifier: the leading four octets of the digest over the sixteen binary address octets — over the address rather than its spelling, and over all of it | ✅ |
| 9748 | The NTP registries as they now stand: every registered Kiss-o'-Death code and clock source is understood, codes are matched exactly, `X…` is never given a registered meaning, and unspecified extension fields stay inside 0xF000–0xFFFF | ✅ |
| 5905 §9.1 | Peer, broadcast and multicast modes | — |
| 5905 §10–§12 | Clock filter, selection, clustering and discipline | — |
| 9769 §2 | Interleaved client/server mode, both sides: mode selection by origin timestamp, the transmit timestamp taken after the previous response left, unique receive timestamps, one interleaved answer per receive timestamp, and a client association that survives loss and then gives up | ✅ |
| 9769 §2 | The bounds on the server's state: a fixed-length queue per address, a capped client table evicting least-recently-used in constant time, and the mode optionally reserved for authenticated clients | ✅ |
| 9769 §3, §4 | Interleaved symmetric and broadcast modes | — |
| 5905 App. A | Symmetric-key MAC: the Key Identifier and Message Digest fields parse, but are never emitted | — |

### Network Time Security — RFC 8915

| RFC | Focus | |
|---|---|:--:|
| §4 | NTS-KE over TLS 1.3 with ALPN `ntske/1`, offered and echoed; TLS 1.2 refused | ✅ |
| §4.1 | Record framing: 16-bit type with the critical bit separated out, body length excluding the header, a body overrunning the message rejected, unknown records rejected only when critical | ✅ |
| §4.1.1 | End of Message: present, critical, empty, and last | ✅ |
| §4.1.2 | Next protocol negotiation: the response must be a subset of the request, and a request listing none is refused | ✅ |
| §4.1.3 | Error records: unknown critical record → 0, malformed record stream → 1, sent rather than dropped in silence | ✅ |
| §4.1.5 | AEAD negotiation: the selection comes from the client's list, the IDs match the IANA registry, and an offer of only an unsupported algorithm is refused | ✅ |
| §4.1.6 | New Cookie for NTPv4: none issued when NTPv4 was not the negotiated protocol | ✅ |
| §4.1.4 | Warning records: no warning code has ever been registered, so every one is unrecognized and must be treated as an error | ✅ |
| §4.1.7, §4.1.8 | NTPv4 server and port negotiation: the time query is observed arriving at the advertised host and port, and an advertised server that cannot be reached is not silently replaced by the key-exchange host | ✅ |
| §5.1 | TLS key extraction: the exporter label and its five-octet context, byte-exact and distinct per direction | ✅ |
| §5.3, §5.4, §5.5 | Unique Identifier echoed; Cookie and Cookie Placeholder fields, a placeholder valid only at cookie length | ✅ |
| §5.6 | Authenticator and Encrypted extension field: associated data is the header followed by every preceding field, as one contiguous string | ✅ |
| §5.7 | Cookie replenishment — one per valid placeholder, capped — and an NTS NAK carrying kiss code `NTSN` for a request that attempted NTS and could not be validated | ✅ |
| §5.7 | Response validation: missing authenticator, wrong key, tampered ciphertext, tampered associated data | ✅ |
| §5.7 | Replay rejection of a duplicate transmit timestamp — asserted in Norn's own suite | 🟡 |
| §6 | Cookie format: opaque on the wire, AEAD-sealed and authenticated, forged/tampered/truncated refused, bound to its master key, rotation with a grace window, expired key refused | ✅ |

### Cryptography — RFC 5297, RFC 4493, RFC 3686

| RFC | Focus | |
|---|---|:--:|
| 5297 App. A | Both published AES-SIV vectors, encrypt and decrypt, plus every S2V intermediate of A.1 | ✅ |
| 5297 §2.4 | S2V sensitivity to component boundaries, and an empty plaintext with no associated data | ✅ |
| 5297 §2.1 | `pad` is defined only below a full block: a full or overlong block must be refused, not read out of bounds | ✅ |
| 4493 | AES-CMAC subkey generation and every published vector | ✅ |
| 3686 | CTR mode with a full 128-bit counter increment, and SIV's counter masking | ✅ |
| 7384 | No key material in logs; authentication failure is constant-time and typed | ✅ |
| — | Differential: every operation cross-checked against an independent implementation, both directions | ✅ |
| 8452 | AES-GCM-SIV: all 24 published AEAD_AES_128_GCM_SIV vectors, encrypt and decrypt, and a full session on it against chronyd, Cloudflare and time.nl | ✅ |
| 8915 §4.1.5 | AEAD negotiation with more than one candidate: the server chooses from the client's list in the client's order, skips what it cannot perform, and the choice reaches the exported key length, the cookie size and the authenticator's nonce length | ✅ |
| 8915 §5.1 | The five-octet exporter context, byte-exact per algorithm and direction | ✅ |
| IANA 1024 | Compliant AES-128-GCM-SIV Exporter Context: claimed when offering algorithm 30, echoed only when 30 was agreed and asked for, and chrony's non-compliant derivation used when it was not — see [above](#the-aes-128-gcm-siv-exporter-context) | ✅ |
| 5297 | AES-SIV-CMAC-384 and -512 | — |
| 8452 | AEAD_AES_256_GCM_SIV (31): implemented and vector-correct, never run against another implementation, so not offered | ⬜ |
| 5116, 5282, 6655, 7253, 8439 | The other AEADs in the IANA registry — enumerated so they can be named in negotiation, none implemented | — |

### Transport and PKI

| RFC | Focus | |
|---|---|:--:|
| 8446 | TLS 1.3 required — a 1.2-only client is refused | ✅ |
| 7301 | ALPN `ntske/1` selected and echoed, verified against two independent TLS stacks | ✅ |
| 5480 §2.1.1 | EC public keys encoded as a named curve rather than explicit parameters; a certificate carrying explicit parameters is unusable by SChannel/CNG | ✅ |
| 9109 | Source port randomization: queries leave from an ephemeral port, never 123, and not the same one twice | ✅ |
| 9525 §6.3 | Certificate identity: which host names a certificate speaks for — a wildcard covers exactly one label, never the apex and never two; partial and misplaced wildcards are ignored rather than guessed at; the Common Name is not a fallback | ✅ |
| 6125 | Certificate identity: the configured certificate is presented, and accepted by a third-party client | 🟡 |

### The command line

Norn ships a `norn` executable alongside the library (`libs/Norn/NornCLI`), and this suite
tests it as a process rather than as a method call — argument strings in, exit code and two
streams out, which is the whole of what a CLI promises.

| | Focus | |
|---|---|:--:|
| `norn query` | Measures against an NTS or plain NTP server; `--plain`, `--count`, `--interleaved`, `--insecure` reach what they name, a Kiss-o'-Death is reported as itself rather than as four failed NTS checks | ✅ |
| `norn ke` | Runs the key exchange alone and reports the TLS version, ALPN, certificate, timings and records — the stage where most of what goes wrong with NTS goes wrong | ✅ |
| `norn serve` | Runs a server; `--stratum`, `--refid` and `--rate-limit` are observed on the wire by this suite's own raw client, and a taken port fails with a sentence rather than a stack trace | ✅ |
| Exit codes | 0 success, 1 the operation failed, 2 the command line could not be understood — a mistyped option is an error rather than a shrug | ✅ |
| `--json` | stdout carries the document and nothing else; warnings and errors stay on stderr, including on failure | ✅ |

### Planned

Not covered yet, in rough order of value:

- **RFC 9769 § 6's timestamp randomization** — "Clients using the interleaved mode SHOULD
  randomize all bits of receive and transmit timestamps in their requests", to make the origin
  timestamp harder for an off-path attacker to guess. Norn's client sends its clock readings
  as they are.
- **RFC 8633's remaining operational advice** — § 5.1's information leakage (an access list on
  who may query at all), and § 5.2's panic threshold, which needs a Norn that steers a clock
  rather than only measuring one. § 5.4, the rate limiting and the kiss codes, is done.
- **A capturing NTS-KE server** — the suite can send any record stream to a server and read the
  reply, but nothing terminates TLS on the *client's* far side, so no test can assert what Norn's
  client actually put in a request. Everything client-side is inferred from how a server answers.
  It would also unlock the TLS-level and error-path tests that the scripted-server design was
  always meant to carry.
- **AEAD_AES_256_GCM_SIV (algorithm 31)** — implemented and vector-correct, and never run against
  an implementation other than this one, so it stays out of `NTSAEAD.Supported`. Nothing reachable
  from here offers it.
- **RFC 8915 §4.1.8's default of 123** — a key exchange that sends a Server Negotiation record
  and no Port Negotiation record obliges the client to assume 123. Norn's server always emits
  both, so proving this needs a scripted NTS-KE server that omits one.
- **RFC 5905 §10–§12** — the clock filter and selection algorithms, once Norn does more than
  measure: its monitoring engine computes offsets but steers nothing.
- **NTS pools** — `draft-venhoek-nts-pool`, which the working group leaned towards adopting as
  Experimental in February 2026, and which ntpd-rs already ships behind a flag. It builds on
  §4.1.7 and §4.1.8, both of which now work here, so a pool key exchange in front of Norn
  would be a realistic test rather than a speculative one.

### Out of scope

Deliberately not covered, and why:

- **RFC 5906 Autokey** — cryptographically broken and effectively abandoned. NTS exists
  because of it; testing it would be testing a mistake.
- **RFC 8573 and RFC 5905 App. A symmetric-key MAC** — the shared-key AES-CMAC and MD5 scheme.
  Norn authenticates with NTS, which is the whole point of Norn.
- **RFC 1305 NTPv3 and RFC 4330 SNTP** — Norn is NTPv4 only. How it treats an older version
  number on the wire is a compatibility question, not a conformance one.
- **RFC 5907 NTP MIB** — there is no SNMP management plane to test.
- **IEEE 1588 PTP and NTS4PTP** — a different protocol family over a different transport.
- **NTPv5** — `draft-ietf-ntp-ntpv5-09` (July 2026), proposed as Experimental and still moving;
  ntpd-rs tracks it draft by draft. There is nothing stable to conform to yet.
- **Roughtime** — `draft-ietf-ntp-roughtime`, also still a draft. A different protocol with a
  different goal: rough time from servers you need not trust individually.
- **Leap second handling** — Norn reports the leap indicator it is given. Getting a leap right
  end to end needs a leap-second file and a clock that can be steered, which belongs to
  whatever does the steering rather than to the protocol implementation.
- **ntpd feature parity** — orphan mode, reference clock drivers, mode 6/7 control queries.

## Layout

```
build/CommonTestSettings.props           shared MSBuild settings for every test project
src/NTSConformance.Core/                 the harness
  RawNtp/                                independent RFC 5905 + 7822 codec, and AES-SIV
  RawNtsKe/                              independent RFC 8915 §4 record codec
  Fixtures/                              Norn and chronyd server fixtures, certificates, DebugX capture
  TestClock.cs                           a TimeProvider the test controls: frozen, or displaced
  UdpRelayProbe.cs                       a loopback socket that records who sent what, and can pass it on
  TestEnvironment.cs                     capability probing, Assert.Ignore gating
  Wsl.cs                                 WSL bridge, host↔VM addressing
conformance/
  NTSConformance.WireFormat.Tests/       RFC 5905 header, RFC 7822 framing, timestamps, the registries
  NTSConformance.Crypto.Tests/           RFC 5297 / 4493 vectors, differential vs reference
  NTSConformance.NTSKE.Tests/            RFC 8915 §4 records, server negotiation, warnings, certificates
  NTSConformance.Client.Tests/           what the client must refuse, which clock it reads, where its query goes
  NTSConformance.Server.Tests/           end-to-end, plain NTP, header fields, listen address, clock, interleaved mode
  NTSConformance.Cookies.Tests/          RFC 8915 §6 — opacity, forgery, rotation
  NTSConformance.CLI.Tests/              the `norn` executable, run as a process
interop/
  NTSInterop.LinuxTools.Tests/           chronyd, ntpd-rs and gnutls-cli via WSL
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

Include anything tagged `KnownIssue`. Nothing is at present, so this currently matches the run
above; it is how an open deviation would be exercised once one is recorded:

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

### The tool itself

Norn's command line lives in the submodule and is built along with everything else. Against a
public server:

```bash
dotnet run --project libs/Norn/NornCLI -- query time.cloudflare.com
```

To see what a key exchange agreed on, which is where most NTS problems are:

```bash
dotnet run --project libs/Norn/NornCLI -- ke ptbtime1.ptb.de
```

To stand one up, unprivileged, on a port that needs no root:

```bash
dotnet run --project libs/Norn/NornCLI -- serve --port 12123 --ke-port 14460 --listen 127.0.0.1
```

### Categories

| Category | Meaning |
|---|---|
| `Online` | Needs outbound internet to public NTS servers |
| `WSL` | Needs WSL with chrony / ntpd-rs / gnutls installed |
| `Loopback` | Drives a real in-process Norn server over loopback |
| `Slow` | Runs longer than about five seconds |
| `KnownIssue` | Pins an open defect — none at present |

Tests whose prerequisites are missing call `Assert.Ignore` with the command needed to
satisfy them, rather than failing.

## Prerequisites

The .NET 10 SDK, and the three submodules checked out:

```bash
git submodule update --init --recursive
```

`libs/Norn` is the system under test; it depends on `libs/Hermod`, which depends on
`libs/Styx`. The existing relative `ProjectReference` paths resolve as-is with this layout.
All three resolve over HTTPS from the public GitHub mirrors, so no account or key is needed.

For the WSL interop tests:

```bash
wsl -u root apt-get install -y chrony ntpd-rs gnutls-bin openssl
```

chrony must be built with NTS support — `chronyd --version` should show `+NTS`. Debian's is.

The chrony tests run **chronyd inside WSL as the NTS server** and connect Norn's client
outward to it. The reverse direction — chronyd and ntpd-rs as clients against a Norn server on
the Windows host — needs inbound TCP and UDP from the WSL subnet, which Windows Firewall may
block. Every test that needs it probes first and skips with the reason rather than failing, so
a machine where it is blocked still reports honestly.

ntpd-rs is handed a certificate carrying the Windows host's address as an **IP** subject
alternative name: rustls ignores the Common Name entirely and matches only against SANs.

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
- Time-dependent assertions inject a clock (`TestClock`) rather than tolerating the real one.
  A substituted clock is the only way to assert a reported time exactly, and it keeps the
  server's clock and the client's independently controllable — which is what makes the offset
  arithmetic testable at all.
