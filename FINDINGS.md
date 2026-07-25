# Findings

RFC deviations this suite found in [Norn](libs/Norn), with chapter and verse, the test that
pins each one, and its current status.

Every entry was reached by writing the test first, watching it fail, and only then reading
the implementation — the suite's own reference codec (`src/NTSConformance.Core/RawNtp`,
`RawNtsKe`) is written from the RFCs and shares no code with Norn, so a disagreement between
the two is evidence rather than an assumption.

Status legend: **fixed** — corrected in `libs/Norn`, the test now guards against regression.
**open** — pinned by a deliberately failing test tagged `KnownIssue`, excluded from the
default gate.

| # | Severity | Deviation | RFC | Status |
|---|---|---|---|---|
| F1 | **critical** | NTS cookies were neither encrypted nor authenticated | 8915 §6 | fixed |
| F2 | medium | NTS-KE server never emits an `Error` record | 8915 §4.1.3 | open, no test |
| F3 | medium | NTS-KE server does not actually negotiate | 8915 §4.1.2, §4.1.5 | open, no test |
| F4 | high | One cookie per response regardless of placeholders | 8915 §5.7 | fixed |
| F5 | high | No NTS NAK on an unusable cookie | 8915 §5.7 | fixed |
| F6 | high | Session keys written to the debug log; SIV compared in variable time | 7384 §5.7 | fixed |
| F7 | high | Malformed extension fields accepted, or thrown on | 7822 §7.5.1.4 | fixed |
| F8 | low | `AES_SIV.Pad` read past its buffer on a full block | 5297 §2.1 | fixed |
| F9 | medium | Server leaves reference id, reference timestamp and root dispersion unset | 5905 §7.3 | open |
| F10 | low | No era handling; timestamps break at the 2036 rollover | 5905 §6 | open |
| F11 | low | `S2V` mis-handled an empty plaintext with no associated data | 5297 §2.4, §2.6 | fixed |
| F12 | low | AEAD authentication failure threw a bare `Exception` | — | fixed |
| F13 | medium | Duplicate Unique Identifier / Authenticator fields accepted | 8915 §5.7 | fixed |
| F14 | low | NTS-KE rejected a bare IP address that the NTP leg accepted | — | fixed |
| F15 | **high** | NTS-KE server never selected or echoed the `ntske/1` ALPN protocol | 8915 §4 | fixed |

---

## F1 — NTS cookies were neither encrypted nor authenticated (critical)

**RFC 8915 §6.** A cookie is server state handed to the client and echoed back on every
request. It carries the C2S and S2C session keys, and it travels as **plaintext inside every
NTS request**, so the cookie's own encryption is the only thing keeping those keys secret.

`NTSCookie.Encrypt(MasterKey)` returned the cookie body unchanged behind a `// TODO:
AEAD-Encrypt`, and `Decrypt` was `return this;`. Two consequences, either one fatal:

1. **Confidentiality.** A passive observer of a single request recovered both session keys
   from the 114-octet plaintext cookie, and could then decrypt all NTS traffic for that
   association and forge authenticated responses. NTS provided no protection at all.
2. **Authentication bypass.** Because nothing was verified, the server accepted *any*
   attacker-authored cookie. Supplying a plausible master key id — a small integer, also
   readable from any cookie on the wire — let an attacker choose the keys the server would
   use, so their forged request then authenticated perfectly.

`MasterKey.Value`, the 32 random octets rotated and persisted to `masterKeys.json`, reached
no cryptographic operation. Rotation was cosmetic.

**Fix.** Cookies are sealed with AES-SIV-CMAC-256 under the master key:

```
MasterKeyId (8) | AEADLength (2) | Nonce (32) | AES-SIV-CMAC-256(body)
                                                 AD = MasterKeyId ‖ AEADLength
                                                 PT = Timestamp ‖ MasterKeyId ‖ Nonce ‖ AlgorithmId ‖ C2SKey ‖ S2CKey
```

The key id stays in the clear because the server must select a key before it can decrypt;
it is covered as associated data, so it cannot be swapped. The keyless `NTSCookie.TryParse`
was **removed** — reading a cookie now requires the master key that issued it, and there is
no API through which the body can be reached otherwise. Validity-window checking moved into
the codec so both call sites get it.

The explicit length field is load-bearing: a cookie rides inside an NTP extension field,
which RFC 7822 pads to a four-octet boundary. Slicing to the declared length keeps that
padding out of the AEAD. Without it every cookie whose size is not a multiple of four failed
to authenticate — which is exactly what happened on the first attempt at this fix, and is
worth knowing before changing the cookie layout again.

**Tests.** `conformance/NTSConformance.Cookies.Tests/CookieConfidentialityTests.cs` — 13
tests: opacity, forgery, per-octet tamper sweep, truncation sweep, master-key binding,
`MasterKey.Value` actually reaching the cipher, expiry, rotation grace, round-trip.

---

## F4 — One cookie per response regardless of placeholders

**RFC 8915 §5.7:** "The number of NTS Cookie extension fields included SHOULD be equal to,
and MUST NOT exceed, one plus the number of valid NTS Cookie Placeholder extension fields
included in the request."

`NTSServer.BuildResponse` called `GenerateNTSCookieExtensions(NumberOfCookies: 1, …)` and
never looked at the request's placeholders. Since a client spends one cookie per request and
got exactly one back, its pool never grew past the NTS-KE seed and it had to re-run the TLS
handshake every few queries.

**Fix.** The count is now `1 + valid placeholders`, capped at
`NTSServer.MaxCookiesPerResponse` (8) so placeholders cannot be used to amplify a small
request into a large response. Per §5.5 a placeholder only counts as valid when its body
length equals the cookie length.

Placeholders are matched on the **wire type**, not the CLR type: the parser produces
`NTSCookiePlaceholderExtension` but the client builds them through
`NTPExtension.NTSCookiePlaceholder`, which returns the base type — so an `OfType<>` filter
silently found none.

**Tests.** `conformance/NTSConformance.Server.Tests/CookieReplenishmentTests.cs`.

---

## F5 — No NTS NAK on an unusable cookie

**RFC 8915 §5.7:** a server that cannot validate the cookie or authenticate the request
"SHOULD respond with a Kiss-o'-Death packet … with kiss code `NTSN`", and "MUST NOT include
any NTS Cookie or NTS Authenticator and Encrypted Extension Fields extension fields".

Both failure branches returned an all-zero packet — `VN = 0`, `Mode = 0`, reference
identifier `0.0.0.0`, no echoed Unique Identifier — and sent it anyway. A client had no way
to tell "your cookie is stale, re-run NTS-KE" from a corrupted datagram. `"NTSN"` existed in
the codebase only as a description string.

**Fix.** `NTSServer.BuildNTSNAK` returns `LI 0, VN 4, Mode 4, Stratum 0`, reference
identifier `NTSN`, the client's Unique Identifier echoed so it can correlate the NAK with the
request, and no cookie or authenticator.

---

## F6 — Session keys in the debug log; variable-time SIV comparison

**RFC 7384 §5.7** requires key material to be protected. `AES_SIV.Encrypt` logged both
halves of the split key, the synthetic IV, every associated-data component, the nonce and the
ciphertext through `DebugX.Log` — on the hot path of **every** NTS request and response.
`NTSKE_Response.ToString()` and `NTSCookie.ToJSON()` also render key material.

`Debug.WriteLine` is `[Conditional("DEBUG")]`, so this reached a sink only in Debug builds —
which is the configuration developers run, and one log capture is enough to compromise every
association the process has served.

Separately, the synthetic IV was compared with `SequenceEqual`, whose early exit leaks how
many leading octets of a forged IV were correct, letting one be built up an octet at a time.

**Fix.** The logging is gone; the comparison uses
`CryptographicOperations.FixedTimeEquals`. The `ToString()`/`ToJSON()` renderings remain and
are worth revisiting — they are opt-in rather than on every packet.

**Test.** `AesSivConformanceTests.Encrypt_DoesNotLogKeyMaterial`, via a `TraceListener` that
captures `DebugX` output.

---

## F7 — Malformed extension fields accepted, or thrown on

**RFC 7822 §7.5.1.4** (extension fields with no MAC present). Four distinct problems, all in
the duplicated extension-field loops of `NTPRequest.TryParse` and `NTPResponse.TryParse`:

- **Truncation silently accepted.** `if (offset + length > Buffer.Length) break;` left the
  loop and then returned *success*, dropping that field and everything after it. Appending a
  field with an overstated length changed how a packet was interpreted without invalidating
  it — the most consequential of the four.
- **Length not a multiple of four** was not checked, though RFC 7822 pads every field to a
  four-octet boundary.
- **One to three trailing octets** were ignored: the loop condition `offset + 4 <= length`
  simply walked off the end.
- **Sub-minimum lengths.** §7.5.1.4 requires ≥ 28 octets for a lone or final field and ≥ 16
  for the others; 20- and 24-octet fields were accepted. Worse, an unrecognised field with a
  4–19 octet body reached `new NTPExtension(...)`, whose constructor **throws**
  `ArgumentOutOfRangeException` — breaking the `TryParse` contract, which must return `false`
  for malformed input rather than throw.

**Fix.** A single `NTPExtensionFieldValidator.TryValidate` pre-pass checks the whole field
chain before anything is decoded, so a malformed tail can no longer be dropped while the rest
of the packet is accepted. Both parsers call it; the duplicated per-field checks are gone.

**Tests.** `conformance/NTSConformance.WireFormat.Tests/ExtensionFieldTests.cs`. Each
malformed input is run through the suite's reference reader first, so the expected verdict
comes from the RFC rather than from Norn.

---

## F9 — Server leaves reference id, reference timestamp and root dispersion unset (open)

**RFC 5905 §7.3.** `NTSServer.BuildResponse` hard-codes stratum 2 and leaves:

- **Reference Identifier** at `0.0.0.0`, though at stratum ≥ 2 it must identify the upstream
  source. A client uses it to detect timing loops (§11.2) and cannot.
- **Reference Timestamp** equal to the transmit timestamp, claiming the clock was corrected
  at the instant of every reply. The field is meant to be when the clock was last set, and as
  written it says nothing about how stale the synchronisation is.
- **Root Delay and Root Dispersion** at zero, asserting a perfect clock. §11.3's root-distance
  calculation then understates the true uncertainty, and a client cannot distinguish this
  server from one deliberately claiming false precision.
- **Leap Indicator** always 0, so the server never announces that it is unsynchronised.

Fixing these properly means the server knowing something about its own clock — plumbing a
time source in, not editing a constant — which is why it is recorded rather than patched.

**Tests.** `conformance/NTSConformance.Server.Tests/ServerHeaderFieldTests.cs`, three
`KnownIssue` tests.

---

## F10 — No era handling; timestamps break at the 2036 rollover (open)

**RFC 5905 §6.** NTP timestamps are 32 bits of seconds since 1900 plus a 32-bit fraction; the
seconds field wraps on **2036-02-07T06:28:16Z**, and the RFC requires era disambiguation.
`NTPPacket.NTPTimestampToDateTime` has no era parameter and always adds the second count to
1900, so a timestamp generated after the rollover decodes to a date in the early 1900s — the
test shows 2036-06-01 arriving as 1900-04-26.

Not yet a live defect. Left open because the fix changes the public timestamp API, which
deserves its own change rather than being folded in here.

Norn's fraction also passes through a `Double`, capping effective precision near a
microsecond where the format allows 233 ps. The suite's reference uses exact integer
arithmetic; the differential test allows a tolerance well under a microsecond, so this is
recorded rather than asserted.

**Test.** `conformance/NTSConformance.WireFormat.Tests/TimestampTests.cs` —
`Norn_HandlesTheEra2036Rollover`, the only `KnownIssue` in the wire-format suite.

---

## F11 — `S2V` mis-handled an empty plaintext with no associated data

**RFC 5297 §2.4, §2.6.** `S2V` returns `AES-CMAC(K, <one>)` only when called with an *empty
vector*, and §2.6 always appends the plaintext:

```
V = S2V(K1, AD1, ..., ADn, P)
```

So with no associated data and an empty plaintext the vector is `("")` — one element of
length zero — which takes the padded-last-block branch. The empty vector is unreachable from
`SIV-ENCRYPT`. Norn short-circuited on "no associated data and no plaintext" and returned
`CMAC(K, <one>)`, producing a synthetic IV no conformant peer would compute. Its `<one>` was
also `0x80 00…00` rather than the `0^127 ‖ 1` of §2.1, though that was the lesser error.

**Fix.** The special case is removed.

---

## F13 — Duplicate Unique Identifier / Authenticator fields accepted

**RFC 8915 §5.7** permits exactly one of each in an NTS-protected packet. Norn accepted two
Unique Identifiers, leaving undefined which one a peer should match against — an attacker
could append a second to change how the packet reads. Now rejected in
`NTPExtensionFieldValidator`.

---

## F14 — NTS-KE rejected a bare IP address the NTP leg accepted

`NTSClient.GetNTSKERecords` sent the hostname to `DNSClient.Query_IPAddresses`
unconditionally, so `new NTSClient(DomainName.Parse("192.0.2.1"))` failed with "No IP address
found" — while `NTPRemoteEndPointResolver` handled literals fine for the UDP leg. A server
could be addressed by IP for plain NTP but not for NTS.

Found by the chrony interop tests, which address the WSL VM by address. Now short-circuited
consistently on both legs, including stripping the trailing root dot that `DomainName`'s FQDN
rendering adds.

---

## F15 — NTS-KE server never selected or echoed the `ntske/1` ALPN protocol

**RFC 8915 §4** runs NTS-KE under the ALPN identifier `ntske/1`. Norn's client advertised it
correctly, but `NTSKE_TLSService` never overrode BouncyCastle's `GetProtocolNames()`, which
returns null by default — so the server ignored the client's ALPN extension entirely and sent
none of its own. The TLS handshake completed normally and the server never said which
protocol it had agreed to.

This was invisible to every test until an outside TLS stack looked at it, because Norn's own
client does not check the response. It matters because other clients do: **chrony's NTS client
requires the server to select `ntske/1`**, so chronyd-as-client against a Norn server would
have failed — the one interop direction the firewall prevented from being tested here.

Caught by `gnutls-cli`, and only because of a control experiment. Against Norn, gnutls printed
no ALPN line; the question was whether that meant "server sent none" or "gnutls doesn't
report it". Running the identical command against chronyd answered it:

```
- Application protocol: ntske/1        # chronyd
                                       # Norn: line absent entirely
```

**Fix.** `NTSKE_TLSService.GetProtocolNames()` returns `[ ProtocolName.Ntske_1 ]`. Beyond
echoing the name, this makes BouncyCastle fail the handshake when a client offers ALPN with no
overlap, rather than proceeding on an unstated protocol.

**Test.** `interop/NTSInterop.LinuxTools.Tests/GnutlsNtsKeTests.NtsKe_NegotiatesNtskeAlpn`,
asserting on gnutls's `Application protocol: ntske/1` line specifically — a substring match
on `ntske/1` alone would also match the client's own request echo in the log and pass
vacuously.

---

## F2, F3 — NTS-KE server error handling and negotiation (open, not yet covered)

Recorded from code review; **no test yet**, because both need a scripted TLS peer that can
send arbitrary NTS-KE record sequences. Stated here so the gap in coverage is visible rather
than implied.

**F2 — no `Error` record.** RFC 8915 §4.1.3 defines codes 0 (unrecognized critical record),
1 (bad request) and 2 (internal server error), and §4 requires the server to respond with one
rather than just closing. `NTSServer`'s handler increments a counter, logs, and drops the
connection; the `NTSKE_Record.Error` factory has no call site in `Norn/`. A client sees a
truncated stream instead of a reason.

**F3 — no negotiation.** `BuildNTSKEResponseRecords` never reads the client's Next Protocol
(record 1) or AEAD Algorithm (record 4) lists — the only thing it takes from the request is
the vendor public-key record — and unconditionally answers NTPv4 plus AES-SIV-CMAC-256. A
client offering only `AES_128_GCM_SIV` (30) is told `15`, which it cannot use. The critical
bit is enforced on inbound records **client**-side (`NTSKERecordValidator`) but not
server-side, so an unknown critical record draws a normal success response instead of
Error 0.

Related, also untested: the client's validator does not require `EndOfMessage` to be present
or last (absence shows up as a read timeout rather than a protocol error), and the client does
not re-run NTS-KE when its cookie pool empties — that logic lives a layer up in
`Monitoring/MeasurementEngine`.

---

## Not a Norn defect, but worth recording

**chronyd starts with no TLS credentials if it cannot read its key.** chronyd is built with
`+PRIVDROP` and switches to the `_chrony` user after start, at which point a root-owned `0600`
key is unreadable. It then serves NTS-KE with no certificate and every handshake fails with
`handshake_failure(40)` — which looks exactly like a client-side TLS bug. The reason appears
only in chronyd's own log: *"Could not set credentials : Error while reading file"*. Cost an
hour of looking in the wrong place; `ChronyNtsServerFixture` now sets `user root`.

**Windows Firewall drops inbound WSL→host traffic.** Silently, so tests hang until their own
timeout rather than failing fast. This is why the reference implementation runs *inside* WSL
and Norn's client connects outward: Windows can reach the VM on both TCP and UDP with no
firewall change. The tests that need the other direction
(`NTSInterop.LinuxTools.Tests/GnutlsNtsKeTests`) probe reachability up front and
`Assert.Ignore` with the exact rule needed to enable them.
