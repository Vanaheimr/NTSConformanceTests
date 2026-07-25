# Findings

RFC deviations this suite found in [Norn](libs/Norn), with chapter and verse, the test that
pins each one, and its current status.

Every entry was reached by writing the test first, watching it fail, and only then reading
the implementation — the suite's own reference codec (`src/NTSConformance.Core/RawNtp`,
`RawNtsKe`) is written from the RFCs and shares no code with Norn, so a disagreement between
the two is evidence rather than an assumption.

Status legend: **fixed** — corrected in `libs/Norn`, the test now guards against regression.
**open** — pinned by a deliberately failing test tagged `KnownIssue`, excluded from the
default gate. Every finding has a test.

| # | Severity | Deviation | RFC | Status |
|---|---|---|---|---|
| F1 | **critical** | NTS cookies were neither encrypted nor authenticated | 8915 §6 | fixed |
| F2 | **high** | NTS-KE server answered malformed requests with success instead of an `Error` record | 8915 §4.1.3 | fixed |
| F3 | **high** | NTS-KE server did not negotiate; it answered with values the client never offered | 8915 §4.1.2, §4.1.5 | fixed |
| F4 | high | One cookie per response regardless of placeholders | 8915 §5.7 | fixed |
| F5 | high | No NTS NAK on an unusable cookie | 8915 §5.7 | fixed |
| F6 | high | Session keys written to the debug log; SIV compared in variable time | 7384 §5.7 | fixed |
| F7 | high | Malformed extension fields accepted, or thrown on | 7822 §7.5.1.4 | fixed |
| F8 | low | `AES_SIV.Pad` read past its buffer on a full block | 5297 §2.1 | fixed |
| F9 | medium | Server left reference id, reference timestamp and root dispersion unset | 5905 §7.3 | fixed |
| F10 | low | No era handling; timestamps broke at the 2036 rollover | 5905 §6 | fixed |
| F11 | low | `S2V` mis-handled an empty plaintext with no associated data | 5297 §2.4, §2.6 | fixed |
| F12 | low | AEAD authentication failure threw a bare `Exception` | — | fixed |
| F13 | medium | Duplicate Unique Identifier / Authenticator fields accepted | 8915 §5.7 | fixed |
| F14 | low | NTS-KE rejected a bare IP address that the NTP leg accepted | — | fixed |
| F15 | **high** | NTS-KE server never selected or echoed the `ntske/1` ALPN protocol | 8915 §4 | fixed |
| F16 | **high** | Default self-signed certificate unusable by any Windows/.NET TLS client | 5480 §2.1.1 | fixed |
| F17 | **high** | Plain NTP requests were answered with an NTS NAK | 8915 §5.7 | fixed |

---

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

## F2 — NTS-KE server answered malformed requests with success

**RFC 8915 §4.1.3** defines three error codes and requires the server to *send* one:

- **0, Unrecognized Critical Record**: "The server MUST respond with this error code if the
  request included a record that the server did not understand and that had its Critical Bit
  set."
- **1, Bad Request**: "The server MUST respond with this error if the request is not complete
  and syntactically well-formed, or, upon the expiration of an implementation-defined timeout,
  it has not yet received such a request."
- **2, Internal Server Error**.

`NTSKE_Record.Error` exists as a factory and has **no call site** in `Norn/`.

Testing it turned out worse than the code review suggested. The server does not merely omit
the Error record — it returns a **full, successful NTS-KE response**, twelve records including
session cookies, to requests it is required to reject:

| Request | Required | Actual |
|---|---|---|
| Unrecognized record with Critical Bit set | Error 0 | success, 12 records |
| No Next Protocol Negotiation record at all | Error 1 | success, 12 records |
| Next Protocol Negotiation with an empty list | Error 1 | success, 12 records |
| A record declaring a body longer than the stream | Error 1 | connection closed after the 10 s request timeout, nothing sent |

So a client that sends something malformed is handed working cookies and keys as though
nothing were wrong, and a client that sends something unparseable waits out a timeout and
then sees the connection drop, with no way to distinguish that from a network fault.

Note the pairing with `UnknownNonCriticalRecord_IsIgnored`, which **passes**: the server does
correctly ignore an unrecognized record when the Critical Bit is clear. It ignores it either
way — which is right half the time by accident, not by design.

**Fix.** Every path now answers. `NegotiateNTSKE` examines the request and returns either an
error code or what was agreed; the connection handler writes `Error` + `End of Message` for the
former. `NTSKE_Record.Error(NTSKEErrorCodes)` was added because the existing factory encoded
free text, where §4.1.3 defines the body as a two-octet code — the old overload is now
`[Obsolete]`.

The timeout case needed more than that, and is worth recording because the symptom was
misleading. The handler duly decided to send Error 1 after the read timed out, and the write
then failed with *"Cannot write application data on closed/failed TLS connection"* — 35 seconds
later, once the client gave up. `Task.WaitAsync` abandons a slow read without stopping it,
BouncyCastle serializes access to the TLS stream, and so the abandoned read went on holding the
stream; when it finally collapsed it marked the connection failed. Bounding the read at the
socket instead was no better: BouncyCastle marks the connection failed on any read exception
too.

What works is not entering the TLS read at all until data is there. `NTSKEMessageReader` now
takes the socket and polls it for readability against a deadline, descending into the TLS stream
only when bytes have arrived. A truncated request then expires with the TLS connection still
healthy, and the Error record can actually be written. A generous socket-level receive timeout
remains as a backstop so a client stalling mid-TLS-record cannot hold the connection and its
semaphore slot indefinitely.

**Tests.** `conformance/NTSConformance.NTSKE.Tests/NtsKeServerNegotiationTests.cs`.
`MalformedRecordStream_DrawsError1` is tagged `Slow`: establishing that the timeout path answers
means waiting out `NTSKERequestTimeout`.

---

## F3 — NTS-KE server did not negotiate

**RFC 8915 §4.1.2:** "Protocol IDs listed in the NTS-KE server's response MUST comprise a
subset of those listed in the request." **§4.1.5:** "When included in a response, this record
denotes which algorithm the server chooses to use. It is empty if the server supports none of
the algorithms offered."

`BuildNTSKEResponseRecords` never reads the client's Next Protocol (record 1) or AEAD
Algorithm (record 4) lists — the only thing it takes from the request is the vendor
public-key record — and unconditionally answers NTPv4 plus AES-SIV-CMAC-256.

Measured behaviour:

- A client offering **only protocol 1** is told **0 (NTPv4)** — a protocol it never offered,
  violating the subset rule outright. It is also handed NTPv4 cookies, which are meaningless
  before NTPv4 has been agreed.
- A client offering **only AEAD 30** (AES-128-GCM-SIV) is told **15**. §4.1.5's remedy for
  "supports none of the algorithms offered" is an *empty* record; answering with an algorithm
  the client did not offer leaves it either failing or, worse, proceeding under an algorithm
  the server chose unilaterally.

The critical bit is enforced on inbound records client-side (`NTSKERecordValidator`) but not
server-side, which is the same root cause as F2: nothing inbound is examined.

What the server already got right, and what kept these tests honest while they were failing:
when a client offers `[30, 15]`, the reply is `15` — correct, though at the time only because 15
was the constant it always sent. That case is `AeadSelection_ComesFromTheClientsList`, and it
passed throughout, so the failures could not be dismissed as the tests misreading the record
format.

**Fix.** `NegotiateNTSKE` intersects the client's offers with what the server implements
(`supportedNextProtocols`, `supportedAEADAlgorithms`) and the response carries the result —
empty when the intersection is, which is exactly how §4.1.2 and §4.1.5 say a server declines.
Cookies, and the Server/Port Negotiation records, are emitted only once NTPv4 is actually
agreed, and the cookies are minted for the negotiated algorithm rather than a hard-coded one.
`NTSKE_Record.NextProtocolNegotiation(...)` and an `IEnumerable<AEADAlgorithms>` overload of
`AEADAlgorithmNegotiation` were added so an empty list is expressible at all.

Inbound critical-bit enforcement came with it: an unrecognized record with the bit set is now
refused with Error 0, which is the same root cause as F2 — nothing inbound had been examined.

**Tests.** Same file, ten tests in total across F2 and F3.

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

## F9 — Server left reference id, reference timestamp and root dispersion unset

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

**Fix.** The server now has a notion of its own clock, settable on the constructor:
`Stratum`, `ReferenceIdentifier`, `RootDelay`, `RootDispersion`, `LeapIndicator`, and a
`ClockLastSynchronized` property that a process observing a real synchronisation can update.

The defaults describe what Norn actually is when nothing is configured — a server handing out
the operating system's clock with no upstream of its own. That is a stratum-1 server whose
reference is the local clock (`LOCL` in the §7.3 identifier table), reachable over no network
path, so a root delay of zero is the truth rather than a placeholder. Root dispersion is the
one value that cannot be zero: it is the maximum error relative to the reference, and Norn
cannot observe how well the OS clock is actually synchronised, so the default is the measured
clock resolution plus a deliberately conservative allowance.

Precision is now the server's own clock resolution, **measured** rather than assumed and no
longer echoed from the request — echoing reported the client's clock back to it as though it
described the server's. It is measured because `Stopwatch.Frequency` describes the
high-resolution timer, not the wall clock the timestamps come from, and on Windows those differ
by orders of magnitude; reporting the timer's resolution would be a more precise claim than the
clock can support. On this machine it measures 0.7 µs.

**Tests.** `conformance/NTSConformance.Server.Tests/ServerHeaderFieldTests.cs`, and the same
fields are asserted on the plain-NTP path by `PlainNtpServerTests`, since a client applies the
same §11.3 arithmetic either way.

---

## F10 — No era handling; timestamps broke at the 2036 rollover

**RFC 5905 §6.** NTP timestamps are 32 bits of seconds since 1900 plus a 32-bit fraction; the
seconds field wraps on **2036-02-07T06:28:16Z**, and the RFC requires era disambiguation.
`NTPPacket.NTPTimestampToDateTime` has no era parameter and always adds the second count to
1900, so a timestamp generated after the rollover decodes to a date in the early 1900s — the
test shows 2036-06-01 arriving as 1900-04-26.

**Fix.** `NTPTimestampToDateTime` takes an optional `ApproximateTime` and picks the era that
places the timestamp nearest it, defaulting to now. Within ±68 years that is unambiguous, and
no NTP timestamp worth reading is further out. Zero is special-cased to the epoch: RFC 5905
uses it for "unspecified" — an unsynchronised server's reference timestamp — and it must not be
dragged into a nearby era. `GetCurrentNTPTimestamp` truncates the seconds to 32 bits, which
*is* the era wrap the wire format expects, instead of overflowing into the fraction.

The `Double` was replaced with integer arithmetic in the same pass. The format resolves to
roughly 233 ps and a `Double` carries 53 bits of mantissa, so routing the fraction through one
discarded everything below about a microsecond. The differential test against the suite's
reference now asserts the fraction **exactly** rather than within a tolerance.

**Test.** `conformance/NTSConformance.WireFormat.Tests/TimestampTests.cs`.

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

## F16 — Default self-signed certificate unusable by any Windows/.NET TLS client

`NTSKE_TLSService.GenerateSelfSignedServerCertificate` built its EC key from an
`ECDomainParameters` assembled out of the curve's components:

```csharp
var ecSpec             = SecNamedCurves.GetByName("secp256r1");
var ecDomainParameters = new ECDomainParameters(ecSpec.Curve, ecSpec.G, ecSpec.N, ecSpec.H, ecSpec.GetSeed());
```

BouncyCastle then encodes the **entire curve specification** into the certificate's
SubjectPublicKeyInfo as explicit EC parameters — measured at 335 octets against 91 for the
named-curve form. RFC 5480 §2.1.1 permits that encoding, but Windows' SChannel/CNG implements
only named curves and rejects the certificate with `CRYPT_E_ASN1_BADTAG` (0x8009310B).

The failure is in **parsing, not trust**, so it happens before any validation callback is
consulted: `RemoteCertificateValidationCallback => true` does not help, and neither does
disabling revocation checking. No .NET `SslStream` client on Windows could complete a handshake
with a default-configured Norn server.

This survived because every client that had ever tested it was lenient: Norn's own client and
the interop suite's `gnutls-cli` both accept explicit parameters. It surfaced the moment a
third stack looked — and initially looked like a bug in the new test client, since the
symptom was an opaque `InternalException -2146881269` on a handshake that worked from two
other clients.

**Fix.** Seed the generator from the curve's OID, `SecObjectIdentifiers.SecP256r1`, so the
certificate carries a named curve.

**Tests.** `conformance/NTSConformance.NTSKE.Tests/NtsKeDefaultCertificateTests.cs`, which runs
against a server started with **no** injected certificate — the configuration the README's own
quickstart produces.

---

## F17 — Plain NTP requests were answered with an NTS NAK

**RFC 8915 §5.7.** The NTS NAK is for a request that *attempted* NTS and could not be
validated. A request carrying no NTS extension field is an ordinary RFC 5905 request and must
be answered as one.

This was **self-inflicted, by the fix for F5**. That fix made the server return a Kiss-o'-Death
with kiss code `NTSN` when there was no valid cookie — which is also true of every plain NTP
request. So the server answered all of them with a KoD, and since a KoD means "do not use me",
no plain NTP client would touch it. The `NTSServer` was unusable as an ordinary NTP server.

**How it surfaced, and why it had not.** Nothing in the suite pointed a plain NTP client at
Norn's server. `PlainNtp_AgainstChronyd` tests Norn's *client* against chronyd's server, and
the chrony fixture only ever ran chronyd as a server — the reverse direction had been written
off as blocked by Windows Firewall.

It turned up while checking, out of caution rather than suspicion, whether an external client
accepted F9's new header fields. chronyd reported "No suitable source for synchronisation",
which is what it also says when it dislikes a stratum or a dispersion — so the first
hypothesis was that F9's defaults were wrong. Three variations of stratum and reference
identifier were all rejected identically, which cleared F9; the server's own request counters
showed five requests received and five answered, which cleared the network; and dumping the
reply with the suite's own reader showed stratum 0 and `NTSN`.

Worth recording as a method: "no suitable source" is not a diagnosis. Separating *rejected my
reply* from *never received it* needed the server-side counters, and finding out *why* needed
the packet.

**Fix.** `BuildResponse` returns a plain response when the request carries none of the four NTS
extension fields, and reaches the NAK path only for a request that did attempt NTS. The RFC 5905
header is built by one shared `BuildResponseHeader` for both paths, so a plain and an
NTS-protected reply describe the same clock.

**Tests.** `conformance/NTSConformance.Server.Tests/PlainNtpServerTests.cs` covers the plain
path directly, including that a request which *does* carry an NTS field but no cookie still
draws the NAK, so F5 cannot be undone by this fix. The interop side is
`interop/NTSInterop.LinuxTools.Tests/ChronyAsClientTests.cs`, which runs chronyd as a client and
requires a real measurement.

The firewall assumption also turned out to be wrong, and for an unrelated reason: the probe
gating those tests wrote to `/dev/udp`, a **bash** feature, through `Wsl.Run`, which uses `sh` —
dash on Debian, where the redirect silently fails. The probe reported a blocked network path
where none existed, and the chrony-as-client tests skipped rather than running. The TCP probe
had invoked `bash -c` explicitly and worked, which is why the two directions appeared to differ.

---

## Still not covered

The client's NTS-KE validator does not require `EndOfMessage` to be present or last; its
absence shows up as a read timeout rather than a protocol error. And the client does not re-run
NTS-KE when its cookie pool empties — that logic lives a layer up in
`Monitoring/MeasurementEngine`, so a bare `NTSClient` simply starts failing.

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
