# Threat model

This document states what `vibe-vpn` is protecting, against whom, and where
the protocol intentionally provides no protection. It is the basis for an
external security review and for the test plan that follows it.

It is deliberately written before the audit so that the reviewer can argue
against specific claims, not against a moving target.

Version: 0.1. Status: pre-review. Any change to the protocol semantics in
`docs/protocol.md` requires a corresponding change here.

## 1. Scope

In scope:

- The wire protocol (Noise XK handshake, session frames, rekey, close).
- The transport interface and the three reference transports (UDP, TLS, raw
  TCP).
- Server-side handshake cookie, rate-limit, replay window.
- Anti-replay, AEAD, key derivation, key at rest.
- Behaviour against malformed input.

Out of scope (documented so a reviewer does not re-litigate them):

- The `vibe-vpn` binary's packaging, packaging-time secrets, supply chain
  on the build host.
- The user's host OS, keyring, route table, firewall.
- The remote application that the user tunnels over the VPN — the tunnel
  protects the *transport* of IP packets, not the applications.
- The behaviour of upstream routing equipment (DPI boxes, NAT, CGN) beyond
  what the protocol itself does to remain either indistinguishable from
  random bytes or indistinguishable from the chosen transport (e.g. TLS).
- Side-channels on the host running the client or server (CPU cache, power,
  electromagnetic). Out of scope for a software prototype.

## 2. Assets

Listed in order of how catastrophically their compromise breaks the
protocol's stated goals.

| # | Asset | Where it lives | Compromise means |
|---|-------|---------------|------------------|
| A1 | Server long-term static private key | `0600` file, optionally passphrase-encrypted | Impersonate server to any client; read past sessions if recorded (forward secrecy limits this to current session). |
| A2 | Client long-term static private key | `0600` file | Allowlist bypass on server. Does not, by itself, reveal server traffic. |
| A3 | Server `peers` allowlist | YAML config | Lets a holder of *any* listed client key connect. |
| A4 | In-flight session keys (send/recv per direction) | Process memory | Read all current traffic. Forward secrecy limits exposure to past traffic. |
| A5 | Ephemeral X25519 keys | Process memory, lifetime of a single handshake / rekey | Recover the session key of that handshake only. |
| A6 | AEAD nonces | In each frame on the wire | Per the AEAD: nonce reuse with the same key is catastrophic. |
| A7 | Pin/trust of the server's static public key on the client | Config | MITM if rotated without operator action. |
| A8 | Server availability / bandwidth | Server host | Service denial. |
| A9 | Operational logs / metrics | Local FS or metrics endpoint | Information about user behaviour, when the tunnel is up, how much. |

## 3. Adversaries

Modelled in increasing capability. Each later adversary can do everything
the former can, plus more.

### AD1. Passive network observer

- Can read every byte on the wire between client and server.
- Cannot inject, modify, drop, delay, or reorder packets.
- Has arbitrary offline computation, including future quantum decryption
  of recorded traffic.

### AD2. Active on-path attacker

- Can do everything AD1 can.
- Can inject, modify, drop, delay, replay individual packets.
- Cannot break the server's TLS certificate (TLS transport is assumed to
  piggy-back on real PKI; the `tls` transport's "fake HTTP" fallback is
  explicitly weakening this; see §6.3).

### AD3. Adversarial network operator (DPI / TSPU-class)

- Can do everything AD2 can.
- Owns or controls the routing/switching infrastructure between client and
  server.
- Can perform statistical analysis on many flows at once.
- Can perform active probing from *off* the path (send probes to the
  server endpoint from arbitrary addresses) — this is the property
  called out below as currently unmitigated.

### AD4. Compromised server host

- Possesses the server's static private key (A1) and all session keys (A4).
- Can record ciphertext for later analysis.
- Cannot retroactively decrypt earlier sessions (forward secrecy) unless
  it also recorded the ephemeral keys, which it does not.

### AD5. Local user on the host

- On the client or server host. Sees process memory, configs, logs.
- Can read A1, A2, A9 by file if permissions are correct.

AD4 and AD5 are stated only so the threat model is complete; the protocol
does not — and largely cannot — defend against either.

## 4. Trust assumptions

Without these, the protocol's claims are void.

- T0. The Noise library (`github.com/flynn/noise`) implements the XK
  pattern correctly and is not backdoored.
- T1. ChaCha20-Poly1305, X25519, SHA-256, HMAC-SHA256 behave as specified.
- T2. `crypto/rand` produces unpredictable bytes on the host.
- T3. The server's long-term static private key is generated with adequate
  entropy and never leaves the host except via the protocol.
- T4. The client operator pins the server's public key out of band (e.g.
  when copying the config). A rotated key is only trusted if the operator
  re-pins.
- T5. The transport layer either (a) preserves frame boundaries (UDP), or
  (b) re-establishes them by length-prefixing (framed stream transports).
  The session layer does not verify this.
- T6. Wall-clock time used for handshake-cookie expiry is monotonic
  forward on both ends during a single handshake.

## 5. Threats and mitigations

Per-asset, with the adversary that defeats the mitigation called out.

### A1 — Server static private key

- Threats: theft from disk (AD5), exfiltration via process memory (AD4).
- Mitigations: `0600` permissions; optional passphrase encryption under
  PBKDF2/Argon2 — see `vibe-vpn keygen -encrypt`. Server does not load
  the key unless the passphrase is provided.
- Residual: nothing protects against AD4 over the protocol — once AD4
  has the host, the key is gone. PBKDF2 / Argon2 only raises the offline
  cost against a stolen-at-rest file.

### A2 — Client static private key

- Threats: same as A1.
- Mitigations: same as A1.
- Residual: a compromised client key bypasses the server's `peers`
  allowlist but does not decrypt recorded traffic (forward secrecy).

### A3 — Server `peers` allowlist

- Threats: misconfiguration (any key trusted), operator typos.
- Mitigations: explicit allowlist format in YAML; pinning warnings on
  unknown client key.
- Residual: a typo on the operator's side is undetectable to the server.
  No out-of-band channel is required for a known client to jump hosts,
  because the client proves possession of the private key via Noise XK.

### A4 — Session keys, A5 — Ephemeral keys

- Threats: in-memory disclosure (AD4, AD5).
- Mitigations: forward secrecy — every handshake and rekey uses fresh
  ephemerals; key separation per direction (Noise `k.send` / `k.recv`).
- Residual: AD4 during the session window decrypts everything in flight.
  Loss of A5 does not retroactively decrypt earlier sessions.

### A6 — AEAD nonces

- Threats: replay of a frame across the replay window (< 1024 by default),
  chosen-nonce attack from a malicious server.
- Mitigations:
  - 12-byte random nonce per frame, drawn from `crypto/rand`.
  - Sliding-window anti-replay (RFC 6479-style) on the receiver.
  - Birthday-bound collision probability: for a typical session of N
    frames, expected collisions ≈ N² / 2 / 2^96. Sessions are bounded by
    rekey (default 2^32 frames or 1 hour, whichever first), so the
    probability of a single collision across the entire session is
    effectively zero.
- Residual: collision probability is non-zero only at absurd frame
  counts. A stubborn attacker who holds the *server's* key (AD4) can
  reuse a nonce by force and break AEAD for that frame; this is a
  consequence of AD4 winning.

### A7 — Server public-key pin

- Threats: silent key rotation (operator accepts a new key on the
  strength of a config file alone).
- Mitigations: explicit `server_public` field in client config; warning
  on key change without operator confirmation.
- Residual: this is a human-channel problem, not a protocol problem. The
  protocol assumes the operator pins out of band (T4).

### A8 — Server availability

- Threats: handshake flood (AD3), bandwidth exhaustion (AD3, AD2).
- Mitigations:
  - Per-IP handshake rate limit.
  - HMAC-bound handshake cookie issued before the expensive Noise DH.
  - Drop on malformed pre-handshake traffic.
- Residual: explicit. The README states *"no DDoS defence beyond dropping
  malformed pre-handshake traffic"*. A determined AD3 can still saturate
  the server's pipe. Mitigations belong upstream (anycast, a real DDoS
  shield), not in the protocol.

### A9 — Logs / metrics

- Threats: leakage of session metadata.
- Mitigations: counters only, no payload. Metrics endpoint is unauthenticated
  by default and is intended to be bound to localhost or a private
  monitoring network.
- Residual: an exposed metrics endpoint leaks the tunnel's byte counts.

## 6. Cross-cutting

### 6.1 Indistinguishability and active probing

The protocol is designed so that on-the-wire ciphertext is
indistinguishable from random bytes. Random bytes, in turn, are not a
known protocol — they look like any non-decoded service. An AD3 that
performs **active probing** — sends traffic at the server endpoint and
observes the response — currently has a path to distinguishability:

- The server replies to a partial handshake with a cookie; the reply
  pattern is fixed.
- The TLS transport replies to an HTTP-shaped probe with an HTTP-shaped
  response.
- The raw TCP transport has no defined response and may be detected as
  black-hole.

Active probing is an explicit gap. See roadmap in `docs/audit.md`.

### 6.2 Behavioural analysis

Even with perfectly encrypted wire bytes, AD3 with many flows can
statistically classify on:

- inter-packet timing,
- packet-size distribution,
- flow duration and daily routine.

The framing layer (`internal/framing`) provides a padding policy and
jitter decorator. This is a *raise-the-cost* measure, not an absolute
one. A real deployment in a hostile environment must measure whether the
chosen profile is sufficient.

### 6.3 TLS transport trade-off

The `tls` transport is presented in two modes:

1. **Real TLS, real PKI.** Behaves as a real HTTPS endpoint. Defeats
   AD2's MITM (assuming PKI is intact). DPI sees a TLS flow that may
   still be fingerprinted by client hello shape (no uTLS).
2. **Fake HTTP.** The transport's "fake HTTP" option accepts non-TLS
   handshakes and replies as if it were a web server. This is a
   camouflage mode for hostile environments; it provides no
   authentication of the server to the client on its own. Documented
   here so reviewers do not assume the TLS padlock on a deployment.

### 6.4 Replay of the handshake itself

Noise XK is a three-message handshake with no negotiation of
parameters. Replaying an old message 1 → message 2 → replayed message 3
does not advance the protocol because the server's response keys depend
on the server's ephemeral, which the attacker does not have. The cookie
mechanism (A8) and the timing window make this a wasted attack.

## 7. Out of scope, restated

The protocol does not protect against:

- Compromise of either endpoint host (AD4, AD5).
- Network-level denial of service beyond the cookie mechanism.
- Traffic-class fingerprinting after long-term behavioural analysis.
- Legal compulsion of the server operator (define jurisdictional rules
  before deploying).
- Anything that requires breaking X25519, ChaCha20-Poly1305, SHA-256, or
  the Noise library.

If any of these is in your threat model, layer other defences (e.g. a
DDoS shield in front, a noisier cover-traffic generator, a jurisdiction
that does not put the operator under the relevant compulsion).

## 8. Verification map

For each claim above, the test that proves it:

| Claim | Where it is verified |
|-------|----------------------|
| AEAD nonces are 12 random bytes | `internal/framing` + `internal/session` unit tests |
| Replay window rejects replays | `internal/protocol` unit tests, fuzz in CI |
| Handshake cookies bind to IP+time | `internal/session` unit tests |
| Malformed pre-handshake traffic is dropped | `internal/framing` + integration test |
| Forward secrecy across rekey | `internal/crypto` unit tests |
| Encrypted key at rest | `cmd/vpn keygen` test + manual verification |
| End-to-end over real TUN | `test/integration` (CI, netns) |
| No data races | `go test -race` in CI |
| No vulns in dependencies | `govulncheck` in CI |
| Static analysis clean | `gosec`, `staticcheck`, `go vet` in CI |

Everything else in this document is a *claim* until an external reviewer
signs off.
