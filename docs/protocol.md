# vibe protocol specification

This document describes the wire protocol used by vibe-vpn. It is written to be
reviewable: the goal is a compact, auditable protocol built from standard
primitives, with the session layer fully decoupled from the transport.

## Primitives

- Key agreement / handshake: **Noise XK** (`Noise_XK_25519_ChaChaPoly_SHA256`)
  as implemented by `github.com/flynn/noise`.
- Key exchange: X25519 (Curve25519).
- AEAD: ChaCha20-Poly1305 (16-byte tag).
- Transcript hash: SHA-256.
- Randomness: `crypto/rand` for keys, handshake material and per-packet nonces.

No cryptography is implemented in this project; all primitives are delegated
to audited libraries.

## Message types

| value | type       | direction   | framing            |
|-------|------------|-------------|--------------------|
| 0x01  | handshake1 | client→server | raw Noise message |
| 0x02  | handshake2 | server→client | raw Noise message |
| 0x03  | handshake3 | client→server | raw Noise message |
| 0x04  | data       | both         | AEAD session frame |
| 0x05  | keepalive  | both         | AEAD session frame |
| 0x06  | close      | both         | AEAD session frame |
| 0x07  | rekey1     | client→server | AEAD session frame |
| 0x08  | rekey2     | server→client | AEAD session frame |
| 0x09  | rekey3     | client→server | AEAD session frame |
| 0x0A  | assign     | server→client | AEAD session frame |
| 0x0B  | decoy      | both         | AEAD session frame |

Handshake messages are the raw Noise transcript with no additional framing.
Session frames are opaque:

```
[ nonce: 12 random bytes ][ ChaCha20-Poly1305 ciphertext ]
```

The ciphertext authenticates the inner plaintext:

```
[ session tag: 4 ][ type: 1 ][ seq: 4 ][ payload length: 2 ][ payload ][ padding ]
```

The `payload length` field bounds the real payload; everything after it is
authenticated padding and is discarded by the receiver. The plaintext includes
no version, so an observer of the wire cannot tell message types apart.

## Handshake (Noise XK)

1. Client picks a random 4-byte **session tag** and sends it inside the first
   Noise message payload (`e, es`). The server is authenticated because the
   client pins its static public key.
2. Server responds (`e, ee`); client responds (`s, se`). The client's static
   key authenticates it to the server, which may enforce a `peers` allowlist.
3. Both sides call `Split()` to obtain the transport keys:
   - client: `send = c2s`, `recv = s2c`
   - server: `send = s2c`, `recv = c2s`
4. The server assigns a tunnel address and sends it as the first session frame
   (`assign`); the client validates the session tag inside it.

## Session keys and nonces

- Two independent AEAD keys (send, recv), each with its own monotonic send
  counter used only as a hint and for replay tracking.
- Every frame carries a fresh **random 12-byte nonce**, so out-of-order
  delivery is safe (no nonce prediction needed) and packets are not
  distinguishable by a counter-based nonce.
- The encrypted `seq` field is checked against an RFC 6479-style sliding
  window (2048 entries) on the receiver. Because frames are AEAD-authenticated
  and the window advances only after successful authentication, an attacker
  cannot advance or roll back the window.

## Rekey

When the send counter approaches the configured threshold, or after
`rekey_after_seconds`, the client starts a fresh Noise XK handshake inside the
session. The rekey messages travel inside AEAD frames (`rekey1..3`), so they
are authenticated by the current keys. On completion both sides atomically swap
to the new keys and reset counters; the server verifies the rekeying peer's
static key matches the session's original peer. This provides forward secrecy
across rekeys.

## Keepalive, timeout, reconnect

- The client periodically sends a keepalive whose payload is a monotonic
  cookie; the server echoes it. This measures RTT and keeps both sides'
  liveness timers fresh.
- A session with no traffic for `session_timeout` is closed; on the client this
  triggers a reconnect, which re-authenticates and reuses the previous address
  (the server hands it over to the new session for the same static key).

## Transports

The session layer talks to `transport.Transport` only:

```go
type Transport interface {
    Send([]byte) error
    Receive() ([]byte, error)
    Close() error
}
```

Implemented transports: UDP (datagram), TLS (HTTPS camouflage with browser
ClientHello via uTLS, ALPN-based or in-stream magic routing), and raw TCP
(obfs4-style: no TLS/banner, black-hole server). Padding profiles, jitter and
decoy traffic are applied at the session/framing layer and are independent of
the transport.

## Threat model

What the protocol provides:

- **Confidentiality and integrity** of all tunnel traffic against passive
  observers, including metadata (message types, sequence numbers, payload
  lengths).
- **Mutual authentication**: client pins the server's static key; server can
  pin clients via `peers`.
- **Replay protection** and tolerance of reordering.
- **Forward secrecy** across sessions and rekeys.
- **Some resistance to passive classification** (opaque frames, padding
  profiles, browser TLS fingerprint, cover traffic).

Assumptions and what is out of scope:

- The server endpoint itself is reachable; an active analyser that can block by
  IP or that terminates TLS (on-path MITM with a trusted root) is out of scope
  for the transport layer.
- No defence against an active analyser that probes the endpoint and detects
  behaviour (a "looks like a tunnel" service). Obfuscation raises the cost of
  classification but is not a guarantee of undetectability.
- No DDoS defence beyond dropping malformed pre-handshake traffic.
- Key material is stored in plaintext on disk (files are created `0600`);
  protecting keys at rest (encryption, TPM/HSM, OS keychain) is not implemented.
- This protocol has not undergone formal security review.

## Known limitations

- The initial handshake consists of a couple of small raw Noise messages at
  session start, which are the main remaining visible structure.
- The server must route pre-handshake traffic by trying the Noise read; this
  bounds per-connection work but is not a full anti-DoS measure.
