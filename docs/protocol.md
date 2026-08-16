# vibe protocol specification

This document is written to be **reviewable**: it defines the wire protocol of
vibe-vpn precisely enough that a reviewer can check the implementation
(`internal/framing`, `internal/session`, `internal/crypto`) against it. It
states the security properties the protocol claims, the invariants it relies
on, and the points that deserve scrutiny.

Version: 0.1 (as implemented). Review status: pending external review.

## 1. Notation and scope

- All integers are unsigned big-endian unless stated otherwise.
- `‖` denotes concatenation. `len(x)` is the byte length of `x`.
- The tunnel is point-to-point between one client and one server. The server
  multiplexes many clients; each client has exactly one session at a time.
- The session layer is transport-agnostic; the transport (UDP/TLS/raw TCP)
  only delivers complete frames. Frame boundaries are preserved by the
  transport (datagram) or by 4-byte length prefixes (stream transports).

## 2. Cryptographic primitives

- Handshake: **Noise XK** with the prologue `NotVPN_1`
  (`Noise_XK_25519_ChaChaPoly_SHA256`), implemented by `github.com/flynn/noise`.
- DH: X25519 (Curve25519), 32-byte public keys.
- AEAD: ChaCha20-Poly1305, 12-byte nonce, 16-byte tag.
- Transcript hash: SHA-256.
- Randomness: `crypto/rand` for keys, ephemerals, per-frame nonces and
  traffic-shaping randomness.

No cryptographic primitive is implemented in this project.

## 3. Wire format

### 3.1 Handshake messages

The three initial handshake messages are **raw Noise messages** with no
additional framing:

| step | direction    | content                          | plaintext length |
|------|--------------|----------------------------------|------------------|
| 1    | client→server | XK message 1, payload = session tag | 4 bytes          |
| 2    | server→client | XK message 2, payload = empty      | 0 bytes          |
| 3    | client→server | XK message 3, payload = empty      | 0 bytes          |

The session tag is 4 random bytes chosen by the client. It is encrypted inside
message 1 (XK encrypts all payloads).

### 3.2 Session frames

Every session message is:

```
[ nonce: 12 bytes ][ ChaCha20-Poly1305 ciphertext ]
```

The ciphertext is over the inner plaintext:

```
[0:4]   session tag
[4]     message type
[5:9]   sequence number (uint32)
[9:11]  payload length (uint16)
[11:]   payload
[+pad]  padding (authenticated, discarded by receiver)
```

- The AEAD **associated data is empty**. Authenticity of the frame therefore
  covers the entire inner plaintext, including the session tag, type,
  sequence number and payload length.
- The receiver validates the session tag after decryption and drops frames
  with the wrong tag.
- `payload length` must satisfy `11 + payload length <= len(inner)`; padding
  is whatever follows the payload and is ignored.

### 3.3 Message types

| value | type       | direction   | framing      |
|-------|------------|-------------|--------------|
| 0x01  | handshake1 | client→server | raw Noise  |
| 0x02  | handshake2 | server→client | raw Noise  |
| 0x03  | handshake3 | client→server | raw Noise  |
| 0x04  | data       | both         | AEAD frame  |
| 0x05  | keepalive  | both         | AEAD frame  |
| 0x06  | close      | both         | AEAD frame  |
| 0x07  | rekey1     | client→server | AEAD frame  |
| 0x08  | rekey2     | server→client | AEAD frame  |
| 0x09  | rekey3     | client→server | AEAD frame  |
| 0x0A  | assign     | server→client | AEAD frame  |
| 0x0B  | decoy      | both         | AEAD frame  |

Payloads: `data` = IPv4 packet; `keepalive` = 8-byte monotonic cookie;
`assign` = `[prefix:1][client IP:4][gateway IP:4]`; `rekey*` = raw Noise
message; `decoy`/`close` = arbitrary bytes.

## 4. Handshake

Noise XK with the client pinning the server's static public key:

```
C -> S: e, es        (payload: session tag)
S -> C: e, ee        (payload: empty)
C -> S: s, se        (payload: empty)   -> Split()
```

- The client is authenticated by its static key (message 3); the server may
  enforce a `peers` allowlist.
- After `Split()`:
  - client: `sendKey = C->S`, `recvKey = S->C`
  - server: `sendKey = S->C`, `recvKey = C->S`
- The server assigns a tunnel address and sends it in the first AEAD frame
  (`assign`); the client verifies the session tag.

## 5. Session keys, nonces, sequence numbers

- Two independent ChaCha20-Poly1305 keys (send, recv), each with its own
  monotonic send counter (`uint64`).
- Every frame carries a **fresh random 12-byte nonce**. This makes
  out-of-order delivery safe and prevents nonce reuse even across frame loss.
- The `sequence number` in the inner plaintext is the low 32 bits of the send
  counter and is the replay token.
- The receiver keeps an RFC 6479-style sliding window (2048 entries). A frame
  is accepted if `Check(seq)` and the AEAD authenticates; only then is the
  window advanced. Replayed or forged frames cannot advance the window.

### Invariants

- **IV1 (no nonce reuse):** the send counter is strictly monotonic per key and
  a rekey is forced before the counter reaches `2^32 - 1024`
  (`maxWireSeq`), so the 32-bit wire sequence never wraps while the key is in
  use.
- **IV2 (no unauthenticated advance):** the replay window advances only after
  successful AEAD authentication.
- **IV3 (tag binding):** every accepted AEAD frame carries the session tag
  chosen in the handshake; frames with a different tag are dropped.
- **IV4 (rekey authentication):** rekey messages are AEAD frames authenticated
  by the current keys, and the rekeyed peer's static key must match the
  original session peer.

## 6. Rekey

The client initiates a fresh Noise XK handshake inside the session when the
send counter exceeds the configured threshold or after
`rekey_after_seconds`. Rekey messages are AEAD frames (`rekey1..3`); on
completion both sides atomically swap to new keys and reset counters, and the
server verifies the peer's static key (IV4). This provides forward secrecy
across rekeys.

## 7. Keepalive, timeout, reconnect

- The client sends `keepalive` frames containing an 8-byte monotonic cookie;
  the server echoes it verbatim. The client derives RTT from the echoed cookie.
- A session with no authenticated traffic for `session_timeout` is closed; the
  client reconnects and requests its previous address, which the server hands
  to the new session for the same static key.
- `decoy` frames are authenticated and discarded; they keep the flow alive and
  obscure timing without affecting protocol state.

## 8. Security claims

The protocol claims, against a network adversary (passive eavesdropper, active
injection/replay, spoofed endpoints):

- **C1 Confidentiality** of all session traffic, including frame metadata
  (type, sequence, payload lengths), under the AEAD keys.
- **C2 Integrity** of all session traffic: any modification is rejected.
- **C3 Mutual authentication**: the client authenticates the server (pinned
  static key); the server can authenticate clients (`peers`).
- **C4 Replay protection** (IV2) with tolerance of reordering.
- **C5 Forward secrecy** across sessions and rekeys (fresh ephemerals, IV4).
- **C6 Handshake unlinkability of traffic content**: handshake messages are
  random-looking Noise messages; session frames are AEAD ciphertext with fresh
  random nonces. There is no version or type in plaintext.

The protocol does **not** claim:

- **Undetectability against an active analyser.** Obfuscation (padding
  profiles, cover traffic, browser TLS fingerprint) raises the cost of passive
  classification but is not a cryptographic property. Any fixed protocol can
  be fingerprinted by a determined active adversary.
- **Availability** beyond bounded effort: there is no COOKIE-style
  anti-spoofing mechanism; a spoofed-source handshake flood consumes a session
  slot until the handshake timeout or `MaxSessions` is reached.
- **Key-at-rest protection** unless `keygen -encrypt` is used (scrypt +
  ChaCha20-Poly1305).

## 9. Points for review

- AEAD associated data is empty; verify the intended semantics (metadata
  authenticated, nothing binds the frame to a specific session beyond the key
  and tag).
- The 32-bit wire sequence with forced rekey (IV1): confirm the rekey guard is
  reachable in all configurations and the window reset on rekey is sound.
- Reconnect address handover (`adopt`): verify an attacker cannot claim
  another client's address without its static key.
- Rekey state machine: verify a failed/aborted rekey leaves both sides using
  the same keys.
- The `web` padding distribution and decoy scheduler: confirm they do not
  leak information through padding or timing in a way that contradicts C1/C6.
