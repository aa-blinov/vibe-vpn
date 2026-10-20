# Architecture

How vibe-vpn is put together.

The project is one Go binary that holds the server, the client and the setup
tools. Its point is that the carrier under the tunnel can be replaced
without touching the session above it, so the layers are kept apart on
purpose and the boundary between them is an interface with three methods.

## The shape

Four layers sit between the TUN device and the wire, and each one is a
package. A packet travels down through them on the way out and up through
them on the way back.

| Path | What it is responsible for |
| --- | --- |
| `cmd/vpn/` | The CLI: `server`, `client`, `setup`, `keygen`, `certgen`, `status`, `quick`. The verb list is in `main.go` and nowhere else. |
| `internal/transport/` | The `Transport` interface and the three carriers: `udp`, `tlsx` and `rawtcp`, plus the shared `framed` length-prefix helper. |
| `internal/framing/` | The wire format, the padding policies and the jitter decorator. |
| `internal/protocol/` | The message types and the anti-replay sliding window. |
| `internal/session/` | The session state machine, the server session manager, the address pool and the counters. |
| `internal/crypto/` | The Noise XK wrapper, the key encoding, the passphrase-encrypted keys and the handshake cookie. |
| `internal/tun/` | The Linux TUN device and the Windows Wintun adapter behind one `Device` interface. |
| `internal/routing/` | The `ip`, `sysctl` and `nft` calls for addresses, routes, forwarding and NAT. |
| `internal/desync/` | The nfqws integration for the DPI desync of the tunnel's own TCP flow. |
| `internal/config/` | The YAML configuration, its defaults and its validation. |
| `internal/ippkt/`, `internal/pcap/`, `internal/metrics/`, `internal/ctl/` | IPv4 header parsing, the pcap capture, the Prometheus endpoint and the control socket. |
| `test/integration/` | The netns test and the soak test. Both are skipped unless `VPN_INTEGRATION` or `VPN_SOAK` is set. |
| `configs/` | The example configurations, with every key commented. |
| `docs/` | The protocol specification, the threat model, the deployment guide and the audit status. |

## The data flow

The four layers, and what crosses each boundary:

```
  TUN device            session layer                framing            transport
  ┌──────────┐  IP      ┌──────────────────┐          ┌───────────┐      ┌──────────┐
  │ packets  │ ──────► │ Noise XK handshake│ ──────► │ AEAD      │ ───► │ udp      │
  │          │          │ keys, sequence   │  frames │ padding   │      │ tls      │
  │          │ ◄────── │ replay window    │ ◄────── │ jitter    │ ◄─── │ raw tcp  │
  └──────────┘          └──────────────────┘          └───────────┘      └──────────┘
```

The boundary that makes the project work is the transport interface in
`internal/transport/transport.go`:

```go
type Transport interface {
    Send([]byte) error
    Receive() ([]byte, error)
    Close() error
}
```

The session layer never touches a socket, a buffer, the MTU or a padding
policy. A new carrier is one file that satisfies this interface, and
`framing.Jitter` wraps any carrier with a random delay.

A session frame on the wire:

```
[nonce: 12 random bytes][ChaCha20-Poly1305 ciphertext]
```

and the plaintext inside that ciphertext:

```
[session tag: 4][type: 1][seq: 4][payload length: 2][payload][padding...]
```

The AEAD associated data is empty, so the tag, the type, the sequence number
and the length are all authenticated by the ciphertext. The length field is
what tells the receiver how much of the tail is padding.

| Type | Value | Direction | Payload |
| --- | --- | --- | --- |
| handshake1 | `0x01` | client to server | the raw Noise XK message 1, which carries the session tag |
| handshake2 | `0x02` | server to client | the raw Noise XK message 2 |
| handshake3 | `0x03` | client to server | the raw Noise XK message 3, which carries the client static key |
| data | `0x04` | both | an IPv4 packet |
| keepalive | `0x05` | both | an 8-byte timestamp the server echoes back |
| close | `0x06` | both | an authenticated close |
| rekey1..3 | `0x07`..`0x09` | both | a fresh Noise handshake inside an AEAD frame |
| assign | `0x0A` | server to client | the prefix, the client address and the gateway |
| decoy | `0x0B` | both | cover traffic, authenticated and discarded |

The three handshake messages are raw Noise messages with no framing at all,
and everything after them is an AEAD frame. The client pins the server's
static public key, the server may keep an allowlist of client keys, and the
server assigns the tunnel address in the first encrypted frame.

## Decisions worth knowing about

### The transport interface has three methods and no more

`Send` delivers exactly one frame, `Receive` returns exactly one frame, and
`Close` tears the carrier down. A carrier that needs a length prefix, a
reconnect or a handshake of its own keeps that to itself. The cost is that
the session layer cannot see the peer address unless the carrier also
implements `RemoteAddr`.

### The framing is structureless on the wire

A frame is a 12-byte random nonce and a ChaCha20-Poly1305 ciphertext. The
type, the sequence number and the length live inside the ciphertext, so
nothing on the wire has a fixed shape that a classifier could learn. The
cost is that the receiver cannot tell a data frame from a handshake frame
before it decrypts it.

### The replay window advances only after the AEAD authenticates

`Keys.open` in `internal/session/session.go` opens the frame first, then
calls `replay.Check` and `replay.Add`. The comment on
`protocol.ReplayWindow` says the caller must check before decrypting, which
is not what the code does, and the code order is the safe one.
`docs/protocol.md` states the invariant as IV2.

### The first handshake message carries the session tag, not an address

The comment above `crypto.Handshake` still says that the payload holds the
requested and the assigned client IP, and that is stale. The client sends 4
random bytes, the server rejects a first message whose payload is not
exactly 4 bytes, and the tunnel address arrives later in the `assign`
frame. Changing the payload length changes the two length constants in
`handshake1` as well.

### The length of the first handshake message is the cookie discriminator

`handshake1` accepts 52 bytes, or 84 with a 32-byte cookie appended, and
closes the session for anything else. More than 20 handshakes from one
address inside 10 seconds makes the server ask for the cookie, and the
client appends it to message 1 and resends. The cost is that a legitimate
client behind a busy NAT has to answer a second round trip.

### The transport selector does not select the transport

In `cmd/vpn/client.go`, `clientDial` puts the TLS carrier first whenever
the configuration has a `tls:` section, and it drops the UDP fallback only
when `transport` is `raw` or `tls`. A configuration with `transport: udp`
and a `tls:` section still dials TLS first. The generated server listens
for UDP on `:4433` and the generated client points its fallback at `:443`,
so that fallback only connects once both listeners sit on the same port.

### The TUN device sits behind an interface too

`internal/tun/` has a `Device` interface with a Linux implementation on
`/dev/net/tun` and a Windows one on Wintun. The session layer reads and
writes packets and never learns which operating system it is on.

### The routing is done with the system tools

`internal/routing/` shells out to `ip`, `sysctl` and `nft` rather than
reimplementing them. The address, the routes, the forwarding and the
masquerade rule are the operating system's job, and the project does not
argue with it.

### The padding shapes the send, never the receive

Each side shapes only its own sends, and the shaping section of the
configuration is the same on both sides. The `web` policy samples the wire
sizes from the distribution of real TLS records, and the `decoy` frames are
encrypted and discarded by the receiver, so the cover traffic costs the
receiver nothing but a decryption.

### The rekey happens inside the live session

After `rekey_after_packets` or `rekey_after_seconds`, the client runs a
fresh Noise handshake inside the live session and both sides swap to the
new keys and a new sequence space. The cost is three extra frames in the
middle of a session, and the benefit is that a key does not stay on the
wire for the whole life of the connection.

### The address comes back on the same static key

A session with no traffic for `session_timeout` seconds is closed and the
client reconnects, and a client that comes back with the same static key
gets its previous address back. The pool is keyed by the client's public
key rather than by the address it had, so a reconnection is invisible to
the applications behind the tunnel.

## Boundaries

- **`internal/session/` may not import a transport.** It talks to the
  `Transport` interface and to nothing else. That is what keeps the
  carriers replaceable.
- **`internal/framing/` may not know about the session.** It takes bytes
  and gives bytes, and the message types live in `internal/protocol/`.
- **`internal/crypto/` implements no primitive.** Every key, nonce and
  encryption comes from the Go standard library, and the repository does
  not carry a cryptographic implementation of its own.
- **`internal/transport/` may not look inside a frame.** A carrier moves
  bytes and never parses them.
- **The server is Linux-only.** The client runs on Linux and on Windows
  through the Wintun adapter, and the server-side code paths for Windows
  do not exist.
- **`cmd/vpn/` holds the wiring and nothing else.** The verbs are thin:
  they read the configuration, build the objects and hand them to the
  session layer.
