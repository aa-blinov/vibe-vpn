# vibe-vpn

vibe-vpn builds a point-to-point IPv4 tunnel between a Linux server and a
client, and keeps the carrier under that tunnel separate from the session
above it. The tunnel runs over UDP, over TLS with a browser-shaped
ClientHello, or over a bare TCP port that answers with random bytes, and any
of the three can be swapped without touching the handshake or the keys. It is
a research prototype for traffic-shaping experiments, and the threat model
under `docs/` states plainly where the guarantees stop.

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build](https://github.com/aa-blinov/vibe-vpn/actions/workflows/ci.yml/badge.svg)](https://github.com/aa-blinov/vibe-vpn/actions/workflows/ci.yml)

---

## Quick start

Two Linux machines with root and `/dev/net/tun`: one on a public host, one
on the client.

```bash
make build
```

On the server, which writes the key, a self-signed certificate and
`server.yaml`, then starts listening:

```bash
sudo ./bin/vibe-vpn server --domain vpn.example.com --out /etc/vibe-vpn-server
```

Copy `/etc/vibe-vpn-server` to the client machine. On the client, which
generates its own key, writes `client.yaml` and connects:

```bash
sudo ./bin/vibe-vpn client --server vpn.example.com:443 --peer /etc/vibe-vpn-server --out /etc/vibe-vpn-client
```

Check it from the client machine:

```bash
ping 10.77.0.1
```

`10.77.0.1` is the server's tunnel gateway, the first usable address of the
default `10.77.0.0/24` subnet.

`vibe-vpn.sh` asks the same questions interactively and can install the
systemd unit for you:

```bash
./vibe-vpn.sh server    # on the server
./vibe-vpn.sh client    # on the client
```

Releases are published for linux/amd64, linux/arm64 and windows/amd64 as
tarballs, `.deb`, `.rpm` and a Windows zip. The installer picks the latest
release and verifies its SHA-256:

```bash
curl -fsSL https://aa-blinov.github.io/vibe-vpn/install | bash
```

| Platform | Role | What it needs |
| --- | --- | --- |
| Linux | server and client | root, `/dev/net/tun`, `iproute2`, `nftables` for NAT |
| Windows | client only | Administrator, `wintun.dll` beside the binary |

The server is Linux-only. The Windows client runs the same protocol, the
same session layer and the same three carriers.

## What it does

- **Carries IPv4 through a TUN device.** The client and the server each open
  a tunnel interface, and the server hands the client an address out of a
  pool inside the tunnel subnet. IPv6 is dropped and counted; there is no
  IPv6 support in this version.
- **Encrypts with the Noise protocol.** The handshake is
  `Noise_XK_25519_ChaChaPoly_SHA256`: X25519 key agreement,
  ChaCha20-Poly1305 for every frame, SHA-256 for the transcript, and
  `crypto/rand` for every nonce and ephemeral. No cryptographic primitive is
  implemented in this repository.
- **Keeps the wire structureless.** A session frame is a 12-byte random
  nonce followed by a ChaCha20-Poly1305 ciphertext. The message type, the
  sequence number and the payload length live inside the ciphertext, so
  nothing on the wire has a fixed shape.
- **Rejects replays and out-of-order frames.** The receiver keeps an
  RFC 6479-style sliding window of 2048 sequence numbers, and advances it
  only after a frame authenticates.
- **Rotates the keys.** After a configured number of packets or seconds, the
  client runs a fresh Noise handshake inside the live session and both sides
  swap to the new keys and a new sequence space.
- **Recovers on its own.** A session with no traffic for `session_timeout`
  seconds is closed, the client reconnects, and a client that comes back
  with the same static key gets its previous address back.
- **Shapes the traffic.** Padding policies (`none`, `pad`, `bucket`,
  `random`, `web`), a random delay before each send, and encrypted cover
  frames when the sender is idle. The `web` policy samples wire sizes from
  the distribution of real TLS records.
- **Carries the tunnel over UDP, TLS or bare TCP.** The TLS carrier imitates
  a browser ClientHello through uTLS and answers probes with a real HTTP
  response. The raw carrier has no banner, no ALPN and no handshake of its
  own, and the server closes a connection whose Noise handshake never
  completes.
- **Falls back between carriers.** The client tries its configured
  transports in order on every reconnect, so a blocked primary is followed by
  the next one without operator action.
- **Runs as a service.** `vibe-vpn quick up|down|status` manages the client
  as a background daemon, systemd units ship for both roles, and
  `vibe-vpn status` reads a running daemon through a control socket.
- **Reports.** A statistics line every `stats_interval` seconds, a snapshot
  on `SIGUSR1`, a peer-allowlist reload on the server's `SIGHUP`, and a
  Prometheus endpoint on `/metrics` bound to a loopback address.
- **Desyncs DPI on the client.** The client can install an nftables queue
  rule for its own TCP flow and run `nfqws` from zapret against it, so the
  connection to the server is harder for a passive inspector to recognise.

## How it works

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
| handshake1 | `0x01` | client to server | raw Noise XK message 1, carries the session tag |
| handshake2 | `0x02` | server to client | raw Noise XK message 2 |
| handshake3 | `0x03` | client to server | raw Noise XK message 3, carries the client static key |
| data | `0x04` | both | an IPv4 packet |
| keepalive | `0x05` | both | an 8-byte timestamp the server echoes back |
| close | `0x06` | both | an authenticated close |
| rekey1..3 | `0x07`..`0x09` | both | a fresh Noise handshake inside an AEAD frame |
| assign | `0x0A` | server to client | prefix, client address and gateway |
| decoy | `0x0B` | both | cover traffic, authenticated and discarded |

The three handshake messages are raw Noise messages with no framing at all;
everything after them is an AEAD frame. The client pins the server's static
public key, the server may keep an allowlist of client keys, and the server
assigns the tunnel address in the first encrypted frame.

| Path | What it holds |
| --- | --- |
| `cmd/vpn/` | The CLI: `server`, `client`, `setup`, `keygen`, `certgen`, `status`, `quick`. |
| `internal/crypto/` | The Noise handshake wrapper, key encoding, passphrase-encrypted keys, handshake cookies. |
| `internal/session/` | The session state machine, the server session manager, the address pool, the statistics. |
| `internal/framing/` | The wire format, the padding policies, the jitter decorator. |
| `internal/protocol/` | Message types and the anti-replay sliding window. |
| `internal/transport/` | The `Transport` interface and the UDP, TLS and raw TCP carriers. |
| `internal/tun/` | The Linux TUN device and the Windows Wintun adapter. |
| `internal/routing/` | TUN addresses, routes, IPv4 forwarding and nftables NAT, run through `ip`, `sysctl` and `nft`. |
| `internal/desync/` | The nfqws integration for DPI desync of the tunnel's own TCP flow. |
| `internal/ippkt/`, `internal/pcap/`, `internal/metrics/`, `internal/ctl/` | IPv4 header parsing, pcap capture, the Prometheus endpoint, the control socket. |
| `docs/` | The protocol specification, the threat model, the deployment guide and the audit status. |

## Configuration

Both roles read one YAML file with a `client:` or a `server:` section. The
examples in `configs/` carry every key with a comment.

| Key | Default | What it does |
| --- | --- | --- |
| `server` | none | Required. The server address as `host:port`. |
| `private_key` / `private_key_encrypted` | none | Exactly one is required. The encrypted form is a `vibe-vpn keygen -encrypt` blob. |
| `server_public_key` | none | Required. The server's X25519 public key, pinned by the client. |
| `transport` | empty | `udp`, `tls` or `raw`. Empty picks TLS when a `tls:` section is present and UDP otherwise. |
| `mtu` | `1280` | Tunnel MTU. Must be between 576 and 65535. |
| `client_ip` | empty | A preferred address inside the server subnet. |
| `keepalive_interval` | `20` | Seconds between keepalives. Must be smaller than `session_timeout`. |
| `session_timeout` | `300` | Seconds of silence before the session is dropped. |
| `rekey_after_packets` | `268435456` | Packets in a key's lifetime before a rekey. |
| `rekey_after_seconds` | `120` | Seconds in a key's lifetime before a rekey. |
| `setup_routing` | `false` | Configure the TUN address and the routes on start. |
| `raw_server` | empty | A `host:port` for the bare TCP fallback carrier. |
| `stats_interval` | `15` | Seconds between statistics lines. |
| `metrics` | empty | A loopback address for the Prometheus endpoint. |
| `ctl` | empty | The unix socket for `vibe-vpn status` and `vibe-vpn quick`. |
| `tls.server_name` | the host part of `server` | SNI and the name the certificate must carry. |
| `tls.ca` | none | The PEM bundle the server certificate is checked against. |
| `tls.insecure` | `false` | Skip certificate verification. |
| `tls.fingerprint` | `chrome` | `chrome`, `firefox` or `legacy`. |
| `desync.enabled`, `desync.nfqws`, `desync.dpi_desync`, `desync.split_pos`, `desync.fooling` | off, `/usr/local/bin/nfqws`, `split2`, `2`, none | The nfqws desync policy for the tunnel's own TCP flow. |

| Key | Default | What it does |
| --- | --- | --- |
| `listen` | `0.0.0.0:4433` | The UDP listener. |
| `tls.listen` | none | The TLS listener, with `tls.cert` and `tls.key`. |
| `raw.listen` | none | The bare TCP listener, which runs beside the other two. |
| `private_key` / `private_key_encrypted` | none | Exactly one is required. |
| `interface` | `vpn0` | The server's tunnel interface. |
| `subnet` | `10.77.0.0/24` | The tunnel subnet. Its first address is the gateway. |
| `outbound_interface` | `eth0` | The interface the NAT rule sends traffic out of. |
| `nat` | `false` | Install the nftables masquerade. The generated `server.yaml` sets it to `true`. |
| `peers` | empty | Client public keys allowed to connect. Empty allows any client that holds the server key. |
| `max_sessions` | `1024` | Concurrent sessions. A `/24` subnet holds 253 addresses, so a `/16` is needed for 1024. |
| `mtu` | `1280` | Tunnel MTU. |
| `keepalive_interval` | `20` | Seconds between keepalives. |
| `session_timeout` | `300` | Seconds of silence before a session is dropped. |
| `stats_interval` | `15` | Seconds between statistics lines. |
| `metrics` | empty | A loopback address for the Prometheus endpoint. |
| `ctl` | empty | The unix socket for `vibe-vpn status`. |
| `debug` | empty | A path prefix; the tunnel traffic is written to `<prefix>.pcap`. |

The `shaping:` section is the same on both sides, and each side shapes only
its own sends:

| Key | Default | What it does |
| --- | --- | --- |
| `padding` | `none` | `none`, `pad`, `bucket`, `random` or `web`. |
| `pad_to` | none | The target wire size for `pad`. |
| `bucket` | none | The multiple the wire size is rounded up to for `bucket`. |
| `rand_max` | none | The padding ceiling for `random`. |
| `decoy_interval_s` | `0` | How long the sender may stay silent before it emits a cover frame. |
| `jitter_max_ms` | `0` | The largest random delay added before a send. |

## Development

```bash
make build         # build ./bin/vibe-vpn
make test          # unit tests, ./internal/... only
make cover         # the same suite with per-package coverage
make vet           # go vet ./...
make integration   # real TUN devices in a network namespace (root)
make soak          # a 30-second ping flood against a live tunnel (root)
make install       # the binary, the systemd units and the example configs
```

`make integration` and `make soak` need root, `iproute2`, `nftables` and
`/dev/net/tun`. `make test` covers the packages under `internal/`; the test
in `cmd/vpn/` is not part of it.

CI runs `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, the unit
tests under the race detector, three fuzz targets and the integration test
on every pull request.

## License

MIT, © Alexander Blinov. See [LICENSE](LICENSE).
