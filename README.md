# vibe-vpn

A compact, readable research prototype of a VPN protocol. It is deliberately
small so the cryptographic/session layer can be studied and modified, and — most
importantly — so the **transport layer can be swapped out independently** for
experiments with framing, padding, packet sizes, multiplexing, scheduling and
passive-traffic characteristics in a lab environment.

The project does **not** implement its own cryptography. It delegates to the
Noise Protocol Framework (`Noise_XK_25519_ChaChaPoly_SHA256`):

- **X25519** key agreement (DH25519),
- **ChaCha20-Poly1305** AEAD for every message,
- **SHA-256** for transcript hashing,
- `crypto/rand` for all randomness,
- separate send/receive keys derived by the Noise handshake.

## Architecture

```
 TUN interface                    TUN interface
      │                                ▲
      ▼                                │
 ┌─────────┐   session layer:     ┌─────────┐
 │  client │   handshake (Noise)  │  server │
 │ session │   keys, seq numbers, │ session │
 │   ┌──────────────┐   replay window,    │
 │   │   keys       │   keepalive, rekey, │
 │   │  (send/recv) │   timeout,          │
 │   └──────────────┘   reconnect         │
 │      │                                │
 │      ▼                                │
 │  framing + AEAD  ◄─── UDP ────►  framing + AEAD
 └─────────┐                                ▲
           │                                │
      transport.Transport            transport.Transport
           │                                │
           ▼                                ▼
          network                        network
```

The single most important boundary is the transport interface
(`internal/transport/transport.go`):

```go
type Transport interface {
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
}
```

The session layer never touches sockets, buffers, MTU or framing policy. The
UDP implementation lives in `internal/transport/udp`. A future TCP/TLS/QUIC
transport, or an experiment with a new framing/padding layer, only needs to
satisfy this interface.

### Package map

| Package                        | Responsibility                                                        |
|--------------------------------|-----------------------------------------------------------------------|
| `cmd/vibe-vpn`                      | CLI: `server`, `client`, `keygen`                                     |
| `internal/config`              | YAML configuration + defaults                                         |
| `internal/crypto`              | Noise XK handshake wrapper, key management                            |
| `internal/framing`             | Obfuscated frame format, padding policy, jitter decorator            |
| `internal/protocol`            | Message types and the anti-replay sliding window                     |
| `internal/session`             | Session state machine: handshake, AEAD keys, keepalive, rekey, reconnect |
| `internal/transport`           | The pluggable `Transport` interface                                   |
| `internal/transport/udp`       | UDP client and multi-client server demultiplexer                      |
| `internal/transport/tlsx`      | TLS/HTTPS-camouflage transport (ALPN routing, fake HTTP)             |
| `internal/transport/rawtcp`    | obfs4-style raw transport (no TLS, black-hole server)                |
| `internal/transport/framed`    | shared length-prefix framing for stream transports                   |
| `internal/desync`              | nfqws-based DPI desync of the tunnel's own TCP flow (zapret)        |
| `internal/tun`                 | Linux TUN device (raw syscalls, no dependencies)                      |
| `internal/routing`             | `ip`/`sysctl`/`nft` commands for TUN address, routes and NAT          |
| `internal/ippkt`               | Minimal IPv4 header parsing                                           |
| `internal/pcap`                | Debug capture in classic pcap format                                  |

### Wire format

There is **no plaintext protocol header**. Everything a passive observer can
read off the wire is indistinguishable from random bytes:

- **Handshake messages** (initial Noise XK handshake) are raw Noise messages,
  no framing at all.
- **Session messages** (data, keepalive, close, assign, rekey, decoy) are:

```
[nonce: 12 random bytes][ChaCha20-Poly1305 ciphertext]
```

The ciphertext protects an inner plaintext whose metadata is encrypted:

```
[session tag: 4][type: 1][seq: 4][payload length: 2][payload][padding...]
```

Each packet begins with a fresh random nonce, and the version, message type,
sequence number and payload length are only visible after decryption. The AEAD
nonce is per-packet random, so packets can arrive out of order; the encrypted
sequence number drives the receiver's sliding-window replay protection (RFC
6479 style, 2048 entries). The inner length field lets the receiver discard any
padding the sender chose to add.

Message types (recovered only after decryption for session messages):

| type | value | direction | payload |
|------|-------|-----------|---------|
| handshake1 | 0x01 | client → server | Noise XK msg 1 (carries session tag) |
| handshake2 | 0x02 | server → client | Noise XK msg 2 |
| handshake3 | 0x03 | client → server | Noise XK msg 3 (authenticates client static) |
| data        | 0x04 | both        | encrypted IP packet |
| keepalive   | 0x05 | both        | encrypted RTT cookie / echo |
| close       | 0x06 | both        | encrypted close notification |
| rekey1..3   | 0x07..09 | both  | fresh Noise XK handshake inside an AEAD frame |
| assign      | 0x0A | server → client | encrypted client address (prefix + ip + gateway) |
| decoy       | 0x0B | both        | encrypted noise traffic, discarded by receiver |

### Handshake

`Noise_XK_25519_ChaChaPoly_SHA256` (3 messages, all payloads encrypted, carried
as raw Noise messages with no framing):

1. client → server: `e, es` (payload: 4-byte opaque session tag)
2. server → client: `e, ee` (payload: empty)
3. client → server: `s, se` (payload: empty) → both sides `Split()` into the
   transport keys.

The server is authenticated because the client pins its static public key; the
client is authenticated to the server because its static key is transmitted in
the final message and checked against the optional `peers` allowlist. The
session tag chosen by the client is encrypted inside the first message and is
validated inside every later frame.

After the handshake the server assigns the client an address inside the tunnel
subnet and sends it in the first encrypted session frame (the `assign`
message). A reconnecting client reuses its previous address (a new session with
the same static key takes over the old one).

### Traffic shaping

The wire behaviour is configurable per side under `shaping:` in the YAML
config, and is independent per direction:

- `padding`: `none` (default) | `pad` (every session frame padded to a fixed
  wire size) | `bucket` (wire size rounded up to a multiple) | `random`
  (bounded random padding) | **`web`** (wire sizes sampled from the
  distribution of real TLS records: mostly small frames, some medium, rare
  large ones — so the packet-size histogram resembles ordinary HTTPS instead
  of a constant-size tunnel). Padding is authenticated and trimmed by the
  receiver using the encrypted length field.
- `jitter_max_ms`: random delay added before each send (flattens timing
  patterns and keepalive periodicity).
- `decoy_interval_s`: when the sender has no real data for this long, it emits
  an encrypted decoy frame that the receiver authenticates and discards. The
  intervals are randomized so cover traffic does not fire like a metronome.

Because session frames carry no plaintext structure and are padded to
predictable sizes, a passive classifier sees uniform, opaque UDP frames rather
than a recognisable protocol. The initial handshake still consists of a couple
of small raw Noise messages at session start, which is the main remaining
fingerprint; experiments that need to hide even that can add a handshake
framing policy on top of `internal/framing`.

### Raw transport (obfs4-style, "looks like nothing")

A third transport choice, `transport: raw`, runs the tunnel over bare TCP with
**no TLS, no banner and no ALPN**. The Noise handshake (whose messages are
already indistinguishable from random bytes) is carried directly over
length-prefixed frames. The server behaves like a **black hole**: a connection
that does not complete the handshake is simply closed, so anyone without the
shared key sees only opaque random data.

```yaml
# server
transport: raw
listen: 0.0.0.0:8443

# client
transport: raw
server: 1.2.3.4:8443
```

This is "looks like nothing" obfuscation in the spirit of
[obfs4](https://github.com/Yawning/obfs4)/ScrambleSuit (a random-looking
handshake instead of a recognizable protocol), not a byte-compatible obfs4
(no Elligator 2 encoding). Trade-off: an HTTPS-camouflage port is
indistinguishable from *web traffic*; a raw port is indistinguishable from
*random noise* — which is itself a service-like pattern to an active analyser.
Pick whichever fits your threat model, or rotate between them.

### TLS transport (HTTPS camouflage)

The client and server also support a TLS transport that hides the tunnel inside
ordinary HTTPS. It uses the same `Transport` interface, so the session layer is
untouched. Features:

- TLS 1.2/1.3 with a real certificate (`vibe-vpn certgen -out server -cn vpn.example.com`
  generates a self-signed certificate; the client pins it as a CA).
- **Browser fingerprint mode (default)**: the client's ClientHello imitates a
  real browser (Chrome or Firefox via [uTLS](https://github.com/refraction-networking/utls)),
  advertises the ordinary `http/1.1` ALPN and speaks TLS 1.3. The tunnel is
  selected by a short magic sequence written inside the (encrypted) TLS stream,
  so there is no custom ALPN in the plaintext handshake.
- **Legacy mode** (`fingerprint: legacy`): the custom `vibe/1` ALPN selects
  the tunnel directly.
- The server answers browsers and probes with a real `HTTP 200` response, so
  the port behaves like a normal web server either way.
- Inside TLS the datagrams are packetized with a 4-byte length prefix. TCP is
  reliable, so the replay/sequence logic is unchanged.
- Optional TLS config is per side:

```yaml
# server
tls:
  listen: 0.0.0.0:443
  cert: /etc/vibe-vpn/server.crt
  key:  /etc/vibe-vpn/server.key

# client
tls:
  server_name: vpn.example.com    # SNI + certificate name
  ca: /etc/vibe-vpn/server.crt      # pin the server certificate
  fingerprint: chrome             # chrome | firefox | legacy (default: chrome)
  # insecure: true                # skip verification (prototype only)
```

To a passive observer the flow is TLS to a web server — a browser ClientHello,
`http/1.1` ALPN, TLS 1.3, and no distinctive protocol signature. This removes
the main plaintext fingerprints (custom ALPN, Go TLS stack). It is still a
fixed protocol: TLS itself and the transport behaviour are well understood, so
treat it as one more experiment in the lab rather than a guarantee against
active probing.

### Combining with zapret (client-side DPI desync)

[zapret](https://github.com/bol-van/zapret) fights DPI at the packet level
(NFQUEUE/raw sockets) on the client. The tunnel client can **run the desync
itself** as part of `vibe-vpn client`: it creates an nftables queue rule for the
tunnel's TCP flow, starts `nfqws`, and removes both on exit. One command, two
mechanisms.

Build nfqws from the zapret repo (Linux, root):

```sh
# e.g. on Debian/Ubuntu:
apt install -y libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libcap-dev
git clone https://github.com/bol-van/zapret && cd zapret/nfq && make
# the binary is ./nfqws
```

Then enable it in the client config (the tunnel must use the TLS transport):

```yaml
client:
  server: vpn.example.com:443
  # ...
  tls:
    server_name: vpn.example.com
    ca: /etc/vibe-vpn/server.crt
  desync:
    enabled: true
    nfqws: /usr/local/bin/nfqws
    dpi_desync: split2      # split2 | fake | fake,multisplit | ...
    split_pos: "2"          # for split modes ("" disables)
    fooling: badseq         # for fake modes ("" disables)
```

On start the client logs `DPI desync active for tcp/<port> via <nfqws> (mode
...)`, creates the `vibe-desync` nftables table with a `queue` rule for that
port, and spawns nfqws with the matching strategy. The tunnel then carries
traffic through the desynced TCP flow. On exit both the process and the rule
are removed.

Verified in a lab netns on this project: with `split2` and with `fake`/`badseq`
strategies the TLS tunnel keeps working (3/3 ICMP through the tunnel), and a
negative control (queue rule present but no nfqws handler) stalls the tunnel,
confirming nfqws genuinely intercepts and modifies the tunnel's TCP flow.

Note: this verifies the mechanics of the combination only. It is not a test
against a real TSPU deployment, and zapret's per-provider tuning
(`blockcheck.sh`) still needs to be done where you intend to use it.

### Session mechanisms

- **Sequence numbers + sliding window** — out-of-order tolerant, replay-proof.
- **Keepalive** — client sends an 8-byte monotonic cookie every
  `keepalive_interval`; the server echoes it, which measures RTT and keeps both
  sides' liveness timers fresh.
- **Session timeout** — a session with no traffic for `session_timeout`
  seconds is closed (and, on the client, a reconnect is started).
- **Reconnect** — the client re-dials, re-handshakes and re-assigns its
  address transparently.
- **Rekey** — after `rekey_after_packets` or `rekey_after_seconds` the client
  runs a fresh Noise handshake inside the session (`rekey1..3`) and both sides
  atomically swap to new keys and a fresh sequence space.
- **Multiple clients** — the UDP server demultiplexes by source address; each
  session owns an address from the pool.
- **Graceful close** — the client sends an authenticated `close` on shutdown.
- **Packet size / MTU** — data packets larger than `mtu` are dropped and
  counted; IPv6 is dropped (IPv4 only in this version).
- **Malformed packets** — anything that fails framing, handshake
  authentication, AEAD or the replay window is dropped and counted; garbage
  before a handshake closes the session immediately.

## Building

Requires Go 1.21+ and Linux with `/dev/net/tun`.

```sh
make build            # builds ./bin/vibe-vpn
make test             # unit + loopback e2e tests (no root needed)
make integration      # full TUN integration test (requires root)
```

## Installation

The binary runs from anywhere; a `make install` installs it system-wide
together with systemd units and example configs:

```sh
make build          # build ./bin/vibe-vpn
make install        # installs to /usr/local (PREFIX=... to change)
```

This installs:

- `/usr/local/bin/vibe-vpn`
- `/usr/local/lib/systemd/system/vibe-vpn-server.service`
- `/usr/local/lib/systemd/system/vibe-vpn-client.service`
- `/etc/vibe-vpn/server.yaml.example`, `/etc/vibe-vpn/client.yaml.example`

Generate a config (see Quick start), then manage the server as a service:

```sh
sudo cp /etc/vibe-vpn/server.yaml.example /etc/vibe-vpn/server.yaml
sudo systemctl enable --now vibe-vpn-server
journalctl -u vibe-vpn-server -f
```

The client service works the same way with `vibe-vpn-client`.

Diagnostics:

- `vibe-vpn --version` prints the version.
- `kill -USR1 <pid>` dumps current statistics to the log on demand.
- Statistics are also logged every `stats_interval` seconds.

## Quick start (two Linux machines)

On the **server** and the **client**, build the binary:

```sh
make build
```

Both machines need `sudo` and `/dev/net/tun`. That's it — everything else
(keys, TLS certificate, configs) is generated for you.

### Interactive setup (recommended)

The `vibe-vpn.sh` script asks the few questions and prepares everything.

**Server** (on the VPS):

```sh
./vibe-vpn.sh server
```

It prompts for the domain, the TLS port, the output directory and the subnet,
then generates keys + certificate + config, opens the firewall port and offers
to install a systemd service (auto-start on boot). At the end it prints the
directory to copy to the client.

**Client** (on your machine):

```sh
./vibe-vpn.sh client
```

It asks for the server address (`vpn.example.com:443`), the peer directory
(copied from the server) and whether to enable nfqws desync, then generates the
client config and offers to connect immediately.

### One-command setup and run (no script)

**Server** (a single command generates keys + certificate + config and starts
listening):

```sh
sudo ./bin/vibe-vpn server --domain vpn.example.com --out /etc/vibe-vpn-server
```

It prints the generated files. Copy the output directory to the client
(`/etc/vibe-vpn-server` contains `peer.txt`, `server.crt`, `server.pub`).

**Client** (single command; `-peer` is the directory copied from the server):

```sh
sudo ./bin/vibe-vpn client --server vpn.example.com:443 --peer /etc/vibe-vpn-server --out /etc/vibe-vpn-client
```

The client connects automatically. Verify with:

```sh
ping 10.77.0.1        # server's tunnel gateway
```

Optional flags:

- Server: `--tls-listen 0.0.0.0:443` (default), `--subnet 10.77.0.0/24`,
  `--interface vpn0`, `--no-nat` (skip nftables masquerade).
- Client: `--desync` (enable nfqws DPI desync of the tunnel's TCP flow; needs
  the nfqws binary), `--nfqws /path/to/nfqws`, `--no-routing`.

### Manual configuration

If you prefer to write the configs yourself, follow the sections below for
keys, configs, forwarding/NAT and run commands.

### 1. Generate keys

On the server:

```sh
./bin/vibe-vpn keygen   # prints private_key and public_key
```

Keep the server `private_key` for the server config and the server
`public_key` for the client config. On each client, run `./bin/vibe-vpn keygen`
and keep its `private_key` (and optionally list its `public_key` in the
server's `peers` allowlist).

### 2. Server config (`server.yaml`)

```yaml
server:
  listen: 0.0.0.0:4433
  private_key: <server private key>
  interface: vpn0
  subnet: 10.77.0.0/24
  outbound_interface: eth0     # interface used for internet access
  nat: true                    # install nftables masquerade automatically
  # peers:                     # optional allowlist
  #   - <client1 public key>
  #   - <client2 public key>
  mtu: 1280
  keepalive_interval: 20
  session_timeout: 300
  # debug: /tmp/vibe-vpn-server  # writes /tmp/vibe-vpn-server.pcap
```

### 3. Client config (`client.yaml`)

```yaml
client:
  server: <server public ip>:4433
  private_key: <client private key>
  server_public_key: <server public key>
  mtu: 1280
  # client_ip: 10.77.0.2       # optional preferred address
  setup_routing: true          # configure TUN address + routes automatically
  keepalive_interval: 20
  session_timeout: 300
  rekey_after_packets: 268435456
  rekey_after_seconds: 3600
  # debug: /tmp/vibe-vpn-client  # writes /tmp/vibe-vpn-client.pcap
```

### 4. Server: forwarding + NAT

The server does the first two steps itself (it calls `sysctl` and `nft`), but
here they are explicitly:

```sh
# IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1

# nftables masquerade (10.77.0.0/24 -> eth0)
nft add table ip vibe-vpn
nft 'add chain ip vibe-vpn postrouting { type nat hook postrouting priority 100; }'
nft add rule ip vibe-vpn postrouting ip saddr 10.77.0.0/24 oifname "eth0" masquerade
```

If your host firewall would otherwise drop tunnel traffic, allow it, for
example:

```sh
nft add rule ip filter INPUT iifname "vpn0" accept
nft add rule ip filter INPUT ip protocol icmp accept
```

### 5. Run

On the server:

```sh
sudo ./bin/vibe-vpn server --config server.yaml
```

On the client:

```sh
sudo ./bin/vibe-vpn client --config client.yaml
```

### 6. Test

From the client:

```sh
ping 10.77.0.1          # ping the server's tunnel gateway
ping 8.8.8.8            # through the tunnel + NAT
curl https://example.com
```

The client logs its assigned address and, every `stats_interval` seconds, a
statistics line:

```
role=client tx_pkts=123 tx_bytes=15000 rx_pkts=121 rx_bytes=14800 dropped=2
handshakes=1 handshake=1.2ms reconnects=0 rekeys=0 rtt=24.3ms loss=0
sizes(<=64/256/1k/1500/gt)=10/40/30/10/0
```

## Tests

- `make test` — unit tests for crypto (handshake/keys), framing (seal/open,
  padding policies, jitter), protocol (message types, replay window), the
  session stack (data flow, multi-client, rekey, reconnect, timeout, malformed
  traffic), transport framing, and config validation, plus an end-to-end run
  over real loopback UDP with fake TUNs and dedicated obfuscation tests
  (uniform padded frames, bucket sizes, web profile, decoy traffic). No root
  required.
- `make cover` — runs the same suite with per-package coverage. Most packages
  are 70-94% covered; the root-gated parts (`tun`, the `nft`/`nfqws` exec paths
  in `routing`/`desync`) are exercised by the integration test instead.
- `make integration` — builds the real binaries and brings up a network
  namespace with actual TUN devices, then pings the server gateway through the
  tunnel. Requires root, iproute2, nftables and `/dev/net/tun`.

```sh
VPN_INTEGRATION=1 sudo -E go test ./test/integration/ -v -count=1
```

## Docker (server)

```sh
docker build -f Dockerfile.server -t vibe-vpn-server .
# forward the tunnel port and give the container the tunnel device + NET_ADMIN
docker run --rm -it \
  --device /dev/net/tun \
  --cap-add NET_ADMIN \
  -p 4433:4433/udp \
  -v $PWD/configs/server.yaml:/etc/vibe-vpn/server.yaml:ro \
  vibe-vpn-server server --config /etc/vibe-vpn/server.yaml
```

> NAT inside the container is limited: the container must itself be the NAT
> device for its clients, so it needs `--net=host` (or an appropriate
> outbound_interface) to masquerade on behalf of tunnel clients.

## Experimenting with transports and shaping

To add a transport, implement `transport.Transport` and wire it into
`cmd/vibe-vpn` (or a test):

- `Send([]byte)` must deliver one frame reliably (UDP: one datagram).
- `Receive()` must return one frame at a time and return an error once closed.

The session layer handles fragmentation limits via `mtu`, so a transport can
choose its own framing, padding, batch size or scheduling policy without
touching `internal/session`, `internal/crypto` or `internal/protocol`.

The frame format and the padding/jitter/decoy policy live in
`internal/framing`, decoupled from the session logic. Swapping the shaping
policy, or adding a new one, does not require touching the handshake, the keys
or the session state machine. `framing.Jitter` is a transport decorator, so it
can be wrapped around any `Transport` implementation.

## Troubleshooting

- **`vibe-vpn client` exits with a config error** — the config is validated on
  start; the message names the offending field (e.g. bad `server` address, a
  `tls.ca` path that does not exist, `shaping.padding` typo).
- **The tunnel never comes up** — check the client log. `assigned` not printed
  means the handshake failed: confirm the server is reachable on the TLS port
  (`nc -vz <server> 443`), the server's public key in the client config matches
  `server.pub`, and the client trusts the CA in `tls.ca`.
- **`ping 10.77.0.1` fails but the client is assigned** — the tunnel is up;
  the server gateway may be unreachable because the server TUN is not
  configured or forwarding is off (see server `ip`/`sysctl` steps).
- **Traffic flows but websites do not resolve** — DNS is not tunnelled by
  default on the server side; point the client's DNS at the server or use a
  resolver over the tunnel.
- **UDP port is blocked by the ISP** — use the TLS transport (port 443) or a
  custom `--tls-listen`/`--listen` port.
- **nfqws desync is configured but the tunnel is slow or stalls** — verify the
  `nfqws` binary exists and the strategy matches your network; try `split2`
  before `fake`, or disable desync to isolate.
- **Statistics are always zero** — counters are per-session atomics; look at
  the periodic log line and `kill -USR1 <pid>` for a snapshot.
- **"permission denied" opening `/dev/net/tun`** — run as root; in a container
  pass `--device /dev/net/tun --cap-add NET_ADMIN`.

## Security

### What the protocol provides

- **Confidentiality and integrity** for all tunnel traffic. The Noise XK
  handshake (X25519, ChaCha20-Poly1305, SHA-256) establishes transport keys,
  and every session frame is authenticated with per-frame AEAD and a fresh
  random nonce. No custom cryptography is used.
- **Authenticated peers.** The client pins the server's static public key; the
  server can enforce a `peers` allowlist. A rekey re-authenticates the same
  peer inside the session.
- **Replay protection.** An RFC 6479-style sliding window rejects replays while
  tolerating out-of-order delivery.
- **Forward secrecy.** Every handshake — initial and rekey — uses fresh
  ephemeral keys, so past sessions are not recoverable from a later key
  compromise.
- **Defensive input handling.** Frames that fail framing, handshake
  authentication, AEAD or the replay window are dropped and counted; garbage
  before a handshake closes the connection immediately.

### What it is not

- This is a **research prototype**, not an audited production VPN. It has not
  been through a formal security review, and key material is stored on disk in
  plaintext (files are created `0600`).
- The obfuscation layer (encrypted metadata, padding profiles, browser TLS
  fingerprint, cover traffic) raises the cost of passive traffic
  classification but is **not a guarantee of undetectability**. Any fixed
  protocol can eventually be fingerprinted by a determined active analyser;
  treat resistance to DPI as something to measure per deployment, in a lab,
  not as an absolute property.
- There is no DDoS defence beyond dropping malformed pre-handshake traffic,
  and no defence against active probing of the server endpoint.

### Using it responsibly

Deploy it on infrastructure you control and be aware of the laws of the
jurisdiction where you operate it. For needs that require audited, supported
software, use an established VPN implementation (e.g. WireGuard).
