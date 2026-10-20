# AGENTS.md — agent context for `vibe-vpn`

A Go VPN prototype whose point is that the transport layer can be replaced
without touching the session layer. One binary holds the server, the client
and the setup tools; the server runs on Linux, the client on Linux and
Windows. This file is what you need to work on the project without reading
all of it.

## Run / build / test

```bash
make build         # build ./bin/vibe-vpn
make test          # go test -count=1 ./internal/...
make cover         # the same suite with per-package coverage
make vet           # go vet ./...
make fmt           # gofmt over every package
make integration   # real TUN devices inside a network namespace (root)
make soak          # a 30-second ping flood against a live tunnel (root)
make install       # binary, systemd units and example configs under PREFIX
make build-windows # dist/vibe-vpn.exe, a Windows binary built on Linux
```

Go 1.25 is the floor in `go.mod`; CI and the Docker images use 1.26.
`make integration` and `make soak` need root, `iproute2`, `nftables` and
`/dev/net/tun`. The fuzz targets CI runs are `FuzzSealOpen` in
`internal/framing`, `FuzzReplayWindow` in `internal/protocol` and
`FuzzParse` in `internal/ippkt`.

## Where things live

| Path | What it is |
| --- | --- |
| `cmd/vpn/main.go` | The verb dispatch. The verb list is here, and nowhere else. |
| `cmd/vpn/client.go`, `cmd/vpn/server.go` | The two roles: config validation, TUN, transports, control socket, metrics. |
| `cmd/vpn/setup.go` | Generates a working config directory for either role. Also the source of the defaults a fresh install gets. |
| `cmd/vpn/quick.go` | The `wg-quick`-style daemon lifecycle, built on the control socket. |
| `internal/crypto/` | The Noise XK wrapper, key encoding, passphrase-encrypted keys, the handshake cookie. |
| `internal/session/` | The client session loop, the server session manager, the address pool, the counters. |
| `internal/framing/` | The wire format, the padding policies, the jitter decorator. |
| `internal/protocol/` | Message types and the replay window. |
| `internal/transport/` | The `Transport` interface, plus `udp`, `tlsx`, `rawtcp` and the shared `framed` length-prefix helper. |
| `internal/tun/` | The Linux TUN device and the Windows Wintun adapter behind one `Device` interface. |
| `internal/routing/` | `ip`, `sysctl` and `nft` calls for addresses, routes, forwarding and NAT. |
| `internal/desync/` | The nfqws and nftables integration for DPI desync. |
| `internal/ippkt/`, `internal/pcap/`, `internal/metrics/`, `internal/ctl/` | IPv4 header parsing, pcap capture, the Prometheus endpoint, the control socket. |
| `test/integration/` | The netns test and the soak test. Both are skipped unless `VPN_INTEGRATION` or `VPN_SOAK` is set. |
| `docs/` | The protocol specification, the threat model, the deployment guide, the audit status. |
| `configs/` | The example configurations, with every key commented. |

## Traps

- **The transport selector does not select the transport.** In
  `cmd/vpn/client.go`, `clientDial` puts the TLS carrier first whenever the
  config has a `tls:` section, and it drops the UDP fallback only when
  `transport` is `raw` or `tls`. A config with `transport: udp` and a
  `tls:` section still dials TLS first. The UDP fallback also points at the
  same `server:` address and port as the TLS primary, while the generated
  server config listens for UDP on `:4433` and the generated client points
  its fallback at `:443`, so that fallback only connects once both
  listeners sit on the same port.
- **The first handshake message carries the session tag, not an address.**
  The comment above `crypto.Handshake` still says "payload: requested
  client IP" and "assigned client IP", which is stale. The client sends 4
  random bytes (`randomTag`), the server rejects a first message whose
  payload is not exactly 4 bytes, and the tunnel address arrives later in
  the `assign` frame. Changing the payload length changes the two length
  constants in `handshake1` as well.
- **The length of the first handshake message is the cookie discriminator.**
  `handshake1` accepts 52 bytes, or 84 with a 32-byte cookie appended, and
  closes the session for anything else. More than 20 handshakes from one
  address inside 10 seconds makes the server ask for the cookie, which the
  client appends to message 1 and resends.
- **The replay window advances only after the AEAD authenticates.**
  `Keys.open` in `internal/session/session.go` opens the frame first, then
  calls `replay.Check` and `replay.Add`. The comment on `protocol.ReplayWindow`
  says the caller must check before decrypting, which is not what the code
  does; the code order is the safe one, and `docs/protocol.md` states the
  invariant as IV2.
- **The wire sequence number is 32 bits and it lives inside the
  ciphertext.** `maxWireSeq` forces a rekey before the counter wraps, and
  that guard fires whatever `rekey_after_packets` says. A rekey that fails
  leaves both sides on the old keys: the server abandons the rekey on
  timeout and keeps the old key set.
- **Data is dropped while a rekey is in flight.** `encryptSend` refuses every
  message type that is not a rekey message while `rekeying` is set, and the
  client counts the packet as dropped.
- **The server checks the source address of every tunnelled packet.**
  `handleData` parses the IPv4 header and drops the packet unless the
  source address is the one the session was assigned.
- **Seal output is a pooled buffer.** `framing.Seal` returns a buffer from a
  freelist that is not cleared by the garbage collector, and the caller
  returns it with `framing.PutWire` exactly once. A transport that keeps
  the slice after `Send` returns sees recycled memory.
- **The decrypted payload aliases a reused buffer.** `Keys.open` decrypts
  into `recvBuf` and reuses it on the next call, so a payload is only valid
  until the next frame is opened. `waitAssign` copies it for that reason.
- **Cover frames only fire when the sender is idle.** The decoy timer
  resets to a randomized interval around `decoy_interval_s`, and a real
  data frame inside that window suppresses the cover traffic.
- **SIGHUP reloads the peer list and nothing else.** The server re-reads
  the config file and calls `SetPeers` with the new allowlist. The
  listeners, the subnet, the shaping policy and the limits are taken from
  the config as it was at start.
- **The UDP server admits a peer on its first datagram.** Every new source
  address becomes a session slot until the handshake times out after 10
  seconds, so a spoofed-source flood costs slots before any key material
  is checked.
- **The metrics address must be a loopback IP.** `config.validateMetrics`
  rejects anything else at load time. The endpoint has no authentication
  and counts byte volumes, so it belongs on loopback or on a private
  monitoring network.
- **The control socket is world readable and writable.** `ctl.Serve` chmods
  it to 0666 so any local user can read the status or ask the daemon to
  stop. That is deliberate; it exposes counters and nothing else.
- **Routing is done by running `ip`, `sysctl` and `nft`, not by netlink.**
  The host needs iproute2 and nftables, the calls are idempotent, and
  every function returns an error the caller only warns about.
- **`make test` runs `./internal/...` and nothing else.** The test in
  `cmd/vpn/server_test.go` is not covered by `make test` or by CI; run
  `go test ./cmd/...` yourself. The `session.test` binary at the root of
  the repository is a committed test binary, 11.8 MB, whose name matches
  `go test -c ./internal/session`; no Makefile target produces it and
  `.gitignore` does not cover it.
- **`Dockerfile.server` builds a package path that does not exist.** It runs
  `go build ./cmd/vibe-vpn`, but the package is `./cmd/vpn`.
  `Dockerfile.client` has the right path. Fix the Dockerfile rather than
  moving the package.
- **Windows never sees the POSIX signals.** `cmd/vpn/signals_windows.go`
  returns channels that never fire, so `SIGUSR1` and `SIGHUP` do nothing
  there. The desync integration is Linux-only as well, because it drives
  nftables.

## Style / safety rails

- **No cryptographic primitive of your own.** The handshake is
  `github.com/flynn/noise` with `Noise_XK_25519_ChaChaPoly_SHA256` and the
  prologue `NotVPN_1`. The prologue is part of the wire protocol: changing
  it is a protocol change and needs a matching edit in `docs/protocol.md`.
- **No plaintext structure on the wire.** The version, the message type,
  the sequence number and the payload length live inside the ciphertext.
  A new field goes inside the inner header, not in front of the nonce.
- **The `#nosec` annotations are load-bearing.** `gosec` runs in CI, and
  each annotation carries the reason the exception is safe. Removing one
  without understanding it fails the build.
- **Comments explain why.** The comments in this codebase are good and
  they carry the reasoning that the code cannot. A comment that repeats
  the line below it is noise; a comment that says why the length is 52
  bytes is the reason the next person does not break it.
- **The dependency list is short on purpose.** `flynn/noise`, `utls`,
  `x/crypto`, `x/sys`, `x/term`, `yaml.v3`, and `wintun` for Windows.
  Anything else needs a reason written down next to it.
- **IPv4 only.** A packet that is not IPv4 is dropped and counted, on both
  sides.
- **Do not add a plaintext header, a version byte or a fixed magic to a
  session frame.** The whole point of the framing layer is that a passive
  observer sees random bytes.

## Where the product truth lives

`PRODUCT.md` holds it. Read it before changing what the product promises,
and write the change there when the behaviour changes.
