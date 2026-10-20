# Product

<!-- impeccable:product-schema 1 -->

## Platform

cli

Two Go binaries in one, `vibe-vpn server` and `vibe-vpn client`, plus the
tools around them: `setup`, `keygen`, `certgen`, `status` and `quick`. The
server runs on Linux and needs `/dev/net/tun`, `iproute2` and `nftables`. The
client runs on Linux with the same TUN device and on Windows with a Wintun
adapter. There is no graphical interface: the surfaces are the command line,
the log lines the daemon writes, the Prometheus endpoint on `/metrics` and
the unix control socket.

## Users

Two audiences, and the repository only speaks about the first one in detail.

The operator: someone with a Linux server on a public host and a machine
that has to reach the internet through a network that blocks or fingerprints
VPNs. The deployment guide points at a VPS in Europe reached from a Russian
network, and says that the per-carrier tuning has to be verified on the real
network of the deployment.

The author: someone who wants to read a VPN protocol end to end and change
one layer of it. The repository is built for that: the protocol
specification is written to be reviewed, the threat model was written before
the audit, and the transport interface is small enough to hold in the head.

Not in the repository: how many people run this, who they are, whether
anyone other than the author has deployed it, or what they use it for
beyond reaching the internet through a filtered network.

## Product Purpose

The tunnel carries IPv4 packets between one client and one server. The
client opens a TUN device, the server opens one too, and the server hands
the client an address out of a pool inside the tunnel subnet. Everything
above that is a Noise XK session: X25519 key agreement, ChaCha20-Poly1305
for every frame, SHA-256 for the transcript, and `crypto/rand` for every
nonce.

The second thing the project does is let the layer under the tunnel be
replaced. The session layer talks to a three-method interface and never
learns what carries the bytes. Three carriers ship with it: UDP datagrams,
TLS with a browser-shaped ClientHello, and a bare TCP port that answers
with random bytes and closes anything that does not complete the handshake.

Success for the operator: the tunnel comes up and stays up, and the traffic
on the wire looks like the carrier it was told to look like. Success for the
author: a carrier or a shaping policy can be replaced, measured and
replaced again without touching the handshake, the keys or the session
state machine.

## Positioning

The neighbouring VPN products are finished tools with one way to work. This
one is a bench with a protocol on it.

The mechanism a neighbour cannot copy without rewriting the middle: the
separation is enforced by the code, not by convention. `internal/session`
imports `internal/transport` and nothing else from the network side, the
padding and jitter policies sit in `internal/framing` as a policy object and
a transport decorator, and the address pool, the replay window and the
cookie logic know nothing about the carrier.

The second difference is how many carriers are on the table. A TLS carrier
that imitates a browser ClientHello, a bare TCP carrier with no banner at
all, and a UDP carrier that can share port 443 with the TLS listener are
three answers to three different networks, and the client walks down the
list on its own when one of them is blocked.

The third is the paperwork. `docs/protocol.md` states the invariants the
implementation relies on and lists the points a reviewer should attack,
`docs/THREAT_MODEL.md` names the adversaries and what is out of scope, and
`docs/audit.md` separates what a tool checked from what a person did. The
protocol specification reads as an invitation to review rather than as a
claim.

## Operating Context

The server runs on a VPS the operator controls, as root, with a TUN device
it creates itself. On start it turns on IPv4 forwarding, gives the tunnel
interface the gateway address of the subnet, and installs an nftables
masquerade so its clients can reach the internet. A systemd unit ships in
`deploy/`, and `make install` writes it to `/usr/local/lib/systemd/system`
along with the example configs.

The client runs on the operator's own machine, also as root, because it has
to open a TUN device and run `ip` to move the default route into the
tunnel. `vibe-vpn quick up` starts it as a background daemon with the logs
in `<ctl>.log`, `quick down` asks that daemon to stop through the control
socket, and `quick status` reads the counters. The same socket answers
`vibe-vpn status`.

The operator watches the tunnel from three places: the periodic statistics
line, a snapshot on `SIGUSR1`, and the Prometheus endpoint when `metrics` is
set. The server re-reads its config file on `SIGHUP` and applies the peer
allowlist from it.

`vibe-vpn.sh` is the path most operators take: it asks for the domain, the
port, the subnet and the output directory, generates the keys, the
certificate and the config, opens the firewall port and can install the
systemd unit.

## Capabilities and Constraints

Confirmed by the code:

- A point-to-point IPv4 tunnel over a TUN device, with addresses handed out
  from a pool inside the tunnel subnet and kept across a reconnect.
- A Noise XK handshake with a pinned server key and an optional allowlist
  of client keys.
- A fresh 12-byte random nonce per frame, an RFC 6479-style replay window
  of 2048 sequence numbers, and a payload length inside the ciphertext that
  tells the receiver how much of the tail is padding.
- A rekey by packet count, by time, or by the hard guard before the 32-bit
  wire sequence number wraps.
- Three carriers: UDP, TLS with a uTLS browser ClientHello or the legacy
  `vibe/1` ALPN, and bare TCP. The TLS port answers a browser or a probe
  with a real HTTP 200.
- A client fallback chain: every reconnect walks the configured carriers in
  order.
- Five padding policies (`none`, `pad`, `bucket`, `random`, `web`), a random
  delay before each send, and encrypted cover frames while the sender is
  idle.
- An anti-DoS handshake cookie bound to the client address and an hour
  window, checked before the expensive key agreement, plus a per-address
  rate limit of 20 handshakes per 10 seconds.
- Private keys that can be stored encrypted, with scrypt and
  ChaCha20-Poly1305, and a passphrase taken from the environment or from a
  terminal prompt without echo.
- A client-side nfqws desync of the tunnel's own TCP flow, with the
  nftables rule and the process removed on exit.
- A Prometheus endpoint restricted to loopback, a control socket, statistics
  lines, and `SIGUSR1` and `SIGHUP` handling.
- Releases for linux/amd64, linux/arm64 and windows/amd64, as tarballs,
  `.deb`, `.rpm` and a zip, plus an installer that verifies the SHA-256.
- A Docker recipe for the server and the client.

Deliberately not true, and worth knowing before a change:

- The protocol has had no external security review. `docs/audit.md` says
  the review is pending, and `docs/protocol.md` lists the points a reviewer
  should attack.
- Active probing is not mitigated. The threat model names the cookie reply
  pattern, the HTTP answer on the TLS port and the black-hole behaviour of
  the raw port as paths an active analyst can take.
- There is no DDoS defence beyond the cookie and the drop of malformed
  pre-handshake traffic.
- IPv4 only. A packet that is not IPv4 is dropped and counted on both
  sides.
- DNS is not tunnelled by the server; the client has to point at a
  resolver that works.
- The server is Linux-only, and the desync path needs the nfqws binary
  built from zapret.
- The client needs root or `CAP_NET_ADMIN`, on the host that owns the
  routes.
- The metrics endpoint has no authentication. The config loader refuses any
  address that is not a loopback IP.
- The control socket is created with mode 0666.
- A key on disk is a plain file unless `keygen -encrypt` was used.
- The obfuscation raises the cost of passive classification. It is not a
  guarantee of undetectability, and the deployment guide says to measure it
  per network.

Open, and to be answered by the owner rather than guessed:

- Who runs this, and how many clients are expected. The default subnet
  `/24` holds 253 addresses while `max_sessions` defaults to 1024, so the
  two defaults do not agree.
- Whether MIT is the intended licence. The package metadata says MIT and
  the release packages carry it, but no licence file ships in the
  repository.
- Which carrier should lead in a given deployment. The setup script asks
  for a TLS port and the deployment guide leaves the order to the operator.

## Brand Commitments

**Name:** vibe-vpn. The protocol names itself `NotVPN_1` inside the Noise
prologue, and the systemd units call themselves `not-vpn server` and
`not-vpn client`.

**Tone:** plain and technical. The logs are one line of `key=value`
counters, the errors name the offending field, and the documents are written
for the person who has to check them rather than for a visitor.

**The interface reports the state instead of reassuring the user.** A
routing setup that fails produces a warning that tells the operator to run
the commands by hand, not a line that says the tunnel is fine. The
statistics line carries the dropped counter next to the sent one.

**The product states what it is not.** The README calls itself a research
prototype that has not been through a security review, the threat model
lists the adversaries it cannot defeat, and the audit separates the checks
that ran from the checks that did not.

## Evidence on Hand

- `docs/protocol.md` is the wire specification, version 0.1, marked as
  pending external review. It defines the frame layout, the message table,
  four invariants and the claims the protocol makes and refuses to make.
- `docs/THREAT_MODEL.md` is version 0.1, pre-review. It names the assets,
  five adversaries, the trust assumptions and the points that are out of
  scope, and it carries a verification map from each claim to the test that
  covers it.
- `docs/audit.md` records the checks and the numbers: `gofmt`, `go vet`,
  `staticcheck`, `gosec`, `govulncheck`, the race-enabled tests, three fuzz
  targets and the netns integration test.
- The measured performance in `docs/audit.md`: an AEAD seal and open of a
  1200-byte payload at about 4.7 µs per frame with 2 allocations, and a
  sustained pipeline over loopback UDP at 8 to 9 µs per packet, 110 to 125
  thousand packets per second, 0 allocations per packet, 13 to 15 MB/s at
  100-byte packets.
- The manual checks in `docs/audit.md`: real TUN tunnels over the TLS, raw
  and UDP carriers, a browser-style client getting an HTTP response from the
  same port, the nfqws desync with a negative control, encrypted key
  storage, the metrics endpoint and the `SIGHUP` reload.
- The implementation: `internal/framing`, `internal/session`,
  `internal/crypto`, `internal/protocol` and the three carriers under
  `internal/transport`.
- The unit tests, the fuzz targets and `test/integration/`, including a soak
  test that runs a ping flood against a live tunnel.

Absent, and not to be invented: no download counts, no number of users, no
testimonials, no comparison with other VPN projects, no external review,
and no verification against a real TSPU in front of a real deployment. The
repository has no images and no landing page.

## Product Principles

1. **The carrier is the experiment.** The session layer must not learn about
   sockets, buffers, the MTU or a padding policy. A new carrier is one file
   that satisfies `transport.Transport`, and a change to the shaping policy
   is a change to `internal/framing`.
2. **Nothing on the wire has a shape.** The version, the type, the sequence
   number and the length live inside the ciphertext, and every frame starts
   with a fresh random nonce.
3. **Measure the resistance, do not claim it.** The padding profiles, the
   cover traffic and the browser ClientHello raise the cost of passive
   classification. What a given network sees is something to measure in a
   lab and on the network, not a property to assert.
4. **Say where the guarantee stops.** The threat model, the protocol
   specification and the audit each carry a list of what is unverified, and
   a change that weakens one of them updates the list.
5. **The specification is written for a reviewer.** A change to the
   protocol semantics is a change to `docs/protocol.md`, in the same commit.

## Accessibility & Inclusion

The product has no interface to design. Its whole surface is a command line
and a line of log output, so there is nothing to make high-contrast,
large-type or screen-reader friendly.

What the code does:

- Every command is a verb with named flags. The two exceptions take a
  positional argument: `setup server|client` and `quick up|down|status`.
- Validation errors name the field and the value, for example
  `client: mtu 100 out of range [576, 65535]`, so a wrong setting is
  described in words rather than only in a log level.
- A passphrase is read from `VIBE_VPN_PASSPHRASE` or from a terminal prompt
  without echo. The environment variable is the path for anyone who cannot
  use a silent prompt.
- The statistics line is one line of `key=value` pairs, which reads poorly
  when it is read aloud.

Not decided: no accessibility standard has been set for the log format or
for the interactive script, and the repository says nothing about the users
it is written for, so there is no way to tell whether the terminal surface
is a barrier for the people who would run it. The honest answer is that the
question is open, and that it should be answered before the product claims
a user base beyond its author.
