# Verification and audit status

What has been checked automatically and what still needs a human reviewer.

## Automated checks (run on every push)

| Check | Tool | Status |
|-------|------|--------|
| Formatting | `gofmt -l` | clean |
| Static analysis | `go vet`, `staticcheck` | 0 findings |
| Security scan | `gosec` | 0 findings (intentional items annotated `#nosec`) |
| Vulnerability scan | `govulncheck` | 0 vulnerabilities affecting code |
| Data races | `go test -race` | clean, all packages |
| Fuzzing | `go test -fuzz` (framing, replay, IPv4 parse) | no crashes; run on every push (30s) and before every release (60s) |
| End-to-end | integration test with real TUN devices in a network namespace | passes |
| Dependencies | Dependabot (go modules + GitHub Actions) | enabled; updates reviewed before merge |

## Manual verification performed

- Full client/server tunnel over real TUNs (netns), TLS transport, raw transport
  and UDP; ping through the tunnel.
- HTTPS camouflage: a browser-style TLS client gets an HTTP response from the
  same port.
- nfqws (zapret) DPI-desync of the tunnel's TCP flow; negative control
  (queue without a handler stalls the tunnel) confirms interception.
- Encrypted key storage: correct passphrase starts the server, wrong one fails
  cleanly.
- Metrics endpoint (server traffic counters, client RTT histogram), SIGHUP
  peer-list reload.

## Performance (current, linux/amd64)

- Per-frame AEAD (Seal+Open, 1200-byte payload): ~4.7 µs/frame, 2 allocs/op
  (the crypto ceiling; ~210k frames/s).
- Full client/server stack over loopback UDP with TUN: ~31.5 µs/packet
  (~32k packets/s), **2 allocs/op**, 320 B/op. Optimizations applied:
  single-allocation in-place AEAD seal, reused decryption plaintext buffer,
  UDP endpoint keyed by `netip.AddrPort` (no per-datagram string/addr
  allocation).
- The remaining ~27 µs per packet is syscalls (TUN + UDP), goroutine
  scheduling and channel hops, not cryptography or allocations. Going faster
  needs architectural work: transport buffer pooling, batching, io_uring /
  zero-copy, or a kernel data path.

## What remains

- **External human review** of the protocol specification
  (`docs/protocol.md`) and the implementation. Automated tooling does not
  replace a reviewer who can reason about the threat model.
- Long-running soak/reliability testing against real-world networks.
