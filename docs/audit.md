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
- Full client/server stack over loopback UDP with TUN:
  - round-trip (one packet in flight): ~31.5 µs/packet;
  - **sustained pipeline: ~8–9 µs/packet (~110–125k packets/s), 0 allocs/op**,
    13–15 MB/s at 100-byte packets (~1 Gbps at MTU-sized packets).
  Optimizations applied (measured step by step): single-allocation in-place
  AEAD seal, reused decryption plaintext buffer, UDP endpoint keyed by
  `netip.AddrPort` (no per-datagram string/addr allocation), batched receive
  draining in the session run loops, and GC-stable freelists for seal output
  and datagram buffers (0 allocations per packet).
- The pipeline is within ~2x of the crypto ceiling (~4.7 µs/frame); the
  remainder is UDP syscalls and goroutine scheduling. Further userspace gains
  are small and costly: recvmmsg/sendmmsg require raw syscalls (no stdlib
  support) for ~5–15%; io_uring is a data-path rewrite for ~15–30%. A kernel
  data path is the only order-of-magnitude option.

## What remains

- **External human review** of the protocol specification
  (`docs/protocol.md`) and the implementation. Automated tooling does not
  replace a reviewer who can reason about the threat model.
- Long-running soak/reliability testing against real-world networks.
