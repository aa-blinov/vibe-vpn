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

## What remains

- **External human review** of the protocol specification
  (`docs/protocol.md`) and the implementation. Automated tooling does not
  replace a reviewer who can reason about the threat model.
- Performance benchmarking across transports and larger topologies.
- Long-running soak/reliability testing against real-world networks.
