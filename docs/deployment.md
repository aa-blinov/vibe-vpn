# Deployment: CDN masking and transport redundancy

This guide covers two things that make the tunnel harder to block and more
resilient in front of network-level censorship (e.g. TSPU in front of a
European server):

1. **CDN / reverse-proxy masking** — put the TLS listener behind a real web
   edge so the public `:443` looks like ordinary HTTPS.
2. **Transport redundancy** — serve several transports at once and let the
   client fall back between them automatically.

## 1. CDN / reverse-proxy masking

The `tlsx` browser mode already imitates a real browser: a Chrome/Firefox
ClientHello (via uTLS), SNI = your real domain, ALPN `http/1.1`, and the
tunnel is selected by a 4-byte magic sequence written *inside* the encrypted
TLS stream. To a passive observer the connection is indistinguishable from
browsing HTTPS.

Because the tunnel is selected inside the TLS stream (not by a URL path), a
normal HTTP terminating proxy (nginx `http{}`, Caddy) will not work — it would
see the magic bytes as an HTTP request and interfere. Use a **TCP passthrough**
instead:

### Option A — nginx `stream` (TCP passthrough)

See `deploy/nginx-stream.conf`. In short:

- nginx owns the public `:443`, holds a real Let's Encrypt certificate and
  forwards raw TCP to the vibe-vpn TLS listener on an internal port
  (e.g. `127.0.0.1:1443`).
- `vibe-vpn server` config:
  ```yaml
  server:
    tls:
      listen: 127.0.0.1:1443   # not public — nginx owns 443
      cert: /etc/vibe-vpn/server.crt
      key: /etc/vibe-vpn/server.key
  ```
- The client still connects to `vpn.example.com:443` and pins `server.crt`
  (generate it for the real domain so SNI matches).

### Option B — Cloudflare Spectrum

Spectrum is a managed TCP/UDP passthrough. Point a Spectrum app at
`vpn.example.com:443` with the origin set to your VPS; Spectrum forwards the
bytes untouched, so the tunnel works unchanged and the edge IPs are
Cloudflare's (which RKN cannot simply block). Same server config as Option A.

### Option C — direct, with a real certificate

If you do not need a CDN, the simplest robust setup is to run vibe-vpn
directly on the public `:443` with a Let's Encrypt certificate for your real
domain and set `tls.server_name` / SNI to that domain. This is the default
`vibe-vpn setup server` behavior.

## 2. Transport redundancy

The server can listen on UDP, TLS and raw TCP **at the same time** (they are
independent listeners). The client tries its transports in order on every
reconnect and falls back to the next one if the current is unreachable or
blocked.

### Server — enable several transports

```yaml
server:
  listen: 0.0.0.0:443     # UDP rendezvous on 443 (UDP and TCP share the port)
  tls:
    listen: 0.0.0.0:443   # TLS on TCP 443 alongside the UDP listener
    cert: /etc/vibe-vpn/server.crt
    key: /etc/vibe-vpn/server.key
  raw:
    listen: 0.0.0.0:4444  # obfs4-style raw TCP black hole
```

### Client — fallback chain

```yaml
client:
  server: vpn.example.com:443      # TLS primary
  raw_server: vpn.example.com:4444 # raw TCP fallback
```

On each (re)connect the client tries TLS first, then raw TCP. If TLS is
blocked but raw TCP passes, the tunnel comes up over the fallback without any
manual action.

> **UDP/TCP on the same port:** Linux allows a TCP socket and a UDP socket to
> both bind `:443`. The rendezvous-on-443 idea is to make UDP look like QUIC,
> which rides UDP/443 and is broadly allowed by middleboxes.

## 3. What still needs a human on a real network

The configuration and unit/integration tests here prove the mechanics (server
serves multiple transports; client fails over). They do **not** prove that a
given transport survives the actual TSPU in front of a European VPS — that
depends on which IPs and protocols are blocked. Verify from a real Russian
ISP/mobile network and adjust the transport order accordingly.
