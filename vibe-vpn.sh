#!/usr/bin/env bash
# vibe-vpn.sh — interactive one-command setup for the vibe-vpn server and client.
#
#   ./vibe-vpn.sh server    # interactive server setup (keys, cert, config, systemd)
#   ./vibe-vpn.sh client    # interactive client setup (config from the server's dir)
#
# Requires: bash, sudo, and the binary built with `make build` (it is built
# automatically if missing).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$ROOT/bin/vibe-vpn"

say()  { printf '%s\n' "$*"; }
step() { printf '\n[==>] %s\n' "$*"; }

need_bin() {
  if [ ! -x "$BIN" ]; then
    step "building the vibe-vpn binary..."
    (cd "$ROOT" && make build)
  fi
}

ask() { # ask VAR prompt default
  local var="$1" prompt="$2" default="${3:-}" ans
  if [ -n "$default" ]; then
    read -rp "$prompt [$default]: " ans
    ans="${ans:-$default}"
  else
    read -rp "$prompt: " ans
  fi
  printf -v "$var" '%s' "$ans"
}

yesno() { # yesno prompt default -> 0=yes 1=no
  local prompt="$1" default="${2:-n}" ans
  read -rp "$prompt [${default}]: " ans
  ans="${ans:-$default}"
  case "$ans" in y|Y|yes|Yes) return 0;; *) return 1;; esac
}

setup_server() {
  need_bin
  step "server setup"
  ask DOMAIN "Domain name (or public IP) of this server" ""
  ask TLS_PORT "TLS listen port" "443"
  ask OUT "Output directory" "/etc/vibe-vpn-server"
  ask SUBNET "Tunnel subnet" "10.77.0.0/24"

  step "generating keys, TLS certificate and server.yaml"
  sudo "$BIN" setup server \
    --out "$OUT" \
    --domain "$DOMAIN" \
    --tls-listen "0.0.0.0:$TLS_PORT" \
    --subnet "$SUBNET"

  step "opening TCP $TLS_PORT in the host firewall (ufw)"
  if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow "${TLS_PORT}/tcp" >/dev/null 2>&1 && say "  ufw: allowed ${TLS_PORT}/tcp"
  fi

  if yesno "Install as a systemd service (auto-start on boot)?" y; then
    install_service "$OUT"
    say "  start now with:  sudo systemctl start vibe-vpn-server"
    say "  view logs:       sudo journalctl -u vibe-vpn-server -f"
  else
    say "  start with:      sudo $BIN server --config $OUT/server.yaml"
  fi

  step "server is ready"
  say "  copy this directory to the client and pass it as -peer:"
  say "      $OUT"
  say "  (it contains peer.txt, server.crt, server.pub)"
}

install_service() {
  local out="$1" bin_path
  bin_path="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
  local unit="$ROOT/deploy/vibe-vpn-server.service"
  local tmp="/tmp/vibe-vpn-server.service"
  if [ -f "$unit" ]; then
    sed -e "s|@BIN@|$bin_path|g" -e "s|@CONFIG@|$out/server.yaml|g" "$unit" > "$tmp"
  else
    cat > "$tmp" <<EOF
[Unit]
Description=vibe-vpn server
After=network-online.target

[Service]
ExecStart=$bin_path server --config $out/server.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  fi
  sudo cp "$tmp" /etc/systemd/system/vibe-vpn-server.service
  sudo systemctl daemon-reload
  sudo systemctl enable vibe-vpn-server
  say "  systemd unit installed: vibe-vpn-server"
}

setup_client() {
  need_bin
  step "client setup"
  ask SERVER "Server address (host:port)" ""
  ask PEER "Server peer directory (copied from the server)" ""
  ask OUT "Output directory" "/etc/vibe-vpn-client"

  local extra=()
  if yesno "Enable nfqws DPI desync of the tunnel's TCP flow?" n; then
    ask NFQWS "Path to the nfqws binary" "/usr/local/bin/nfqws"
    extra=(--desync --nfqws "$NFQWS")
  fi

  step "generating client.yaml"
  sudo "$BIN" setup client \
    --out "$OUT" \
    --server "$SERVER" \
    --peer "$PEER" \
    "${extra[@]}"

  step "client is ready"
  say "  connect with:  sudo $BIN client --config $OUT/client.yaml"
  say "  verify with:   ping 10.77.0.1"
  if yesno "Connect now?" n; then
    sudo "$BIN" client --config "$OUT/client.yaml"
  fi
}

case "${1:-}" in
  server) setup_server ;;
  client) setup_client ;;
  *)
    echo "usage: $0 server|client" >&2
    echo "  $0 server   — interactive server setup (run on the VPS)" >&2
    echo "  $0 client   — interactive client setup (run on the laptop)" >&2
    exit 1 ;;
esac
