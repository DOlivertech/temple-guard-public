#!/usr/bin/env bash
#
# tg-vpn — VPN sidecar for Temple Guard.
#
# Runs your VPN INSIDE a container so the scan containers can reach a client's
# PRIVATE network (which normally only your machine can see). Scan containers then
# attach with `--network container:tg-vpn` — set the engagement's "Scan network"
# to `container:tg-vpn` and run your suites as usual. Works on macOS *and* Linux
# (the tunnel lives in Docker, so the Mac-VPN-vs-Docker-VM problem doesn't apply).
#
# Reuses the templeguard/kali image (ships openvpn / wireguard / tailscale) — no
# extra image.
#
# Usage:
#   scripts/vpn-sidecar.sh up <client.ovpn> [auth-user-pass.txt]   # OpenVPN (auto)
#   scripts/vpn-sidecar.sh up <client.conf>                        # WireGuard (auto)
#   scripts/vpn-sidecar.sh up openvpn   <client.ovpn> [auth.txt]
#   scripts/vpn-sidecar.sh up wireguard <client.conf>              # Proton/Mullvad/WG
#   scripts/vpn-sidecar.sh up tailscale <authkey> [exit-node-ip]   # exit-node = carry ALL traffic
#   scripts/vpn-sidecar.sh status
#   scripts/vpn-sidecar.sh down
#
# Authorized engagements only. Only tunnel into a network you are permitted to test.
set -euo pipefail

NAME="tg-vpn"
IMAGE="templeguard/kali:latest"
COMMON=(-d --name "$NAME" --cap-add=NET_ADMIN --device /dev/net/tun
        --label templeguard=true --label tg.role=vpn)

abspath() { cd "$(dirname "$1")" && printf '%s/%s' "$(pwd)" "$(basename "$1")"; }
die() { echo "✗ $*" >&2; exit 1; }

wait_for() {  # wait_for <grep-pattern> <max-tries>
  local pat="$1" tries="${2:-45}"
  for _ in $(seq 1 "$tries"); do
    docker logs "$NAME" 2>&1 | grep -q "$pat" && return 0
    docker ps -q --filter "name=$NAME" | grep -q . || {
      echo "✗ the VPN container exited:"; docker logs "$NAME" 2>&1 | tail -15; exit 1; }
    sleep 2
  done
  return 1
}

ready_banner() {
  echo "✓ tunnel up."
  docker exec "$NAME" sh -c "ip -4 addr show 2>/dev/null | sed -n 's/.*inet \\([0-9.]*\\).* \\(tun0\\|wg\\|tailscale0\\)$/  \\2: \\1/p'" 2>/dev/null || true
  echo
  echo "Next: set the engagement's Scan network to →  container:$NAME"
  echo "      (engagement page → Scan network → ✎ edit), then run your suite."
}

up_openvpn() {
  local cfg; cfg="$(abspath "$1")"; [ -f "$cfg" ] || die "no such file: $1"
  local run=("${COMMON[@]}" -v "$cfg":/vpn/client.ovpn:ro)
  local cmd=(openvpn --config /vpn/client.ovpn --auth-nocache --verb 3)
  if [ -n "${2:-}" ]; then
    local auth; auth="$(abspath "$2")"; [ -f "$auth" ] || die "no such auth file: $2"
    run+=(-v "$auth":/vpn/auth.txt:ro); cmd+=(--auth-user-pass /vpn/auth.txt)
  fi
  docker run "${run[@]}" "$IMAGE" "${cmd[@]}" >/dev/null
  echo "→ OpenVPN tunnel starting in '$NAME'…"
  wait_for "Initialization Sequence Completed" && ready_banner \
    || echo "⚠ not confirmed yet — docker logs -f $NAME"
}

up_wireguard() {
  local cfg; cfg="$(abspath "$1")"; [ -f "$cfg" ] || die "no such file: $1"
  docker run "${COMMON[@]}" \
    --sysctl net.ipv4.conf.all.src_valid_mark=1 \
    -e WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go -e LOG_LEVEL=info \
    -v "$cfg":/vpn/wg.conf:ro "$IMAGE" \
    bash -c 'wg-quick up /vpn/wg.conf && echo "WG_SIDECAR_UP" && sleep infinity' >/dev/null
  echo "→ WireGuard tunnel starting in '$NAME'…"
  wait_for "WG_SIDECAR_UP" && ready_banner \
    || { echo "✗ wg-quick failed:"; docker logs "$NAME" 2>&1 | tail -15; exit 1; }
}

up_tailscale() {
  local key="$1"; [ -n "$key" ] || die "tailscale needs an auth key (tailscale up --authkey)"
  local exit_node="${2:-}"
  docker run "${COMMON[@]}" -e TS_AUTHKEY="$key" -e TS_EXIT="$exit_node" "$IMAGE" \
    bash -c 'mkdir -p /var/run/tailscale /var/lib/tailscale
             tailscaled --state=/var/lib/tailscale/tailscaled.state \
                        --socket=/var/run/tailscale/tailscaled.sock >/tmp/tsd.log 2>&1 &
             sleep 3
             tailscale up --authkey="$TS_AUTHKEY" --hostname=tg-vpn --accept-routes \
               ${TS_EXIT:+--exit-node="$TS_EXIT" --exit-node-allow-lan-access} \
               && echo "TS_SIDECAR_UP" && sleep infinity' >/dev/null
  echo "→ Tailscale joining your tailnet…${exit_node:+ (exit-node $exit_node — all traffic routes through it)}"
  wait_for "TS_SIDECAR_UP" && { ready_banner; docker exec "$NAME" tailscale status 2>/dev/null | head -5; } \
    || { echo "✗ tailscale up failed:"; docker logs "$NAME" 2>&1 | tail -20; exit 1; }
}

case "${1:-}" in
  up)
    sub="${2:-}"; [ -n "$sub" ] || die "usage: up {<f.ovpn>|<f.conf>|openvpn <f>|wireguard <f>|tailscale <key> [exit-ip]}"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    case "$sub" in
      openvpn)   up_openvpn   "${3:?need <client.ovpn>}" "${4:-}" ;;
      wireguard) up_wireguard "${3:?need <client.conf>}" ;;
      tailscale) up_tailscale "${3:?need <authkey>}" "${4:-}" ;;
      *.ovpn)    up_openvpn   "$sub" "${3:-}" ;;
      *.conf)    up_wireguard "$sub" ;;
      *) die "can't tell the VPN type — use: up {openvpn <f.ovpn> | wireguard <f.conf> | tailscale <key> [exit-ip]}" ;;
    esac
    ;;
  status)
    if docker ps -q --filter "name=$NAME" | grep -q .; then
      docker ps --filter "name=$NAME" --format '  {{.Names}}: {{.Status}}'
      docker exec "$NAME" sh -c "ip -4 addr show 2>/dev/null | sed -n 's/.*inet /  ip: /p' | grep -vE '127.0.0.1|172.1[0-9]'" 2>/dev/null || true
    else
      echo "  $NAME is not running."
    fi
    ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "✓ stopped $NAME" || echo "  $NAME was not running"
    ;;
  *)
    echo "usage: $0 {up <vpn-config|backend ...> | status | down}"
    echo "  up <client.ovpn> [auth.txt]      OpenVPN"
    echo "  up <client.conf>                 WireGuard (Proton/Mullvad/WG)"
    echo "  up tailscale <authkey> [exit-ip] Tailscale (exit-node = carry ALL traffic)"
    exit 1
    ;;
esac
