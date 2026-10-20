#!/usr/bin/env bash
# Run on the server: IP forwarding + NAT for the VPN subnet.
#   sudo ./setup.sh up      enable
#   sudo ./setup.sh down    remove the rules
set -euo pipefail
SUBNET=${SUBNET:-10.8.0.0/24}
TUN=${TUN:-vpn-s0}
WAN=${WAN:-$(ip -4 route show default | awk '{print $5; exit}')}

add() { iptables "$@" 2>/dev/null || true; }

case "${1:-up}" in
  up)
    sysctl -w net.ipv4.ip_forward=1
    iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE
    iptables -C FORWARD -i "$TUN" -o "$WAN" -j ACCEPT 2>/dev/null \
      || iptables -A FORWARD -i "$TUN" -o "$WAN" -j ACCEPT
    iptables -C FORWARD -i "$WAN" -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
      || iptables -A FORWARD -i "$WAN" -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
      || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    echo "NAT up: $SUBNET -> $WAN (tun $TUN)"
    ;;
  down)
    add -t nat -D POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE
    add -D FORWARD -i "$TUN" -o "$WAN" -j ACCEPT
    add -D FORWARD -i "$WAN" -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    add -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    echo "NAT rules removed"
    ;;
  *) echo "usage: sudo $0 up|down"; exit 1 ;;
esac