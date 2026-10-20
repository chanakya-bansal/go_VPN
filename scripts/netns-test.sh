#!/usr/bin/env bash
# Creates a fake "client machine" (network namespace) wired to the host by a virtual cable.
#   host (server side): veth-h  192.168.100.1
#   namespace (client): veth-c  192.168.100.2
set -e
case "$1" in
  up)
    mkdir -p /etc/netns/vpnclient
    echo "nameserver 1.1.1.1" > /etc/netns/vpnclient/resolv.conf
    ip netns add vpnclient
    ip link add veth-h type veth peer name veth-c
    ip link set veth-c netns vpnclient
    ip addr add 192.168.100.1/24 dev veth-h
    ip link set veth-h up
    ip netns exec vpnclient ip addr add 192.168.100.2/24 dev veth-c
    ip netns exec vpnclient ip link set veth-c up
    ip netns exec vpnclient ip link set lo up
    echo "namespace 'vpnclient' ready"
    ;;
  down)
    rm -rf /etc/netns/vpnclient
    ip netns del vpnclient 2>/dev/null || true
    ip link del veth-h 2>/dev/null || true
    echo "cleaned up"
    ;;
  *)
    echo "usage: sudo $0 up|down"; exit 1 ;;
esac