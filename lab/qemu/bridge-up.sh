#!/usr/bin/env bash
#
# bridge-up.sh — create the isolated L2 bridge + per-node tap devices for the
#                notch QEMU lab. Run ONCE as root; qemu/run.sh then attaches to
#                the taps as your normal user (no root, no cargo-under-sudo).
#
# The bridge has no uplink and (by default) no IP, so it is a private L2
# segment shared only by the lab VMs — nothing reaches the host network or the
# internet. Add nodes just by naming them; each gets tap-<node> on the bridge.
#
# Usage:
#   sudo ./qemu/bridge-up.sh [node ...]        # default node: sender
#   sudo ./qemu/bridge-up.sh sender receiver relay
#
# Environment:
#   BRIDGE     bridge name              (default: br-notch)
#   TAP_USER   user that owns the taps  (default: $SUDO_USER, else root)
#   BRIDGE_IP  host IP/CIDR to put on the bridge so you can tcpdump/observe
#              from the host (default: unset -> no IP, fully isolated)
#
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "error: run as root, e.g. sudo $0 $*" >&2; exit 1; }

BRIDGE="${BRIDGE:-br-notch}"
TAP_USER="${TAP_USER:-${SUDO_USER:-root}}"
NODES=("$@"); [ "${#NODES[@]}" -gt 0 ] || NODES=(sender)

# Don't let netfilter filter bridged L2 frames (keeps VM<->VM traffic flowing
# regardless of host firewall rules). Only applies if br_netfilter is loaded.
for f in /proc/sys/net/bridge/bridge-nf-call-{iptables,ip6tables,arptables}; do
  [ -w "$f" ] && echo 0 > "$f" || true
done

# --- bridge -------------------------------------------------------------------
if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
  ip link add name "$BRIDGE" type bridge
  echo "created bridge $BRIDGE"
fi
# STP off + zero forward delay: ports forward immediately, no spanning tree.
ip link set "$BRIDGE" type bridge stp_state 0 forward_delay 0
ip link set "$BRIDGE" up
if [ -n "${BRIDGE_IP:-}" ]; then
  ip addr replace "$BRIDGE_IP" dev "$BRIDGE"
  echo "bridge $BRIDGE host IP: $BRIDGE_IP"
fi

# --- per-node taps ------------------------------------------------------------
for node in "${NODES[@]}"; do
  tap="tap-$node"
  if ! ip link show "$tap" >/dev/null 2>&1; then
    ip tuntap add dev "$tap" mode tap user "$TAP_USER"
    echo "created tap $tap (owner: $TAP_USER)"
  fi
  ip link set "$tap" master "$BRIDGE"
  ip link set "$tap" up
done

echo "ready: bridge '$BRIDGE' with taps ${NODES[*]/#/tap-}"
ip -br link show master "$BRIDGE"
