#!/usr/bin/env bash
#
# bridge-down.sh — tear down the lab taps (and the bridge, once empty) created
#                  by bridge-up.sh. Run as root.
#
# Usage:
#   sudo ./qemu/bridge-down.sh [node ...]      # default node: sender
#   sudo ./qemu/bridge-down.sh sender receiver relay
#
# Environment:
#   BRIDGE   bridge name (default: br-notch)
#
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "error: run as root, e.g. sudo $0 $*" >&2; exit 1; }

BRIDGE="${BRIDGE:-br-notch}"
NODES=("$@"); [ "${#NODES[@]}" -gt 0 ] || NODES=(sender)

for node in "${NODES[@]}"; do
  tap="tap-$node"
  if ip link show "$tap" >/dev/null 2>&1; then
    ip link set "$tap" down 2>/dev/null || true
    ip tuntap del dev "$tap" mode tap
    echo "removed tap $tap"
  fi
done

# Remove the bridge only if no ports remain (so it survives a single-node down
# while other nodes are still attached).
if ip link show "$BRIDGE" >/dev/null 2>&1; then
  remaining=$(ls /sys/class/net/"$BRIDGE"/brif 2>/dev/null | wc -l)
  if [ "$remaining" -eq 0 ]; then
    ip link set "$BRIDGE" down
    ip link delete "$BRIDGE" type bridge
    echo "removed bridge $BRIDGE"
  else
    echo "bridge $BRIDGE still has $remaining port(s); leaving it up"
  fi
fi
