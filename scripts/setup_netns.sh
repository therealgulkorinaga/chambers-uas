#!/usr/bin/env bash
# setup_netns.sh - Idempotent setup of the chambers_drone network namespace
# Usage: ./setup_netns.sh [--teardown]
set -euo pipefail

NS_NAME="chambers_drone"
VETH_HOST="veth-host"
VETH_DRONE="veth-drone"
HOST_IP="10.0.0.1/24"
DRONE_IP="10.0.0.2/24"

teardown() {
    echo "[netns] Tearing down namespace '$NS_NAME'..."
    # Delete the namespace (also removes veth pair)
    if ip netns list | grep -qw "$NS_NAME"; then
        ip netns del "$NS_NAME"
        echo "[netns] Namespace '$NS_NAME' deleted."
    else
        echo "[netns] Namespace '$NS_NAME' does not exist, nothing to tear down."
    fi

    # Remove host-side veth if it lingers
    if ip link show "$VETH_HOST" &>/dev/null; then
        ip link del "$VETH_HOST" 2>/dev/null || true
        echo "[netns] Removed lingering $VETH_HOST interface."
    fi

    # Remove iptables NAT rule
    iptables -t nat -D POSTROUTING -s 10.0.0.0/24 ! -o "$VETH_HOST" -j MASQUERADE 2>/dev/null || true
    echo "[netns] NAT rule cleaned up."
}

setup() {
    # Check if namespace already exists
    if ip netns list | grep -qw "$NS_NAME"; then
        echo "[netns] Namespace '$NS_NAME' already exists. Skipping creation."
        echo "[netns] Use --teardown to remove it first if you want to recreate."
        exit 0
    fi

    echo "[netns] Creating namespace '$NS_NAME'..."

    # Create the network namespace
    ip netns add "$NS_NAME"

    # Create veth pair
    ip link add "$VETH_HOST" type veth peer name "$VETH_DRONE"

    # Move drone end into the namespace
    ip link set "$VETH_DRONE" netns "$NS_NAME"

    # Configure host side
    ip addr add "$HOST_IP" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    # Configure drone side
    ip netns exec "$NS_NAME" ip addr add "$DRONE_IP" dev "$VETH_DRONE"
    ip netns exec "$NS_NAME" ip link set "$VETH_DRONE" up
    ip netns exec "$NS_NAME" ip link set lo up
    ip netns exec "$NS_NAME" ip route add default via 10.0.0.1

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Add NAT rule (idempotent: check first)
    if ! iptables -t nat -C POSTROUTING -s 10.0.0.0/24 ! -o "$VETH_HOST" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.0.0.0/24 ! -o "$VETH_HOST" -j MASQUERADE
    fi

    echo "[netns] Namespace '$NS_NAME' is ready."
    echo "[netns]   Host side: $VETH_HOST ($HOST_IP)"
    echo "[netns]   Drone side: $VETH_DRONE ($DRONE_IP) inside ns '$NS_NAME'"
}

# ---- Main ----
if [[ "${1:-}" == "--teardown" ]]; then
    teardown
else
    setup
fi
