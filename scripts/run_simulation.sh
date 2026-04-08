#!/usr/bin/env bash
# run_simulation.sh - Wrapper to start the full Chambers UAS simulation
# Sets up v4l2loopback, network namespace, then launches docker compose.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cleanup() {
    echo ""
    echo "[sim] Caught signal, shutting down..."
    echo "[sim] Stopping docker compose..."
    docker compose -f "$PROJECT_DIR/docker-compose.yml" down || true
    echo "[sim] Tearing down network namespace..."
    sudo "$SCRIPT_DIR/setup_netns.sh" --teardown || true
    echo "[sim] Cleanup complete."
}

trap cleanup EXIT INT TERM

echo "============================================"
echo " Chambers UAS Simulation"
echo "============================================"

# Step 1: Set up v4l2loopback
echo ""
echo "[sim] Step 1/3: Setting up v4l2loopback..."
if [[ -x "$SCRIPT_DIR/setup_v4l2loopback.sh" ]]; then
    sudo "$SCRIPT_DIR/setup_v4l2loopback.sh"
else
    echo "[sim] WARNING: setup_v4l2loopback.sh not found or not executable, skipping."
fi

# Step 2: Set up network namespace
echo ""
echo "[sim] Step 2/3: Setting up network namespace..."
sudo "$SCRIPT_DIR/setup_netns.sh"

# Step 3: Launch docker compose
echo ""
echo "[sim] Step 3/3: Starting docker compose..."
docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d

echo ""
echo "[sim] Simulation is running. Press Ctrl+C to stop."
echo ""

# Wait indefinitely until interrupted
while true; do
    sleep 1
done
