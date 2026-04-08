#!/usr/bin/env bash
# verify_audit_log.sh - Verify a Chambers audit log using the chambers-verify binary
# Usage: ./verify_audit_log.sh <audit_log_path> <hex_public_key>
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <audit_log_path> <hex_public_key>"
    echo ""
    echo "  audit_log_path  Path to the NDJSON audit log file"
    echo "  hex_public_key  Hex-encoded Ed25519 public key for signature verification"
    exit 1
fi

AUDIT_LOG="$1"
PUBKEY="$2"

if [[ ! -f "$AUDIT_LOG" ]]; then
    echo "Error: Audit log file not found: $AUDIT_LOG"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Look for the binary in common locations
VERIFY_BIN=""
for candidate in \
    "$PROJECT_DIR/chambers/target/release/chambers-verify" \
    "$PROJECT_DIR/chambers/target/debug/chambers-verify" \
    "$(command -v chambers-verify 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
        VERIFY_BIN="$candidate"
        break
    fi
done

if [[ -z "$VERIFY_BIN" ]]; then
    echo "Error: chambers-verify binary not found."
    echo "Build it with: cd chambers && cargo build --release"
    exit 1
fi

echo "Verifying audit log: $AUDIT_LOG"
echo "Public key: $PUBKEY"
echo ""

exec "$VERIFY_BIN" --audit-log "$AUDIT_LOG" --public-key "$PUBKEY"
