#!/bin/bash
set -euo pipefail

# setup_v4l2loopback.sh -- Load the v4l2loopback kernel module.
#
# Idempotent: safe to run multiple times. Pass --teardown to remove.

DEVICES=2
VIDEO_NR="10,11"
CARD_LABELS="Chambers-Camera-0,Chambers-Camera-1"

usage() {
    echo "Usage: $0 [--teardown]"
    echo "  (no args)    Load v4l2loopback with $DEVICES devices at /dev/video{$VIDEO_NR}"
    echo "  --teardown   Unload v4l2loopback module"
    exit 0
}

teardown() {
    echo "Tearing down v4l2loopback..."
    if lsmod | grep -q v4l2loopback; then
        sudo modprobe -r v4l2loopback
        echo "v4l2loopback module unloaded."
    else
        echo "v4l2loopback is not loaded, nothing to do."
    fi
}

setup() {
    if lsmod | grep -q v4l2loopback; then
        echo "v4l2loopback is already loaded."
        # Verify expected devices exist
        for dev_nr in ${VIDEO_NR//,/ }; do
            if [ -e "/dev/video${dev_nr}" ]; then
                echo "  /dev/video${dev_nr} exists"
            else
                echo "  WARNING: /dev/video${dev_nr} not found despite module loaded"
            fi
        done
        return 0
    fi

    echo "Loading v4l2loopback module..."
    sudo modprobe v4l2loopback \
        devices="$DEVICES" \
        video_nr="$VIDEO_NR" \
        card_label="$CARD_LABELS" \
        exclusive_caps=1

    # Brief wait for device nodes to appear
    sleep 1

    for dev_nr in ${VIDEO_NR//,/ }; do
        if [ -e "/dev/video${dev_nr}" ]; then
            echo "  /dev/video${dev_nr} ready"
        else
            echo "  ERROR: /dev/video${dev_nr} did not appear" >&2
            exit 1
        fi
    done

    echo "v4l2loopback loaded successfully."
}

case "${1:-}" in
    --teardown)
        teardown
        ;;
    --help|-h)
        usage
        ;;
    *)
        setup
        ;;
esac
