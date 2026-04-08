#!/bin/bash
set -euo pipefail

# bridge.sh -- Pipe video into a V4L2 loopback device.
#
# When GAZEBO_CAMERA_TOPIC is set, attempt to pull frames from that ROS/Gazebo
# image topic via GStreamer's rosimagesrc element. Otherwise fall back to a
# synthetic test pattern so the rest of the stack can run without Gazebo.

DEVICE="${V4L2_DEVICE:-/dev/video10}"

wait_for_device() {
    local retries=30
    while [ ! -e "$DEVICE" ] && [ "$retries" -gt 0 ]; do
        echo "Waiting for $DEVICE to appear..."
        sleep 1
        retries=$((retries - 1))
    done
    if [ ! -e "$DEVICE" ]; then
        echo "ERROR: $DEVICE did not appear after 30 seconds" >&2
        exit 1
    fi
}

wait_for_device

if [ -n "${GAZEBO_CAMERA_TOPIC:-}" ]; then
    echo "Bridging Gazebo camera topic: $GAZEBO_CAMERA_TOPIC -> $DEVICE"
    exec gst-launch-1.0 -v \
        rosimagesrc topic="$GAZEBO_CAMERA_TOPIC" \
        ! videoconvert \
        ! "video/x-raw,format=YUY2,width=1920,height=1080,framerate=30/1" \
        ! v4l2sink device="$DEVICE"
else
    echo "Using test pattern (Gazebo not connected)"
    exec gst-launch-1.0 -v \
        videotestsrc pattern=ball \
        ! "video/x-raw,format=YUY2,width=1920,height=1080,framerate=30/1" \
        ! v4l2sink device="$DEVICE"
fi
