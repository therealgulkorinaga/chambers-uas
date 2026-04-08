# Chambers for UAS — Simulation Implementation PRD

**Product Requirements Document — Exhaustive Specification**
**Author:** Arko Ganguli
**Date:** 2026-04-08
**Status:** Draft
**Reference:** `chambers_uas_position_paper.pdf` (Revised Draft, April 2026)

---

## Table of Contents

1. [Purpose & Scope](#1-purpose--scope)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [System Architecture Overview](#3-system-architecture-overview)
4. [Simulation Infrastructure](#4-simulation-infrastructure)
5. [Module 1: Session Lifecycle Manager](#5-module-1-session-lifecycle-manager)
6. [Module 2: Cryptographic Engine](#6-module-2-cryptographic-engine)
7. [Module 3: Preservation Manifest](#7-module-3-preservation-manifest)
8. [Module 4: Burn Engine](#8-module-4-burn-engine)
9. [Module 5: MAVLink Encryption Proxy](#9-module-5-mavlink-encryption-proxy)
10. [Module 6: Camera Pipeline Encryption](#10-module-6-camera-pipeline-encryption)
11. [Module 7: V4L2 Anomaly Detection](#11-module-7-v4l2-anomaly-detection)
12. [Module 8: Manifest-Aware Firewall](#12-module-8-manifest-aware-firewall)
13. [Module 9: Sealed Event Engine](#13-module-9-sealed-event-engine)
14. [Module 10: Audit Log System](#14-module-10-audit-log-system)
15. [Module 11: Ground Control Station Interface](#15-module-11-ground-control-station-interface)
16. [Integration Testing Scenarios](#16-integration-testing-scenarios)
17. [Technology Stack & Dependencies](#17-technology-stack--dependencies)
18. [Directory Structure](#18-directory-structure)
19. [Acceptance Criteria](#19-acceptance-criteria)
20. [Risk Register](#20-risk-register)

---

## 1. Purpose & Scope

### 1.1 Purpose

This PRD specifies the complete implementation of the Chambers sealed ephemeral computation model for UAS, running in a PX4 SITL + Gazebo simulation environment. The implementation validates the architecture described in the position paper by building every software component that does not require physical drone hardware.

### 1.2 What This Implementation Proves

- The Chambers session lifecycle (key generation, encryption, burn) works end-to-end on a simulated drone mission.
- The preservation manifest grammar can express real-world data governance policies and enforce them at runtime.
- Sealed events fire correctly in response to simulated flight safety triggers (geofence violations, emergency landings, near-miss events).
- The V4L2 anomaly detection pipeline detects undeclared sensor access via a `v4l2loopback` bridge from Gazebo camera output.
- MAVLink telemetry can be encrypted in-flight with negligible latency overhead in simulation.
- The audit log maintains cryptographic integrity across the full mission lifecycle and is verifiable post-mission using only the preserved public key.
- The manifest-aware firewall blocks undeclared outbound data flows.

### 1.3 What This Implementation Does NOT Prove

- Real-time encryption throughput on embedded hardware (Jetson Orin NX, Raspberry Pi 5).
- Hardware trust boundary guarantees (TPM, Secure Boot, ARM TrustZone).
- DJI Payload SDK integration.
- Counterfeit component detection.
- Flight controller firmware integrity.
- Multi-drone federation semantics.

### 1.4 Reference Architecture Mapping

| Paper Section | Implementation Module | Simulation Fidelity |
|---|---|---|
| 5.1 Companion Computer | Simulated as a Linux process co-located with PX4 SITL | High — same OS interfaces |
| 5.2 Session Lifecycle | Module 1: Session Lifecycle Manager | Full |
| 5.3 Key Management | Module 2: Cryptographic Engine | Full |
| 5.4 Anomaly Detection | Module 7: V4L2 via v4l2loopback bridge | Medium — virtual device, not real CSI |
| 6. Preservation Manifest | Module 3: Preservation Manifest | Full |
| 6.1 Sealed Events | Module 9: Sealed Event Engine | Full (PX4 SITL triggers) |
| 3.1 Data Exfiltration Protection | Module 8: Manifest-Aware Firewall | Medium — network namespaces |
| 3.1 Network Surveillance Protection | Module 2 + Module 5 | Full |

---

## 2. Goals & Non-Goals

### 2.1 Goals

1. **G1:** Build a fully functional Chambers companion computer module that runs alongside PX4 SITL + Gazebo.
2. **G2:** Implement the complete preservation manifest grammar as a typed, parseable, machine-readable specification with conflict resolution.
3. **G3:** Implement all six layers of the burn engine and demonstrate cryptographic destruction of undeclared data.
4. **G4:** Bridge Gazebo camera output into a virtual V4L2 device and demonstrate anomaly detection when an undeclared process accesses the camera.
5. **G5:** Encrypt all MAVLink telemetry between the simulated flight controller and the companion computer module using session-ephemeral keys.
6. **G6:** Implement all five sealed event types (airspace incursion, near-miss, emergency landing, geofence violation, payload anomaly) with correct preservation scope and stakeholder routing.
7. **G7:** Produce a signed, verifiable audit log for every simulated mission.
8. **G8:** Implement a manifest-aware network firewall that blocks undeclared outbound connections in a network-namespaced environment.
9. **G9:** Build a minimal GCS interface that can load manifests, receive session public keys, display audit logs, and trigger mid-mission preservation extensions.
10. **G10:** Create end-to-end integration tests covering the 8 scenarios defined in Section 16.

### 2.2 Non-Goals

1. **NG1:** Production-grade performance optimization. This is a validation prototype.
2. **NG2:** Real hardware deployment or cross-compilation for ARM targets.
3. **NG3:** DJI platform integration or any proprietary SDK usage.
4. **NG4:** Multi-drone swarm or federation semantics.
5. **NG5:** GUI for the GCS beyond what is needed for demonstration.
6. **NG6:** Hardware attestation, TPM integration, or Secure Boot configuration.
7. **NG7:** Cost-benefit analysis tooling.

---

## 3. System Architecture Overview

### 3.1 Component Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE (macOS/Linux)                   │
│                                                                     │
│  ┌──────────────┐     MAVLink (UDP)     ┌────────────────────────┐ │
│  │  PX4 SITL    │◄────────────────────►│  CHAMBERS MODULE       │ │
│  │  (Flight     │     :14540/:14550     │  (Companion Computer)  │ │
│  │  Controller) │                       │                        │ │
│  └──────┬───────┘                       │  ┌──────────────────┐  │ │
│         │                               │  │ Session Lifecycle │  │ │
│         │ Gazebo Plugin API             │  │ Manager           │  │ │
│  ┌──────▼───────┐                       │  ├──────────────────┤  │ │
│  │  GAZEBO      │    ROS2/GzTransport   │  │ Crypto Engine    │  │ │
│  │  (World +    │──────────────────────►│  ├──────────────────┤  │ │
│  │  Sensors)    │    Camera frames      │  │ Manifest Engine  │  │ │
│  │              │    LiDAR points       │  ├──────────────────┤  │ │
│  │  - Camera    │    IMU data           │  │ Burn Engine      │  │ │
│  │  - LiDAR     │                       │  ├──────────────────┤  │ │
│  │  - IMU       │                       │  │ MAVLink Proxy    │  │ │
│  │  - GPS       │                       │  ├──────────────────┤  │ │
│  └──────────────┘                       │  │ V4L2 Monitor     │  │ │
│                                         │  ├──────────────────┤  │ │
│  ┌──────────────┐                       │  │ Firewall         │  │ │
│  │ v4l2loopback │◄──(gst-launch)────── │  ├──────────────────┤  │ │
│  │ /dev/video0  │                       │  │ Sealed Events    │  │ │
│  └──────┬───────┘                       │  ├──────────────────┤  │ │
│         │ V4L2 ioctl                    │  │ Audit Logger     │  │ │
│         ▼                               │  └──────────────────┘  │ │
│  ┌──────────────┐                       └────────────┬───────────┘ │
│  │ Rogue Process│                                    │             │
│  │ (Test Only)  │                                    │ WebSocket   │
│  └──────────────┘                                    ▼             │
│                                         ┌────────────────────────┐ │
│                                         │  GCS Interface         │ │
│                                         │  (Web UI / CLI)        │ │
│                                         └────────────────────────┘ │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  NETWORK NAMESPACE (chambers_net)                             │   │
│  │  - veth pair simulating cellular/Wi-Fi                       │   │
│  │  - iptables/nftables rules from manifest                     │   │
│  │  - Traffic capture for audit                                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow Summary

1. **Telemetry path:** PX4 SITL → MAVLink UDP → Chambers MAVLink Proxy (encrypt) → Session-encrypted storage + permitted GCS forwarding.
2. **Camera path:** Gazebo camera sensor → GStreamer bridge → v4l2loopback `/dev/videoN` → Chambers V4L2 interceptor (encrypt + event label) → Session-encrypted storage.
3. **Network path:** Any outbound connection attempt → Chambers firewall (check manifest) → Allow declared / Block + log undeclared.
4. **Audit path:** Every data flow decision → Signed event label → Append to audit log → Signed with session private key at mission end.
5. **Burn path:** Mission end trigger → Extract preservation-declared data → Re-encrypt under stakeholder keys → Six-layer burn of everything else → Zeroise session private key.

### 3.3 Language & Runtime Decisions

| Component | Language | Rationale |
|---|---|---|
| Core Chambers module | Rust | Matches reference implementation (`github.com/therealgulkorinaga/chamber`). Memory safety, no GC pauses, `zeroize` crate for key material. |
| Manifest parser | Rust | Typed grammar enforcement requires a proper parser. Use `nom` or `pest`. |
| MAVLink proxy | Rust | `mavlink` crate provides PX4 dialect parsing. Zero-copy message handling. |
| V4L2 interceptor | Rust | `v4l` crate for Video4Linux2 bindings. Direct ioctl monitoring. |
| Firewall | Rust + nftables | `nftnl` crate or shell out to `nft` for rule management. |
| GCS interface | Python + FastAPI | Rapid prototyping. Consumes Chambers module via WebSocket/gRPC. Not performance-critical. |
| Gazebo-to-V4L2 bridge | GStreamer pipeline (bash) | `gst-launch` with `v4l2sink`. Standard, zero custom code. |
| Integration tests | Rust (`#[test]`) + Python (pytest) | Rust for unit/module tests, Python for end-to-end orchestration. |
| Simulation orchestration | Docker Compose + shell scripts | Reproducible environment setup. |

---

## 4. Simulation Infrastructure

### 4.1 PX4 SITL Configuration

#### 4.1.1 PX4 Version & Vehicle Model

- **PX4 version:** v1.15.x (latest stable)
- **Vehicle model:** `iris` (standard quadcopter with camera mount) or `typhoon_h480` (hexacopter with camera gimbal — better for inspection simulation)
- **Airframe:** Standard multirotor with GPS, IMU, barometer, magnetometer
- **Companion computer link:** MAVLink over UDP, port 14540 (offboard API), port 14550 (GCS)

#### 4.1.2 PX4 Parameters to Configure

```
# Enable companion computer MAVLink stream
MAV_1_CONFIG = TELEM2
MAV_1_MODE = Onboard
MAV_1_RATE = 921600

# Enable geofencing (required for sealed events)
GF_ACTION = 2          # Warning + Return to Launch
GF_ALTMODE = 0         # WGS84 altitude
GF_COUNT = -1          # Use uploaded geofence
GF_MAX_HOR_DIST = 500  # 500m horizontal limit
GF_MAX_VER_DIST = 100  # 100m vertical limit
GF_SOURCE = 0          # Use onboard geofence

# Enable failsafe triggers (required for sealed events)
COM_DL_LOSS_T = 10     # Data link loss timeout (seconds)
COM_RC_LOSS_T = 5      # RC loss timeout
NAV_DLL_ACT = 2        # Data link loss action: Return to Launch
COM_LOW_BAT_ACT = 3    # Low battery: Return to Launch then Land

# Enable obstacle avoidance interface (required for near-miss sealed events)
COM_OBS_AVOID = 1
```

#### 4.1.3 SITL Launch Command

```bash
# From PX4-Autopilot directory
HEADLESS=0 make px4_sitl gz_x500_cam
# or for typhoon with gimbal camera:
HEADLESS=0 make px4_sitl gazebo-classic_typhoon_h480
```

### 4.2 Gazebo Configuration

#### 4.2.1 Gazebo Version

- **Gazebo Harmonic** (latest LTS) for PX4 + Gazebo integration
- Fallback: Gazebo Classic 11 if Harmonic integration is unstable

#### 4.2.2 World File Requirements

The Gazebo world must include:

1. **Ground plane with texture** — provides visual content for camera anomaly testing
2. **Buildings/structures** — inspection targets; generates realistic camera frame entropy
3. **Geofence boundary markers** (visual only) — helps visualize geofence zones during testing
4. **Wind plugin** — `libgazebo_wind_plugin.so` for realistic flight perturbation
5. **GPS noise plugin** — realistic GPS drift for position-dependent sealed events

Custom world file: `worlds/chambers_test_world.sdf`

#### 4.2.3 Sensor Configuration

**Camera sensor (primary payload):**
```xml
<sensor name="camera" type="camera">
  <update_rate>30</update_rate>
  <camera>
    <horizontal_fov>1.047</horizontal_fov>
    <image>
      <width>1920</width>
      <height>1080</height>
      <format>R8G8B8</format>
    </image>
    <clip>
      <near>0.1</near>
      <far>100</far>
    </clip>
  </camera>
  <plugin name="camera_plugin" filename="libgazebo_ros_camera.so">
    <ros>
      <namespace>/chambers</namespace>
      <remapping>image_raw:=camera/image_raw</remapping>
    </ros>
    <camera_name>payload_camera</camera_name>
    <frame_name>camera_link</frame_name>
  </plugin>
</sensor>
```

**LiDAR sensor (if applicable):**
```xml
<sensor name="lidar" type="ray">
  <update_rate>10</update_rate>
  <ray>
    <scan>
      <horizontal>
        <samples>360</samples>
        <resolution>1</resolution>
        <min_angle>-3.14159</min_angle>
        <max_angle>3.14159</max_angle>
      </horizontal>
    </scan>
    <range>
      <min>0.2</min>
      <max>30.0</max>
      <resolution>0.01</resolution>
    </range>
  </ray>
</sensor>
```

### 4.3 v4l2loopback Setup

#### 4.3.1 Kernel Module Installation

```bash
# Linux host
sudo apt install v4l2loopback-dkms v4l2loopback-utils
sudo modprobe v4l2loopback devices=2 video_nr=10,11 \
  card_label="ChambersCam0,ChambersCam1" exclusive_caps=1

# Verify
v4l2-ctl --list-devices
# Expected output:
# ChambersCam0 (platform:v4l2loopback-000):
#         /dev/video10
# ChambersCam1 (platform:v4l2loopback-001):
#         /dev/video11
```

#### 4.3.2 macOS Note

`v4l2loopback` is Linux-only. On macOS (the current dev machine), the simulation infrastructure must run inside a Linux VM or Docker container with `--device` passthrough. The Docker approach is specified in Section 4.5.

#### 4.3.3 GStreamer Bridge: Gazebo → v4l2loopback

```bash
# Subscribe to Gazebo camera topic and write to v4l2loopback device
gst-launch-1.0 \
  rosimagesrc topic=/chambers/camera/image_raw ! \
  videoconvert ! \
  video/x-raw,format=YUY2,width=1920,height=1080,framerate=30/1 ! \
  v4l2sink device=/dev/video10
```

Alternative using `ros2` and `image_transport`:
```bash
# ROS2 node that reads image topic and writes to V4L2
ros2 run chambers_sim v4l2_bridge_node \
  --ros-args -p topic:=/chambers/camera/image_raw \
  -p device:=/dev/video10 \
  -p width:=1920 -p height:=1080 -p fps:=30
```

This bridge is the critical link that makes V4L2 anomaly detection testable in simulation. The Chambers module reads from `/dev/video10` via V4L2 ioctls exactly as it would on a real companion computer. Any other process reading `/dev/video10` is detectable.

### 4.4 Network Namespace Setup

To simulate the drone's network interfaces in isolation:

```bash
# Create namespace
sudo ip netns add chambers_drone

# Create veth pair (simulating cellular modem)
sudo ip link add veth-drone type veth peer name veth-host
sudo ip link set veth-drone netns chambers_drone

# Assign addresses
sudo ip netns exec chambers_drone ip addr add 10.0.0.2/24 dev veth-drone
sudo ip addr add 10.0.0.1/24 dev veth-host

# Bring up
sudo ip netns exec chambers_drone ip link set veth-drone up
sudo ip link set veth-host up

# Enable routing (simulates internet access through host)
sudo ip netns exec chambers_drone ip route add default via 10.0.0.1
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1
```

The Chambers firewall module runs inside `chambers_drone` namespace and controls all egress via nftables rules derived from the manifest.

### 4.5 Docker Compose Orchestration

```yaml
# docker-compose.yml
version: "3.8"

services:
  px4-sitl:
    image: px4io/px4-dev-simulation-focal:latest
    container_name: chambers-px4
    environment:
      - PX4_SIM_MODEL=gz_x500_cam
      - PX4_GZ_WORLD=chambers_test
    volumes:
      - ./worlds:/PX4-Autopilot/Tools/simulation/gz/worlds
      - ./models:/PX4-Autopilot/Tools/simulation/gz/models
    ports:
      - "14540:14540/udp"   # MAVSDK / offboard
      - "14550:14550/udp"   # QGroundControl / GCS
      - "18570:18570/udp"   # Gazebo transport
    networks:
      - chambers_net
    privileged: true

  gazebo:
    image: gazebo:harmonic
    container_name: chambers-gazebo
    environment:
      - DISPLAY=${DISPLAY}
      - GZ_SIM_RESOURCE_PATH=/worlds
    volumes:
      - ./worlds:/worlds
      - /tmp/.X11-unix:/tmp/.X11-unix
    ports:
      - "11345:11345"       # Gazebo transport
    networks:
      - chambers_net
    depends_on:
      - px4-sitl

  chambers-module:
    build:
      context: ./chambers
      dockerfile: Dockerfile
    container_name: chambers-companion
    cap_add:
      - NET_ADMIN             # Required for nftables/firewall
      - SYS_ADMIN             # Required for network namespace
    devices:
      - /dev/video10:/dev/video10   # v4l2loopback passthrough
      - /dev/video11:/dev/video11
    volumes:
      - ./manifests:/etc/chambers/manifests
      - ./audit_logs:/var/chambers/audit
      - chambers_session:/var/chambers/session   # tmpfs in production
    environment:
      - CHAMBERS_MANIFEST=/etc/chambers/manifests/default.toml
      - CHAMBERS_PX4_HOST=chambers-px4
      - CHAMBERS_PX4_PORT=14540
      - CHAMBERS_V4L2_DEVICE=/dev/video10
      - CHAMBERS_GCS_ENDPOINT=ws://chambers-gcs:8080/ws
    networks:
      - chambers_net
    depends_on:
      - px4-sitl
      - gazebo

  v4l2-bridge:
    image: chambers-v4l2-bridge:latest
    build:
      context: ./bridge
      dockerfile: Dockerfile
    container_name: chambers-v4l2-bridge
    devices:
      - /dev/video10:/dev/video10
    networks:
      - chambers_net
    depends_on:
      - gazebo

  gcs:
    build:
      context: ./gcs
      dockerfile: Dockerfile
    container_name: chambers-gcs
    ports:
      - "8080:8080"           # Web UI
      - "8081:8081"           # API
    volumes:
      - ./audit_logs:/var/chambers/audit:ro
      - ./manifests:/etc/chambers/manifests
    networks:
      - chambers_net
    depends_on:
      - chambers-module

  rogue-process:
    build:
      context: ./test/rogue
      dockerfile: Dockerfile
    container_name: chambers-rogue
    devices:
      - /dev/video10:/dev/video10
    networks:
      - chambers_net
    profiles:
      - testing
    depends_on:
      - v4l2-bridge

networks:
  chambers_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  chambers_session:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=2g,mode=1700
```

---

## 5. Module 1: Session Lifecycle Manager

### 5.1 Responsibility

Orchestrates the complete mission lifecycle: session creation, state transitions, and orderly shutdown including burn. This is the top-level state machine that coordinates all other modules.

### 5.2 State Machine

```
                    ┌─────────┐
                    │  IDLE   │
                    └────┬────┘
                         │ arm_mission(manifest)
                         ▼
                    ┌─────────┐
                    │ PRE_FLT │ ← Generate session keypair
                    │         │ ← Load & validate manifest
                    │         │ ← Initialize encrypted storage
                    │         │ ← Transmit session pubkey to GCS
                    │         │ ← Arm all modules
                    └────┬────┘
                         │ takeoff_detected OR manual_start
                         ▼
                    ┌─────────┐
                    │ IN_FLT  │ ← All data pipelines active
                    │         │ ← Encryption active
                    │         │ ← Firewall enforcing
                    │         │ ← Anomaly detection active
                    │         │ ← Sealed event monitoring active
                    └────┬────┘
                         │ land_detected OR manual_stop
                         ▼
                    ┌─────────┐
                    │POST_FLT │ ← Extract preserved data
                    │         │ ← Re-encrypt under stakeholder keys
                    │         │ ← Write to preservation partition
                    │         │ ← Finalise audit log
                    │         │ ← Sign audit log with session key
                    │         │ ← Sync audit log to GCS
                    └────┬────┘
                         │ preservation_complete
                         ▼
                    ┌─────────┐
                    │ BURNING │ ← Execute 6-layer burn
                    │         │ ← Zeroise session private key
                    └────┬────┘
                         │ burn_verified
                         ▼
                    ┌─────────┐
                    │  IDLE   │
                    └─────────┘
```

### 5.3 State Transition Events

| Current State | Event | Next State | Side Effects |
|---|---|---|---|
| IDLE | `arm_mission(manifest_path)` | PRE_FLIGHT | Load manifest, generate keys, init storage |
| PRE_FLIGHT | `takeoff_detected` | IN_FLIGHT | Start all pipelines |
| PRE_FLIGHT | `arm_failed(reason)` | IDLE | Log error, no burn needed (nothing encrypted yet) |
| IN_FLIGHT | `land_detected` | POST_FLIGHT | Stop data pipelines, begin preservation |
| IN_FLIGHT | `emergency_stop` | POST_FLIGHT | Immediate transition, sealed event fires |
| IN_FLIGHT | `preservation_extension(cmd)` | IN_FLIGHT | Update manifest in-flight (Section 7.2 of paper) |
| POST_FLIGHT | `preservation_complete` | BURNING | All preserved data extracted and re-encrypted |
| BURNING | `burn_verified` | IDLE | All 6 burn layers passed verification |
| BURNING | `burn_failed(layer, reason)` | ERROR | Requires manual intervention |
| ANY | `panic` | EMERGENCY_BURN | Immediate key destruction, skip preservation |

### 5.4 Interfaces

```rust
pub trait SessionLifecycle {
    /// Arm a new mission with the given manifest. Returns session public key.
    fn arm_mission(&mut self, manifest: &Path) -> Result<SessionPublicKey, ArmError>;

    /// Signal that the vehicle has taken off.
    fn notify_takeoff(&mut self) -> Result<(), StateError>;

    /// Signal that the vehicle has landed.
    fn notify_landing(&mut self) -> Result<(), StateError>;

    /// Get current session state.
    fn state(&self) -> SessionState;

    /// Get session metadata (start time, manifest hash, public key).
    fn session_info(&self) -> Option<&SessionInfo>;

    /// Request emergency burn (immediate key destruction).
    fn emergency_burn(&mut self) -> Result<BurnReport, BurnError>;
}
```

### 5.5 Detection of Takeoff/Landing

In simulation, detect via MAVLink:
- **Takeoff:** `HEARTBEAT.base_mode` transitions to include `MAV_MODE_FLAG_SAFETY_ARMED` AND `EXTENDED_SYS_STATE.landed_state` transitions from `MAV_LANDED_STATE_ON_GROUND` to `MAV_LANDED_STATE_IN_AIR`.
- **Landing:** `EXTENDED_SYS_STATE.landed_state` transitions to `MAV_LANDED_STATE_ON_GROUND` AND motors disarmed.

---

## 6. Module 2: Cryptographic Engine

### 6.1 Responsibility

All cryptographic operations: key generation, encryption, decryption (for preservation extraction), key zeroisation. No other module directly calls cryptographic primitives.

### 6.2 Key Types

| Key | Algorithm | Purpose | Lifetime | Storage |
|---|---|---|---|---|
| Session signing keypair | Ed25519 | Sign audit log entries and final log | Mission duration | RAM only, zeroised at burn |
| Session encryption keypair | X25519 | Derive shared secrets for session encryption | Mission duration | RAM only, zeroised at burn |
| Session symmetric key | AES-256-GCM | Bulk data encryption | Mission duration | RAM only, zeroised at burn |
| Stakeholder public keys | X25519 | Re-encrypt preserved data for stakeholders | Loaded from manifest | Read-only, not secret |
| Preservation keys | AES-256-GCM (per stakeholder) | Encrypt preserved data partitions | Derived via ECDH(session_priv, stakeholder_pub) | Ephemeral, used once |

### 6.3 Key Generation Sequence

```
1. Generate Ed25519 signing keypair
   session_sign_priv, session_sign_pub = Ed25519::generate()

2. Generate X25519 encryption keypair
   session_enc_priv, session_enc_pub = X25519::generate()

3. Derive session symmetric key (for bulk encryption)
   session_sym_key = HKDF-SHA256(
     ikm = random(32),
     salt = session_sign_pub || session_enc_pub,
     info = b"chambers-session-v1"
   )

4. Store session_sign_pub and session_enc_pub in session metadata
5. Transmit session_sign_pub to GCS (for post-flight audit verification)
6. Transmit session_enc_pub to GCS (for session metadata)
```

### 6.4 Encryption Operations

**Bulk data encryption (camera frames, telemetry):**
```
ciphertext = AES-256-GCM(
  key = session_sym_key,
  nonce = monotonic_counter || random(4),  // 12 bytes total
  aad = event_label_bytes,                 // Authenticated additional data
  plaintext = sensor_data
)
```

The nonce uses a 8-byte monotonic counter (never repeats within a session) concatenated with 4 random bytes. The AAD binds each ciphertext to its event label, preventing label substitution attacks.

**Preservation re-encryption (post-flight):**
```
For each stakeholder S in manifest.stakeholders:
  shared_secret = X25519(session_enc_priv, S.public_key)
  preservation_key = HKDF-SHA256(
    ikm = shared_secret,
    salt = session_sign_pub,
    info = b"chambers-preserve-v1" || S.stakeholder_id
  )
  preserved_ciphertext = AES-256-GCM(
    key = preservation_key,
    nonce = fresh_random(12),
    aad = manifest_hash || S.stakeholder_id,
    plaintext = declared_data_for_S
  )
```

### 6.5 Zeroisation

All key material stored in types that implement the `Zeroize` and `ZeroizeOnDrop` traits from the `zeroize` crate. Explicit zeroisation occurs during burn Layer 4 (memory zeroing). The type system prevents accidental copies:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    sign_private: Ed25519PrivateKey,
    enc_private: X25519PrivateKey,
    sym_key: [u8; 32],
}
```

### 6.6 Dependencies

- `ring` or `rustls` for AES-256-GCM, HKDF
- `ed25519-dalek` for Ed25519 signing
- `x25519-dalek` for X25519 key agreement
- `zeroize` for secure memory clearing
- `rand` with `OsRng` for key generation

---

## 7. Module 3: Preservation Manifest

### 7.1 Responsibility

Parse, validate, and enforce the typed preservation manifest. The manifest is the policy — this module is the policy engine.

### 7.2 Manifest Grammar (TOML)

The manifest is a TOML file with the following structure:

```toml
[meta]
version = "1.0"
mission_type = "infrastructure_inspection"
operator_id = "OP-2026-00142"
created = "2026-04-08T10:00:00Z"
# SHA-256 of the complete manifest (excluding this field), set at signing
manifest_hash = ""

# Regulatory requirements — must be present for the module to arm
[regulatory]
remote_id = true                    # FAA Part 89 compliance
jurisdiction = "US"                 # Determines which sealed event rules apply
operation_category = "part_107"     # FAA: part_107, part_108_bvlos
                                    # EASA: open, specific, certified

# Default rule — MUST be the last evaluated rule
[default]
action = "BURN"

# Stakeholder declarations
[[stakeholder]]
id = "operator"
name = "AcmeDrone Services LLC"
public_key = "base64-encoded-X25519-public-key"
role = "operator"

[[stakeholder]]
id = "client"
name = "PowerGrid Corp"
public_key = "base64-encoded-X25519-public-key"
role = "client"

[[stakeholder]]
id = "faa"
name = "Federal Aviation Administration"
public_key = "base64-encoded-X25519-public-key"
role = "regulator"

[[stakeholder]]
id = "manufacturer"
name = "DroneManufacturer Inc"
public_key = "base64-encoded-X25519-public-key"
role = "manufacturer"

# Preservation rules — evaluated in order, first match wins (within priority tier)
[[preserve]]
id = "rule-001"
data_category = "thermal_imagery"
sensor = "camera_thermal"
for_stakeholder = "client"
format = "radiometric_tiff"
retention = "90d"
justification = "Contracted inspection deliverable"

[[preserve]]
id = "rule-002"
data_category = "eo_imagery"
sensor = "camera_eo"
for_stakeholder = "client"
format = "jpeg"
retention = "90d"
justification = "Visual inspection deliverable"

[[preserve]]
id = "rule-003"
data_category = "flight_telemetry"
sensor = "flight_controller"
for_stakeholder = "operator"
fields = ["position", "altitude", "velocity", "battery", "motor_rpm"]
retention = "365d"
justification = "Operational records and maintenance"

[[preserve]]
id = "rule-004"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
format = "cleartext"
transmission = "real_time"
retention = "0"   # Not stored, broadcast only
justification = "14 CFR Part 89 compliance"

# Deny rules — block specific data flows regardless of other rules
[[deny]]
id = "deny-001"
data_category = "flight_telemetry"
for_stakeholder = "manufacturer"
justification = "Manufacturer does not need telemetry for this mission"

[[deny]]
id = "deny-002"
data_category = "eo_imagery"
for_stakeholder = "manufacturer"
justification = "No imagery to manufacturer cloud"

# System allowlist — known OS-level processes that may access sensors
# outside mission-specific rules (Section 5.4 of paper)
[system_allowlist]
platform = "jetson_orin"    # Platform-specific defaults
processes = [
    "nvargus-daemon",       # NVIDIA camera service
    "thumbnailing-service", # OS thumbnail generator
    "v4l2-compliance",      # V4L2 test utility
]
```

### 7.3 Manifest Validation Rules

The manifest engine MUST enforce:

1. **`[regulatory].remote_id` must be `true`** for any operation subject to Part 89. If `false` and `jurisdiction = "US"`, the module refuses to arm.
2. **At least one `[[preserve]]` rule with `data_category = "remote_id"` and `transmission = "real_time"`** must exist. This ensures Remote ID broadcasts happen.
3. **`[default].action` must be `"BURN"`**. No other value is accepted.
4. **Every `for_stakeholder` in preserve/deny rules must reference a declared `[[stakeholder]]`.**
5. **Every stakeholder must have a valid X25519 public key** (32 bytes, base64-encoded).
6. **`retention` must be a valid duration** (`Nd` for days) or `"0"` for no-store.
7. **No preserve rule may declare `for_stakeholder = "*"` (all stakeholders) unless signed by a regulator** (manifest co-signing, Section 6.3 of paper).
8. **The manifest must be self-consistent:** a deny rule and a preserve rule for the same data_category + stakeholder is a conflict. The deny rule wins (more restrictive), but a warning is logged.

### 7.4 Rule Evaluation Order

Per Section 6.2 of the paper:

1. **Sealed event rules** (hardcoded, not in manifest) — absolute precedence
2. **Regulatory stakeholder rules** (role = "regulator") — override operator rules
3. **Operator/client rules** — evaluated in manifest order
4. **Deny rules** — within the same priority tier, DENY overrides PRESERVE
5. **Default rule** — BURN everything not explicitly preserved

### 7.5 Manifest Hashing & Signing

```
manifest_hash = SHA-256(canonical_toml(manifest, excluding manifest_hash field))
```

The hash is included in:
- Every audit log entry (binds the log to the manifest)
- Every ciphertext AAD (binds data to the policy that governed it)
- The session metadata transmitted to GCS

### 7.6 Interface

```rust
pub struct Manifest {
    pub meta: ManifestMeta,
    pub regulatory: RegulatoryConfig,
    pub stakeholders: Vec<Stakeholder>,
    pub preserve_rules: Vec<PreserveRule>,
    pub deny_rules: Vec<DenyRule>,
    pub system_allowlist: SystemAllowlist,
    pub manifest_hash: [u8; 32],
}

pub enum ManifestDecision {
    Preserve { rule_id: String, stakeholder_id: String, retention: Duration },
    Deny { rule_id: String, reason: String },
    Burn,  // Default
    SealedEvent { event_type: SealedEventType, preservation_scope: PreservationScope },
}

impl Manifest {
    /// Parse and validate a manifest file. Returns errors for all validation failures.
    pub fn load(path: &Path) -> Result<Self, Vec<ManifestError>>;

    /// Evaluate a data flow against the manifest.
    /// Returns the decision (preserve, deny, burn) and the rule that produced it.
    pub fn evaluate(&self, flow: &DataFlow) -> ManifestDecision;

    /// Check if a process is in the system allowlist.
    pub fn is_allowlisted(&self, process_name: &str) -> bool;

    /// Get all stakeholder public keys for preservation.
    pub fn stakeholder_keys(&self) -> Vec<(&str, &X25519PublicKey)>;
}
```

---

## 8. Module 4: Burn Engine

### 8.1 Responsibility

Execute the six-layer burn sequence described in Section 2 of the paper. Verify each layer completed successfully. This is the core guarantee of Chambers: undeclared data ceases to exist.

### 8.2 Six-Layer Burn Sequence

```
Layer 1: Capability Revocation
  ├── Revoke all file descriptors to session-encrypted storage
  ├── Revoke all network socket permissions
  ├── Revoke V4L2 device access
  └── Verify: no open handles to session data remain

Layer 2: Cryptographic Erasure
  ├── Zeroise session symmetric key (AES-256-GCM)
  ├── Zeroise session encryption private key (X25519)
  ├── Zeroise all derived preservation keys (already used)
  └── Verify: session_sym_key, session_enc_priv are all-zero

Layer 3: Storage Cleanup
  ├── Overwrite session-encrypted storage files with random bytes
  ├── Issue TRIM/discard commands to underlying storage (if SSD/NVMe)
  ├── fsync to ensure writes hit storage
  ├── Unlink all session storage files
  └── Verify: no session files exist in filesystem

Layer 4: Memory Zeroing
  ├── Zeroise all buffers that held plaintext sensor data
  ├── Zeroise any decryption buffers used during preservation extraction
  ├── Zeroise the guard buffer (Section 2 of paper — locked memory region)
  ├── Call madvise(MADV_DONTNEED) on mapped regions
  └── Verify: guard buffer contents are all-zero

Layer 5: Audit Burn
  ├── The audit log is NOT burned — it is preserved
  ├── But: audit entries for burned data have their plaintext references removed
  ├── Audit log records THAT data was burned, not WHAT the data contained
  └── Verify: audit log is intact, signed, and contains burn records

Layer 6: Semantic Verification
  ├── Re-scan session storage directory — must be empty
  ├── Re-scan /proc/self/maps — no session-related mappings
  ├── Re-scan /proc/self/fd — no session file descriptors
  ├── Verify session private key is zero
  ├── Verify session symmetric key is zero
  ├── Generate BurnReport with per-layer pass/fail
  └── Sign BurnReport with session signing key (LAST use before zeroise)
  └── Zeroise session signing private key
```

### 8.3 Burn Report

```rust
pub struct BurnReport {
    pub session_id: SessionId,
    pub burn_start: DateTime<Utc>,
    pub burn_end: DateTime<Utc>,
    pub layers: [LayerResult; 6],
    pub signature: Ed25519Signature,  // Signed by session signing key (last use)
}

pub struct LayerResult {
    pub layer: u8,           // 1-6
    pub name: &'static str,
    pub status: LayerStatus, // Pass, Fail, Skipped
    pub details: String,
    pub duration_us: u64,
}
```

### 8.4 Interface

```rust
pub trait BurnEngine {
    /// Execute the full 6-layer burn sequence.
    /// The session signing key is used for the BurnReport signature
    /// and then zeroised as the final act.
    fn execute_burn(
        &mut self,
        session_keys: &mut SessionKeys,
        session_storage: &Path,
        preservation_complete: bool,
    ) -> Result<BurnReport, BurnError>;

    /// Emergency burn — skip preservation, destroy everything immediately.
    fn emergency_burn(
        &mut self,
        session_keys: &mut SessionKeys,
        session_storage: &Path,
    ) -> Result<BurnReport, BurnError>;
}
```

---

## 9. Module 5: MAVLink Encryption Proxy

### 9.1 Responsibility

Sit between PX4 SITL and all downstream consumers. Receive MAVLink messages in cleartext from the flight controller, encrypt them under the session key, and store them. Forward permitted messages to the GCS per manifest rules.

### 9.2 Architecture

```
PX4 SITL (UDP :14540)
      │
      │ cleartext MAVLink
      ▼
┌─────────────────────────┐
│ MAVLink Encryption Proxy │
│                         │
│ 1. Parse MAVLink frame  │
│ 2. Generate event label │
│ 3. Encrypt frame        │
│ 4. Write to session     │
│    encrypted storage    │
│ 5. Evaluate manifest:   │
│    - Forward to GCS?    │
│    - Forward to UTM?    │
│ 6. Forward permitted    │
│    messages (cleartext  │
│    or re-encrypted)     │
└──────────┬──────────────┘
           │
           ├──► Session Encrypted Storage
           │
           ├──► GCS (permitted telemetry, via WebSocket)
           │
           └──► Audit Log (event label for every message)
```

### 9.3 MAVLink Message Handling

| Message Category | Examples | Default Action | Manifest Override |
|---|---|---|---|
| Position/Navigation | GLOBAL_POSITION_INT, LOCAL_POSITION_NED, GPS_RAW_INT | Encrypt + store | Preserve for declared stakeholders |
| Attitude | ATTITUDE, ATTITUDE_QUATERNION | Encrypt + store | Preserve for operator |
| System Status | HEARTBEAT, SYS_STATUS, BATTERY_STATUS | Encrypt + store | Preserve for operator |
| Mission | MISSION_CURRENT, MISSION_ITEM_REACHED | Encrypt + store | Preserve for operator + client |
| Motor/Actuator | SERVO_OUTPUT_RAW, ACTUATOR_OUTPUT_STATUS | Encrypt + store | Preserve for operator (maintenance) |
| RC Input | RC_CHANNELS | Encrypt + store | Usually burn (not needed post-mission) |
| Parameter | PARAM_VALUE | Encrypt + store | Usually burn |
| Command/Ack | COMMAND_LONG, COMMAND_ACK | Encrypt + store | Preserve for operator |

### 9.4 Sealed Event Triggers from MAVLink

The proxy monitors specific MAVLink messages to trigger sealed events:

| MAVLink Message | Condition | Sealed Event |
|---|---|---|
| GLOBAL_POSITION_INT | Position inside geofence exclusion zone | Geofence Violation |
| GLOBAL_POSITION_INT | Position inside restricted airspace (checked against loaded database) | Airspace Incursion |
| STATUSTEXT | Severity=EMERGENCY or CRITICAL | Emergency Landing candidate |
| HEARTBEAT | `base_mode` transitions from ARMED to DISARMED unexpectedly | Emergency Landing |
| BATTERY_STATUS | Remaining < failsafe threshold | Emergency Landing |
| OBSTACLE_DISTANCE | Min distance < safety margin | Near-Miss |
| HIGH_LATENCY2 | Failsafe flags set | Emergency Landing |

### 9.5 Performance Requirements

- **Latency budget:** <1ms per message for encryption + event label generation
- **Throughput:** PX4 SITL generates ~50-200 MAVLink messages/second depending on configuration. The proxy must handle 500 msg/s with headroom.
- **Zero message loss:** Every MAVLink message from PX4 SITL must be captured, encrypted, and logged. Dropped messages are audit failures.

### 9.6 Interface

```rust
pub struct MavlinkProxy {
    px4_connection: MavlinkConnection,      // UDP to PX4 SITL
    gcs_connections: Vec<GcsConnection>,     // WebSocket to GCS
    crypto: Arc<CryptoEngine>,
    manifest: Arc<Manifest>,
    audit: Arc<AuditLogger>,
    sealed_events: Arc<SealedEventEngine>,
    storage: SessionStorage,
}

impl MavlinkProxy {
    /// Start the proxy. Blocks until session ends.
    pub async fn run(&mut self) -> Result<(), ProxyError>;

    /// Get message statistics.
    pub fn stats(&self) -> ProxyStats;
}
```

---

## 10. Module 6: Camera Pipeline Encryption

### 10.1 Responsibility

Read camera frames from the V4L2 device (fed by Gazebo via v4l2loopback), encrypt each frame under the session key, write to session-encrypted storage, and generate event labels for the V4L2 anomaly detection module.

### 10.2 Pipeline

```
/dev/video10 (v4l2loopback, fed by Gazebo)
      │
      │ V4L2 ioctl (VIDIOC_DQBUF)
      ▼
┌──────────────────────────┐
│ Camera Pipeline Module    │
│                          │
│ 1. Dequeue frame buffer  │
│ 2. Record event label:   │
│    - process: self       │
│    - timestamp: now      │
│    - buffer: index, size │
│    - manifest_rule: id   │
│ 3. Encrypt frame:        │
│    AES-256-GCM(          │
│      key=session_sym,    │
│      aad=event_label,    │
│      plaintext=frame)    │
│ 4. Write ciphertext to   │
│    session storage        │
│ 5. Send event label to   │
│    audit logger           │
│ 6. Requeue buffer        │
└──────────────────────────┘
```

### 10.3 Frame Metadata

Each frame generates:

```rust
pub struct CameraEventLabel {
    pub timestamp: DateTime<Utc>,
    pub frame_index: u64,           // Monotonic counter
    pub process_id: u32,            // PID of reader (self)
    pub process_name: String,       // "chambers_camera"
    pub v4l2_device: String,        // "/dev/video10"
    pub buffer_index: u32,          // V4L2 buffer index
    pub bytes_read: usize,          // Frame size in bytes
    pub resolution: (u32, u32),     // Width x Height
    pub format: V4l2Format,         // YUY2, MJPEG, etc.
    pub manifest_rule: String,      // Rule ID that governs this data
    pub destination: DataDestination, // SessionStorage | Preserved(stakeholder)
}
```

### 10.4 V4L2 Capture Configuration

```rust
// V4L2 device configuration
let mut cap = v4l::capture::Device::new("/dev/video10")?;
let format = cap.set_format(&v4l::Format {
    width: 1920,
    height: 1080,
    fourcc: v4l::FourCC::new(b"YUYV"),
    ..Default::default()
})?;
let params = cap.set_params(&v4l::CaptureParameters {
    timeperframe: v4l::Fraction { numerator: 1, denominator: 30 },
    ..Default::default()
})?;
// Request buffers (MMAP mode)
let mut stream = v4l::io::mmap::Stream::with_buffers(&mut cap, 4)?;
```

### 10.5 Performance Budget

At 1920x1080 YUY2 @ 30fps:
- Frame size: 1920 * 1080 * 2 = ~4.1 MB
- Data rate: ~124 MB/s
- AES-256-GCM encryption at ~1 GB/s (software, x86) → ~4ms per frame
- Budget: 33ms per frame (30fps), encryption uses ~12% of budget
- Comfortable margin for simulation. Real hardware benchmarks are out of scope.

---

## 11. Module 7: V4L2 Anomaly Detection

### 11.1 Responsibility

Monitor all V4L2 device access at the OS level. Detect when any process other than the declared Chambers camera pipeline reads from the camera device. Generate anomaly events for undeclared access. This implements Section 5.4 of the paper.

### 11.2 Detection Mechanism

**Primary approach: inotify + /proc monitoring**

Since we cannot intercept V4L2 ioctls directly from userspace without a kernel module, we use a combination of:

1. **`/proc/[pid]/fd` scanning:** Periodically scan all processes for open file descriptors pointing to the V4L2 device.
2. **`fanotify` (Linux 5.1+):** Use `fanotify` with `FAN_OPEN` and `FAN_ACCESS` on the V4L2 device file to get notified when any process opens or reads the device.
3. **eBPF (preferred, if available):** Attach a BPF program to the `v4l2_ioctl` tracepoint to intercept `VIDIOC_DQBUF` calls from any process. This is the most precise approach.

**Detection hierarchy (most precise to least):**

```
Priority 1: eBPF tracepoint on v4l2_ioctl (VIDIOC_DQBUF, VIDIOC_QBUF)
  └── Reports: PID, process name, ioctl type, buffer index, timestamp
  └── Requires: CAP_BPF or root, kernel 5.8+

Priority 2: fanotify on /dev/video10
  └── Reports: PID, process name, access type (open/read)
  └── Requires: CAP_SYS_ADMIN
  └── Limitation: does not distinguish ioctl types

Priority 3: /proc scanning (polling fallback)
  └── Reports: PID, process name, open FD to device
  └── Requires: /proc access
  └── Limitation: polling interval creates detection gaps
```

### 11.3 Anomaly Classification

For each detected access:

```rust
pub enum AccessClassification {
    /// Access by the declared Chambers camera pipeline. Expected.
    DeclaredMission { rule_id: String },

    /// Access by a process in the system_allowlist. Logged, not flagged.
    SystemAllowlisted { process: String, allowlist_entry: String },

    /// Access by an undeclared process. THIS IS AN ANOMALY.
    Undeclared {
        process_id: u32,
        process_name: String,
        process_exe: PathBuf,        // /proc/[pid]/exe
        process_cmdline: String,     // /proc/[pid]/cmdline
        parent_pid: u32,
        access_type: AccessType,     // Open, Read, DQBUF, QBUF
        timestamp: DateTime<Utc>,
    },
}
```

### 11.4 Anomaly Patterns (from paper Table, Section 5.4)

| Pattern ID | Description | Detection Method | Severity |
|---|---|---|---|
| ANM-001 | Camera buffer read by undeclared process | eBPF/fanotify detects PID not in manifest or allowlist | HIGH |
| ANM-002 | Camera reads continue after motor disarm | Timestamp of V4L2 read > timestamp of DISARMED state | HIGH |
| ANM-003 | Reads at unexpected resolution/framerate | eBPF captures buffer metadata; compare against manifest-declared resolution | MEDIUM |
| ANM-004 | Reads to non-session-encrypted memory region | eBPF captures destination buffer address; check against session storage mmap range | HIGH |
| ANM-005 | Burst reads correlated with cellular modem activity | Correlate V4L2 read timestamps with network TX timestamps (from firewall module) | CRITICAL |
| ANM-006 | Camera accessed during firmware update window | Detect OTA update process + concurrent V4L2 access | HIGH |

### 11.5 Anomaly Response

Per Section 5.4 of the paper: anomaly detection is a **logging function, not a blocking function**. The module:

1. Records the anomaly in the signed audit log with full context
2. Sends an alert event to the GCS
3. Does NOT terminate the undeclared process
4. Does NOT block the V4L2 read

Rationale: blocking undeclared access risks breaking legitimate OS utilities (thumbnailing, health checks) that the operator may not have enumerated.

### 11.6 Interface

```rust
pub trait AnomalyDetector {
    /// Start monitoring the V4L2 device for undeclared access.
    fn start(&mut self, device: &str, manifest: &Manifest) -> Result<(), DetectorError>;

    /// Stop monitoring.
    fn stop(&mut self) -> Result<(), DetectorError>;

    /// Get all detected anomalies since last call (drains the queue).
    fn drain_anomalies(&mut self) -> Vec<AnomalyEvent>;

    /// Get current monitoring statistics.
    fn stats(&self) -> DetectorStats;
}

pub struct AnomalyEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub pattern: AnomalyPattern,     // ANM-001 through ANM-006
    pub classification: AccessClassification,
    pub severity: Severity,
    pub context: AnomalyContext,     // Additional metadata
}
```

### 11.7 Testing with Rogue Process

A dedicated test container (`rogue-process` in Docker Compose) will:

1. Open `/dev/video10` and read frames at various intervals
2. Read at different resolutions than declared
3. Read after a simulated motor disarm
4. Read in bursts correlated with network transmissions
5. Attempt to exfiltrate frames via an undeclared network connection

Each scenario validates that the anomaly detector correctly identifies and classifies the access.

---

## 12. Module 8: Manifest-Aware Firewall

### 12.1 Responsibility

Enforce the manifest's network policy: block all outbound connections not declared in the manifest. Log every connection attempt (allowed and blocked) to the audit log.

### 12.2 Architecture

The firewall runs inside a network namespace. All outbound traffic from the Chambers module must pass through nftables rules derived from the manifest.

### 12.3 Rule Generation

From the manifest, extract all declared outbound data flows:

```toml
# Example: manifest declares these outbound flows
[[network_flow]]
id = "flow-001"
destination = "gcs"
protocol = "websocket"
host = "172.20.0.100"
port = 8080
data_category = "telemetry_subset"
justification = "Real-time flight monitoring"

[[network_flow]]
id = "flow-002"
destination = "remote_id"
protocol = "broadcast"
interface = "bluetooth"
data_category = "remote_id"
justification = "14 CFR Part 89"

[[network_flow]]
id = "flow-003"
destination = "utm_provider"
protocol = "https"
host = "api.utm-provider.example.com"
port = 443
data_category = "position_telemetry"
justification = "U-space flight authorization"
```

Generated nftables rules:

```
table inet chambers {
    chain output {
        type filter hook output priority 0; policy drop;

        # Allow loopback (internal communication)
        oif "lo" accept

        # Allow DNS resolution (required for UTM hostname)
        udp dport 53 accept
        tcp dport 53 accept

        # flow-001: GCS WebSocket
        ip daddr 172.20.0.100 tcp dport 8080 accept

        # flow-003: UTM provider
        ip daddr {resolved_utm_ips} tcp dport 443 accept

        # Log and drop everything else
        log prefix "CHAMBERS_BLOCKED: " group 1
        counter drop
    }

    chain input {
        type filter hook input priority 0; policy accept;
        # Accept responses to allowed connections
        ct state established,related accept
    }
}
```

### 12.4 Firewall Events

Every connection attempt generates:

```rust
pub struct FirewallEvent {
    pub timestamp: DateTime<Utc>,
    pub direction: Direction,           // Outbound (inbound always accepted for responses)
    pub protocol: Protocol,             // TCP, UDP, ICMP
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub action: FirewallAction,         // Allow(flow_id) | Block
    pub manifest_rule: Option<String>,  // The network_flow rule that permitted it (or None if blocked)
    pub process_id: u32,
    pub process_name: String,
    pub bytes: u64,                     // 0 for blocked connections
}
```

### 12.5 Correlation with Anomaly Detection

The firewall module exposes a stream of `FirewallEvent`s that the V4L2 anomaly detector can correlate with camera access timestamps (ANM-005: burst reads correlated with cellular activity).

```rust
pub trait FirewallEventStream {
    /// Subscribe to firewall events for correlation.
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<FirewallEvent>;
}
```

### 12.6 Interface

```rust
pub trait ManifestFirewall {
    /// Load manifest and generate nftables rules.
    fn configure(&mut self, manifest: &Manifest) -> Result<(), FirewallError>;

    /// Activate the firewall (apply nftables rules).
    fn activate(&mut self) -> Result<(), FirewallError>;

    /// Deactivate the firewall (remove nftables rules).
    fn deactivate(&mut self) -> Result<(), FirewallError>;

    /// Get blocked connection log.
    fn blocked_connections(&self) -> Vec<FirewallEvent>;

    /// Get event stream for correlation.
    fn event_stream(&self) -> tokio::sync::broadcast::Receiver<FirewallEvent>;
}
```

---

## 13. Module 9: Sealed Event Engine

### 13.1 Responsibility

Monitor flight state for safety-critical events. When a sealed event fires, override the manifest's preservation rules to preserve safety-relevant data for the mandated stakeholders and duration. Sealed events are hardcoded invariants — the operator cannot suppress them.

### 13.2 Sealed Event Types (from paper Section 6.1)

| Event Type | Trigger Condition | Preservation Scope | Stakeholders | Retention |
|---|---|---|---|---|
| `AIRSPACE_INCURSION` | Position enters restricted/controlled airspace (checked against geofence database) | All telemetry T-30s to T+30s | All stakeholders | 365 days |
| `NEAR_MISS` | Obstacle avoidance fires within safety margin | All sensor data from event window | Operator + Regulator | 365 days |
| `EMERGENCY_LANDING` | Failsafe triggered (low battery, GPS loss, motor failure, link loss) | Full flight log preceding 60s through landing | All regulatory stakeholders | 365 days |
| `GEOFENCE_VIOLATION` | Position crosses geofence boundary | Position + telemetry | Regulator + UTM | 90 days |
| `PAYLOAD_ANOMALY` | Payload exhibits unexpected software behaviour (undeclared filesystem access, unexpected process spawning, undeclared network connections, power draw/RF emission anomalies) | Full context | Operator | 90 days |

### 13.3 Trigger Detection Sources

```rust
pub enum TriggerSource {
    /// MAVLink message from flight controller
    Mavlink(MavlinkTrigger),
    /// Geofence database lookup
    GeofenceDb(GeofenceTrigger),
    /// V4L2 anomaly detector
    AnomalyDetector(AnomalyTrigger),
    /// Firewall (undeclared network connection)
    Firewall(FirewallTrigger),
    /// Process monitor (unexpected process spawned)
    ProcessMonitor(ProcessTrigger),
}

pub struct MavlinkTrigger {
    pub message_id: u32,
    pub message_name: String,
    pub field: String,
    pub condition: TriggerCondition,
}
```

### 13.4 Geofence Database

For simulation, load a GeoJSON file with restricted airspace polygons:

```json
{
  "type": "FeatureCollection",
  "features": [
    {
      "type": "Feature",
      "properties": {
        "airspace_class": "B",
        "name": "KSFO Class B Surface Area",
        "floor_ft_msl": 0,
        "ceiling_ft_msl": 10000
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[[-122.38, 37.63], [-122.35, 37.63], ...]]
      }
    }
  ]
}
```

The sealed event engine checks `GLOBAL_POSITION_INT` against this database on every position update. Computational cost is negligible for a single-drone simulation.

### 13.5 Preservation Override Mechanism

When a sealed event fires:

1. **Tag all current session data** within the preservation scope (time window) as `sealed_event_preserved`.
2. **Override any manifest BURN rules** for this data — sealed events have absolute precedence.
3. **Add stakeholders** to the preservation list for this data, even if the manifest does not declare them.
4. **Record the sealed event** in the audit log with full context.
5. **Notify GCS** of the sealed event.

```rust
pub struct SealedEventRecord {
    pub id: Uuid,
    pub event_type: SealedEventType,
    pub trigger_timestamp: DateTime<Utc>,
    pub detection_timestamp: DateTime<Utc>,
    pub trigger_source: TriggerSource,
    pub preservation_window: TimeRange,       // T-30s to T+30s, etc.
    pub stakeholders: Vec<StakeholderId>,
    pub retention: Duration,
    pub data_categories_preserved: Vec<DataCategory>,
    pub context: serde_json::Value,           // Trigger-specific context
}
```

### 13.6 Interface

```rust
pub trait SealedEventEngine {
    /// Register a trigger source.
    fn register_source(&mut self, source: Box<dyn TriggerSource>) -> Result<(), EngineError>;

    /// Process an incoming event from any trigger source.
    fn process_event(&mut self, event: TriggerEvent) -> Option<SealedEventRecord>;

    /// Get all fired sealed events in this session.
    fn fired_events(&self) -> &[SealedEventRecord];

    /// Check if a data item is covered by a sealed event preservation.
    fn is_sealed(&self, timestamp: DateTime<Utc>, data_category: &DataCategory) -> bool;
}
```

---

## 14. Module 10: Audit Log System

### 14.1 Responsibility

Maintain a signed, append-only log of every data flow decision made during the mission. The audit log survives the burn — it is the transparency mechanism. Post-flight, the audit log is verifiable using only the preserved session public key.

### 14.2 Log Entry Structure

```rust
pub struct AuditEntry {
    pub sequence: u64,                    // Monotonic, gapless
    pub timestamp: DateTime<Utc>,
    pub previous_hash: [u8; 32],          // SHA-256 of previous entry (hash chain)
    pub entry_type: AuditEntryType,
    pub manifest_hash: [u8; 32],          // Binds entry to manifest
    pub session_id: SessionId,
    pub signature: Ed25519Signature,      // Signed by session signing key
}

pub enum AuditEntryType {
    /// Session started
    SessionStart {
        session_public_key: Ed25519PublicKey,
        manifest_hash: [u8; 32],
        timestamp: DateTime<Utc>,
    },

    /// Data flow decision
    DataFlow {
        source: DataSource,               // Camera, MAVLink, LiDAR, etc.
        decision: ManifestDecision,       // Preserve, Deny, Burn
        rule_id: Option<String>,
        bytes: u64,
        event_label: EventLabel,
    },

    /// Sealed event fired
    SealedEvent(SealedEventRecord),

    /// Anomaly detected
    Anomaly(AnomalyEvent),

    /// Firewall event
    FirewallEvent(FirewallEvent),

    /// Preservation extension received
    PreservationExtension {
        authority: String,
        scope: PreservationScope,
        signature: Vec<u8>,
    },

    /// Burn layer completed
    BurnLayer {
        layer: u8,
        status: LayerStatus,
        details: String,
    },

    /// Session ended
    SessionEnd {
        burn_report: BurnReport,
        preserved_categories: Vec<DataCategory>,
        burned_categories: Vec<DataCategory>,
    },
}
```

### 14.3 Hash Chain Integrity

Each audit entry includes the SHA-256 hash of the previous entry, forming a chain:

```
Entry 0: previous_hash = [0; 32] (genesis)
Entry 1: previous_hash = SHA-256(Entry 0)
Entry 2: previous_hash = SHA-256(Entry 1)
...
Entry N: previous_hash = SHA-256(Entry N-1)
```

Verification: recompute the hash chain from Entry 0. Any tampering breaks the chain from the tampered entry onward.

### 14.4 Signing

Every entry is individually signed with the session Ed25519 signing key. The final entry (SessionEnd) is signed last, and then the signing key is zeroised.

Post-flight verification uses only the session public key (which was transmitted to the GCS at session start):

```
For each entry in audit_log:
  assert Ed25519::verify(entry.signature, entry.without_signature(), session_public_key)
  assert entry.previous_hash == SHA-256(previous_entry)
  assert entry.manifest_hash == expected_manifest_hash
  assert entry.sequence == expected_sequence
```

### 14.5 Storage

During flight: append-only file in a non-session-encrypted partition (the audit log must survive the burn).

Format: newline-delimited JSON (NDJSON) for simplicity. Each line is one `AuditEntry` serialized as JSON.

```
{"sequence":0,"timestamp":"2026-04-08T10:00:00Z","previous_hash":"AAAA...","entry_type":{"SessionStart":{...}},"signature":"..."}
{"sequence":1,"timestamp":"2026-04-08T10:00:01Z","previous_hash":"abc1...","entry_type":{"DataFlow":{...}},"signature":"..."}
```

### 14.6 GCS Sync

The audit log is synced to the GCS:
- **Pre-flight:** Session public key transmitted
- **In-flight:** Periodic audit log tail sync (every 10 seconds) — GCS can monitor data flow decisions in near-real-time
- **Post-flight:** Final audit log transmitted in full, including burn report

### 14.7 Interface

```rust
pub trait AuditLogger {
    /// Append an entry to the audit log. Automatically computes hash chain and signature.
    fn log(&mut self, entry_type: AuditEntryType) -> Result<u64, AuditError>;

    /// Finalise the audit log (called during burn). Returns the complete log.
    fn finalise(&mut self, burn_report: &BurnReport) -> Result<AuditLog, AuditError>;

    /// Verify a completed audit log using the session public key.
    fn verify(log: &AuditLog, session_public_key: &Ed25519PublicKey) -> Result<VerifyResult, AuditError>;

    /// Get entries since sequence number (for GCS sync).
    fn entries_since(&self, sequence: u64) -> &[AuditEntry];
}
```

---

## 15. Module 11: Ground Control Station Interface

### 15.1 Responsibility

Minimal GCS that demonstrates the ground-side integration points:
- Load and sign manifests
- Receive session public keys
- Display real-time audit log
- Trigger mid-mission preservation extensions
- Verify post-mission audit logs
- Display sealed event alerts

### 15.2 GCS API (WebSocket + REST)

**REST endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/api/manifest/load` | Upload and validate a manifest |
| POST | `/api/manifest/sign` | Sign a manifest with operator credentials |
| GET | `/api/session/current` | Get current session info (state, public key) |
| GET | `/api/audit/entries?since=N` | Get audit entries since sequence N |
| GET | `/api/audit/verify` | Verify the audit log for a completed session |
| POST | `/api/preserve/extend` | Send mid-mission preservation extension command |
| GET | `/api/sealed-events` | List all sealed events in current session |
| GET | `/api/anomalies` | List all detected anomalies in current session |

**WebSocket endpoint:**

`ws://host:8080/ws` — real-time stream of:
- Audit log entries (as they're generated)
- Sealed event alerts
- Anomaly alerts
- Session state transitions
- Firewall block events

### 15.3 GCS UI (Minimal Web)

A single-page HTML/JS application displaying:

1. **Session status panel:** State machine visualization, session timer, key fingerprints
2. **Manifest viewer:** Parsed manifest with syntax highlighting
3. **Audit log feed:** Real-time scrolling log of audit entries
4. **Sealed events panel:** Alert cards for each fired sealed event
5. **Anomaly panel:** Alert cards for detected V4L2 anomalies
6. **Firewall panel:** Blocked connection log
7. **Post-mission verification:** Button to verify audit log integrity

### 15.4 Mid-Mission Preservation Extension (Section 7.2 of paper)

The GCS can send a signed preservation extension command during flight:

```json
{
  "type": "preservation_extension",
  "authority": "court_order",
  "authority_key_id": "judge-smith-2026",
  "scope": {
    "data_categories": ["all"],
    "time_range": "session_start_to_now"
  },
  "signature": "base64-ed25519-signature"
}
```

The Chambers module verifies the signature against the pre-provisioned judicial authority trust store, tags all current session data as preservation-extended, and suspends burn for the specified categories.

---

## 16. Integration Testing Scenarios

### 16.1 Scenario 1: Normal Mission Lifecycle

**Description:** Complete mission from arming to post-mission verification with no anomalies.

**Steps:**
1. Load manifest with operator + client stakeholders
2. Arm mission → verify session keypair generated
3. Takeoff (PX4 SITL scripted mission)
4. Fly a 2-minute inspection pattern
5. Camera captures ~3,600 frames (30fps * 120s)
6. MAVLink generates ~12,000-24,000 messages
7. Land
8. Verify preservation: client gets thermal/EO imagery, operator gets telemetry
9. Verify burn: everything else destroyed
10. Verify audit log: complete, signed, hash chain intact
11. Verify audit log is verifiable using only session public key

**Pass criteria:** Audit log verifies. Preserved data decryptable by declared stakeholders only. Session storage directory empty after burn. Session keys are zero.

### 16.2 Scenario 2: Geofence Violation Sealed Event

**Steps:**
1. Load manifest + geofence database
2. Arm and takeoff
3. Script PX4 to fly outside geofence boundary
4. Verify GEOFENCE_VIOLATION sealed event fires
5. Verify position + telemetry preserved for regulator + UTM for 90 days
6. Verify sealed event overrides any manifest BURN rules for this data
7. Land and complete burn
8. Verify preserved sealed event data survives burn

### 16.3 Scenario 3: Emergency Landing Sealed Event

**Steps:**
1. Arm and takeoff
2. Simulate low battery via PX4 parameter injection (`BAT_LOW_THR` threshold)
3. PX4 triggers failsafe → Return to Launch → Land
4. Verify EMERGENCY_LANDING sealed event fires
5. Verify flight log preceding 60s through landing preserved for all regulatory stakeholders
6. Verify 365-day retention

### 16.4 Scenario 4: Undeclared Camera Access (Anomaly Detection)

**Steps:**
1. Arm and takeoff, camera pipeline active
2. Launch rogue process that opens `/dev/video10` and reads frames
3. Verify ANM-001 anomaly detected and logged
4. Verify anomaly includes: PID, process name, exe path, cmdline, timestamp
5. Verify GCS receives anomaly alert
6. Verify PAYLOAD_ANOMALY sealed event fires
7. Verify rogue process was NOT killed (detection, not enforcement)

### 16.5 Scenario 5: Post-Disarm Camera Access

**Steps:**
1. Complete a mission, land, motors disarm
2. Rogue process reads camera after disarm
3. Verify ANM-002 anomaly detected (reads after motor disarm)
4. Verify severity HIGH

### 16.6 Scenario 6: Undeclared Network Connection (Firewall)

**Steps:**
1. Arm with manifest declaring only GCS + UTM network flows
2. During flight, a process inside the network namespace attempts to connect to an undeclared IP:port
3. Verify connection blocked by nftables
4. Verify CHAMBERS_BLOCKED log entry
5. Verify firewall event in audit log
6. Verify PAYLOAD_ANOMALY sealed event fires (undeclared network connection)

### 16.7 Scenario 7: Mid-Mission Preservation Extension

**Steps:**
1. Arm and takeoff
2. GCS sends preservation extension command signed by pre-provisioned authority key
3. Verify Chambers module validates signature
4. Verify all current session data tagged as preservation-extended
5. Verify burn suspends for specified categories
6. Land and verify extended data preserved
7. Verify audit log records the extension with authority, timestamp, scope

### 16.8 Scenario 8: Burst Camera Access Correlated with Network Activity (ANM-005)

**Steps:**
1. Arm and takeoff
2. Rogue process reads camera in bursts of 10 frames every 5 seconds
3. Rogue process simultaneously transmits data to an undeclared endpoint
4. Firewall blocks the transmission
5. Anomaly detector correlates: burst V4L2 reads within 500ms of blocked network TX
6. Verify ANM-005 anomaly detected with CRITICAL severity
7. Verify correlation evidence in audit log

---

## 17. Technology Stack & Dependencies

### 17.1 Rust Crates

| Crate | Version | Purpose |
|---|---|---|
| `tokio` | 1.x | Async runtime |
| `mavlink` | 0.13+ | MAVLink protocol parsing (PX4 dialect) |
| `ring` | 0.17+ | AES-256-GCM, HKDF-SHA256 |
| `ed25519-dalek` | 2.x | Ed25519 signing |
| `x25519-dalek` | 2.x | X25519 key agreement |
| `zeroize` | 1.x | Secure memory clearing |
| `v4l` | 0.14+ | Video4Linux2 bindings |
| `toml` | 0.8+ | Manifest parsing |
| `serde` / `serde_json` | 1.x | Serialization |
| `chrono` | 0.4+ | Timestamps |
| `uuid` | 1.x | Event IDs |
| `tracing` | 0.1+ | Structured logging |
| `nix` | 0.29+ | Unix syscalls (fanotify, inotify, madvise) |
| `aya` | 0.12+ | eBPF (optional, for V4L2 monitoring) |
| `tokio-tungstenite` | 0.21+ | WebSocket for GCS communication |
| `sha2` | 0.10+ | SHA-256 for hash chain |
| `base64` | 0.22+ | Base64 encoding for keys in manifest |
| `geo` | 0.28+ | Geospatial operations (point-in-polygon for geofence) |
| `geojson` | 0.24+ | GeoJSON parsing for airspace database |

### 17.2 Python Packages (GCS)

| Package | Purpose |
|---|---|
| `fastapi` | REST + WebSocket API |
| `uvicorn` | ASGI server |
| `websockets` | WebSocket client for testing |
| `pydantic` | Data validation |
| `ed25519` / `PyNaCl` | Signature verification |
| `pytest` | Integration testing |
| `mavsdk` | MAVLink scripting for test scenarios |

### 17.3 System Dependencies

| Component | Version | Purpose |
|---|---|---|
| PX4-Autopilot | v1.15.x | Flight controller SITL |
| Gazebo Harmonic or Classic 11 | Latest | Physics + sensor simulation |
| v4l2loopback | 0.13+ | Virtual V4L2 device |
| GStreamer | 1.20+ | Camera bridge |
| Docker + Docker Compose | Latest | Orchestration |
| nftables | 1.0+ | Firewall |
| Linux kernel | 5.8+ | eBPF support (optional) |

---

## 18. Directory Structure

```
UAS/
├── chambers_uas_position_paper.pdf     # Reference document
├── PRD.md                               # This document
├── ISSUES.md                            # Issue list
├── docker-compose.yml                   # Orchestration
├── Makefile                             # Build + run shortcuts
│
├── chambers/                            # Rust workspace: core Chambers module
│   ├── Cargo.toml                       # Workspace root
│   ├── Dockerfile
│   ├── chambers-core/                   # Library crate
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── session.rs               # Module 1: Session Lifecycle
│   │       ├── crypto.rs                # Module 2: Cryptographic Engine
│   │       ├── manifest.rs              # Module 3: Preservation Manifest
│   │       ├── manifest_grammar.rs      # Manifest parser
│   │       ├── burn.rs                  # Module 4: Burn Engine
│   │       ├── mavlink_proxy.rs         # Module 5: MAVLink Proxy
│   │       ├── camera.rs               # Module 6: Camera Pipeline
│   │       ├── v4l2_monitor.rs          # Module 7: V4L2 Anomaly Detection
│   │       ├── firewall.rs              # Module 8: Manifest-Aware Firewall
│   │       ├── sealed_events.rs         # Module 9: Sealed Event Engine
│   │       ├── audit.rs                 # Module 10: Audit Log
│   │       ├── types.rs                 # Shared types
│   │       └── error.rs                 # Error types
│   ├── chambers-daemon/                 # Binary crate (the running module)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs                  # Wires all modules together
│   └── chambers-verify/                 # Binary crate (post-flight verification tool)
│       ├── Cargo.toml
│       └── src/
│           └── main.rs                  # Audit log verification CLI
│
├── bridge/                              # Gazebo → v4l2loopback bridge
│   ├── Dockerfile
│   ├── bridge.sh                        # GStreamer pipeline script
│   └── ros2_bridge_node.py              # Alternative ROS2 bridge node
│
├── gcs/                                 # Python GCS interface
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── gcs/
│   │   ├── __init__.py
│   │   ├── app.py                       # FastAPI application
│   │   ├── api/
│   │   │   ├── manifest.py              # Manifest endpoints
│   │   │   ├── session.py               # Session endpoints
│   │   │   ├── audit.py                 # Audit log endpoints
│   │   │   └── websocket.py             # WebSocket handler
│   │   ├── verification.py              # Audit log verifier
│   │   └── models.py                    # Pydantic models
│   └── static/
│       └── index.html                   # Minimal web UI
│
├── manifests/                           # Example manifests
│   ├── inspection_basic.toml            # Basic inspection mission
│   ├── inspection_full.toml             # Full inspection with all stakeholders
│   ├── bvlos_utm.toml                   # BVLOS with UTM integration
│   └── test_minimal.toml               # Minimal manifest for unit tests
│
├── geofence/                            # Airspace databases
│   ├── test_geofence.geojson            # Test geofence for simulation
│   └── restricted_airspace_sample.geojson
│
├── worlds/                              # Gazebo world files
│   ├── chambers_test_world.sdf          # Primary test world
│   └── models/                          # Custom Gazebo models
│
├── test/                                # Integration tests
│   ├── rogue/                           # Rogue process for anomaly testing
│   │   ├── Dockerfile
│   │   └── rogue.py                     # Configurable V4L2 rogue reader
│   ├── scenarios/                       # Test scenario scripts
│   │   ├── test_normal_mission.py       # Scenario 1
│   │   ├── test_geofence_violation.py   # Scenario 2
│   │   ├── test_emergency_landing.py    # Scenario 3
│   │   ├── test_undeclared_camera.py    # Scenario 4
│   │   ├── test_post_disarm_camera.py   # Scenario 5
│   │   ├── test_undeclared_network.py   # Scenario 6
│   │   ├── test_preservation_ext.py     # Scenario 7
│   │   └── test_burst_correlation.py    # Scenario 8
│   └── conftest.py                      # Shared pytest fixtures
│
├── scripts/                             # Utility scripts
│   ├── setup_v4l2loopback.sh            # v4l2loopback kernel module setup
│   ├── setup_netns.sh                   # Network namespace setup
│   ├── run_simulation.sh                # Full simulation launcher
│   └── verify_audit_log.sh              # Post-mission verification wrapper
│
└── docs/                                # Implementation notes (generated during development)
    └── .gitkeep
```

---

## 19. Acceptance Criteria

### 19.1 Must-Have (MVP)

| ID | Criterion | Verification |
|---|---|---|
| AC-01 | Session lifecycle completes: IDLE → PRE_FLIGHT → IN_FLIGHT → POST_FLIGHT → BURNING → IDLE | Integration test Scenario 1 |
| AC-02 | Session keypair generated with Ed25519 + X25519, zeroised after burn | Unit test + memory inspection |
| AC-03 | Manifest loads, validates, and rejects invalid manifests with specific errors | Unit tests for each validation rule |
| AC-04 | MAVLink telemetry encrypted with AES-256-GCM, event labels generated | Scenario 1 |
| AC-05 | Camera frames from v4l2loopback encrypted and stored | Scenario 1 |
| AC-06 | Undeclared V4L2 access detected (ANM-001) | Scenario 4 |
| AC-07 | Geofence violation sealed event fires | Scenario 2 |
| AC-08 | Emergency landing sealed event fires | Scenario 3 |
| AC-09 | Six-layer burn completes, session storage empty, keys zero | Scenario 1 |
| AC-10 | Audit log verifiable post-mission using only session public key | Scenario 1 |
| AC-11 | Firewall blocks undeclared outbound connections | Scenario 6 |
| AC-12 | Preserved data decryptable by declared stakeholder, not by others | Unit test + Scenario 1 |

### 19.2 Should-Have

| ID | Criterion | Verification |
|---|---|---|
| AC-13 | Post-disarm camera access detected (ANM-002) | Scenario 5 |
| AC-14 | Burst/network correlation detected (ANM-005) | Scenario 8 |
| AC-15 | Mid-mission preservation extension works | Scenario 7 |
| AC-16 | GCS displays real-time audit feed | Manual verification |
| AC-17 | Near-miss sealed event fires from obstacle avoidance | Scenario with obstacle |
| AC-18 | Payload anomaly sealed event fires from undeclared process | Scenario 4 |

### 19.3 Nice-to-Have

| ID | Criterion | Verification |
|---|---|---|
| AC-19 | eBPF-based V4L2 monitoring (vs. fanotify fallback) | Unit test |
| AC-20 | Multiple simultaneous stakeholder preservation | Scenario 1 (multi-stakeholder manifest) |
| AC-21 | Manifest co-signing by regulator | Unit test |
| AC-22 | Full Docker Compose one-command launch | `docker compose up` |

---

## 20. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R-01 | v4l2loopback does not work inside Docker containers | Medium | High — blocks V4L2 anomaly detection | Test early. Fallback: run V4L2 components on host, not in container. |
| R-02 | PX4 SITL + Gazebo Harmonic integration instability | Medium | Medium — delays simulation setup | Fallback to Gazebo Classic 11 which has mature PX4 support. |
| R-03 | eBPF not available in Docker/VM environment | High | Low — fanotify fallback exists | Implement fanotify first, eBPF as enhancement. |
| R-04 | GStreamer → v4l2loopback pipeline drops frames | Medium | Medium — affects camera encryption throughput testing | Accept frame drops in simulation; real hardware is the true benchmark. |
| R-05 | nftables not available in container without privileged mode | Low | Medium — blocks firewall testing | Docker Compose already specifies `cap_add: NET_ADMIN`. |
| R-06 | macOS host cannot run v4l2loopback natively | Certain | High — dev machine is macOS | All Linux-dependent components run in Docker or a Linux VM. |
| R-07 | MAVLink proxy introduces unacceptable latency to PX4 control loop | Low | High — would make simulation unusable | Proxy only intercepts telemetry stream, not control commands. Control loop remains direct. |
| R-08 | Rust `v4l` crate incompatible with v4l2loopback virtual devices | Low | Medium | Test early. Fallback: raw ioctl via `nix` crate. |

---

*End of PRD*
