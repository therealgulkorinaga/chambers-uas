# Chambers UAS

**Sealed ephemeral computation for drone missions — a reference implementation of the Chambers architecture applied to Unmanned Aerial Systems.**

Chambers UAS enforces the principle of *default destroy, explicit preserve*: every byte a drone captures is encrypted with a session-ephemeral key and cryptographically destroyed at mission end unless the operator's signed manifest explicitly declares otherwise. No key, no data. The architecture is designed so that data sovereignty decisions are made before wheels-off and enforced in hardware-adjacent software — not cloud policies that can be revised after the fact.

---

## Table of Contents

1. [Background and Motivation](#1-background-and-motivation)
2. [Core Principles](#2-core-principles)
3. [System Architecture](#3-system-architecture)
4. [Repository Layout](#4-repository-layout)
5. [The Manifest Grammar](#5-the-manifest-grammar)
6. [Session Lifecycle](#6-session-lifecycle)
7. [Cryptographic Design](#7-cryptographic-design)
8. [The Six-Layer Burn Engine](#8-the-six-layer-burn-engine)
9. [The Preservation Pipeline](#9-the-preservation-pipeline)
10. [Sealed Events](#10-sealed-events)
11. [V4L2 Anomaly Detection](#11-v4l2-anomaly-detection)
12. [Manifest-Aware Firewall](#12-manifest-aware-firewall)
13. [MAVLink Proxy and Encryption](#13-mavlink-proxy-and-encryption)
14. [Camera Pipeline](#14-camera-pipeline)
15. [Audit Log and Verification](#15-audit-log-and-verification)
16. [Ground Control Station (GCS)](#16-ground-control-station-gcs)
17. [Simulation Environment](#17-simulation-environment)
18. [Running the System](#18-running-the-system)
19. [Testing](#19-testing)
20. [Technology Stack](#20-technology-stack)
21. [Threat Model](#21-threat-model)
22. [Regulatory Mapping](#22-regulatory-mapping)
23. [Data Categories Reference](#23-data-categories-reference)
24. [Anomaly Pattern Reference](#24-anomaly-pattern-reference)

---

## 1. Background and Motivation

Modern drone operations produce continuous high-resolution sensor data — thermal imagery, electro-optical video, LiDAR point clouds, precise GPS telemetry, and more. That data passes through an ecosystem of operators, clients, regulators, and third-party cloud platforms, each with different, often conflicting, interests in what gets retained, where, and for how long.

The status quo is cloud-centric retention: data is uploaded post-flight to a managed platform, and access controls are enforced by policy files that can be silently amended. The data exists until actively deleted. The burden of proof for erasure is nearly impossible to meet. For missions over sensitive infrastructure, private land, or in contested regulatory jurisdictions, this is unacceptable.

Chambers inverts this model. Rather than "store everything, delete later," the system defaults to cryptographic destruction of all data at mission completion. Preservation is the exception, declared explicitly in a signed TOML manifest that is committed before the aircraft arms. The manifest specifies:

- Which sensor data categories may be retained
- Which stakeholders (operator, client, regulator, manufacturer, public) may receive which categories
- How long each stakeholder's copy may be retained
- Which network flows are permitted in-flight
- Which operating system processes are permitted to access sensor hardware

Everything outside the manifest's declared scope is encrypted with a key that is destroyed at mission end. The encrypted ciphertext remains on-disk until storage cleanup; after key destruction it is computationally unrecoverable.

This repository is the first complete working implementation of the Chambers architecture for UAS, built as a simulation-capable reference system using PX4 SITL, Gazebo, V4L2 loopback devices, and Docker Compose.

---

## 2. Core Principles

### 2.1 Ephemeral-by-Default

Session keys are generated at mission arm and destroyed at the start of the burn phase. No copy of the symmetric encryption key is persisted anywhere during the mission. The only entities that can decrypt preserved data are the stakeholders whose public keys appear in the manifest — and only after post-flight re-encryption under their respective keys.

### 2.2 Manifest Sovereignty

The preservation manifest is the sole source of truth for data policy. It is a TOML file with a validated schema, hashed on load, and the hash committed to every audit log entry. Any discrepancy between the manifest at arm time and any downstream claim about what was or was not retained is detectable. Manifests are not modifiable after the session starts.

### 2.3 Sealed Events

Certain flight events — geofence violations, near-miss encounters, emergency landings, airspace incursions, payload anomalies — are *sealed*: their associated sensor data is preserved regardless of what the manifest says about default disposal. Sealed events are defined by hardcoded invariants in the chambers-core library and cannot be suppressed by operator configuration. This ensures regulatory compliance data survives even on missions where the operator has chosen maximum privacy.

### 2.4 Auditability Without Retention

The audit log is hash-chained and signed with the session key. It records every data flow decision, every anomaly, every sealed event, every firewall block, and every burn layer result. The log is preserved at mission end. The public key needed to verify signatures is transmitted to the GCS at arm time. Post-mission verification of the audit log proves, cryptographically, that the records were produced by a specific session and have not been tampered with — without requiring that any sensor data be retained.

### 2.5 Hardware-Adjacent Enforcement

Enforcement happens as close to the sensor as possible. The Chambers daemon runs on the companion computer (the small Linux board sitting between the flight controller and the uplink radio). It intercepts MAVLink before it reaches the GCS radio, intercepts camera frames before they reach storage, monitors V4L2 device access at the kernel-level interface, and programs nftables rules before the network interface comes up. There is no "upload and filter" step.

### 2.6 Multi-Stakeholder Isolation

Each stakeholder receives their preserved data encrypted under their own public key, derived via X25519 ECDH. The operator cannot decrypt data preserved for the regulator. The client cannot decrypt telemetry preserved for the manufacturer. Stakeholder keys are included in the manifest before arming — they cannot be changed post-flight.

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FLIGHT HARDWARE                                  │
│                                                                         │
│   ┌───────────────────┐        ┌──────────────────────────────────────┐ │
│   │   PX4 Flight       │        │           Companion Computer          │ │
│   │   Controller       │◄──────►│    (Linux SBC — e.g. Raspberry Pi)   │ │
│   │  (SITL in sim)     │ UART   │                                      │ │
│   └───────────────────┘        │  ┌────────────────────────────────┐  │ │
│                                 │  │     chambers-daemon (Rust)     │  │ │
│   ┌───────────────────┐        │  │                                │  │ │
│   │   Camera Sensor    │        │  │  ┌──────────┐ ┌────────────┐ │  │ │
│   │  (V4L2 /dev/video) │───────►│  │  │ Camera   │ │ MAVLink    │ │  │ │
│   └───────────────────┘  V4L2  │  │  │ Pipeline │ │ Proxy      │ │  │ │
│                                 │  │  └─────┬────┘ └─────┬──────┘ │  │ │
│                                 │  │        │             │        │  │ │
│                                 │  │  ┌─────▼─────────────▼──────┐ │  │ │
│                                 │  │  │    Session Keys           │ │  │ │
│                                 │  │  │    (AES-256-GCM)          │ │  │ │
│                                 │  │  └─────────────┬────────────┘ │  │ │
│                                 │  │                │               │  │ │
│                                 │  │  ┌─────────────▼────────────┐ │  │ │
│                                 │  │  │    Session Storage        │ │  │ │
│                                 │  │  │  (encrypted at rest)     │ │  │ │
│                                 │  │  └──────────────────────────┘ │  │ │
│                                 │  │                                │  │ │
│                                 │  │  ┌──────────┐ ┌────────────┐ │  │ │
│                                 │  │  │ Anomaly  │ │ Sealed     │ │  │ │
│                                 │  │  │ Detector │ │ Events     │ │  │ │
│                                 │  │  └──────────┘ └────────────┘ │  │ │
│                                 │  │                                │  │ │
│                                 │  │  ┌──────────┐ ┌────────────┐ │  │ │
│                                 │  │  │ Firewall │ │ Audit Log  │ │  │ │
│                                 │  │  │(nftables)│ │ (chained)  │ │  │ │
│                                 │  │  └──────────┘ └────────────┘ │  │ │
│                                 │  └────────────────────────────────┘  │ │
│                                 └──────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                      │ WebSocket (declared)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    GROUND CONTROL STATION (GCS)                          │
│                                                                         │
│   FastAPI + WebSocket server                                            │
│   ├── Session state endpoint (/api/session/current)                     │
│   ├── Manifest endpoint (/api/manifest/)                                │
│   ├── Audit log endpoint (/api/audit/entries)                           │
│   └── Real-time event stream (/ws WebSocket)                            │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     POST-FLIGHT VERIFICATION                             │
│                                                                         │
│   chambers-verify --audit <path> --pubkey <hex>                         │
│   ├── Verify Ed25519 signature on every audit entry                     │
│   ├── Verify SHA-256 hash chain integrity                               │
│   └── Report: entries, anomalies, sealed events, burn layers            │
└─────────────────────────────────────────────────────────────────────────┘
```

### Simulation Stack

In the simulation environment, hardware components are replaced by software equivalents:

| Hardware | Simulation Equivalent |
|---|---|
| PX4 flight controller | PX4 SITL (Software In The Loop) container |
| Camera sensor | Gazebo virtual camera → GStreamer → v4l2loopback /dev/video10 |
| Companion computer | Docker container (chambers-module) |
| Physical network interfaces | Docker bridge network (172.20.0.0/16) |
| Radio uplink | Direct UDP/TCP on Docker network |

---

## 4. Repository Layout

```
UAS/
├── chambers/                   # Core Rust implementation
│   ├── chambers-core/          # Library: crypto, manifest, session, burn, etc.
│   │   └── src/
│   │       ├── lib.rs          # Module exports
│   │       ├── types.rs        # Shared domain types
│   │       ├── error.rs        # Unified error hierarchy
│   │       ├── crypto.rs       # Ed25519, X25519, AES-256-GCM, HKDF
│   │       ├── manifest.rs     # TOML parsing, rule evaluation
│   │       ├── session.rs      # 5-state lifecycle machine, storage
│   │       ├── audit.rs        # Hash-chained signed audit log
│   │       ├── burn.rs         # 6-layer destruction engine
│   │       ├── mavlink_proxy.rs# MAVLink parsing, classification, encryption
│   │       ├── camera.rs       # V4L2 frame reader, encryption pipeline
│   │       ├── v4l2_monitor.rs # Anomaly detection (ANM-001 through ANM-006)
│   │       ├── firewall.rs     # nftables rule generation
│   │       └── sealed_events.rs# GeoJSON geofence, 5 sealed event types
│   ├── chambers-daemon/        # Binary: companion computer daemon
│   │   └── src/main.rs         # 5-phase mission orchestration
│   ├── chambers-verify/        # Binary: post-flight CLI verifier
│   │   └── src/main.rs         # Audit log signature + hash chain verification
│   ├── Cargo.toml              # Workspace manifest
│   └── rust-toolchain.toml     # Pinned Rust 1.75
│
├── gcs/                        # Ground Control Station (Python/FastAPI)
│   ├── gcs/
│   │   ├── app.py              # FastAPI application, routing, lifecycle
│   │   ├── models.py           # Pydantic models for all API types
│   │   └── api/
│   │       ├── manifest.py     # Manifest upload/retrieval
│   │       ├── session.py      # Session state query
│   │       ├── audit.py        # Audit entry streaming and verification
│   │       └── websocket.py    # Real-time event broadcasting
│   ├── requirements.txt
│   └── Dockerfile
│
├── test/                       # Integration testing
│   ├── conftest.py             # pytest fixtures: docker-compose lifecycle
│   └── rogue/
│       ├── rogue.py            # Adversarial V4L2 reader for anomaly tests
│       └── Dockerfile
│
├── bridge/
│   └── bridge.sh               # GStreamer: Gazebo camera → v4l2loopback
│
├── scripts/
│   ├── run_simulation.sh       # Top-level: v4l2loopback → netns → compose
│   ├── setup_v4l2loopback.sh   # Create /dev/video10 loopback device
│   ├── setup_netns.sh          # Network namespace isolation
│   └── verify_audit_log.sh     # Wrapper for chambers-verify
│
├── manifests/                  # Example preservation manifests (TOML)
│   ├── inspection_basic.toml   # Infrastructure inspection — operator + client
│   ├── inspection_full.toml    # Full multi-stakeholder example
│   └── test_minimal.toml       # Minimal manifest for unit testing
│
├── geofence/                   # GeoJSON airspace zone definitions
│   ├── restricted_airspace_sample.geojson
│   └── test_geofence.geojson
│
├── worlds/                     # Gazebo world files and models
│
├── docker-compose.yml          # Full simulation stack orchestration
├── Makefile                    # Build, test, lint, sim-up/down, verify
├── PRD.md                      # Product Requirements Document
├── chambers_uas_v2.md          # Position paper (architecture + regulatory)
└── ISSUES.md                   # Tracked issues by domain prefix
```

---

## 5. The Manifest Grammar

The preservation manifest is a TOML file that defines the complete data policy for a mission. It must be provided to the daemon before arming and cannot be modified once the session starts. The manifest hash is committed to every audit log entry.

### Structure

```toml
[meta]
version = "1.0"
drone_id = "DRN-2026-0042"
operator_id = "OP-2026-00142"
mission_type = "infrastructure_inspection"
manifest_hash = ""             # auto-computed on load

[regulatory]
remote_id = true               # MUST be true for Part 107 / sUAS operations
jurisdiction = "US"
operation_category = "part_107"

[defaults]
action = "burn"                # burn | preserve | deny — applied to all unmatched data

[[stakeholders]]
id = "operator"
role = "Operator"
display_name = "AcmeDrone Services LLC"
public_key_base64 = "<32-byte X25519 public key in Base64>"

[[stakeholders]]
id = "client"
role = "Client"
display_name = "PowerGrid Corp"
public_key_base64 = "<32-byte X25519 public key in Base64>"

[[preserve]]
id = "thermal-to-client"
data_category = "thermal_imagery"
stakeholder_id = "client"
retention_days = "90d"

[[preserve]]
id = "telemetry-to-operator"
data_category = "flight_telemetry"
stakeholder_id = "operator"
retention_days = "365d"

[[preserve]]
id = "remote-id-broadcast"
data_category = "remote_id"
stakeholder_id = "public"
retention_days = "0"           # 0 = broadcast-only, not stored

[[deny]]
id = "no-audio"
data_category = "custom"
reason = "Mission scope does not include audio capture"

[[network_flows]]
id = "gcs-websocket"
destination = "gcs"
host = "172.20.0.100"
port = 8080
protocol = "websocket"
data_category = "flight_telemetry"

[system_allowlist]
processes = ["v4l2-compliance", "gst-launch-1.0"]
```

### Validation Rules

The manifest engine enforces eight rules at load time:

1. `remote_id` must be `true` (regulatory requirement; no manifest without Remote ID compliance is accepted)
2. `[defaults]` must specify an action (`burn`, `preserve`, or `deny`)
3. Every `[[preserve]]` entry must reference a declared stakeholder
4. Every `[[deny]]` entry must include a non-empty `reason`
5. Stakeholder public keys must be valid Base64-encoded 32-byte values
6. No duplicate rule IDs across `[[preserve]]` and `[[deny]]` tables
7. No duplicate stakeholder IDs in `[[stakeholders]]`
8. At least one preserve rule must exist if any stakeholder is declared

### Evaluation Order

When the preservation engine evaluates a `(DataCategory, StakeholderId)` pair:

1. Check all `[[deny]]` rules in stakeholder priority order (Regulator > Operator > Client > Manufacturer > Public). First match returns `Deny`.
2. Check all `[[preserve]]` rules in stakeholder priority order. First match returns `Preserve{retention_days}`.
3. If no rule matches, apply the `[defaults].action`.

The default action on any standard mission is `burn` — data is encrypted with the session key and rendered unrecoverable at burn time.

---

## 6. Session Lifecycle

The session manager is a five-state machine. State transitions are validated — an illegal transition panics rather than silently permitting it.

```
                    arm_mission()
  ┌──────┐         ┌──────────┐       notify_takeoff()    ┌──────────┐
  │ Idle │────────►│PreFlight │──────────────────────────►│ InFlight │
  └──────┘         └──────────┘                           └─────┬────┘
                                                                 │
                                                   notify_landing()
                                                                 │
  ┌─────────┐      ┌──────────────┐                      ┌──────▼───┐
  │ Burning │◄─────│ PostFlight   │◄─────────────────────│PostFlight│
  └─────────┘      └──────────────┘                      └──────────┘
                         │
                    trigger_burn()
                         │
                   ┌─────▼──────┐
                   │   Burning  │
                   └────────────┘
```

### Phase 1 — ARM (Idle → PreFlight)

Triggered by `arm_mission(manifest_path)`.

1. Parse and validate the manifest TOML file.
2. Compute SHA-256 hash of the raw manifest bytes.
3. Generate ephemeral session keypair: Ed25519 (signing) + X25519 (key agreement).
4. Derive session symmetric key: `HKDF-SHA256(ikm=OsRng(32), salt=sign_pub||enc_pub, info="chambers-session-v1")`.
5. Allocate a unique `SessionId` (16 random bytes, displayed as hex).
6. Create the session storage directory tree under the configured base path.
7. Open the NDJSON audit log file.
8. Write the genesis `SessionStart` audit entry (includes manifest hash, public key material, timestamp).
9. Configure and activate the nftables firewall from manifest network flows.
10. Initialize the anomaly detector with the manifest system allowlist.
11. Initialize the sealed event engine with the geofence database.
12. Transmit session public keys and manifest hash to GCS via WebSocket.

### Phase 2 — WAITING FOR TAKEOFF (PreFlight)

The daemon waits for a takeoff signal. In simulation, this is a configurable timer (`--auto-takeoff-secs`). On real hardware, it listens for a MAVLink COMMAND_ACK confirming `MAV_CMD_NAV_TAKEOFF`.

### Phase 3 — IN FLIGHT (PreFlight → InFlight)

Triggered by `notify_takeoff()`. The main processing loop runs at approximately 30 Hz:

- **Camera loop**: Read a frame from V4L2 → encrypt with session AES-256-GCM → write `.enc` file to session storage → append `DataFlow` audit entry.
- **MAVLink loop**: Receive UDP datagram from PX4 → parse frame → classify by message ID → encrypt → write to session storage → append `DataFlow` audit entry.
- **Sealed events**: Extract position, battery, obstacle distance from MAVLink messages → pass to sealed event engine → fire appropriate sealed events.
- **Anomaly detection**: The V4L2 monitor observes access patterns on the camera device; any undeclared process touch triggers an anomaly.
- **Firewall events**: nftables logs blocked connection attempts; these are fed to the anomaly correlator for ANM-005 detection.
- **GCS streaming**: All events forwarded over the declared WebSocket connection in real time.

### Phase 4 — POST-FLIGHT (InFlight → PostFlight)

Triggered by `notify_landing()`. The daemon:

1. Logs statistics: total frames captured, messages encrypted, sealed events, anomalies.
2. Evaluates the manifest preservation rules for all captured data categories.
3. Re-encrypts preserved data under each stakeholder's public key (X25519 ECDH → HKDF → AES-256-GCM).
4. Prepares the burn sequence.

### Phase 5 — BURN (PostFlight → Burning)

The 6-layer burn engine executes. See [Section 8](#8-the-six-layer-burn-engine) for full detail.

---

## 7. Cryptographic Design

### 7.1 Key Hierarchy

```
OsRng(32 bytes) ─── HKDF-SHA256 ──► Session Symmetric Key (AES-256-GCM, 32 bytes)
                      salt = sign_pub_bytes || enc_pub_bytes
                      info = "chambers-session-v1"

OsRng ──────────────────────────► Ed25519 Keypair (signing key, 32 bytes + public 32 bytes)

OsRng ──────────────────────────► X25519 Keypair (encryption key, 32 bytes + public 32 bytes)

For each stakeholder:
  SessionKeys.enc_private × Stakeholder.public_key ──► X25519 Shared Secret
  HKDF-SHA256(shared_secret, salt=stakeholder_id, info="chambers-preservation-v1") ──► Preservation Key
```

### 7.2 Nonce Design

AES-256-GCM requires a unique 12-byte nonce per encryption call. Chambers uses a `CounterNonceSequence`:

- **Bytes 0–7**: Monotonically incrementing 64-bit counter (little-endian). Starts at zero, increments per call.
- **Bytes 8–11**: 4-byte random suffix generated at session initialization.

This structure guarantees nonce uniqueness within a session even under rapid sequential encryption (camera frames at 30 fps), while also preventing cross-session nonce reuse if a counter is accidentally reset.

### 7.3 Authenticated Encryption

All data is encrypted with Additional Authenticated Data (AAD). The AAD is the serialized `EventLabel` for the data flow: it includes the data source, timestamp, destination, manifest rule, and sequence number. This binds each ciphertext to its metadata — an attacker cannot substitute one encrypted payload for another without breaking authentication.

### 7.4 Signature Scheme

Ed25519 is used for:
- Signing every audit log entry (covers the serialized entry JSON minus the signature field).
- Signing the burn report (the signing key's final use before zeroization).

The public key is transmitted to the GCS at session start and retained there for post-flight verification.

### 7.5 Key Material Handling

All key structs implement the `ZeroizeOnDrop` trait from the `zeroize` crate. Explicit `zeroise()` methods are called at burn Layer 2. The Rust compiler cannot optimize out explicit zeroise calls because the `zeroize` crate uses platform-appropriate volatile writes and memory barriers.

### 7.6 Key Derivation for Preservation

Stakeholder preservation keys are derived per-stakeholder, not shared:

```
ECDH(session_x25519_private, stakeholder_x25519_public) → shared_secret (32 bytes)
HKDF-SHA256(
  ikm    = shared_secret,
  salt   = stakeholder_id_bytes,
  info   = "chambers-preservation-v1",
  length = 32
) → preservation_key
```

Each stakeholder can only perform the reverse ECDH if they hold their own private key. The operator's copy of preservation key material is not derivable from the session's audit log alone.

---

## 8. The Six-Layer Burn Engine

The burn engine is the core enforcement mechanism. It is invoked at the end of every mission, regardless of whether the mission ended normally, was interrupted, or terminated in error. An emergency burn path is also available that skips the audit layer in case of critical failure.

### Layer 1 — Capability Revocation

**Goal**: Ensure no process holds an open file descriptor to session storage before destruction begins.

**Method**: Enumerate `/proc/self/fd`, compare symlink targets against the session storage base path. If any FD points inside the storage tree, log the discrepancy. In production, this triggers an advisory alert before proceeding.

**Result**: PASS (no open FDs) or FAIL with details (which FDs remain open).

### Layer 2 — Cryptographic Erasure

**Goal**: Destroy the session symmetric encryption key.

**Method**: Call `SessionKeys.zeroise()` which invokes the zeroize crate's volatile write sequence on the AES-256-GCM key bytes and the X25519 private key bytes. The Ed25519 signing key is deferred — it must remain valid until after the burn report is signed at the end of Layer 6.

**Result**: All symmetric key material is overwritten with zeros and the memory is no longer accessible to the process. After this layer, the encrypted session storage is permanently unrecoverable (no key exists anywhere to decrypt it).

### Layer 3 — Storage Cleanup

**Goal**: Remove the physical ciphertext from disk.

**Method**: For each file in the session storage tree:
1. Open the file and overwrite its contents with cryptographically random bytes (multiple passes).
2. Sync to disk (`fsync`).
3. Truncate to zero bytes.
4. Delete the file.

After all files are deleted, remove the directory tree. Note that even without this step the data is unrecoverable (the key was destroyed in Layer 2), but this layer eliminates the ciphertext as a side-channel (e.g., to prevent forensic tools from observing block-level patterns or inferring data volume).

**Result**: Storage directory is empty.

### Layer 4 — Memory Zeroing

**Goal**: Verify that key material is not present in process memory.

**Method**: Call `sym_key_is_zero()` which checks that the previously zeroized key bytes are all zero. This is a post-condition check, not a second zeroization — it confirms the earlier zeroise() call succeeded and was not optimized away.

**Result**: PASS (all key bytes zero) or FAIL (memory zeroing may have been incomplete).

### Layer 5 — Audit Burn

**Goal**: Mark the audit log to reflect that encryption references have been removed.

**Method**: Append a `BurnLayer` audit entry for each completed layer, recording the layer name, status, and duration. This preserves the audit trail of the destruction event itself.

**Result**: Audit log contains a complete record of the burn sequence.

### Layer 6 — Semantic Verification

**Goal**: Confirm the end state of the system matches expectations.

**Method**:
1. Walk the session storage root — assert it is empty or does not exist.
2. Re-scan `/proc/self/fd` — assert no FDs point to session paths.
3. Check that the session state has transitioned to `Burning`.

**Result**: PASS (all assertions hold) or FAIL with specific details.

### Burn Report

After all six layers complete, a `BurnReport` is assembled:

```json
{
  "session_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "burn_start": "2026-04-09T14:22:00.000Z",
  "burn_end":   "2026-04-09T14:22:01.347Z",
  "layers": [
    {"layer": 1, "name": "Capability Revocation", "status": "Pass", "duration_us": 1204},
    {"layer": 2, "name": "Cryptographic Erasure",  "status": "Pass", "duration_us": 89},
    {"layer": 3, "name": "Storage Cleanup",        "status": "Pass", "duration_us": 847223},
    {"layer": 4, "name": "Memory Zeroing",         "status": "Pass", "duration_us": 12},
    {"layer": 5, "name": "Audit Burn",             "status": "Pass", "duration_us": 4033},
    {"layer": 6, "name": "Semantic Verification",  "status": "Pass", "duration_us": 913}
  ],
  "all_passed": true,
  "signature": "<Ed25519 signature over report bytes>"
}
```

The report is signed with the session Ed25519 signing key. This is the key's final use. The signing key is zeroized immediately after signing the report.

---

## 9. The Preservation Pipeline

Data that the manifest has declared `preserve` is not stored in plaintext. The preservation pipeline:

1. **In-flight**: Data is encrypted with the session symmetric key and stored in session storage (same as all other data).
2. **Post-flight**: The manifest is re-evaluated to identify which categories are preserved for which stakeholders.
3. **Re-encryption**: Preserved data is decrypted using the session key (still live at this point), then immediately re-encrypted using the stakeholder-specific preservation key derived via X25519 ECDH.
4. **Delivery**: Re-encrypted payloads are either written to a designated output directory for operator pickup, or transmitted over the declared GCS connection.
5. **Key derivation detail**:
   ```
   preservation_key[stakeholder] = HKDF-SHA256(
     ikm  = X25519(session.enc_private, stakeholder.public_key),
     salt = stakeholder_id.as_bytes(),
     info = "chambers-preservation-v1"
   )
   ```
   The stakeholder can decrypt their data by performing the reverse ECDH with their own private key.

6. **Retention enforcement**: Retention period (from `retention_days`) is stored alongside the encrypted payload. Enforcement of actual deletion after the retention window is the responsibility of the receiving party (the Chambers system records the obligation; it cannot enforce deletion on an external system).

---

## 10. Sealed Events

Sealed events are the mechanism by which legally or regulatorily mandated data is preserved independently of the operator's manifest policy. They represent the "floor" of preservation that no manifest can opt out of.

### Event Types

| Event | Trigger Condition | Preservation Scope |
|---|---|---|
| `AirspaceIncursion` | Aircraft enters Class B/C airspace or a restricted zone defined in the geofence database | 60 seconds before detection + 120 seconds after |
| `GeofenceViolation` | Aircraft exits a declared permitted zone | 30 seconds before + 90 seconds after |
| `NearMiss` | Obstacle distance drops below the safety margin (configurable, default 5m) | 30 seconds before + 60 seconds after |
| `EmergencyLanding` | Emergency landing command received (MAVLink `MAV_CMD_NAV_EMERGENCY_LAND`) | 120 seconds before + full post-landing sequence |
| `PayloadAnomaly` | Anomaly detected in payload sensor behavior | 30 seconds before + 60 seconds after |

### Geofence Database

Airspace zones are loaded from a GeoJSON FeatureCollection. Each feature is a polygon with properties:

```json
{
  "name": "Example Restricted Zone",
  "airspace_class": "B",
  "zone_type": "restricted",
  "floor_ft": 0,
  "ceiling_ft": 10000
}
```

`zone_type` values: `"restricted"`, `"tfr"` (temporary flight restriction), `"permitted"` (the aircraft is expected to be here).

Position checks use point-in-polygon tests against all loaded zones. A sealed event fires if the aircraft enters a `restricted` or `tfr` zone, or exits all `permitted` zones.

### Deduplication

Sealed events have a 60-second deduplication window per event type. Once an event type fires, it will not fire again for the same event type within 60 seconds. This prevents log spam from sustained airspace incursions or persistent obstacle proximity.

### Invariants

Sealed events are implemented as hardcoded logic in `chambers-core/src/sealed_events.rs`. They are not configurable from the manifest. The manifest cannot add a `deny` rule that would suppress a sealed event. The daemon's main loop calls `check_position()`, `check_obstacle()`, and `trigger_emergency_landing()` unconditionally, regardless of what the manifest says.

---

## 11. V4L2 Anomaly Detection

The anomaly detector monitors who is reading the camera device file descriptor during a mission. It classifies each access attempt against three categories:

- **DeclaredMission**: The chambers-daemon process itself (identified by PID).
- **SystemAllowlisted**: A process listed in the manifest's `[system_allowlist].processes` array (e.g., `gst-launch-1.0` for the GStreamer bridge).
- **Undeclared**: Any other process — a potential data exfiltration attempt.

### Anomaly Patterns

| ID | Name | Trigger | Severity |
|---|---|---|---|
| ANM-001 | Undeclared Camera Access | Any undeclared process calls `open()`, `read()`, or `VIDIOC_DQBUF` on the camera device | High |
| ANM-002 | Post-Disarm Camera Access | Camera reads occur after the motors have been commanded to disarm (MAVLink `MAV_CMD_COMPONENT_ARM_DISARM`) | Critical |
| ANM-003 | Resolution/Framerate Mismatch | Frames arrive at a resolution or rate inconsistent with what the manifest declared | Medium |
| ANM-004 | Undeclared Memory Write | Process writes to memory regions not declared in the manifest | High |
| ANM-005 | Burst-Exfil Correlation | A burst of camera reads from an undeclared process is temporally correlated with a blocked outbound firewall event (suggesting a read-then-exfiltrate pattern) | Critical |
| ANM-006 | Firmware Update Access | Camera device accessed during an in-progress firmware update (which should freeze the camera pipeline) | High |

### Access Record Structure

```rust
pub struct V4l2AccessRecord {
    pub timestamp: SystemTime,
    pub pid: u32,
    pub process_name: String,
    pub access_type: String,   // "open" | "read" | "dqbuf"
}
```

The detector maintains a circular buffer of 10,000 access records. ANM-005 correlation uses a time window comparison between the access record timestamps and the firewall event timestamps.

### Integration with Audit

Every detected anomaly is appended to the audit log as an `Anomaly` entry, including the anomaly ID, severity, the classification result, and the process details. Anomalies at Critical severity can also trigger sealed event recording.

---

## 12. Manifest-Aware Firewall

The firewall module generates and applies an nftables ruleset derived from the manifest's `[[network_flows]]` declarations. No outbound connection is permitted unless it appears in the manifest.

### Generated Ruleset Structure

```
table inet chambers {
  chain output {
    type filter hook output priority 0; policy drop;

    # Always allow loopback
    iif lo accept

    # Always allow DNS (needed for hostname resolution in declared flows)
    udp dport 53 accept

    # Allow established/related connections
    ct state established,related accept

    # Declared flows (from manifest [[network_flows]])
    ip daddr 172.20.0.100 tcp dport 8080 accept  # gcs-websocket

    # Log and drop everything else
    log prefix "CHAMBERS_BLOCKED: " drop
  }
}
```

### Rule Application

Rules are applied via `nft -f <generated_rules_file>`. The firewall is activated at mission arm and deactivated after burn. If nftables is unavailable (e.g., in simulation on macOS), the firewall module logs a warning and continues in simulation mode — all traffic is allowed but rule generation is still exercised and logged.

### Firewall Events

Every blocked connection attempt generates a `FirewallEvent`:

```rust
pub struct FirewallEvent {
    pub timestamp:        SystemTime,
    pub direction:        String,      // "outbound"
    pub protocol:         String,      // "tcp" | "udp"
    pub source:           String,      // IP:port
    pub destination:      String,      // IP:port
    pub action:           String,      // "drop"
    pub manifest_flow_id: Option<String>,
    pub process_name:     Option<String>,
    pub process_id:       Option<u32>,
}
```

Firewall events are broadcast on a Tokio channel. The anomaly detector subscribes to this channel to enable ANM-005 burst-exfil correlation.

---

## 13. MAVLink Proxy and Encryption

The MAVLink proxy intercepts the UDP stream between the PX4 flight controller and the upstream radio. In simulation, it binds to the PX4 SITL's MAVLink output port (14540) and re-broadcasts encrypted/forwarded messages.

### Protocol Support

Both MAVLink v1 (0xFE start byte) and MAVLink v2 (0xFD start byte) framing are supported. The parser extracts:

- Magic byte (v1 or v2)
- Payload length
- System ID, Component ID
- Message sequence number
- Message ID (24-bit for v2, 8-bit for v1)
- Raw payload bytes

### Message Classification

Messages are classified by ID into categories that map to manifest `DataCategory` values:

| MAVLink Message ID Range / Specific IDs | Category |
|---|---|
| 0 (HEARTBEAT) | `SystemStatus` |
| 24 (GPS_RAW_INT), 33 (GLOBAL_POSITION_INT) | `PositionNavigation` |
| 30 (ATTITUDE) | `Attitude` |
| 65 (RC_CHANNELS_RAW) | `RcInput` |
| 69 (MANUAL_CONTROL) | `RcInput` |
| 147 (BATTERY_STATUS) | `SystemStatus` |
| 246–255 (STATUSTEXT, etc.) | `SystemStatus` |
| 328 (OBSTACLE_DISTANCE) | `PositionNavigation` |
| Mission message range (40–51) | `MissionData` |
| Motor/actuator messages | `MotorActuator` |

### Data Extraction for Sealed Events

Three values are extracted from specific messages to drive sealed event logic:

- **Position** (from GLOBAL_POSITION_INT, msg_id 33): latitude, longitude, altitude in meters MSL.
- **Battery remaining** (from BATTERY_STATUS, msg_id 147): percentage remaining; low battery can trigger EmergencyLanding sealed event.
- **Obstacle distance** (from OBSTACLE_DISTANCE, msg_id 328): minimum distance across sensor sectors; near-miss detection threshold.

### Encryption

Each received message is encrypted with the session AES-256-GCM key. The AAD is the `EventLabel` for the message: includes source `MAVLink{msg_id, name}`, timestamp, destination `SessionStorage`, sequence number, and manifest rule applied.

---

## 14. Camera Pipeline

### Linux V4L2 (Production)

On Linux, the `V4l2FrameReader` struct opens the camera device via `nix` (raw Linux syscalls), issues the standard V4L2 `VIDIOC_REQBUFS`, `VIDIOC_QUERYBUF`, `VIDIOC_QBUF`, and `VIDIOC_DQBUF` ioctl sequence, and reads YUY2 (YUYV 4:2:2) frames at the configured width/height (default 1920×1080, 30 fps).

Each frame read is:
1. Returned as raw bytes (width × height × 2 bytes for YUY2).
2. Encrypted with the session AES-256-GCM key.
3. Written to `<session_storage>/camera/frame_<index>.enc`.
4. Accompanied by a `CameraFrameMetadata` struct (frame index, timestamp, resolution, format, byte count, device path).
5. An `EventLabel` is attached describing the data flow (source, destination, manifest rule).
6. A `DataFlow` audit entry is appended.

### Simulation (Test Frame Reader)

In simulation (`--v4l2-device test`), the `TestFrameReader` generates synthetic frames: each frame is filled with incrementing byte values (frame `n` → bytes `0`, `1`, ..., `n % 256`, repeating). This allows testing the full encryption pipeline and burn sequence without requiring a real camera device.

### GStreamer Bridge

In the Docker simulation stack, a `v4l2-bridge` container runs a GStreamer pipeline that reads from Gazebo's virtual camera (via ROS image topic) and writes to `/dev/video10`, the v4l2loopback device:

```bash
gst-launch-1.0 rosimagesrc topic=/camera/image_raw \
  ! videoconvert \
  ! video/x-raw,format=YUY2,width=1920,height=1080,framerate=30/1 \
  ! v4l2sink device=/dev/video10
```

If Gazebo is unavailable (no ROS topic), the bridge falls back to a `videotestsrc` ball pattern.

---

## 15. Audit Log and Verification

### Format

The audit log is an NDJSON file (one JSON object per line). Each entry has the form:

```json
{
  "sequence":      42,
  "timestamp":     "2026-04-09T14:20:00.000000000Z",
  "previous_hash": "e3b0c44298fc1c149afb....",
  "session_id":    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "manifest_hash": "sha256:abcd1234...",
  "entry_type": {
    "DataFlow": {
      "source":       "Camera { device: \"/dev/video10\" }",
      "destination":  "SessionStorage",
      "category":     "EoImagery",
      "bytes":        4147200,
      "manifest_rule": "preserve:eo-to-client"
    }
  },
  "signature": "<hex-encoded Ed25519 signature>"
}
```

### Hash Chain

Each entry's `previous_hash` is the SHA-256 hash of the prior entry's full serialized JSON. The genesis entry (sequence 0, `SessionStart`) uses an all-zero previous hash. The chain forms a cryptographic commitment: if any historical entry is altered, all subsequent hashes are invalid.

### Entry Types

| Type | When Appended | Key Fields |
|---|---|---|
| `SessionStart` | Mission arm | manifest_hash, public_key_hex, operator_id, drone_id |
| `DataFlow` | Every encrypted frame/message | source, destination, category, bytes, manifest_rule |
| `SealedEvent` | When sealed event fires | event_type, trigger_source, preservation_scope |
| `Anomaly` | When anomaly detected | pattern, severity, classification, process_details |
| `FirewallEvent` | When connection blocked | direction, protocol, src, dst, process |
| `PreservationExtension` | When sealed event extends retention | event_id, new_expiry |
| `BurnLayer` | After each burn layer | layer_number, layer_name, status, duration_us |
| `SessionEnd` | Mission end | final_state, total_frames, total_messages, sealed_event_count |

### Post-Flight Verification

The `chambers-verify` binary performs full audit log verification:

```bash
chambers-verify --audit /path/to/audit.ndjson --pubkey <hex-encoded-ed25519-pubkey>
```

Verification steps:
1. Parse each NDJSON line into an `AuditEntry`.
2. For each entry, verify the Ed25519 signature against the session public key.
3. For each entry (except genesis), verify `previous_hash` matches SHA-256 of the prior entry.
4. Count entries by type (anomalies, sealed events, burn layers, data flows).
5. Output a `VerifyResult`:

```
Audit verification: PASS
  Total entries:          1,847
  Hash chain:             intact
  All signatures valid:   true
  Sealed events:          2
  Anomalies:              1
  Data flow entries:      1,839
  Burn layers:            6 / 6 passed
```

Exit codes: `0` (verified), `1` (verification failed), `2` (I/O or parse error).

---

## 16. Ground Control Station (GCS)

The GCS is a Python FastAPI server that serves as the remote observer and operator interface. It does not have access to session keys and cannot decrypt session storage — it is a display and archive system, not a data custody system.

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Health check — returns `{"status": "ok"}` |
| POST | `/api/manifest/upload` | Accept a manifest TOML file |
| GET | `/api/manifest/current` | Return the current active manifest metadata |
| GET | `/api/session/current` | Return session state and public key |
| GET | `/api/audit/entries?since=N` | Stream audit entries with sequence ≥ N |
| GET | `/api/audit/verify` | Stub — instructs caller to use chambers-verify CLI |
| WS  | `/ws` | WebSocket for real-time event streaming |

### WebSocket Protocol

The chambers-daemon connects to `/ws` over the declared GCS network flow. It transmits structured JSON events:

```json
{"type": "SessionStart",   "session_id": "...", "public_key_hex": "...", "timestamp": "..."}
{"type": "DataFlow",       "category": "EoImagery", "bytes": 4147200, "manifest_rule": "eo-to-client"}
{"type": "SealedEvent",    "event_type": "GeofenceViolation", "trigger_source": "Position"}
{"type": "Anomaly",        "pattern": "ANM-001", "severity": "High", "process": "rogue.py"}
{"type": "FirewallEvent",  "destination": "203.0.113.42:443", "action": "drop"}
{"type": "BurnComplete",   "all_passed": true, "duration_ms": 1347}
```

Multiple browser/operator clients can connect to `/ws` simultaneously; the GCS broadcasts all events to all connected clients.

---

## 17. Simulation Environment

The simulation environment replaces all physical hardware with software equivalents, allowing the complete system to be exercised on a single laptop.

### Docker Compose Services

| Service | Image | Role |
|---|---|---|
| `px4-sitl` | `px4io/px4-dev-simulation-focal` | Simulated PX4 flight controller, exposes MAVLink on UDP 14540/14550 |
| `chambers-module` | Built from `./chambers` | Companion computer process (chambers-daemon) |
| `v4l2-bridge` | Built from `./bridge` | GStreamer: Gazebo → v4l2loopback /dev/video10 |
| `gcs` | Built from `./gcs` | FastAPI GCS on :8080 |
| `rogue-process` | Built from `./test/rogue` | Adversarial test process (testing profile only) |

### Network Layout

All services share the `chambers_net` Docker bridge network (`172.20.0.0/16`). The manifest firewall's declared flows reference IPs within this network. The chambers-module container is granted `CAP_NET_ADMIN` to program nftables rules.

### Storage

Session storage is mounted on a 2GB `tmpfs` volume (`session_storage`), ensuring all session data lives in RAM and is automatically destroyed if the container stops. This mirrors the companion computer's behavior on hardware (session storage on a RAM-backed filesystem).

### v4l2loopback

A Linux kernel module (`v4l2loopback`) creates a virtual video device at `/dev/video10`. The setup script:

```bash
# scripts/setup_v4l2loopback.sh
modprobe v4l2loopback devices=1 video_nr=10 card_label="ChambersCam" exclusive_caps=1
```

This device is bind-mounted into both the `chambers-module` container (reader) and the `v4l2-bridge` container (writer).

---

## 18. Running the System

### Prerequisites

- Linux host (for v4l2loopback; macOS can run chambers-daemon in test mode)
- Docker and Docker Compose v2
- Rust 1.75 (or use the pinned toolchain via `rustup`)
- Python 3.12 (for GCS and tests)
- `v4l2loopback-dkms` or equivalent kernel module

### Quick Start (Simulation)

```bash
# 1. Build all Rust binaries
make build

# 2. Start the simulation stack (sets up v4l2loopback, then docker-compose up)
make sim-up

# 3. Watch GCS events in real time
curl http://localhost:8080/healthz
# Or open /ws in a WebSocket client

# 4. Verify an audit log after the mission completes
make verify AUDIT=./audit_logs/<session_id>.ndjson PUBKEY=<hex>

# 5. Tear down
make sim-down
```

### Manual Daemon Invocation

```bash
./chambers/target/release/chambers-daemon \
  --manifest    manifests/inspection_basic.toml \
  --px4-host    127.0.0.1 \
  --px4-port    14540 \
  --v4l2-device test \
  --gcs-endpoint ws://localhost:8080/ws \
  --storage-dir /tmp/chambers_session \
  --audit-dir   /tmp/chambers_audit \
  --geofence    geofence/restricted_airspace_sample.geojson \
  --auto-takeoff-secs 5 \
  --auto-land-secs    60
```

### Audit Log Verification

```bash
./chambers/target/release/chambers-verify \
  --audit  /tmp/chambers_audit/<session_id>.ndjson \
  --pubkey <hex-encoded-ed25519-public-key>
```

The public key is logged in the `SessionStart` audit entry and transmitted to the GCS at session start. Retrieve it from either source before burn completes.

### Makefile Targets

| Target | Description |
|---|---|
| `make build` | `cargo build --release` for all Rust crates |
| `make test` | `cargo test` + `pytest` for GCS |
| `make lint` | `cargo clippy` + `cargo fmt --check` |
| `make sim-up` | Set up v4l2loopback, start docker-compose stack |
| `make sim-down` | docker-compose down |
| `make sim-test` | Run integration tests with rogue process enabled |
| `make verify` | Run chambers-verify (requires AUDIT= and PUBKEY= args) |
| `make clean` | `cargo clean` + `docker-compose down -v` |

---

## 19. Testing

### Unit Tests (Rust)

126 unit tests distributed across 12 modules:

| Module | Tests | What They Cover |
|---|---|---|
| `crypto` | 12 | Key generation, encrypt/decrypt round-trips, signature verification, nonce uniqueness, zeroise |
| `manifest` | 30 | TOML parsing, 8 validation rules, preservation evaluation, stakeholder key decoding |
| `session` | 8 | State machine transitions, illegal transition panics, storage initialization |
| `audit` | 10 | Entry append, hash chain construction, verification against tampered entries |
| `burn` | 7 | Layer sequencing, Layer 2 key zeroise verification, Layer 6 assertions |
| `mavlink_proxy` | 5 | v1/v2 frame parsing, classification by message ID, position extraction |
| `camera` | 5 | TestFrameReader output, pipeline encryption, metadata construction |
| `v4l2_monitor` | 10 | ANM-001 through ANM-006 detection, allowlist pass-through |
| `firewall` | 8 | Rule generation from manifest flows, declared vs. undeclared evaluation |
| `sealed_events` | 12 | Geofence loading, point-in-polygon checks, event deduplication, 5 event types |
| `types` | 5 | SessionId display, DataCategory round-trips, StakeholderRole ordering |

```bash
cd chambers && cargo test
```

### Integration Tests (Python + Docker Compose)

Integration tests use pytest with the `conftest.py` fixtures that spin up the full docker-compose stack (excluding the rogue process), exercise the GCS API, and assert audit log content.

```bash
make sim-test
```

### Adversarial Tests (Rogue Process)

The `rogue.py` process runs inside a Docker container and attempts to read from `/dev/video10` without being declared in the manifest. Three modes:

```bash
# Continuous read — triggers ANM-001
python rogue.py --mode continuous --device /dev/video10 --duration 30

# Burst read correlated with firewall block — triggers ANM-005
python rogue.py --mode burst --device /dev/video10 \
  --burst-count 50 --burst-interval 2 \
  --exfil-host 203.0.113.42 --exfil-port 4444

# Post-disarm read — triggers ANM-002
python rogue.py --mode post-disarm --device /dev/video10 --disarm-signal /tmp/disarm_signal
```

All three modes should produce audit log entries with corresponding anomaly patterns when run against an active Chambers session.

---

## 20. Technology Stack

### Rust (chambers-core, chambers-daemon, chambers-verify)

| Crate | Version | Purpose |
|---|---|---|
| `ring` | 0.17 | AES-256-GCM encryption/decryption |
| `ed25519-dalek` | 2.1 | Ed25519 keypair generation and signing |
| `x25519-dalek` | 2.0 | X25519 ECDH key agreement |
| `sha2` | 0.10 | SHA-256 for hash chain and manifest hashing |
| `hkdf` | 0.12 | HKDF-SHA256 key derivation |
| `zeroize` | 1.7 | Cryptographic memory zeroing with ZeroizeOnDrop |
| `aes-gcm` | 0.10 | AES-256-GCM AEAD (via ring) |
| `tokio` | 1.x | Async runtime for daemon main loop |
| `clap` | 4.x | CLI argument parsing |
| `serde` / `serde_json` | 1.x | JSON serialization for audit log |
| `toml` | 0.8 | Manifest TOML parsing |
| `thiserror` | 1.x | Error type derivation |
| `ctrlc` | 3.x | Signal handler for graceful shutdown |
| `nix` | 0.27 | Linux V4L2 ioctl access |
| `geo` | 0.27 | Geospatial point-in-polygon computation |
| `geojson` | 0.24 | GeoJSON parsing for geofence zones |
| `base64` | 0.21 | Base64 decoding for stakeholder public keys |
| `hex` | 0.4 | Hex encoding for public key display |
| `rand` | 0.8 | Cryptographically secure random number generation |
| `chrono` | 0.4 | Timestamp formatting |

### Python (GCS)

| Package | Purpose |
|---|---|
| `fastapi` | Web framework |
| `uvicorn` | ASGI server |
| `websockets` | WebSocket protocol support |
| `pydantic` | Request/response model validation |
| `PyNaCl` | Ed25519 signature verification (audit stub) |
| `toml` | Manifest TOML parsing |
| `httpx` | Async HTTP client for tests |
| `pytest` | Test runner |
| `pytest-asyncio` | Async test support |

### Simulation Infrastructure

| Tool | Purpose |
|---|---|
| PX4 SITL | Simulated flight controller, generates realistic MAVLink streams |
| Gazebo | 3D physics simulation, provides virtual camera feeds |
| GStreamer | Video pipeline: Gazebo ROS topic → v4l2loopback |
| v4l2loopback | Linux kernel module creating virtual `/dev/video10` |
| Docker Compose | Multi-container orchestration |
| nftables | Manifest-aware network filtering (Linux netfilter) |

---

## 21. Threat Model

### In-Scope Threats

| Threat | Mitigation |
|---|---|
| Rogue process reads camera buffer in-flight | ANM-001 anomaly detection; sealed event; audit entry |
| Operator edits manifest post-arm to extend retention | Manifest hash committed in every audit entry; tampering detectable |
| Operator delays burn to exfiltrate data | Session state machine enforces burn at landing; no API to extend |
| Stakeholder spoofs another stakeholder's public key | Public keys committed to manifest hash before arm; no modification post-arm |
| Post-burn forensic recovery of session ciphertext | Layer 3 overwrites ciphertext with random bytes before deletion |
| Firmware update replaces burn logic | Sealed event + ANM-006 alert; TPM-backed binary attestation (future work) |
| In-flight cellular exfiltration | Manifest-aware firewall blocks undeclared network flows; ANM-005 correlation |
| Audit log tampering | Hash chain + Ed25519 signatures; tamper evident to anyone with the public key |
| Session key extraction from memory | ZeroizeOnDrop + explicit zeroise at Layer 2; no key persistence beyond session |

### Out-of-Scope (Explicit Non-Guarantees)

- **Physical access to companion computer during flight**: An attacker with physical access to the running SBC can extract keys from RAM (cold boot, DMA). TPM-backed key sealing is a planned mitigation.
- **GCS key storage**: The GCS receives and stores the session public key. Compromise of the GCS after mission end allows audit log verification but not decryption of burned data.
- **Stakeholder private key security**: If a stakeholder's private key is compromised, their preserved data is compromised. The system does not manage stakeholder private keys.
- **Retention enforcement on stakeholder systems**: Once preserved data is delivered, retention period enforcement is the stakeholder's responsibility. The audit log records the obligation, not compliance.

---

## 22. Regulatory Mapping

| Regulation | Requirement | Chambers Mechanism |
|---|---|---|
| 14 CFR Part 107 (FAA sUAS) | Remote ID broadcast | Manifest `remote_id = true` requirement; `RemoteId` data category with `retention_days = "0"` (broadcast-only) |
| FAA Order 8040.6B | UAS safety risk management | Sealed events for near-miss, emergency landing, geofence violations |
| GDPR Article 5(1)(e) | Storage limitation | Manifest `retention_days` per stakeholder; default burn enforces minimization |
| GDPR Article 25 | Privacy by design | Default action is burn; preservation is the exception, not the default |
| NIST SP 800-88 | Media sanitization | Layer 3 overwrite (multiple passes of random bytes) + Layer 4 memory zeroing |
| ICAO Annex 2 | Airspace compliance | Geofence-based AirspaceIncursion sealed events for Class B/C/restricted zones |

---

## 23. Data Categories Reference

| Category | Description | Typical Source |
|---|---|---|
| `ThermalImagery` | Infrared/thermal camera frames | FLIR or Lepton sensor |
| `EoImagery` | Electro-optical (visible) camera frames | V4L2 camera |
| `FlightTelemetry` | Position, attitude, velocity, motor state | MAVLink |
| `RemoteId` | FAA Remote ID broadcast data | MAVLink / RID module |
| `LidarPointCloud` | LiDAR scan data | Serial/UDP LiDAR sensor |
| `MotorActuator` | Motor commands and actuator states | MAVLink (ESC, servo messages) |
| `RcInput` | Pilot RC stick inputs | MAVLink RC_CHANNELS_RAW |
| `SystemStatus` | Battery, heartbeat, error codes | MAVLink |
| `MissionData` | Waypoints, mission plan | MAVLink mission protocol |
| `AuditLog` | Chambers audit log itself | chambers-daemon |
| `AnomalyLog` | Detected anomaly records | AnomalyDetector |
| `Custom` | User-defined categories | Operator-specified in manifest |

---

## 24. Anomaly Pattern Reference

| Pattern | Description | Detection Method | Default Severity |
|---|---|---|---|
| ANM-001 | Undeclared V4L2 Access | Process name/PID not matching daemon PID or system allowlist accesses camera device | High |
| ANM-002 | Post-Disarm Camera Access | Camera reads recorded after motor disarm signal (`set_post_disarm()` called) | Critical |
| ANM-003 | Resolution/Framerate Mismatch | Incoming frame dimensions or arrival rate differ from manifest-declared values by >10% | Medium |
| ANM-004 | Undeclared Memory Write | Process writes to virtual address range not declared in memory map (kernel-space detection) | High |
| ANM-005 | Burst-Exfil Correlation | ≥10 undeclared camera reads within a 500ms window, overlapping with a `CHAMBERS_BLOCKED` firewall event within ±2 seconds | Critical |
| ANM-006 | Firmware Update Camera Access | Camera device accessed while a firmware update (`MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN`) is in progress | High |
