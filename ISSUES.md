# Chambers for UAS — Implementation Issue List

**Exhaustive issue breakdown for implementation**
**Date:** 2026-04-08
**Reference:** `PRD.md`, `chambers_uas_position_paper.pdf`

---

## Issue Numbering Convention

- `INFRA-NNN` — Simulation infrastructure, build system, Docker, CI
- `CRYPTO-NNN` — Cryptographic engine, key management, zeroisation
- `MANIFEST-NNN` — Manifest grammar, parsing, validation, evaluation
- `SESSION-NNN` — Session lifecycle state machine
- `BURN-NNN` — Burn engine (all 6 layers)
- `MAV-NNN` — MAVLink encryption proxy
- `CAM-NNN` — Camera pipeline encryption
- `V4L2-NNN` — V4L2 anomaly detection
- `FW-NNN` — Manifest-aware firewall
- `SEALED-NNN` — Sealed event engine
- `AUDIT-NNN` — Audit log system
- `GCS-NNN` — Ground control station interface
- `TEST-NNN` — Integration test scenarios
- `DOC-NNN` — Documentation (only where required for usability)

**Priority levels:** P0 = blocks other work, P1 = core functionality, P2 = important but not blocking, P3 = nice-to-have

**Dependency notation:** `blocked_by: [ISSUE-ID]` means this issue cannot start until the listed issue is complete.

---

## Phase 0: Infrastructure & Scaffolding

### INFRA-001: Initialize Rust workspace
**Priority:** P0
**Blocked by:** None
**Description:**
Create the Rust workspace with three crates:
- `chambers-core` (library)
- `chambers-daemon` (binary)
- `chambers-verify` (binary)

**Acceptance criteria:**
- `cargo build` succeeds for all three crates
- `cargo test` runs (no tests yet, but harness works)
- Workspace-level `Cargo.toml` with shared dependency versions
- `.cargo/config.toml` with any needed build flags
- `rust-toolchain.toml` pinning stable Rust version

**Files to create:**
```
chambers/Cargo.toml
chambers/chambers-core/Cargo.toml
chambers/chambers-core/src/lib.rs
chambers/chambers-daemon/Cargo.toml
chambers/chambers-daemon/src/main.rs
chambers/chambers-verify/Cargo.toml
chambers/chambers-verify/src/main.rs
chambers/.cargo/config.toml
chambers/rust-toolchain.toml
```

---

### INFRA-002: Add all Rust dependencies to Cargo.toml
**Priority:** P0
**Blocked by:** INFRA-001
**Description:**
Add all crate dependencies listed in PRD Section 17.1 to the workspace. Use workspace-level dependency declarations for version consistency.

**Dependencies to add to `chambers-core`:**
```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
mavlink = { version = "0.13", features = ["ardupilotmega"] }
ring = "0.17"
ed25519-dalek = { version = "2", features = ["rand_core"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
zeroize = { version = "1", features = ["derive"] }
v4l = "0.14"
toml = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
nix = { version = "0.29", features = ["fs", "net", "process", "signal"] }
tokio-tungstenite = "0.21"
sha2 = "0.10"
base64 = "0.22"
geo = "0.28"
geojson = "0.24"
thiserror = "1"
rand = "0.8"
```

**Acceptance criteria:**
- `cargo check` passes with all dependencies resolved
- No version conflicts

---

### INFRA-003: Create shared type definitions
**Priority:** P0
**Blocked by:** INFRA-001
**Description:**
Create `chambers-core/src/types.rs` with all shared types referenced across modules. These are the foundational data structures.

**Types to define:**
```rust
// Session types
pub struct SessionId(pub [u8; 16]);
pub struct SessionPublicKey { pub sign: Ed25519PublicKey, pub enc: X25519PublicKey }

// Data flow types
pub enum DataSource { Camera { device: String }, Mavlink { msg_id: u32 }, Lidar, Imu, Gps, RemoteId }
pub enum DataDestination { SessionStorage, Preserved { stakeholder: String }, Burn, GcsForward, Broadcast }
pub struct DataFlow { pub source: DataSource, pub timestamp: DateTime<Utc>, pub bytes: u64, pub metadata: HashMap<String, String> }

// Event label (Section 5.4 of paper)
pub struct EventLabel { pub timestamp: DateTime<Utc>, pub source: DataSource, pub process_id: u32, pub process_name: String, pub byte_count: u64, pub destination: DataDestination, pub manifest_rule: Option<String> }

// Severity levels
pub enum Severity { Low, Medium, High, Critical }

// Time range for sealed event preservation windows
pub struct TimeRange { pub start: DateTime<Utc>, pub end: DateTime<Utc> }

// Data categories (typed, not stringly-typed)
pub enum DataCategory { ThermalImagery, EoImagery, FlightTelemetry, RemoteId, LidarPointCloud, MotorActuator, RcInput, SystemStatus, MissionData, AuditLog }

// Stakeholder role
pub enum StakeholderRole { Operator, Client, Regulator, Manufacturer }
```

**Acceptance criteria:**
- All types implement `Debug`, `Clone`, `Serialize`, `Deserialize` where appropriate
- `SessionId` implements `Display` (hex formatting)
- Types compile and are usable from other modules

---

### INFRA-004: Create error type hierarchy
**Priority:** P0
**Blocked by:** INFRA-001
**Description:**
Create `chambers-core/src/error.rs` with a unified error hierarchy using `thiserror`.

**Error types:**
```rust
#[derive(thiserror::Error, Debug)]
pub enum ChambersError {
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("Burn error: {0}")]
    Burn(#[from] BurnError),
    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("Firewall error: {0}")]
    Firewall(#[from] FirewallError),
    #[error("V4L2 error: {0}")]
    V4l2(#[from] V4l2Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// Plus individual error enums for each module:
pub enum SessionError { InvalidState { current: SessionState, attempted: SessionState }, ManifestNotLoaded, AlreadyArmed, ... }
pub enum CryptoError { KeyGenerationFailed, EncryptionFailed { reason: String }, ZeroisationFailed, ... }
pub enum ManifestError { ParseError { line: usize, message: String }, ValidationError(Vec<String>), MissingRemoteId, InvalidStakeholderKey { id: String }, ... }
pub enum BurnError { LayerFailed { layer: u8, reason: String }, VerificationFailed { layer: u8 }, StorageNotEmpty, KeyNotZero, ... }
pub enum AuditError { HashChainBroken { sequence: u64 }, SignatureInvalid { sequence: u64 }, IoError(std::io::Error), ... }
pub enum FirewallError { NftablesNotAvailable, RuleApplicationFailed { rule: String }, NamespaceError, ... }
pub enum V4l2Error { DeviceNotFound { path: String }, FanotifySetupFailed, EbpfNotAvailable, ... }
```

**Acceptance criteria:**
- All errors implement `std::error::Error` + `Display` + `Debug`
- Conversions between error types via `From` implementations
- No `unwrap()` or `expect()` in library code — all errors propagated

---

### INFRA-005: PX4 SITL + Gazebo Docker image
**Priority:** P0
**Blocked by:** None (parallel with Rust scaffolding)
**Description:**
Create or pull a Docker image that runs PX4 SITL with Gazebo. Verify MAVLink telemetry is accessible from the host/other containers on UDP port 14540.

**Steps:**
1. Test `px4io/px4-dev-simulation-focal` image
2. If Gazebo Harmonic integration is unstable, fall back to Gazebo Classic 11
3. Verify `make px4_sitl gz_x500_cam` or `make px4_sitl gazebo-classic_typhoon_h480` works
4. Verify MAVLink messages visible on UDP 14540 from another container
5. Verify simulated camera publishes image topic

**Acceptance criteria:**
- `docker compose up px4-sitl` starts PX4 SITL with Gazebo
- MAVLink HEARTBEAT received on UDP 14540 from host
- Camera image topic published (ROS2 topic or Gazebo transport)
- Clean shutdown on `docker compose down`

---

### INFRA-006: Gazebo world file for Chambers testing
**Priority:** P1
**Blocked by:** INFRA-005
**Description:**
Create `worlds/chambers_test_world.sdf` with:
1. Ground plane with textured surface (parking lot, rooftop, or solar farm for inspection scenario)
2. At least 3 buildings/structures as inspection targets
3. Camera sensor on the drone (1920x1080, 30fps, RGB)
4. GPS coordinates set to a known test location (e.g., 47.397742, 8.545594 — PX4 default Zurich location)
5. Wind plugin for flight perturbation
6. Geofence boundary visualization (transparent colored walls marking the geofence perimeter)

**Acceptance criteria:**
- World loads in Gazebo without errors
- Drone spawns and can take off
- Camera publishes images with visual content (not black frames)
- GPS reports the configured coordinates

---

### INFRA-007: v4l2loopback setup in Docker
**Priority:** P0
**Blocked by:** INFRA-005
**Description:**
Validate that v4l2loopback works inside a Docker container. This is a known risk (R-01 in PRD).

**Steps:**
1. Install v4l2loopback-dkms on the Linux host (or Linux VM if developing on macOS)
2. `modprobe v4l2loopback devices=2 video_nr=10,11 card_label="ChambersCam0,ChambersCam1" exclusive_caps=1`
3. Verify `/dev/video10` and `/dev/video11` exist
4. Create a Docker container with `--device /dev/video10:/dev/video10`
5. Inside the container, verify `v4l2-ctl --device=/dev/video10 --list-formats-ext` works
6. Write a test frame using `v4l2sink` on host, read it inside container

**macOS workaround:**
- Use a Linux VM (UTM/Parallels/Docker Desktop with Linux VM) as the Docker host
- v4l2loopback must be installed in the VM's kernel, not on macOS

**Acceptance criteria:**
- v4l2loopback device accessible from inside Docker container
- Can write frames from one container (bridge) and read from another (Chambers module)
- If this fails: document the failure and design a fallback (shared memory IPC, Unix socket frame passing)

---

### INFRA-008: GStreamer bridge — Gazebo camera to v4l2loopback
**Priority:** P1
**Blocked by:** INFRA-005, INFRA-007
**Description:**
Create the GStreamer pipeline (or ROS2 node) that reads camera frames from Gazebo and writes them to the v4l2loopback device.

**Option A: GStreamer pipeline (preferred — no custom code):**
```bash
gst-launch-1.0 \
  rosimagesrc topic=/chambers/camera/image_raw ! \
  videoconvert ! \
  video/x-raw,format=YUY2,width=1920,height=1080,framerate=30/1 ! \
  v4l2sink device=/dev/video10
```

**Option B: ROS2 bridge node (if GStreamer rosimagesrc unavailable):**
```python
# bridge/ros2_bridge_node.py
# Subscribe to /chambers/camera/image_raw
# For each frame: convert to YUY2, write to /dev/video10 via v4l2 ioctls
```

**Option C: Direct Gazebo transport (if not using ROS2):**
```bash
# Use gz topic to pipe frames
gz topic -e -t /world/chambers_test/model/x500_cam/link/camera_link/sensor/camera/image \
  | custom_frame_writer --device /dev/video10
```

**Acceptance criteria:**
- Frames from Gazebo camera appear on `/dev/video10`
- Frame rate is stable (within 10% of 30fps)
- Resolution matches configured 1920x1080
- No memory leak over 10-minute run
- Dockerfile for the bridge container builds and runs

---

### INFRA-009: Docker Compose full stack
**Priority:** P1
**Blocked by:** INFRA-005, INFRA-007, INFRA-008
**Description:**
Create `docker-compose.yml` as specified in PRD Section 4.5. All services must start with `docker compose up` and stop cleanly with `docker compose down`.

**Services:**
1. `px4-sitl` — PX4 SITL + Gazebo
2. `chambers-module` — The Rust Chambers daemon
3. `v4l2-bridge` — Gazebo→v4l2loopback bridge
4. `gcs` — Python GCS
5. `rogue-process` — Test-only rogue V4L2 reader (profile: testing)

**Acceptance criteria:**
- `docker compose up` starts all services in correct dependency order
- MAVLink flows from px4-sitl to chambers-module
- Camera frames flow from Gazebo → bridge → v4l2loopback → chambers-module
- GCS WebSocket connects to chambers-module
- `docker compose --profile testing up` additionally starts rogue-process
- `docker compose down` cleans up all containers, networks, volumes
- tmpfs volume for session storage (not persisted to disk)

---

### INFRA-010: Makefile with standard targets
**Priority:** P2
**Blocked by:** INFRA-001, INFRA-009
**Description:**
Create a `Makefile` with:
```makefile
build:        # cargo build --release
test:         # cargo test + pytest
lint:         # cargo clippy + cargo fmt --check
sim-up:       # docker compose up -d
sim-down:     # docker compose down
sim-test:     # docker compose --profile testing up + run integration tests
verify:       # Run chambers-verify on an audit log
clean:        # cargo clean + docker compose down -v
```

---

### INFRA-011: Network namespace setup script
**Priority:** P1
**Blocked by:** None
**Description:**
Create `scripts/setup_netns.sh` that sets up the `chambers_drone` network namespace as specified in PRD Section 4.4.

**Script must:**
1. Create `chambers_drone` namespace
2. Create veth pair `veth-drone` ↔ `veth-host`
3. Assign IPs (10.0.0.2/24 and 10.0.0.1/24)
4. Enable routing + NAT via iptables
5. Be idempotent (safe to run multiple times)
6. Have a `--teardown` flag to clean up

**Acceptance criteria:**
- `ping 10.0.0.1` works from inside the namespace
- `curl http://example.com` works from inside the namespace (through NAT)
- nftables rules can be applied inside the namespace

---

## Phase 1: Cryptographic Foundation

### CRYPTO-001: Implement Ed25519 key generation and signing
**Priority:** P0
**Blocked by:** INFRA-001, INFRA-002
**Description:**
Implement Ed25519 keypair generation, message signing, and signature verification in `chambers-core/src/crypto.rs`.

**Functions:**
```rust
pub fn generate_signing_keypair() -> (SigningPrivateKey, SigningPublicKey);
pub fn sign(private_key: &SigningPrivateKey, message: &[u8]) -> Ed25519Signature;
pub fn verify(public_key: &SigningPublicKey, message: &[u8], signature: &Ed25519Signature) -> bool;
```

**Requirements:**
- Private key type implements `Zeroize` + `ZeroizeOnDrop`
- Uses `OsRng` for generation (not a deterministic PRNG)
- Signing is deterministic (same key + message = same signature) per Ed25519 spec

**Tests:**
- Generate keypair, sign message, verify succeeds
- Verify fails with wrong public key
- Verify fails with tampered message
- Private key is zeroed on drop (test via unsafe memory inspection)

---

### CRYPTO-002: Implement X25519 key agreement
**Priority:** P0
**Blocked by:** INFRA-001, INFRA-002
**Description:**
Implement X25519 keypair generation and Diffie-Hellman key agreement for deriving stakeholder-specific preservation keys.

**Functions:**
```rust
pub fn generate_encryption_keypair() -> (EncPrivateKey, EncPublicKey);
pub fn derive_shared_secret(our_private: &EncPrivateKey, their_public: &EncPublicKey) -> SharedSecret;
```

**Requirements:**
- Private key type implements `Zeroize` + `ZeroizeOnDrop`
- `SharedSecret` implements `Zeroize` + `ZeroizeOnDrop`
- Uses `OsRng`

**Tests:**
- Two keypairs can derive the same shared secret (DH symmetry)
- Different keypairs produce different shared secrets
- Shared secret is 32 bytes

---

### CRYPTO-003: Implement HKDF-SHA256 key derivation
**Priority:** P0
**Blocked by:** CRYPTO-001, CRYPTO-002
**Description:**
Implement HKDF-SHA256 for deriving the session symmetric key and stakeholder preservation keys.

**Functions:**
```rust
pub fn derive_session_key(sign_pub: &SigningPublicKey, enc_pub: &EncPublicKey) -> SessionSymmetricKey;
pub fn derive_preservation_key(shared_secret: &SharedSecret, sign_pub: &SigningPublicKey, stakeholder_id: &str) -> PreservationKey;
```

**Requirements:**
- Session key derivation uses `HKDF-SHA256(ikm=random(32), salt=sign_pub||enc_pub, info="chambers-session-v1")`
- Preservation key uses `HKDF-SHA256(ikm=shared_secret, salt=sign_pub, info="chambers-preserve-v1"||stakeholder_id)`
- Output keys implement `Zeroize` + `ZeroizeOnDrop`

**Tests:**
- Derived key is 32 bytes
- Same inputs produce same output (deterministic)
- Different inputs produce different outputs

---

### CRYPTO-004: Implement AES-256-GCM encryption/decryption
**Priority:** P0
**Blocked by:** CRYPTO-003
**Description:**
Implement bulk data encryption and decryption using AES-256-GCM.

**Functions:**
```rust
pub fn encrypt(key: &SessionSymmetricKey, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub fn decrypt(key: &SessionSymmetricKey, nonce: &Nonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
```

**Nonce construction:**
```rust
// 12-byte nonce = 8-byte monotonic counter || 4-byte random
pub struct NonceGenerator {
    counter: AtomicU64,
}
impl NonceGenerator {
    pub fn next(&self) -> Nonce {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&count.to_be_bytes());
        OsRng.fill_bytes(&mut nonce[8..]);
        Nonce(nonce)
    }
}
```

**Requirements:**
- Nonce never repeats within a session (monotonic counter guarantees this)
- AAD (authenticated additional data) is included in authentication tag but not encrypted
- Decryption fails with `CryptoError` if tag verification fails (tampered ciphertext or AAD)

**Tests:**
- Encrypt then decrypt recovers plaintext
- Decrypt with wrong key fails
- Decrypt with tampered ciphertext fails
- Decrypt with tampered AAD fails
- Decrypt with wrong nonce fails
- Nonce generator never produces duplicates (generate 10,000 nonces, assert all unique)

---

### CRYPTO-005: Implement SessionKeys aggregate with zeroisation
**Priority:** P0
**Blocked by:** CRYPTO-001, CRYPTO-002, CRYPTO-003
**Description:**
Create the `SessionKeys` struct that holds all key material for a session and ensures complete zeroisation on drop.

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    sign_private: SigningPrivateKey,
    sign_public: SigningPublicKey,   // Not secret, but bundled for convenience
    enc_private: EncPrivateKey,
    enc_public: EncPublicKey,        // Not secret
    sym_key: SessionSymmetricKey,
    nonce_gen: NonceGenerator,
}

impl SessionKeys {
    pub fn generate() -> Self;
    pub fn public_keys(&self) -> SessionPublicKey;
    pub fn encrypt_data(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature;
    pub fn derive_preservation_key(&self, stakeholder_pub: &EncPublicKey, stakeholder_id: &str) -> PreservationKey;
}
```

**Tests:**
- Full lifecycle: generate → encrypt → decrypt → sign → verify → drop (zeroised)
- Multiple stakeholder preservation keys are different
- After explicit `zeroize()`, all key bytes are zero

---

### CRYPTO-006: Implement SHA-256 hash chain utilities
**Priority:** P1
**Blocked by:** INFRA-002
**Description:**
Utility functions for the audit log hash chain.

```rust
pub fn hash_entry(entry_bytes: &[u8]) -> [u8; 32];
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), AuditError>;
```

**Tests:**
- Chain of 1000 entries verifies correctly
- Tampering any single entry breaks the chain from that point forward
- Inserting an entry breaks the chain
- Removing an entry breaks the chain

---

## Phase 2: Manifest Engine

### MANIFEST-001: Define manifest TOML schema
**Priority:** P0
**Blocked by:** INFRA-003
**Description:**
Define the complete `serde` deserialization types for the manifest TOML format as specified in PRD Section 7.2.

**Structs:**
```rust
pub struct ManifestFile {
    pub meta: ManifestMeta,
    pub regulatory: RegulatoryConfig,
    pub default: DefaultRule,
    pub stakeholder: Vec<StakeholderDecl>,
    pub preserve: Vec<PreserveRule>,
    pub deny: Option<Vec<DenyRule>>,
    pub network_flow: Option<Vec<NetworkFlow>>,
    pub system_allowlist: Option<SystemAllowlist>,
}

pub struct ManifestMeta {
    pub version: String,
    pub mission_type: String,
    pub operator_id: String,
    pub created: DateTime<Utc>,
    pub manifest_hash: String,
}

pub struct RegulatoryConfig {
    pub remote_id: bool,
    pub jurisdiction: String,
    pub operation_category: String,
}

pub struct DefaultRule {
    pub action: String,  // Must be "BURN"
}

pub struct StakeholderDecl {
    pub id: String,
    pub name: String,
    pub public_key: String,   // Base64-encoded X25519
    pub role: StakeholderRole,
}

pub struct PreserveRule {
    pub id: String,
    pub data_category: String,
    pub sensor: Option<String>,
    pub for_stakeholder: String,
    pub format: Option<String>,
    pub fields: Option<Vec<String>>,
    pub retention: String,
    pub transmission: Option<String>,
    pub justification: String,
}

pub struct DenyRule {
    pub id: String,
    pub data_category: String,
    pub for_stakeholder: String,
    pub justification: String,
}

pub struct NetworkFlow {
    pub id: String,
    pub destination: String,
    pub protocol: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub interface: Option<String>,
    pub data_category: String,
    pub justification: String,
}

pub struct SystemAllowlist {
    pub platform: String,
    pub processes: Vec<String>,
}
```

**Tests:**
- Parse `manifests/inspection_basic.toml` — succeeds
- Parse invalid TOML — returns parse error with line number
- All optional fields correctly default to None

---

### MANIFEST-002: Create example manifest files
**Priority:** P1
**Blocked by:** MANIFEST-001
**Description:**
Create four example manifests in `manifests/`:

1. **`inspection_basic.toml`** — Basic infrastructure inspection. Operator + client. Thermal + EO imagery preserved for client. Telemetry for operator. Remote ID declared.
2. **`inspection_full.toml`** — Full inspection with operator, client, regulator (FAA), manufacturer. Multiple preserve rules, deny rules blocking manufacturer from imagery.
3. **`bvlos_utm.toml`** — BVLOS operation with UTM integration. Network flows declared for UTM provider. Regulator co-signing placeholder.
4. **`test_minimal.toml`** — Absolute minimum valid manifest. One stakeholder, one preserve rule, Remote ID, default BURN.

**Acceptance criteria:**
- All four manifests parse without errors
- All four pass validation (MANIFEST-003)
- Each manifest demonstrates a different real-world scenario

---

### MANIFEST-003: Implement manifest validation
**Priority:** P0
**Blocked by:** MANIFEST-001
**Description:**
Implement all 8 validation rules from PRD Section 7.3.

**Validation rules (each must produce a specific, actionable error):**

1. `remote_id` must be `true` when `jurisdiction = "US"` → `ManifestError::RemoteIdRequired { jurisdiction }`
2. At least one preserve rule with `data_category = "remote_id"` and `transmission = "real_time"` → `ManifestError::MissingRemoteIdPreserveRule`
3. `default.action` must be `"BURN"` → `ManifestError::InvalidDefaultAction { found }`
4. Every `for_stakeholder` references a declared stakeholder → `ManifestError::UndeclaredStakeholder { rule_id, stakeholder_id }`
5. Every stakeholder has a valid 32-byte base64 X25519 public key → `ManifestError::InvalidStakeholderKey { id, reason }`
6. Retention is a valid duration (`Nd`) or `"0"` → `ManifestError::InvalidRetention { rule_id, value }`
7. No `for_stakeholder = "*"` without regulator signature → `ManifestError::WildcardRequiresRegulatorSignature { rule_id }`
8. Conflicting preserve + deny for same (data_category, stakeholder) produces warning → logged, deny wins

**Tests:**
- Valid manifest passes all 8 checks
- One test per validation rule verifying correct error is produced
- Manifest with multiple errors returns ALL errors (not just the first)
- Edge cases: empty stakeholder list, zero preserve rules, stakeholder referenced by deny but not preserve

---

### MANIFEST-004: Implement manifest evaluation engine
**Priority:** P0
**Blocked by:** MANIFEST-003
**Description:**
Implement the `evaluate(&self, flow: &DataFlow) -> ManifestDecision` function that determines how to handle a given data flow.

**Evaluation algorithm:**
```
1. Check sealed events (highest priority — handled by SealedEventEngine, not here)
2. For each deny rule (regulator roles first):
     if rule matches (data_category, stakeholder): return Deny
3. For each preserve rule (regulator roles first, then in manifest order):
     if rule matches (data_category, stakeholder): return Preserve { rule_id, stakeholder, retention }
4. Return Burn (default)
```

**Matching logic:**
- `data_category` comparison is exact string match
- `for_stakeholder` is the stakeholder ID
- A DataFlow is evaluated once per potential stakeholder (the system asks "should this data be preserved for stakeholder X?")

**Tests:**
- Data matching a preserve rule → Preserve
- Data matching a deny rule → Deny
- Data matching both preserve and deny → Deny wins
- Data matching no rules → Burn
- Regulator deny overrides operator preserve
- Rule evaluation respects declared order within same priority tier

---

### MANIFEST-005: Implement manifest hashing
**Priority:** P1
**Blocked by:** MANIFEST-001
**Description:**
Implement canonical TOML serialization and SHA-256 hashing for the manifest.

```rust
impl Manifest {
    pub fn compute_hash(&self) -> [u8; 32];
}
```

The hash is computed over the canonical TOML representation of the manifest with the `manifest_hash` field set to empty string. This ensures the hash is deterministic regardless of TOML formatting.

**Tests:**
- Same manifest content produces same hash
- Changing any field produces different hash
- Hash is 32 bytes (SHA-256)

---

### MANIFEST-006: Implement system allowlist lookup
**Priority:** P1
**Blocked by:** MANIFEST-001
**Description:**
```rust
impl Manifest {
    pub fn is_allowlisted(&self, process_name: &str) -> bool;
}
```

Simple lookup against `system_allowlist.processes`. Case-sensitive exact match.

**Tests:**
- Listed process → true
- Unlisted process → false
- No allowlist section → always false
- Empty allowlist → always false

---

## Phase 3: Session Lifecycle

### SESSION-001: Implement session state machine
**Priority:** P0
**Blocked by:** INFRA-003, INFRA-004
**Description:**
Implement the session state machine from PRD Section 5.2 in `chambers-core/src/session.rs`.

**State enum:**
```rust
pub enum SessionState {
    Idle,
    PreFlight,
    InFlight,
    PostFlight,
    Burning,
    Error(String),
}
```

**State transition validation:**
- Only valid transitions are allowed (see PRD Section 5.3 table)
- Invalid transitions return `SessionError::InvalidState { current, attempted }`

**Tests:**
- Full happy path: Idle → PreFlight → InFlight → PostFlight → Burning → Idle
- Invalid transitions rejected: Idle → InFlight (skipping PreFlight)
- Error state is terminal (no transitions out except reset)
- Concurrent state queries are safe (RwLock on state)

---

### SESSION-002: Implement arm_mission
**Priority:** P0
**Blocked by:** SESSION-001, CRYPTO-005, MANIFEST-003
**Description:**
Implement the `arm_mission` function that transitions from Idle to PreFlight:

1. Load and validate manifest
2. Generate session keypair (`SessionKeys::generate()`)
3. Initialize session-encrypted storage directory
4. Return session public key

```rust
pub fn arm_mission(&mut self, manifest_path: &Path) -> Result<SessionPublicKey, ArmError> {
    self.assert_state(SessionState::Idle)?;
    let manifest = Manifest::load(manifest_path)?;
    let keys = SessionKeys::generate();
    let pub_keys = keys.public_keys();
    let storage = SessionStorage::initialize(&self.storage_root, &keys)?;
    self.state = SessionState::PreFlight;
    self.keys = Some(keys);
    self.manifest = Some(manifest);
    self.storage = Some(storage);
    Ok(pub_keys)
}
```

**Tests:**
- Arm succeeds with valid manifest → state is PreFlight, keys exist
- Arm fails with invalid manifest → state remains Idle, no keys generated
- Arm fails if already armed → SessionError::AlreadyArmed
- Session public key is returned and can be used for verification later

---

### SESSION-003: Implement takeoff/landing detection via MAVLink
**Priority:** P1
**Blocked by:** SESSION-001, MAV-001
**Description:**
Monitor MAVLink `HEARTBEAT` and `EXTENDED_SYS_STATE` messages to detect takeoff and landing.

**Takeoff detection:**
- `HEARTBEAT.base_mode` includes `MAV_MODE_FLAG_SAFETY_ARMED` (bit 7)
- AND `EXTENDED_SYS_STATE.landed_state` transitions from `MAV_LANDED_STATE_ON_GROUND` (1) to `MAV_LANDED_STATE_IN_AIR` (2)

**Landing detection:**
- `EXTENDED_SYS_STATE.landed_state` transitions to `MAV_LANDED_STATE_ON_GROUND` (1)
- AND `HEARTBEAT.base_mode` no longer includes `MAV_MODE_FLAG_SAFETY_ARMED`

**Tests:**
- Simulated MAVLink sequence triggers takeoff detection
- Simulated MAVLink sequence triggers landing detection
- Rapid arm/disarm doesn't cause false takeoff (debounce 1 second)

---

### SESSION-004: Implement session storage initialization and cleanup
**Priority:** P1
**Blocked by:** CRYPTO-004
**Description:**
Create a tmpfs-backed directory for session-encrypted storage. All encrypted data written here during the mission. Cleaned up during burn.

```rust
pub struct SessionStorage {
    root: PathBuf,           // /var/chambers/session/<session_id>/
    telemetry_dir: PathBuf,  // .../telemetry/
    camera_dir: PathBuf,     // .../camera/
    lidar_dir: PathBuf,      // .../lidar/
    metadata_file: PathBuf,  // .../session_meta.json
}

impl SessionStorage {
    pub fn initialize(root: &Path, keys: &SessionKeys) -> Result<Self, io::Error>;
    pub fn write_encrypted(&self, category: &DataCategory, ciphertext: &[u8], label: &EventLabel) -> Result<(), io::Error>;
    pub fn list_files(&self) -> Vec<PathBuf>;
    pub fn total_bytes(&self) -> u64;
    pub fn destroy(&self) -> Result<(), io::Error>;  // Used by burn engine
}
```

**Tests:**
- Initialize creates all directories
- Write stores files in correct category subdirectory
- Files are named with monotonic index for ordering
- Destroy removes all files and directories
- After destroy, `list_files()` returns empty

---

## Phase 4: Audit Log

### AUDIT-001: Implement audit entry serialization
**Priority:** P0
**Blocked by:** INFRA-003, CRYPTO-001
**Description:**
Implement `AuditEntry` and all `AuditEntryType` variants with serde serialization.

Each entry serializes to a single line of JSON (NDJSON format).

**Tests:**
- Serialize → deserialize round-trip for every AuditEntryType variant
- JSON output is single-line (no embedded newlines)
- All timestamps are UTC ISO 8601

---

### AUDIT-002: Implement hash chain construction
**Priority:** P0
**Blocked by:** AUDIT-001, CRYPTO-006
**Description:**
Implement the append-only audit log with hash chain.

```rust
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    current_hash: [u8; 32],
    next_sequence: u64,
    file: File,  // Append-only file handle
}

impl AuditLog {
    pub fn new(path: &Path) -> Result<Self, AuditError>;
    pub fn append(&mut self, entry_type: AuditEntryType, signer: &SigningPrivateKey, manifest_hash: &[u8; 32], session_id: &SessionId) -> Result<u64, AuditError>;
}
```

**append logic:**
1. Construct `AuditEntry` with `sequence = next_sequence`, `previous_hash = current_hash`
2. Serialize entry (without signature)
3. Sign serialized bytes with session signing key
4. Set signature on entry
5. Serialize complete entry to JSON
6. Append JSON line to file, fsync
7. Update `current_hash = SHA-256(serialized_entry)`
8. Increment `next_sequence`

**Tests:**
- Append 100 entries, verify chain is intact
- File is append-only (subsequent appends don't overwrite)
- fsync is called after each append (mock or verify via strace)
- Sequence numbers are gapless: 0, 1, 2, ...

---

### AUDIT-003: Implement audit log verification
**Priority:** P0
**Blocked by:** AUDIT-002
**Description:**
Implement standalone verification that works with only the audit log file and the session public key.

```rust
pub fn verify_audit_log(log_path: &Path, session_public_key: &SigningPublicKey) -> Result<VerifyResult, AuditError>;

pub struct VerifyResult {
    pub total_entries: u64,
    pub all_signatures_valid: bool,
    pub hash_chain_intact: bool,
    pub first_invalid_entry: Option<u64>,
    pub manifest_hash: [u8; 32],
    pub session_start: DateTime<Utc>,
    pub session_end: Option<DateTime<Utc>>,
    pub sealed_events: Vec<SealedEventRecord>,
    pub anomalies: Vec<AnomalyEvent>,
    pub data_flow_summary: DataFlowSummary,
}
```

This is the core post-mission verification capability. Build the `chambers-verify` CLI tool around this function.

**Tests:**
- Valid log verifies successfully
- Log with one tampered entry reports the exact entry number
- Log with removed entry reports broken chain
- Log with inserted entry reports broken chain
- Empty log (no entries) is valid but reports no session
- Log from a different session (wrong public key) fails all signatures

---

### AUDIT-004: Implement audit log GCS sync
**Priority:** P2
**Blocked by:** AUDIT-002, GCS-001
**Description:**
Periodically send new audit entries to the GCS via WebSocket.

```rust
pub async fn sync_to_gcs(log: &AuditLog, ws: &mut WebSocket, last_synced: &mut u64) -> Result<(), SyncError> {
    let new_entries = log.entries_since(*last_synced);
    for entry in new_entries {
        ws.send(serde_json::to_string(&entry)?).await?;
        *last_synced = entry.sequence + 1;
    }
    Ok(())
}
```

**Sync interval:** Every 10 seconds during IN_FLIGHT, immediately on state transitions and sealed events.

**Tests:**
- GCS receives all entries in order
- After reconnection, sync resumes from last_synced (no duplicates, no gaps)
- Sealed events trigger immediate sync (not delayed to next interval)

---

## Phase 5: MAVLink Proxy

### MAV-001: Implement MAVLink UDP connection to PX4 SITL
**Priority:** P0
**Blocked by:** INFRA-002
**Description:**
Establish a UDP connection to PX4 SITL on port 14540 and parse incoming MAVLink messages using the `mavlink` crate.

```rust
pub struct MavlinkConnection {
    socket: UdpSocket,
    parser: MavlinkParser,
}

impl MavlinkConnection {
    pub fn connect(addr: &str) -> Result<Self, io::Error>;
    pub async fn recv(&mut self) -> Result<MavlinkMessage, MavlinkError>;
    pub async fn send(&mut self, msg: &MavlinkMessage) -> Result<(), MavlinkError>;
}
```

**Tests:**
- Connect to PX4 SITL on localhost:14540
- Receive HEARTBEAT messages (PX4 sends these at 1Hz)
- Parse GLOBAL_POSITION_INT, ATTITUDE, SYS_STATUS
- Send COMMAND_LONG (for testing, e.g., request specific message streams)

---

### MAV-002: Implement MAVLink message encryption pipeline
**Priority:** P0
**Blocked by:** MAV-001, CRYPTO-004
**Description:**
For each received MAVLink message:
1. Parse the message type
2. Classify per PRD Section 9.3 table
3. Generate event label
4. Encrypt the raw message bytes with AES-256-GCM (AAD = event label)
5. Write ciphertext to session storage (telemetry directory)
6. Return the event label for audit logging

```rust
pub struct MavlinkEncryptor {
    crypto: Arc<SessionKeys>,
    storage: Arc<SessionStorage>,
    manifest: Arc<Manifest>,
}

impl MavlinkEncryptor {
    pub fn process_message(&self, msg: &MavlinkMessage) -> Result<EventLabel, ProxyError>;
}
```

**Tests:**
- HEARTBEAT message encrypted and stored
- Event label contains correct message ID, timestamp, byte count
- Stored ciphertext can be decrypted with session key
- AAD mismatch causes decryption failure (integrity check)

---

### MAV-003: Implement MAVLink GCS forwarding
**Priority:** P1
**Blocked by:** MAV-002, MANIFEST-004
**Description:**
After encryption, evaluate the manifest to determine which messages should be forwarded to the GCS.

**Logic:**
- For each message type, check if any preserve rule declares it for a GCS-connected stakeholder
- If yes, forward the cleartext message to the GCS WebSocket
- If no, the message is only in session-encrypted storage (will burn)
- Remote ID data is always forwarded (regulatory exception)

**Tests:**
- Messages matching a preserve rule for operator → forwarded to GCS
- Messages not matching any preserve rule → not forwarded
- Remote ID messages always forwarded regardless of other rules

---

### MAV-004: Implement MAVLink sealed event trigger detection
**Priority:** P1
**Blocked by:** MAV-001, SEALED-001
**Description:**
Monitor incoming MAVLink messages for conditions that trigger sealed events, per PRD Section 9.4.

**Triggers to implement:**
1. `GLOBAL_POSITION_INT` → check against geofence database → GEOFENCE_VIOLATION, AIRSPACE_INCURSION
2. `HEARTBEAT` → unexpected disarm → EMERGENCY_LANDING
3. `BATTERY_STATUS` → below failsafe threshold → EMERGENCY_LANDING
4. `STATUSTEXT` → severity EMERGENCY/CRITICAL → EMERGENCY_LANDING
5. `OBSTACLE_DISTANCE` → min distance < safety margin → NEAR_MISS

**Tests:**
- Position inside geofence → GEOFENCE_VIOLATION fires
- Position outside all geofences → no event
- Battery at 10% with failsafe at 15% → EMERGENCY_LANDING fires
- STATUSTEXT with severity EMERGENCY → EMERGENCY_LANDING fires
- Obstacle at 2m with safety margin 5m → NEAR_MISS fires

---

## Phase 6: Camera Pipeline

### CAM-001: Implement V4L2 device reader
**Priority:** P0
**Blocked by:** INFRA-007, INFRA-002
**Description:**
Open a V4L2 device, configure format and framerate, and read frames using memory-mapped buffers.

```rust
pub struct V4l2Reader {
    device: v4l::capture::Device,
    stream: v4l::io::mmap::Stream,
    device_path: String,
    format: V4l2Format,
    frame_count: u64,
}

impl V4l2Reader {
    pub fn open(device_path: &str, width: u32, height: u32, fps: u32) -> Result<Self, V4l2Error>;
    pub fn read_frame(&mut self) -> Result<(Vec<u8>, FrameMetadata), V4l2Error>;
    pub fn close(self) -> Result<(), V4l2Error>;
}
```

**Tests (require v4l2loopback):**
- Open `/dev/video10`, configure 1920x1080@30fps
- Read a frame, verify size matches expected (1920*1080*2 for YUY2)
- Read 100 frames, verify monotonically increasing timestamps
- Close device cleanly

---

### CAM-002: Implement camera frame encryption
**Priority:** P0
**Blocked by:** CAM-001, CRYPTO-004
**Description:**
For each camera frame:
1. Read frame from V4L2 device
2. Generate event label (process ID, timestamp, resolution, byte count, manifest rule)
3. Encrypt frame with AES-256-GCM (AAD = serialized event label)
4. Write ciphertext to session storage (camera directory)
5. Send event label to audit logger

```rust
pub struct CameraPipeline {
    reader: V4l2Reader,
    crypto: Arc<SessionKeys>,
    storage: Arc<SessionStorage>,
    manifest: Arc<Manifest>,
    audit: Arc<AuditLogger>,
}

impl CameraPipeline {
    pub async fn run(&mut self) -> Result<(), CameraError>;  // Runs until stopped
    pub fn stop(&mut self);
    pub fn stats(&self) -> CameraStats;
}
```

**Tests:**
- Pipeline processes 30 frames/second without falling behind
- Each frame has a unique event label
- Encrypted frames can be decrypted with session key
- Stats report correct frame count and byte count

---

### CAM-003: Implement camera preservation extraction
**Priority:** P1
**Blocked by:** CAM-002, MANIFEST-004
**Description:**
During POST_FLIGHT, extract camera frames declared for preservation:
1. Read each encrypted frame from session storage
2. Decrypt with session symmetric key
3. Evaluate manifest to determine which stakeholder(s) get this frame
4. Re-encrypt under stakeholder-specific preservation key
5. Write to preservation partition

**Tests:**
- Frames declared for client stakeholder are extractable
- Frames declared for burn are NOT in preservation output
- Stakeholder A cannot decrypt frames preserved for stakeholder B

---

## Phase 7: V4L2 Anomaly Detection

### V4L2-001: Implement fanotify-based V4L2 device monitoring
**Priority:** P0
**Blocked by:** INFRA-007
**Description:**
Use Linux `fanotify` to monitor all access to the V4L2 device file. This is the Priority 2 detection method from PRD Section 11.2.

```rust
pub struct FanotifyMonitor {
    fd: RawFd,               // fanotify file descriptor
    device_path: String,
    manifest: Arc<Manifest>,
    own_pid: u32,            // To exclude self
    anomalies: Vec<AnomalyEvent>,
}

impl FanotifyMonitor {
    pub fn new(device_path: &str, manifest: &Manifest) -> Result<Self, V4l2Error>;
    pub fn start(&mut self) -> Result<JoinHandle<()>, V4l2Error>;
    pub fn drain_anomalies(&mut self) -> Vec<AnomalyEvent>;
}
```

**fanotify setup:**
```rust
let fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY)?;
fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN | FAN_ACCESS, AT_FDCWD, device_path)?;
```

**Event processing:**
- For each fanotify event, read `/proc/<pid>/comm` and `/proc/<pid>/exe` to identify the process
- If PID == own PID → ignore (declared access)
- If process name in `manifest.system_allowlist` → log, don't flag
- Otherwise → ANOMALY (ANM-001)

**Tests (require v4l2loopback + two processes):**
- Chambers camera pipeline reads device → no anomaly
- Allowlisted process reads device → logged, no anomaly flag
- Unknown process reads device → ANM-001 anomaly generated
- Anomaly includes correct PID, process name, exe path, timestamp
- Multiple concurrent rogue processes → each generates separate anomaly

---

### V4L2-002: Implement eBPF-based V4L2 monitoring (optional enhancement)
**Priority:** P3
**Blocked by:** V4L2-001
**Description:**
If the kernel supports eBPF (5.8+), attach a BPF program to V4L2 ioctl tracepoints for more precise monitoring than fanotify.

**eBPF program (using `aya` crate):**
- Attach to `tracepoint/v4l2/v4l2_qbuf` and `tracepoint/v4l2/v4l2_dqbuf`
- For each event: capture PID, ioctl type, buffer index, timestamp
- Send event to userspace via perf ring buffer
- Userspace classifies the access

**Tests:**
- eBPF program loads without error
- Detects DQBUF calls from rogue process
- Reports correct PID, ioctl type, buffer index
- Falls back to fanotify if eBPF unavailable

---

### V4L2-003: Implement post-disarm camera access detection (ANM-002)
**Priority:** P1
**Blocked by:** V4L2-001, SESSION-003
**Description:**
After the session lifecycle detects motor disarm (landing), any continued V4L2 reads should be flagged as ANM-002.

**Logic:**
- Session state transitions to POST_FLIGHT → set a `post_disarm` flag
- V4L2 monitor checks this flag for all access events
- Any V4L2 read after `post_disarm` AND from a process that is NOT the Chambers preservation extraction → ANM-002

**Tests:**
- Camera reads during IN_FLIGHT by declared pipeline → normal
- Same reads after disarm by rogue process → ANM-002
- Chambers preservation extraction during POST_FLIGHT → not flagged (it's the authorized process)

---

### V4L2-004: Implement burst/network correlation detection (ANM-005)
**Priority:** P2
**Blocked by:** V4L2-001, FW-001
**Description:**
Correlate V4L2 access timestamps with network transmission timestamps from the firewall module.

**Algorithm:**
```
window = 500ms  # Correlation window

For each V4L2 access burst (>3 reads within 1 second):
  For each firewall event within [burst_start - window, burst_end + window]:
    if firewall_event.action == Blocked:
      → ANM-005 (burst reads correlated with blocked network activity) CRITICAL
    if firewall_event.action == Allowed AND firewall_event.destination is undeclared:
      → ANM-005 CRITICAL (should not happen if firewall is working)
```

**Tests:**
- Rogue process reads camera in bursts + attempts network TX → ANM-005 detected
- Rogue process reads camera steadily (no bursts) + no network → no ANM-005
- Normal camera pipeline at 30fps + declared GCS network → no ANM-005

---

### V4L2-005: Implement resolution/framerate mismatch detection (ANM-003)
**Priority:** P2
**Blocked by:** V4L2-001, MANIFEST-001
**Description:**
If V4L2 monitoring detects reads at a different resolution or framerate than declared in the manifest, flag ANM-003.

**Detection:**
- The manifest declares expected resolution (e.g., 1920x1080) and framerate (e.g., 30fps)
- eBPF can capture buffer metadata; fanotify cannot directly (would need `/proc/<pid>/fd` + `v4l2-ctl` to query format)
- If a process opens the device and reconfigures it to 720p/5fps → ANM-003

**Tests:**
- Rogue process opens device at 720p → ANM-003
- Rogue process opens device at declared resolution → ANM-001 (undeclared process, but not resolution mismatch)

---

## Phase 8: Firewall

### FW-001: Implement nftables rule generation from manifest
**Priority:** P1
**Blocked by:** MANIFEST-001, INFRA-011
**Description:**
Generate nftables rules from the manifest's `[[network_flow]]` declarations.

```rust
pub struct NftablesRuleGenerator {
    manifest: Arc<Manifest>,
}

impl NftablesRuleGenerator {
    pub fn generate(&self) -> Result<String, FirewallError>;  // Returns nftables rule text
}
```

**Rule generation logic:**
1. Start with `policy drop` on output chain
2. Allow loopback
3. Allow DNS (UDP/TCP 53) — needed for hostname resolution
4. For each `[[network_flow]]`: generate an allow rule for the declared host:port
5. Log + drop everything else
6. Accept established/related on input chain

**Tests:**
- Manifest with 3 network flows → 3 allow rules + defaults
- Manifest with no network flows → only loopback + DNS allowed
- Generated rules are valid nftables syntax (verify by loading into `nft -c -f -`)

---

### FW-002: Implement nftables rule application
**Priority:** P1
**Blocked by:** FW-001, INFRA-011
**Description:**
Apply generated nftables rules inside the network namespace (or Docker container).

```rust
pub struct Firewall {
    rules: String,
    active: bool,
}

impl Firewall {
    pub fn activate(&mut self) -> Result<(), FirewallError>;   // nft -f <rules>
    pub fn deactivate(&mut self) -> Result<(), FirewallError>; // nft flush ruleset
    pub fn is_active(&self) -> bool;
}
```

**Tests:**
- Activate firewall → undeclared connections blocked
- Deactivate firewall → all connections allowed
- Activate → deactivate → activate → rules still correct

---

### FW-003: Implement firewall event logging
**Priority:** P1
**Blocked by:** FW-002
**Description:**
Capture nftables log events (from the `log prefix "CHAMBERS_BLOCKED:"` rule) and convert them to `FirewallEvent` structs.

**Approach:**
- Use nftables `log group 1` to send blocked packets to NFLOG
- Read NFLOG via `nflog` crate or by reading from `/var/log/nflog` or `journalctl`
- Parse each log line to extract: source IP, dest IP, dest port, protocol, timestamp
- Resolve PID from conntrack or `/proc/net/tcp`

**Tests:**
- Blocked connection generates FirewallEvent
- Allowed connection also logged (separate nftables counter + log)
- FirewallEvent includes correct source, destination, protocol

---

### FW-004: Implement firewall event broadcast for correlation
**Priority:** P2
**Blocked by:** FW-003
**Description:**
Broadcast `FirewallEvent` via `tokio::sync::broadcast` so the V4L2 anomaly detector can subscribe for ANM-005 correlation.

```rust
impl Firewall {
    pub fn event_stream(&self) -> broadcast::Receiver<FirewallEvent>;
}
```

**Tests:**
- V4L2 monitor receives firewall events via broadcast channel
- Events are received in chronological order
- No events lost (broadcast channel sized appropriately)

---

## Phase 9: Sealed Events

### SEALED-001: Implement sealed event type definitions
**Priority:** P0
**Blocked by:** INFRA-003
**Description:**
Define all five sealed event types with their trigger conditions, preservation scopes, stakeholders, and retention periods.

```rust
pub enum SealedEventType {
    AirspaceIncursion,
    NearMiss,
    EmergencyLanding,
    GeofenceViolation,
    PayloadAnomaly,
}

impl SealedEventType {
    pub fn preservation_window(&self) -> TimeRange;      // Relative to trigger time
    pub fn stakeholders(&self) -> Vec<StakeholderRole>;
    pub fn retention(&self) -> Duration;
    pub fn data_categories(&self) -> Vec<DataCategory>;
}
```

**Per-type specifications (from paper Section 6.1):**

| Type | Window | Stakeholders | Retention | Categories |
|---|---|---|---|---|
| AirspaceIncursion | T-30s to T+30s | All | 365d | All telemetry |
| NearMiss | Event window | Operator + Regulator | 365d | All sensor data |
| EmergencyLanding | T-60s to landing | All regulatory | 365d | Full flight log |
| GeofenceViolation | Trigger point | Regulator + UTM | 90d | Position + telemetry |
| PayloadAnomaly | Full context | Operator | 90d | Full context |

**Tests:**
- Each type returns correct preservation window, stakeholders, retention, categories
- Types are exhaustive (no `_` match arm needed)

---

### SEALED-002: Implement geofence database loader
**Priority:** P1
**Blocked by:** INFRA-003
**Description:**
Load GeoJSON airspace boundary files and provide point-in-polygon queries.

```rust
pub struct GeofenceDatabase {
    zones: Vec<AirspaceZone>,
}

pub struct AirspaceZone {
    pub name: String,
    pub airspace_class: String,
    pub floor_ft_msl: f64,
    pub ceiling_ft_msl: f64,
    pub polygon: geo::Polygon<f64>,
}

impl GeofenceDatabase {
    pub fn load(path: &Path) -> Result<Self, io::Error>;
    pub fn check_position(&self, lat: f64, lon: f64, alt_ft_msl: f64) -> Vec<&AirspaceZone>;
}
```

**Tests:**
- Point inside polygon → zone returned
- Point outside all polygons → empty
- Point at polygon boundary → inside (inclusive)
- Altitude check: point below floor → not inside, point above ceiling → not inside

---

### SEALED-003: Implement sealed event engine
**Priority:** P0
**Blocked by:** SEALED-001, SEALED-002
**Description:**
The central engine that receives trigger events from all sources and fires sealed events.

```rust
pub struct SealedEventEngine {
    geofence_db: GeofenceDatabase,
    fired_events: Vec<SealedEventRecord>,
    audit: Arc<AuditLogger>,
}

impl SealedEventEngine {
    pub fn process_mavlink(&mut self, msg: &MavlinkMessage, timestamp: DateTime<Utc>) -> Vec<SealedEventRecord>;
    pub fn process_anomaly(&mut self, anomaly: &AnomalyEvent) -> Option<SealedEventRecord>;
    pub fn process_firewall(&mut self, event: &FirewallEvent) -> Option<SealedEventRecord>;
    pub fn is_sealed(&self, timestamp: DateTime<Utc>, category: &DataCategory) -> bool;
    pub fn fired_events(&self) -> &[SealedEventRecord];
}
```

**Deduplication:**
- Same sealed event type should not fire multiple times for the same continuous condition
- E.g., if the drone stays outside the geofence for 30 seconds, only one GEOFENCE_VIOLATION fires (not one per position update)
- Dedup window: 60 seconds per event type

**Tests:**
- Single geofence violation → one event
- Sustained geofence violation (30s) → still one event (dedup)
- Return inside geofence, then violate again → second event
- Multiple different sealed event types can fire simultaneously
- Sealed event preservation overrides manifest BURN

---

### SEALED-004: Create test geofence GeoJSON
**Priority:** P1
**Blocked by:** None
**Description:**
Create `geofence/test_geofence.geojson` with:
1. A test geofence polygon around the PX4 default location (47.397742, 8.545594) — 500m radius
2. A simulated restricted airspace zone nearby (within 1km, so the simulated drone can fly into it)
3. A TFR (Temporary Flight Restriction) zone

**Acceptance criteria:**
- Valid GeoJSON
- GeofenceDatabase can load it
- point_in_polygon works for test coordinates

---

## Phase 10: Burn Engine

### BURN-001: Implement Layer 1 — Capability Revocation
**Priority:** P0
**Blocked by:** SESSION-004
**Description:**
Close all file descriptors to session-encrypted storage, network sockets, and V4L2 devices.

```rust
pub fn burn_layer_1(session_storage: &SessionStorage, v4l2_device: &str) -> LayerResult;
```

**Steps:**
1. Close session storage file handles
2. Close V4L2 device fd
3. Close any network sockets used for undeclared flows
4. Scan `/proc/self/fd` to verify no open fds point to session files

**Tests:**
- After Layer 1, attempting to read session storage files fails
- `/proc/self/fd` scan confirms no session-related fds

---

### BURN-002: Implement Layer 2 — Cryptographic Erasure
**Priority:** P0
**Blocked by:** CRYPTO-005
**Description:**
Zeroise all key material.

```rust
pub fn burn_layer_2(keys: &mut SessionKeys) -> LayerResult;
```

**Steps:**
1. `keys.sym_key.zeroize()`
2. `keys.enc_private.zeroize()`
3. Verify all key bytes are zero

**Tests:**
- After Layer 2, key material is all zeros
- Attempting to encrypt/sign with zeroised keys fails

---

### BURN-003: Implement Layer 3 — Storage Cleanup
**Priority:** P0
**Blocked by:** BURN-001
**Description:**
Overwrite and delete all session storage files.

```rust
pub fn burn_layer_3(session_storage: &SessionStorage) -> LayerResult;
```

**Steps:**
1. For each file in session storage:
   a. Open file
   b. Write random bytes over entire file content
   c. `fsync()`
   d. Unlink file
2. Remove all session subdirectories
3. Remove session root directory

**Tests:**
- After Layer 3, session storage directory does not exist
- Files cannot be recovered (overwritten with random data)
- No partial files remain

---

### BURN-004: Implement Layer 4 — Memory Zeroing
**Priority:** P0
**Blocked by:** BURN-002
**Description:**
Zeroise all in-memory buffers that held plaintext data.

```rust
pub fn burn_layer_4() -> LayerResult;
```

**Steps:**
1. Zero any plaintext buffers used during preservation extraction
2. Call `madvise(MADV_DONTNEED)` on any mmap'd regions
3. Run `zeroize` on all `Vec<u8>` buffers in scope

**Note:** In Rust with `zeroize`, most of this is automatic via `ZeroizeOnDrop`. This layer explicitly confirms it.

**Tests:**
- After Layer 4, guard buffer contents are zero
- `madvise` called (verify via strace or mock)

---

### BURN-005: Implement Layer 5 — Audit Burn
**Priority:** P1
**Blocked by:** AUDIT-002
**Description:**
The audit log itself is NOT burned. But:
- Audit entries for burned data have their plaintext data references cleared
- The audit log records THAT data was burned, what category, what manifest rule triggered the burn

```rust
pub fn burn_layer_5(audit: &mut AuditLog) -> LayerResult;
```

**Steps:**
1. Append `BurnLayer { layer: 5 }` audit entry
2. Verify audit log is intact (hash chain valid)
3. Ensure no plaintext data is embedded in audit entries (event labels contain metadata, not data)

**Tests:**
- Audit log remains intact after Layer 5
- No sensor data (frame bytes, telemetry values) in audit log
- Burn layer entries added correctly

---

### BURN-006: Implement Layer 6 — Semantic Verification
**Priority:** P0
**Blocked by:** BURN-001, BURN-002, BURN-003, BURN-004, BURN-005
**Description:**
Final verification that all burn layers completed successfully.

```rust
pub fn burn_layer_6(session_storage_root: &Path, keys: &SessionKeys) -> LayerResult;
```

**Checks:**
1. Session storage directory does not exist (or is empty)
2. No `/proc/self/fd` entries point to session files
3. Session private keys are all zero
4. Session symmetric key is all zero
5. No `/proc/self/maps` entries for session mmap regions

If all checks pass → generate `BurnReport`, sign with session signing key (LAST use), then zeroise session signing key.

**Tests:**
- All checks pass after successful burn → BurnReport with all layers PASS
- Intentionally skip Layer 3 → Layer 6 detects non-empty storage → FAIL
- BurnReport signature verifiable with session public key

---

### BURN-007: Implement full burn sequence orchestrator
**Priority:** P0
**Blocked by:** BURN-001 through BURN-006
**Description:**
Orchestrate all 6 layers in sequence, collecting results into a `BurnReport`.

```rust
pub fn execute_full_burn(
    session_keys: &mut SessionKeys,
    session_storage: &SessionStorage,
    v4l2_device: &str,
    audit: &mut AuditLog,
) -> Result<BurnReport, BurnError>;
```

**Error handling:**
- If any layer fails, continue executing remaining layers (best-effort)
- Report per-layer pass/fail in BurnReport
- Return `BurnError` only if Layer 6 verification fails (data may still exist)

**Tests:**
- Full burn sequence on a populated session → all 6 layers PASS
- Emergency burn (skip preservation) → all 6 layers PASS, but no preserved data
- Burn with simulated Layer 3 failure → BurnReport shows Layer 3 FAIL, Layer 6 FAIL

---

## Phase 11: GCS Interface

### GCS-001: Initialize Python GCS project
**Priority:** P1
**Blocked by:** None (parallel with Rust work)
**Description:**
Create the Python project structure for the GCS:

```
gcs/
├── Dockerfile
├── requirements.txt
├── gcs/
│   ├── __init__.py
│   ├── app.py           # FastAPI app
│   ├── api/
│   │   ├── __init__.py
│   │   ├── manifest.py
│   │   ├── session.py
│   │   ├── audit.py
│   │   └── websocket.py
│   ├── verification.py
│   └── models.py
└── static/
    └── index.html
```

**Acceptance criteria:**
- `pip install -r requirements.txt` succeeds
- `uvicorn gcs.app:app` starts
- `GET /health` returns 200

---

### GCS-002: Implement manifest upload and validation endpoint
**Priority:** P1
**Blocked by:** GCS-001
**Description:**
`POST /api/manifest/load` — accepts a TOML manifest file, validates it (basic Python-side validation), returns parsed manifest or errors.

**Tests:**
- Upload valid manifest → 200, parsed JSON response
- Upload invalid TOML → 400 with parse error
- Upload manifest with validation errors → 400 with list of errors

---

### GCS-003: Implement WebSocket real-time feed
**Priority:** P1
**Blocked by:** GCS-001
**Description:**
`ws://host:8080/ws` — accepts WebSocket connections and broadcasts:
- Audit log entries
- Sealed event alerts
- Anomaly alerts
- Session state transitions

**Tests:**
- Client connects, receives messages
- Multiple clients receive same messages
- Client disconnect doesn't crash the server

---

### GCS-004: Implement audit log verification endpoint
**Priority:** P1
**Blocked by:** GCS-001, AUDIT-003
**Description:**
`GET /api/audit/verify` — reads the audit log file and verifies it using the session public key.

Uses `chambers-verify` (Rust CLI) as a subprocess, or reimplements verification in Python using `PyNaCl`.

**Tests:**
- Valid audit log → verification passes, returns summary
- Tampered audit log → verification fails, reports first invalid entry

---

### GCS-005: Implement preservation extension endpoint
**Priority:** P2
**Blocked by:** GCS-003
**Description:**
`POST /api/preserve/extend` — sends a signed preservation extension command to the Chambers module via WebSocket.

**Tests:**
- Valid signed extension → forwarded to Chambers module
- Invalid signature → rejected at GCS level

---

### GCS-006: Implement minimal web UI
**Priority:** P3
**Blocked by:** GCS-003
**Description:**
Single HTML file (`static/index.html`) with inline JavaScript that:
1. Connects to WebSocket
2. Displays session state
3. Shows scrolling audit log
4. Shows sealed event and anomaly alerts

Minimal styling. No framework (vanilla JS). Purpose is demonstration, not production UI.

---

## Phase 12: Integration & Daemon

### DAEMON-001: Wire all modules together in chambers-daemon
**Priority:** P0
**Blocked by:** SESSION-002, MAV-002, CAM-002, V4L2-001, FW-002, SEALED-003, AUDIT-002
**Description:**
`chambers-daemon/src/main.rs` — the main binary that:
1. Parses CLI arguments (manifest path, PX4 host/port, V4L2 device, GCS endpoint)
2. Creates instances of all modules
3. Arms the session
4. Spawns async tasks for:
   - MAVLink proxy
   - Camera pipeline
   - V4L2 anomaly monitor
   - Firewall event logger
   - Sealed event engine
   - Audit log GCS sync
   - Takeoff/landing detection
5. Waits for landing
6. Runs preservation extraction
7. Runs burn sequence
8. Exits

**Acceptance criteria:**
- `chambers-daemon --manifest /path/to/manifest.toml` starts all modules
- Ctrl+C triggers graceful shutdown (emergency burn)
- All modules communicate correctly (shared state via Arc)

---

### DAEMON-002: Implement graceful shutdown
**Priority:** P1
**Blocked by:** DAEMON-001
**Description:**
Handle SIGINT/SIGTERM:
1. Stop all data pipelines
2. If in IN_FLIGHT: transition to POST_FLIGHT, run preservation + burn
3. If in POST_FLIGHT/BURNING: let current operation complete
4. If in PRE_FLIGHT: skip to burn (no data to preserve)

**Tests:**
- SIGINT during IN_FLIGHT → preservation happens, burn completes
- SIGINT during BURNING → burn completes (not interrupted)

---

### DAEMON-003: Implement chambers-verify CLI
**Priority:** P1
**Blocked by:** AUDIT-003
**Description:**
`chambers-verify` CLI tool for post-mission audit log verification.

```
USAGE:
    chambers-verify --audit <AUDIT_LOG_PATH> --pubkey <SESSION_PUBLIC_KEY_HEX>

OUTPUT:
    Verification result:
      Total entries: 1,234
      Hash chain: INTACT
      Signatures: ALL VALID (1,234/1,234)
      Session start: 2026-04-08T10:00:00Z
      Session end:   2026-04-08T10:32:15Z
      Sealed events: 1 (GEOFENCE_VIOLATION at 10:15:32Z)
      Anomalies: 2 (ANM-001 at 10:20:05Z, ANM-005 at 10:20:07Z)
      Data preserved: thermal_imagery (client), flight_telemetry (operator)
      Data burned: eo_imagery, rc_input, motor_actuator
      Burn report: ALL 6 LAYERS PASSED
```

**Tests:**
- Verify a known-good audit log → success output
- Verify a tampered log → failure output with details

---

## Phase 13: Integration Tests

### TEST-001: Scenario 1 — Normal Mission Lifecycle
**Priority:** P0
**Blocked by:** DAEMON-001
**Description:**
End-to-end test of a complete normal mission. See PRD Section 16.1.

**Script:** `test/scenarios/test_normal_mission.py`

**Steps:**
1. Start Docker Compose stack
2. Upload manifest via GCS API
3. Arm mission via GCS API
4. Use MAVSDK Python to command: takeoff → fly waypoint mission (2 min) → land
5. Wait for burn to complete
6. Verify audit log via `chambers-verify`
7. Verify preserved data exists and is decryptable
8. Verify session storage is empty
9. Verify all session keys are zero (inspect process memory if possible, or trust burn report)

**Pass criteria:** All verification steps pass.

---

### TEST-002: Scenario 2 — Geofence Violation
**Priority:** P1
**Blocked by:** DAEMON-001, SEALED-003
**Description:**
See PRD Section 16.2.

**Script:** `test/scenarios/test_geofence_violation.py`

**Steps:**
1. Start stack with test geofence loaded
2. Arm and takeoff
3. Use MAVSDK to command drone outside geofence
4. Verify GEOFENCE_VIOLATION sealed event appears in audit log
5. Verify preserved data includes position + telemetry for regulator + UTM
6. Complete mission, verify sealed event data survives burn

---

### TEST-003: Scenario 3 — Emergency Landing
**Priority:** P1
**Blocked by:** DAEMON-001, SEALED-003
**Description:**
See PRD Section 16.3.

**Script:** `test/scenarios/test_emergency_landing.py`

**Steps:**
1. Arm and takeoff
2. Inject low battery via PX4 SITL parameter: `param set BAT_V_CHARGED 3.5` (forces low reading)
3. Wait for PX4 failsafe to trigger RTL + Land
4. Verify EMERGENCY_LANDING sealed event
5. Verify 60s flight log preserved for regulatory stakeholders

---

### TEST-004: Scenario 4 — Undeclared Camera Access
**Priority:** P0
**Blocked by:** DAEMON-001, V4L2-001
**Description:**
See PRD Section 16.4.

**Script:** `test/scenarios/test_undeclared_camera.py`

**Steps:**
1. Arm and takeoff
2. Start rogue-process container (`docker compose --profile testing up rogue-process`)
3. Rogue process reads `/dev/video10`
4. Wait 10 seconds
5. Stop rogue process
6. Query GCS API for anomalies
7. Verify ANM-001 anomaly with correct PID, process name
8. Verify PAYLOAD_ANOMALY sealed event fired
9. Verify rogue process was NOT killed

---

### TEST-005: Scenario 5 — Post-Disarm Camera Access
**Priority:** P1
**Blocked by:** TEST-004
**Description:**
See PRD Section 16.5.

---

### TEST-006: Scenario 6 — Undeclared Network Connection
**Priority:** P1
**Blocked by:** FW-002, DAEMON-001
**Description:**
See PRD Section 16.6.

**Script:** `test/scenarios/test_undeclared_network.py`

**Steps:**
1. Arm with manifest declaring only GCS network flow
2. During flight, exec into chambers-module container and attempt `curl http://evil.example.com`
3. Verify connection blocked
4. Verify firewall event in audit log
5. Verify PAYLOAD_ANOMALY sealed event

---

### TEST-007: Scenario 7 — Mid-Mission Preservation Extension
**Priority:** P2
**Blocked by:** GCS-005, DAEMON-001
**Description:**
See PRD Section 16.7.

---

### TEST-008: Scenario 8 — Burst/Network Correlation
**Priority:** P2
**Blocked by:** V4L2-004, FW-004
**Description:**
See PRD Section 16.8.

---

## Phase 14: Rogue Process Test Tooling

### ROGUE-001: Implement configurable rogue V4L2 reader
**Priority:** P1
**Blocked by:** INFRA-007
**Description:**
Create `test/rogue/rogue.py` — a Python script that reads from a V4L2 device with configurable behavior.

**CLI arguments:**
```
--device /dev/video10          # V4L2 device path
--mode continuous|burst|post-disarm
--burst-count 10               # Frames per burst (burst mode)
--burst-interval 5             # Seconds between bursts
--resolution 720p|1080p|4k     # Resolution to request
--duration 30                  # Seconds to run
--exfil-host 1.2.3.4           # (Optional) attempt to send frames here
--exfil-port 9999
```

**Modes:**
- `continuous`: Read frames at configured fps until duration expires
- `burst`: Read `burst-count` frames, wait `burst-interval` seconds, repeat
- `post-disarm`: Wait for a signal file, then start reading (simulates post-disarm access)

**Tests:**
- Each mode produces the expected V4L2 access pattern
- `--exfil-host` attempts a TCP connection to the specified host:port

---

### ROGUE-002: Rogue process Dockerfile
**Priority:** P1
**Blocked by:** ROGUE-001
**Description:**
```dockerfile
FROM python:3.12-slim
RUN pip install v4l2 numpy
COPY rogue.py /app/rogue.py
ENTRYPOINT ["python", "/app/rogue.py"]
```

**Acceptance criteria:**
- `docker compose --profile testing run rogue-process --mode continuous --duration 10` runs and reads frames

---

## Dependency Graph Summary

```
INFRA-001 ──► INFRA-002 ──► CRYPTO-001 ──► CRYPTO-005
    │              │              │
    │              ├──► CRYPTO-002 ──► CRYPTO-003 ──► CRYPTO-004
    │              │
    ├──► INFRA-003 ──► MANIFEST-001 ──► MANIFEST-003 ──► MANIFEST-004
    │         │              │
    │         │              ├──► MANIFEST-002 (example manifests)
    │         │              └──► MANIFEST-005, MANIFEST-006
    │         │
    │         └──► SESSION-001 ──► SESSION-002
    │                   │
    │                   └──► SESSION-003, SESSION-004
    │
    └──► INFRA-004

INFRA-005 ──► INFRA-006
    │
    ├──► INFRA-007 ──► INFRA-008 ──► INFRA-009
    │         │
    │         ├──► CAM-001 ──► CAM-002 ──► CAM-003
    │         │
    │         └──► V4L2-001 ──► V4L2-002 (optional)
    │                   │
    │                   ├──► V4L2-003
    │                   └──► V4L2-004

INFRA-011 ──► FW-001 ──► FW-002 ──► FW-003 ──► FW-004

SEALED-001 ──► SEALED-003
SEALED-002 ──┘
SEALED-004 (parallel)

AUDIT-001 ──► AUDIT-002 ──► AUDIT-003 ──► AUDIT-004

BURN-001 through BURN-006 ──► BURN-007

All modules ──► DAEMON-001 ──► TEST-001 through TEST-008
```

## Critical Path

The longest dependency chain (determines minimum implementation time):

```
INFRA-001 → INFRA-002 → CRYPTO-001 → CRYPTO-005 → SESSION-002 → DAEMON-001 → TEST-001
     (1)        (1)         (1)          (1)           (1)          (3)         (2)
                                                                          = ~10 work units
```

**Parallelizable work streams:**
1. **Rust core:** INFRA-001 → CRYPTO → SESSION → MANIFEST → AUDIT → BURN → DAEMON
2. **Simulation infra:** INFRA-005 → INFRA-006 → INFRA-007 → INFRA-008 → INFRA-009 (fully parallel with #1)
3. **GCS:** GCS-001 through GCS-006 (fully parallel with #1 and #2)
4. **Firewall:** INFRA-011 → FW-001 → FW-002 (parallel after MANIFEST-001)
5. **Sealed events:** SEALED-001 → SEALED-003 (parallel after INFRA-003)
6. **Rogue process:** ROGUE-001 → ROGUE-002 (parallel with everything)

---

## Issue Count Summary

| Phase | Count | Priority P0 | Priority P1 | Priority P2 | Priority P3 |
|---|---|---|---|---|---|
| 0: Infrastructure | 11 | 5 | 5 | 1 | 0 |
| 1: Crypto | 6 | 5 | 1 | 0 | 0 |
| 2: Manifest | 6 | 2 | 4 | 0 | 0 |
| 3: Session | 4 | 2 | 2 | 0 | 0 |
| 4: Audit | 4 | 3 | 0 | 1 | 0 |
| 5: MAVLink | 4 | 2 | 2 | 0 | 0 |
| 6: Camera | 3 | 2 | 1 | 0 | 0 |
| 7: V4L2 Anomaly | 5 | 1 | 1 | 2 | 1 |
| 8: Firewall | 4 | 0 | 3 | 1 | 0 |
| 9: Sealed Events | 4 | 2 | 2 | 0 | 0 |
| 10: Burn | 7 | 6 | 1 | 0 | 0 |
| 11: GCS | 6 | 0 | 4 | 1 | 1 |
| 12: Daemon | 3 | 1 | 2 | 0 | 0 |
| 13: Integration Tests | 8 | 2 | 3 | 3 | 0 |
| 14: Rogue Process | 2 | 0 | 2 | 0 | 0 |
| **TOTAL** | **77** | **33** | **32** | **9** | **2** |

---

*End of Issue List*
