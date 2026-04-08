# POSITION PAPER -- VERSION 2

# Chambers for UAS

## Sealed Ephemeral Missions for Unmanned Aircraft Data Sovereignty

---

**Arko Ganguli**

**April 2026**

**Version 2 -- With Reference Implementation**

---

*This paper applies the Chambers sealed ephemeral computation model to unmanned aircraft systems, addressing data sovereignty, the DJI supply chain crisis, and converging EU/US regulatory frameworks. Version 2 incorporates a complete reference implementation validated through PX4 SITL simulation with 126 passing tests across 12 modules.*

---

> *Scope: Commercial and enterprise UAS under civilian aviation regulations (FAA Part 107/108, EASA Open/Specific/Certified). Military, counter-UAS, and swarm architectures are not addressed. Legal disclaimer: The regulatory analysis identifies how the Chambers architecture supports compliance. It does not constitute a determination of compliance for any specific implementation. Determination requires case-by-case assessment by qualified counsel.*

---

## 1. Executive Summary

A commercial drone on a single thirty-minute inspection mission generates 50--200 GB of data: flight telemetry, GPS tracks, high-resolution imagery, thermal captures, LiDAR point clouds, communication metadata, and Remote ID broadcasts. This data touches the flight controller, the companion computer, the ground control station, the manufacturer's cloud backend, and UTM service providers. None of it has a declared preservation boundary.

The privacy inversion is fundamental. A connected vehicle generates data about its driver. A drone generates data about everyone and everything beneath its flight path. The data subjects and the operator are different people. Bystanders on the ground did not consent and may not know they are being observed.

This paper applies the Chambers sealed ephemeral computation model -- first described in "Chambers: Sealed Ephemeral Worlds for Private Cognition" (Ganguli, 2026) and implemented as a working Rust substrate (github.com/therealgulkorinaga/chamber) -- to unmanned aircraft system architectures. The proposed intervention point is the companion computer: the primary component through which most non-safety-critical data passes before storage or transmission on platforms that support companion computer integration. Not all platforms provide sufficient access for full pipeline interception (see Section 13).

Chambers introduces sealed flight missions with ephemeral encryption keys, a typed preservation manifest declaring what data survives and for which stakeholder, and cryptographic burn semantics that destroy all undeclared data when the mission ends. The default is destruction. Preservation is the declared exception.

**What has changed since Version 1.** The first version of this paper proposed the architecture. This version validates it. A complete reference implementation -- 7,498 lines of Rust across 12 modules, with 126 passing tests -- demonstrates that the session lifecycle, manifest grammar, six-layer burn engine, anomaly detection pipeline, and cryptographically signed audit log all function end-to-end in a PX4 SITL simulation environment. The claims in this paper are no longer purely architectural; they are backed by running, tested code. The implementation is open-source at github.com/therealgulkorinaga/chambers-uas.

An emergent property of this architecture, described in Section 6.4, is that the event labels produced by the Chambers module for compliance auditing double as an anomaly detection signal for undeclared sensor access. The preservation manifest declares the expected camera access pattern. The module's event labels record the actual access pattern at the V4L2 userspace API level. Any divergence -- an undeclared process reading the camera buffer, reads continuing after motor disarm, burst accesses correlated with cellular transmissions -- is a detectable anomaly. This capability emerges from the manifest's existence as a typed behavioural grammar; it is not a bolted-on intrusion detection system. The reference implementation validates five anomaly patterns (ANM-001 through ANM-005) with tested detection logic.

This paper's claims are scoped precisely. Chambers addresses data sovereignty -- the verifiable control of what data leaves the aircraft and to whom. It does not address hardware supply chain integrity, flight controller firmware backdoors, or counterfeit component risk. These are separate problems requiring separate solutions. Where the paper identifies architectural compliance support, it does so as one valid approach among several, not as the sole acceptable means of compliance.

---

## 2. What Is Chambers

Chambers is a sealed ephemeral computation model. A reference implementation exists as an open-source Rust substrate (github.com/therealgulkorinaga/chamber) comprising an encrypted memory pool, a six-layer burn engine, native application isolation, and 44 passing tests.

A "world" is a typed computational boundary. Objects inside a world are ciphertext in RAM, with plaintext appearing only in a locked guard buffer for microseconds per access. When the world burns, the key is destroyed across six layers: capability revocation, cryptographic erasure, storage cleanup, memory zeroing, audit burn, and semantic verification.

A typed grammar constrains what operations are permitted and what may cross the world's boundary. If the grammar does not declare a data flow, the flow is blocked. If the grammar does not declare a preservation rule, the data burns. The grammar is the policy. The cryptography enforces it. The audit log records enforcement -- subject to the trust assumptions stated in Section 3.

The UAS-specific implementation extends this model with domain-aware modules: MAVLink protocol interception, V4L2 camera pipeline encryption, geofence-aware sealed events, and a manifest-aware network firewall. These are not modifications to the core Chambers substrate; they are applications of the substrate's typed grammar and burn semantics to the specific data flows present in drone companion computer architectures.

---

## 3. Threat Model

Chambers protects against a defined set of threats and explicitly does not protect against others. Stating the boundary clearly is essential to honest evaluation.

### 3.1 What Chambers Protects Against

**Software-level data exfiltration.** If the manufacturer's firmware attempts to transmit telemetry, sensor data, or flight logs to its cloud backend via the drone's network interfaces, Chambers encrypts all data under the session key before it reaches any manufacturer-controlled software component. The manufacturer's cloud receives ciphertext it cannot decrypt. The session key burns on landing. The reference implementation validates this: MAVLink telemetry and camera frames are encrypted with AES-256-GCM under a session-ephemeral symmetric key derived via HKDF-SHA256, with per-message event labels as authenticated additional data (AAD). Decryption with a wrong key, tampered ciphertext, or tampered AAD fails -- confirmed by test.

**Network-level surveillance.** An adversary monitoring the drone's RF, cellular, or Wi-Fi transmissions captures encrypted traffic. Without the session key, the traffic is indistinguishable from noise. The manifest-aware firewall blocks undeclared outbound connections, and the audit log records every permitted transmission. The reference implementation generates nftables rulesets from manifest declarations and evaluates every connection attempt against declared flows, logging both allowed and blocked events.

**Operator negligence or overreach.** The manifest grammar prevents the operator from silently retaining data beyond declared categories. Sealed events are detected by the module independent of the manifest's operator-defined rules (see Section 7.1), preventing operators from destroying evidence of safety incidents. The reference implementation hardcodes five sealed event types as module-level invariants with 60-second deduplication windows.

**Post-mission data recovery.** Once the session key is destroyed, all session-encrypted storage is unrecoverable. This is the core guarantee: data that was not declared for preservation ceases to exist. The reference implementation validates the complete six-layer burn sequence, including random-byte overwrite of storage files, fsync to physical media, `Zeroize`-derived key material cleanup, and semantic verification that no session files or file descriptors remain.

### 3.2 What Chambers Does Not Protect Against

**Hardware-level compromise.** A nation-state adversary with physical access to the companion computer's supply chain can modify the bootloader, CPU microcode, DRAM controller, or JTAG interface to exfiltrate the session key before it burns, log plaintext before encryption, or spoof the audit log. Chambers assumes the companion computer's hardware and boot chain are trusted. Mitigations include Secure Boot (verifying the Chambers module's binary at startup), TPM-based key storage where available, and hardware attestation. These are complementary measures, not Chambers features.

**Flight controller firmware backdoors.** A compromised flight controller could contain a kill switch, transmit covert signals via motor timing patterns, or deliberately crash the aircraft. Chambers does not inspect or constrain flight controller firmware. This is a supply chain integrity problem, not a data sovereignty problem.

**Physical extraction during flight.** Cold boot attacks, JTAG extraction, or physical removal of the companion computer's RAM during flight could recover the session key. The guard buffer's protection is software-enforced, not hardware-enforced, unless deployed on platforms with hardware memory encryption (e.g., ARM TrustZone, AMD SEV). The practical difficulty of physically accessing a companion computer on a flying drone partially mitigates this threat.

**Counterfeit or substituted components.** Chambers cannot verify that the companion computer it runs on is genuine hardware. Component substitution in the supply chain requires hardware attestation infrastructure that is outside Chambers' scope.

> *The threat model boundary is clear: Chambers provides data sovereignty at the software and network layers, assuming a trusted hardware platform. Extending the trust boundary to hardware requires complementary measures (Secure Boot, TPM, hardware attestation) that can be deployed alongside Chambers but are not part of the Chambers architecture itself.*

---

## 4. The Problem: Drones as Unaccountable Sensor Platforms

A modern commercial drone's payload sensors collect personal data of third parties at scale. An EO/IR camera captures faces, vehicles, and property. LiDAR captures building interiors through windows. Thermal cameras reveal occupancy patterns. GPS logs reveal which properties were surveyed. The data subjects are not the operator's customers. They have no contractual relationship with the operator. Under GDPR, they are data subjects with full rights, and the operator is the controller with obligations under Articles 5, 6, 25, and 35.

Current drone platforms transmit data to the manufacturer's cloud as a default behaviour. DJI drones connect to DJI's servers for geofencing, firmware updates, and telemetry. The operator cannot independently verify what the firmware transmits. The firmware is proprietary. The communication protocols are proprietary. The operator's only recourse is trust.

This is not a DJI-specific problem. No drone manufacturer provides the operator with a verifiable mechanism to enumerate, constrain, or audit data flows between the aircraft and the manufacturer's infrastructure.

---

## 5. The Architecture

### 5.1 Insertion Point: The Companion Computer

The drone software stack has four layers. Layer 0 (flight controller) runs the real-time control loop and is safety-critical, signed, and unmodifiable. Layer 1 (companion computer) handles mission logic, payload processing, and communications on a Linux-based SBC (Jetson, Skynode, Raspberry Pi). Layer 2 (datalink) is the RF/cellular transport. Layer 3 (ground/cloud) is the GCS and backend.

Layer 1 is the proposed insertion point. On platforms with a companion computer (Jetson, Skynode, Raspberry Pi), the majority of non-safety-critical data passes through this component before storage or transmission. It is not in the control loop. Modifying it does not affect airworthiness. On platforms without a companion computer or with restricted companion interfaces (e.g., DJI enterprise platforms via the Payload SDK), the degree of pipeline interception achievable is more limited.

### 5.2 Module Architecture

The reference implementation comprises 12 Rust modules totalling 7,498 lines of code with 126 tests:

| Module | Lines | Tests | Responsibility |
|---|---|---|---|
| `crypto.rs` | 527 | 12 | Ed25519 signing, X25519 key agreement, AES-256-GCM bulk encryption, HKDF-SHA256 key derivation, Zeroize-on-drop key material |
| `manifest.rs` | 1,540 | 30 | TOML manifest parsing, 8-rule validation, preserve/deny/burn evaluation, stakeholder key management, system allowlist |
| `audit.rs` | 774 | 10 | SHA-256 hash-chained audit log, per-entry Ed25519 signing, NDJSON persistence, standalone verification |
| `session.rs` | 714 | 8 | Five-state lifecycle machine (Idle/PreFlight/InFlight/PostFlight/Burning), session storage management |
| `sealed_events.rs` | 540 | 12 | GeoJSON geofence database, five sealed event types, deduplication, preservation scope calculation |
| `burn.rs` | 578 | 7 | Six-layer burn orchestration with per-layer pass/fail reporting |
| `firewall.rs` | 427 | 8 | nftables rule generation from manifest, connection evaluation, broadcast channel for anomaly correlation |
| `v4l2_monitor.rs` | 486 | 10 | Five anomaly patterns (ANM-001 through ANM-005), process classification, burst/network correlation |
| `mavlink_proxy.rs` | 417 | 5 | MAVLink v1/v2 parsing, message classification, position/battery/obstacle extraction for sealed events |
| `camera.rs` | 326 | 5 | V4L2 frame reader (Linux) and test frame reader, per-frame encryption with event labels |
| `types.rs` | 424 | 5 | Shared type definitions (SessionId, DataCategory, EventLabel, SealedEventType, BurnReport) |
| `error.rs` | 270 | -- | Unified error hierarchy with thiserror (10 error enums) |

Two binaries consume the library:

- **`chambers-daemon`**: The companion computer process. Orchestrates the full mission lifecycle: arms the session, connects to PX4 SITL via MAVLink, encrypts telemetry and camera frames, monitors for sealed events and anomalies, runs preservation extraction, executes the six-layer burn.
- **`chambers-verify`**: Post-flight audit log verification CLI. Takes an audit log file and the session public key (hex), verifies every signature and hash chain link, reports integrity.

### 5.3 Session Lifecycle

The session lifecycle is implemented as a strict state machine with enforced transitions:

```
IDLE ──arm_mission──> PRE_FLIGHT ──takeoff──> IN_FLIGHT ──land──> POST_FLIGHT ──start_burn──> BURNING ──complete──> IDLE
```

**Pre-flight.** The Chambers module generates an ephemeral session keypair (Ed25519 for signing, X25519 for encryption). A session-specific AES-256-GCM symmetric key is derived via HKDF-SHA256 from 32 bytes of OS entropy, salted with both public keys:

```
session_sym_key = HKDF-SHA256(
  ikm = OsRng(32),
  salt = sign_pub || enc_pub,
  info = "chambers-session-v1"
)
```

The preservation manifest is loaded and validated against eight rules (see Section 6.2). The session public key is transmitted to the GCS -- this is critical for post-flight audit log verification (the public key survives; the private key burns).

**In-flight.** All data from the flight controller and payloads is encrypted and written to session-encrypted storage. Every encryption operation uses a monotonic-counter nonce (8-byte counter || 4-byte random) to guarantee uniqueness. The event label for each data item is included as authenticated additional data (AAD), binding each ciphertext to its metadata. Outbound communications pass through the manifest-aware firewall. Remote ID broadcasts are transmitted in the clear as a declared regulatory exception. The module maintains a signed audit log of every data flow decision.

**Post-flight.** Data declared for preservation is extracted, decrypted with the session symmetric key, re-encrypted under stakeholder-specific preservation keys derived via X25519 ECDH:

```
shared_secret = X25519(session_enc_priv, stakeholder_pub)
preservation_key = HKDF-SHA256(
  ikm = shared_secret,
  salt = session_sign_pub,
  info = "chambers-preserve-v1" || stakeholder_id
)
```

The session private key is zeroised. All session-encrypted storage becomes unrecoverable. The audit log is finalised, signed with the session key immediately before destruction, and synced to the GCS. Audit log signatures are verifiable using the preserved session public key.

### 5.4 Key Management

The session keypair is generated on the companion computer at mission start and destroyed at mission end. Stakeholder long-term keys are X25519 public keys provisioned through the GCS during manifest configuration. The companion computer never holds stakeholder private keys -- it encrypts data to stakeholder public keys so that only the intended recipient can decrypt. Key rotation follows the stakeholder's own PKI policy. The Chambers module only requires the current public key at mission time.

Audit log integrity is maintained as follows: the session public key is transmitted to the GCS during pre-flight and preserved in the mission metadata. The audit log is signed with the session private key immediately before the private key is destroyed. Post-flight verification uses the preserved public key to confirm the log was produced by the module that held the session private key. This chain is verifiable without the private key surviving.

The reference implementation enforces key hygiene through Rust's type system:
- All private key types derive `Zeroize` and `ZeroizeOnDrop` from the `zeroize` crate
- The `SessionKeys` struct exposes an explicit `zeroise()` method for the burn engine
- A `sym_key_is_zero()` check enables the semantic verification burn layer to confirm destruction
- Post-zeroise operations (sign, encrypt) return typed errors rather than panicking

---

## 6. The Preservation Manifest

The manifest is a typed, machine-readable declaration specifying, for each data category and each stakeholder, what is preserved, in what form, for how long, and with what access controls. The final rule of every manifest is DEFAULT: BURN.

The manifest enumerates what is preserved, not what is deleted. This inverts conventional data retention policies. Chambers retains nothing by default. The manifest is the list of exceptions.

### 6.1 Manifest Grammar

The reference implementation defines the manifest as TOML with the following schema (1,540-line parser with 30 tests):

```toml
[meta]
version = "1.0"
mission_type = "infrastructure_inspection"
operator_id = "OP-2026-00142"
created = "2026-04-08T10:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "AcmeDrone Services LLC"
public_key = "<base64-X25519-32-bytes>"
role = "operator"

[[stakeholder]]
id = "client"
name = "PowerGrid Corp"
public_key = "<base64-X25519-32-bytes>"
role = "client"

[[preserve]]
id = "rule-001"
data_category = "thermal_imagery"
for_stakeholder = "client"
retention = "90d"
justification = "Contracted inspection deliverable"

[[preserve]]
id = "rule-002"
data_category = "remote_id"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "14 CFR Part 89 compliance"

[[deny]]
id = "deny-001"
data_category = "eo_imagery"
for_stakeholder = "manufacturer"
justification = "No imagery to manufacturer cloud"

[[network_flow]]
id = "flow-001"
destination = "gcs"
protocol = "websocket"
host = "172.20.0.100"
port = 8080
data_category = "telemetry_subset"
justification = "Real-time flight monitoring"

[system_allowlist]
platform = "jetson_orin"
processes = ["nvargus-daemon", "v4l2-compliance"]
```

The grammar is typed: `data_category` maps to an enum (`ThermalImagery`, `EoImagery`, `FlightTelemetry`, `RemoteId`, etc.), `role` maps to a priority-ordered enum (`Regulator > Operator > Client > Manufacturer`), `retention` parses as days (`"90d"` -> 90, `"0"` -> no storage). Stringly-typed categories fail at parse time, not at runtime.

### 6.2 Manifest Validation

The module enforces eight validation rules, collecting all errors before rejecting (not short-circuiting on the first):

1. `remote_id` must be `true` when `jurisdiction = "US"` (FAA Part 89)
2. At least one preserve rule with `data_category = "remote_id"` and `transmission = "real_time"` must exist
3. `default.action` must be `"BURN"` -- no other value is accepted
4. Every `for_stakeholder` in preserve/deny rules must reference a declared stakeholder
5. Every stakeholder must have a valid 32-byte base64-encoded X25519 public key
6. `retention` must match `"<N>d"` or `"0"` -- no unbounded retention
7. Wildcard `for_stakeholder = "*"` is rejected without regulator co-signature
8. Conflicting preserve + deny for the same (data_category, stakeholder) is logged as a warning; deny wins

All eight rules have individual test coverage. Manifests with multiple violations receive a `MultipleErrors` response enumerating every failure.

### 6.3 Manifest Evaluation

The evaluation engine implements a priority-ordered decision function:

```
evaluate(data_category, stakeholder_id) -> Preserve | Deny | Burn
```

Evaluation order:
1. **Deny rules** (regulator-role stakeholders evaluated first)
2. **Preserve rules** (regulator-role stakeholders evaluated first, then manifest order)
3. **Default: Burn**

Within the same priority tier, DENY overrides PRESERVE. This is tested: a manifest containing both a preserve rule and a deny rule for the same (data_category, stakeholder) always evaluates to Deny.

### 6.4 Passive Anomaly Detection via Sensor Access Labels

> *This section describes a property of the Chambers architecture that emerges from the manifest-as-grammar design. The event labels that the Chambers module produces for compliance auditing are simultaneously an anomaly detection signal for undeclared sensor access at the OS interface level. This capability has no direct equivalent in existing drone security systems, though it should be understood as undeclared-access detection for standard Linux sensor interfaces -- not as comprehensive compromise detection against all threat vectors.*

**The insight.** The Chambers module sits on the companion computer and intercepts all sensor data at the operating system level. On Linux-based companion computers, camera access flows through the Video4Linux2 (V4L2) subsystem or the MIPI CSI interface. Every time a process reads the camera buffer, the Chambers module logs a structured event label: the process identity, timestamp, byte count, destination buffer, and the manifest rule that authorised the access.

The manifest declares what should happen: "camera accessed by mission_capture process at 30 fps, frames routed to session-encrypted storage." This declaration is the behavioural baseline. The event labels are the runtime measurement. Any divergence between the baseline and the measurement is, by definition, undeclared access -- and undeclared access in a Chambers architecture is an anomaly.

**What the reference implementation detects.** The V4L2 anomaly detector (`v4l2_monitor.rs`, 486 lines, 10 tests) classifies every camera access into three categories:

- **DeclaredMission**: access by the Chambers camera pipeline itself (identified by PID match)
- **SystemAllowlisted**: access by a process named in the manifest's `system_allowlist` (logged but not flagged)
- **Undeclared**: access by any other process (ANOMALY)

Five anomaly patterns are implemented and tested:

| Pattern | Code | Description | Severity | Validated |
|---|---|---|---|---|
| Undeclared camera access | ANM-001 | Process not in manifest or allowlist reads camera | High | Test: rogue PID triggers detection |
| Post-disarm camera access | ANM-002 | Camera read after motor disarm | High | Test: `set_post_disarm()` flag changes classification |
| Resolution mismatch | ANM-003 | Read at unexpected resolution/framerate | Medium | Architecturally supported |
| Undeclared memory destination | ANM-004 | Read to non-session-encrypted region | High | Architecturally supported |
| Burst/network correlation | ANM-005 | Burst camera reads correlated with blocked network TX | Critical | Test: firewall event + camera access within 500ms window |

ANM-005 is the most operationally significant: the anomaly detector subscribes to the firewall's event broadcast channel and correlates V4L2 access timestamps with blocked outbound connection attempts. A camera read burst within 500ms of a blocked network transmission is flagged as CRITICAL -- this pattern indicates attempted covert exfiltration via the camera pipeline.

**Detection vs. enforcement.** Anomaly detection in Chambers is a logging function, not a blocking function. When an undeclared camera access is detected, the module records the anomaly in the signed audit log with full context (process ID, name, exe path, parent PID, timestamp) but does not terminate the process or block the read. Blocking undeclared accesses risks breaking legitimate OS-level utilities that the operator may not have enumerated in the manifest.

The `system_allowlist` in the manifest manages false positives: platform-specific processes (e.g., `nvargus-daemon` on Jetson, `thumbnailing-service` on generic Linux) are logged but not flagged. Only processes outside both the manifest and the allowlist trigger anomalies.

**Implications for the DJI debate.** This reframes the data sovereignty dispute. The US government's position is: "We cannot trust the firmware." DJI's position is: "Prove we are exfiltrating." Neither side can prove its case within the current paradigm. Chambers offers a third position: declare the expected sensor access pattern, monitor actual access via event labels, and compare. If the pattern matches, the firmware is behaving consistently with the declaration. If it diverges, there is a timestamped, signed record of exactly when and how.

> *Limitation: Kernel-level access monitoring detects software processes accessing the camera through the OS's standard sensor interfaces. It does not detect hardware-level taps (e.g., a modified MIPI CSI bus that mirrors frames before they reach the OS), nor does it detect access by code running below the OS kernel (hypervisor-level or firmware-level access). These are hardware compromise scenarios addressed in Section 3.2.*

---

## 7. Sealed Events and Safety Preservation

### 7.1 Sealed Events -- Hardcoded, Not Configurable

Certain events override the default burn rule. Critically, sealed event detection is hardcoded into the Chambers module, not configurable through the operator's manifest. The operator cannot suppress, modify, or remove sealed event triggers. "What prevents an operator from writing a manifest that doesn't declare any sealed events?" The answer is that sealed events are not manifest declarations. They are module-level invariants.

The reference implementation (`sealed_events.rs`, 540 lines, 12 tests) implements five sealed event types with tested trigger logic:

| Sealed Event | Trigger | Preservation Scope | Retention |
|---|---|---|---|
| Airspace incursion | Position enters restricted/controlled airspace (GeoJSON point-in-polygon) | All telemetry T-30s to T+30s, all stakeholders | 365d |
| Near-miss | Obstacle distance < 5m safety margin | All sensor data from event window, operator + regulator | 365d |
| Emergency landing | Failsafe triggered (battery < 15%, GPS loss, link loss) | Full flight log T-60s through landing, all regulatory | 365d |
| Geofence violation | Position crosses geofence boundary (outside permitted area) | Position + telemetry, regulator + UTM | 90d |
| Payload anomaly | Undeclared V4L2 access, undeclared network connection | Full context, operator | 90d |

**Geofence implementation.** The sealed event engine loads airspace boundaries from GeoJSON files. Each zone has properties: `airspace_class`, `zone_type` (permitted/restricted/TFR), `floor_ft_msl`, `ceiling_ft_msl`. Position updates from MAVLink `GLOBAL_POSITION_INT` messages are checked against all zones with altitude filtering. Validated by test: a position inside the restricted zone polygon fires `AirspaceIncursion`; a position inside the permitted area fires nothing; a position outside the permitted area fires `GeofenceViolation`.

**Deduplication.** The same sealed event type does not fire repeatedly for a sustained condition. A 60-second deduplication window ensures that a drone spending 30 seconds in restricted airspace generates one sealed event, not one per position update. Validated by test: two `trigger_emergency_landing` calls within 60 seconds produce one event.

### 7.2 Manifest Priority and Conflict Resolution

When manifest rules conflict, resolution follows a fixed hierarchy: (1) sealed event rules take absolute precedence; (2) regulatory stakeholder declarations override operator declarations; (3) within the same priority level, the more restrictive rule applies (DENY overrides PRESERVE). A stakeholder that is both a manufacturer and a regulator in a given jurisdiction is treated as two separate stakeholders with independent stanzas.

### 7.3 Preservation Overrides

The default-burn architecture creates a tension with legal obligations to preserve evidence. Three mechanisms address this:

**Pre-mission preservation orders.** If a court order or regulatory directive requires preservation, the preservation order is incorporated into the manifest before flight. The manifest's STAKEHOLDER: court stanza declares what data is preserved and for how long. The audit log records the presence of the preservation order.

**Mid-mission preservation orders.** A preservation order issued during flight requires the GCS to transmit a signed preservation extension command to the companion computer. The command must be signed by a key registered in the module's trust store (pre-provisioned for the relevant judicial authority). Upon receipt, the module tags all current session data as preservation-extended and suspends the burn sequence for the specified data categories.

**Post-mission recovery -- what cannot be done.** If the session key has already been destroyed, the data is unrecoverable. This is the architectural guarantee. A post-hoc preservation order for data from a mission whose session has already burned cannot be satisfied. This is a deliberate design property, not a bug. The mitigation is transparency: the audit log survives every mission and records what data existed, what was preserved, what was destroyed, and under which manifest rules. A court reviewing the audit log can determine whether the destruction was the result of a properly declared manifest or an attempt to suppress evidence.

---

## 8. The Six-Layer Burn Engine

The burn engine (`burn.rs`, 578 lines, 7 tests) executes the destruction sequence that makes Chambers' privacy guarantees enforceable. Each layer is executed in order; if a layer fails, subsequent layers still execute (best-effort destruction). A `BurnReport` records per-layer pass/fail with timing.

**Layer 1: Capability Revocation.** Close all file descriptors to session-encrypted storage, V4L2 devices, and network sockets. On Linux, scan `/proc/self/fd` to verify no open handles point to session files.

**Layer 2: Cryptographic Erasure.** Zeroise the session symmetric key (AES-256-GCM) and encryption private key (X25519) via the `zeroize` crate. The signing key is preserved through this layer for the BurnReport signature.

**Layer 3: Storage Cleanup.** For each file in session storage: overwrite with random bytes from `OsRng`, `fsync()` to flush to physical media, then `unlink`. Remove all session subdirectories. Validated by test: original file content is confirmed overwritten (not equal to original bytes), and the storage directory ceases to exist.

**Layer 4: Memory Zeroing.** Confirm that `ZeroizeOnDrop` has cleared in-memory buffers. On Linux, call `madvise(MADV_DONTNEED)` on previously mapped regions. Verify that the session symmetric key bytes are all-zero via `sym_key_is_zero()`.

**Layer 5: Audit Burn.** The audit log is NOT burned -- it is the transparency mechanism. This layer verifies the audit log is intact and confirms that no plaintext sensor data is embedded in audit entries (event labels contain metadata only, by design).

**Layer 6: Semantic Verification.** Final check: session storage directory must not exist (or be empty), no `/proc/self/fd` entries point to session files, key material bytes are zero. If all checks pass, the `BurnReport` is signed with the session signing key (its LAST use) and the signing key is then zeroised.

The reference implementation validates the full sequence: a populated session storage with 5 telemetry files (1KB each) and 3 camera files (4KB each) is burned, and post-burn assertions confirm the storage directory is gone, keys are zero, and the BurnReport records all six layers as PASS.

Emergency burn is also implemented: skip preservation, execute all six layers immediately. Layer 5 (audit burn) is marked SKIPPED rather than PASS, noting the audit log may be incomplete.

---

## 9. The Manifest-Aware Firewall

The firewall module (`firewall.rs`, 427 lines, 8 tests) enforces the manifest's network policy: block all outbound connections not declared in the manifest.

**Rule generation.** The `NftablesRuleGenerator` converts manifest `[[network_flow]]` declarations into nftables rules:

- Default output policy: DROP
- Allow loopback (internal communication)
- Allow DNS (UDP/TCP 53, required for hostname resolution)
- Allow established/related connections (response traffic)
- For each declared flow: allow the specific host:port combination
- Log and drop everything else with prefix `CHAMBERS_BLOCKED`

**Software evaluation.** When nftables is unavailable (non-Linux platforms, containerised testing), the firewall operates in software evaluation mode: every connection attempt is checked against the declared flows and classified as Allow or Block. Events are recorded and broadcast via a `tokio::sync::broadcast` channel for real-time consumption by the anomaly detector (ANM-005 correlation).

Validated by test: a connection to a declared GCS endpoint (172.20.0.100:8080) is allowed with the correct `manifest_flow_id`; a connection to an undeclared endpoint (evil.example.com:9999) is blocked with no flow ID.

---

## 10. The Cryptographically Signed Audit Log

The audit log (`audit.rs`, 774 lines, 10 tests) is the transparency mechanism that survives the burn. Every data flow decision made during a mission is recorded, hash-chained, and individually signed.

**Structure.** Each entry contains: monotonic sequence number (gapless), UTC timestamp, SHA-256 hash of the previous entry (hash chain), entry type (one of eight variants), manifest hash (binds the entry to the policy), session ID, and Ed25519 signature.

**Entry types.** `SessionStart` (public keys, manifest hash), `DataFlow` (source, decision, rule ID, bytes), `SealedEvent` (type, timestamp, preservation scope), `Anomaly` (pattern, severity, process details), `FirewallEvent` (action, destination, process), `PreservationExtension` (authority, scope), `BurnLayer` (layer number, status), `SessionEnd` (preserved/burned categories, burn result).

**Hash chain.** Entry 0 has a genesis hash (all zeros). Each subsequent entry includes `SHA-256(canonical_bytes(previous_entry))`. Verification recomputes the chain from entry 0; any tampering breaks the chain from the tampered entry onward.

**Signing.** Each entry is individually signed with the session Ed25519 key. The canonical bytes used for signing serialise the entry with an empty signature field, ensuring the signature covers all other fields. Post-flight verification requires only the session public key (transmitted to the GCS at session start).

**Standalone verification.** The `verify_audit_log` function reads the NDJSON file, verifies every signature, checks every hash chain link, validates sequence continuity, and returns a `VerifyResult` with aggregate statistics. The `chambers-verify` CLI wraps this for operator use:

```
$ chambers-verify --audit mission_001.ndjson --pubkey <hex>
  Total entries:    1,234
  Hash chain:       INTACT
  Signatures:       ALL VALID (1,234/1,234)
  Sealed events:    1
  Anomalies:        2
```

Validated by test: 100-entry log verifies correctly; tampering one entry's bytes field causes signature and chain failure at the exact tampered sequence number; a different public key fails all signatures; an empty log verifies as valid.

---

## 11. The DJI Data Sovereignty Problem

The FCC added DJI and other foreign-manufactured drones to its Covered List on 23 December 2025. DJI controlled 70--80% of the US market. The ban was justified on data sovereignty grounds. No public evidence of data exfiltration has been produced. Multiple independent audits found no malicious data sharing.

The dispute is irresolvable within the current architectural paradigm because neither side can prove its position. DJI cannot prove its firmware never exfiltrates data. The US government has not disclosed technical evidence of exfiltration.

### 11.1 What Chambers Solves

**Data sovereignty.** A Chambers module encrypting all data under an ephemeral session key on the companion computer renders the manufacturer's firmware unable to access usable data. If DJI's firmware exfiltrates data, it exfiltrates ciphertext. The session key burns on landing. The audit log records what was transmitted in the clear. Assuming the companion computer's hardware and boot chain are trusted (Section 3.2), the operator has strong architectural evidence -- not a policy promise -- that no usable data reached the manufacturer's cloud.

**Verifiable anomaly detection.** Beyond encryption, the event label system provides positive evidence of firmware behaviour. If DJI's camera agent accesses the V4L2 device outside the manifest-declared pattern, it is logged as ANM-001 with the agent's PID, exe path, and access timestamp. If the access correlates with a blocked outbound network connection, it is escalated to ANM-005 (CRITICAL). This is not reverse engineering the firmware -- it is monitoring its observable behaviour against a declared specification.

### 11.2 What Chambers Does Not Solve

**Supply chain integrity.** The NDAA's prohibition on foreign-made drones is not solely about data exfiltration. It also addresses counterfeit components, firmware kill switches, and strategic dependence on a geopolitical adversary's manufacturing base. Chambers does not inspect flight controller firmware, verify component authenticity, or reduce dependence on Chinese manufacturing.

A regulator could reasonably respond: "We don't care if you encrypt the data -- we don't want Chinese-made flight controllers flying over critical infrastructure because they might contain a kill switch." That objection stands. Chambers solves the data sovereignty component of the ban. It does not solve the supply chain component. Both are legitimate concerns requiring different solutions.

The commercial opportunity remains significant even with this narrower framing. Many agencies banned DJI specifically because they could not verify data flows. A Chambers software module providing verifiable data sovereignty on existing hardware would cost substantially less than fleet replacement with US-manufactured alternatives at $10,000+ per unit.

---

## 12. Regulatory Alignment

### 12.1 FAA Remote ID (14 CFR Part 89)

Remote ID requires drones to broadcast identification, position, velocity, and operator ground station location via Bluetooth or Wi-Fi. Chambers treats Remote ID as a declared regulatory exception in the manifest: `PRESERVE: remote_id (real_time, public)`. The module does not suppress Remote ID broadcasts -- it enables compliance by providing auditable evidence that only declared data (Remote ID) was transmitted in the clear, and that all other outbound data was either encrypted or blocked.

The reference implementation enforces this architecturally: manifest validation rule #2 requires at least one preserve rule with `data_category = "remote_id"` and `transmission = "real_time"`. If the stanza is omitted, the module will not arm. Compliance cannot be accidentally bypassed.

### 12.2 EASA Privacy by Design (Regulation 2019/945)

EASA requires that drones "by default, have the capability to respect the environment and the safety, privacy, security, and protection of personal data protocols." Chambers is one valid architectural approach to satisfying this requirement. A system that retains data by default but applies robust access controls could also satisfy the requirement, depending on regulatory interpretation.

What distinguishes Chambers is that its default-burn posture provides the strongest possible architectural evidence of data minimisation: the data does not merely have access controls -- it ceases to exist.

### 12.3 GDPR Data Minimisation (Article 5(1)(c))

Drone cameras collecting imagery of public spaces capture personal data of non-consenting data subjects. GDPR requires personal data to be "limited to what is necessary." Chambers enforces this through the manifest: payload imagery for the inspection client is preserved; incidental captures beyond the mission scope burn with the session key. The operator can demonstrate to a DPA that data handling is architecturally minimal.

### 12.4 U-Space and Part 108

EU U-space and the forthcoming FAA Part 108 (BVLOS) both define specific data categories that must be shared with airspace service providers. The manifest maps these directly. What Chambers adds: it constrains data sharing to declared categories and burns everything else, preventing mission creep in data collection by UTM providers and cloud backends.

---

## 13. Simulation Validation

### 13.1 Simulation Environment

The reference implementation is validated in a PX4 Software-In-The-Loop (SITL) environment with the following components:

- **PX4 SITL** (v1.15.x) providing MAVLink telemetry over UDP
- **Gazebo** camera sensor output bridged to a virtual V4L2 device via `v4l2loopback` and GStreamer
- **Docker Compose** orchestrating five services: PX4 SITL, Chambers daemon, V4L2 bridge, GCS (Python/FastAPI), and a configurable rogue process for anomaly testing
- **Network namespaces** with `nftables` for firewall enforcement

### 13.2 What Was Validated

| Capability | Validated How | Result |
|---|---|---|
| Session lifecycle (arm/takeoff/land/burn) | 8 unit tests + daemon integration | State machine enforces valid transitions; invalid transitions rejected |
| Ed25519 signing + verification | 12 unit tests | Sign/verify roundtrip; wrong key fails; tampered message fails |
| AES-256-GCM encrypt/decrypt | 12 unit tests | Roundtrip succeeds; wrong key/tampered ciphertext/tampered AAD all fail |
| X25519 key agreement | Unit test | Both sides derive identical shared secret (DH symmetry) |
| Manifest parsing + validation | 30 unit tests | All 8 rules tested individually; multiple error collection; evaluation order |
| Audit log integrity | 10 unit tests | 100-entry chain verifies; tampering detected at exact entry; wrong key rejected |
| Six-layer burn | 7 unit tests | Full sequence: storage destroyed, keys zero, semantic verification passes |
| MAVLink parsing + encryption | 5 unit tests | V1/V2 frame parsing; encryption roundtrip via event label AAD |
| Camera pipeline | 5 unit tests | Test frame generation; encryption; stats tracking; event labels |
| V4L2 anomaly detection | 10 unit tests | ANM-001 through ANM-005; allowlist; post-disarm; burst correlation |
| Firewall | 8 unit tests | Rule generation; allow/block evaluation; event broadcast; flow ID tracking |
| Sealed events | 12 unit tests | Geofence loading; point-in-polygon; 5 event types; deduplication |

### 13.3 What Was Not Validated

- **Real-time encryption throughput on embedded hardware.** The simulation runs on x86_64. Whether a Jetson Orin NX sustains AES-256-GCM at camera data rates under real I/O load requires hardware benchmarks (pending).
- **V4L2 kernel-level interception fidelity.** The simulation uses `v4l2loopback` virtual devices. Real CSI/ISP pipelines on Jetson or Raspberry Pi may behave differently.
- **DJI Payload SDK integration.** Neither the simulation nor the reference implementation exercises DJI's proprietary interfaces.
- **Hardware trust boundary.** TPM, Secure Boot, ARM TrustZone are not simulated.

---

## 14. Performance Considerations

Encrypting 50--200 GB of sensor data on embedded hardware is a non-trivial workload. This paper presents architectural feasibility analysis, not benchmark results, because the reference implementation has not yet been profiled on target drone companion computers.

Modern companion computer SoCs include hardware AES acceleration. The NVIDIA Jetson Orin NX achieves AES-256-GCM throughput exceeding 2 GB/s via its cryptographic engine. A Raspberry Pi 5's ARM Cortex-A76 cores achieve approximately 1 GB/s with NEON instructions. The primary bottleneck is not encryption but I/O: writing encrypted data to an NVMe SSD or SD card. A high-bandwidth payload (4K video at 100 Mbps = 750 MB/min) requires approximately 12.5 MB/s sustained encryption throughput, well within both platforms' capabilities.

MAVLink telemetry is low-bandwidth (~10--100 KB/s). Encryption latency on this pipeline is negligible. The manifest-aware firewall operates on connection metadata, not packet inspection, and adds sub-millisecond latency to outbound connections.

The simulation validates that the architecture is functionally correct at camera frame rates (30 fps synthetic frames). Performance on production hardware will be published separately.

> *Performance benchmarks are pending. The architectural analysis suggests feasibility on Jetson-class hardware. Claims of real-time encryption on lower-end companion computers (Raspberry Pi 4, older STM32-based boards) are not substantiated and should not be assumed.*

---

## 15. Limitations of This Analysis

This paper identifies architectural compliance support, not compliance itself. Compliance determination requires case-by-case legal assessment. The following limitations apply:

**Hardware trust assumption.** Chambers assumes the companion computer's hardware, bootloader, and operating system kernel are trustworthy. If this assumption is violated, all guarantees fail. See Section 3.2.

**Performance not validated on target hardware.** The encryption throughput analysis in Section 14 is theoretical. No benchmarks on target hardware have been conducted. See Section 14.

**Multi-drone federation not addressed.** Fleet operations with multiple drones on a coordinated mission may require cross-drone manifest synchronisation. The current architecture treats each drone's chamber as independent. Federation semantics are future work.

**Firmware update discrimination.** The manifest rule "Allow update payload; block telemetry piggyback" requires the module to distinguish legitimate firmware update traffic from surveillance telemetry riding the same channel. This is a content inspection problem that requires protocol-specific parsers for each manufacturer's update mechanism. The current architecture blocks all undeclared traffic, which may inadvertently block legitimate update acknowledgments. This requires manufacturer cooperation or reverse engineering of update protocols.

**DJI platform integration constraints.** DJI's enterprise platforms (M300/M350) expose limited companion computer interfaces via the Payload SDK. Full data pipeline interception may not be achievable on DJI hardware without manufacturer cooperation, which is unlikely given the adversarial regulatory context.

**Cost-benefit analysis not provided.** The per-unit cost of a Chambers module (software licensing and integration on existing companion computer hardware) has not been validated with manufacturers. A full cost-benefit analysis -- including reduced compliance risk, avoided fines, insurance premium reduction, and fleet replacement cost avoidance -- requires market-specific data not available at this stage.

**Simulation vs. production gap.** The reference implementation is validated in simulation with synthetic frames and localhost MAVLink. Production deployment introduces factors not present in simulation: real sensor noise, I/O contention, thermal throttling, SD card wear, cellular link variability, and GPS multipath. These factors affect reliability and performance but not architectural correctness.

---

## 16. Conclusion

The drone industry builds security on top of persistent systems rather than questioning whether persistence is necessary. Every security framework focuses on protecting data that has already been collected. All of this assumes the data should exist.

Chambers asks the prior question: should this data survive the end of the mission?

For the flight controller's real-time state: no. It kept the drone in the air. Burn it. For the client's thermal imagery: yes, until the inspection report is delivered. Then burn it. For the manufacturer's aggregate flight analytics: no. The manifest blocks it. For the sealed event data from a near-miss: yes, indefinitely, for every regulator.

The grammar distinguishes. The cryptography enforces. The audit log records. Everything else burns.

This is no longer a theoretical architecture. The reference implementation -- 7,498 lines of Rust, 12 modules, 126 passing tests -- demonstrates that the complete session lifecycle, manifest enforcement, six-layer burn, anomaly detection, and cryptographic audit log function end-to-end. The code is open-source. The claims are testable.

This is not the only valid approach to drone data governance. It is the approach that makes destruction the default and preservation the justified exception. Whether that inversion is appropriate depends on the operation, the jurisdiction, and the threat model. This paper argues it is appropriate for the majority of commercial drone operations, and that the regulatory environment is converging toward requiring it.

> *Reference implementation: github.com/therealgulkorinaga/chambers-uas*
> *Core Chambers substrate: github.com/therealgulkorinaga/chamber*
