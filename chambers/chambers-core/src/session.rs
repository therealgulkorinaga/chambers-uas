use crate::audit::{AuditEntryType, AuditLog};
use crate::crypto::SessionKeys;
use crate::error::SessionError;
use crate::manifest::Manifest;
use crate::types::{DataCategory, SessionId, SessionPublicKey, SessionState};

use chrono::{DateTime, Utc};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ─── SessionInfo ───────────────────────────────────────────────────────────

/// Immutable snapshot of session metadata, created at arm time and updated
/// on state transitions.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: SessionId,
    pub state: SessionState,
    pub public_keys: SessionPublicKey,
    pub manifest_hash: [u8; 32],
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
}

// ─── SessionStorage ────────────────────────────────────────────────────────

/// Manages the encrypted on-disk directory tree for a single session.
///
/// Layout:
///   <base>/<session_id>/
///     telemetry/
///     camera/
///     metadata.json
pub struct SessionStorage {
    root: PathBuf,
    telemetry_dir: PathBuf,
    camera_dir: PathBuf,
    metadata_file: PathBuf,
}

impl SessionStorage {
    /// Create the directory tree and return an initialised handle.
    pub fn initialize(base_dir: &Path, session_id: &SessionId) -> Result<Self, io::Error> {
        let root = base_dir.join(session_id.to_string());
        let telemetry_dir = root.join("telemetry");
        let camera_dir = root.join("camera");
        let metadata_file = root.join("metadata.json");

        fs::create_dir_all(&telemetry_dir)?;
        fs::create_dir_all(&camera_dir)?;

        // Create an empty metadata file so it is present from the start.
        fs::write(&metadata_file, "{}")?;

        Ok(Self {
            root,
            telemetry_dir,
            camera_dir,
            metadata_file,
        })
    }

    /// Write an encrypted blob into the appropriate category directory.
    ///
    /// The file is named `<category_str>_<index>.enc`.  Returns the path to
    /// the newly written file.
    pub fn write_encrypted(
        &self,
        category: &DataCategory,
        data: &[u8],
        index: u64,
    ) -> Result<PathBuf, io::Error> {
        let dir = match category {
            DataCategory::EoImagery | DataCategory::ThermalImagery => &self.camera_dir,
            _ => &self.telemetry_dir,
        };
        let filename = format!("{}_{}.enc", category.as_str(), index);
        let path = dir.join(filename);
        fs::write(&path, data)?;
        Ok(path)
    }

    /// Recursively enumerate every file under the session root.
    pub fn list_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if self.root.exists() {
            Self::collect_files(&self.root, &mut files);
        }
        files
    }

    /// Sum of all file sizes (bytes) under the session root.
    pub fn total_bytes(&self) -> u64 {
        self.list_files()
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    /// Destroy all files and directories belonging to this session.
    /// Used by the burn procedure.
    pub fn destroy(&self) -> Result<(), io::Error> {
        if self.root.exists() {
            fs::remove_dir_all(&self.root)?;
        }
        Ok(())
    }

    /// The top-level session directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the session directory still exists on disk.
    pub fn exists(&self) -> bool {
        self.root.exists()
    }

    // ── helpers ────────────────────────────────────────────────────────────

    fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}

// ─── SessionManager ────────────────────────────────────────────────────────

/// The main session lifecycle state-machine.
///
/// Valid transitions:
///   Idle       → PreFlight   (arm_mission)
///   PreFlight  → InFlight    (notify_takeoff)
///   PreFlight  → Idle        (arm_failed)
///   InFlight   → PostFlight  (notify_landing / emergency_stop)
///   PostFlight → Burning     (start_burn)
///   Burning    → Idle        (burn_complete / reset)
pub struct SessionManager {
    state: SessionState,
    session_id: Option<SessionId>,
    keys: Option<SessionKeys>,
    manifest: Option<Manifest>,
    storage: Option<SessionStorage>,
    audit_log: Option<AuditLog>,
    info: Option<SessionInfo>,
    storage_base: PathBuf,
    audit_base: PathBuf,
}

impl SessionManager {
    /// Create a new manager rooted at the given base directories.
    pub fn new(storage_base: PathBuf, audit_base: PathBuf) -> Self {
        Self {
            state: SessionState::Idle,
            session_id: None,
            keys: None,
            manifest: None,
            storage: None,
            audit_log: None,
            info: None,
            storage_base,
            audit_base,
        }
    }

    // ── state transitions ─────────────────────────────────────────────────

    /// Arm a new mission.
    ///
    /// 1. Assert we are Idle
    /// 2. Load and validate the manifest
    /// 3. Generate session keys
    /// 4. Create a session id
    /// 5. Initialise on-disk storage
    /// 6. Initialise the audit log
    /// 7. Log `SessionStart`
    /// 8. Transition to PreFlight
    /// 9. Return the public keys
    pub fn arm_mission(&mut self, manifest_path: &Path) -> Result<SessionPublicKey, SessionError> {
        if self.state != SessionState::Idle {
            return Err(SessionError::AlreadyArmed);
        }

        // 2 – manifest
        let manifest = Manifest::load(manifest_path)?;
        let manifest_hash = manifest.hash();

        // 3 – keys
        let keys = SessionKeys::generate()?;
        let public_keys = keys.public_keys();

        // 4 – session id
        let session_id = SessionId::generate();
        info!(session = %session_id, "Arming mission");

        // 5 – storage
        let storage = SessionStorage::initialize(&self.storage_base, &session_id)
            .map_err(SessionError::Io)?;
        debug!(root = %storage.root().display(), "Session storage initialised");

        // 6 – audit
        let audit_path = self.audit_base.join(session_id.to_string()).join("audit.ndjson");
        let mut audit_log = AuditLog::new(&audit_path, session_id, manifest_hash)
            .map_err(|e| SessionError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        // 7 – audit entry
        let sign_fn = |data: &[u8]| keys.sign(data);
        audit_log
            .append(
                AuditEntryType::SessionStart {
                    session_public_key_sign: public_keys.sign.clone(),
                    session_public_key_enc: public_keys.enc.clone(),
                    manifest_hash,
                },
                &sign_fn,
            )
            .map_err(|e| SessionError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        // 8 – info snapshot
        let info = SessionInfo {
            id: session_id,
            state: SessionState::PreFlight,
            public_keys: public_keys.clone(),
            manifest_hash,
            start_time: Utc::now(),
            end_time: None,
        };

        // Commit to self
        self.state = SessionState::PreFlight;
        self.session_id = Some(session_id);
        self.keys = Some(keys);
        self.manifest = Some(manifest);
        self.storage = Some(storage);
        self.audit_log = Some(audit_log);
        self.info = Some(info);

        info!(session = %session_id, "Mission armed — state is PreFlight");
        Ok(public_keys)
    }

    /// Called when the autopilot reports takeoff.
    pub fn notify_takeoff(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::PreFlight, SessionState::InFlight)?;
        self.log_transition("PreFlight", "InFlight");
        info!("Takeoff — state is InFlight");
        Ok(())
    }

    /// Called when the autopilot reports a normal landing.
    pub fn notify_landing(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::InFlight, SessionState::PostFlight)?;
        if let Some(info) = self.info.as_mut() {
            info.end_time = Some(Utc::now());
            info.state = SessionState::PostFlight;
        }
        self.log_transition("InFlight", "PostFlight");
        info!("Landing — state is PostFlight");
        Ok(())
    }

    /// Called when an in-flight emergency forces immediate landing.
    pub fn emergency_stop(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::InFlight, SessionState::PostFlight)?;
        if let Some(info) = self.info.as_mut() {
            info.end_time = Some(Utc::now());
            info.state = SessionState::PostFlight;
        }
        self.log_transition("InFlight", "PostFlight(emergency)");
        warn!("Emergency stop — state is PostFlight");
        Ok(())
    }

    /// Called when arming fails during PreFlight (e.g. preflight checks fail).
    /// Cleans up session state and returns to Idle without running the burn
    /// procedure.
    pub fn arm_failed(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::PreFlight, SessionState::Idle)?;
        self.log_transition("PreFlight", "Idle(arm_failed)");
        warn!("Arm failed — returning to Idle");
        self.clear_session_state();
        Ok(())
    }

    /// Begin the burn procedure.
    pub fn start_burn(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::PostFlight, SessionState::Burning)?;
        self.log_transition("PostFlight", "Burning");
        info!("Burn started");
        Ok(())
    }

    /// Signal that the burn has completed successfully.  Resets all session
    /// state and returns to Idle.
    pub fn burn_complete(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::Burning, SessionState::Idle)?;
        self.log_transition("Burning", "Idle");
        info!("Burn complete — state is Idle");
        self.clear_session_state();
        Ok(())
    }

    /// Hard reset from Burning to Idle, clearing all session state.
    pub fn reset(&mut self) -> Result<(), SessionError> {
        self.transition(SessionState::Burning, SessionState::Idle)?;
        info!("Session reset — state is Idle");
        self.clear_session_state();
        Ok(())
    }

    // ── accessors ─────────────────────────────────────────────────────────

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn session_info(&self) -> Option<&SessionInfo> {
        self.info.as_ref()
    }

    pub fn keys(&self) -> Option<&SessionKeys> {
        self.keys.as_ref()
    }

    pub fn keys_mut(&mut self) -> Option<&mut SessionKeys> {
        self.keys.as_mut()
    }

    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    pub fn storage(&self) -> Option<&SessionStorage> {
        self.storage.as_ref()
    }

    pub fn audit_log(&self) -> Option<&AuditLog> {
        self.audit_log.as_ref()
    }

    pub fn audit_log_mut(&mut self) -> Option<&mut AuditLog> {
        self.audit_log.as_mut()
    }

    /// Consume and return the session keys (used by the burn layer that
    /// needs ownership to zeroise).
    pub fn take_keys(&mut self) -> Option<SessionKeys> {
        self.keys.take()
    }

    // ── internal helpers ──────────────────────────────────────────────────

    /// Enforce that we are in `expected` and move to `next`.
    fn transition(
        &mut self,
        expected: SessionState,
        next: SessionState,
    ) -> Result<(), SessionError> {
        if self.state != expected {
            return Err(SessionError::InvalidState {
                current: self.state,
                attempted: next,
            });
        }
        self.state = next;
        if let Some(info) = self.info.as_mut() {
            info.state = next;
        }
        Ok(())
    }

    /// Best-effort audit log of a state transition.
    ///
    /// NOTE: The signed audit log requires a `sign_fn` for every append,
    /// so callers that need transition records should use `audit_log.append()`
    /// directly with the session keys.  This placeholder logs via tracing only.
    fn log_transition(&mut self, from: &str, to: &str) {
        debug!(from = from, to = to, "State transition");
    }

    /// Wipe all per-session fields so the manager is ready for another arm.
    fn clear_session_state(&mut self) {
        self.session_id = None;
        self.keys = None;
        self.manifest = None;
        self.storage = None;
        self.audit_log = None;
        self.info = None;
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::TempDir;

    /// A minimal valid manifest TOML.
    const TEST_MANIFEST_TOML: &str = r#"
[meta]
version = "1.0"
mission_type = "test_flight"
operator_id = "OP-TEST-001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Operator"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "14 CFR Part 89 compliance"
"#;

    /// Write the test manifest to a temp file and return its path.
    fn write_test_manifest(dir: &Path) -> PathBuf {
        let path = dir.join("manifest.toml");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(TEST_MANIFEST_TOML.as_bytes()).unwrap();
        path
    }

    /// Construct a SessionManager backed by two temp directories.
    fn make_manager(storage: &Path, audit: &Path) -> SessionManager {
        SessionManager::new(storage.to_path_buf(), audit.to_path_buf())
    }

    // ── happy-path lifecycle ───────────────────────────────────────────────

    #[test]
    fn full_happy_path() {
        let tmp = TempDir::new().unwrap();
        let storage = tmp.path().join("storage");
        let audit = tmp.path().join("audit");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&audit).unwrap();

        let manifest_path = write_test_manifest(tmp.path());
        let mut mgr = make_manager(&storage, &audit);

        // Idle → PreFlight
        assert_eq!(mgr.state(), SessionState::Idle);
        let pub_keys = mgr.arm_mission(&manifest_path).unwrap();
        assert_eq!(mgr.state(), SessionState::PreFlight);
        assert_eq!(pub_keys.sign.len(), 32);
        assert_eq!(pub_keys.enc.len(), 32);

        // PreFlight → InFlight
        mgr.notify_takeoff().unwrap();
        assert_eq!(mgr.state(), SessionState::InFlight);

        // InFlight → PostFlight
        mgr.notify_landing().unwrap();
        assert_eq!(mgr.state(), SessionState::PostFlight);
        assert!(mgr.session_info().unwrap().end_time.is_some());

        // PostFlight → Burning
        mgr.start_burn().unwrap();
        assert_eq!(mgr.state(), SessionState::Burning);

        // Burning → Idle
        mgr.burn_complete().unwrap();
        assert_eq!(mgr.state(), SessionState::Idle);
        assert!(mgr.session_info().is_none());
        assert!(mgr.keys().is_none());
    }

    // ── invalid transition ─────────────────────────────────────────────────

    #[test]
    fn invalid_transition_idle_to_inflight() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = make_manager(tmp.path(), tmp.path());
        let result = mgr.notify_takeoff();
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::InvalidState { current, attempted } => {
                assert_eq!(current, SessionState::Idle);
                assert_eq!(attempted, SessionState::InFlight);
            }
            other => panic!("Expected InvalidState, got: {:?}", other),
        }
    }

    // ── arm creates dirs and audit ─────────────────────────────────────────

    #[test]
    fn arm_creates_storage_and_audit() {
        let tmp = TempDir::new().unwrap();
        let storage = tmp.path().join("storage");
        let audit = tmp.path().join("audit");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&audit).unwrap();

        let manifest_path = write_test_manifest(tmp.path());
        let mut mgr = make_manager(&storage, &audit);
        mgr.arm_mission(&manifest_path).unwrap();

        // Storage dirs should exist
        let sess_storage = mgr.storage().unwrap();
        assert!(sess_storage.exists());
        assert!(sess_storage.root().join("telemetry").is_dir());
        assert!(sess_storage.root().join("camera").is_dir());
        assert!(sess_storage.root().join("metadata.json").is_file());

        // Audit log file should exist
        let audit_log = mgr.audit_log().unwrap();
        assert!(audit_log.path().is_file());
    }

    // ── cannot arm twice ───────────────────────────────────────────────────

    #[test]
    fn cannot_arm_twice() {
        let tmp = TempDir::new().unwrap();
        let storage = tmp.path().join("storage");
        let audit = tmp.path().join("audit");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&audit).unwrap();

        let manifest_path = write_test_manifest(tmp.path());
        let mut mgr = make_manager(&storage, &audit);
        mgr.arm_mission(&manifest_path).unwrap();

        let result = mgr.arm_mission(&manifest_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::AlreadyArmed => {}
            other => panic!("Expected AlreadyArmed, got: {:?}", other),
        }
    }

    // ── SessionStorage write + list + total_bytes + destroy ────────────────

    #[test]
    fn session_storage_operations() {
        let tmp = TempDir::new().unwrap();
        let session_id = SessionId::generate();
        let ss = SessionStorage::initialize(tmp.path(), &session_id).unwrap();

        // Write a telemetry blob
        let telem_data = b"encrypted telemetry payload";
        let telem_path = ss
            .write_encrypted(&DataCategory::FlightTelemetry, telem_data, 0)
            .unwrap();
        assert!(telem_path.exists());
        assert_eq!(fs::read(&telem_path).unwrap(), telem_data);

        // Write a camera blob
        let cam_data = b"encrypted camera frame";
        let cam_path = ss
            .write_encrypted(&DataCategory::EoImagery, cam_data, 1)
            .unwrap();
        assert!(cam_path.exists());
        assert!(cam_path.starts_with(ss.root().join("camera")));

        // list_files should return at least 3 files (metadata + 2 data)
        let files = ss.list_files();
        assert!(files.len() >= 3, "Expected >=3 files, got {}", files.len());

        // total_bytes should be >= the data we wrote plus metadata stub
        let total = ss.total_bytes();
        assert!(
            total >= (telem_data.len() + cam_data.len()) as u64,
            "Expected >= {} bytes, got {}",
            telem_data.len() + cam_data.len(),
            total
        );

        // destroy
        assert!(ss.exists());
        ss.destroy().unwrap();
        assert!(!ss.exists());
    }

    // ── accessor methods ───────────────────────────────────────────────────

    #[test]
    fn accessor_methods() {
        let tmp = TempDir::new().unwrap();
        let storage = tmp.path().join("storage");
        let audit = tmp.path().join("audit");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&audit).unwrap();

        let manifest_path = write_test_manifest(tmp.path());
        let mut mgr = make_manager(&storage, &audit);

        // Before arming — everything is None / Idle
        assert_eq!(mgr.state(), SessionState::Idle);
        assert!(mgr.session_info().is_none());
        assert!(mgr.keys().is_none());
        assert!(mgr.keys_mut().is_none());
        assert!(mgr.manifest().is_none());
        assert!(mgr.storage().is_none());
        assert!(mgr.audit_log().is_none());
        assert!(mgr.audit_log_mut().is_none());
        assert!(mgr.take_keys().is_none());

        // After arming — everything is populated
        mgr.arm_mission(&manifest_path).unwrap();

        assert_eq!(mgr.state(), SessionState::PreFlight);
        assert!(mgr.session_info().is_some());
        assert!(mgr.keys().is_some());
        assert!(mgr.keys_mut().is_some());
        assert!(mgr.manifest().is_some());
        assert!(mgr.storage().is_some());
        assert!(mgr.audit_log().is_some());
        assert!(mgr.audit_log_mut().is_some());

        // take_keys consumes
        let taken = mgr.take_keys();
        assert!(taken.is_some());
        assert!(mgr.keys().is_none());
    }

    // ── emergency stop ─────────────────────────────────────────────────────

    #[test]
    fn emergency_stop_transitions_to_postflight() {
        let tmp = TempDir::new().unwrap();
        let storage = tmp.path().join("storage");
        let audit = tmp.path().join("audit");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&audit).unwrap();

        let manifest_path = write_test_manifest(tmp.path());
        let mut mgr = make_manager(&storage, &audit);

        mgr.arm_mission(&manifest_path).unwrap();
        mgr.notify_takeoff().unwrap();
        mgr.emergency_stop().unwrap();

        assert_eq!(mgr.state(), SessionState::PostFlight);
        assert!(mgr.session_info().unwrap().end_time.is_some());
    }

    // ── arm_failed returns to idle ─────────────────────────────────────────

    #[test]
    fn arm_failed_returns_to_idle() {
        let tmp = TempDir::new().unwrap();
        let storage = tmp.path().join("storage");
        let audit = tmp.path().join("audit");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&audit).unwrap();

        let manifest_path = write_test_manifest(tmp.path());
        let mut mgr = make_manager(&storage, &audit);

        mgr.arm_mission(&manifest_path).unwrap();
        assert_eq!(mgr.state(), SessionState::PreFlight);

        mgr.arm_failed().unwrap();
        assert_eq!(mgr.state(), SessionState::Idle);
        assert!(mgr.session_info().is_none());
        assert!(mgr.keys().is_none());
    }

    // ── reset from burning ─────────────────────────────────────────────────

    #[test]
    fn reset_from_burning() {
        let tmp = TempDir::new().unwrap();
        let storage = tmp.path().join("storage");
        let audit = tmp.path().join("audit");
        fs::create_dir_all(&storage).unwrap();
        fs::create_dir_all(&audit).unwrap();

        let manifest_path = write_test_manifest(tmp.path());
        let mut mgr = make_manager(&storage, &audit);

        mgr.arm_mission(&manifest_path).unwrap();
        mgr.notify_takeoff().unwrap();
        mgr.notify_landing().unwrap();
        mgr.start_burn().unwrap();
        assert_eq!(mgr.state(), SessionState::Burning);

        mgr.reset().unwrap();
        assert_eq!(mgr.state(), SessionState::Idle);
        assert!(mgr.session_info().is_none());
    }
}
