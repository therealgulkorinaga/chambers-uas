use crate::crypto::{sha256, verify_signature};
use crate::error::{AuditError, CryptoError};
use crate::types::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

// ─── Audit entry types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEntryType {
    SessionStart {
        session_public_key_sign: Vec<u8>,
        session_public_key_enc: Vec<u8>,
        manifest_hash: [u8; 32],
    },
    DataFlow {
        source: DataSource,
        decision: String, // "preserve", "deny", "burn"
        rule_id: Option<String>,
        bytes: u64,
    },
    SealedEvent {
        event_type: SealedEventType,
        trigger_timestamp: DateTime<Utc>,
        preservation_scope: PreservationScope,
    },
    Anomaly {
        pattern: AnomalyPattern,
        severity: Severity,
        process_name: String,
        process_id: u32,
        details: String,
    },
    FirewallEvent {
        action: FirewallAction,
        direction: Direction,
        protocol: Protocol,
        destination: String,
        process_name: String,
    },
    PreservationExtension {
        authority: String,
        scope: String,
    },
    BurnLayer {
        layer: u8,
        status: String,
        details: String,
    },
    SessionEnd {
        preserved_categories: Vec<String>,
        burned_categories: Vec<String>,
        burn_all_passed: bool,
    },
}

// ─── Audit entry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub previous_hash: [u8; 32],
    pub entry_type: AuditEntryType,
    pub manifest_hash: [u8; 32],
    pub session_id: SessionId,
    pub signature: Vec<u8>, // Ed25519 signature
}

impl AuditEntry {
    /// Serialize the entry with an empty signature for hashing/signing purposes.
    /// This produces the canonical bytes that are both signed and hashed into
    /// the chain.
    fn canonical_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let mut canon = self.clone();
        canon.signature = Vec::new();
        serde_json::to_vec(&canon).map_err(|e| AuditError::Serialization(e.to_string()))
    }

    /// Compute the SHA-256 hash of the canonical (signature-excluded) form.
    fn hash(&self) -> Result<[u8; 32], AuditError> {
        let bytes = self.canonical_bytes()?;
        Ok(sha256(&bytes))
    }
}

// ─── Verification result ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub total_entries: u64,
    pub all_signatures_valid: bool,
    pub hash_chain_intact: bool,
    pub first_invalid_entry: Option<u64>,
    pub manifest_hash: [u8; 32],
    pub session_id: SessionId,
    pub sealed_events_count: u64,
    pub anomalies_count: u64,
    pub data_flow_count: u64,
}

// ─── Audit log ─────────────────────────────────────────────────────────────

/// Append-only, hash-chained, signed audit log for a Chambers session.
///
/// Each entry is serialized as a single JSON line (NDJSON format), signed
/// with the session Ed25519 key, and chained via SHA-256 hashes so that
/// any tampering — insertion, deletion, or modification — is detectable.
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    current_hash: [u8; 32],
    next_sequence: u64,
    manifest_hash: [u8; 32],
    session_id: SessionId,
    file_path: PathBuf,
}

impl AuditLog {
    /// Create a new audit log backed by the given file path.
    ///
    /// The file is created (or truncated) immediately.  The genesis
    /// `previous_hash` is all zeros.
    pub fn new(
        path: impl Into<PathBuf>,
        session_id: SessionId,
        manifest_hash: [u8; 32],
    ) -> Result<Self, AuditError> {
        let file_path = path.into();

        // Ensure parent directory exists
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create or truncate the log file
        File::create(&file_path)?;

        Ok(Self {
            entries: Vec::new(),
            current_hash: [0u8; 32], // Genesis hash: all zeros
            next_sequence: 0,
            manifest_hash,
            session_id,
            file_path,
        })
    }

    /// Append a new entry to the audit log.
    ///
    /// 1. Builds the entry with sequence, timestamp, and previous_hash.
    /// 2. Serializes the entry WITHOUT a signature (empty vec) to produce
    ///    the canonical bytes.
    /// 3. Calls `sign_fn` on those bytes to obtain the Ed25519 signature.
    /// 4. Sets the signature on the entry.
    /// 5. Serializes the complete entry as a single JSON line and appends
    ///    it to the backing file, followed by `fsync`.
    /// 6. Updates `current_hash` and `next_sequence`.
    ///
    /// Returns the sequence number of the appended entry.
    pub fn append(
        &mut self,
        entry_type: AuditEntryType,
        sign_fn: &dyn Fn(&[u8]) -> Result<Vec<u8>, CryptoError>,
    ) -> Result<u64, AuditError> {
        // Build entry with empty signature placeholder
        let mut entry = AuditEntry {
            sequence: self.next_sequence,
            timestamp: Utc::now(),
            previous_hash: self.current_hash,
            entry_type,
            manifest_hash: self.manifest_hash,
            session_id: self.session_id,
            signature: Vec::new(),
        };

        // Serialize canonical form (empty signature) for signing
        let canonical = entry.canonical_bytes()?;

        // Sign the canonical bytes
        let signature = sign_fn(&canonical)?;
        entry.signature = signature;

        // Serialize the complete entry as a single JSON line
        let json_line = serde_json::to_string(&entry)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        // Append to file with newline, then fsync
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;
        writeln!(file, "{}", json_line)?;
        file.flush()?;
        file.sync_all()?;

        // Compute hash of this entry (canonical bytes, excluding signature)
        let entry_hash = entry.hash()?;

        let seq = entry.sequence;
        self.entries.push(entry);
        self.current_hash = entry_hash;
        self.next_sequence += 1;

        Ok(seq)
    }

    /// Return all entries with sequence number >= `sequence`.
    ///
    /// Because entries are stored in order and sequence N lives at index N,
    /// this is a simple slice operation.
    pub fn entries_since(&self, sequence: u64) -> &[AuditEntry] {
        let idx = sequence as usize;
        if idx >= self.entries.len() {
            return &[];
        }
        &self.entries[idx..]
    }

    /// Return the total number of entries in the log.
    pub fn entry_count(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Path to the backing NDJSON file.
    pub fn path(&self) -> &Path {
        &self.file_path
    }
}

// ─── Standalone verification ───────────────────────────────────────────────

/// Verify an NDJSON audit log file for:
///
/// - **Signature validity**: each entry's Ed25519 signature matches its
///   canonical bytes when checked against `sign_public_key`.
/// - **Hash chain integrity**: each entry's `previous_hash` equals the
///   SHA-256 of the preceding entry's canonical bytes (genesis is all
///   zeros).
/// - **Sequence continuity**: sequence numbers are strictly monotonic
///   starting from 0.
///
/// Returns a [`VerifyResult`] summarizing the findings.
pub fn verify_audit_log(
    log_path: &Path,
    sign_public_key: &[u8],
) -> Result<VerifyResult, AuditError> {
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);

    let mut total_entries: u64 = 0;
    let mut all_signatures_valid = true;
    let mut hash_chain_intact = true;
    let mut first_invalid_entry: Option<u64> = None;
    let mut sealed_events_count: u64 = 0;
    let mut anomalies_count: u64 = 0;
    let mut data_flow_count: u64 = 0;

    let mut expected_sequence: u64 = 0;
    let mut expected_previous_hash: [u8; 32] = [0u8; 32];
    let mut manifest_hash: [u8; 32] = [0u8; 32];
    let mut session_id = SessionId([0u8; 16]);

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let entry: AuditEntry = serde_json::from_str(trimmed)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        // On first entry, capture manifest_hash and session_id
        if total_entries == 0 {
            manifest_hash = entry.manifest_hash;
            session_id = entry.session_id;
        }

        // Count by type
        match &entry.entry_type {
            AuditEntryType::SealedEvent { .. } => sealed_events_count += 1,
            AuditEntryType::Anomaly { .. } => anomalies_count += 1,
            AuditEntryType::DataFlow { .. } => data_flow_count += 1,
            _ => {}
        }

        // ── Sequence continuity ──
        if entry.sequence != expected_sequence {
            if first_invalid_entry.is_none() {
                first_invalid_entry = Some(entry.sequence);
            }
            hash_chain_intact = false;
        }

        // ── Hash chain ──
        if entry.previous_hash != expected_previous_hash {
            if first_invalid_entry.is_none() {
                first_invalid_entry = Some(entry.sequence);
            }
            hash_chain_intact = false;
        }

        // ── Signature verification ──
        let canonical = {
            let mut canon = entry.clone();
            canon.signature = Vec::new();
            serde_json::to_vec(&canon)
                .map_err(|e| AuditError::Serialization(e.to_string()))?
        };

        match verify_signature(sign_public_key, &canonical, &entry.signature) {
            Ok(true) => { /* valid */ }
            Ok(false) | Err(_) => {
                all_signatures_valid = false;
                if first_invalid_entry.is_none() {
                    first_invalid_entry = Some(entry.sequence);
                }
            }
        }

        // Compute entry hash for the next link in the chain
        let entry_hash = sha256(&canonical);
        expected_previous_hash = entry_hash;
        expected_sequence = entry.sequence + 1;
        total_entries += 1;
    }

    Ok(VerifyResult {
        total_entries,
        all_signatures_valid,
        hash_chain_intact,
        first_invalid_entry,
        manifest_hash,
        session_id,
        sealed_events_count,
        anomalies_count,
        data_flow_count,
    })
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::io::{BufRead, BufReader};

    /// Helper: generate an Ed25519 keypair, returning (signing_key, public_key_bytes).
    fn test_keypair() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        (sk, pk.as_bytes().to_vec())
    }

    /// Helper: build a `sign_fn` closure from a [`SigningKey`].
    fn make_sign_fn(
        sk: &SigningKey,
    ) -> Box<dyn Fn(&[u8]) -> Result<Vec<u8>, CryptoError> + '_> {
        Box::new(move |data: &[u8]| {
            let sig = sk.sign(data);
            Ok(sig.to_bytes().to_vec())
        })
    }

    /// Helper: a simple DataFlow entry type for testing.
    fn sample_data_flow(i: u64) -> AuditEntryType {
        AuditEntryType::DataFlow {
            source: DataSource::Gps,
            decision: "preserve".to_string(),
            rule_id: Some(format!("rule-{}", i)),
            bytes: 1024 * i,
        }
    }

    /// Helper: create a temp directory that is cleaned up when dropped.
    fn tmp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("failed to create temp dir")
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 1: Create log, append 100 entries, verify chain intact
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn append_100_entries_and_verify_chain() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"test-manifest-v1");

        let (sk, pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();

        for i in 0..100 {
            let seq = log.append(sample_data_flow(i), sign_fn.as_ref()).unwrap();
            assert_eq!(seq, i);
        }
        assert_eq!(log.entry_count(), 100);

        let result = verify_audit_log(&log_path, &pk).unwrap();
        assert_eq!(result.total_entries, 100);
        assert!(result.all_signatures_valid);
        assert!(result.hash_chain_intact);
        assert!(result.first_invalid_entry.is_none());
        assert_eq!(result.manifest_hash, manifest_hash);
        assert_eq!(result.session_id, session_id);
        assert_eq!(result.data_flow_count, 100);
        assert_eq!(result.sealed_events_count, 0);
        assert_eq!(result.anomalies_count, 0);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 2: Tamper one entry -> verification detects it
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn tamper_one_entry_detected() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"manifest");

        let (sk, pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();
        for i in 0..10 {
            log.append(sample_data_flow(i), sign_fn.as_ref()).unwrap();
        }

        // Tamper with entry at line 5 (sequence 5) by changing the bytes field.
        // The signature will no longer match.
        let contents = fs::read_to_string(&log_path).unwrap();
        let mut lines: Vec<String> = contents.lines().map(String::from).collect();
        assert_eq!(lines.len(), 10);

        let mut entry: AuditEntry = serde_json::from_str(&lines[5]).unwrap();
        if let AuditEntryType::DataFlow { ref mut bytes, .. } = entry.entry_type {
            *bytes = 999_999_999;
        }
        lines[5] = serde_json::to_string(&entry).unwrap();

        let tampered = lines.join("\n") + "\n";
        fs::write(&log_path, tampered).unwrap();

        let result = verify_audit_log(&log_path, &pk).unwrap();
        // Tampered entry should break signature and/or hash chain
        assert!(
            !result.all_signatures_valid || !result.hash_chain_intact,
            "Verification should have detected tampering"
        );
        let first_bad = result.first_invalid_entry.unwrap();
        // The tampered entry is at sequence 5; hash chain break propagates to 6
        assert!(
            first_bad <= 6,
            "Expected first invalid entry <= 6, got {}",
            first_bad
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 3: Signature verification with correct key
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_verification_correct_key() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"m");

        let (sk, pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();
        log.append(sample_data_flow(0), sign_fn.as_ref()).unwrap();

        let result = verify_audit_log(&log_path, &pk).unwrap();
        assert!(result.all_signatures_valid);
        assert!(result.hash_chain_intact);
        assert!(result.first_invalid_entry.is_none());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 4: Signature verification with wrong key
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_verification_wrong_key() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"m");

        let (sk, _pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();
        log.append(sample_data_flow(0), sign_fn.as_ref()).unwrap();

        // Verify with a different key — should fail
        let (_sk2, wrong_pk) = test_keypair();
        let result = verify_audit_log(&log_path, &wrong_pk).unwrap();
        assert!(!result.all_signatures_valid);
        assert_eq!(result.first_invalid_entry, Some(0));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 5: entries_since returns correct slice
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn entries_since_returns_correct_slice() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"m");

        let (sk, _pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();
        for i in 0..20 {
            log.append(sample_data_flow(i), sign_fn.as_ref()).unwrap();
        }

        // All entries
        assert_eq!(log.entries_since(0).len(), 20);

        // Entries from sequence 10 onward
        let slice = log.entries_since(10);
        assert_eq!(slice.len(), 10);
        assert_eq!(slice[0].sequence, 10);
        assert_eq!(slice[9].sequence, 19);

        // Single last entry
        let slice = log.entries_since(19);
        assert_eq!(slice.len(), 1);
        assert_eq!(slice[0].sequence, 19);

        // Beyond the end
        assert_eq!(log.entries_since(20).len(), 0);
        assert_eq!(log.entries_since(100).len(), 0);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 6: NDJSON format (each line is valid JSON)
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn ndjson_format_each_line_is_valid_json() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"m");

        let (sk, _pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();
        for i in 0..5 {
            log.append(sample_data_flow(i), sign_fn.as_ref()).unwrap();
        }

        let file = File::open(&log_path).unwrap();
        let reader = BufReader::new(file);
        let mut count = 0u64;
        for line in reader.lines() {
            let line = line.unwrap();
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Must parse as valid JSON
            let _value: serde_json::Value =
                serde_json::from_str(trimmed).expect("Each line must be valid JSON");
            // Must round-trip to AuditEntry
            let entry: AuditEntry =
                serde_json::from_str(trimmed).expect("Each line must be a valid AuditEntry");
            assert_eq!(entry.sequence, count);
            count += 1;
        }
        assert_eq!(count, 5);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 7: Empty log verifies as valid
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn empty_log_verifies_as_valid() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"m");

        let _log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();

        let (_sk, pk) = test_keypair();
        let result = verify_audit_log(&log_path, &pk).unwrap();
        assert_eq!(result.total_entries, 0);
        assert!(result.all_signatures_valid);
        assert!(result.hash_chain_intact);
        assert!(result.first_invalid_entry.is_none());
        assert_eq!(result.sealed_events_count, 0);
        assert_eq!(result.anomalies_count, 0);
        assert_eq!(result.data_flow_count, 0);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 8: Mixed entry types are counted correctly
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn mixed_entry_types_counted_correctly() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"manifest");

        let (sk, pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();

        // SessionStart
        log.append(
            AuditEntryType::SessionStart {
                session_public_key_sign: pk.clone(),
                session_public_key_enc: vec![0u8; 32],
                manifest_hash,
            },
            sign_fn.as_ref(),
        )
        .unwrap();

        // 3 DataFlow entries
        for i in 0..3 {
            log.append(sample_data_flow(i), sign_fn.as_ref()).unwrap();
        }

        // 2 Anomaly entries
        for _ in 0..2 {
            log.append(
                AuditEntryType::Anomaly {
                    pattern: AnomalyPattern::UndeclaredCameraAccess,
                    severity: Severity::High,
                    process_name: "rogue".into(),
                    process_id: 1234,
                    details: "unexpected camera read".into(),
                },
                sign_fn.as_ref(),
            )
            .unwrap();
        }

        // 1 SealedEvent
        log.append(
            AuditEntryType::SealedEvent {
                event_type: SealedEventType::AirspaceIncursion,
                trigger_timestamp: Utc::now(),
                preservation_scope: PreservationScope {
                    time_range: TimeRange::new(Utc::now(), Utc::now()),
                    data_categories: vec![DataCategory::FlightTelemetry],
                    stakeholders: vec!["regulator".into()],
                    retention_days: 90,
                },
            },
            sign_fn.as_ref(),
        )
        .unwrap();

        // 1 FirewallEvent
        log.append(
            AuditEntryType::FirewallEvent {
                action: FirewallAction::Block,
                direction: Direction::Outbound,
                protocol: Protocol::Tcp,
                destination: "10.0.0.1:443".into(),
                process_name: "suspicious".into(),
            },
            sign_fn.as_ref(),
        )
        .unwrap();

        // SessionEnd
        log.append(
            AuditEntryType::SessionEnd {
                preserved_categories: vec!["flight_telemetry".into()],
                burned_categories: vec!["eo_imagery".into()],
                burn_all_passed: true,
            },
            sign_fn.as_ref(),
        )
        .unwrap();

        assert_eq!(log.entry_count(), 9);

        let result = verify_audit_log(&log_path, &pk).unwrap();
        assert_eq!(result.total_entries, 9);
        assert!(result.all_signatures_valid);
        assert!(result.hash_chain_intact);
        assert_eq!(result.data_flow_count, 3);
        assert_eq!(result.anomalies_count, 2);
        assert_eq!(result.sealed_events_count, 1);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 9: Hash chain breaks on line reorder
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn hash_chain_breaks_on_reorder() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"m");

        let (sk, pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();
        for i in 0..5 {
            log.append(sample_data_flow(i), sign_fn.as_ref()).unwrap();
        }

        // Swap lines 2 and 3
        let contents = fs::read_to_string(&log_path).unwrap();
        let mut lines: Vec<&str> = contents.lines().collect();
        lines.swap(2, 3);
        let reordered = lines.join("\n") + "\n";
        fs::write(&log_path, reordered).unwrap();

        let result = verify_audit_log(&log_path, &pk).unwrap();
        assert!(
            !result.hash_chain_intact || result.first_invalid_entry.is_some(),
            "Reordering lines must be detected"
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 10: entry_count tracks correctly
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn entry_count_tracks_correctly() {
        let dir = tmp_dir();
        let log_path = dir.path().join("audit.ndjson");
        let session_id = SessionId::generate();
        let manifest_hash = sha256(b"m");

        let (sk, _pk) = test_keypair();
        let sign_fn = make_sign_fn(&sk);

        let mut log = AuditLog::new(&log_path, session_id, manifest_hash).unwrap();
        assert_eq!(log.entry_count(), 0);

        log.append(sample_data_flow(0), sign_fn.as_ref()).unwrap();
        assert_eq!(log.entry_count(), 1);

        for i in 1..50 {
            log.append(sample_data_flow(i), sign_fn.as_ref()).unwrap();
        }
        assert_eq!(log.entry_count(), 50);
    }
}
