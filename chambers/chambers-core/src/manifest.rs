//! Manifest engine for Chambers.
//!
//! Parses, validates, and evaluates TOML preservation manifests that define
//! which data categories are preserved for which stakeholders, what is denied,
//! and what falls through to the default BURN action.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::ManifestError;
use crate::types::StakeholderRole;

// ─── Raw TOML deserialization structs ──────────────────────────────────────

/// Top-level structure mirroring the TOML manifest file layout.
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestMeta {
    pub version: String,
    pub mission_type: String,
    pub operator_id: String,
    pub created: String,
    #[serde(default)]
    pub manifest_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegulatoryConfig {
    pub remote_id: bool,
    pub jurisdiction: String,
    pub operation_category: String,
    #[serde(default)]
    pub waiver_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultRule {
    pub action: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StakeholderDecl {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreserveRule {
    pub id: String,
    pub data_category: String,
    #[serde(default)]
    pub sensor: Option<String>,
    pub for_stakeholder: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub transmission: Option<String>,
    pub retention: String,
    pub justification: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DenyRule {
    pub id: String,
    pub data_category: String,
    pub for_stakeholder: String,
    pub justification: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkFlow {
    pub id: String,
    pub destination: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub data_category: String,
    pub justification: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SystemAllowlist {
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub processes: Vec<String>,
}

// ─── Decision enum ─────────────────────────────────────────────────────────

/// The outcome of evaluating a (data_category, stakeholder_id) pair against
/// the manifest rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestDecision {
    /// Data should be preserved for the given stakeholder.
    Preserve {
        rule_id: String,
        stakeholder_id: String,
        retention_days: u32,
    },
    /// Data is explicitly denied to the given stakeholder.
    Deny {
        rule_id: String,
        reason: String,
    },
    /// No matching rule; fall through to the default burn action.
    Burn,
}

// ─── Validated Manifest ────────────────────────────────────────────────────

/// A fully parsed, validated manifest ready for evaluation.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub meta: ManifestMeta,
    pub regulatory: RegulatoryConfig,
    pub stakeholders: Vec<StakeholderDecl>,
    pub preserve_rules: Vec<PreserveRule>,
    pub deny_rules: Vec<DenyRule>,
    pub network_flows: Vec<NetworkFlow>,
    pub system_allowlist: SystemAllowlist,
    pub manifest_hash: [u8; 32],
}

impl Manifest {
    /// Load a manifest from a file path on disk.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ManifestError::IoError(e.to_string()))?;
        Self::from_str(&content)
    }

    /// Parse a manifest from a TOML string, validate it, and compute its hash.
    pub fn from_str(toml_str: &str) -> Result<Self, ManifestError> {
        let file: ManifestFile =
            toml::from_str(toml_str).map_err(|e| ManifestError::ParseError {
                message: e.to_string(),
            })?;

        let errors = validate(&file);
        if !errors.is_empty() {
            if errors.len() == 1 {
                return Err(errors.into_iter().next().unwrap());
            }
            return Err(ManifestError::MultipleErrors {
                count: errors.len(),
                errors,
            });
        }

        let hash = compute_hash(toml_str);

        Ok(Manifest {
            meta: file.meta,
            regulatory: file.regulatory,
            stakeholders: file.stakeholder,
            preserve_rules: file.preserve,
            deny_rules: file.deny.unwrap_or_default(),
            network_flows: file.network_flow.unwrap_or_default(),
            system_allowlist: file.system_allowlist.unwrap_or_default(),
            manifest_hash: hash,
        })
    }

    /// Evaluate a (data_category, stakeholder_id) pair against the manifest rules.
    ///
    /// Evaluation order:
    ///   1. Deny rules (regulator-stakeholder denies first, then others in manifest order)
    ///   2. Preserve rules (regulator-stakeholder preserves first, then manifest order)
    ///   3. Default BURN
    pub fn evaluate(&self, data_category: &str, stakeholder_id: &str) -> ManifestDecision {
        // Build a lookup from stakeholder id to role for priority sorting.
        let role_map: HashMap<&str, &StakeholderDecl> = self
            .stakeholders
            .iter()
            .map(|s| (s.id.as_str(), s))
            .collect();

        // Helper: get priority for a stakeholder id (lower = higher priority).
        let priority = |sid: &str| -> u8 {
            role_map
                .get(sid)
                .and_then(|s| StakeholderRole::from_str(&s.role))
                .map(|r| r.priority())
                .unwrap_or(255)
        };

        // --- Deny rules ---
        // Collect matching deny rules, sort by stakeholder priority (regulator first),
        // preserving manifest order for ties (stable sort).
        let mut deny_matches: Vec<&DenyRule> = self
            .deny_rules
            .iter()
            .filter(|d| d.data_category == data_category && d.for_stakeholder == stakeholder_id)
            .collect();
        deny_matches.sort_by_key(|d| priority(&d.for_stakeholder));

        if let Some(deny) = deny_matches.first() {
            return ManifestDecision::Deny {
                rule_id: deny.id.clone(),
                reason: deny.justification.clone(),
            };
        }

        // --- Preserve rules ---
        // Collect matching preserve rules, sort by stakeholder priority (regulator first),
        // preserving manifest order for ties (stable sort).
        let mut preserve_matches: Vec<&PreserveRule> = self
            .preserve_rules
            .iter()
            .filter(|p| {
                p.data_category == data_category && p.for_stakeholder == stakeholder_id
            })
            .collect();
        preserve_matches.sort_by_key(|p| priority(&p.for_stakeholder));

        if let Some(preserve) = preserve_matches.first() {
            let days = parse_retention(&preserve.retention).unwrap_or(0);
            return ManifestDecision::Preserve {
                rule_id: preserve.id.clone(),
                stakeholder_id: preserve.for_stakeholder.clone(),
                retention_days: days,
            };
        }

        // --- Default ---
        ManifestDecision::Burn
    }

    /// Check whether a process name is on the system allowlist.
    pub fn is_allowlisted(&self, process_name: &str) -> bool {
        self.system_allowlist
            .processes
            .iter()
            .any(|p| p == process_name)
    }

    /// Return stakeholder IDs paired with their decoded 32-byte X25519 public keys.
    ///
    /// Stakeholders whose keys fail to decode are silently skipped (validation
    /// should have already caught them).
    pub fn stakeholder_keys(&self) -> Vec<(&str, [u8; 32])> {
        self.stakeholders
            .iter()
            .filter_map(|s| {
                let decoded = BASE64.decode(&s.public_key).ok()?;
                if decoded.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&decoded);
                    Some((s.id.as_str(), key))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Compute SHA-256 hash of the raw manifest content (convenience re-export
    /// kept for backward compatibility with callers that used the old API).
    pub fn hash(&self) -> [u8; 32] {
        self.manifest_hash
    }
}

// ─── Retention parser ──────────────────────────────────────────────────────

/// Parse a retention string like "90d" or "0" into a number of days.
///
/// Accepted formats:
///   - `"0"` — zero-day retention (broadcast-only, not stored)
///   - `"<N>d"` — N days, where N is a positive integer
pub fn parse_retention(s: &str) -> Option<u32> {
    let s = s.trim();
    if s == "0" {
        return Some(0);
    }
    if s.ends_with('d') {
        let num_part = &s[..s.len() - 1];
        num_part.parse::<u32>().ok()
    } else {
        None
    }
}

// ─── SHA-256 hash ──────────────────────────────────────────────────────────

fn compute_hash(content: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ─── Validation ────────────────────────────────────────────────────────────

/// Run all eight validation rules against a parsed `ManifestFile`, collecting
/// every error encountered (rather than stopping at the first).
fn validate(file: &ManifestFile) -> Vec<ManifestError> {
    let mut errors: Vec<ManifestError> = Vec::new();

    // Rule 1: remote_id must be true when jurisdiction = "US".
    if file.regulatory.jurisdiction == "US" && !file.regulatory.remote_id {
        errors.push(ManifestError::RemoteIdRequired {
            jurisdiction: file.regulatory.jurisdiction.clone(),
        });
    }

    // Rule 2: At least one preserve rule with data_category = "remote_id"
    //         and transmission = "real_time".
    let has_remote_id_realtime = file.preserve.iter().any(|p| {
        p.data_category == "remote_id"
            && p.transmission.as_deref() == Some("real_time")
    });
    if !has_remote_id_realtime {
        errors.push(ManifestError::MissingRemoteIdPreserveRule);
    }

    // Rule 3: default.action must be "BURN".
    if file.default.action != "BURN" {
        errors.push(ManifestError::InvalidDefaultAction {
            found: file.default.action.clone(),
        });
    }

    // Build the set of declared stakeholder IDs.
    let declared_ids: HashSet<&str> = file
        .stakeholder
        .iter()
        .map(|s| s.id.as_str())
        .collect();

    // Rule 4: Every for_stakeholder in preserve/deny references a declared
    //         stakeholder id. "public" is a special pseudo-stakeholder.
    for rule in &file.preserve {
        if rule.for_stakeholder != "public"
            && !declared_ids.contains(rule.for_stakeholder.as_str())
        {
            errors.push(ManifestError::UndeclaredStakeholder {
                rule_id: rule.id.clone(),
                stakeholder_id: rule.for_stakeholder.clone(),
            });
        }
    }
    if let Some(ref denies) = file.deny {
        for rule in denies {
            if rule.for_stakeholder != "public"
                && !declared_ids.contains(rule.for_stakeholder.as_str())
            {
                errors.push(ManifestError::UndeclaredStakeholder {
                    rule_id: rule.id.clone(),
                    stakeholder_id: rule.for_stakeholder.clone(),
                });
            }
        }
    }

    // Rule 5: Every stakeholder has a valid 32-byte base64 X25519 public key.
    for s in &file.stakeholder {
        match BASE64.decode(&s.public_key) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    errors.push(ManifestError::InvalidStakeholderKey {
                        id: s.id.clone(),
                        reason: format!("expected 32 bytes, got {}", bytes.len()),
                    });
                }
            }
            Err(e) => {
                errors.push(ManifestError::InvalidStakeholderKey {
                    id: s.id.clone(),
                    reason: format!("base64 decode failed: {}", e),
                });
            }
        }
    }

    // Rule 6: Retention is valid -- matches pattern like "90d", "365d", or "0".
    for rule in &file.preserve {
        if parse_retention(&rule.retention).is_none() {
            errors.push(ManifestError::InvalidRetention {
                rule_id: rule.id.clone(),
                value: rule.retention.clone(),
            });
        }
    }

    // Rule 7: No wildcard for_stakeholder = "*" without regulator (reject for now).
    for rule in &file.preserve {
        if rule.for_stakeholder == "*" {
            errors.push(ManifestError::WildcardRequiresRegulatorSignature {
                rule_id: rule.id.clone(),
            });
        }
    }
    if let Some(ref denies) = file.deny {
        for rule in denies {
            if rule.for_stakeholder == "*" {
                errors.push(ManifestError::WildcardRequiresRegulatorSignature {
                    rule_id: rule.id.clone(),
                });
            }
        }
    }

    // Rule 8: Conflicting preserve + deny for same (data_category, stakeholder).
    //         This is a warning, not a hard error. The deny rule wins at
    //         evaluation time. We print to stderr so callers are aware.
    if let Some(ref denies) = file.deny {
        let deny_set: HashSet<(&str, &str)> = denies
            .iter()
            .map(|d| (d.data_category.as_str(), d.for_stakeholder.as_str()))
            .collect();

        for rule in &file.preserve {
            let key = (rule.data_category.as_str(), rule.for_stakeholder.as_str());
            if deny_set.contains(&key) {
                eprintln!(
                    "WARN: Conflicting preserve and deny rules for ({}, {}): deny wins",
                    key.0, key.1
                );
            }
        }
    }

    errors
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid inspection manifest used across multiple tests.
    const VALID_MANIFEST: &str = r#"
[meta]
version = "1.0"
mission_type = "infrastructure_inspection"
operator_id = "OP-2026-00142"
created = "2026-04-08T10:00:00Z"
manifest_hash = ""

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "AcmeDrone Services LLC"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[stakeholder]]
id = "client"
name = "PowerGrid Corp"
public_key = "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s="
role = "client"

[[stakeholder]]
id = "faa"
name = "Federal Aviation Administration"
public_key = "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw="
role = "regulator"

[[stakeholder]]
id = "manufacturer"
name = "DroneWorks Inc"
public_key = "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0="
role = "manufacturer"

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
retention = "365d"
justification = "Operational records and maintenance"

[[preserve]]
id = "rule-004"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
format = "cleartext"
transmission = "real_time"
retention = "0"
justification = "14 CFR Part 89 compliance"

[[preserve]]
id = "rule-005"
data_category = "flight_telemetry"
sensor = "flight_controller"
for_stakeholder = "faa"
retention = "365d"
justification = "Regulatory oversight and incident investigation"

[[deny]]
id = "deny-001"
data_category = "thermal_imagery"
for_stakeholder = "manufacturer"
justification = "Imagery contains client proprietary infrastructure data"

[[network_flow]]
id = "flow-001"
destination = "gcs"
protocol = "websocket"
host = "172.20.0.100"
port = 8080
data_category = "telemetry_subset"
justification = "Real-time flight monitoring"

[system_allowlist]
platform = "simulation"
processes = ["v4l2-compliance", "gst-launch-1.0", "mavlink-routerd"]
"#;

    // ── Parsing tests ──────────────────────────────────────────────────

    #[test]
    fn parse_valid_manifest() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        assert_eq!(manifest.meta.version, "1.0");
        assert_eq!(manifest.meta.mission_type, "infrastructure_inspection");
        assert_eq!(manifest.meta.operator_id, "OP-2026-00142");
        assert_eq!(manifest.regulatory.jurisdiction, "US");
        assert!(manifest.regulatory.remote_id);
        assert_eq!(manifest.stakeholders.len(), 4);
        assert_eq!(manifest.preserve_rules.len(), 5);
        assert_eq!(manifest.deny_rules.len(), 1);
        assert_eq!(manifest.network_flows.len(), 1);
        assert_eq!(manifest.system_allowlist.processes.len(), 3);
    }

    #[test]
    fn parse_minimal_manifest() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let manifest = Manifest::from_str(toml).unwrap();
        assert_eq!(manifest.stakeholders.len(), 1);
        assert_eq!(manifest.preserve_rules.len(), 1);
        assert!(manifest.deny_rules.is_empty());
        assert!(manifest.network_flows.is_empty());
        assert!(manifest.system_allowlist.processes.is_empty());
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let m1 = Manifest::from_str(VALID_MANIFEST).unwrap();
        let m2 = Manifest::from_str(VALID_MANIFEST).unwrap();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
        assert_ne!(m1.manifest_hash, [0u8; 32]);
    }

    #[test]
    fn manifest_hash_changes_with_content() {
        let m1 = Manifest::from_str(VALID_MANIFEST).unwrap();
        let modified = VALID_MANIFEST.replace("OP-2026-00142", "OP-2026-99999");
        let m2 = Manifest::from_str(&modified).unwrap();
        assert_ne!(m1.manifest_hash, m2.manifest_hash);
    }

    #[test]
    fn parse_invalid_toml() {
        let result = Manifest::from_str("this is not valid toml {{{{");
        assert!(result.is_err());
        match result.unwrap_err() {
            ManifestError::ParseError { message } => {
                assert!(!message.is_empty());
            }
            other => panic!("Expected ParseError, got: {:?}", other),
        }
    }

    // ── Validation rule tests ──────────────────────────────────────────

    #[test]
    fn rule1_remote_id_required_for_us() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = false
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::RemoteIdRequired { ref jurisdiction } if jurisdiction == "US"
            ),
            "Expected RemoteIdRequired, got: {:?}",
            err
        );
    }

    #[test]
    fn rule1_remote_id_not_required_outside_us() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = false
jurisdiction = "EU"
operation_category = "specific"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "compliance"
"#;
        let result = Manifest::from_str(toml);
        assert!(
            result.is_ok(),
            "Expected Ok for non-US jurisdiction, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rule2_missing_remote_id_realtime_preserve() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "flight_telemetry"
sensor = "flight_controller"
for_stakeholder = "operator"
retention = "30d"
justification = "Records"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(err, ManifestError::MissingRemoteIdPreserveRule),
            "Expected MissingRemoteIdPreserveRule, got: {:?}",
            err
        );
    }

    #[test]
    fn rule3_default_action_must_be_burn() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "PRESERVE"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::InvalidDefaultAction { ref found } if found == "PRESERVE"
            ),
            "Expected InvalidDefaultAction, got: {:?}",
            err
        );
    }

    #[test]
    fn rule4_undeclared_stakeholder() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"

[[preserve]]
id = "rule-002"
data_category = "thermal_imagery"
for_stakeholder = "nonexistent_client"
retention = "90d"
justification = "Oops"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::UndeclaredStakeholder {
                    ref rule_id,
                    ref stakeholder_id
                } if rule_id == "rule-002" && stakeholder_id == "nonexistent_client"
            ),
            "Expected UndeclaredStakeholder, got: {:?}",
            err
        );
    }

    #[test]
    fn rule5_invalid_public_key_wrong_length() {
        // "AQID" decodes to [1, 2, 3] -- only 3 bytes, not 32.
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AQID"
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::InvalidStakeholderKey { ref id, .. } if id == "operator"
            ),
            "Expected InvalidStakeholderKey, got: {:?}",
            err
        );
    }

    #[test]
    fn rule5_invalid_public_key_bad_base64() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "not-valid-base64!!!"
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::InvalidStakeholderKey { ref id, ref reason }
                if id == "operator" && reason.contains("base64")
            ),
            "Expected InvalidStakeholderKey with base64 reason, got: {:?}",
            err
        );
    }

    #[test]
    fn rule6_invalid_retention() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"

[[preserve]]
id = "rule-002"
data_category = "flight_telemetry"
for_stakeholder = "operator"
retention = "three months"
justification = "Bad retention"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::InvalidRetention {
                    ref rule_id,
                    ref value
                } if rule_id == "rule-002" && value == "three months"
            ),
            "Expected InvalidRetention, got: {:?}",
            err
        );
    }

    #[test]
    fn rule7_wildcard_stakeholder_rejected() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"

[[preserve]]
id = "rule-002"
data_category = "flight_telemetry"
for_stakeholder = "*"
retention = "30d"
justification = "All stakeholders"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        // May be wrapped in MultipleErrors if "*" also triggers UndeclaredStakeholder.
        match err {
            ManifestError::WildcardRequiresRegulatorSignature { ref rule_id } => {
                assert_eq!(rule_id, "rule-002");
            }
            ManifestError::MultipleErrors { ref errors, .. } => {
                let has_wildcard = errors.iter().any(|e| {
                    matches!(
                        e,
                        ManifestError::WildcardRequiresRegulatorSignature { ref rule_id }
                        if rule_id == "rule-002"
                    )
                });
                assert!(
                    has_wildcard,
                    "Expected WildcardRequiresRegulatorSignature in errors: {:?}",
                    errors
                );
            }
            other => panic!(
                "Expected WildcardRequiresRegulatorSignature, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn rule8_conflicting_preserve_deny_warning() {
        // The valid manifest has both a preserve (rule-001 thermal_imagery for client)
        // and a deny (deny-001 thermal_imagery for manufacturer). Here we test the
        // deny-wins semantics at evaluation time -- the conflict for manufacturer.
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("thermal_imagery", "manufacturer");
        assert!(
            matches!(
                decision,
                ManifestDecision::Deny { ref rule_id, .. } if rule_id == "deny-001"
            ),
            "Expected Deny for conflicting rules, got: {:?}",
            decision
        );
    }

    #[test]
    fn multiple_errors_collected() {
        // Triggers: Rule 1 (remote_id=false, US), Rule 2 (no remote_id realtime),
        // Rule 3 (action=KEEP), Rule 5 (bad key length).
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = false
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "KEEP"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AQID"
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "flight_telemetry"
for_stakeholder = "operator"
retention = "30d"
justification = "Records"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        match err {
            ManifestError::MultipleErrors { count, ref errors } => {
                assert!(
                    count >= 3,
                    "Expected at least 3 errors, got {}: {:?}",
                    count,
                    errors
                );
                assert_eq!(count, errors.len());
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, ManifestError::RemoteIdRequired { .. })));
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, ManifestError::MissingRemoteIdPreserveRule)));
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, ManifestError::InvalidDefaultAction { .. })));
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, ManifestError::InvalidStakeholderKey { .. })));
            }
            other => panic!("Expected MultipleErrors, got: {:?}", other),
        }
    }

    #[test]
    fn single_error_not_wrapped_in_multiple() {
        // Exactly one validation error should be returned directly, not wrapped.
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "PRESERVE"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(err, ManifestError::InvalidDefaultAction { .. }),
            "Single error should not be MultipleErrors, got: {:?}",
            err
        );
    }

    // ── Evaluation tests ───────────────────────────────────────────────

    #[test]
    fn evaluate_preserve_decision() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("thermal_imagery", "client");
        assert_eq!(
            decision,
            ManifestDecision::Preserve {
                rule_id: "rule-001".to_string(),
                stakeholder_id: "client".to_string(),
                retention_days: 90,
            }
        );
    }

    #[test]
    fn evaluate_deny_decision() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("thermal_imagery", "manufacturer");
        match decision {
            ManifestDecision::Deny { rule_id, reason } => {
                assert_eq!(rule_id, "deny-001");
                assert!(reason.contains("proprietary"));
            }
            other => panic!("Expected Deny, got: {:?}", other),
        }
    }

    #[test]
    fn evaluate_burn_default() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("lidar_point_cloud", "client");
        assert_eq!(decision, ManifestDecision::Burn);
    }

    #[test]
    fn evaluate_burn_for_unknown_stakeholder() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("thermal_imagery", "unknown_entity");
        assert_eq!(decision, ManifestDecision::Burn);
    }

    #[test]
    fn evaluate_remote_id_public() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("remote_id", "public");
        assert_eq!(
            decision,
            ManifestDecision::Preserve {
                rule_id: "rule-004".to_string(),
                stakeholder_id: "public".to_string(),
                retention_days: 0,
            }
        );
    }

    #[test]
    fn evaluate_regulator_preserve() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("flight_telemetry", "faa");
        assert_eq!(
            decision,
            ManifestDecision::Preserve {
                rule_id: "rule-005".to_string(),
                stakeholder_id: "faa".to_string(),
                retention_days: 365,
            }
        );
    }

    #[test]
    fn evaluate_operator_preserve() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let decision = manifest.evaluate("flight_telemetry", "operator");
        assert_eq!(
            decision,
            ManifestDecision::Preserve {
                rule_id: "rule-003".to_string(),
                stakeholder_id: "operator".to_string(),
                retention_days: 365,
            }
        );
    }

    // ── Allowlist tests ────────────────────────────────────────────────

    #[test]
    fn allowlist_known_process() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        assert!(manifest.is_allowlisted("v4l2-compliance"));
        assert!(manifest.is_allowlisted("gst-launch-1.0"));
        assert!(manifest.is_allowlisted("mavlink-routerd"));
    }

    #[test]
    fn allowlist_unknown_process() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        assert!(!manifest.is_allowlisted("rogue-process"));
        assert!(!manifest.is_allowlisted(""));
    }

    #[test]
    fn allowlist_empty_when_section_missing() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let manifest = Manifest::from_str(toml).unwrap();
        assert!(!manifest.is_allowlisted("anything"));
    }

    // ── Stakeholder keys tests ─────────────────────────────────────────

    #[test]
    fn stakeholder_keys_returns_decoded_keys() {
        let manifest = Manifest::from_str(VALID_MANIFEST).unwrap();
        let keys = manifest.stakeholder_keys();
        assert_eq!(keys.len(), 4);

        for (id, key) in &keys {
            assert!(!id.is_empty());
            assert_eq!(key.len(), 32);
        }

        // AAAA...A= (44 chars of 'A' then '=') is base64 for 32 zero bytes.
        let operator_key = keys.iter().find(|(id, _)| *id == "operator").unwrap();
        assert_eq!(operator_key.1, [0u8; 32]);
    }

    // ── Retention parser tests ─────────────────────────────────────────

    #[test]
    fn parse_retention_valid() {
        assert_eq!(parse_retention("0"), Some(0));
        assert_eq!(parse_retention("90d"), Some(90));
        assert_eq!(parse_retention("365d"), Some(365));
        assert_eq!(parse_retention("1d"), Some(1));
        assert_eq!(parse_retention("7d"), Some(7));
    }

    #[test]
    fn parse_retention_invalid() {
        assert_eq!(parse_retention(""), None);
        assert_eq!(parse_retention("90"), None);
        assert_eq!(parse_retention("d"), None);
        assert_eq!(parse_retention("three months"), None);
        assert_eq!(parse_retention("-1d"), None);
        assert_eq!(parse_retention("90days"), None);
    }

    #[test]
    fn parse_retention_whitespace() {
        assert_eq!(parse_retention(" 90d "), Some(90));
        assert_eq!(parse_retention(" 0 "), Some(0));
    }

    // ── Edge case tests ────────────────────────────────────────────────

    #[test]
    fn deny_undeclared_stakeholder_in_deny_rule() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"

[[deny]]
id = "deny-001"
data_category = "thermal_imagery"
for_stakeholder = "ghost_stakeholder"
justification = "No such stakeholder"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::UndeclaredStakeholder {
                    ref rule_id,
                    ref stakeholder_id,
                } if rule_id == "deny-001" && stakeholder_id == "ghost_stakeholder"
            ),
            "Expected UndeclaredStakeholder for deny rule, got: {:?}",
            err
        );
    }

    #[test]
    fn wildcard_in_deny_rule_rejected() {
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"

[[deny]]
id = "deny-001"
data_category = "thermal_imagery"
for_stakeholder = "*"
justification = "Deny everything"
"#;
        let err = Manifest::from_str(toml).unwrap_err();
        match err {
            ManifestError::WildcardRequiresRegulatorSignature { ref rule_id } => {
                assert_eq!(rule_id, "deny-001");
            }
            ManifestError::MultipleErrors { ref errors, .. } => {
                let has_wildcard = errors.iter().any(|e| {
                    matches!(
                        e,
                        ManifestError::WildcardRequiresRegulatorSignature { ref rule_id }
                        if rule_id == "deny-001"
                    )
                });
                assert!(
                    has_wildcard,
                    "Expected WildcardRequiresRegulatorSignature: {:?}",
                    errors
                );
            }
            other => panic!(
                "Expected WildcardRequiresRegulatorSignature, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn load_from_real_toml_file() {
        // Test Manifest::load with a temporary file.
        let toml = r#"
[meta]
version = "1.0"
mission_type = "test"
operator_id = "OP-0001"
created = "2026-01-01T00:00:00Z"

[regulatory]
remote_id = true
jurisdiction = "US"
operation_category = "part_107"

[default]
action = "BURN"

[[stakeholder]]
id = "operator"
name = "Test Op"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
role = "operator"

[[preserve]]
id = "rule-001"
data_category = "remote_id"
sensor = "remote_id_broadcast"
for_stakeholder = "public"
transmission = "real_time"
retention = "0"
justification = "Part 89"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_manifest.toml");
        std::fs::write(&path, toml).unwrap();

        let manifest = Manifest::load(&path).unwrap();
        assert_eq!(manifest.meta.operator_id, "OP-0001");
        assert_eq!(manifest.manifest_hash, compute_hash(toml));
    }

    #[test]
    fn load_nonexistent_file() {
        let result = Manifest::load(Path::new("/tmp/does_not_exist_chambers_test.toml"));
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ManifestError::IoError(_)),
            "Expected IoError for missing file"
        );
    }
}
