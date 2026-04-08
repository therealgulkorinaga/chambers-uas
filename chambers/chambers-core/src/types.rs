use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

// ─── Session types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    pub fn generate() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPublicKey {
    pub sign: Vec<u8>,  // Ed25519 public key bytes (32)
    pub enc: Vec<u8>,   // X25519 public key bytes (32)
}

impl SessionPublicKey {
    pub fn sign_hex(&self) -> String {
        hex::encode(&self.sign)
    }

    pub fn enc_hex(&self) -> String {
        hex::encode(&self.enc)
    }
}

// Inline hex encoding since we don't want to add another dep just for this
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ─── Session state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Idle,
    PreFlight,
    InFlight,
    PostFlight,
    Burning,
    Error,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "IDLE"),
            Self::PreFlight => write!(f, "PRE_FLIGHT"),
            Self::InFlight => write!(f, "IN_FLIGHT"),
            Self::PostFlight => write!(f, "POST_FLIGHT"),
            Self::Burning => write!(f, "BURNING"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ─── Data flow types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DataSource {
    Camera { device: String },
    Mavlink { msg_id: u32, msg_name: String },
    Lidar,
    Imu,
    Gps,
    RemoteId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DataDestination {
    SessionStorage,
    Preserved { stakeholder: String },
    Burn,
    GcsForward,
    Broadcast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub source: DataSource,
    pub timestamp: DateTime<Utc>,
    pub bytes: u64,
    pub data_category: DataCategory,
    pub metadata: HashMap<String, String>,
}

// ─── Event label (Section 5.4) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLabel {
    pub timestamp: DateTime<Utc>,
    pub source: DataSource,
    pub process_id: u32,
    pub process_name: String,
    pub byte_count: u64,
    pub destination: DataDestination,
    pub manifest_rule: Option<String>,
    pub sequence: u64,
}

impl EventLabel {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

// ─── Data categories ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataCategory {
    ThermalImagery,
    EoImagery,
    FlightTelemetry,
    RemoteId,
    LidarPointCloud,
    MotorActuator,
    RcInput,
    SystemStatus,
    MissionData,
    AuditLog,
    AnomalyLog,
    Custom(String),
}

impl DataCategory {
    pub fn from_str(s: &str) -> Self {
        match s {
            "thermal_imagery" => Self::ThermalImagery,
            "eo_imagery" => Self::EoImagery,
            "flight_telemetry" => Self::FlightTelemetry,
            "remote_id" => Self::RemoteId,
            "lidar_point_cloud" => Self::LidarPointCloud,
            "motor_actuator" => Self::MotorActuator,
            "rc_input" => Self::RcInput,
            "system_status" => Self::SystemStatus,
            "mission_data" => Self::MissionData,
            "audit_log" => Self::AuditLog,
            "anomaly_log" => Self::AnomalyLog,
            other => Self::Custom(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::ThermalImagery => "thermal_imagery",
            Self::EoImagery => "eo_imagery",
            Self::FlightTelemetry => "flight_telemetry",
            Self::RemoteId => "remote_id",
            Self::LidarPointCloud => "lidar_point_cloud",
            Self::MotorActuator => "motor_actuator",
            Self::RcInput => "rc_input",
            Self::SystemStatus => "system_status",
            Self::MissionData => "mission_data",
            Self::AuditLog => "audit_log",
            Self::AnomalyLog => "anomaly_log",
            Self::Custom(s) => s.as_str(),
        }
    }
}

// ─── Stakeholder types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeholderRole {
    Operator,
    Client,
    Regulator,
    Manufacturer,
    Public,
}

impl StakeholderRole {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "operator" => Some(Self::Operator),
            "client" => Some(Self::Client),
            "regulator" => Some(Self::Regulator),
            "manufacturer" => Some(Self::Manufacturer),
            "public" => Some(Self::Public),
            _ => None,
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            Self::Regulator => 0,  // Highest priority
            Self::Operator => 1,
            Self::Client => 2,
            Self::Manufacturer => 3,
            Self::Public => 4,
        }
    }
}

// ─── Severity ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// ─── Time range ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeRange {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, t: DateTime<Utc>) -> bool {
        t >= self.start && t <= self.end
    }

    pub fn around(center: DateTime<Utc>, before: Duration, after: Duration) -> Self {
        Self {
            start: center - before,
            end: center + after,
        }
    }
}

// ─── Sealed event types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SealedEventType {
    AirspaceIncursion,
    NearMiss,
    EmergencyLanding,
    GeofenceViolation,
    PayloadAnomaly,
}

impl fmt::Display for SealedEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AirspaceIncursion => write!(f, "AIRSPACE_INCURSION"),
            Self::NearMiss => write!(f, "NEAR_MISS"),
            Self::EmergencyLanding => write!(f, "EMERGENCY_LANDING"),
            Self::GeofenceViolation => write!(f, "GEOFENCE_VIOLATION"),
            Self::PayloadAnomaly => write!(f, "PAYLOAD_ANOMALY"),
        }
    }
}

// ─── Anomaly patterns ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyPattern {
    /// ANM-001: Camera buffer read by undeclared process
    UndeclaredCameraAccess,
    /// ANM-002: Camera reads continue after motor disarm
    PostDisarmCameraAccess,
    /// ANM-003: Reads at unexpected resolution/framerate
    ResolutionMismatch,
    /// ANM-004: Reads to non-session-encrypted memory region
    UndeclaredMemoryDestination,
    /// ANM-005: Burst reads correlated with cellular modem activity
    BurstNetworkCorrelation,
    /// ANM-006: Camera accessed during firmware update window
    FirmwareUpdateCameraAccess,
}

impl AnomalyPattern {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UndeclaredCameraAccess => "ANM-001",
            Self::PostDisarmCameraAccess => "ANM-002",
            Self::ResolutionMismatch => "ANM-003",
            Self::UndeclaredMemoryDestination => "ANM-004",
            Self::BurstNetworkCorrelation => "ANM-005",
            Self::FirmwareUpdateCameraAccess => "ANM-006",
        }
    }

    pub fn default_severity(&self) -> Severity {
        match self {
            Self::UndeclaredCameraAccess => Severity::High,
            Self::PostDisarmCameraAccess => Severity::High,
            Self::ResolutionMismatch => Severity::Medium,
            Self::UndeclaredMemoryDestination => Severity::High,
            Self::BurstNetworkCorrelation => Severity::Critical,
            Self::FirmwareUpdateCameraAccess => Severity::High,
        }
    }
}

// ─── Firewall types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

// ─── Burn types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayerStatus {
    Pass,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerResult {
    pub layer: u8,
    pub name: String,
    pub status: LayerStatus,
    pub details: String,
    pub duration_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnReport {
    pub session_id: SessionId,
    pub burn_start: DateTime<Utc>,
    pub burn_end: DateTime<Utc>,
    pub layers: Vec<LayerResult>,
    pub all_passed: bool,
    pub signature: Vec<u8>,
}

// ─── Preservation scope ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservationScope {
    pub time_range: TimeRange,
    pub data_categories: Vec<DataCategory>,
    pub stakeholders: Vec<String>,
    pub retention_days: u32,
}

// ─── Camera frame metadata ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraFrameMetadata {
    pub frame_index: u64,
    pub timestamp: DateTime<Utc>,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub bytes: usize,
    pub device: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_display() {
        let id = SessionId([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);
        assert_eq!(id.to_string(), "0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn data_category_roundtrip() {
        let cat = DataCategory::from_str("thermal_imagery");
        assert_eq!(cat, DataCategory::ThermalImagery);
        assert_eq!(cat.as_str(), "thermal_imagery");
    }

    #[test]
    fn time_range_contains() {
        let now = Utc::now();
        let range = TimeRange::around(now, Duration::seconds(30), Duration::seconds(30));
        assert!(range.contains(now));
        assert!(range.contains(now - Duration::seconds(15)));
        assert!(!range.contains(now - Duration::seconds(60)));
    }

    #[test]
    fn stakeholder_priority_order() {
        assert!(StakeholderRole::Regulator.priority() < StakeholderRole::Operator.priority());
        assert!(StakeholderRole::Operator.priority() < StakeholderRole::Client.priority());
    }

    #[test]
    fn anomaly_pattern_codes() {
        assert_eq!(AnomalyPattern::UndeclaredCameraAccess.code(), "ANM-001");
        assert_eq!(AnomalyPattern::BurstNetworkCorrelation.code(), "ANM-005");
    }
}
