use crate::crypto::SessionKeys;
use crate::error::ProxyError;
use crate::types::*;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn, trace};

// ─── MAVLink message categories ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MavlinkCategory {
    PositionNavigation,
    Attitude,
    SystemStatus,
    Mission,
    MotorActuator,
    RcInput,
    Parameter,
    CommandAck,
    Heartbeat,
    ObstacleDistance,
    StatusText,
    Battery,
    Other,
}

impl MavlinkCategory {
    /// Classify a MAVLink message by its ID.
    /// Uses PX4/ArduPilot common message IDs.
    pub fn from_msg_id(msg_id: u32) -> Self {
        match msg_id {
            0 => Self::Heartbeat,                    // HEARTBEAT
            1 => Self::SystemStatus,                 // SYS_STATUS
            24 => Self::PositionNavigation,          // GPS_RAW_INT
            30 => Self::Attitude,                    // ATTITUDE
            31 => Self::Attitude,                    // ATTITUDE_QUATERNION
            32 => Self::PositionNavigation,          // LOCAL_POSITION_NED
            33 => Self::PositionNavigation,          // GLOBAL_POSITION_INT
            36 => Self::MotorActuator,               // SERVO_OUTPUT_RAW
            42 => Self::Mission,                     // MISSION_CURRENT
            46 => Self::Mission,                     // MISSION_ITEM_REACHED
            65 => Self::RcInput,                     // RC_CHANNELS
            76 => Self::CommandAck,                  // COMMAND_LONG
            77 => Self::CommandAck,                  // COMMAND_ACK
            147 => Self::Battery,                    // BATTERY_STATUS
            253 => Self::StatusText,                 // STATUSTEXT
            328 => Self::ObstacleDistance,            // OBSTACLE_DISTANCE
            _ => Self::Other,
        }
    }

    pub fn default_data_category(&self) -> DataCategory {
        match self {
            Self::PositionNavigation | Self::Heartbeat => DataCategory::FlightTelemetry,
            Self::Attitude => DataCategory::FlightTelemetry,
            Self::SystemStatus | Self::Battery => DataCategory::SystemStatus,
            Self::Mission => DataCategory::MissionData,
            Self::MotorActuator => DataCategory::MotorActuator,
            Self::RcInput => DataCategory::RcInput,
            Self::StatusText => DataCategory::SystemStatus,
            Self::ObstacleDistance => DataCategory::FlightTelemetry,
            _ => DataCategory::FlightTelemetry,
        }
    }
}

// ─── Parsed MAVLink message ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MavlinkMessage {
    pub msg_id: u32,
    pub system_id: u8,
    pub component_id: u8,
    pub sequence: u8,
    pub payload: Vec<u8>,
    pub raw_bytes: Vec<u8>,
    pub category: MavlinkCategory,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Minimal MAVLink v2 parser (header only — we encrypt the full frame).
pub fn parse_mavlink_frame(data: &[u8]) -> Option<MavlinkMessage> {
    if data.len() < 12 {
        return None;
    }

    // MAVLink v2: 0xFD marker
    // MAVLink v1: 0xFE marker
    let (msg_id, sys_id, comp_id, seq) = if data[0] == 0xFD {
        // MAVLink v2
        let payload_len = data[1] as usize;
        if data.len() < 12 + payload_len {
            return None;
        }
        let msg_id = u32::from_le_bytes([data[7], data[8], data[9], 0]);
        (msg_id, data[5], data[6], data[4])
    } else if data[0] == 0xFE {
        // MAVLink v1
        let payload_len = data[1] as usize;
        if data.len() < 8 + payload_len {
            return None;
        }
        (data[5] as u32, data[3], data[4], data[2])
    } else {
        return None;
    };

    Some(MavlinkMessage {
        msg_id,
        system_id: sys_id,
        component_id: comp_id,
        sequence: seq,
        payload: data[10..].to_vec(),
        raw_bytes: data.to_vec(),
        category: MavlinkCategory::from_msg_id(msg_id),
        timestamp: Utc::now(),
    })
}

// ─── Position extraction for sealed events ──────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Position {
    pub lat: f64,  // degrees
    pub lon: f64,  // degrees
    pub alt: f64,  // meters MSL
}

/// Extract position from GLOBAL_POSITION_INT (msg_id 33) payload.
pub fn extract_position(msg: &MavlinkMessage) -> Option<Position> {
    if msg.msg_id != 33 || msg.payload.len() < 28 {
        return None;
    }
    // GLOBAL_POSITION_INT fields (after header):
    // time_boot_ms: u32 (offset 0)
    // lat: i32 (offset 4, in degE7)
    // lon: i32 (offset 8, in degE7)
    // alt: i32 (offset 12, in mm MSL)
    // relative_alt: i32 (offset 16)

    // Note: in a real parser, offsets depend on whether we stripped the header.
    // For simulation, we use a simplified approach.
    let payload = &msg.payload;
    if payload.len() >= 16 {
        let lat_e7 = i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let lon_e7 = i32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let alt_mm = i32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);

        Some(Position {
            lat: lat_e7 as f64 / 1e7,
            lon: lon_e7 as f64 / 1e7,
            alt: alt_mm as f64 / 1000.0,
        })
    } else {
        None
    }
}

/// Extract battery remaining percentage from BATTERY_STATUS (msg_id 147).
pub fn extract_battery_remaining(msg: &MavlinkMessage) -> Option<u8> {
    if msg.msg_id != 147 {
        return None;
    }
    // battery_remaining is at offset 33 in the payload (1 byte, -1 = unknown)
    if msg.payload.len() > 33 {
        let remaining = msg.payload[33] as i8;
        if remaining >= 0 {
            Some(remaining as u8)
        } else {
            None
        }
    } else {
        None
    }
}

/// Extract obstacle min distance from OBSTACLE_DISTANCE (msg_id 328).
pub fn extract_min_obstacle_distance(msg: &MavlinkMessage) -> Option<f64> {
    if msg.msg_id != 328 {
        return None;
    }
    // min_distance is at offset 2 (uint16, in cm)
    if msg.payload.len() >= 4 {
        let min_dist_cm = u16::from_le_bytes([msg.payload[2], msg.payload[3]]);
        Some(min_dist_cm as f64 / 100.0) // Convert to meters
    } else {
        None
    }
}

// ─── MAVLink proxy stats ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyStats {
    pub messages_received: u64,
    pub messages_encrypted: u64,
    pub messages_forwarded_gcs: u64,
    pub bytes_received: u64,
    pub bytes_encrypted: u64,
    pub errors: u64,
    pub heartbeats: u64,
    pub position_updates: u64,
}

// ─── MAVLink proxy ──────────────────────────────────────────────────────────

pub struct MavlinkProxy {
    bind_addr: String,
    px4_addr: String,
    socket: Option<UdpSocket>,
    stats: Arc<ProxyStats>,
    running: Arc<AtomicBool>,
    msg_count: AtomicU64,
}

impl MavlinkProxy {
    pub fn new(bind_addr: &str, px4_addr: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            px4_addr: px4_addr.to_string(),
            socket: None,
            stats: Arc::new(ProxyStats::default()),
            running: Arc::new(AtomicBool::new(false)),
            msg_count: AtomicU64::new(0),
        }
    }

    /// Connect to PX4 SITL via UDP.
    pub fn connect(&mut self) -> Result<(), ProxyError> {
        let socket = UdpSocket::bind(&self.bind_addr).map_err(|e| ProxyError::ConnectionFailed {
            reason: format!("Failed to bind {}: {}", self.bind_addr, e),
        })?;

        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();

        // Send initial packet to PX4 to establish the UDP "connection"
        // (PX4 SITL requires this to start sending telemetry)
        socket.send_to(&[0], &self.px4_addr).map_err(|e| ProxyError::ConnectionFailed {
            reason: format!("Failed to contact PX4 at {}: {}", self.px4_addr, e),
        })?;

        info!("MAVLink proxy connected: {} → {}", self.bind_addr, self.px4_addr);
        self.socket = Some(socket);
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Receive one MAVLink message (blocking with timeout).
    pub fn recv_message(&self) -> Result<Option<MavlinkMessage>, ProxyError> {
        let socket = self.socket.as_ref().ok_or(ProxyError::ConnectionFailed {
            reason: "Not connected".into(),
        })?;

        let mut buf = [0u8; 1024];
        match socket.recv_from(&mut buf) {
            Ok((len, _addr)) => {
                let msg = parse_mavlink_frame(&buf[..len]);
                if msg.is_some() {
                    self.msg_count.fetch_add(1, Ordering::SeqCst);
                }
                Ok(msg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(ProxyError::Io(e)),
        }
    }

    /// Encrypt a MAVLink message and return the encrypted data + event label.
    pub fn encrypt_message(
        &self,
        msg: &MavlinkMessage,
        keys: &SessionKeys,
        msg_index: u64,
    ) -> Result<(crate::crypto::EncryptedData, EventLabel), ProxyError> {
        let label = EventLabel {
            timestamp: msg.timestamp,
            source: DataSource::Mavlink {
                msg_id: msg.msg_id,
                msg_name: format!("MSG_{}", msg.msg_id),
            },
            process_id: std::process::id(),
            process_name: "chambers_mavlink_proxy".to_string(),
            byte_count: msg.raw_bytes.len() as u64,
            destination: DataDestination::SessionStorage,
            manifest_rule: None,
            sequence: msg_index,
        };

        let aad = label.to_bytes();
        let encrypted = keys.encrypt(&aad, &msg.raw_bytes).map_err(ProxyError::Crypto)?;

        Ok((encrypted, label))
    }

    pub fn message_count(&self) -> u64 {
        self.msg_count.load(Ordering::SeqCst)
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_messages() {
        assert_eq!(MavlinkCategory::from_msg_id(0), MavlinkCategory::Heartbeat);
        assert_eq!(MavlinkCategory::from_msg_id(33), MavlinkCategory::PositionNavigation);
        assert_eq!(MavlinkCategory::from_msg_id(30), MavlinkCategory::Attitude);
        assert_eq!(MavlinkCategory::from_msg_id(147), MavlinkCategory::Battery);
        assert_eq!(MavlinkCategory::from_msg_id(253), MavlinkCategory::StatusText);
        assert_eq!(MavlinkCategory::from_msg_id(328), MavlinkCategory::ObstacleDistance);
        assert_eq!(MavlinkCategory::from_msg_id(9999), MavlinkCategory::Other);
    }

    #[test]
    fn parse_mavlink_v2_frame() {
        // MAVLink v2: FD, len, incompat, compat, seq, sysid, compid, msgid(3 bytes), payload..., crc(2)
        let mut frame = vec![
            0xFD, // Magic
            4,    // Payload length
            0,    // Incompat flags
            0,    // Compat flags
            42,   // Sequence
            1,    // System ID
            1,    // Component ID
            33, 0, 0, // Message ID = 33 (GLOBAL_POSITION_INT)
            // 4 bytes payload
            0x01, 0x02, 0x03, 0x04,
            // CRC (2 bytes)
            0x00, 0x00,
        ];

        let msg = parse_mavlink_frame(&frame).unwrap();
        assert_eq!(msg.msg_id, 33);
        assert_eq!(msg.system_id, 1);
        assert_eq!(msg.sequence, 42);
        assert_eq!(msg.category, MavlinkCategory::PositionNavigation);
    }

    #[test]
    fn parse_mavlink_v1_frame() {
        let frame = vec![
            0xFE, // Magic v1
            4,    // Payload length
            10,   // Sequence
            1,    // System ID
            1,    // Component ID
            0,    // Message ID = 0 (HEARTBEAT)
            0x01, 0x02, 0x03, 0x04,
            // CRC (2 bytes)
            0x00, 0x00,
        ];

        let msg = parse_mavlink_frame(&frame).unwrap();
        assert_eq!(msg.msg_id, 0);
        assert_eq!(msg.category, MavlinkCategory::Heartbeat);
    }

    #[test]
    fn parse_invalid_frame() {
        assert!(parse_mavlink_frame(&[0x00, 0x01]).is_none());
        assert!(parse_mavlink_frame(&[]).is_none());
        assert!(parse_mavlink_frame(&[0xFD]).is_none());
    }

    #[test]
    fn encrypt_message() {
        let keys = crate::crypto::SessionKeys::generate().unwrap();

        let frame = vec![
            0xFD, 4, 0, 0, 1, 1, 1, 0, 0, 0,
            0x01, 0x02, 0x03, 0x04,
            0x00, 0x00, // CRC
        ];
        let msg = parse_mavlink_frame(&frame).unwrap();

        let proxy = MavlinkProxy::new("0.0.0.0:0", "127.0.0.1:14540");
        let (encrypted, label) = proxy.encrypt_message(&msg, &keys, 0).unwrap();

        // Verify decryption roundtrip
        let aad = label.to_bytes();
        let decrypted = keys.decrypt(&encrypted.nonce, &aad, &encrypted.ciphertext).unwrap();
        assert_eq!(decrypted, frame);
    }

    #[test]
    fn data_category_mapping() {
        assert_eq!(
            MavlinkCategory::PositionNavigation.default_data_category(),
            DataCategory::FlightTelemetry
        );
        assert_eq!(
            MavlinkCategory::Battery.default_data_category(),
            DataCategory::SystemStatus
        );
        assert_eq!(
            MavlinkCategory::RcInput.default_data_category(),
            DataCategory::RcInput
        );
    }
}
