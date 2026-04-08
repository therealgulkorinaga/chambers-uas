use crate::types::*;
use crate::error::V4l2Error;
use crate::firewall::FirewallEvent;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::{info, warn};
use uuid::Uuid;

// ─── Access classification ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessClassification {
    /// Declared mission camera pipeline access.
    DeclaredMission { rule_id: String },
    /// System allowlisted process.
    SystemAllowlisted { process: String, allowlist_entry: String },
    /// ANOMALY: Undeclared process accessing the camera.
    Undeclared {
        process_id: u32,
        process_name: String,
        process_exe: String,
        process_cmdline: String,
        parent_pid: u32,
    },
}

// ─── Anomaly event ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub pattern: AnomalyPattern,
    pub severity: Severity,
    pub classification: AccessClassification,
    pub device: String,
    pub details: String,
}

// ─── V4L2 access record ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct V4l2AccessRecord {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub process_name: String,
    pub access_type: String, // "open", "read", "dqbuf"
}

// ─── Anomaly detector ───────────────────────────────────────────────────────

pub struct AnomalyDetector {
    device_path: String,
    own_pid: u32,
    allowlist: Vec<String>,
    anomalies: Arc<Mutex<Vec<AnomalyEvent>>>,
    access_log: Arc<Mutex<VecDeque<V4l2AccessRecord>>>,
    /// Whether motors are disarmed (for ANM-002 detection)
    post_disarm: Arc<Mutex<bool>>,
    /// Firewall event receiver for correlation (ANM-005)
    firewall_rx: Option<broadcast::Receiver<FirewallEvent>>,
    /// Recent firewall events for correlation window
    recent_firewall_events: Arc<Mutex<VecDeque<FirewallEvent>>>,
    /// Declared camera resolution from manifest
    declared_resolution: Option<(u32, u32)>,
    /// Declared framerate
    declared_fps: Option<u32>,
    running: Arc<Mutex<bool>>,
}

impl AnomalyDetector {
    pub fn new(device_path: &str, allowlist: Vec<String>) -> Self {
        Self {
            device_path: device_path.to_string(),
            own_pid: std::process::id(),
            allowlist,
            anomalies: Arc::new(Mutex::new(Vec::new())),
            access_log: Arc::new(Mutex::new(VecDeque::with_capacity(10000))),
            post_disarm: Arc::new(Mutex::new(false)),
            firewall_rx: None,
            recent_firewall_events: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            declared_resolution: None,
            declared_fps: None,
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_firewall_events(mut self, rx: broadcast::Receiver<FirewallEvent>) -> Self {
        self.firewall_rx = Some(rx);
        self
    }

    pub fn with_declared_format(mut self, width: u32, height: u32, fps: u32) -> Self {
        self.declared_resolution = Some((width, height));
        self.declared_fps = Some(fps);
        self
    }

    /// Record a V4L2 access event from an external process.
    /// This is the primary detection entry point.
    pub fn record_access(&self, pid: u32, process_name: &str, access_type: &str) {
        let now = Utc::now();
        let record = V4l2AccessRecord {
            timestamp: now,
            pid,
            process_name: process_name.to_string(),
            access_type: access_type.to_string(),
        };

        // Store in access log
        if let Ok(mut log) = self.access_log.lock() {
            log.push_back(record.clone());
            // Keep last 10000 records
            while log.len() > 10000 {
                log.pop_front();
            }
        }

        // Classify the access
        let classification = self.classify_access(pid, process_name);
        match &classification {
            AccessClassification::DeclaredMission { .. } => {
                // Normal access, no anomaly
            }
            AccessClassification::SystemAllowlisted { .. } => {
                // Logged but not flagged
                info!("V4L2 access by allowlisted process: {} (pid {})", process_name, pid);
            }
            AccessClassification::Undeclared { .. } => {
                // ANOMALY
                self.detect_anomaly_type(now, pid, process_name, access_type, classification);
            }
        }
    }

    /// Signal that motors have been disarmed (enables ANM-002 detection).
    pub fn set_post_disarm(&self) {
        if let Ok(mut pd) = self.post_disarm.lock() {
            *pd = true;
        }
        info!("V4L2 monitor: post-disarm mode enabled");
    }

    /// Get and drain all detected anomalies.
    pub fn drain_anomalies(&self) -> Vec<AnomalyEvent> {
        if let Ok(mut anomalies) = self.anomalies.lock() {
            std::mem::take(&mut *anomalies)
        } else {
            Vec::new()
        }
    }

    /// Get anomaly count without draining.
    pub fn anomaly_count(&self) -> usize {
        self.anomalies.lock().map(|a| a.len()).unwrap_or(0)
    }

    /// Add a firewall event for ANM-005 correlation.
    pub fn add_firewall_event(&self, event: FirewallEvent) {
        if let Ok(mut events) = self.recent_firewall_events.lock() {
            events.push_back(event);
            // Keep last 1000 events
            while events.len() > 1000 {
                events.pop_front();
            }
        }
    }

    /// Get access log for debugging.
    pub fn access_log_len(&self) -> usize {
        self.access_log.lock().map(|l| l.len()).unwrap_or(0)
    }

    // ─── Internal classification ────────────────────────────────────────

    fn classify_access(&self, pid: u32, process_name: &str) -> AccessClassification {
        // Is it us?
        if pid == self.own_pid {
            return AccessClassification::DeclaredMission {
                rule_id: "self".to_string(),
            };
        }

        // Is it allowlisted?
        for allowed in &self.allowlist {
            if process_name == allowed {
                return AccessClassification::SystemAllowlisted {
                    process: process_name.to_string(),
                    allowlist_entry: allowed.clone(),
                };
            }
        }

        // It's undeclared
        let (exe, cmdline, ppid) = get_process_info(pid);
        AccessClassification::Undeclared {
            process_id: pid,
            process_name: process_name.to_string(),
            process_exe: exe,
            process_cmdline: cmdline,
            parent_pid: ppid,
        }
    }

    fn detect_anomaly_type(
        &self,
        timestamp: DateTime<Utc>,
        pid: u32,
        process_name: &str,
        _access_type: &str,
        classification: AccessClassification,
    ) {
        let is_post_disarm = self.post_disarm.lock().map(|pd| *pd).unwrap_or(false);

        // ANM-002: Post-disarm camera access
        let pattern = if is_post_disarm {
            AnomalyPattern::PostDisarmCameraAccess
        } else {
            // ANM-001: Undeclared camera access
            AnomalyPattern::UndeclaredCameraAccess
        };

        let anomaly = AnomalyEvent {
            id: Uuid::new_v4().to_string(),
            timestamp,
            pattern,
            severity: pattern.default_severity(),
            classification: classification.clone(),
            device: self.device_path.clone(),
            details: format!(
                "Undeclared process '{}' (pid {}) accessed V4L2 device {}",
                process_name, pid, self.device_path
            ),
        };

        warn!("{}: {} — pid {} ({})",
            pattern.code(), anomaly.details, pid, process_name);

        if let Ok(mut anomalies) = self.anomalies.lock() {
            anomalies.push(anomaly);
        }

        // Also check for ANM-005: burst/network correlation
        self.check_burst_correlation(timestamp);
    }

    /// ANM-005: Check if there are burst V4L2 reads correlated with network activity.
    fn check_burst_correlation(&self, timestamp: DateTime<Utc>) {
        let correlation_window_ms = 500;

        // Check if there are recent firewall events within the correlation window
        if let Ok(fw_events) = self.recent_firewall_events.lock() {
            for fw_event in fw_events.iter().rev() {
                let delta = (timestamp - fw_event.timestamp).num_milliseconds().abs();
                if delta <= correlation_window_ms {
                    if fw_event.action == FirewallAction::Block {
                        // Burst camera read correlated with blocked network activity!
                        let anomaly = AnomalyEvent {
                            id: Uuid::new_v4().to_string(),
                            timestamp,
                            pattern: AnomalyPattern::BurstNetworkCorrelation,
                            severity: Severity::Critical,
                            classification: AccessClassification::Undeclared {
                                process_id: 0,
                                process_name: "correlation".to_string(),
                                process_exe: String::new(),
                                process_cmdline: String::new(),
                                parent_pid: 0,
                            },
                            device: self.device_path.clone(),
                            details: format!(
                                "V4L2 access at {} correlated with blocked network TX to {} (delta: {}ms)",
                                timestamp, fw_event.destination, delta
                            ),
                        };

                        warn!("ANM-005 CRITICAL: {}", anomaly.details);

                        if let Ok(mut anomalies) = self.anomalies.lock() {
                            anomalies.push(anomaly);
                        }
                        return; // One correlation per access event
                    }
                }
            }
        }
    }
}

// ─── Process info helper ────────────────────────────────────────────────────

/// Get process exe, cmdline, and parent PID from /proc (Linux) or defaults.
fn get_process_info(pid: u32) -> (String, String, u32) {
    #[cfg(target_os = "linux")]
    {
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .unwrap_or_else(|_| "unknown".to_string())
            .replace('\0', " ")
            .trim()
            .to_string();

        let ppid = std::fs::read_to_string(format!("/proc/{}/stat", pid))
            .ok()
            .and_then(|s| {
                // Format: pid (comm) state ppid ...
                let parts: Vec<&str> = s.split(')').last()?.split_whitespace().collect();
                parts.get(1)?.parse().ok()
            })
            .unwrap_or(0);

        (exe, cmdline, ppid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        ("unknown".to_string(), "unknown".to_string(), 0)
    }
}

// ─── Proc scanner (fallback monitoring) ─────────────────────────────────────

/// Scan all processes for open file descriptors to the V4L2 device.
/// This is the polling fallback when fanotify/eBPF isn't available.
#[cfg(target_os = "linux")]
pub fn scan_procs_for_device(device_path: &str) -> Vec<(u32, String)> {
    let mut results = Vec::new();

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return results,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                for fd in fds.flatten() {
                    if let Ok(target) = std::fs::read_link(fd.path()) {
                        if target.to_string_lossy().contains(device_path) {
                            let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                                .unwrap_or_else(|_| "unknown".to_string())
                                .trim()
                                .to_string();
                            results.push((pid, comm));
                            break;
                        }
                    }
                }
            }
        }
    }

    results
}

#[cfg(not(target_os = "linux"))]
pub fn scan_procs_for_device(_device_path: &str) -> Vec<(u32, String)> {
    Vec::new() // Not supported on non-Linux
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FirewallAction;

    #[test]
    fn classify_own_process() {
        let detector = AnomalyDetector::new("/dev/video10", vec![]);
        let classification = detector.classify_access(std::process::id(), "chambers");
        assert!(matches!(classification, AccessClassification::DeclaredMission { .. }));
    }

    #[test]
    fn classify_allowlisted_process() {
        let detector = AnomalyDetector::new("/dev/video10", vec!["gst-launch-1.0".to_string()]);
        let classification = detector.classify_access(99999, "gst-launch-1.0");
        assert!(matches!(classification, AccessClassification::SystemAllowlisted { .. }));
    }

    #[test]
    fn classify_undeclared_process() {
        let detector = AnomalyDetector::new("/dev/video10", vec!["allowed".to_string()]);
        let classification = detector.classify_access(99999, "rogue_reader");
        assert!(matches!(classification, AccessClassification::Undeclared { .. }));
    }

    #[test]
    fn detect_undeclared_access_anm001() {
        let detector = AnomalyDetector::new("/dev/video10", vec![]);
        detector.record_access(99999, "rogue", "read");

        let anomalies = detector.drain_anomalies();
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].pattern, AnomalyPattern::UndeclaredCameraAccess);
        assert_eq!(anomalies[0].severity, Severity::High);
    }

    #[test]
    fn detect_post_disarm_access_anm002() {
        let detector = AnomalyDetector::new("/dev/video10", vec![]);
        detector.set_post_disarm();
        detector.record_access(99999, "rogue", "read");

        let anomalies = detector.drain_anomalies();
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].pattern, AnomalyPattern::PostDisarmCameraAccess);
    }

    #[test]
    fn no_anomaly_for_self() {
        let detector = AnomalyDetector::new("/dev/video10", vec![]);
        detector.record_access(std::process::id(), "chambers_camera", "read");
        assert_eq!(detector.anomaly_count(), 0);
    }

    #[test]
    fn no_anomaly_for_allowlisted() {
        let detector = AnomalyDetector::new("/dev/video10", vec!["gst-launch-1.0".to_string()]);
        detector.record_access(99999, "gst-launch-1.0", "read");
        assert_eq!(detector.anomaly_count(), 0);
    }

    #[test]
    fn burst_network_correlation_anm005() {
        let detector = AnomalyDetector::new("/dev/video10", vec![]);

        // Add a blocked firewall event
        let fw_event = FirewallEvent {
            timestamp: Utc::now(),
            direction: Direction::Outbound,
            protocol: Protocol::Tcp,
            source: "local".to_string(),
            destination: "evil.com:9999".to_string(),
            port: Some(9999),
            action: FirewallAction::Block,
            manifest_flow_id: None,
            process_name: "rogue".to_string(),
            process_id: 99999,
        };
        detector.add_firewall_event(fw_event);

        // Now record a camera access within the correlation window
        detector.record_access(99999, "rogue", "read");

        let anomalies = detector.drain_anomalies();
        // Should have ANM-001 (undeclared access) AND ANM-005 (burst correlation)
        assert!(anomalies.len() >= 2);
        assert!(anomalies.iter().any(|a| a.pattern == AnomalyPattern::BurstNetworkCorrelation));
        assert!(anomalies.iter().any(|a| a.pattern == AnomalyPattern::UndeclaredCameraAccess));
    }

    #[test]
    fn access_log_maintained() {
        let detector = AnomalyDetector::new("/dev/video10", vec![]);
        for i in 0..5 {
            detector.record_access(std::process::id(), "self", "read");
        }
        assert_eq!(detector.access_log_len(), 5);
    }

    #[test]
    fn drain_clears_anomalies() {
        let detector = AnomalyDetector::new("/dev/video10", vec![]);
        detector.record_access(99999, "rogue1", "read");
        detector.record_access(99998, "rogue2", "read");

        let first = detector.drain_anomalies();
        assert_eq!(first.len(), 2);

        let second = detector.drain_anomalies();
        assert!(second.is_empty());
    }
}
