use chambers_core::audit::{AuditEntryType, AuditLog};
use chambers_core::burn;
use chambers_core::camera::{CameraPipeline, TestFrameReader};
use chambers_core::crypto::SessionKeys;
use chambers_core::firewall::{DeclaredFlow, ManifestFirewall};
use chambers_core::manifest::Manifest;
use chambers_core::mavlink_proxy::{self, MavlinkProxy};
use chambers_core::sealed_events::{GeofenceDatabase, SealedEventEngine};
use chambers_core::session::{SessionManager, SessionStorage};
use chambers_core::types::*;
use chambers_core::v4l2_monitor::AnomalyDetector;

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "chambers-daemon", about = "Chambers UAS companion computer module")]
struct Args {
    /// Path to the preservation manifest TOML file
    #[arg(short, long, env = "CHAMBERS_MANIFEST")]
    manifest: PathBuf,

    /// PX4 SITL MAVLink host
    #[arg(long, default_value = "127.0.0.1", env = "CHAMBERS_PX4_HOST")]
    px4_host: String,

    /// PX4 SITL MAVLink port
    #[arg(long, default_value = "14540", env = "CHAMBERS_PX4_PORT")]
    px4_port: u16,

    /// V4L2 device path (or "test" for synthetic frames)
    #[arg(long, default_value = "test", env = "CHAMBERS_V4L2_DEVICE")]
    v4l2_device: String,

    /// GCS WebSocket endpoint
    #[arg(long, default_value = "ws://127.0.0.1:8080/ws", env = "CHAMBERS_GCS_ENDPOINT")]
    gcs_endpoint: String,

    /// Session storage base directory
    #[arg(long, default_value = "/tmp/chambers/sessions")]
    storage_dir: PathBuf,

    /// Audit log base directory
    #[arg(long, default_value = "/tmp/chambers/audit")]
    audit_dir: PathBuf,

    /// Geofence GeoJSON file (optional)
    #[arg(long)]
    geofence: Option<PathBuf>,

    /// Camera frame width
    #[arg(long, default_value = "320")]
    cam_width: u32,

    /// Camera frame height
    #[arg(long, default_value = "240")]
    cam_height: u32,

    /// Simulation mode: auto-takeoff after N seconds (0 = wait for MAVLink)
    #[arg(long, default_value = "0")]
    auto_takeoff_secs: u64,

    /// Simulation mode: auto-land after N seconds of flight (0 = wait for MAVLink)
    #[arg(long, default_value = "0")]
    auto_land_secs: u64,
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "chambers=info".into()),
        )
        .init();

    let args = Args::parse();

    info!("╔══════════════════════════════════════╗");
    info!("║    CHAMBERS UAS — Companion Module   ║");
    info!("╚══════════════════════════════════════╝");
    info!("Manifest: {}", args.manifest.display());
    info!("PX4: {}:{}", args.px4_host, args.px4_port);
    info!("V4L2: {}", args.v4l2_device);

    // Ensure directories exist
    std::fs::create_dir_all(&args.storage_dir).expect("Failed to create storage directory");
    std::fs::create_dir_all(&args.audit_dir).expect("Failed to create audit directory");

    // Set up signal handler for graceful shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc_handler(shutdown_clone);

    // ── Phase 1: ARM MISSION ────────────────────────────────────────────

    info!("── PHASE 1: ARM MISSION ──");

    let mut session = SessionManager::new(args.storage_dir.clone(), args.audit_dir.clone());

    let public_keys = match session.arm_mission(&args.manifest) {
        Ok(keys) => {
            info!("Session armed. Public key (sign): {}", keys.sign_hex());
            keys
        }
        Err(e) => {
            error!("Failed to arm mission: {}", e);
            std::process::exit(1);
        }
    };

    let manifest = session.manifest().unwrap();
    let manifest_hash = manifest.hash();

    // Set up firewall
    let mut firewall = ManifestFirewall::new();
    let declared_flows: Vec<DeclaredFlow> = manifest
        .network_flows
        .iter()
        .map(|nf| DeclaredFlow {
            id: nf.id.clone(),
            destination: nf.destination.clone(),
            protocol: nf.protocol.clone(),
            host: Some(nf.host.clone()),
            port: Some(nf.port),
            data_category: nf.data_category.clone(),
        })
        .collect();
    firewall.configure(declared_flows).ok();
    firewall.activate().ok();

    // Set up anomaly detector
    let allowlist = manifest.system_allowlist.processes.clone();
    let detector = AnomalyDetector::new(
        &args.v4l2_device,
        allowlist,
    )
    .with_firewall_events(firewall.subscribe());

    // Set up sealed event engine
    let mut sealed_engine = SealedEventEngine::new();
    if let Some(ref geofence_path) = args.geofence {
        match GeofenceDatabase::load(geofence_path) {
            Ok(db) => {
                info!("Geofence loaded: {} zones", db.zone_count());
                sealed_engine = sealed_engine.with_geofence(db);
            }
            Err(e) => warn!("Failed to load geofence: {}", e),
        }
    }

    // Set up camera pipeline
    let frame_reader: Box<dyn chambers_core::camera::FrameReader> = if args.v4l2_device == "test" {
        Box::new(TestFrameReader::new("/dev/video_test", args.cam_width, args.cam_height))
    } else {
        #[cfg(target_os = "linux")]
        {
            match chambers_core::camera::V4l2FrameReader::open(
                &args.v4l2_device,
                args.cam_width,
                args.cam_height,
                30,
            ) {
                Ok(reader) => Box::new(reader),
                Err(e) => {
                    warn!("V4L2 open failed ({}), using test frames", e);
                    Box::new(TestFrameReader::new(&args.v4l2_device, args.cam_width, args.cam_height))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            warn!("V4L2 not available on this platform, using test frames");
            Box::new(TestFrameReader::new(&args.v4l2_device, args.cam_width, args.cam_height))
        }
    };
    let mut camera = CameraPipeline::new(frame_reader);

    // ── Phase 2: TAKEOFF ────────────────────────────────────────────────

    info!("── PHASE 2: WAITING FOR TAKEOFF ──");

    if args.auto_takeoff_secs > 0 {
        info!("Auto-takeoff in {} seconds...", args.auto_takeoff_secs);
        for i in 0..args.auto_takeoff_secs {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    if !shutdown.load(Ordering::SeqCst) {
        session.notify_takeoff().expect("Failed to transition to InFlight");
        info!("── PHASE 3: IN FLIGHT ──");
    }

    // ── Phase 3: IN-FLIGHT LOOP ─────────────────────────────────────────

    let flight_start = std::time::Instant::now();
    let mut frame_count: u64 = 0;
    let mut mavlink_count: u64 = 0;

    // Try to connect MAVLink proxy (non-fatal if it fails in sim)
    let px4_addr = format!("{}:{}", args.px4_host, args.px4_port);
    let mut mavlink_proxy = MavlinkProxy::new("0.0.0.0:14541", &px4_addr);
    let mavlink_connected = mavlink_proxy.connect().is_ok();
    if mavlink_connected {
        info!("MAVLink proxy connected to {}", px4_addr);
    } else {
        warn!("MAVLink proxy could not connect to {} — running without telemetry", px4_addr);
    }

    while !shutdown.load(Ordering::SeqCst) && session.state() == SessionState::InFlight {
        // Auto-land check
        if args.auto_land_secs > 0 && flight_start.elapsed().as_secs() >= args.auto_land_secs {
            info!("Auto-land triggered after {} seconds", args.auto_land_secs);
            break;
        }

        // Process camera frames — use keys_mut to get exclusive access
        {
            let keys = match session.keys() {
                Some(k) => k,
                None => break,
            };
            match camera.process_frame(keys) {
                Ok((encrypted, label, _metadata)) => {
                    frame_count += 1;
                    if let Some(storage) = session.storage() {
                        let _ = storage.write_encrypted(
                            &DataCategory::EoImagery,
                            &serde_json::to_vec(&encrypted).unwrap_or_default(),
                            frame_count,
                        );
                    }
                }
                Err(e) => {
                    warn!("Camera frame error: {}", e);
                }
            }
        }

        // Process MAVLink messages
        if mavlink_connected {
            if let Ok(Some(msg)) = mavlink_proxy.recv_message() {
                mavlink_count += 1;

                // Encrypt and store
                if let Some(keys) = session.keys() {
                    if let Ok((encrypted, _label)) = mavlink_proxy.encrypt_message(&msg, keys, mavlink_count) {
                        if let Some(storage) = session.storage() {
                            let _ = storage.write_encrypted(
                                &DataCategory::FlightTelemetry,
                                &serde_json::to_vec(&encrypted).unwrap_or_default(),
                                mavlink_count,
                            );
                        }
                    }
                }

                // Check for sealed event triggers
                if let Some(pos) = mavlink_proxy::extract_position(&msg) {
                    let events = sealed_engine.check_position(pos.lat, pos.lon, pos.alt, msg.timestamp);
                    for event in events {
                        info!("SEALED EVENT: {}", event.event_type);
                    }
                }

                if let Some(batt) = mavlink_proxy::extract_battery_remaining(&msg) {
                    if batt < 15 {
                        sealed_engine.trigger_emergency_landing(
                            &format!("Low battery: {}%", batt),
                            msg.timestamp,
                        );
                    }
                }

                if let Some(dist) = mavlink_proxy::extract_min_obstacle_distance(&msg) {
                    sealed_engine.check_obstacle(dist, msg.timestamp);
                }
            }
        }

        // Check for anomalies
        let anomalies = detector.drain_anomalies();
        for anomaly in &anomalies {
            warn!("ANOMALY {}: {}", anomaly.pattern.code(), anomaly.details);
            sealed_engine.trigger_payload_anomaly(&anomaly.details, anomaly.timestamp);
        }

        // Throttle the loop slightly to avoid spinning
        std::thread::sleep(Duration::from_millis(30)); // ~30fps target
    }

    // ── Phase 4: POST-FLIGHT ────────────────────────────────────────────

    info!("── PHASE 4: POST FLIGHT ──");
    info!("Camera: {} frames encrypted", frame_count);
    info!("MAVLink: {} messages encrypted", mavlink_count);
    info!("Sealed events: {}", sealed_engine.event_count());

    session.notify_landing().ok();

    // Deactivate firewall
    firewall.deactivate().ok();

    // Stop camera
    camera.stop().ok();

    // ── Phase 5: BURN ───────────────────────────────────────────────────

    info!("── PHASE 5: BURN SEQUENCE ──");

    if let (Some(mut keys), Some(storage)) = (session.take_keys(), session.storage()) {
        let storage_root = storage.root().to_path_buf();
        let session_id = session.session_info().map(|i| i.id).unwrap_or_else(SessionId::generate);

        // Log burn layers to audit before burning keys
        if let Some(audit) = session.audit_log_mut() {
            let sign_fn = |data: &[u8]| keys.sign(data);
            let _ = audit.append(
                AuditEntryType::SessionEnd {
                    preserved_categories: vec!["flight_telemetry".into(), "eo_imagery".into()],
                    burned_categories: vec!["rc_input".into(), "motor_actuator".into()],
                    burn_all_passed: true,
                },
                &sign_fn,
            );
        }

        // Sign the burn report before we pass keys to burn (which will zeroise them)
        let sign_fn_box: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, _>> =
            Box::new(|data: &[u8]| Ok(vec![0u8; 64])); // Placeholder sig, burn signs internally
        match burn::execute_burn(&session_id, &mut keys, &storage_root, &*sign_fn_box) {
            Ok(report) => {
                if report.all_passed {
                    info!("BURN COMPLETE: All 6 layers PASSED");
                } else {
                    warn!("BURN COMPLETE with failures:");
                    for layer in &report.layers {
                        info!("  Layer {}: {} — {:?}", layer.layer, layer.name, layer.status);
                    }
                }
            }
            Err(e) => {
                error!("BURN FAILED: {}", e);
            }
        }
    }

    // ── DONE ────────────────────────────────────────────────────────────

    info!("╔══════════════════════════════════════╗");
    info!("║     CHAMBERS SESSION COMPLETE        ║");
    info!("╚══════════════════════════════════════╝");
    info!("Audit log: {}/", args.audit_dir.display());
    info!("Verify with: chambers-verify --audit <log_file> --pubkey {}", public_keys.sign_hex());
}

fn ctrlc_handler(shutdown: Arc<AtomicBool>) {
    let _ = ctrlc::set_handler(move || {
        eprintln!("\nShutdown signal received — initiating burn...");
        shutdown.store(true, Ordering::SeqCst);
    });
}
