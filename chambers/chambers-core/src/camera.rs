use crate::crypto::{EncryptedData, SessionKeys};
use crate::error::CameraError;
use crate::types::*;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

// ─── Camera pipeline stats ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CameraStats {
    pub frames_captured: u64,
    pub frames_encrypted: u64,
    pub bytes_captured: u64,
    pub bytes_encrypted: u64,
    pub errors: u64,
}

// ─── Frame reader trait ─────────────────────────────────────────────────────

/// Abstraction over V4L2 device reading.
/// Allows testing without actual V4L2 hardware.
pub trait FrameReader: Send {
    /// Read the next frame. Returns (frame_data, metadata).
    fn read_frame(&mut self) -> Result<(Vec<u8>, CameraFrameMetadata), CameraError>;

    /// Get the device path.
    fn device_path(&self) -> &str;

    /// Close the device.
    fn close(&mut self) -> Result<(), CameraError>;
}

// ─── V4L2 frame reader ─────────────────────────────────────────────────────

/// Real V4L2 device reader. Only works on Linux with v4l2loopback.
#[cfg(target_os = "linux")]
pub struct V4l2FrameReader {
    device_path: String,
    width: u32,
    height: u32,
    fps: u32,
    frame_count: AtomicU64,
    fd: Option<std::os::unix::io::RawFd>,
}

#[cfg(target_os = "linux")]
impl V4l2FrameReader {
    pub fn open(device_path: &str, width: u32, height: u32, fps: u32) -> Result<Self, CameraError> {
        use std::os::unix::io::AsRawFd;

        // Open the V4L2 device
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .map_err(|e| CameraError::V4l2(crate::error::V4l2Error::DeviceNotFound {
                path: format!("{}: {}", device_path, e),
            }))?;

        let fd = file.as_raw_fd();
        std::mem::forget(file); // Keep FD open

        info!("V4L2 device opened: {} ({}x{}@{}fps)", device_path, width, height, fps);

        Ok(Self {
            device_path: device_path.to_string(),
            width,
            height,
            fps,
            frame_count: AtomicU64::new(0),
            fd: Some(fd),
        })
    }
}

#[cfg(target_os = "linux")]
impl FrameReader for V4l2FrameReader {
    fn read_frame(&mut self) -> Result<(Vec<u8>, CameraFrameMetadata), CameraError> {
        let fd = self.fd.ok_or(CameraError::PipelineStopped)?;

        // Read raw frame data from the device
        let frame_size = (self.width * self.height * 2) as usize; // YUY2 = 2 bytes/pixel
        let mut buf = vec![0u8; frame_size];

        let bytes_read = nix::unistd::read(fd, &mut buf)
            .map_err(|e| CameraError::V4l2(crate::error::V4l2Error::ReadFailed {
                reason: e.to_string(),
            }))?;

        let idx = self.frame_count.fetch_add(1, Ordering::SeqCst);

        let metadata = CameraFrameMetadata {
            frame_index: idx,
            timestamp: Utc::now(),
            width: self.width,
            height: self.height,
            format: "YUY2".to_string(),
            bytes: bytes_read,
            device: self.device_path.clone(),
        };

        buf.truncate(bytes_read);
        Ok((buf, metadata))
    }

    fn device_path(&self) -> &str {
        &self.device_path
    }

    fn close(&mut self) -> Result<(), CameraError> {
        if let Some(fd) = self.fd.take() {
            nix::unistd::close(fd).ok();
        }
        Ok(())
    }
}

// ─── Test frame reader ──────────────────────────────────────────────────────

/// Generates synthetic frames for testing without V4L2 hardware.
pub struct TestFrameReader {
    device_path: String,
    width: u32,
    height: u32,
    frame_count: AtomicU64,
    pattern: u8,
}

impl TestFrameReader {
    pub fn new(device_path: &str, width: u32, height: u32) -> Self {
        Self {
            device_path: device_path.to_string(),
            width,
            height,
            frame_count: AtomicU64::new(0),
            pattern: 0,
        }
    }
}

impl FrameReader for TestFrameReader {
    fn read_frame(&mut self) -> Result<(Vec<u8>, CameraFrameMetadata), CameraError> {
        let idx = self.frame_count.fetch_add(1, Ordering::SeqCst);
        let frame_size = (self.width * self.height * 2) as usize;

        // Generate a test pattern that varies per frame
        self.pattern = self.pattern.wrapping_add(1);
        let data: Vec<u8> = (0..frame_size).map(|i| {
            ((i as u8).wrapping_add(self.pattern))
        }).collect();

        let metadata = CameraFrameMetadata {
            frame_index: idx,
            timestamp: Utc::now(),
            width: self.width,
            height: self.height,
            format: "YUY2".to_string(),
            bytes: frame_size,
            device: self.device_path.clone(),
        };

        Ok((data, metadata))
    }

    fn device_path(&self) -> &str {
        &self.device_path
    }

    fn close(&mut self) -> Result<(), CameraError> {
        Ok(())
    }
}

// ─── Camera encryption pipeline ─────────────────────────────────────────────

pub struct CameraPipeline {
    reader: Box<dyn FrameReader>,
    stats: CameraStats,
    running: Arc<AtomicBool>,
}

impl CameraPipeline {
    pub fn new(reader: Box<dyn FrameReader>) -> Self {
        Self {
            reader,
            stats: CameraStats::default(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Process one frame: read, encrypt, return encrypted data + event label.
    pub fn process_frame(
        &mut self,
        keys: &SessionKeys,
    ) -> Result<(EncryptedData, EventLabel, CameraFrameMetadata), CameraError> {
        let (frame_data, metadata) = self.reader.read_frame()?;

        let label = EventLabel {
            timestamp: metadata.timestamp,
            source: DataSource::Camera {
                device: metadata.device.clone(),
            },
            process_id: std::process::id(),
            process_name: "chambers_camera".to_string(),
            byte_count: frame_data.len() as u64,
            destination: DataDestination::SessionStorage,
            manifest_rule: None,
            sequence: metadata.frame_index,
        };

        let aad = label.to_bytes();
        let encrypted = keys.encrypt(&aad, &frame_data).map_err(CameraError::Crypto)?;

        self.stats.frames_captured += 1;
        self.stats.frames_encrypted += 1;
        self.stats.bytes_captured += frame_data.len() as u64;
        self.stats.bytes_encrypted += encrypted.ciphertext.len() as u64;

        Ok((encrypted, label, metadata))
    }

    /// Get pipeline statistics.
    pub fn stats(&self) -> &CameraStats {
        &self.stats
    }

    /// Get the device path.
    pub fn device_path(&self) -> &str {
        self.reader.device_path()
    }

    /// Stop the pipeline.
    pub fn stop(&mut self) -> Result<(), CameraError> {
        self.running.store(false, Ordering::SeqCst);
        self.reader.close()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKeys;

    #[test]
    fn test_frame_reader_generates_data() {
        let mut reader = TestFrameReader::new("/dev/video10", 320, 240);
        let (data, meta) = reader.read_frame().unwrap();

        assert_eq!(data.len(), 320 * 240 * 2);
        assert_eq!(meta.width, 320);
        assert_eq!(meta.height, 240);
        assert_eq!(meta.frame_index, 0);
        assert_eq!(meta.format, "YUY2");
    }

    #[test]
    fn test_frame_reader_increments_index() {
        let mut reader = TestFrameReader::new("/dev/video10", 64, 64);
        for i in 0..10 {
            let (_, meta) = reader.read_frame().unwrap();
            assert_eq!(meta.frame_index, i);
        }
    }

    #[test]
    fn test_frames_vary() {
        let mut reader = TestFrameReader::new("/dev/video10", 64, 64);
        let (data1, _) = reader.read_frame().unwrap();
        let (data2, _) = reader.read_frame().unwrap();
        assert_ne!(data1, data2, "Sequential frames should differ");
    }

    #[test]
    fn camera_pipeline_encrypt_frame() {
        let reader = TestFrameReader::new("/dev/video10", 64, 64);
        let mut pipeline = CameraPipeline::new(Box::new(reader));
        let keys = SessionKeys::generate().unwrap();

        let (encrypted, label, metadata) = pipeline.process_frame(&keys).unwrap();

        // Verify decryption roundtrip
        let aad = label.to_bytes();
        let decrypted = keys.decrypt(&encrypted.nonce, &aad, &encrypted.ciphertext).unwrap();
        assert_eq!(decrypted.len(), 64 * 64 * 2);
        assert_eq!(metadata.frame_index, 0);
    }

    #[test]
    fn camera_pipeline_stats() {
        let reader = TestFrameReader::new("/dev/video10", 64, 64);
        let mut pipeline = CameraPipeline::new(Box::new(reader));
        let keys = SessionKeys::generate().unwrap();

        for _ in 0..5 {
            pipeline.process_frame(&keys).unwrap();
        }

        let stats = pipeline.stats();
        assert_eq!(stats.frames_captured, 5);
        assert_eq!(stats.frames_encrypted, 5);
        assert_eq!(stats.bytes_captured, 5 * 64 * 64 * 2);
    }

    #[test]
    fn camera_pipeline_event_labels() {
        let reader = TestFrameReader::new("/dev/video10", 32, 32);
        let mut pipeline = CameraPipeline::new(Box::new(reader));
        let keys = SessionKeys::generate().unwrap();

        let (_, label, _) = pipeline.process_frame(&keys).unwrap();
        assert_eq!(label.process_name, "chambers_camera");
        assert!(matches!(label.source, DataSource::Camera { .. }));
        assert_eq!(label.destination, DataDestination::SessionStorage);
        assert_eq!(label.sequence, 0);

        let (_, label2, _) = pipeline.process_frame(&keys).unwrap();
        assert_eq!(label2.sequence, 1);
    }
}
