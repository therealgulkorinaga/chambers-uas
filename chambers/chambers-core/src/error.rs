use crate::types::{LayerStatus, SessionState};

// ─── Top-level error ────────────────────────────────────────────────────────

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

    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),

    #[error("Camera error: {0}")]
    Camera(#[from] CameraError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Session errors ─────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("Invalid state transition: cannot go from {current} to {attempted}")]
    InvalidState {
        current: SessionState,
        attempted: SessionState,
    },

    #[error("Manifest not loaded")]
    ManifestNotLoaded,

    #[error("Session already armed")]
    AlreadyArmed,

    #[error("No active session")]
    NoActiveSession,

    #[error("Session keys not available")]
    NoKeys,

    #[error("Manifest error: {0}")]
    Manifest(#[from] ManifestError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Crypto errors ──────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },

    #[error("Signature failed: {reason}")]
    SignatureFailed { reason: String },

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Zeroisation failed: {reason}")]
    ZeroisationFailed { reason: String },

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("HKDF derivation failed: {reason}")]
    DerivationFailed { reason: String },

    #[error("Nonce overflow — session has encrypted too many items")]
    NonceOverflow,
}

// ─── Manifest errors ────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug, Clone)]
pub enum ManifestError {
    #[error("TOML parse error: {message}")]
    ParseError { message: String },

    #[error("Remote ID must be enabled for jurisdiction {jurisdiction}")]
    RemoteIdRequired { jurisdiction: String },

    #[error("Missing preserve rule for remote_id with real_time transmission")]
    MissingRemoteIdPreserveRule,

    #[error("Default action must be BURN, found: {found}")]
    InvalidDefaultAction { found: String },

    #[error("Rule {rule_id} references undeclared stakeholder: {stakeholder_id}")]
    UndeclaredStakeholder {
        rule_id: String,
        stakeholder_id: String,
    },

    #[error("Stakeholder {id} has invalid public key: {reason}")]
    InvalidStakeholderKey { id: String, reason: String },

    #[error("Rule {rule_id} has invalid retention value: {value}")]
    InvalidRetention { rule_id: String, value: String },

    #[error("Rule {rule_id} uses wildcard stakeholder without regulator signature")]
    WildcardRequiresRegulatorSignature { rule_id: String },

    #[error("Conflicting preserve and deny rules for ({data_category}, {stakeholder}): deny wins")]
    ConflictingRules {
        data_category: String,
        stakeholder: String,
    },

    #[error("Validation failed with {count} errors")]
    MultipleErrors {
        count: usize,
        errors: Vec<ManifestError>,
    },

    #[error("IO error: {0}")]
    IoError(String),
}

// ─── Burn errors ────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum BurnError {
    #[error("Burn layer {layer} failed: {reason}")]
    LayerFailed { layer: u8, reason: String },

    #[error("Verification failed at layer {layer}: {reason}")]
    VerificationFailed { layer: u8, reason: String },

    #[error("Session storage not empty after burn")]
    StorageNotEmpty,

    #[error("Session key not zeroed after burn")]
    KeyNotZero,

    #[error("IO error during burn: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Audit errors ───────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    #[error("Hash chain broken at entry {sequence}")]
    HashChainBroken { sequence: u64 },

    #[error("Signature invalid at entry {sequence}")]
    SignatureInvalid { sequence: u64 },

    #[error("Sequence gap: expected {expected}, got {got}")]
    SequenceGap { expected: u64, got: u64 },

    #[error("Manifest hash mismatch at entry {sequence}")]
    ManifestHashMismatch { sequence: u64 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

// ─── Firewall errors ────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum FirewallError {
    #[error("nftables not available: {reason}")]
    NftablesNotAvailable { reason: String },

    #[error("Failed to apply firewall rules: {reason}")]
    RuleApplicationFailed { reason: String },

    #[error("Network namespace error: {reason}")]
    NamespaceError { reason: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── V4L2 errors ────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum V4l2Error {
    #[error("V4L2 device not found: {path}")]
    DeviceNotFound { path: String },

    #[error("fanotify setup failed: {reason}")]
    FanotifySetupFailed { reason: String },

    #[error("eBPF not available: {reason}")]
    EbpfNotAvailable { reason: String },

    #[error("Device configuration failed: {reason}")]
    ConfigurationFailed { reason: String },

    #[error("Frame read failed: {reason}")]
    ReadFailed { reason: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Proxy errors ───────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("Connection failed: {reason}")]
    ConnectionFailed { reason: String },

    #[error("Parse error: {reason}")]
    ParseError { reason: String },

    #[error("Send failed: {reason}")]
    SendFailed { reason: String },

    #[error("Encryption error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Camera errors ──────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum CameraError {
    #[error("V4L2 error: {0}")]
    V4l2(#[from] V4l2Error),

    #[error("Encryption error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Pipeline stopped")]
    PipelineStopped,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
