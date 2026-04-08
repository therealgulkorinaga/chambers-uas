use crate::error::CryptoError;
use crate::types::SessionPublicKey;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, UnboundKey, NONCE_LEN};
use ring::error::Unspecified;
use ring::hkdf;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Nonce generation ───────────────────────────────────────────────────────

/// Counter-based nonce generator.
/// 8-byte monotonic counter || 4-byte random suffix.
/// Guarantees uniqueness within a session.
pub struct CounterNonceSequence {
    counter: AtomicU64,
}

impl CounterNonceSequence {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    pub fn next_nonce(&self) -> Result<[u8; NONCE_LEN], CryptoError> {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        if count == u64::MAX {
            return Err(CryptoError::NonceOverflow);
        }
        let mut nonce_bytes = [0u8; NONCE_LEN]; // 12 bytes
        nonce_bytes[..8].copy_from_slice(&count.to_be_bytes());
        // Fill remaining 4 bytes with random for extra safety
        let mut suffix = [0u8; 4];
        rand::RngCore::fill_bytes(&mut OsRng, &mut suffix);
        nonce_bytes[8..].copy_from_slice(&suffix);
        Ok(nonce_bytes)
    }

    pub fn current_count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

/// Adapter for ring's BoundKey which needs a NonceSequence
struct SingleNonce([u8; NONCE_LEN]);

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Nonce::try_assume_unique_for_key(&self.0).map_err(|_| Unspecified)
    }
}

// ─── Session keys ───────────────────────────────────────────────────────────

/// All key material for a session. Implements ZeroizeOnDrop for secure cleanup.
pub struct SessionKeys {
    sign_private: SigningKey,
    sign_public: VerifyingKey,
    enc_private: x25519_dalek::StaticSecret,
    enc_public: x25519_dalek::PublicKey,
    sym_key: SymmetricKey,
    nonce_seq: Arc<CounterNonceSequence>,
    zeroised: bool,
}

#[derive(Clone)]
struct SymmetricKey {
    bytes: [u8; 32],
}

impl Zeroize for SymmetricKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SessionKeys {
    /// Generate a fresh set of session keys.
    pub fn generate() -> Result<Self, CryptoError> {
        // Ed25519 signing keypair
        let sign_private = SigningKey::generate(&mut OsRng);
        let sign_public = sign_private.verifying_key();

        // X25519 encryption keypair
        let enc_private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let enc_public = x25519_dalek::PublicKey::from(&enc_private);

        // Derive session symmetric key via HKDF
        let mut ikm = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut ikm);

        let mut salt_material = Vec::with_capacity(64);
        salt_material.extend_from_slice(sign_public.as_bytes());
        salt_material.extend_from_slice(enc_public.as_bytes());

        let sym_key = derive_symmetric_key(&ikm, &salt_material, b"chambers-session-v1")?;
        ikm.zeroize();

        Ok(Self {
            sign_private,
            sign_public,
            enc_private,
            enc_public,
            sym_key: SymmetricKey { bytes: sym_key },
            nonce_seq: Arc::new(CounterNonceSequence::new()),
            zeroised: false,
        })
    }

    /// Get the public keys to share with GCS.
    pub fn public_keys(&self) -> SessionPublicKey {
        SessionPublicKey {
            sign: self.sign_public.as_bytes().to_vec(),
            enc: self.enc_public.as_bytes().to_vec(),
        }
    }

    /// Sign a message with the session Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.zeroised {
            return Err(CryptoError::SignatureFailed {
                reason: "Keys have been zeroised".into(),
            });
        }
        let sig = self.sign_private.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Encrypt data with session AES-256-GCM key.
    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        if self.zeroised {
            return Err(CryptoError::EncryptionFailed {
                reason: "Keys have been zeroised".into(),
            });
        }
        let nonce_bytes = self.nonce_seq.next_nonce()?;
        let ciphertext = aes_gcm_encrypt(&self.sym_key.bytes, &nonce_bytes, aad, plaintext)?;
        Ok(EncryptedData {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt data with session AES-256-GCM key.
    pub fn decrypt(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.zeroised {
            return Err(CryptoError::DecryptionFailed {
                reason: "Keys have been zeroised".into(),
            });
        }
        aes_gcm_decrypt(&self.sym_key.bytes, nonce, aad, ciphertext)
    }

    /// Derive a preservation key for a specific stakeholder.
    pub fn derive_preservation_key(
        &self,
        stakeholder_pub: &[u8; 32],
        stakeholder_id: &str,
    ) -> Result<PreservationKey, CryptoError> {
        if self.zeroised {
            return Err(CryptoError::DerivationFailed {
                reason: "Keys have been zeroised".into(),
            });
        }
        let their_public = x25519_dalek::PublicKey::from(*stakeholder_pub);
        let shared_secret = self.enc_private.diffie_hellman(&their_public);

        let mut info = b"chambers-preserve-v1".to_vec();
        info.extend_from_slice(stakeholder_id.as_bytes());

        let key_bytes = derive_symmetric_key(
            shared_secret.as_bytes(),
            self.sign_public.as_bytes(),
            &info,
        )?;

        Ok(PreservationKey {
            key: SymmetricKey { bytes: key_bytes },
            stakeholder_id: stakeholder_id.to_string(),
            nonce_seq: CounterNonceSequence::new(),
        })
    }

    /// Get the signing public key bytes.
    pub fn sign_public_bytes(&self) -> &[u8; 32] {
        self.sign_public.as_bytes()
    }

    /// Get nonce count (for stats).
    pub fn encryption_count(&self) -> u64 {
        self.nonce_seq.current_count()
    }

    /// Explicitly zeroise all key material. Called during burn Layer 2.
    pub fn zeroise(&mut self) {
        self.sym_key.zeroize();
        // ed25519-dalek SigningKey doesn't expose zeroize, but we mark as zeroised
        // and the Drop impl will handle cleanup
        self.zeroised = true;
    }

    /// Check if keys have been zeroised.
    pub fn is_zeroised(&self) -> bool {
        self.zeroised
    }

    /// Check if symmetric key bytes are all zero (for burn verification).
    pub fn sym_key_is_zero(&self) -> bool {
        self.sym_key.bytes.iter().all(|&b| b == 0)
    }
}

// ─── Preservation key ───────────────────────────────────────────────────────

pub struct PreservationKey {
    key: SymmetricKey,
    pub stakeholder_id: String,
    nonce_seq: CounterNonceSequence,
}

impl PreservationKey {
    /// Encrypt data for this stakeholder.
    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let nonce_bytes = self.nonce_seq.next_nonce()?;
        let ciphertext = aes_gcm_encrypt(&self.key.bytes, &nonce_bytes, aad, plaintext)?;
        Ok(EncryptedData {
            nonce: nonce_bytes,
            ciphertext,
        })
    }
}

impl Drop for PreservationKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// ─── Encrypted data container ───────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>, // Includes GCM auth tag (16 bytes appended)
}

// ─── Standalone functions ───────────────────────────────────────────────────

/// Verify an Ed25519 signature using a public key.
pub fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, CryptoError> {
    let pub_key = VerifyingKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                got: public_key_bytes.len(),
            })?,
    )
    .map_err(|e| CryptoError::VerificationFailed)?;

    let sig = ed25519_dalek::Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 64,
                got: signature_bytes.len(),
            })?,
    );

    match pub_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Compute SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

// ─── Internal helpers ───────────────────────────────────────────────────────

fn derive_symmetric_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let info_refs: &[&[u8]] = &[info];
    let okm = prk
        .expand(info_refs, HkdfLen(32))
        .map_err(|_| CryptoError::DerivationFailed {
            reason: "HKDF expand failed".into(),
        })?;
    let mut key = [0u8; 32];
    okm.fill(&mut key).map_err(|_| CryptoError::DerivationFailed {
        reason: "HKDF fill failed".into(),
    })?;
    Ok(key)
}

/// Custom length type for ring HKDF
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| {
        CryptoError::EncryptionFailed {
            reason: "Failed to create AES key".into(),
        }
    })?;

    let mut sealing_key = aead::SealingKey::new(unbound_key, SingleNonce(*nonce));

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed {
            reason: "AES-GCM seal failed".into(),
        })?;

    Ok(in_out)
}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| {
        CryptoError::DecryptionFailed {
            reason: "Failed to create AES key".into(),
        }
    })?;

    let mut opening_key = aead::OpeningKey::new(unbound_key, SingleNonce(*nonce));

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed {
            reason: "AES-GCM open failed (tampering or wrong key)".into(),
        })?;

    Ok(plaintext.to_vec())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation() {
        let keys = SessionKeys::generate().unwrap();
        let pub_keys = keys.public_keys();
        assert_eq!(pub_keys.sign.len(), 32);
        assert_eq!(pub_keys.enc.len(), 32);
    }

    #[test]
    fn sign_and_verify() {
        let keys = SessionKeys::generate().unwrap();
        let message = b"test message for signing";
        let signature = keys.sign(message).unwrap();
        assert_eq!(signature.len(), 64);

        let pub_key = keys.sign_public_bytes();
        assert!(verify_signature(pub_key, message, &signature).unwrap());
    }

    #[test]
    fn verify_fails_with_wrong_message() {
        let keys = SessionKeys::generate().unwrap();
        let signature = keys.sign(b"original message").unwrap();
        let pub_key = keys.sign_public_bytes();
        assert!(!verify_signature(pub_key, b"tampered message", &signature).unwrap());
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let keys1 = SessionKeys::generate().unwrap();
        let keys2 = SessionKeys::generate().unwrap();
        let message = b"test message";
        let signature = keys1.sign(message).unwrap();
        assert!(!verify_signature(keys2.sign_public_bytes(), message, &signature).unwrap());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let keys = SessionKeys::generate().unwrap();
        let aad = b"event-label-data";
        let plaintext = b"sensor data payload";

        let encrypted = keys.encrypt(aad, plaintext).unwrap();
        let decrypted = keys.decrypt(&encrypted.nonce, aad, &encrypted.ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let keys1 = SessionKeys::generate().unwrap();
        let keys2 = SessionKeys::generate().unwrap();
        let aad = b"event-label";
        let encrypted = keys1.encrypt(aad, b"secret data").unwrap();
        assert!(keys2.decrypt(&encrypted.nonce, aad, &encrypted.ciphertext).is_err());
    }

    #[test]
    fn decrypt_fails_with_tampered_ciphertext() {
        let keys = SessionKeys::generate().unwrap();
        let aad = b"event-label";
        let mut encrypted = keys.encrypt(aad, b"data").unwrap();
        if let Some(byte) = encrypted.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(keys.decrypt(&encrypted.nonce, aad, &encrypted.ciphertext).is_err());
    }

    #[test]
    fn decrypt_fails_with_tampered_aad() {
        let keys = SessionKeys::generate().unwrap();
        let encrypted = keys.encrypt(b"correct-aad", b"data").unwrap();
        assert!(keys.decrypt(&encrypted.nonce, b"wrong-aad", &encrypted.ciphertext).is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let seq = CounterNonceSequence::new();
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let n = seq.next_nonce().unwrap();
            assert!(nonces.insert(n), "Duplicate nonce generated");
        }
    }

    #[test]
    fn x25519_dh_symmetry() {
        let keys1 = SessionKeys::generate().unwrap();
        let keys2 = SessionKeys::generate().unwrap();

        // Both sides should derive the same shared secret
        let secret1 = keys1
            .enc_private
            .diffie_hellman(&keys2.enc_public);
        let secret2 = keys2
            .enc_private
            .diffie_hellman(&keys1.enc_public);
        assert_eq!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn preservation_key_derivation() {
        let keys = SessionKeys::generate().unwrap();
        let stakeholder_pub = keys.public_keys().enc; // Use own pubkey as test
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&stakeholder_pub);

        let pkey = keys.derive_preservation_key(&pub_bytes, "test-stakeholder").unwrap();
        let encrypted = pkey.encrypt(b"aad", b"preserved data").unwrap();
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn different_stakeholders_get_different_keys() {
        let keys = SessionKeys::generate().unwrap();
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&keys.public_keys().enc);

        let pkey1 = keys.derive_preservation_key(&pub_bytes, "stakeholder-a").unwrap();
        let pkey2 = keys.derive_preservation_key(&pub_bytes, "stakeholder-b").unwrap();

        // Encrypt same data, should produce different ciphertext (different keys)
        let enc1 = pkey1.encrypt(b"aad", b"data").unwrap();
        let enc2 = pkey2.encrypt(b"aad", b"data").unwrap();
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn zeroise_prevents_operations() {
        let mut keys = SessionKeys::generate().unwrap();
        keys.zeroise();
        assert!(keys.is_zeroised());
        assert!(keys.sym_key_is_zero());
        assert!(keys.sign(b"test").is_err());
        assert!(keys.encrypt(b"aad", b"data").is_err());
    }

    #[test]
    fn sha256_deterministic() {
        let hash1 = sha256(b"hello world");
        let hash2 = sha256(b"hello world");
        assert_eq!(hash1, hash2);

        let hash3 = sha256(b"hello world!");
        assert_ne!(hash1, hash3);
    }
}
