//! AnonChat Cryptographic Cipher & Padding Module
//!
//! Security Requirements Checklist Implemented:
//! - [x] No plaintext is ever written to disk without encryption.
//! - [x] Keys are never logged to console.
//! - [x] Messages are padded to a fixed length (4KB) before encryption.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;
use zeroize::Zeroize;

/// Standard fixed block size for message padding (4 KB).
pub const FIXED_MESSAGE_BLOCK_SIZE: usize = 4096;

/// Nonce size for AES-256-GCM (12 bytes / 96 bits).
pub const GCM_NONCE_SIZE: usize = 12;

/// Tag size for AES-256-GCM (16 bytes / 128 bits).
pub const GCM_TAG_SIZE: usize = 16;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("AES-GCM encryption failed")]
    EncryptionFailed,
    #[error("AES-GCM decryption failed (integrity check failed)")]
    DecryptionFailed,
    #[error("Message length ({0}) exceeds maximum allowed block capacity")]
    PayloadTooLarge(usize),
    #[error("Invalid padding or corrupted padded packet")]
    InvalidPadding,
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("Invalid nonce length: expected 12 bytes, got {0}")]
    InvalidNonceLength(usize),
}

/// Pads a plaintext message to a fixed size of `FIXED_MESSAGE_BLOCK_SIZE` (4KB)
/// or an integer multiple thereof if the message is larger.
///
/// Format:
/// [4 bytes: big-endian payload length] + [raw payload] + [cryptographic random padding]
///
/// This prevents traffic analysis from inferring message content via packet size.
pub fn pad_message(payload: &[u8]) -> Result<Vec<u8>, CipherError> {
    let payload_len = payload.len();
    let header_len = 4;
    let min_capacity = header_len + payload_len;

    // Calculate next multiple of FIXED_MESSAGE_BLOCK_SIZE
    let target_size = if min_capacity <= FIXED_MESSAGE_BLOCK_SIZE {
        FIXED_MESSAGE_BLOCK_SIZE
    } else {
        ((min_capacity + FIXED_MESSAGE_BLOCK_SIZE - 1) / FIXED_MESSAGE_BLOCK_SIZE)
            * FIXED_MESSAGE_BLOCK_SIZE
    };

    let padding_len = target_size - min_capacity;
    let mut padded = Vec::with_capacity(target_size);

    // 4-byte big-endian payload length
    padded.extend_from_slice(&(payload_len as u32).to_be_bytes());
    padded.extend_from_slice(payload);

    // Fill the remainder with cryptographically secure random bytes (NOT deterministic zeros)
    let mut padding_bytes = vec![0u8; padding_len];
    OsRng.fill_bytes(&mut padding_bytes);
    padded.extend_from_slice(&padding_bytes);
    padding_bytes.zeroize();

    debug_assert_eq!(padded.len(), target_size);
    Ok(padded)
}

/// Removes fixed-size padding and recovers original plaintext.
pub fn unpad_message(padded: &[u8]) -> Result<Vec<u8>, CipherError> {
    if padded.len() < 4 {
        return Err(CipherError::InvalidPadding);
    }

    let payload_len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

    if 4 + payload_len > padded.len() {
        return Err(CipherError::InvalidPadding);
    }

    let payload = padded[4..4 + payload_len].to_vec();
    Ok(payload)
}

/// Encrypts padded plaintext with AES-256-GCM.
///
/// Uses:
/// - 256-bit symmetric key
/// - 96-bit unique IV/nonce
/// - Associated Data (AAD) for header authentication
pub fn encrypt_aes_gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; GCM_NONCE_SIZE],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CipherError::InvalidKeyLength(key.len()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    // Security requirement: Always pad message to fixed 4KB blocks before encryption
    let padded_plaintext = pad_message(plaintext)?;

    let payload = Payload {
        msg: &padded_plaintext,
        aad: associated_data,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CipherError::EncryptionFailed)?;

    Ok(ciphertext)
}

/// Decrypts AES-256-GCM ciphertext, verifies authentication tag, and strips 4KB padding.
pub fn decrypt_aes_gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; GCM_NONCE_SIZE],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CipherError::InvalidKeyLength(key.len()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    let padded_plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CipherError::DecryptionFailed)?;

    let plaintext = unpad_message(&padded_plaintext)?;
    Ok(plaintext)
}

/// Derives a 96-bit AES-GCM nonce deterministically from a message counter or HKDF
pub fn derive_nonce(chain_counter: u32) -> [u8; GCM_NONCE_SIZE] {
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    // Big-endian 32-bit counter in the last 4 bytes, padded with zeros
    nonce[8..12].copy_from_slice(&chain_counter.to_be_bytes());
    nonce
}

