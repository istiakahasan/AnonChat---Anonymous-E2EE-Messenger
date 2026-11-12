//! AnonChat Sealed Sender Layer
//!
//! Provides metadata privacy by ensuring the server NEVER sees the sender's identity.
//!
//! Security Requirements Checklist Implemented:
//! - [x] The server never sees the sender's identity (Sealed Sender envelope).
//! - [x] Zero-knowledge relay: The server only sees `recipientId` and an opaque blob.
//! - [x] Keys and sender identity are encrypted with recipient's public key.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use rand_core::OsRng;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::cipher::{decrypt_aes_gcm, derive_nonce, encrypt_aes_gcm, CipherError, GCM_NONCE_SIZE};
use crate::identity::ClientIdentity;
use crate::ratchet::EncryptedEnvelope;
use crate::x3dh::X3DHInitiation;

pub const SEALED_SENDER_KDF_INFO: &[u8] = b"AnonChat_Sealed_Sender_v1";

#[derive(Error, Debug)]
pub enum SealedSenderError {
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Cipher error: {0}")]
    Cipher(#[from] CipherError),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid public key")]
    InvalidPublicKey,
}

/// The inner confidential envelope decrypted ONLY by the recipient.
/// Contains the sender's identity, optional X3DH first-message initiation header,
/// and the double ratchet encrypted payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerSealedPayload {
    /// Alice's User ID (SHA-256 of her Ed25519 Identity Key)
    pub sender_id: String,
    /// Present only on the initial session establishment message
    pub x3dh_initiation: Option<X3DHInitiation>,
    /// The Double Ratchet encrypted envelope
    pub ratchet_envelope: EncryptedEnvelope,
}

/// The opaque envelope submitted to the Blind Relay Server.
/// The server sees ONLY this blob and cannot read the inner payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedSenderEnvelope {
    /// Ephemeral X25519 public key used for this transmission (Base64)
    pub ephemeral_dh_pub: String,
    /// 12-byte nonce for AES-256-GCM (Base64)
    pub nonce: String,
    /// AES-256-GCM ciphertext of `InnerSealedPayload` (Base64)
    pub encrypted_payload: String,
}

/// Seals a message for the recipient so that no intermediate relay can identify the sender.
///
/// 1. Alice generates an ephemeral keypair: (ek_priv, ek_pub).
/// 2. Alice performs DH with Bob's Identity DH public key: `dh = ek_priv.diffie_hellman(bob_ik_dh_pub)`.
/// 3. Alice derives a symmetric key using HKDF-SHA256: `key = HKDF(dh)`.
/// 4. Alice serializes `InnerSealedPayload { sender_id, x3dh_initiation, ratchet_envelope }`.
/// 5. Alice encrypts the payload using AES-256-GCM.
/// 6. Returns `SealedSenderEnvelope`.
pub fn seal_message(
    sender_id: &str,
    bob_identity_dh_pub: &X25519PublicKey,
    x3dh_initiation: Option<X3DHInitiation>,
    ratchet_envelope: EncryptedEnvelope,
) -> Result<SealedSenderEnvelope, SealedSenderError> {
    let inner_payload = InnerSealedPayload {
        sender_id: sender_id.to_string(),
        x3dh_initiation,
        ratchet_envelope,
    };

    let inner_bytes = serde_json::to_vec(&inner_payload)?;

    let mut csprng = OsRng;
    let ephemeral_secret = StaticSecret::random_from_rng(&mut csprng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let dh_out = ephemeral_secret.diffie_hellman(bob_identity_dh_pub);

    // Derive symmetric key via HKDF
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), dh_out.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(SEALED_SENDER_KDF_INFO, &mut sym_key)
        .expect("HKDF expand 32 bytes always succeeds");

    let nonce = derive_nonce(0);
    let aad = ephemeral_public.as_bytes();

    let ciphertext = encrypt_aes_gcm(&sym_key, &nonce, &inner_bytes, aad)?;
    sym_key.zeroize();

    Ok(SealedSenderEnvelope {
        ephemeral_dh_pub: BASE64.encode(ephemeral_public.as_bytes()),
        nonce: BASE64.encode(&nonce),
        encrypted_payload: BASE64.encode(&ciphertext),
    })
}

/// Unseals a message received by Bob from the blind relay server.
///
/// 1. Bob decodes `ephemeral_dh_pub`.
/// 2. Bob performs DH with his Identity DH private key: `dh = bob_ik_dh_priv.diffie_hellman(ephemeral_pub)`.
/// 3. Bob derives identical symmetric key: `key = HKDF(dh)`.
/// 4. Bob decrypts `encrypted_payload` with AES-256-GCM.
/// 5. Bob reconstructs `InnerSealedPayload`, learning Alice's `sender_id`.
pub fn unseal_message(
    bob_identity: &ClientIdentity,
    envelope: &SealedSenderEnvelope,
) -> Result<InnerSealedPayload, SealedSenderError> {
    let ephem_bytes = BASE64.decode(&envelope.ephemeral_dh_pub)?;
    let ephem_bytes: [u8; 32] = ephem_bytes
        .try_into()
        .map_err(|_| SealedSenderError::InvalidPublicKey)?;
    let ephemeral_public = X25519PublicKey::from(ephem_bytes);

    let bob_ik_dh_priv = bob_identity.get_identity_dh_secret();
    let dh_out = bob_ik_dh_priv.diffie_hellman(&ephemeral_public);

    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), dh_out.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(SEALED_SENDER_KDF_INFO, &mut sym_key)
        .expect("HKDF expand 32 bytes always succeeds");

    let ciphertext = BASE64.decode(&envelope.encrypted_payload)?;
    let nonce_bytes = BASE64.decode(&envelope.nonce)?;
    let nonce_bytes: [u8; GCM_NONCE_SIZE] = nonce_bytes
        .try_into()
        .map_err(|_| SealedSenderError::Cipher(CipherError::InvalidNonceLength(0)))?;

    let aad = ephemeral_public.as_bytes();
    let decrypted_bytes = decrypt_aes_gcm(&sym_key, &nonce_bytes, &ciphertext, aad)?;
    sym_key.zeroize();

    let inner: InnerSealedPayload = serde_json::from_slice(&decrypted_bytes)?;
    Ok(inner)
}

