//! AnonChat Cryptographic Identity Layer (Task 1)
//!
//! Security Requirements Checklist Implemented:
//! - [x] No plaintext is ever written to disk without encryption.
//! - [x] Keys are never logged to console (using `secrecy` and custom redacted Debug).
//! - [x] Private keys are zeroized on drop.

use std::fmt;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use secrecy::{CloneableSecret, DebugSecret, ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_ONE_TIME_PREKEYS_COUNT: usize = 100;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Failed to decode base64 key: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Failed to parse Ed25519 key: {0}")]
    Ed25519Error(#[from] ed25519_dalek::SignatureError),
    #[error("Signature verification failed for signed prekey")]
    SignatureVerificationFailed,
    #[error("One-Time PreKey with id {0} not found")]
    OneTimePreKeyNotFound(u32),
}

/// A zeroizing secret wrapper for 32-byte private keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes32(pub [u8; 32]);

impl DebugSecret for SecretBytes32 {}
impl CloneableSecret for SecretBytes32 {}

/// Local Client Identity Storage containing private and public components.
///
/// Private keys are guarded with `secrecy::Secret` and `ZeroizeOnDrop`
/// to guarantee they are wiped from RAM when dropped and never accidentally logged.
pub struct ClientIdentity {
    /// Ed25519 Identity private key (for signatures and identity verification)
    pub identity_private: Secret<SecretBytes32>,
    /// Ed25519 Identity public key
    pub identity_public: VerifyingKey,
    /// X25519 Identity DH private key (for X3DH key agreements)
    pub identity_dh_private: Secret<SecretBytes32>,
    /// X25519 Identity DH public key
    pub identity_dh_public: X25519PublicKey,
    /// Signed PreKey ID
    pub signed_prekey_id: u32,
    /// Signed PreKey private key (X25519)
    pub signed_prekey_private: Secret<SecretBytes32>,
    /// Signed PreKey public key (X25519)
    pub signed_prekey_public: X25519PublicKey,
    /// Ed25519 signature over `signed_prekey_public` bytes
    pub signed_prekey_signature: Signature,
    /// Pool of 100 One-Time PreKeys: (id, private_key, public_key)
    pub one_time_prekeys: Vec<(u32, Secret<SecretBytes32>, X25519PublicKey)>,
}

// Ensure ClientIdentity custom Debug NEVER prints private key material
impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("user_id", &self.user_id())
            .field("identity_public", &BASE64.encode(self.identity_public.as_bytes()))
            .field("identity_dh_public", &BASE64.encode(self.identity_dh_public.as_bytes()))
            .field("signed_prekey_id", &self.signed_prekey_id)
            .field("signed_prekey_public", &BASE64.encode(self.signed_prekey_public.as_bytes()))
            .field("one_time_prekeys_count", &self.one_time_prekeys.len())
            .field("identity_private", &"[REDACTED_SECRET]")
            .field("identity_dh_private", &"[REDACTED_SECRET]")
            .field("signed_prekey_private", &"[REDACTED_SECRET]")
            .finish()
    }
}

/// Public PreKey bundle that is uploaded to the Blind Relay Server.
/// Contains ZERO private key material.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreKeyBundle {
    /// Hex-encoded SHA-256 of the Ed25519 Identity public key
    pub user_id: String,
    /// Base64-encoded Ed25519 Identity public key (signing/identity)
    pub identity_key: String,
    /// Base64-encoded X25519 Identity public key (Diffie-Hellman)
    pub identity_dh_key: String,
    /// ID of the Signed PreKey
    pub signed_prekey_id: u32,
    /// Base64-encoded X25519 Signed PreKey public key
    pub signed_prekey: String,
    /// Base64-encoded Ed25519 signature over the Signed PreKey
    pub signed_prekey_signature: String,
    /// List of public One-Time PreKeys (or single OPK returned by server)
    pub one_time_prekeys: Vec<PublicOneTimePreKey>,
}

impl fmt::Debug for PreKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreKeyBundle")
            .field("user_id", &self.user_id)
            .field("identity_key", &self.identity_key)
            .field("signed_prekey_id", &self.signed_prekey_id)
            .field("signed_prekey", &self.signed_prekey)
            .field("one_time_prekeys_count", &self.one_time_prekeys.len())
            .finish()
    }
}

/// Single public one-time prekey entry
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicOneTimePreKey {
    pub id: u32,
    /// Base64-encoded X25519 public key
    pub key: String,
}

impl ClientIdentity {
    /// Generates a complete cryptographic identity:
    /// 1. Ed25519 Identity KeyPair locally.
    /// 2. X25519 Signed PreKey + signature by Identity Key.
    /// 3. 100 One-Time X25519 PreKeys.
    pub fn generate() -> Self {
        // 1. Ed25519 Identity KeyPair (for digital signatures)
        let mut csprng = OsRng;
        let identity_signing_key = SigningKey::generate(&mut csprng);
        let identity_verifying_key = identity_signing_key.verifying_key();

        let mut id_priv_bytes = [0u8; 32];
        id_priv_bytes.copy_from_slice(identity_signing_key.as_bytes());
        let identity_private = Secret::new(SecretBytes32(id_priv_bytes));
        id_priv_bytes.zeroize();

        // 2. X25519 Identity DH KeyPair (for Diffie-Hellman exchanges)
        let id_dh_secret = StaticSecret::random_from_rng(&mut csprng);
        let id_dh_public = X25519PublicKey::from(&id_dh_secret);
        let mut id_dh_priv_bytes = id_dh_secret.to_bytes();
        let identity_dh_private = Secret::new(SecretBytes32(id_dh_priv_bytes));
        id_dh_priv_bytes.zeroize();

        // 3. X25519 Signed PreKey
        let signed_prekey_id = 1u32;
        let spk_secret = StaticSecret::random_from_rng(&mut csprng);
        let spk_public = X25519PublicKey::from(&spk_secret);
        let mut spk_priv_bytes = spk_secret.to_bytes();
        let signed_prekey_private = Secret::new(SecretBytes32(spk_priv_bytes));
        spk_priv_bytes.zeroize();

        // Sign the X25519 Signed PreKey public key using Ed25519 Identity Key
        let signed_prekey_signature = identity_signing_key.sign(spk_public.as_bytes());

        // 4. Generate 100 One-Time PreKeys (OPKs)
        let mut one_time_prekeys = Vec::with_capacity(DEFAULT_ONE_TIME_PREKEYS_COUNT);
        for id in 0..DEFAULT_ONE_TIME_PREKEYS_COUNT as u32 {
            let opk_secret = StaticSecret::random_from_rng(&mut csprng);
            let opk_public = X25519PublicKey::from(&opk_secret);
            let mut opk_priv_bytes = opk_secret.to_bytes();
            let opk_private = Secret::new(SecretBytes32(opk_priv_bytes));
            opk_priv_bytes.zeroize();

            one_time_prekeys.push((id, opk_private, opk_public));
        }

        Self {
            identity_private,
            identity_public: identity_verifying_key,
            identity_dh_private,
            identity_dh_public: id_dh_public,
            signed_prekey_id,
            signed_prekey_private,
            signed_prekey_public: spk_public,
            signed_prekey_signature,
            one_time_prekeys,
        }
    }

    /// Derives the User ID: SHA-256 hash of the public Ed25519 identity key.
    pub fn user_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.identity_public.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Derives the "Friend Code" for easy contact sharing and QR code display.
    pub fn friend_code(&self) -> String {
        format!("anon:fc:{}", self.user_id())
    }

    /// Exports public keys into a `PreKeyBundle` JSON object ready for server upload.
    /// Does NOT include any private keys.
    pub fn export_prekey_bundle(&self) -> PreKeyBundle {
        let public_opks = self
            .one_time_prekeys
            .iter()
            .map(|(id, _, pubkey)| PublicOneTimePreKey {
                id: *id,
                key: BASE64.encode(pubkey.as_bytes()),
            })
            .collect();

        PreKeyBundle {
            user_id: self.user_id(),
            identity_key: BASE64.encode(self.identity_public.as_bytes()),
            identity_dh_key: BASE64.encode(self.identity_dh_public.as_bytes()),
            signed_prekey_id: self.signed_prekey_id,
            signed_prekey: BASE64.encode(self.signed_prekey_public.as_bytes()),
            signed_prekey_signature: BASE64.encode(self.signed_prekey_signature.to_bytes()),
            one_time_prekeys: public_opks,
        }
    }

    /// Returns a copy of the Identity DH StaticSecret
    pub fn get_identity_dh_secret(&self) -> StaticSecret {
        let bytes = self.identity_dh_private.expose_secret().0;
        StaticSecret::from(bytes)
    }

    /// Retrieves and removes a One-Time PreKey private key by ID when answering an X3DH request.
    pub fn take_one_time_prekey(&mut self, opk_id: u32) -> Result<StaticSecret, IdentityError> {
        if let Some(pos) = self.one_time_prekeys.iter().position(|(id, _, _)| *id == opk_id) {
            let (_, secret_wrapper, _) = self.one_time_prekeys.remove(pos);
            let secret_bytes = secret_wrapper.expose_secret().0;
            Ok(StaticSecret::from(secret_bytes))
        } else {
            Err(IdentityError::OneTimePreKeyNotFound(opk_id))
        }
    }

    /// Returns a copy of the Signed PreKey StaticSecret
    pub fn get_signed_prekey_secret(&self) -> StaticSecret {
        let bytes = self.signed_prekey_private.expose_secret().0;
        StaticSecret::from(bytes)
    }

    /// Returns a copy of the Ed25519 SigningKey
    pub fn get_signing_key(&self) -> SigningKey {
        let bytes = self.identity_private.expose_secret().0;
        SigningKey::from_bytes(&bytes)
    }

    /// Serializes the complete client identity state (private keys + metadata) for backup.
    pub fn to_serialized(&self) -> SerializedIdentityState {
        SerializedIdentityState {
            identity_private_bytes: self.identity_private.expose_secret().0,
            identity_dh_private_bytes: self.identity_dh_private.expose_secret().0,
            signed_prekey_id: self.signed_prekey_id,
            signed_prekey_private_bytes: self.signed_prekey_private.expose_secret().0,
            signed_prekey_signature_bytes: self.signed_prekey_signature.to_bytes(),
            one_time_prekeys: self
                .one_time_prekeys
                .iter()
                .map(|(id, sec, _)| SerializedOneTimePreKey {
                    id: *id,
                    private_key_bytes: sec.expose_secret().0,
                })
                .collect(),
        }
    }

    /// Reconstructs and validates a `ClientIdentity` from serialized state.
    pub fn from_serialized(state: &SerializedIdentityState) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(&state.identity_private_bytes);
        let identity_public = signing_key.verifying_key();

        let id_dh_secret = StaticSecret::from(state.identity_dh_private_bytes);
        let identity_dh_public = X25519PublicKey::from(&id_dh_secret);

        let spk_secret = StaticSecret::from(state.signed_prekey_private_bytes);
        let signed_prekey_public = X25519PublicKey::from(&spk_secret);

        let signed_prekey_signature = Signature::from_bytes(&state.signed_prekey_signature_bytes);
        identity_public
            .verify(signed_prekey_public.as_bytes(), &signed_prekey_signature)
            .map_err(|_| IdentityError::SignatureVerificationFailed)?;

        let mut one_time_prekeys = Vec::with_capacity(state.one_time_prekeys.len());
        for opk in &state.one_time_prekeys {
            let secret = StaticSecret::from(opk.private_key_bytes);
            let public = X25519PublicKey::from(&secret);
            one_time_prekeys.push((
                opk.id,
                Secret::new(SecretBytes32(opk.private_key_bytes)),
                public,
            ));
        }

        Ok(Self {
            identity_private: Secret::new(SecretBytes32(state.identity_private_bytes)),
            identity_public,
            identity_dh_private: Secret::new(SecretBytes32(state.identity_dh_private_bytes)),
            identity_dh_public,
            signed_prekey_id: state.signed_prekey_id,
            signed_prekey_private: Secret::new(SecretBytes32(state.signed_prekey_private_bytes)),
            signed_prekey_public,
            signed_prekey_signature,
            one_time_prekeys,
        })
    }
}

/// Serialized representation of a single one-time prekey for encrypted backup.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SerializedOneTimePreKey {
    pub id: u32,
    pub private_key_bytes: [u8; 32],
}

/// Serialized representation of local ClientIdentity secrets for encrypted backup.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` so decrypted key material in RAM
/// is securely wiped on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SerializedIdentityState {
    pub identity_private_bytes: [u8; 32],
    pub identity_dh_private_bytes: [u8; 32],
    pub signed_prekey_id: u32,
    pub signed_prekey_private_bytes: [u8; 32],
    #[zeroize(skip)]
    #[serde(with = "serde_big_array::BigArray")]
    pub signed_prekey_signature_bytes: [u8; 64],
    pub one_time_prekeys: Vec<SerializedOneTimePreKey>,
}

// Redacted Debug impls: these types hold raw private key bytes, so they must
// never print them (security checklist: keys are never logged).
impl fmt::Debug for SerializedOneTimePreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerializedOneTimePreKey")
            .field("id", &self.id)
            .field("private_key_bytes", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for SerializedIdentityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerializedIdentityState")
            .field("identity_private_bytes", &"[REDACTED]")
            .field("identity_dh_private_bytes", &"[REDACTED]")
            .field("signed_prekey_id", &self.signed_prekey_id)
            .field("signed_prekey_private_bytes", &"[REDACTED]")
            .field("one_time_prekeys", &format_args!("[{} redacted]", self.one_time_prekeys.len()))
            .finish()
    }
}
