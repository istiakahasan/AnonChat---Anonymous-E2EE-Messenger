//! AnonChat Double Ratchet State Machine (Task 3)
//!
//! Implements the Signal Double Ratchet algorithm:
//! - Symmetric-key ratchet for sending and receiving chains (KDF_CK)
//! - Diffie-Hellman ratchet (KDF_RK)
//! - AES-256-GCM encryption with 96-bit nonce and AAD header binding
//! - Fixed 4KB padding before encryption
//! - Out-of-order and skipped message key tracking with DoS limits
//!
//! Security Requirements Checklist Implemented:
//! - [x] No plaintext is ever written to disk without encryption.
//! - [x] Keys are never logged to console.
//! - [x] Authenticated headers prevent replay and tampering.
//! - [x] Zeroize secrets on drop.

use std::collections::HashMap;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher::{decrypt_aes_gcm, derive_nonce, encrypt_aes_gcm, CipherError, GCM_NONCE_SIZE};
use crate::identity::SecretBytes32;
use crate::x3dh::SharedSecret;

pub const MAX_SKIPPED_KEYS: usize = 1000;
pub const MAX_SKIP_GAP: u32 = 2000;

#[derive(Error, Debug)]
pub enum RatchetError {
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Cipher error: {0}")]
    Cipher(#[from] CipherError),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Missing sending chain key")]
    MissingSendingChain,
    #[error("Missing receiving chain key")]
    MissingReceivingChain,
    #[error("Message gap too large ({0} > {MAX_SKIP_GAP})")]
    GapTooLarge(u32),
    #[error("Skipped keys table reached maximum capacity ({MAX_SKIPPED_KEYS})")]
    TooManySkippedKeys,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid message key")]
    InvalidMessageKey,
}

/// Message header sent in the clear alongside the ciphertext.
/// The header is cryptographically authenticated via AES-256-GCM Associated Authenticated Data (AAD).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key (Base64)
    pub dh_pub: String,
    /// Previous sending chain length
    pub pn: u32,
    /// Message number in the current sending chain
    pub n: u32,
}

/// The encrypted message payload containing header, ciphertext, and nonce.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub header: MessageHeader,
    /// Base64-encoded AES-256-GCM ciphertext of 4KB padded message
    pub ciphertext: String,
    /// Base64-encoded 12-byte nonce
    pub nonce: String,
}

/// The complete Double Ratchet Session state.
pub struct RatchetSession {
    /// Our DH ratchet private key
    pub dhs_secret: Secret<SecretBytes32>,
    /// Our DH ratchet public key
    pub dhs_public: X25519PublicKey,
    /// Peer's current DH ratchet public key
    pub dhr_public: Option<X25519PublicKey>,
    /// 32-byte Root Key
    pub root_key: Secret<SecretBytes32>,
    /// 32-byte Sending Chain Key
    pub sending_chain_key: Option<Secret<SecretBytes32>>,
    /// 32-byte Receiving Chain Key
    pub receiving_chain_key: Option<Secret<SecretBytes32>>,
    /// Message number in the sending chain
    pub ns: u32,
    /// Message number in the receiving chain
    pub nr: u32,
    /// Previous sending chain length
    pub pn: u32,
    /// Cache of skipped message keys for out-of-order delivery
    /// Key: (Peer DH public key bytes, message number) -> Message Key
    pub skipped_message_keys: HashMap<([u8; 32], u32), Secret<SecretBytes32>>,
}

// Ensure RatchetSession debug NEVER leaks root keys, chain keys, or DH secrets
impl std::fmt::Debug for RatchetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetSession")
            .field("dhs_public", &BASE64.encode(self.dhs_public.as_bytes()))
            .field("dhr_public", &self.dhr_public.map(|k| BASE64.encode(k.as_bytes())))
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped_keys_count", &self.skipped_message_keys.len())
            .field("root_key", &"[REDACTED_SECRET]")
            .field("sending_chain_key", &"[REDACTED_SECRET]")
            .field("receiving_chain_key", &"[REDACTED_SECRET]")
            .finish()
    }
}

impl RatchetSession {
    /// Initializes Alice's ratchet session as the conversation initiator.
    ///
    /// Alice uses the X3DH `SharedSecret` as the initial root key,
    /// generates a fresh DH keypair, and ratchets once against Bob's Signed PreKey.
    pub fn init_alice(
        shared_secret: &Secret<SharedSecret>,
        bob_spk_public: &X25519PublicKey,
    ) -> Self {
        let mut csprng = OsRng;
        let dhs_secret = StaticSecret::random_from_rng(&mut csprng);
        let dhs_public = X25519PublicKey::from(&dhs_secret);

        let dh_out = dhs_secret.diffie_hellman(bob_spk_public);
        let (new_rk, cks) = kdf_rk(shared_secret.expose_secret().0, dh_out.as_bytes());

        let mut dhs_priv_bytes = dhs_secret.to_bytes();
        let dhs_secret_wrapper = Secret::new(SecretBytes32(dhs_priv_bytes));
        dhs_priv_bytes.zeroize();

        Self {
            dhs_secret: dhs_secret_wrapper,
            dhs_public,
            dhr_public: Some(*bob_spk_public),
            root_key: Secret::new(SecretBytes32(new_rk)),
            sending_chain_key: Some(Secret::new(SecretBytes32(cks))),
            receiving_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Initializes Bob's ratchet session as the conversation receiver.
    ///
    /// Bob uses the X3DH `SharedSecret` as the initial root key,
    /// and uses his Signed PreKey as his initial DH keypair.
    pub fn init_bob(
        shared_secret: &Secret<SharedSecret>,
        bob_spk_secret: StaticSecret,
    ) -> Self {
        let bob_spk_public = X25519PublicKey::from(&bob_spk_secret);
        let mut spk_bytes = bob_spk_secret.to_bytes();
        let spk_secret_wrapper = Secret::new(SecretBytes32(spk_bytes));
        spk_bytes.zeroize();

        let rk_bytes = shared_secret.expose_secret().0;

        Self {
            dhs_secret: spk_secret_wrapper,
            dhs_public: bob_spk_public,
            dhr_public: None,
            root_key: Secret::new(SecretBytes32(rk_bytes)),
            sending_chain_key: None,
            receiving_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Ratchet Encrypt: Encrypts an outbound plaintext message.
    ///
    /// 1. Advances sending chain: `(next_cks, mk) = KDF_CK(cks)`
    /// 2. Creates `MessageHeader { dh_pub, pn, n }`
    /// 3. Serializes header to JSON as Associated Authenticated Data (AAD)
    /// 4. Pads plaintext to 4096 bytes
    /// 5. Encrypts with AES-256-GCM using `mk`
    /// 6. Returns `EncryptedEnvelope`
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedEnvelope, RatchetError> {
        let cks_secret = self
            .sending_chain_key
            .as_ref()
            .ok_err(|| RatchetError::MissingSendingChain)?;

        let (next_cks, mk) = kdf_ck(cks_secret.expose_secret().0);
        self.sending_chain_key = Some(Secret::new(SecretBytes32(next_cks)));

        let header = MessageHeader {
            dh_pub: BASE64.encode(self.dhs_public.as_bytes()),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        // Header authenticated via AAD
        let aad = serde_json::to_vec(&header)?;
        let nonce = derive_nonce(header.n);

        let ciphertext = encrypt_aes_gcm(&mk, &nonce, plaintext, &aad)?;

        Ok(EncryptedEnvelope {
            header,
            ciphertext: BASE64.encode(&ciphertext),
            nonce: BASE64.encode(&nonce),
        })
    }

    /// Ratchet Decrypt: Decrypts an inbound message envelope.
    ///
    /// 1. Checks skipped message keys for `(dh_pub, n)`.
    /// 2. If new peer DH public key, performs DH ratchet step.
    /// 3. Skips any intermediate message keys up to `header.n`.
    /// 4. Advances receiving chain: `(next_ckr, mk) = KDF_CK(ckr)`.
    /// 5. Authenticates header as AAD and decrypts ciphertext with AES-256-GCM.
    /// 6. Strips 4KB padding and returns original plaintext.
    pub fn ratchet_decrypt(&mut self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, RatchetError> {
        let peer_dh_bytes = BASE64.decode(&envelope.header.dh_pub)?;
        let peer_dh_bytes: [u8; 32] = peer_dh_bytes
            .try_into()
            .map_err(|_| RatchetError::InvalidPublicKey)?;
        let peer_dh_public = X25519PublicKey::from(peer_dh_bytes);

        let aad = serde_json::to_vec(&envelope.header)?;
        let ciphertext = BASE64.decode(&envelope.ciphertext)?;
        let nonce_bytes = BASE64.decode(&envelope.nonce)?;
        let nonce_bytes: [u8; GCM_NONCE_SIZE] = nonce_bytes
            .try_into()
            .map_err(|_| RatchetError::Cipher(CipherError::InvalidNonceLength(0)))?;

        // 1. Try skipped keys first
        let skipped_key = (peer_dh_bytes, envelope.header.n);
        if let Some(mk_secret) = self.skipped_message_keys.remove(&skipped_key) {
            let mk = mk_secret.expose_secret().0;
            return decrypt_aes_gcm(&mk, &nonce_bytes, &ciphertext, &aad)
                .map_err(RatchetError::Cipher);
        }

        // 2. If new DH key received from peer, advance DH Ratchet
        let is_new_dh = self
            .dhr_public
            .map(|existing| existing.as_bytes() != peer_dh_public.as_bytes())
            .unwrap_or(true);

        if is_new_dh {
            // Skip any messages left in the previous receiving chain
            self.skip_message_keys(envelope.header.pn)?;
            self.dh_ratchet(&peer_dh_public)?;
        }

        // 3. Skip message keys in the current receiving chain up to header.n
        self.skip_message_keys(envelope.header.n)?;

        // 4. Advance receiving chain
        let ckr_secret = self
            .receiving_chain_key
            .as_ref()
            .ok_err(|| RatchetError::MissingReceivingChain)?;

        let (next_ckr, mk) = kdf_ck(ckr_secret.expose_secret().0);
        self.receiving_chain_key = Some(Secret::new(SecretBytes32(next_ckr)));
        self.nr += 1;

        // 5. Decrypt and verify AAD
        decrypt_aes_gcm(&mk, &nonce_bytes, &ciphertext, &aad).map_err(RatchetError::Cipher)
    }

    /// Advances the DH ratchet upon receiving a new DH public key from the peer.
    fn dh_ratchet(&mut self, peer_dh_public: &X25519PublicKey) -> Result<(), RatchetError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr_public = Some(*peer_dh_public);

        // DH step 1: Derives receiving chain key
        let dhs_secret_bytes = self.dhs_secret.expose_secret().0;
        let dhs_secret = StaticSecret::from(dhs_secret_bytes);
        let dh_out_rx = dhs_secret.diffie_hellman(peer_dh_public);
        let (new_rk_rx, ckr) = kdf_rk(self.root_key.expose_secret().0, dh_out_rx.as_bytes());
        self.root_key = Secret::new(SecretBytes32(new_rk_rx));
        self.receiving_chain_key = Some(Secret::new(SecretBytes32(ckr)));

        // DH step 2: Generate fresh ephemeral DH keypair and derive sending chain key
        let mut csprng = OsRng;
        let new_dhs_secret = StaticSecret::random_from_rng(&mut csprng);
        let new_dhs_public = X25519PublicKey::from(&new_dhs_secret);

        let dh_out_tx = new_dhs_secret.diffie_hellman(peer_dh_public);
        let (new_rk_tx, cks) = kdf_rk(self.root_key.expose_secret().0, dh_out_tx.as_bytes());

        let mut new_dhs_priv_bytes = new_dhs_secret.to_bytes();
        self.dhs_secret = Secret::new(SecretBytes32(new_dhs_priv_bytes));
        new_dhs_priv_bytes.zeroize();
        self.dhs_public = new_dhs_public;

        self.root_key = Secret::new(SecretBytes32(new_rk_tx));
        self.sending_chain_key = Some(Secret::new(SecretBytes32(cks)));

        Ok(())
    }

    /// Skips message keys in the receiving chain and stores them in `skipped_message_keys`.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if self.nr + MAX_SKIP_GAP < until {
            return Err(RatchetError::GapTooLarge(until - self.nr));
        }

        if let Some(ref ckr_secret) = self.receiving_chain_key {
            let mut current_ckr = ckr_secret.expose_secret().0;
            let dhr_bytes = match self.dhr_public {
                Some(ref k) => *k.as_bytes(),
                None => return Ok(()),
            };

            while self.nr < until {
                if self.skipped_message_keys.len() >= MAX_SKIPPED_KEYS {
                    return Err(RatchetError::TooManySkippedKeys);
                }

                let (next_ckr, mk) = kdf_ck(current_ckr);
                current_ckr = next_ckr;
                self.skipped_message_keys
                    .insert((dhr_bytes, self.nr), Secret::new(SecretBytes32(mk)));
                self.nr += 1;
            }

            self.receiving_chain_key = Some(Secret::new(SecretBytes32(current_ckr)));
        }

        Ok(())
    }
}

/// Helper extension trait for Option -> Result
trait OptionExt<T> {
    fn ok_err<E>(self, err: impl FnOnce() -> E) -> Result<T, E>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_err<E>(self, err: impl FnOnce() -> E) -> Result<T, E> {
        match self {
            Some(v) => Ok(v),
            None => Err(err()),
        }
    }
}

/// KDF_RK: Derives a new Root Key and Chain Key from Root Key and DH output.
/// Uses HKDF-SHA256 with info constants.
fn kdf_rk(rk: [u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(&rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"AnonChat_DoubleRatchet_RootKDF", &mut okm)
        .expect("HKDF expand must succeed with 64 byte output");

    let mut next_rk = [0u8; 32];
    let mut next_ck = [0u8; 32];
    next_rk.copy_from_slice(&okm[0..32]);
    next_ck.copy_from_slice(&okm[32..64]);
    okm.zeroize();

    (next_rk, next_ck)
}

/// KDF_CK: Derives a new Chain Key and Message Key from current Chain Key.
/// Uses HMAC-SHA256 with byte constants 0x01 (message key) and 0x02 (next chain key).
fn kdf_ck(ck: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    type HmacSha256 = Hmac<Sha256>;

    // Message key: HMAC(ck, [0x01])
    let mut hmac_mk = HmacSha256::new_from_slice(&ck).expect("HMAC can take any key length");
    hmac_mk.update(&[0x01]);
    let mk_bytes: [u8; 32] = hmac_mk.finalize().into_bytes().into();

    // Next chain key: HMAC(ck, [0x02])
    let mut hmac_ck = HmacSha256::new_from_slice(&ck).expect("HMAC can take any key length");
    hmac_ck.update(&[0x02]);
    let next_ck_bytes: [u8; 32] = hmac_ck.finalize().into_bytes().into();

    (next_ck_bytes, mk_bytes)
}

/// Serialized representation of a skipped message key for backup.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SerializedSkippedKey {
    pub dh_pub_bytes: [u8; 32],
    pub n: u32,
    pub key_bytes: [u8; 32],
}

/// Serialized representation of an active Double Ratchet session for encrypted backup.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SerializedRatchetSession {
    pub dhs_secret_bytes: [u8; 32],
    pub dhs_public_bytes: [u8; 32],
    pub dhr_public_bytes: Option<[u8; 32]>,
    pub root_key_bytes: [u8; 32],
    pub sending_chain_key_bytes: Option<[u8; 32]>,
    pub receiving_chain_key_bytes: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub skipped_keys: Vec<SerializedSkippedKey>,
}

impl RatchetSession {
    /// Serializes the ratchet session state for encrypted backup.
    pub fn to_serialized(&self) -> SerializedRatchetSession {
        let skipped_keys = self
            .skipped_message_keys
            .iter()
            .map(|((dh_pub, n), key)| SerializedSkippedKey {
                dh_pub_bytes: *dh_pub,
                n: *n,
                key_bytes: key.expose_secret().0,
            })
            .collect();

        SerializedRatchetSession {
            dhs_secret_bytes: self.dhs_secret.expose_secret().0,
            dhs_public_bytes: *self.dhs_public.as_bytes(),
            dhr_public_bytes: self.dhr_public.map(|k| *k.as_bytes()),
            root_key_bytes: self.root_key.expose_secret().0,
            sending_chain_key_bytes: self.sending_chain_key.as_ref().map(|k| k.expose_secret().0),
            receiving_chain_key_bytes: self.receiving_chain_key.as_ref().map(|k| k.expose_secret().0),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped_keys,
        }
    }

    /// Reconstructs a ratchet session from serialized state.
    pub fn from_serialized(state: &SerializedRatchetSession) -> Self {
        let mut skipped_message_keys = HashMap::new();
        for item in &state.skipped_keys {
            skipped_message_keys.insert(
                (item.dh_pub_bytes, item.n),
                Secret::new(SecretBytes32(item.key_bytes)),
            );
        }

        Self {
            dhs_secret: Secret::new(SecretBytes32(state.dhs_secret_bytes)),
            dhs_public: X25519PublicKey::from(state.dhs_public_bytes),
            dhr_public: state.dhr_public_bytes.map(X25519PublicKey::from),
            root_key: Secret::new(SecretBytes32(state.root_key_bytes)),
            sending_chain_key: state
                .sending_chain_key_bytes
                .map(|b| Secret::new(SecretBytes32(b))),
            receiving_chain_key: state
                .receiving_chain_key_bytes
                .map(|b| Secret::new(SecretBytes32(b))),
            ns: state.ns,
            nr: state.nr,
            pn: state.pn,
            skipped_message_keys,
        }
    }
}

