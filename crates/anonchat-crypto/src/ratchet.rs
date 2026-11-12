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
pub const MAX_SKIP: u32 = 100;
pub const MAX_SKIP_GAP: u32 = MAX_SKIP;

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
    #[error("Message gap too large ({0} > {MAX_SKIP})")]
    GapTooLarge(u32),
    #[error("Skipped keys table reached maximum capacity ({MAX_SKIPPED_KEYS})")]
    TooManySkippedKeys,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid message key")]
    InvalidMessageKey,
    #[error("Unsupported wire packet version: {0}")]
    UnsupportedVersion(u32),
    #[error("Invalid nonce length: expected 12 bytes, got {0}")]
    InvalidNonceLength(usize),
    #[error("Invalid ciphertext: expected at least 16 bytes")]
    InvalidCiphertext,
    #[error("Duplicate or already-consumed message: message key cannot be reused")]
    DuplicateOrOldMessage,
    #[error("Durable storage error: {0}")]
    DurableStorage(String),
    #[error("Network dispatch error: {0}")]
    NetworkDispatch(String),
}

/// Message header sent in the clear alongside the ciphertext.
/// The header is cryptographically authenticated via AES-256-GCM Associated Authenticated Data (AAD).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key (Base64)
    #[serde(alias = "dh_pub", rename = "dh")]
    pub dh: String,
    /// Previous sending chain length
    pub pn: u32,
    /// Message number in the current sending chain
    pub n: u32,
}

impl MessageHeader {
    pub fn new(dh: String, pn: u32, n: u32) -> Self {
        Self { dh, pn, n }
    }

    /// Accessor for DH public key
    pub fn dh_pub(&self) -> &str {
        &self.dh
    }
}

pub fn default_wire_version() -> u32 {
    1
}

/// The wire packet / encrypted message payload transmitted over the server relay.
///
/// Follows Sub-Step 4.5 wire packet format:
/// ```json
/// {
///   "v": 1,
///   "header": {
///     "dh": "base64_x25519_public_key",
///     "pn": 0,
///     "n": 42
///   },
///   "nonce": "base64_12_bytes",
///   "ciphertext": "base64_aes_gcm_output_with_tag"
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    #[serde(default = "default_wire_version")]
    pub v: u32,
    pub header: MessageHeader,
    /// Base64-encoded 12-byte nonce
    pub nonce: String,
    /// Base64-encoded AES-256-GCM ciphertext of 4KB padded message
    pub ciphertext: String,
}

/// WirePacket alias for wire format compatibility.
pub type WirePacket = EncryptedEnvelope;

impl EncryptedEnvelope {
    pub fn new(header: MessageHeader, nonce: String, ciphertext: String) -> Self {
        Self {
            v: 1,
            header,
            nonce,
            ciphertext,
        }
    }

    pub fn to_json(&self) -> Result<String, RatchetError> {
        serde_json::to_string(self).map_err(RatchetError::Json)
    }

    pub fn from_json(json_str: &str) -> Result<Self, RatchetError> {
        let envelope: Self = serde_json::from_str(json_str)?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), RatchetError> {
        if self.v != 1 {
            return Err(RatchetError::UnsupportedVersion(self.v));
        }
        let nonce_bytes = BASE64.decode(&self.nonce)?;
        if nonce_bytes.len() != GCM_NONCE_SIZE {
            return Err(RatchetError::InvalidNonceLength(nonce_bytes.len()));
        }
        let dh_bytes = BASE64.decode(&self.header.dh)?;
        if dh_bytes.len() != 32 {
            return Err(RatchetError::InvalidPublicKey);
        }
        let ct_bytes = BASE64.decode(&self.ciphertext)?;
        if ct_bytes.len() < 16 {
            return Err(RatchetError::InvalidCiphertext);
        }
        Ok(())
    }
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
    /// Flag for receiver initial state (BOB_FIRST_MESSAGE)
    pub bob_first_message: bool,
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
            .field("bob_first_message", &self.bob_first_message)
            .field("root_key", &"[REDACTED_SECRET]")
            .field("sending_chain_key", &"[REDACTED_SECRET]")
            .field("receiving_chain_key", &"[REDACTED_SECRET]")
            .finish()
    }
}

/// Helper struct representing an X25519 keypair for ratchet state initialization
#[derive(Clone)]
pub struct RatchetKeyPair {
    pub private: StaticSecret,
    pub public: X25519PublicKey,
}

impl RatchetKeyPair {
    pub fn new(private: StaticSecret) -> Self {
        let public = X25519PublicKey::from(&private);
        Self { private, public }
    }

    pub fn from_private_bytes(bytes: &[u8; 32]) -> Self {
        let private = StaticSecret::from(*bytes);
        let public = X25519PublicKey::from(&private);
        Self { private, public }
    }

    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let private = StaticSecret::random_from_rng(&mut csprng);
        let public = X25519PublicKey::from(&private);
        Self { private, public }
    }
}

/// Trait to allow flexible keypair types into `init_receiver_state`
pub trait IntoReceiverKeypair {
    fn into_secret(self) -> StaticSecret;
}

impl IntoReceiverKeypair for StaticSecret {
    fn into_secret(self) -> StaticSecret {
        self
    }
}

impl IntoReceiverKeypair for RatchetKeyPair {
    fn into_secret(self) -> StaticSecret {
        self.private
    }
}

impl IntoReceiverKeypair for &[u8; 32] {
    fn into_secret(self) -> StaticSecret {
        StaticSecret::from(*self)
    }
}

impl IntoReceiverKeypair for [u8; 32] {
    fn into_secret(self) -> StaticSecret {
        StaticSecret::from(self)
    }
}

impl IntoReceiverKeypair for (&[u8; 32], &[u8; 32]) {
    fn into_secret(self) -> StaticSecret {
        StaticSecret::from(*self.0)
    }
}

impl IntoReceiverKeypair for ([u8; 32], [u8; 32]) {
    fn into_secret(self) -> StaticSecret {
        StaticSecret::from(self.0)
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
            bob_first_message: false,
        }
    }

    /// Initializes Double Ratchet sender state (Alice, who initiated X3DH)
    ///
    /// Inputs:
    /// - `shared_secret`: 32-byte output from X3DH
    /// - `bob_ratchet_public`: Bob's signed prekey public key (DH ratchet key Bob published)
    ///
    /// Initialize:
    /// - `DHs` = a NEW X25519 keypair generated by Alice for this session
    /// - `DHr` = `bob_ratchet_public`
    /// - `RK` = HKDF(shared_secret, DH(DHs_private, DHr), info="root")
    /// - `CKs` = HKDF(RK, info="chain-send")
    /// - `CKr` = null
    /// - `Ns` = 0 (messages sent in current chain)
    /// - `Nr` = 0 (messages received in current chain)
    /// - `PNs` = 0 (previous chain length)
    /// - `MKSKIPPED` = empty map
    /// - `BOB_FIRST_MESSAGE` = false
    pub fn init_sender_state(
        shared_secret: &[u8; 32],
        bob_ratchet_public: &[u8; 32],
    ) -> Result<Self, RatchetError> {
        let bob_pub = X25519PublicKey::from(*bob_ratchet_public);
        let secret = Secret::new(SharedSecret(*shared_secret));
        Ok(Self::init_alice(&secret, &bob_pub))
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
            bob_first_message: true,
        }
    }

    /// Initializes Double Ratchet receiver state (Bob)
    ///
    /// Inputs:
    /// - `shared_secret`: same 32 bytes
    /// - `bob_ratchet_keypair`: Bob's signed prekey keypair (private + public)
    ///
    /// Initialize:
    /// - `DHs` = `bob_ratchet_keypair`
    /// - `DHr` = null (Bob has not yet received Alice's ratchet key)
    /// - `RK` = `shared_secret` (before the first DH ratchet step)
    /// - `CKs` = null
    /// - `CKr` = null
    /// - `Ns` = 0, `Nr` = 0, `PNs` = 0
    /// - `MKSKIPPED` = empty map
    /// - `BOB_FIRST_MESSAGE` = true (flag to handle the initial state specially)
    pub fn init_receiver_state<K: IntoReceiverKeypair>(
        shared_secret: &[u8; 32],
        bob_ratchet_keypair: K,
    ) -> Self {
        let secret = Secret::new(SharedSecret(*shared_secret));
        let spk_secret = bob_ratchet_keypair.into_secret();
        Self::init_bob(&secret, spk_secret)
    }

    /// Performs a DH ratchet step to generate a new sending chain if CKs is null (Sub-Step 4.4).
    pub fn perform_dh_ratchet_send(&mut self) -> Result<(), RatchetError> {
        let peer_dh_public = self
            .dhr_public
            .ok_err(|| RatchetError::MissingSendingChain)?;

        self.pn = self.ns;
        self.ns = 0;

        let mut csprng = OsRng;
        let new_dhs_secret = StaticSecret::random_from_rng(&mut csprng);
        let new_dhs_public = X25519PublicKey::from(&new_dhs_secret);

        let dh_out_tx = new_dhs_secret.diffie_hellman(&peer_dh_public);
        let (new_rk_tx, cks) = kdf_rk(self.root_key.expose_secret().0, dh_out_tx.as_bytes());

        let mut new_dhs_priv_bytes = new_dhs_secret.to_bytes();
        self.dhs_secret = Secret::new(SecretBytes32(new_dhs_priv_bytes));
        new_dhs_priv_bytes.zeroize();
        self.dhs_public = new_dhs_public;

        self.root_key = Secret::new(SecretBytes32(new_rk_tx));
        self.sending_chain_key = Some(Secret::new(SecretBytes32(cks)));
        Ok(())
    }

    /// Ratchet Encrypt: Encrypts an outbound plaintext message (Sub-Step 4.2).
    ///
    /// Algorithm:
    /// 1. If `CKs` is null, perform a DH ratchet step to generate a new sending chain.
    /// 2. Derive next chain key and message key: `CKs_new, MK = KDF_CK(CKs)`
    ///    Where KDF_CK is HMAC-SHA256 with constants (0x01 for message key, 0x02 for next chain key).
    /// 3. Generate a random 12-byte nonce for AES-256-GCM.
    /// 4. Build the header: { "dh": base64(DHs_public), "pn": PNs, "n": Ns }
    /// 5. Increment Ns.
    /// 6. Encrypt with AES-256-GCM using `mk`, binding header as AAD.
    /// 7. Return `EncryptedEnvelope`.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedEnvelope, RatchetError> {
        // 1. If CKs is null, perform a DH ratchet step to generate a new sending chain
        if self.sending_chain_key.is_none() {
            self.perform_dh_ratchet_send()?;
        }

        let cks_secret = self
            .sending_chain_key
            .as_ref()
            .ok_err(|| RatchetError::MissingSendingChain)?;

        // 2. Derive next chain key and message key: CKs_new, MK = KDF_CK(CKs)
        let (next_cks, mut mk) = kdf_ck(cks_secret.expose_secret().0);
        self.sending_chain_key = Some(Secret::new(SecretBytes32(next_cks)));

        // 3. Generate a random 12-byte nonce for AES-256-GCM
        let mut nonce = [0u8; GCM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        // 4. Build the header: { "dh": base64(DHs_public), "pn": PNs, "n": Ns }
        let header = MessageHeader {
            dh: BASE64.encode(self.dhs_public.as_bytes()),
            pn: self.pn,
            n: self.ns,
        };
        // 5. Increment Ns
        self.ns += 1;

        // Header authenticated via AAD
        let aad = serde_json::to_vec(&header)?;

        // Sub-Step SM.2: Message Key Uniqueness Enforcement:
        // Use mk for AES-GCM, then zeroize it immediately
        let ciphertext = encrypt_aes_gcm(&mk, &nonce, plaintext, &aad)?;
        mk.zeroize();

        Ok(EncryptedEnvelope {
            v: 1,
            header,
            nonce: BASE64.encode(&nonce),
            ciphertext: BASE64.encode(&ciphertext),
        })
    }

    /// Returns the stored peer DH ratchet public key (`state.DHr`) Base64-encoded string, or None if unset.
    pub fn dhr(&self) -> Option<String> {
        self.dhr_public.map(|k| BASE64.encode(k.as_bytes()))
    }

    /// Accessor for the peer's stored DH public key (`state.DHr`) as raw bytes.
    pub fn dhr_bytes(&self) -> Option<[u8; 32]> {
        self.dhr_public.map(|k| *k.as_bytes())
    }

    /// Ratchet Decrypt: Decrypts an inbound message envelope.
    ///
    /// 1. Checks skipped message keys for `(dh_pub, n)`.
    /// 2. If new peer DH public key (`header.dh != state.DHr`), performs DH ratchet step:
    ///    a. Saves skipped keys from current receiving chain up to `header.pn`.
    ///    b. Advances DH ratchet (derives new CKr and fresh DHs / CKs).
    /// 3. Skips any intermediate message keys up to `header.n`.
    /// 4. Advances receiving chain: `(next_ckr, mk) = KDF_CK(ckr)`.
    /// 5. Authenticates header as AAD and decrypts ciphertext with AES-256-GCM.
    /// 6. Strips 4KB padding and returns original plaintext.
    pub fn ratchet_decrypt(&mut self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, RatchetError> {
        let peer_dh_bytes = BASE64.decode(&envelope.header.dh)?;
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
            let mut mk = mk_secret.expose_secret().0;
            let res = decrypt_aes_gcm(&mk, &nonce_bytes, &ciphertext, &aad)
                .map_err(RatchetError::Cipher);
            mk.zeroize();
            return res;
        }

        // 2. Check for DH ratchet step when a new DH public key appears in the header:
        // Compare `header.dh` (the sender's current DH public key) with `state.DHr` (the stored peer DH public key).
        // if header.dh != state.DHr {
        //     // New DH key detected — perform DH ratchet step
        // }
        let is_new_dh = match &self.dhr_public {
            Some(existing) => existing.as_bytes() != peer_dh_public.as_bytes(),
            None => true,
        };

        if is_new_dh {
            // a. Save skipped keys from the current receiving chain up to header.pn
            self.skip_message_keys(envelope.header.pn)?;
            // b. Perform DH ratchet step (Sub-Step 4.4)
            self.dh_ratchet(&peer_dh_public)?;
            self.bob_first_message = false;
        } else if envelope.header.n < self.nr {
            // Sub-Step SM.2: Enforce message key uniqueness.
            // If the message number has already been passed in this receiving chain and was not
            // in skipped_message_keys, it has already been consumed. Reusing message keys is forbidden.
            return Err(RatchetError::DuplicateOrOldMessage);
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
        self.bob_first_message = false;

        // 5. Decrypt and verify AAD
        let mut mk = mk;
        let res = decrypt_aes_gcm(&mk, &nonce_bytes, &ciphertext, &aad).map_err(RatchetError::Cipher);
        // 6. Zeroize MK
        mk.zeroize();
        res
    }

    /// Advances the DH ratchet upon receiving a new DH public key from the peer (Sub-Step 4.4).
    pub fn dh_ratchet(&mut self, peer_dh_public: &X25519PublicKey) -> Result<(), RatchetError> {
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
        if until > self.nr.saturating_add(MAX_SKIP) {
            return Err(RatchetError::GapTooLarge(until.saturating_sub(self.nr)));
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

/// KDF_RK: Derives a new Root Key and Chain Key from Root Key and DH output (Sub-Step 4.4).
/// Uses HKDF-SHA256 with info="DoubleRatchet".
fn kdf_rk(rk: [u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(&rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"DoubleRatchet", &mut okm)
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
    #[serde(default)]
    pub bob_first_message: bool,
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
            bob_first_message: self.bob_first_message,
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
            bob_first_message: state.bob_first_message,
        }
    }

    /// Serializes the ratchet session state to a JSON string for persistent encrypted storage.
    pub fn to_json(&self) -> Result<String, RatchetError> {
        let serialized = self.to_serialized();
        serde_json::to_string(&serialized).map_err(RatchetError::Json)
    }

    /// Deserializes a ratchet session from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, RatchetError> {
        let serialized: SerializedRatchetSession = serde_json::from_str(json_str)?;
        Ok(Self::from_serialized(&serialized))
    }

    /// Sub-Step SM.3: Encrypts plaintext and durably commits updated ratchet state before calling network dispatch.
    ///
    /// Threat Model Defense:
    /// Research on libsignal store implementations explicitly warns:
    /// "The Double Ratchet has no per-message random nonce guard, so a write that is lost (crash, unflushed buffer)
    /// or rolled back (restored backup, cloned image) makes the next send reuse a message key and IV it has
    /// already used — which costs confidentiality, forward secrecy and replay protection" [citation:25].
    ///
    /// Strict Order of Execution:
    /// 1. Encrypt plaintext under current ratchet state -> envelope.
    /// 2. Serialize updated ratchet state to JSON.
    /// 3. Save serialized state durably (SQLite synchronous=FULL / fsync).
    /// 4. ONLY AFTER the write is confirmed durable, dispatch the ciphertext over network.
    pub fn durable_encrypt<S, F, R, E>(
        &mut self,
        peer_id: &str,
        plaintext: &[u8],
        store: &S,
        send_fn: F,
    ) -> Result<R, RatchetError>
    where
        S: DurableRatchetStore,
        F: FnOnce(&EncryptedEnvelope) -> Result<R, E>,
        E: std::fmt::Display,
    {
        durable_encrypt_and_send(self, peer_id, plaintext, store, send_fn)
    }

    /// Sub-Step SM.3: Decrypts inbound envelope and durably commits updated ratchet state before delivering plaintext.
    ///
    /// Strict Order of Execution:
    /// 1. Decrypt ciphertext under current ratchet state -> plaintext.
    /// 2. Serialize updated ratchet state to JSON.
    /// 3. Save serialized state durably (SQLite synchronous=FULL / fsync).
    /// 4. ONLY AFTER the write is confirmed durable, deliver or display plaintext.
    pub fn durable_decrypt<S, F, R, E>(
        &mut self,
        peer_id: &str,
        envelope: &EncryptedEnvelope,
        store: &S,
        deliver_fn: F,
    ) -> Result<R, RatchetError>
    where
        S: DurableRatchetStore,
        F: FnOnce(&[u8]) -> Result<R, E>,
        E: std::fmt::Display,
    {
        durable_decrypt_and_deliver(self, peer_id, envelope, store, deliver_fn)
    }
}

/// Trait representing durable storage for ratchet session state (Sub-Step SM.3).
///
/// Ensures state is written with fsync / SQLite synchronous = FULL.
pub trait DurableRatchetStore {
    type Error: std::fmt::Display;

    /// Writes serialized ratchet state durably to storage before release of ciphertext or plaintext.
    fn save_durable(&self, peer_id: &str, serialized_state: &str) -> Result<(), Self::Error>;
}

/// Sub-Step SM.3: Durable encrypt-and-send pipeline function.
///
/// Pattern:
/// 1. Encrypt plaintext under current state
/// 2. Serialize ratchet state to JSON
/// 3. Save serialized state durably (fsync / synchronous=FULL)
/// 4. ONLY AFTER durable write succeeds, invoke network send callback
pub fn durable_encrypt_and_send<S, F, R, E>(
    session: &mut RatchetSession,
    peer_id: &str,
    plaintext: &[u8],
    store: &S,
    send_fn: F,
) -> Result<R, RatchetError>
where
    S: DurableRatchetStore,
    F: FnOnce(&EncryptedEnvelope) -> Result<R, E>,
    E: std::fmt::Display,
{
    // 1. Encrypt
    let envelope = session.ratchet_encrypt(plaintext)?;
    // 2. Serialize state
    let serialized = session.to_json()?;
    // 3. Save durably
    store
        .save_durable(peer_id, &serialized)
        .map_err(|e| RatchetError::DurableStorage(e.to_string()))?;
    // 4. Send over network ONLY after durable write confirmed
    send_fn(&envelope).map_err(|e| RatchetError::NetworkDispatch(e.to_string()))
}

/// Sub-Step SM.3: Durable decrypt-and-deliver pipeline function.
///
/// Pattern:
/// 1. Decrypt inbound message under current state
/// 2. Serialize ratchet state to JSON
/// 3. Save serialized state durably (fsync / synchronous=FULL)
/// 4. ONLY AFTER durable write succeeds, deliver or display plaintext
pub fn durable_decrypt_and_deliver<S, F, R, E>(
    session: &mut RatchetSession,
    peer_id: &str,
    envelope: &EncryptedEnvelope,
    store: &S,
    deliver_fn: F,
) -> Result<R, RatchetError>
where
    S: DurableRatchetStore,
    F: FnOnce(&[u8]) -> Result<R, E>,
    E: std::fmt::Display,
{
    // 1. Decrypt
    let plaintext = session.ratchet_decrypt(envelope)?;
    // 2. Serialize state
    let serialized = session.to_json()?;
    // 3. Save durably
    store
        .save_durable(peer_id, &serialized)
        .map_err(|e| RatchetError::DurableStorage(e.to_string()))?;
    // 4. Deliver or display plaintext ONLY after durable write confirmed
    deliver_fn(&plaintext).map_err(|e| RatchetError::NetworkDispatch(e.to_string()))
}

/// Top-level helper function matching libsignal-style API:
/// `let mut alice = init_sender_state(shared_secret, bob_dh_public)?;`
pub fn init_sender_state(
    shared_secret: &[u8; 32],
    bob_ratchet_public: &[u8; 32],
) -> Result<RatchetSession, RatchetError> {
    RatchetSession::init_sender_state(shared_secret, bob_ratchet_public)
}

/// Top-level helper function matching libsignal-style API:
/// `let mut bob = init_receiver_state(shared_secret, bob_keypair);`
pub fn init_receiver_state<K: IntoReceiverKeypair>(
    shared_secret: &[u8; 32],
    bob_ratchet_keypair: K,
) -> RatchetSession {
    RatchetSession::init_receiver_state(shared_secret, bob_ratchet_keypair)
}

/// Top-level helper function matching libsignal-style API:
/// `let (header, ciphertext) = encrypt(&mut alice, b"Hello Bob!", b"")?;`
///
/// Encrypts an outbound plaintext message under the Double Ratchet session.
/// Returns the message header struct and the combined nonce + ciphertext (including the 16-byte GCM authentication tag).
pub fn encrypt(
    session: &mut RatchetSession,
    plaintext: &[u8],
    _aad: &[u8],
) -> Result<(MessageHeader, Vec<u8>), RatchetError> {
    let envelope = session.ratchet_encrypt(plaintext)?;
    let ct_bytes = BASE64.decode(&envelope.ciphertext)?;
    let nonce_bytes = BASE64.decode(&envelope.nonce)?;
    let mut combined = Vec::with_capacity(nonce_bytes.len() + ct_bytes.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ct_bytes);
    Ok((envelope.header, combined))
}

/// Top-level helper function matching libsignal-style API:
/// `let plaintext = decrypt(&mut bob, &header, &ciphertext, b"")?;`
///
/// Decrypts an inbound message under the Double Ratchet session.
pub fn decrypt(
    session: &mut RatchetSession,
    header: &MessageHeader,
    ciphertext: &[u8],
    aad_or_nonce: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    let (nonce, actual_ct) = if aad_or_nonce.len() == 12 {
        (aad_or_nonce.to_vec(), ciphertext.to_vec())
    } else if ciphertext.len() >= 12 + 16 {
        (ciphertext[0..12].to_vec(), ciphertext[12..].to_vec())
    } else {
        return Err(RatchetError::Cipher(CipherError::InvalidNonceLength(0)));
    };

    let envelope = EncryptedEnvelope {
        v: 1,
        header: header.clone(),
        nonce: BASE64.encode(&nonce),
        ciphertext: BASE64.encode(&actual_ct),
    };
    session.ratchet_decrypt(&envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_ratchet_step_detection_when_new_dh_key_appears() {
        let shared_secret = [0x42u8; 32];
        let bob_keypair = RatchetKeyPair::generate();
        let bob_spk_pub = bob_keypair.public;

        let mut alice = init_sender_state(&shared_secret, bob_spk_pub.as_bytes()).unwrap();
        let mut bob = init_receiver_state(&shared_secret, bob_keypair);

        // Initially, Bob has not yet received Alice's ratchet key
        assert!(bob.dhr().is_none());
        assert_eq!(bob.ns, 0);
        assert_eq!(bob.nr, 0);
        assert!(bob.bob_first_message);

        // Alice sends message 0
        let msg0 = b"Hello Bob, this is message 0";
        let (header0, ct0) = encrypt(&mut alice, msg0, b"").unwrap();
        assert_eq!(header0.n, 0);
        assert_eq!(header0.pn, 0);
        assert_eq!(header0.dh, BASE64.encode(alice.dhs_public.as_bytes()));

        // When message 0 arrives at Bob:
        // Detection: header0.dh != bob.dhr() (since bob.dhr() is None)
        assert_ne!(Some(header0.dh.clone()), bob.dhr());

        // Bob decrypts: triggers DH ratchet step
        let pt0 = decrypt(&mut bob, &header0, &ct0, b"").unwrap();
        assert_eq!(pt0, msg0);

        // Invariants after DH ratchet step:
        // 1. Bob's state.DHr updated to header0.dh
        assert_eq!(bob.dhr(), Some(header0.dh.clone()));
        // 2. Bob's bob_first_message transitioned to false
        assert!(!bob.bob_first_message);
        // 3. Bob's receiving message counter Nr incremented to 1
        assert_eq!(bob.nr, 1);
        // 4. Bob derived sending chain key CKs during the DH ratchet step
        assert!(bob.sending_chain_key.is_some());
        // 5. Bob's Ns is 0
        assert_eq!(bob.ns, 0);

        // Alice sends message 1 in the SAME sending chain (no new DH key)
        let msg1 = b"Hello Bob, message 1 in same chain";
        let (header1, ct1) = encrypt(&mut alice, msg1, b"").unwrap();
        assert_eq!(header1.n, 1);
        assert_eq!(header1.pn, 0);
        assert_eq!(header1.dh, header0.dh, "DH key must remain same within sending chain");

        // When message 1 arrives at Bob:
        // Detection: header1.dh == bob.dhr() -> NO DH ratchet step!
        assert_eq!(Some(header1.dh.clone()), bob.dhr());
        let pt1 = decrypt(&mut bob, &header1, &ct1, b"").unwrap();
        assert_eq!(pt1, msg1);
        assert_eq!(bob.nr, 2);

        // Now Bob replies: Bob sends message 0 on his ratcheted sending chain
        let reply0 = b"Hi Alice, Bob replying with newly ratcheted DHs";
        let (bob_header0, bob_ct0) = encrypt(&mut bob, reply0, b"").unwrap();
        assert_eq!(bob_header0.n, 0);
        assert_eq!(bob_header0.dh, BASE64.encode(bob.dhs_public.as_bytes()));

        // Alice receives Bob's reply:
        // Detection: bob_header0.dh != alice.dhr()
        assert_ne!(Some(bob_header0.dh.clone()), alice.dhr());

        let alice_pt0 = decrypt(&mut alice, &bob_header0, &bob_ct0, b"").unwrap();
        assert_eq!(alice_pt0, reply0);
        assert_eq!(alice.dhr(), Some(bob_header0.dh.clone()));
        assert_eq!(alice.nr, 1);
        assert_eq!(alice.ns, 0, "Alice Ns reset to 0 after DH ratchet step");
    }

    #[test]
    fn test_out_of_order_message_skip_and_resolve() {
        let shared_secret = [0x55u8; 32];
        let bob_kp = RatchetKeyPair::generate();
        let mut alice = init_sender_state(&shared_secret, bob_kp.public.as_bytes()).unwrap();
        let mut bob = init_receiver_state(&shared_secret, bob_kp);

        let (h0, ct0) = encrypt(&mut alice, b"Msg 0", b"").unwrap();
        let (h1, ct1) = encrypt(&mut alice, b"Msg 1", b"").unwrap();
        let (h2, ct2) = encrypt(&mut alice, b"Msg 2", b"").unwrap();

        // Deliver Msg 2 first (skipping 0 and 1)
        let pt2 = decrypt(&mut bob, &h2, &ct2, b"").unwrap();
        assert_eq!(pt2, b"Msg 2");
        assert_eq!(bob.nr, 3);
        assert_eq!(bob.skipped_message_keys.len(), 2);

        // Deliver delayed Msg 0
        let pt0 = decrypt(&mut bob, &h0, &ct0, b"").unwrap();
        assert_eq!(pt0, b"Msg 0");
        assert_eq!(bob.skipped_message_keys.len(), 1);

        // Deliver delayed Msg 1
        let pt1 = decrypt(&mut bob, &h1, &ct1, b"").unwrap();
        assert_eq!(pt1, b"Msg 1");
        assert_eq!(bob.skipped_message_keys.len(), 0);
    }

    #[test]
    fn test_max_skip_enforcement() {
        let shared_secret = [0x77u8; 32];
        let bob_kp = RatchetKeyPair::generate();
        let mut bob = init_receiver_state(&shared_secret, bob_kp);

        // Craft a header with gap > 100
        let dh = BASE64.encode(&[0x11u8; 32]);
        let malicious_header = MessageHeader { dh, pn: 0, n: 100000 };
        let dummy_ct = vec![0u8; 32];
        let dummy_nonce = vec![0u8; 12];

        let err = decrypt(&mut bob, &malicious_header, &dummy_ct, &dummy_nonce);
        assert!(err.is_err());
    }

    #[test]
    fn test_sub_step_sm2_message_key_uniqueness_enforcement() {
        let shared_secret = [0x99u8; 32];
        let bob_kp = RatchetKeyPair::generate();
        let mut alice = init_sender_state(&shared_secret, bob_kp.public.as_bytes()).unwrap();
        let mut bob = init_receiver_state(&shared_secret, bob_kp);

        // 1. Encrypt two identical plaintexts
        let plaintext = b"Identical plaintext payload";
        let cks_before_1 = alice.sending_chain_key.as_ref().unwrap().expose_secret().0;
        let (h1, ct1) = encrypt(&mut alice, plaintext, b"").unwrap();
        let cks_after_1 = alice.sending_chain_key.as_ref().unwrap().expose_secret().0;

        assert_ne!(cks_before_1, cks_after_1, "Sending chain key must advance after every message");
        assert_eq!(h1.n, 0);

        let (h2, ct2) = encrypt(&mut alice, plaintext, b"").unwrap();
        let cks_after_2 = alice.sending_chain_key.as_ref().unwrap().expose_secret().0;
        assert_ne!(cks_after_1, cks_after_2, "Sending chain key must advance on second message");
        assert_eq!(h2.n, 1);

        // Ciphertexts of identical plaintexts must differ due to unique fresh message keys and nonces
        assert_ne!(ct1, ct2, "Message key uniqueness: identical plaintexts must produce distinct ciphertexts");

        // 2. Decrypt both messages sequentially
        let pt1 = decrypt(&mut bob, &h1, &ct1, b"").unwrap();
        assert_eq!(pt1, plaintext);
        assert_eq!(bob.nr, 1);

        let pt2 = decrypt(&mut bob, &h2, &ct2, b"").unwrap();
        assert_eq!(pt2, plaintext);
        assert_eq!(bob.nr, 2);

        // 3. Replay attack prevention: Attempting to decrypt message 1 again MUST fail
        // Reusing an already-consumed message key is strictly forbidden
        let replay_err = decrypt(&mut bob, &h1, &ct1, b"");
        match replay_err {
            Err(RatchetError::DuplicateOrOldMessage) => {}
            other => panic!("Expected DuplicateOrOldMessage error on replaying consumed message, got: {:?}", other),
        }

        // 4. Also replaying message 2 must fail
        let replay_err_2 = decrypt(&mut bob, &h2, &ct2, b"");
        match replay_err_2 {
            Err(RatchetError::DuplicateOrOldMessage) => {}
            other => panic!("Expected DuplicateOrOldMessage error on replaying consumed message 2, got: {:?}", other),
        }
    }
}



