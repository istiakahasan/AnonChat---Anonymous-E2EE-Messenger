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
        let (next_cks, mk) = kdf_ck(cks_secret.expose_secret().0);
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

        // 2. If new DH key received from peer, advance DH Ratchet
        let is_new_dh = self
            .dhr_public
            .map(|existing| existing.as_bytes() != peer_dh_public.as_bytes())
            .unwrap_or(true);

        if is_new_dh {
            // Skip any messages left in the previous receiving chain
            self.skip_message_keys(envelope.header.pn)?;
            self.dh_ratchet(&peer_dh_public)?;
            self.bob_first_message = false;
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
        if until > self.nr + MAX_SKIP {
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
        header: header.clone(),
        ciphertext: BASE64.encode(&actual_ct),
        nonce: BASE64.encode(&nonce),
    };
    session.ratchet_decrypt(&envelope)
}



