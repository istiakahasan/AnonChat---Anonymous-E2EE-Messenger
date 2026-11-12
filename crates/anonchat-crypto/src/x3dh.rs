//! AnonChat X3DH (Extended Triple Diffie-Hellman) Key Agreement (Task 2)
//!
//! Security Requirements Checklist Implemented:
//! - [x] No plaintext is ever written to disk without encryption.
//! - [x] Keys are never logged to console.
//! - [x] Mutual authentication: Alice verifies Bob's signature on his Signed PreKey.
//! - [x] Forward Secrecy: Ephemeral keys + One-Time PreKeys guarantee forward secrecy.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use secrecy::{CloneableSecret, DebugSecret, ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::{ClientIdentity, PreKeyBundle, SecretBytes32};

pub const X3DH_KDF_INFO: &[u8] = b"AnonChat_X3DH_v1_Protocol";

#[derive(Error, Debug)]
pub enum X3DHError {
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Ed25519 signature error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
    #[error("Invalid signature on Signed PreKey")]
    InvalidPreKeySignature,
    #[error("One-Time PreKey with ID {0} not found")]
    OneTimePreKeyNotFound(u32),
    #[error("Missing ephemeral key")]
    MissingEphemeralKey,
    #[error("HKDF key derivation failed")]
    KdfFailed,
}

/// The initiation header that Alice attaches to the first message sent to Bob.
/// Allows Bob to derive the identical SharedSecret using his private keys.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct X3DHInitiation {
    /// Alice's Ed25519 Identity public key (Base64)
    pub alice_identity_key: String,
    /// Alice's X25519 Identity DH public key (Base64)
    pub alice_identity_dh_key: String,
    /// Alice's X25519 Ephemeral public key (Base64)
    pub alice_ephemeral_key: String,
    /// ID of Bob's Signed PreKey used
    pub signed_prekey_id: u32,
    /// ID of Bob's One-Time PreKey used, if available
    pub one_time_prekey_id: Option<u32>,
}

/// A zeroizing wrapper around the derived 32-byte SharedSecret
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl DebugSecret for SharedSecret {}
impl CloneableSecret for SharedSecret {}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

/// Performs X3DH key agreement as Alice (initiator).
///
/// 1. Alice fetches Bob's `PreKeyBundle`.
/// 2. Alice verifies the signature on Bob's Signed PreKey using Bob's Identity Key.
/// 3. Alice generates an ephemeral key pair: (EK_A_priv, EK_A_pub).
/// 4. Alice calculates:
///    DH1 = X25519(IK_A_dh_priv, SPK_B_pub)
///    DH2 = X25519(EK_A_priv, IK_B_dh_pub)
///    DH3 = X25519(EK_A_priv, SPK_B_pub)
///    DH4 = X25519(EK_A_priv, OPK_B_pub) [if OPK provided]
/// 5. SharedSecret = HKDF-SHA256(DH1 || DH2 || DH3 [|| DH4])
/// 6. Returns `(SharedSecret, X3DHInitiation)`.
pub fn alice_initiate(
    alice_identity: &ClientIdentity,
    bob_bundle: &PreKeyBundle,
) -> Result<(Secret<SharedSecret>, X3DHInitiation), X3DHError> {
    // 1. Decode Bob's public keys
    let bob_ik_bytes = BASE64.decode(&bob_bundle.identity_key)?;
    let bob_ik_bytes: [u8; 32] = bob_ik_bytes
        .try_into()
        .map_err(|_| X3DHError::InvalidKeyLength)?;
    let bob_identity_key = VerifyingKey::from_bytes(&bob_ik_bytes)?;

    let bob_ik_dh_bytes = BASE64.decode(&bob_bundle.identity_dh_key)?;
    let bob_ik_dh_bytes: [u8; 32] = bob_ik_dh_bytes
        .try_into()
        .map_err(|_| X3DHError::InvalidKeyLength)?;
    let bob_identity_dh_key = X25519PublicKey::from(bob_ik_dh_bytes);

    let bob_spk_bytes = BASE64.decode(&bob_bundle.signed_prekey)?;
    let bob_spk_bytes: [u8; 32] = bob_spk_bytes
        .try_into()
        .map_err(|_| X3DHError::InvalidKeyLength)?;
    let bob_signed_prekey = X25519PublicKey::from(bob_spk_bytes);

    let sig_bytes = BASE64.decode(&bob_bundle.signed_prekey_signature)?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| X3DHError::InvalidKeyLength)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // 2. Alice verifies Bob's signature on his Signed PreKey
    bob_identity_key
        .verify(bob_signed_prekey.as_bytes(), &signature)
        .map_err(|_| X3DHError::InvalidPreKeySignature)?;

    // 3. Generate Alice's ephemeral keypair
    let mut csprng = OsRng;
    let alice_ek_secret = StaticSecret::random_from_rng(&mut csprng);
    let alice_ek_public = X25519PublicKey::from(&alice_ek_secret);

    // 4. Perform Diffie-Hellman operations
    // DH1 = X25519(IK_A_dh_priv, SPK_B_pub)
    let alice_ik_dh_priv = alice_identity.get_identity_dh_secret();
    let dh1 = alice_ik_dh_priv.diffie_hellman(&bob_signed_prekey);

    // DH2 = X25519(EK_A_priv, IK_B_dh_pub)
    let dh2 = alice_ek_secret.diffie_hellman(&bob_identity_dh_key);

    // DH3 = X25519(EK_A_priv, SPK_B_pub)
    let dh3 = alice_ek_secret.diffie_hellman(&bob_signed_prekey);

    // DH4 = X25519(EK_A_priv, OPK_B_pub) (if OPK exists)
    let (dh4_opt, used_opk_id) = if let Some(first_opk) = bob_bundle.one_time_prekeys.first() {
        let opk_bytes = BASE64.decode(&first_opk.key)?;
        let opk_bytes: [u8; 32] = opk_bytes
            .try_into()
            .map_err(|_| X3DHError::InvalidKeyLength)?;
        let bob_opk = X25519PublicKey::from(opk_bytes);
        let dh4 = alice_ek_secret.diffie_hellman(&bob_opk);
        (Some(dh4), Some(first_opk.id))
    } else {
        (None, None)
    };

    // 5. Concatenate DH outputs
    let mut km = Vec::with_capacity(32 * 4);
    km.extend_from_slice(dh1.as_bytes());
    km.extend_from_slice(dh2.as_bytes());
    km.extend_from_slice(dh3.as_bytes());
    if let Some(ref dh4) = dh4_opt {
        km.extend_from_slice(dh4.as_bytes());
    }

    // 6. HKDF-SHA256 to derive SharedSecret
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &km);
    let mut okm = [0u8; 32];
    hk.expand(X3DH_KDF_INFO, &mut okm)
        .map_err(|_| X3DHError::KdfFailed)?;

    km.zeroize();

    let initiation = X3DHInitiation {
        alice_identity_key: BASE64.encode(alice_identity.identity_public.as_bytes()),
        alice_identity_dh_key: BASE64.encode(alice_identity.identity_dh_public.as_bytes()),
        alice_ephemeral_key: BASE64.encode(alice_ek_public.as_bytes()),
        signed_prekey_id: bob_bundle.signed_prekey_id,
        one_time_prekey_id: used_opk_id,
    };

    Ok((Secret::new(SharedSecret(okm)), initiation))
}

/// Performs X3DH key agreement as Bob (receiver of the first message).
///
/// 1. Bob extracts Alice's Identity Key and Ephemeral Key from `X3DHInitiation`.
/// 2. Bob retrieves his SPK private key and (if used) his OPK private key.
/// 3. Bob computes:
///    DH1 = X25519(SPK_B_priv, IK_A_dh_pub)
///    DH2 = X25519(IK_B_dh_priv, EK_A_pub)
///    DH3 = X25519(SPK_B_priv, EK_A_pub)
///    DH4 = X25519(OPK_B_priv, EK_A_pub)
/// 4. SharedSecret = HKDF-SHA256(...) - identical to Alice's!
/// 5. Bob deletes the consumed One-Time PreKey.
pub fn bob_respond(
    bob_identity: &mut ClientIdentity,
    initiation: &X3DHInitiation,
) -> Result<Secret<SharedSecret>, X3DHError> {
    // 1. Decode Alice's public keys
    let alice_ik_dh_bytes = BASE64.decode(&initiation.alice_identity_dh_key)?;
    let alice_ik_dh_bytes: [u8; 32] = alice_ik_dh_bytes
        .try_into()
        .map_err(|_| X3DHError::InvalidKeyLength)?;
    let alice_identity_dh_key = X25519PublicKey::from(alice_ik_dh_bytes);

    let alice_ek_bytes = BASE64.decode(&initiation.alice_ephemeral_key)?;
    let alice_ek_bytes: [u8; 32] = alice_ek_bytes
        .try_into()
        .map_err(|_| X3DHError::InvalidKeyLength)?;
    let alice_ephemeral_key = X25519PublicKey::from(alice_ek_bytes);

    // 2. Retrieve Bob's private keys
    let bob_spk_priv = bob_identity.get_signed_prekey_secret();
    let bob_ik_dh_priv = bob_identity.get_identity_dh_secret();

    // 3. Diffie-Hellman derivations
    // DH1 = X25519(SPK_B_priv, IK_A_dh_pub)
    let dh1 = bob_spk_priv.diffie_hellman(&alice_identity_dh_key);

    // DH2 = X25519(IK_B_dh_priv, EK_A_pub)
    let dh2 = bob_ik_dh_priv.diffie_hellman(&alice_ephemeral_key);

    // DH3 = X25519(SPK_B_priv, EK_A_pub)
    let dh3 = bob_spk_priv.diffie_hellman(&alice_ephemeral_key);

    // DH4 = X25519(OPK_B_priv, EK_A_pub) (if OPK was used)
    let dh4_opt = if let Some(opk_id) = initiation.one_time_prekey_id {
        // Take and immediately destroy Bob's OPK
        let opk_secret = bob_identity
            .take_one_time_prekey(opk_id)
            .map_err(|_| X3DHError::OneTimePreKeyNotFound(opk_id))?;
        let dh4 = opk_secret.diffie_hellman(&alice_ephemeral_key);
        Some(dh4)
    } else {
        None
    };

    // 4. Concatenate DH outputs
    let mut km = Vec::with_capacity(32 * 4);
    km.extend_from_slice(dh1.as_bytes());
    km.extend_from_slice(dh2.as_bytes());
    km.extend_from_slice(dh3.as_bytes());
    if let Some(ref dh4) = dh4_opt {
        km.extend_from_slice(dh4.as_bytes());
    }

    // 5. Derive identical SharedSecret
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &km);
    let mut okm = [0u8; 32];
    hk.expand(X3DH_KDF_INFO, &mut okm)
        .map_err(|_| X3DHError::KdfFailed)?;

    km.zeroize();

    Ok(Secret::new(SharedSecret(okm)))
}

