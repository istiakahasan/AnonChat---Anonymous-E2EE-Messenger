//! AnonChat Cryptographic Engine
//!
//! Provides the core Signal Protocol primitives (X3DH + Double Ratchet)
//! and anonymity layers (Sealed Sender, 4KB fixed padding, zero-knowledge metadata).
//!
//! # Security Requirements Checklist
//! - [x] No plaintext is ever written to disk without encryption.
//! - [x] Keys are never logged to console (guarded by `secrecy` and redacted debuggers).
//! - [x] The server never sees the sender's identity (enforced by Sealed Sender envelopes).
//! - [x] Messages are padded to a fixed length (4096 bytes) before encryption.

pub mod cipher;
pub mod identity;
pub mod ratchet;
pub mod safety_number;
pub mod sealed_sender;
pub mod x3dh;

pub use cipher::{
    decrypt_aes_gcm, encrypt_aes_gcm, pad_message, unpad_message, CipherError,
    FIXED_MESSAGE_BLOCK_SIZE, GCM_NONCE_SIZE, GCM_TAG_SIZE,
};
pub use identity::{
    ClientIdentity, IdentityError, PreKeyBundle, PublicOneTimePreKey, SecretBytes32,
    DEFAULT_ONE_TIME_PREKEYS_COUNT,
};
pub use ratchet::{EncryptedEnvelope, MessageHeader, RatchetError, RatchetSession};
pub use safety_number::{
    compute_individual_fingerprint, derive_safety_number, ContactVerificationState,
    SIGNAL_FINGERPRINT_ITERATIONS,
};
pub use sealed_sender::{
    seal_message, unseal_message, InnerSealedPayload, SealedSenderEnvelope, SealedSenderError,
};
pub use x3dh::{alice_initiate, bob_respond, SharedSecret, X3DHError, X3DHInitiation};

