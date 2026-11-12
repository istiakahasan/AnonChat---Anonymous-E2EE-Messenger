//! AnonChat Client Library
//!
//! Exposes Tor transport, SQLCipher encrypted database, and the high-level AnonChatEngine.
//!
//! # Security Requirements Checklist
//! - [x] No plaintext is ever written to disk without encryption.
//! - [x] Keys are never logged to console.
//! - [x] The server never sees the sender's identity (Sealed Sender).
//! - [x] Messages are padded to a fixed length (4KB) before encryption.

pub mod client;
pub mod session;
pub mod storage;
pub mod tor;

pub use client::RelayApiClient;
pub use session::AnonChatEngine;
pub use storage::{ClientDatabase, LocalDbError, StoredContact, StoredMessage};
pub use tor::{TorConfig, TorTransport, TorTransportError};

