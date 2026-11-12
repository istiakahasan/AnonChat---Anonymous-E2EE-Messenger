//! AnonChat Encrypted Local Storage & Disappearing Messages (SQLCipher)
//!
//! Security Requirements Checklist Implemented:
//! - [x] No plaintext is ever written to disk without encryption (SQLCipher AES-256).
//! - [x] Keys are never logged to console.
//! - [x] Disappearing Messages: Expired messages are permanently wiped from the database.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use chrono::Utc;
use rusqlite::{params, Connection, Result as SqlResult};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info};
use uuid::Uuid;

use anonchat_crypto::identity::SecretBytes32;

#[derive(Error, Debug)]
pub enum LocalDbError {
    #[error("SQLite / SQLCipher error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Database lock poisoned")]
    LockPoisoned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredContact {
    pub friend_code: String,
    pub user_id: String,
    pub nickname: String,
    pub ttl_seconds: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub is_mine: bool,
    pub plaintext: String,
    pub timestamp: i64,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredRatchetSession {
    pub peer_user_id: String,
    pub session_json: String,
    pub updated_at: i64,
}

/// Backup payload data structure containing complete state for encrypted backup containers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupData {
    pub version: u32,
    pub created_at: i64,
    pub identity: anonchat_crypto::SerializedIdentityState,
    pub contacts: Vec<StoredContact>,
    pub verification_states: Vec<anonchat_crypto::ContactVerificationState>,
    pub ratchet_sessions: Vec<StoredRatchetSession>,
    pub messages: Vec<StoredMessage>,
}

/// Thread-safe wrapper around SQLCipher encrypted connection.
#[derive(Clone)]
pub struct ClientDatabase {
    conn: Arc<Mutex<Connection>>,
}

impl ClientDatabase {
    /// Opens or creates an encrypted SQLCipher database file using a 256-bit passphrase/key.
    ///
    /// Security Requirement:
    /// - [x] No plaintext is ever written to disk without encryption.
    pub fn open_encrypted<P: AsRef<Path>>(
        db_path: P,
        encryption_key: &Secret<SecretBytes32>,
    ) -> Result<Self, LocalDbError> {
        let conn = Connection::open(db_path)?;

        // Apply SQLCipher 256-bit AES encryption key
        let key_hex = hex::encode(encryption_key.expose_secret().0);
        conn.pragma_update(None, "key", &format!("x'{}'", key_hex))?;

        // Verify cipher operation
        conn.query_row("SELECT count(*) FROM sqlite_master;", [], |_| Ok(()))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.initialize_schema()?;
        Ok(db)
    }

    /// In-memory encrypted database for ephemeral sessions / tests.
    pub fn open_in_memory(encryption_key: &Secret<SecretBytes32>) -> Result<Self, LocalDbError> {
        let conn = Connection::open_in_memory()?;
        let key_hex = hex::encode(encryption_key.expose_secret().0);
        conn.pragma_update(None, "key", &format!("x'{}'", key_hex))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.initialize_schema()?;
        Ok(db)
    }

    fn initialize_schema(&self) -> Result<(), LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS contacts (
                friend_code TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                nickname TEXT NOT NULL,
                ttl_seconds INTEGER DEFAULT 86400
            );

            CREATE TABLE IF NOT EXISTS ratchet_sessions (
                peer_user_id TEXT PRIMARY KEY,
                session_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                is_mine INTEGER NOT NULL,
                plaintext TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                expires_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS contact_verification (
                contact_id TEXT PRIMARY KEY,
                safety_number TEXT NOT NULL,
                verified_at INTEGER,
                last_remote_key_hex TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id);
            CREATE INDEX IF NOT EXISTS idx_msg_expires ON messages(expires_at);
            "#,
        )?;

        Ok(())
    }

    /// Saves or updates a contact.
    pub fn save_contact(&self, contact: &StoredContact) -> Result<(), LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        conn.execute(
            r#"
            INSERT INTO contacts (friend_code, user_id, nickname, ttl_seconds)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (friend_code) DO UPDATE SET
                nickname = excluded.nickname,
                ttl_seconds = excluded.ttl_seconds;
            "#,
            params![
                contact.friend_code,
                contact.user_id,
                contact.nickname,
                contact.ttl_seconds
            ],
        )?;
        Ok(())
    }

    /// Fetches all stored contacts.
    pub fn list_contacts(&self) -> Result<Vec<StoredContact>, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT friend_code, user_id, nickname, ttl_seconds FROM contacts ORDER BY nickname ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(StoredContact {
                friend_code: row.get(0)?,
                user_id: row.get(1)?,
                nickname: row.get(2)?,
                ttl_seconds: row.get(3)?,
            })
        })?;

        let mut contacts = Vec::new();
        for r in rows {
            contacts.push(r?);
        }
        Ok(contacts)
    }

    /// Updates TTL for a given conversation contact.
    pub fn set_conversation_ttl(
        &self,
        user_id: &str,
        ttl_seconds: Option<i64>,
    ) -> Result<(), LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        conn.execute(
            "UPDATE contacts SET ttl_seconds = ?1 WHERE user_id = ?2",
            params![ttl_seconds, user_id],
        )?;
        Ok(())
    }

    /// Saves or updates contact Safety Number verification state in SQLCipher.
    pub fn save_verification_state(
        &self,
        state: &anonchat_crypto::ContactVerificationState,
    ) -> Result<(), LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        conn.execute(
            r#"
            INSERT INTO contact_verification (contact_id, safety_number, verified_at, last_remote_key_hex)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (contact_id) DO UPDATE SET
                safety_number = excluded.safety_number,
                verified_at = excluded.verified_at,
                last_remote_key_hex = excluded.last_remote_key_hex;
            "#,
            params![
                state.contact_id,
                state.safety_number,
                state.verified_at,
                state.last_remote_key_hex
            ],
        )?;
        Ok(())
    }

    /// Fetches contact Safety Number verification state from SQLCipher.
    pub fn get_verification_state(
        &self,
        contact_id: &str,
    ) -> Result<Option<anonchat_crypto::ContactVerificationState>, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT contact_id, safety_number, verified_at, last_remote_key_hex FROM contact_verification WHERE contact_id = ?1",
        )?;

        let mut rows = stmt.query(params![contact_id])?;
        if let Some(row) = rows.next()? {
            let v_at: Option<i64> = row.get(2)?;
            Ok(Some(anonchat_crypto::ContactVerificationState {
                contact_id: row.get(0)?,
                safety_number: row.get(1)?,
                verified_at: v_at.map(|v| v as u64),
                last_remote_key_hex: row.get(3)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Marks contact safety number as manually verified by user.
    pub fn mark_contact_verified(&self, contact_id: &str) -> Result<(), LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let now = Utc::now().timestamp();
        conn.execute(
            "UPDATE contact_verification SET verified_at = ?1 WHERE contact_id = ?2",
            params![now, contact_id],
        )?;
        Ok(())
    }

    /// Inserts a message into the encrypted database.
    pub fn insert_message(&self, msg: &StoredMessage) -> Result<(), LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        conn.execute(
            r#"
            INSERT INTO messages (id, conversation_id, sender_id, is_mine, plaintext, timestamp, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
            "#,
            params![
                msg.id,
                msg.conversation_id,
                msg.sender_id,
                if msg.is_mine { 1 } else { 0 },
                msg.plaintext,
                msg.timestamp,
                msg.expires_at
            ],
        )?;
        Ok(())
    }

    /// Lists messages for a given conversation, filtering out expired ones.
    pub fn get_messages(&self, conversation_id: &str) -> Result<Vec<StoredMessage>, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let now = Utc::now().timestamp();

        let mut stmt = conn.prepare(
            r#"
            SELECT id, conversation_id, sender_id, is_mine, plaintext, timestamp, expires_at
            FROM messages
            WHERE conversation_id = ?1
              AND (expires_at IS NULL OR expires_at > ?2)
            ORDER BY timestamp ASC
            "#,
        )?;

        let rows = stmt.query_map(params![conversation_id, now], |row| {
            let is_mine_int: i32 = row.get(3)?;
            Ok(StoredMessage {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_id: row.get(2)?,
                is_mine: is_mine_int != 0,
                plaintext: row.get(4)?,
                timestamp: row.get(5)?,
                expires_at: row.get(6)?,
            })
        })?;

        let mut messages = Vec::new();
        for r in rows {
            messages.push(r?);
        }
        Ok(messages)
    }

    /// Disappearing Messages Engine:
    /// Atomically removes all messages whose TTL has expired.
    pub fn purge_expired_messages(&self) -> Result<usize, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let now = Utc::now().timestamp();

        let deleted_count = conn.execute(
            "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;

        if deleted_count > 0 {
            info!("Disappearing Messages: permanently purged {} expired messages from encrypted disk.", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Spawns a background task that continuously runs message TTL cleanup.
    pub fn spawn_ttl_cleanup_worker(self: Arc<Self>, check_interval: Duration) {
        tokio::spawn(async move {
            info!("Disappearing messages background cleaner started.");
            let mut interval = tokio::time::interval(check_interval);

            loop {
                interval.tick().await;
                if let Err(e) = self.purge_expired_messages() {
                    error!("Error purging expired messages: {}", e);
                }
            }
        });
    }

    /// Saves a ratchet session JSON into the encrypted database.
    pub fn save_ratchet_session(&self, peer_user_id: &str, session_json: &str) -> Result<(), LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let now = Utc::now().timestamp();
        conn.execute(
            r#"
            INSERT INTO ratchet_sessions (peer_user_id, session_json, updated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT (peer_user_id) DO UPDATE SET
                session_json = excluded.session_json,
                updated_at = excluded.updated_at;
            "#,
            params![peer_user_id, session_json, now],
        )?;
        Ok(())
    }

    /// Fetches an individual stored ratchet session for a peer.
    pub fn get_ratchet_session(&self, peer_user_id: &str) -> Result<Option<StoredRatchetSession>, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let mut stmt = conn.prepare("SELECT peer_user_id, session_json, updated_at FROM ratchet_sessions WHERE peer_user_id = ?1")?;
        let mut rows = stmt.query(params![peer_user_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(StoredRatchetSession {
                peer_user_id: row.get(0)?,
                session_json: row.get(1)?,
                updated_at: row.get(2)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Fetches all stored ratchet sessions.
    pub fn list_ratchet_sessions(&self) -> Result<Vec<StoredRatchetSession>, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let mut stmt = conn.prepare("SELECT peer_user_id, session_json, updated_at FROM ratchet_sessions")?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredRatchetSession {
                peer_user_id: row.get(0)?,
                session_json: row.get(1)?,
                updated_at: row.get(2)?,
            })
        })?;
        let mut sessions = Vec::new();
        for r in rows {
            sessions.push(r?);
        }
        Ok(sessions)
    }

    /// Lists all contact verification states stored in the encrypted database.
    pub fn list_all_verification_states(&self) -> Result<Vec<anonchat_crypto::ContactVerificationState>, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let mut stmt = conn.prepare("SELECT contact_id, safety_number, verified_at, last_remote_key_hex FROM contact_verification")?;
        let rows = stmt.query_map([], |row| {
            let v_at: Option<i64> = row.get(2)?;
            Ok(anonchat_crypto::ContactVerificationState {
                contact_id: row.get(0)?,
                safety_number: row.get(1)?,
                verified_at: v_at.map(|v| v as u64),
                last_remote_key_hex: row.get(3)?,
            })
        })?;
        let mut states = Vec::new();
        for r in rows {
            states.push(r?);
        }
        Ok(states)
    }

    /// Lists all non-expired messages across all conversations.
    pub fn list_all_unexpired_messages(&self) -> Result<Vec<StoredMessage>, LocalDbError> {
        let conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let now = Utc::now().timestamp();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, conversation_id, sender_id, is_mine, plaintext, timestamp, expires_at
            FROM messages
            WHERE expires_at IS NULL OR expires_at > ?1
            ORDER BY timestamp ASC
            "#,
        )?;
        let rows = stmt.query_map(params![now], |row| {
            let is_mine_int: i32 = row.get(3)?;
            Ok(StoredMessage {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                sender_id: row.get(2)?,
                is_mine: is_mine_int != 0,
                plaintext: row.get(4)?,
                timestamp: row.get(5)?,
                expires_at: row.get(6)?,
            })
        })?;
        let mut messages = Vec::new();
        for r in rows {
            messages.push(r?);
        }
        Ok(messages)
    }

    /// Atomically restores all backup data (contacts, verification states, ratchet sessions, messages)
    /// into the encrypted database within a single SQLite transaction.
    pub fn restore_backup_data(&self, data: &BackupData) -> Result<(), LocalDbError> {
        let mut conn = self.conn.lock().map_err(|_| LocalDbError::LockPoisoned)?;
        let tx = conn.transaction()?;

        // 1. Restore contacts
        for contact in &data.contacts {
            tx.execute(
                r#"
                INSERT INTO contacts (friend_code, user_id, nickname, ttl_seconds)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT (friend_code) DO UPDATE SET
                    nickname = excluded.nickname,
                    ttl_seconds = excluded.ttl_seconds;
                "#,
                params![
                    contact.friend_code,
                    contact.user_id,
                    contact.nickname,
                    contact.ttl_seconds
                ],
            )?;
        }

        // 2. Restore verification states
        for state in &data.verification_states {
            tx.execute(
                r#"
                INSERT INTO contact_verification (contact_id, safety_number, verified_at, last_remote_key_hex)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT (contact_id) DO UPDATE SET
                    safety_number = excluded.safety_number,
                    verified_at = excluded.verified_at,
                    last_remote_key_hex = excluded.last_remote_key_hex;
                "#,
                params![
                    state.contact_id,
                    state.safety_number,
                    state.verified_at,
                    state.last_remote_key_hex
                ],
            )?;
        }

        // 3. Restore ratchet sessions
        for session in &data.ratchet_sessions {
            tx.execute(
                r#"
                INSERT INTO ratchet_sessions (peer_user_id, session_json, updated_at)
                VALUES (?1, ?2, ?3)
                ON CONFLICT (peer_user_id) DO UPDATE SET
                    session_json = excluded.session_json,
                    updated_at = excluded.updated_at;
                "#,
                params![
                    session.peer_user_id,
                    session.session_json,
                    session.updated_at
                ],
            )?;
        }

        // 4. Restore messages (skip already expired messages)
        let now = Utc::now().timestamp();
        for msg in &data.messages {
            if let Some(exp) = msg.expires_at {
                if exp <= now {
                    continue;
                }
            }
            tx.execute(
                r#"
                INSERT OR REPLACE INTO messages (id, conversation_id, sender_id, is_mine, plaintext, timestamp, expires_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
                "#,
                params![
                    msg.id,
                    msg.conversation_id,
                    msg.sender_id,
                    if msg.is_mine { 1 } else { 0 },
                    msg.plaintext,
                    msg.timestamp,
                    msg.expires_at
                ],
            )?;
        }

        tx.commit()?;
        info!(
            "Restored backup data: {} contacts, {} verifications, {} sessions, {} messages",
            data.contacts.len(),
            data.verification_states.len(),
            data.ratchet_sessions.len(),
            data.messages.len()
        );
        Ok(())
    }
}

