//! AnonChat Server Storage Engine (Task 4)
//!
//! Implements:
//! - PreKeyBundle storage with atomic One-Time PreKey popping.
//! - Blind message queue with immediate atomic deletion upon retrieval.
//! - Supports both PostgreSQL (production) and In-Memory / SQLite (standalone testing).

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use anonchat_crypto::identity::{PreKeyBundle, PublicOneTimePreKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub id: Uuid,
    pub recipient_id: String,
    pub blob: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredBackup {
    pub user_id: String,
    pub blob: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub size_bytes: i64,
}

/// Abstract Storage Interface for the Blind Relay
#[async_trait::async_trait]
pub trait RelayStorage: Send + Sync {
    /// Stores or updates a user's PreKeyBundle along with their pool of One-Time PreKeys.
    async fn save_prekey_bundle(&self, bundle: PreKeyBundle) -> Result<()>;

    /// Fetches a user's PreKeyBundle and atomically pops ONE One-Time PreKey.
    /// The popped OPK is immediately removed from the database so it cannot be reused.
    async fn get_prekey_bundle_and_pop_opk(&self, user_id: &str) -> Result<Option<PreKeyBundle>>;

    /// Enqueues an encrypted message blob for a recipient.
    async fn enqueue_message(&self, recipient_id: &str, blob: Vec<u8>) -> Result<Uuid>;

    /// Fetches all queued messages for a user and ATOMICALLY DELETES them.
    async fn drain_messages(&self, user_id: &str) -> Result<Vec<QueuedMessage>>;

    /// Stores or replaces the user's latest encrypted backup blob.
    /// Kept strictly as an opaque blob; previous backups are replaced.
    async fn save_backup(&self, user_id: &str, blob: Vec<u8>) -> Result<()>;

    /// Fetches the user's latest encrypted backup blob.
    async fn get_backup(&self, user_id: &str) -> Result<Option<StoredBackup>>;
}

/// In-Memory Storage Engine with fine-grained async locking.
/// Perfect for zero-trace servers, ephemeral instances, and local testing.
#[derive(Default)]
pub struct MemoryRelayStorage {
    /// Maps user_id -> User base bundle without OPKs
    users: RwLock<HashMap<String, UserBundleBase>>,
    /// Maps user_id -> List of One-Time PreKeys
    opk_pools: RwLock<HashMap<String, Vec<PublicOneTimePreKey>>>,
    /// Messages queued per recipient_id
    queues: RwLock<HashMap<String, Vec<QueuedMessage>>>,
    /// Backups stored per user_id (replaces previous, keeps latest)
    backups: RwLock<HashMap<String, StoredBackup>>,
}

#[derive(Clone)]
struct UserBundleBase {
    user_id: String,
    identity_key: String,
    identity_dh_key: String,
    signed_prekey_id: u32,
    signed_prekey: String,
    signed_prekey_signature: String,
}

impl MemoryRelayStorage {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[async_trait::async_trait]
impl RelayStorage for MemoryRelayStorage {
    async fn save_prekey_bundle(&self, bundle: PreKeyBundle) -> Result<()> {
        let base = UserBundleBase {
            user_id: bundle.user_id.clone(),
            identity_key: bundle.identity_key,
            identity_dh_key: bundle.identity_dh_key,
            signed_prekey_id: bundle.signed_prekey_id,
            signed_prekey: bundle.signed_prekey,
            signed_prekey_signature: bundle.signed_prekey_signature,
        };

        let mut users = self.users.write().await;
        users.insert(bundle.user_id.clone(), base);

        let mut opk_pools = self.opk_pools.write().await;
        // Append or replace OPK pool
        let entry = opk_pools.entry(bundle.user_id).or_default();
        entry.extend(bundle.one_time_prekeys);

        Ok(())
    }

    async fn get_prekey_bundle_and_pop_opk(&self, user_id: &str) -> Result<Option<PreKeyBundle>> {
        let users = self.users.read().await;
        let base = match users.get(user_id) {
            Some(b) => b.clone(),
            None => return Ok(None),
        };
        drop(users);

        // Atomically pop ONE OPK
        let mut opk_pools = self.opk_pools.write().await;
        let popped_opk = if let Some(pool) = opk_pools.get_mut(user_id) {
            if pool.is_empty() {
                None
            } else {
                Some(pool.remove(0))
            }
        } else {
            None
        };

        let bundle = PreKeyBundle {
            user_id: base.user_id,
            identity_key: base.identity_key,
            identity_dh_key: base.identity_dh_key,
            signed_prekey_id: base.signed_prekey_id,
            signed_prekey: base.signed_prekey,
            signed_prekey_signature: base.signed_prekey_signature,
            one_time_prekeys: popped_opk.into_iter().collect(),
        };

        Ok(Some(bundle))
    }

    async fn enqueue_message(&self, recipient_id: &str, blob: Vec<u8>) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let message = QueuedMessage {
            id,
            recipient_id: recipient_id.to_string(),
            blob,
            timestamp: Utc::now(),
        };

        let mut queues = self.queues.write().await;
        queues
            .entry(recipient_id.to_string())
            .or_default()
            .push(message);

        Ok(id)
    }

    async fn drain_messages(&self, user_id: &str) -> Result<Vec<QueuedMessage>> {
        let mut queues = self.queues.write().await;
        // Atomically remove and return all messages for this recipient
        let messages = queues.remove(user_id).unwrap_or_default();
        Ok(messages)
    }

    async fn save_backup(&self, user_id: &str, blob: Vec<u8>) -> Result<()> {
        let size_bytes = blob.len() as i64;
        let mut backups = self.backups.write().await;
        // Server-Side Requirement: Replace previous backups for the same user (keep only latest)
        backups.insert(
            user_id.to_string(),
            StoredBackup {
                user_id: user_id.to_string(),
                blob,
                created_at: Utc::now(),
                size_bytes,
            },
        );
        Ok(())
    }

    async fn get_backup(&self, user_id: &str) -> Result<Option<StoredBackup>> {
        let backups = self.backups.read().await;
        Ok(backups.get(user_id).cloned())
    }
}

/// PostgreSQL Relay Storage Implementation using SQLx.
/// Uses transactions to ensure atomic popping of OPKs and atomic message deletion.
pub struct PostgresRelayStorage {
    pool: sqlx::PgPool,
}

impl PostgresRelayStorage {
    pub async fn connect(database_url: &str) -> Result<Arc<Self>> {
        let pool = sqlx::PgPool::connect(database_url)
            .await
            .context("Failed to connect to PostgreSQL")?;

        let storage = Arc::new(Self { pool });
        storage.migrate().await?;
        Ok(storage)
    }

    /// Initializes tables if they do not exist
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(64) PRIMARY KEY,
                identity_key TEXT NOT NULL,
                identity_dh_key TEXT NOT NULL,
                signed_prekey_id INT NOT NULL,
                signed_prekey TEXT NOT NULL,
                signed_prekey_signature TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS one_time_prekeys (
                user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                opk_id INT NOT NULL,
                opk_key TEXT NOT NULL,
                PRIMARY KEY (user_id, opk_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id UUID PRIMARY KEY,
                recipient_id VARCHAR(64) NOT NULL,
                blob BYTEA NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);

            CREATE TABLE IF NOT EXISTS backups (
                user_id VARCHAR(64) PRIMARY KEY,
                blob BYTEA NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                size_bytes BIGINT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await
        .context("PostgreSQL schema initialization failed")?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl RelayStorage for PostgresRelayStorage {
    async fn save_prekey_bundle(&self, bundle: PreKeyBundle) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO users (user_id, identity_key, identity_dh_key, signed_prekey_id, signed_prekey, signed_prekey_signature)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id) DO UPDATE SET
                identity_key = EXCLUDED.identity_key,
                identity_dh_key = EXCLUDED.identity_dh_key,
                signed_prekey_id = EXCLUDED.signed_prekey_id,
                signed_prekey = EXCLUDED.signed_prekey,
                signed_prekey_signature = EXCLUDED.signed_prekey_signature;
            "#,
        )
        .bind(&bundle.user_id)
        .bind(&bundle.identity_key)
        .bind(&bundle.identity_dh_key)
        .bind(bundle.signed_prekey_id as i32)
        .bind(&bundle.signed_prekey)
        .bind(&bundle.signed_prekey_signature)
        .execute(&mut *tx)
        .await?;

        for opk in bundle.one_time_prekeys {
            sqlx::query(
                r#"
                INSERT INTO one_time_prekeys (user_id, opk_id, opk_key)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id, opk_id) DO NOTHING;
                "#,
            )
            .bind(&bundle.user_id)
            .bind(opk.id as i32)
            .bind(&opk.key)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_prekey_bundle_and_pop_opk(&self, user_id: &str) -> Result<Option<PreKeyBundle>> {
        let mut tx = self.pool.begin().await?;

        let user_row = sqlx::query(
            r#"
            SELECT identity_key, identity_dh_key, signed_prekey_id, signed_prekey, signed_prekey_signature
            FROM users WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let user = match user_row {
            Some(u) => u,
            None => return Ok(None),
        };

        // Atomically select and delete ONE One-Time PreKey (FOR UPDATE SKIP LOCKED)
        let opk_row = sqlx::query(
            r#"
            DELETE FROM one_time_prekeys
            WHERE (user_id, opk_id) = (
                SELECT user_id, opk_id FROM one_time_prekeys
                WHERE user_id = $1
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING opk_id, opk_key;
            "#,
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;

        use sqlx::Row;
        let opk_list = match opk_row {
            Some(row) => vec![PublicOneTimePreKey {
                id: row.get::<i32, _>("opk_id") as u32,
                key: row.get::<String, _>("opk_key"),
            }],
            None => Vec::new(),
        };

        Ok(Some(PreKeyBundle {
            user_id: user_id.to_string(),
            identity_key: user.get::<String, _>("identity_key"),
            identity_dh_key: user.get::<String, _>("identity_dh_key"),
            signed_prekey_id: user.get::<i32, _>("signed_prekey_id") as u32,
            signed_prekey: user.get::<String, _>("signed_prekey"),
            signed_prekey_signature: user.get::<String, _>("signed_prekey_signature"),
            one_time_prekeys: opk_list,
        }))
    }

    async fn enqueue_message(&self, recipient_id: &str, blob: Vec<u8>) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO messages (id, recipient_id, blob, timestamp)
            VALUES ($1, $2, $3, NOW());
            "#,
        )
        .bind(id)
        .bind(recipient_id)
        .bind(blob)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    async fn drain_messages(&self, user_id: &str) -> Result<Vec<QueuedMessage>> {
        // Atomically fetch and delete all messages in a single query
        let rows = sqlx::query(
            r#"
            DELETE FROM messages
            WHERE recipient_id = $1
            RETURNING id, recipient_id, blob, timestamp;
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        use sqlx::Row;
        let messages = rows
            .into_iter()
            .map(|row| QueuedMessage {
                id: row.get::<Uuid, _>("id"),
                recipient_id: row.get::<String, _>("recipient_id"),
                blob: row.get::<Vec<u8>, _>("blob"),
                timestamp: row.get::<chrono::DateTime<chrono::Utc>, _>("timestamp"),
            })
            .collect();

        Ok(messages)
    }

    async fn save_backup(&self, user_id: &str, blob: Vec<u8>) -> Result<()> {
        let size_bytes = blob.len() as i64;
        sqlx::query(
            r#"
            INSERT INTO backups (user_id, blob, created_at, size_bytes)
            VALUES ($1, $2, NOW(), $3)
            ON CONFLICT (user_id) DO UPDATE SET
                blob = EXCLUDED.blob,
                created_at = NOW(),
                size_bytes = EXCLUDED.size_bytes;
            "#,
        )
        .bind(user_id)
        .bind(blob)
        .bind(size_bytes)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_backup(&self, user_id: &str) -> Result<Option<StoredBackup>> {
        let row = sqlx::query(
            r#"
            SELECT user_id, blob, created_at, size_bytes
            FROM backups
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            use sqlx::Row;
            StoredBackup {
                user_id: r.get(0),
                blob: r.get(1),
                created_at: r.get(2),
                size_bytes: r.get(3),
            }
        }))
    }
}

