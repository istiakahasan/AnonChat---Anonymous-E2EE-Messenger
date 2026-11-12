//! AnonChat Client Session Manager
//!
//! Ties together Cryptography (X3DH + Double Ratchet + Sealed Sender),
//! Encrypted Storage (SQLCipher + Disappearing Messages TTL),
//! and Network Transport (Tor SOCKS5 + Blind Relay).

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use x25519_dalek::PublicKey as X25519PublicKey;

use anonchat_crypto::{
    alice_initiate, bob_respond, seal_message, unseal_message, ClientIdentity, PreKeyBundle,
    RatchetSession, SealedSenderEnvelope, SerializedRatchetSession,
};

use crate::client::RelayApiClient;
use crate::storage::{ClientDatabase, StoredContact, StoredMessage};

pub struct AnonChatEngine {
    pub identity: Arc<RwLock<ClientIdentity>>,
    pub db: Arc<ClientDatabase>,
    pub api_client: RelayApiClient,
    pub active_ratchets: Arc<RwLock<HashMap<String, RatchetSession>>>,
}

impl AnonChatEngine {
    pub fn new(
        identity: ClientIdentity,
        db: Arc<ClientDatabase>,
        api_client: RelayApiClient,
    ) -> Self {
        Self {
            identity: Arc::new(RwLock::new(identity)),
            db,
            api_client,
            active_ratchets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers / uploads client's public PreKeyBundle to the relay server.
    pub async fn register_on_relay(&self) -> Result<()> {
        let bundle = {
            let id = self.identity.read().await;
            id.export_prekey_bundle()
        };
        self.api_client.upload_keys(&bundle).await?;
        info!("Successfully registered PreKeyBundle on relay.");
        Ok(())
    }

    /// Sends an encrypted message to a peer using X3DH (if first message) + Double Ratchet + Sealed Sender.
    pub async fn send_message(&self, recipient_user_id: &str, plaintext: &str) -> Result<String> {
        let mut ratchets = self.active_ratchets.write().await;
        let mut id_lock = self.identity.write().await;

        let (envelope, x3dh_init) = if let Some(ratchet) = ratchets.get_mut(recipient_user_id) {
            // Existing session: symmetric or DH ratchet step
            let env = ratchet
                .ratchet_encrypt(plaintext.as_bytes())
                .context("Ratchet encrypt failed")?;
            (env, None)
        } else {
            // First message: perform X3DH key agreement
            info!("Initiating X3DH session with peer {}", recipient_user_id);
            let peer_bundle = self.api_client.fetch_peer_keys(recipient_user_id).await?;

            let (shared_secret, initiation) = alice_initiate(&id_lock, &peer_bundle)
                .context("X3DH Alice initiation failed")?;

            let bob_spk_bytes = BASE64.decode(&peer_bundle.signed_prekey)?;
            let bob_spk_bytes: [u8; 32] = bob_spk_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid SPK length"))?;
            let bob_spk_public = X25519PublicKey::from(bob_spk_bytes);

            let mut ratchet = RatchetSession::init_alice(&shared_secret, &bob_spk_public);
            let env = ratchet
                .ratchet_encrypt(plaintext.as_bytes())
                .context("Initial ratchet encrypt failed")?;

            ratchets.insert(recipient_user_id.to_string(), ratchet);
            (env, Some(initiation))
        };

        // Get peer's Identity DH Public Key for Sealed Sender encryption
        let peer_bundle = self.api_client.fetch_peer_keys(recipient_user_id).await?;
        let peer_ik_dh_bytes = BASE64.decode(&peer_bundle.identity_dh_key)?;
        let peer_ik_dh_bytes: [u8; 32] = peer_ik_dh_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid IK DH length"))?;
        let peer_ik_dh_public = X25519PublicKey::from(peer_ik_dh_bytes);

        // Security requirement: Sealed Sender envelope blinds server from sender identity
        let sealed = seal_message(
            &id_lock.user_id(),
            &peer_ik_dh_public,
            x3dh_init,
            envelope,
        )?;

        let blob_bytes = serde_json::to_vec(&sealed)?;
        self.api_client
            .send_blob(recipient_user_id, &blob_bytes)
            .await?;

        // Calculate TTL for disappearing messages
        let contacts = self.db.list_contacts().unwrap_or_default();
        let ttl_seconds = contacts
            .iter()
            .find(|c| c.user_id == recipient_user_id)
            .and_then(|c| c.ttl_seconds)
            .unwrap_or(86400); // Default 24h

        let now = Utc::now().timestamp();
        let expires_at = if ttl_seconds > 0 {
            Some(now + ttl_seconds)
        } else {
            None
        };

        let msg_id = Uuid::new_v4().to_string();
        self.db.insert_message(&StoredMessage {
            id: msg_id.clone(),
            conversation_id: recipient_user_id.to_string(),
            sender_id: id_lock.user_id(),
            is_mine: true,
            plaintext: plaintext.to_string(),
            timestamp: now,
            expires_at,
        })?;

        Ok(msg_id)
    }

    /// Polls relay for queued messages, unseals them, decrypts via Double Ratchet,
    /// and saves them into the SQLCipher database.
    pub async fn receive_messages(&self) -> Result<Vec<StoredMessage>> {
        let my_user_id = {
            let id = self.identity.read().await;
            id.user_id()
        };

        let items = self.api_client.poll_messages(&my_user_id).await?;
        let mut decrypted_messages = Vec::new();

        for item in items {
            let blob_bytes = match BASE64.decode(&item.blob) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let sealed_envelope: SealedSenderEnvelope = match serde_json::from_slice(&blob_bytes) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Unseal the sender envelope
            let inner_payload = {
                let id = self.identity.read().await;
                match unseal_message(&id, &sealed_envelope) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to unseal message: {}", e);
                        continue;
                    }
                }
            };

            let sender_id = inner_payload.sender_id;
            let mut ratchets = self.active_ratchets.write().await;
            let mut id_lock = self.identity.write().await;

            // Handle first message X3DH handshake as Bob
            if let Some(ref initiation) = inner_payload.x3dh_initiation {
                if !ratchets.contains_key(&sender_id) {
                    info!("Received initial X3DH handshake from {}", sender_id);
                    let shared_secret = match bob_respond(&mut id_lock, initiation) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Bob X3DH respond failed: {}", e);
                            continue;
                        }
                    };

                    let bob_spk_secret = id_lock.get_signed_prekey_secret();
                    let ratchet = RatchetSession::init_bob(&shared_secret, bob_spk_secret);
                    ratchets.insert(sender_id.clone(), ratchet);
                }
            }

            let ratchet = match ratchets.get_mut(&sender_id) {
                Some(r) => r,
                None => {
                    warn!("No ratchet session for sender {}", sender_id);
                    continue;
                }
            };

            // Decrypt message
            let plaintext_bytes = match ratchet.ratchet_decrypt(&inner_payload.ratchet_envelope) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Ratchet decryption failed: {}", e);
                    continue;
                }
            };

            let plaintext = match String::from_utf8(plaintext_bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Calculate TTL
            let contacts = self.db.list_contacts().unwrap_or_default();
            let ttl_seconds = contacts
                .iter()
                .find(|c| c.user_id == sender_id)
                .and_then(|c| c.ttl_seconds)
                .unwrap_or(86400);

            let now = Utc::now().timestamp();
            let expires_at = if ttl_seconds > 0 {
                Some(now + ttl_seconds)
            } else {
                None
            };

            let stored = StoredMessage {
                id: item.id,
                conversation_id: sender_id.clone(),
                sender_id,
                is_mine: false,
                plaintext,
                timestamp: item.timestamp / 1000,
                expires_at,
            };

            let _ = self.db.insert_message(&stored);
            decrypted_messages.push(stored);
        }

        Ok(decrypted_messages)
    }

    /// Exports a self-describing encrypted backup container (Sub-Steps 3.1–3.4).
    ///
    /// 1. Serializes client identity secrets into `SerializedIdentityState`.
    /// 2. Collects contacts, verification records, ratchet sessions, and unexpired messages.
    /// 3. Serializes `BackupData` to JSON bytes.
    /// 4. Encrypts payload with Argon2id + AES-256-GCM + 38-byte header AAD.
    /// 5. Returns container bytes `[42-byte header || ciphertext]`.
    pub async fn export_backup(&self, passphrase: &str) -> Result<Vec<u8>> {
        let serialized_identity = {
            let id = self.identity.read().await;
            id.to_serialized()
        };

        let contacts = self.db.list_contacts().context("Failed to list contacts")?;
        let verification_states = self
            .db
            .list_all_verification_states()
            .context("Failed to list verification states")?;
        let messages = self
            .db
            .list_all_unexpired_messages()
            .context("Failed to list messages")?;

        // Collect ratchet sessions
        let mut ratchet_sessions = Vec::new();
        {
            let ratchets = self.active_ratchets.read().await;
            for (peer_id, session) in ratchets.iter() {
                let serialized = session.to_serialized();
                let json = serde_json::to_string(&serialized)
                    .context("Failed to serialize ratchet session")?;
                ratchet_sessions.push(crate::storage::StoredRatchetSession {
                    peer_user_id: peer_id.clone(),
                    session_json: json,
                    updated_at: Utc::now().timestamp(),
                });
            }
        }

        let backup_data = crate::storage::BackupData {
            version: 1,
            created_at: Utc::now().timestamp(),
            identity: serialized_identity,
            contacts,
            verification_states,
            ratchet_sessions,
            messages,
        };

        let json_bytes = serde_json::to_vec(&backup_data)
            .context("Failed to serialize backup data to JSON")?;

        let container = anonchat_crypto::BackupContainer::encrypt_with_passphrase(
            passphrase,
            &json_bytes,
            anonchat_crypto::DEFAULT_ARGON2_TIME_COST,
            anonchat_crypto::DEFAULT_ARGON2_MEMORY_EXPONENT,
            anonchat_crypto::DEFAULT_ARGON2_PARALLELISM,
        )
        .context("Failed to encrypt backup container")?;

        Ok(container.to_bytes())
    }

    /// Restores complete client state from a backup container file (Sub-Step 3.4 Restore Path).
    ///
    /// 1. Reads the 42-byte header, validates magic == "ANON" and version == 0x01.
    /// 2. Enforces resource exhaustion ceilings before Argon2:
    ///    - memory_exponent <= 20
    ///    - time_cost <= 10
    ///    - parallelism <= 4
    /// 3. Derives 256-bit key from file's header parameters.
    /// 4. Decrypts AES-256-GCM ciphertext using header bytes 0..37 as AAD.
    ///    Reports: "Incorrect passphrase or corrupted backup file." on any failure.
    /// 5. Deserializes plaintext JSON into `BackupData`.
    /// 6. Imports identity keys, ratchet sessions, verification records, and messages.
    pub async fn restore_backup(
        &self,
        container_bytes: &[u8],
        passphrase: &str,
    ) -> Result<crate::storage::BackupData> {
        let container = anonchat_crypto::BackupContainer::from_bytes(container_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid backup file format: {}", e))?;

        let decrypted_bytes = container
            .decrypt_with_passphrase(passphrase)
            .map_err(|_| anyhow::anyhow!("Incorrect passphrase or corrupted backup file."))?;

        let backup_data: crate::storage::BackupData = serde_json::from_slice(&decrypted_bytes)
            .map_err(|_| anyhow::anyhow!("Incorrect passphrase or corrupted backup file."))?;

        // 1. Reconstruct and import ClientIdentity
        let restored_identity = ClientIdentity::from_serialized(&backup_data.identity)
            .context("Failed to reconstruct client identity from backup")?;
        {
            let mut id_lock = self.identity.write().await;
            *id_lock = restored_identity;
        }

        // 2. Import contacts, verification records, ratchet sessions, messages atomically into SQLCipher
        self.db
            .restore_backup_data(&backup_data)
            .context("Failed to restore backup data into encrypted database")?;

        // 3. Load restored ratchet sessions into active memory
        {
            let mut ratchets_lock = self.active_ratchets.write().await;
            ratchets_lock.clear();
            for session_entry in &backup_data.ratchet_sessions {
                if let Ok(serialized) =
                    serde_json::from_str::<anonchat_crypto::SerializedRatchetSession>(
                        &session_entry.session_json,
                    )
                {
                    let session = RatchetSession::from_serialized(&serialized);
                    ratchets_lock.insert(session_entry.peer_user_id.clone(), session);
                }
            }
        }

        info!(
            "Successfully restored AnonChat state from backup container: user_id={}",
            self.identity.read().await.user_id()
        );

        Ok(backup_data)
    }

    /// Uploads the encrypted backup container to the blind relay server as an opaque blob.
    ///
    /// Server Requirements:
    /// - Server identifies the user by the hash of their identity public key (user_id).
    /// - Server does not inspect, parse, or log the backup contents.
    /// - Replaces previous backups (keeps only latest).
    ///
    /// Client-Side Confirmation:
    /// Displays: "Backup encrypted and uploaded. Your passphrase is the only way to restore it. We cannot recover it if you forget it."
    /// (No success checkmark that implies the server can assist with recovery).
    pub async fn upload_backup_to_server(&self, passphrase: &str) -> Result<String> {
        let backup_bytes = self.export_backup(passphrase).await?;
        let user_id = {
            let id = self.identity.read().await;
            id.user_id()
        };

        self.api_client.upload_backup(&user_id, &backup_bytes).await?;

        Ok(
            "Backup encrypted and uploaded. Your passphrase is the only way to restore it. We cannot recover it if you forget it."
                .to_string(),
        )
    }

    /// Fetches the opaque backup blob from the server and restores complete client state.
    pub async fn restore_backup_from_server(
        &self,
        passphrase: &str,
    ) -> Result<crate::storage::BackupData> {
        let user_id = {
            let id = self.identity.read().await;
            id.user_id()
        };

        let backup_bytes = self.api_client.fetch_backup(&user_id).await?;
        self.restore_backup(&backup_bytes, passphrase).await
    }
}

