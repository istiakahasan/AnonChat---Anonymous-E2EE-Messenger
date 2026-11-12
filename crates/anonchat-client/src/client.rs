//! AnonChat Relay Client API (Network Layer)
//!
//! Communicates with the Blind Relay Server strictly through the Tor transport.

use std::sync::Arc;
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use anonchat_crypto::identity::PreKeyBundle;
use crate::tor::TorTransport;

#[derive(Clone)]
pub struct RelayApiClient {
    server_base_url: String,
    transport: TorTransport,
}

#[derive(Serialize)]
struct EnqueuePayload {
    #[serde(rename = "recipientId")]
    recipient_id: String,
    blob: String,
}

#[derive(Deserialize)]
struct EnqueueResponse {
    #[serde(rename = "messageId")]
    message_id: String,
}

#[derive(Deserialize)]
pub struct InboundMessageItem {
    pub id: String,
    pub blob: String,
    pub timestamp: i64,
}

#[derive(Deserialize)]
struct QueuePollResponse {
    messages: Vec<InboundMessageItem>,
}

impl RelayApiClient {
    pub fn new(server_base_url: String, transport: TorTransport) -> Self {
        Self {
            server_base_url: server_base_url.trim_end_matches('/').to_string(),
            transport,
        }
    }

    /// Uploads the local client's PreKeyBundle to the relay server.
    pub async fn upload_keys(&self, bundle: &PreKeyBundle) -> Result<()> {
        let url = format!("{}/v1/keys", self.server_base_url);
        let bundle_json = serde_json::to_string(bundle)?;

        let response = self
            .transport
            .execute_with_retry(|client| {
                client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(bundle_json.clone())
            })
            .await
            .context("Failed to upload PreKeyBundle to relay")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Server returned error {} on /v1/keys: {}", status, body);
        }

        Ok(())
    }

    /// Fetches a peer's PreKeyBundle (atomically popping one OPK).
    pub async fn fetch_peer_keys(&self, peer_user_id: &str) -> Result<PreKeyBundle> {
        let url = format!("{}/v1/keys/{}", self.server_base_url, peer_user_id);

        let response = self
            .transport
            .execute_with_retry(|client| client.get(&url))
            .await
            .context("Failed to fetch peer prekey bundle")?;

        if response.status() == StatusCode::NOT_FOUND {
            anyhow::bail!("Peer '{}' not found on relay server", peer_user_id);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Relay error {} fetching peer keys: {}", status, body);
        }

        let bundle: PreKeyBundle = response.json().await?;
        Ok(bundle)
    }

    /// Sends an opaque encrypted blob to the recipient.
    pub async fn send_blob(&self, recipient_id: &str, blob_bytes: &[u8]) -> Result<String> {
        let url = format!("{}/v1/queue", self.server_base_url);
        let payload = EnqueuePayload {
            recipient_id: recipient_id.to_string(),
            blob: BASE64.encode(blob_bytes),
        };
        let body_json = serde_json::to_string(&payload)?;

        let response = self
            .transport
            .execute_with_retry(|client| {
                client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(body_json.clone())
            })
            .await
            .context("Failed to enqueue blob via Tor")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Relay error {} on /v1/queue: {}", status, body);
        }

        let res: EnqueueResponse = response.json().await?;
        Ok(res.message_id)
    }

    /// Polls and atomically deletes pending messages from the server queue for this user.
    pub async fn poll_messages(&self, my_user_id: &str) -> Result<Vec<InboundMessageItem>> {
        let url = format!("{}/v1/queue/{}", self.server_base_url, my_user_id);

        let response = self
            .transport
            .execute_with_retry(|client| client.get(&url))
            .await
            .context("Failed to poll message queue via Tor")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Relay error {} on /v1/queue/{}: {}", status, my_user_id, body);
        }

        let res: QueuePollResponse = response.json().await?;
        Ok(res.messages)
    }
}

