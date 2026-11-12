//! AnonChat HTTP Blind Relay API Routes (Task 4)
//!
//! Endpoints:
//! - POST /v1/keys         : Uploads public PreKeyBundle
//! - GET  /v1/keys/:userId : Fetches public PreKeyBundle (atomically pops 1 One-Time PreKey)
//! - POST /v1/queue        : Enqueues an opaque encrypted blob for recipientId
//! - GET  /v1/queue/:userId: Fetches and ATOMICALLY DELETES all pending blobs for that user

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use anonchat_crypto::identity::PreKeyBundle;
use crate::storage::RelayStorage;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn RelayStorage>,
}

#[derive(Serialize, Deserialize)]
pub struct EnqueuePayload {
    #[serde(rename = "recipientId")]
    pub recipient_id: String,
    /// Base64-encoded encrypted blob (sealed sender envelope)
    pub blob: String,
}

#[derive(Serialize, Deserialize)]
pub struct EnqueueResponse {
    pub status: String,
    #[serde(rename = "messageId")]
    pub message_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct MessageItem {
    pub id: String,
    pub blob: String,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize)]
pub struct QueueResponse {
    pub messages: Vec<MessageItem>,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// POST /v1/keys: Accepts public PreKeyBundle and stores it associated with UserId
pub async fn upload_keys(
    State(state): State<AppState>,
    Json(bundle): Json<PreKeyBundle>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Validate that bundle.user_id matches SHA-256 of identity_key
    let ik_bytes = match BASE64.decode(&bundle.identity_key) {
        Ok(b) => b,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid base64 in identity_key".into(),
                }),
            ))
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&ik_bytes);
    let expected_user_id = hex::encode(hasher.finalize());

    if bundle.user_id != expected_user_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "UserId mismatch: must match SHA-256 of identity_key".into(),
            }),
        ));
    }

    state
        .storage
        .save_prekey_bundle(bundle)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to store prekey bundle: {}", e),
                }),
            )
        })?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "status": "keys_stored" }))))
}

/// GET /v1/keys/:userId: Returns PreKeyBundle and atomically pops ONE One-Time PreKey.
pub async fn get_keys(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let bundle_opt = state
        .storage
        .get_prekey_bundle_and_pop_opk(&user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Database error: {}", e),
                }),
            )
        })?;

    match bundle_opt {
        Some(bundle) => Ok((StatusCode::OK, Json(bundle))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User not found".into(),
            }),
        )),
    }
}

/// POST /v1/queue: Accepts { recipientId, blob } and enqueues it.
pub async fn enqueue_blob(
    State(state): State<AppState>,
    Json(payload): Json<EnqueuePayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let blob_bytes = BASE64.decode(&payload.blob).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid base64 in blob".into(),
            }),
        )
    })?;

    let message_id = state
        .storage
        .enqueue_message(&payload.recipient_id, blob_bytes)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to enqueue message: {}", e),
                }),
            )
        })?;

    Ok((
        StatusCode::OK,
        Json(EnqueueResponse {
            status: "queued".into(),
            message_id: message_id.to_string(),
        }),
    ))
}

/// GET /v1/queue/:userId: Returns all pending blobs and deletes them immediately upon HTTP 200 response.
pub async fn drain_queue(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let queued = state
        .storage
        .drain_messages(&user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to drain messages: {}", e),
                }),
            )
        })?;

    let message_items = queued
        .into_iter()
        .map(|msg| MessageItem {
            id: msg.id.to_string(),
            blob: BASE64.encode(&msg.blob),
            timestamp: msg.timestamp.timestamp_millis(),
        })
        .collect();

    Ok((StatusCode::OK, Json(QueueResponse { messages: message_items })))
}

