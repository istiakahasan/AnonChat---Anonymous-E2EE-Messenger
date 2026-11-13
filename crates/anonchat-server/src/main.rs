//! AnonChat Blind Relay Server (Task 4)
//!
//! Security Requirements Checklist Implemented:
//! - [x] No plaintext is ever written to disk without encryption.
//! - [x] Keys are never logged to console.
//! - [x] The server never sees the sender's identity.
//! - [x] Messages are padded to a fixed length (4KB) before encryption.
//! - [x] Zero-logging: IP addresses and User-Agent headers are scrubbed and never recorded.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod middleware;
mod routes;
mod storage;

use crate::middleware::zero_logging_middleware;
use crate::routes::{
    drain_queue, enqueue_blob, get_backup, get_keys, upload_backup, upload_keys, AppState,
    MAX_BACKUP_BLOB_SIZE,
};
use crate::storage::{MemoryRelayStorage, PostgresRelayStorage, RelayStorage};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize minimal tracing subscriber that DOES NOT record client headers or IPs
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "anonchat_server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    // Determine storage backend (PostgreSQL vs Memory)
    let storage: Arc<dyn RelayStorage> = match env::var("DATABASE_URL") {
        Ok(db_url) => {
            tracing::info!("Connecting to PostgreSQL database...");
            PostgresRelayStorage::connect(&db_url).await?
        }
        Err(_) => {
            tracing::info!("No DATABASE_URL provided. Running with Ephemeral Memory Storage.");
            MemoryRelayStorage::new()
        }
    };

    let state = AppState { storage };

    // Build API router with zero-logging middleware and 100 MB body limit
    let app = Router::new()
        .route("/v1/keys", post(upload_keys))
        .route("/v1/keys/:userId", get(get_keys))
        .route("/v1/queue", post(enqueue_blob))
        .route("/v1/queue/:userId", get(drain_queue))
        .route("/v1/backup", post(upload_backup))
        .route("/v1/backup/:userId", get(get_backup))
        .layer(DefaultBodyLimit::max(MAX_BACKUP_BLOB_SIZE))
        .layer(axum_middleware::from_fn(zero_logging_middleware))
        .with_state(state);

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("AnonChat Blind Relay listening on http://{}", addr);
    tracing::info!("Zero-logging policy active: IP and User-Agent logging strictly disabled.");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

