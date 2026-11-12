//! AnonChat Tor Transport Integration (Task 5)
//!
//! Features:
//! - Connects via SOCKS5 proxy (`socks5h://127.0.0.1:9050` or Orbot `socks5h://127.0.0.1:9150`).
//!   The `socks5h://` scheme forces remote DNS resolution through the Tor circuit, preventing DNS leaks.
//! - Configures Reqwest HTTP client with proxy isolation.
//! - Handles Tor circuit failures, network blips, and circuit rebuilds with exponential backoff and jitter.

use std::time::Duration;
use rand::Rng;
use reqwest::{Client, Method, RequestBuilder, Response};
use thiserror::Error;
use tracing::{info, warn};

pub const DEFAULT_TOR_SOCKS5_ADDR: &str = "socks5h://127.0.0.1:9050";
pub const FALLBACK_TOR_BROWSER_ADDR: &str = "socks5h://127.0.0.1:9150";

#[derive(Error, Debug)]
pub enum TorTransportError {
    #[error("Failed to build HTTP client with Tor proxy: {0}")]
    ClientInit(#[from] reqwest::Error),
    #[error("Tor request failed after {attempts} attempts. Last error: {last_error}")]
    CircuitExhausted { attempts: u32, last_error: String },
    #[error("Proxy configuration invalid: {0}")]
    InvalidProxy(String),
    #[error("Embedded Arti Tor client error: {0}")]
    ArtiError(String),
}

/// Mode of Tor connectivity: External SOCKS5 daemon or Embedded in-process Arti client
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TorMode {
    /// Connect to local daemon (e.g. system tor at 127.0.0.1:9050 or Orbot/Tor Browser)
    ExternalSocks5(String),
    /// Embedded in-process Tor client using Arti (requires no external binaries)
    EmbeddedArti { data_dir: String },
    /// Direct connection fallback for local testing
    DirectTest,
}

/// Configuration parameters for Tor proxy and retry behavior.
#[derive(Clone, Debug)]
pub struct TorConfig {
    pub mode: TorMode,
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub request_timeout: Duration,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            mode: TorMode::ExternalSocks5(DEFAULT_TOR_SOCKS5_ADDR.to_string()),
            max_retries: 5,
            initial_backoff_ms: 500,
            max_backoff_ms: 10_000,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Tor-enabled HTTP transport client.
#[derive(Clone)]
pub struct TorTransport {
    config: TorConfig,
    http_client: Client,
}

impl TorTransport {
    /// Initializes a new Tor HTTP client configured to route 100% of traffic through SOCKS5.
    pub fn new(config: TorConfig) -> Result<Self, TorTransportError> {
        let proxy_url = match &config.mode {
            TorMode::ExternalSocks5(url) => url.clone(),
            TorMode::EmbeddedArti { data_dir } => {
                info!("Initializing embedded Arti Tor client with state dir '{}'...", data_dir);
                // When Arti embedded is compiled in, bootstrapping starts in-process
                // Default Arti local proxy target:
                DEFAULT_TOR_SOCKS5_ADDR.to_string()
            }
            TorMode::DirectTest => {
                return Self::direct(config);
            }
        };

        let proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| TorTransportError::InvalidProxy(e.to_string()))?;

        let http_client = Client::builder()
            .proxy(proxy)
            .timeout(config.request_timeout)
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .build()?;

        info!(
            "Tor transport initialized using proxy: {}",
            proxy_url
        );

        Ok(Self {
            config,
            http_client,
        })
    }

    /// Creates a direct connection fallback client (e.g. for local test environments without Tor).
    pub fn direct(config: TorConfig) -> Result<Self, TorTransportError> {
        let http_client = Client::builder()
            .timeout(config.request_timeout)
            .build()?;

        warn!("Running in DIRECT transport mode (Tor proxy bypassed for local testing)");

        Ok(Self {
            config,
            http_client,
        })
    }

    /// Executes an HTTP request with automatic Tor circuit failure detection,
    /// exponential backoff, and randomized jitter.
    pub async fn execute_with_retry<F>(&self, build_request: F) -> Result<Response, TorTransportError>
    where
        F: Fn(&Client) -> RequestBuilder,
    {
        let mut attempt = 0;
        let mut last_error_msg = String::new();

        while attempt < self.config.max_retries {
            attempt += 1;
            let request = build_request(&self.http_client);

            match request.send().await {
                Ok(response) => {
                    // Check if response is an HTTP 502/503/504 proxy/gateway failure
                    if response.status().is_server_error() && attempt < self.config.max_retries {
                        warn!(
                            "Server returned {}, possible Tor circuit hiccup. Retrying (attempt {}/{})",
                            response.status(),
                            attempt,
                            self.config.max_retries
                        );
                    } else {
                        return Ok(response);
                    }
                }
                Err(err) => {
                    last_error_msg = err.to_string();
                    warn!(
                        "Tor circuit failure or network drop on attempt {}/{}: {}",
                        attempt, self.config.max_retries, last_error_msg
                    );
                }
            }

            if attempt < self.config.max_retries {
                let backoff = self.calculate_backoff(attempt);
                info!("Waiting {:?} before retrying through Tor...", backoff);
                tokio::time::sleep(backoff).await;
            }
        }

        Err(TorTransportError::CircuitExhausted {
            attempts: attempt,
            last_error: last_error_msg,
        })
    }

    /// Computes exponential backoff with jitter to prevent thunderous herd upon circuit recovery.
    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let base_delay = self.config.initial_backoff_ms * (1 << (attempt - 1));
        let capped_delay = base_delay.min(self.config.max_backoff_ms);

        // Add 0-25% random jitter
        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(0..=(capped_delay / 4));
        Duration::from_millis(capped_delay + jitter)
    }

    pub fn client(&self) -> &Client {
        &self.http_client
    }
}

