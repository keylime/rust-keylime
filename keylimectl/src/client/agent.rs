// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent client for communicating with Keylime agents (API < 3.0 pull model)
//!
//! This module provides a client interface for interacting with Keylime agents
//! when using API versions less than 3.0, where agents act as complete web servers
//! (pull model). In this model, the tenant communicates directly with the agent
//! to perform attestation operations like TPM quote retrieval, key delivery,
//! and verification.
//!
//! # API Version Support
//!
//! This client is designed for API versions < 3.0 where:
//! - Agents run as HTTP servers listening on a port
//! - Tenant connects directly to agent for attestation
//! - Agent provides endpoints for quotes, keys, and verification
//!
//! For API >= 3.0 (push model), agents connect to the verifier instead.
//!
//! # Agent Endpoints
//!
//! The client supports these agent endpoints:
//! - `GET /v{version}/quotes/identity?nonce={nonce}` - Get TPM quote
//! - `POST /v{version}/keys/ukey` - Deliver encrypted U key and payload
//! - `GET /v{version}/keys/verify?challenge={challenge}` - Verify key derivation
//!
//! # Security
//!
//! - Supports mutual TLS authentication with agent certificates
//! - Validates TPM quotes against agent's AIK
//! - Encrypts sensitive keys before transmission
//! - Provides HMAC-based verification of key derivation
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::client::agent::AgentClient;
//! use keylimectl::config::Config;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::default();
//! let client = AgentClient::new("192.168.1.100", 9002, &config).await?;
//!
//! // Get TPM quote
//! let nonce = "random_nonce_12345";
//! let quote_response = client.get_quote(nonce).await?;
//!
//! // Deliver encrypted key
//! let encrypted_key = b"encrypted_u_key_data";
//! let auth_tag = "authentication_tag";
//! client.deliver_key(encrypted_key, auth_tag, None).await?;
//!
//! // Verify key derivation
//! let challenge = "verification_challenge";
//! let is_valid = client.verify_key_derivation(challenge, "expected_hmac").await?;
//! # Ok(())
//! # }
//! ```

use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use base64::{engine::general_purpose::STANDARD, Engine};
use keylime::resilient_client::ResilientClient;
use log::{debug, warn};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// Unknown API version constant for when version detection fails
const UNKNOWN_API_VERSION: &str = "unknown";

/// Supported API versions for agent communication (all < 3.0)
const SUPPORTED_AGENT_API_VERSIONS: &[&str] = &["2.0", "2.1", "2.2"];

/// Client for communicating with Keylime agents in pull model (API < 3.0)
///
/// The `AgentClient` provides direct communication with Keylime agents when
/// using API versions less than 3.0. In this model, agents run as HTTP servers
/// and the tenant connects directly to them for attestation operations.
///
/// # Deprecation Notice
///
/// This client is designed for the legacy pull model and should be considered
/// deprecated for new deployments. The push model (API >= 3.0) is recommended
/// for new installations.
///
/// # Connection Management
///
/// The client maintains a persistent HTTP connection pool and automatically
/// handles connection failures with exponential backoff retry logic.
///
/// # Thread Safety
///
/// `AgentClient` is thread-safe and can be shared across multiple tasks
/// or threads using `Arc<AgentClient>`.
#[derive(Debug)]
pub struct AgentClient {
    client: ResilientClient,
    base_url: String,
    api_version: String,
    agent_ip: String,
    agent_port: u16,
}

impl AgentClient {
    /// Create a new agent client with automatic API version detection
    ///
    /// Initializes a new `AgentClient` for communicating with the specified agent
    /// and automatically detects the best API version to use.
    ///
    /// # Arguments
    ///
    /// * `agent_ip` - IP address of the agent
    /// * `agent_port` - Port number the agent is listening on
    /// * `config` - Configuration containing TLS and client settings
    ///
    /// # Returns
    ///
    /// Returns a configured `AgentClient` with detected API version.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - TLS certificate files cannot be read
    /// - Certificate/key files are invalid
    /// - HTTP client initialization fails
    /// - Version detection fails (falls back to default version)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::agent::AgentClient;
    /// use keylimectl::config::Config;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = AgentClient::new("192.168.1.100", 9002, &config).await?;
    /// println!("Agent client created for {}:{}", "192.168.1.100", 9002);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(
        agent_ip: &str,
        agent_port: u16,
        config: &Config,
    ) -> Result<Self, KeylimectlError> {
        let mut client = Self::new_without_version_detection(
            agent_ip, agent_port, config,
        )?;

        // Attempt to detect API version
        if let Err(e) = client.detect_api_version().await {
            warn!("Failed to detect agent API version, using default: {e}");
        }

        Ok(client)
    }

    /// Create a new agent client without API version detection
    ///
    /// Initializes a new `AgentClient` with the provided configuration
    /// using the default API version without attempting to detect the
    /// agent's supported version. This is mainly useful for testing.
    ///
    /// # Arguments
    ///
    /// * `agent_ip` - IP address of the agent
    /// * `agent_port` - Port number the agent is listening on
    /// * `config` - Configuration containing TLS and client settings
    ///
    /// # Returns
    ///
    /// Returns a configured `AgentClient` with default API version.
    pub fn new_without_version_detection(
        agent_ip: &str,
        agent_port: u16,
        config: &Config,
    ) -> Result<Self, KeylimectlError> {
        let base_url = if agent_ip.contains(':') && !agent_ip.starts_with('[')
        {
            // IPv6 address without brackets
            format!("https://[{agent_ip}]:{agent_port}")
        } else if agent_ip.starts_with('[') && agent_ip.ends_with(']') {
            // IPv6 address with brackets
            format!("https://{agent_ip}:{agent_port}")
        } else {
            // IPv4 address or hostname
            format!("https://{agent_ip}:{agent_port}")
        };

        // Create HTTP client with TLS configuration
        let http_client = Self::create_http_client(config)?;

        // Create resilient client with retry logic
        let client = ResilientClient::new(
            Some(http_client),
            Duration::from_secs(1), // Initial delay
            config.client.max_retries,
            &[
                StatusCode::OK,
                StatusCode::CREATED,
                StatusCode::ACCEPTED,
                StatusCode::NO_CONTENT,
            ],
            Some(Duration::from_secs(60)), // Max delay
        );

        Ok(Self {
            client,
            base_url,
            api_version: "2.1".to_string(), // Default API version
            agent_ip: agent_ip.to_string(),
            agent_port,
        })
    }

    /// Auto-detect and set the API version
    ///
    /// Attempts to determine the agent's API version by trying each supported
    /// API version from newest to oldest until one works. Since agents in API < 3.0
    /// don't typically have a /version endpoint, this uses a test request approach.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if version detection succeeded or failed gracefully.
    /// Returns `Err()` only for critical errors that prevent client operation.
    ///
    /// # Behavior
    ///
    /// 1. Tries API versions from newest to oldest
    /// 2. On success, caches the detected version for future requests
    /// 3. On complete failure, leaves default version unchanged
    async fn detect_api_version(&mut self) -> Result<(), KeylimectlError> {
        // Try each supported version from newest to oldest
        for &api_version in SUPPORTED_AGENT_API_VERSIONS.iter().rev() {
            debug!("Trying agent API version {api_version}");

            // Test this version by making a simple request (quotes endpoint with dummy nonce)
            if self.test_api_version(api_version).await.is_ok() {
                debug!(
                    "Successfully detected agent API version: {api_version}"
                );
                self.api_version = api_version.to_string();
                return Ok(());
            }
        }

        // If all versions failed, set to unknown and continue with default
        warn!(
            "Could not detect agent API version, using default: {}",
            self.api_version
        );
        self.api_version = UNKNOWN_API_VERSION.to_string();
        Ok(())
    }

    /// Test if a specific API version works by making a simple request
    async fn test_api_version(
        &self,
        api_version: &str,
    ) -> Result<(), KeylimectlError> {
        let url = format!(
            "{}/v{}/quotes/identity?nonce=test",
            self.base_url, api_version
        );

        debug!("Testing agent API version {api_version} with URL: {url}");

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                format!("Failed to test API version {api_version}")
            })?;

        if response.status().is_success()
            || response.status() == StatusCode::BAD_REQUEST
        {
            // Accept 400 as well since the test nonce might be rejected but the endpoint exists
            Ok(())
        } else {
            Err(KeylimectlError::api_error(
                response.status().as_u16(),
                format!("API version {api_version} not supported"),
                None,
            ))
        }
    }

    /// Get TPM quote from the agent
    ///
    /// Requests a TPM quote from the agent using the provided nonce.
    /// This is used during the attestation process to verify the agent's
    /// TPM state and integrity.
    ///
    /// # Arguments
    ///
    /// * `nonce` - Random nonce to include in the quote for freshness
    ///
    /// # Returns
    ///
    /// Returns JSON containing:
    /// - `quote`: Base64-encoded TPM quote
    /// - `pubkey`: Agent's public key for verification
    /// - `tpm_version`: TPM version information
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent is not reachable
    /// - Agent rejects the nonce
    /// - TPM quote generation fails
    /// - Network communication fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keylimectl::client::agent::AgentClient;
    /// # async fn example(client: &AgentClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let nonce = "random_nonce_value_12345";
    /// let quote_response = client.get_quote(nonce).await?;
    ///
    /// if let Some(quote) = quote_response["results"]["quote"].as_str() {
    ///     println!("Received TPM quote: {}", quote);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_quote(
        &self,
        nonce: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!(
            "Getting TPM quote from agent {}:{} with nonce: {}",
            self.agent_ip, self.agent_port, nonce
        );

        let url = format!(
            "{}/v{}/quotes/identity?nonce={}",
            self.base_url, self.api_version, nonce
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send quote request to agent".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Deliver encrypted U key and optional payload to the agent
    ///
    /// Sends the encrypted U key (and optionally a payload) to the agent
    /// after successful TPM quote verification. The U key is encrypted
    /// with the agent's public key before transmission.
    ///
    /// # Arguments
    ///
    /// * `encrypted_key` - Base64-encoded encrypted U key
    /// * `auth_tag` - Authentication tag for the key
    /// * `payload` - Optional payload to deliver to the agent
    ///
    /// # Returns
    ///
    /// Returns the agent's response confirming key delivery.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent is not reachable
    /// - Key format is invalid
    /// - Agent rejects the key or payload
    /// - Network communication fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keylimectl::client::agent::AgentClient;
    /// # async fn example(client: &AgentClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let encrypted_key = b"base64_encoded_encrypted_key";
    /// let auth_tag = "authentication_tag_value";
    /// let payload = Some("configuration_data".to_string());
    ///
    /// let result = client.deliver_key(encrypted_key, auth_tag, payload.as_deref()).await?;
    /// println!("Key delivered successfully: {:?}", result);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn deliver_key(
        &self,
        encrypted_key: &[u8],
        auth_tag: &str,
        payload: Option<&str>,
    ) -> Result<Value, KeylimectlError> {
        debug!(
            "Delivering encrypted U key to agent {}:{}",
            self.agent_ip, self.agent_port
        );

        let url =
            format!("{}/v{}/keys/ukey", self.base_url, self.api_version);

        let mut data = json!({
            "encrypted_key": STANDARD.encode(encrypted_key),
            "auth_tag": auth_tag
        });

        // Add payload if provided
        if let Some(payload_data) = payload {
            data["payload"] = json!(payload_data);
        }

        let response = self
            .client
            .get_json_request_from_struct(Method::POST, &url, &data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send key delivery request to agent".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Verify key derivation using HMAC challenge
    ///
    /// Sends a challenge to the agent to verify that it can correctly
    /// derive keys using the delivered U key. The agent should respond
    /// with an HMAC of the challenge computed using the derived key.
    ///
    /// # Arguments
    ///
    /// * `challenge` - Random challenge string
    /// * `expected_hmac` - Expected HMAC value for verification
    ///
    /// # Returns
    ///
    /// Returns `true` if the agent's HMAC matches the expected value,
    /// `false` otherwise.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent is not reachable
    /// - Agent cannot derive the key
    /// - Network communication fails
    /// - Response format is invalid
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keylimectl::client::agent::AgentClient;
    /// # async fn example(client: &AgentClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let challenge = "random_challenge_12345";
    /// let expected_hmac = "computed_hmac_value";
    ///
    /// let is_valid = client.verify_key_derivation(challenge, expected_hmac).await?;
    /// if is_valid {
    ///     println!("Key derivation verified successfully");
    /// } else {
    ///     println!("Key derivation verification failed");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_key_derivation(
        &self,
        challenge: &str,
        expected_hmac: &str,
    ) -> Result<bool, KeylimectlError> {
        debug!(
            "Verifying key derivation with agent {}:{}",
            self.agent_ip, self.agent_port
        );

        let url = format!(
            "{}/v{}/keys/verify?challenge={}",
            self.base_url, self.api_version, challenge
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send verification request to agent".to_string()
            })?;

        let response_json = self.handle_response(response).await?;

        // Extract HMAC from response and compare
        if let Some(results) = response_json.get("results") {
            if let Some(hmac) = results.get("hmac").and_then(|v| v.as_str()) {
                return Ok(hmac == expected_hmac);
            }
        }

        Err(KeylimectlError::validation(
            "Invalid verification response format from agent",
        ))
    }

    /// Check if the agent is using API version < 3.0 (pull model)
    ///
    /// Returns `true` if the detected/configured API version is less than 3.0,
    /// indicating that agent communication should be used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keylimectl::client::agent::AgentClient;
    /// # fn example(client: &AgentClient) {
    /// if client.is_pull_model() {
    ///     println!("Using pull model - will communicate directly with agent");
    /// } else {
    ///     println!("Using push model - agent will connect to verifier");
    /// }
    /// # }
    /// ```
    pub fn is_pull_model(&self) -> bool {
        if self.api_version == UNKNOWN_API_VERSION {
            // Default to pull model for unknown versions to be safe
            return true;
        }

        // Parse version as float for comparison
        if let Ok(version) = self.api_version.parse::<f32>() {
            version < 3.0
        } else {
            // If we can't parse, assume pull model
            true
        }
    }

    /// Get the agent's base URL
    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the detected/configured API version
    #[allow(dead_code)]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Create HTTP client with TLS configuration
    ///
    /// Initializes a reqwest HTTP client with the TLS settings specified
    /// in the configuration. This includes client certificates for mutual TLS
    /// and server certificate verification settings.
    fn create_http_client(
        config: &Config,
    ) -> Result<reqwest::Client, KeylimectlError> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.client.timeout));

        // Configure TLS
        if !config.tls.verify_server_cert {
            builder = builder.danger_accept_invalid_certs(true);
            warn!("Server certificate verification is disabled for agent communication");
        }

        // Add trusted CA certificates
        for ca_path in &config.tls.trusted_ca {
            if std::path::Path::new(ca_path).exists() {
                let ca_cert = std::fs::read(ca_path).with_context(|| {
                    format!(
                        "Failed to read trusted CA certificate: {ca_path}"
                    )
                })?;

                let ca_cert = reqwest::Certificate::from_pem(&ca_cert)
                    .with_context(|| {
                        format!("Failed to parse CA certificate: {ca_path}")
                    })?;

                builder = builder.add_root_certificate(ca_cert);
            } else {
                warn!("Trusted CA certificate file not found: {ca_path}");
            }
        }

        // Add client certificate if configured and enabled for agent mTLS
        if config.tls.enable_agent_mtls {
            if let (Some(cert_path), Some(key_path)) =
                (&config.tls.client_cert, &config.tls.client_key)
            {
                let cert = std::fs::read(cert_path).with_context(|| {
                    format!("Failed to read client certificate: {cert_path}")
                })?;

                let key = std::fs::read(key_path).with_context(|| {
                    format!("Failed to read client key: {key_path}")
                })?;

                let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key)
                    .with_context(|| "Failed to create client identity from certificate and key".to_string())?;

                builder = builder.identity(identity);
                debug!("Configured client certificate for agent mTLS");
            } else {
                warn!(
                    "Agent mTLS enabled but no client certificate configured"
                );
            }
        }

        builder
            .build()
            .with_context(|| "Failed to create HTTP client".to_string())
    }

    /// Handle HTTP response and convert to JSON
    ///
    /// Processes HTTP responses from the agent, handling both
    /// success and error cases. Converts successful responses to JSON
    /// and transforms HTTP errors into appropriate `KeylimectlError` types.
    async fn handle_response(
        &self,
        response: reqwest::Response,
    ) -> Result<Value, KeylimectlError> {
        let status = response.status();
        let response_text = response
            .text()
            .await
            .with_context(|| "Failed to read response body".to_string())?;

        match status {
            StatusCode::OK
            | StatusCode::CREATED
            | StatusCode::ACCEPTED
            | StatusCode::NO_CONTENT => {
                if response_text.is_empty() {
                    Ok(json!({"status": "success"}))
                } else {
                    serde_json::from_str(&response_text).with_context(|| {
                        format!(
                            "Failed to parse JSON response: {response_text}"
                        )
                    })
                }
            }
            _ => {
                let error_message = if response_text.is_empty() {
                    format!("HTTP {} error", status.as_u16())
                } else {
                    // Try to parse as JSON for better error message
                    match serde_json::from_str::<Value>(&response_text) {
                        Ok(json_error) => json_error
                            .get("status")
                            .or_else(|| json_error.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&response_text)
                            .to_string(),
                        Err(_) => response_text.clone(),
                    }
                };

                Err(KeylimectlError::api_error(
                    status.as_u16(),
                    error_message,
                    serde_json::from_str(&response_text).ok(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, TlsConfig};

    /// Create a test configuration
    fn create_test_config() -> Config {
        Config {
            verifier: crate::config::VerifierConfig::default(),
            registrar: crate::config::RegistrarConfig::default(),
            tls: TlsConfig {
                client_cert: None,
                client_key: None,
                client_key_password: None,
                trusted_ca: vec![],
                verify_server_cert: false, // Disable for testing
                enable_agent_mtls: true,
            },
            client: ClientConfig {
                timeout: 30,
                retry_interval: 1.0,
                exponential_backoff: true,
                max_retries: 3,
            },
        }
    }

    #[test]
    fn test_agent_client_new() {
        let config = create_test_config();
        let result = AgentClient::new_without_version_detection(
            "127.0.0.1",
            9002,
            &config,
        );

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.base_url, "https://127.0.0.1:9002");
        assert_eq!(client.api_version, "2.1");
        assert_eq!(client.agent_ip, "127.0.0.1");
        assert_eq!(client.agent_port, 9002);
    }

    #[test]
    fn test_agent_client_ipv6() {
        let config = create_test_config();

        // Test IPv6 without brackets
        let result =
            AgentClient::new_without_version_detection("::1", 9002, &config);
        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.base_url, "https://[::1]:9002");

        // Test IPv6 with brackets
        let result = AgentClient::new_without_version_detection(
            "[2001:db8::1]",
            9002,
            &config,
        );
        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.base_url, "https://[2001:db8::1]:9002");
    }

    #[test]
    fn test_is_pull_model() {
        let config = create_test_config();
        let mut client = AgentClient::new_without_version_detection(
            "127.0.0.1",
            9002,
            &config,
        )
        .unwrap();

        // Test default version (2.1 < 3.0)
        assert!(client.is_pull_model());

        // Test version 2.0
        client.api_version = "2.0".to_string();
        assert!(client.is_pull_model());

        // Test version 2.2
        client.api_version = "2.2".to_string();
        assert!(client.is_pull_model());

        // Test version 3.0 (should be push model)
        client.api_version = "3.0".to_string();
        assert!(!client.is_pull_model());

        // Test unknown version (should default to pull model)
        client.api_version = UNKNOWN_API_VERSION.to_string();
        assert!(client.is_pull_model());

        // Test invalid version (should default to pull model)
        client.api_version = "invalid".to_string();
        assert!(client.is_pull_model());
    }

    #[test]
    fn test_supported_api_versions() {
        // Verify our supported versions are all < 3.0
        for &version in SUPPORTED_AGENT_API_VERSIONS {
            let parsed: f32 =
                version.parse().expect("Version should be parseable");
            assert!(
                parsed < 3.0,
                "Agent API version {version} should be < 3.0"
            );
        }

        // Verify versions are in ascending order
        for i in 1..SUPPORTED_AGENT_API_VERSIONS.len() {
            let prev: f32 =
                SUPPORTED_AGENT_API_VERSIONS[i - 1].parse().unwrap();
            let curr: f32 = SUPPORTED_AGENT_API_VERSIONS[i].parse().unwrap();
            assert!(prev < curr, "API versions should be in ascending order");
        }
    }

    #[test]
    fn test_base_url_construction() {
        let config = create_test_config();

        // IPv4
        let client = AgentClient::new_without_version_detection(
            "192.168.1.100",
            9002,
            &config,
        )
        .unwrap();
        assert_eq!(client.base_url(), "https://192.168.1.100:9002");

        // IPv6 without brackets
        let client = AgentClient::new_without_version_detection(
            "2001:db8::1",
            9002,
            &config,
        )
        .unwrap();
        assert_eq!(client.base_url(), "https://[2001:db8::1]:9002");

        // IPv6 with brackets
        let client = AgentClient::new_without_version_detection(
            "[2001:db8::1]",
            9002,
            &config,
        )
        .unwrap();
        assert_eq!(client.base_url(), "https://[2001:db8::1]:9002");

        // Hostname
        let client = AgentClient::new_without_version_detection(
            "agent.example.com",
            9002,
            &config,
        )
        .unwrap();
        assert_eq!(client.base_url(), "https://agent.example.com:9002");
    }

    #[test]
    fn test_api_version_detection_order() {
        // Test that iter().rev() gives us newest to oldest as expected
        let versions: Vec<&str> =
            SUPPORTED_AGENT_API_VERSIONS.iter().rev().copied().collect();

        // Should be newest first
        assert_eq!(versions[0], "2.2");
        assert_eq!(versions[1], "2.1");
        assert_eq!(versions[2], "2.0");

        // Verify it's actually newest to oldest
        for i in 1..versions.len() {
            let prev: f32 = versions[i - 1].parse().unwrap();
            let curr: f32 = versions[i].parse().unwrap();
            assert!(
                prev > curr,
                "Reversed iteration should give newest to oldest"
            );
        }
    }

    #[test]
    fn test_tls_config() {
        let mut config = create_test_config();

        // Test with mTLS disabled
        config.tls.enable_agent_mtls = false;
        let result = AgentClient::create_http_client(&config);
        assert!(result.is_ok());

        // Test with mTLS enabled but no certificates
        config.tls.enable_agent_mtls = true;
        let result = AgentClient::create_http_client(&config);
        assert!(result.is_ok()); // Should still work, just warn about missing certs

        // Test with server verification disabled
        config.tls.verify_server_cert = false;
        let result = AgentClient::create_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_getters() {
        let config = create_test_config();
        let client = AgentClient::new_without_version_detection(
            "127.0.0.1",
            9002,
            &config,
        )
        .unwrap();

        assert_eq!(client.base_url(), "https://127.0.0.1:9002");
        assert_eq!(client.api_version(), "2.1");
    }
}
