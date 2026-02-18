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

use crate::client::base::BaseClient;
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use base64::{engine::general_purpose::STANDARD, Engine};
use log::{debug, info, warn};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

use crate::api_versions::SUPPORTED_AGENT_API_VERSIONS;

/// Unknown API version constant for when version detection fails
const UNKNOWN_API_VERSION: &str = "unknown";

/// Response structure for agent version endpoint
#[derive(serde::Deserialize, Debug)]
struct AgentVersionResponse {
    #[allow(dead_code)]
    code: serde_json::Number,
    #[allow(dead_code)]
    status: String,
    results: AgentVersionResults,
}

/// Agent version results structure
#[derive(serde::Deserialize, Debug)]
struct AgentVersionResults {
    supported_version: String,
}

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
    base: BaseClient,
    api_version: String,
    agent_ip: String,
    agent_port: u16,
}

/// Builder for creating AgentClient instances with flexible configuration
///
/// The `AgentClientBuilder` provides a fluent interface for configuring
/// and creating `AgentClient` instances. It allows for optional API version
/// detection and custom API version specification.
///
/// # Examples
///
/// ```rust
/// use keylimectl::client::agent::AgentClient;
/// use keylimectl::config::Config;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
///
/// // Create client with automatic version detection
/// let client = AgentClient::builder()
///     .agent_ip("192.168.1.100")
///     .agent_port(9002)
///     .config(&config)
///     .build()
///     .await?;
///
/// // Create client without version detection (for testing)
/// let client = AgentClient::builder()
///     .agent_ip("192.168.1.100")
///     .agent_port(9002)
///     .config(&config)
///     .skip_version_detection()
///     .build_sync()?;
///
/// // Create client with specific API version
/// let client = AgentClient::builder()
///     .agent_ip("192.168.1.100")
///     .agent_port(9002)
///     .config(&config)
///     .api_version("2.0")
///     .skip_version_detection()
///     .build_sync()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct AgentClientBuilder<'a> {
    agent_ip: Option<String>,
    agent_port: Option<u16>,
    config: Option<&'a Config>,
}

impl<'a> AgentClientBuilder<'a> {
    /// Create a new builder instance
    pub fn new() -> Self {
        Self {
            agent_ip: None,
            agent_port: None,
            config: None,
        }
    }

    /// Set the agent IP address
    pub fn agent_ip<S: Into<String>>(mut self, ip: S) -> Self {
        self.agent_ip = Some(ip.into());
        self
    }

    /// Set the agent port
    pub fn agent_port(mut self, port: u16) -> Self {
        self.agent_port = Some(port);
        self
    }

    /// Set the configuration for the client
    pub fn config(mut self, config: &'a Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Build the AgentClient with automatic API version detection
    ///
    /// This is the recommended way to create a client for production use,
    /// as it will automatically detect the optimal API version supported
    /// by the agent.
    pub async fn build(self) -> Result<AgentClient, KeylimectlError> {
        let agent_ip = self.agent_ip.ok_or_else(|| {
            KeylimectlError::validation(
                "Agent IP is required for AgentClient",
            )
        })?;
        let agent_port = self.agent_port.ok_or_else(|| {
            KeylimectlError::validation(
                "Agent port is required for AgentClient",
            )
        })?;
        let config = self.config.ok_or_else(|| {
            KeylimectlError::validation(
                "Configuration is required for AgentClient",
            )
        })?;

        AgentClient::new(&agent_ip, agent_port, config).await
    }
}

impl<'a> Default for AgentClientBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentClient {
    /// Create a new builder for configuring an AgentClient
    ///
    /// This is the recommended way to create AgentClient instances,
    /// as it provides a flexible interface for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::agent::AgentClient;
    /// use keylimectl::config::Config;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = AgentClient::builder()
    ///     .agent_ip("192.168.1.100")
    ///     .agent_port(9002)
    ///     .config(&config)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> AgentClientBuilder<'static> {
        AgentClientBuilder::new()
    }
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
    pub(crate) fn new_without_version_detection(
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

        let base = BaseClient::new(base_url, config)
            .map_err(KeylimectlError::from)?;

        Ok(Self {
            base,
            api_version: crate::api_versions::DEFAULT_API_VERSION.to_string(),
            agent_ip: agent_ip.to_string(),
            agent_port,
        })
    }

    /// Auto-detect and set the API version
    ///
    /// Attempts to determine the agent's API version by first trying the `/version` endpoint
    /// and then falling back to testing each API version individually if needed.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if version detection succeeded or failed gracefully.
    /// Returns `Err()` only for critical errors that prevent client operation.
    ///
    /// # Behavior
    ///
    /// 1. First try the `/version` endpoint to get the supported_version
    /// 2. If `/version` fails, fall back to testing each API version from newest to oldest
    /// 3. On success, caches the detected version for future requests
    /// 4. On complete failure, leaves default version unchanged
    async fn detect_api_version(&mut self) -> Result<(), KeylimectlError> {
        info!("Starting agent API version detection");

        // Step 1: Try the /version endpoint first
        match self.get_agent_api_version().await {
            Ok(version) => {
                info!("Successfully detected agent API version from /version endpoint: {version}");
                self.api_version = version;
                return Ok(());
            }
            Err(e) => {
                debug!("Failed to get version from /version endpoint ({e}), falling back to version probing");
            }
        }

        // Step 2: Fall back to testing each version individually (newest to oldest)
        info!("Falling back to individual version testing");
        for &api_version in SUPPORTED_AGENT_API_VERSIONS.iter().rev() {
            debug!("Testing agent API version {api_version}");

            // Test this version by making a simple request (quotes endpoint with dummy nonce)
            if self.test_api_version(api_version).await.is_ok() {
                info!(
                    "Successfully detected agent API version: {api_version}"
                );
                self.api_version = api_version.to_string();
                return Ok(());
            }
        }

        // If all versions failed, continue with default version
        warn!(
            "Could not detect agent API version, using default: {}",
            self.api_version
        );
        Ok(())
    }

    /// Get the agent API version from the '/version' endpoint
    ///
    /// Attempts to retrieve the agent's supported API version using the `/version` endpoint.
    /// The expected response format is:
    /// ```json
    /// {
    ///   "code": 200,
    ///   "status": "Success",
    ///   "results": {
    ///     "supported_version": "2.2"
    ///   }
    /// }
    /// ```
    async fn get_agent_api_version(&self) -> Result<String, KeylimectlError> {
        let url = format!("{}/version", self.base.base_url);

        info!("Requesting agent API version from {url}");
        debug!("GET {url}");

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                format!("Failed to send version request to agent at {url}")
            })?;

        if !response.status().is_success() {
            return Err(KeylimectlError::api_error(
                response.status().as_u16(),
                "Agent does not support the /version endpoint".to_string(),
                None,
            ));
        }

        let resp: AgentVersionResponse =
            response.json().await.with_context(|| {
                "Failed to parse version response from agent".to_string()
            })?;

        Ok(resp.results.supported_version)
    }

    /// Test if a specific API version works by making a simple request
    async fn test_api_version(
        &self,
        api_version: &str,
    ) -> Result<(), KeylimectlError> {
        let url = format!(
            "{}/v{}/quotes/identity?nonce=test",
            self.base.base_url, api_version
        );

        debug!("Testing agent API version {api_version} with URL: {url}");

        let response = self
            .base
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
            self.base.base_url, self.api_version, nonce
        );

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send quote request to agent".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
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
            format!("{}/v{}/keys/ukey", self.base.base_url, self.api_version);

        let mut data = json!({
            "encrypted_key": STANDARD.encode(encrypted_key),
            "auth_tag": auth_tag
        });

        // Add payload if provided
        if let Some(payload_data) = payload {
            data["payload"] = json!(payload_data);
        }

        let response = self
            .base
            .client
            .get_json_request_from_struct(Method::POST, &url, &data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send key delivery request to agent".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
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
            self.base.base_url, self.api_version, challenge
        );

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send verification request to agent".to_string()
            })?;

        let response_json = self.base.handle_response(response).await?;

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
    #[allow(dead_code)] // Will be used when agent model detection is enabled
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::base::BaseClient;
    use crate::config::{ClientConfig, TlsConfig};

    /// Create a test configuration
    fn create_test_config() -> Config {
        Config {
            loaded_from: None,
            cli_overrides: crate::config::CliOverrides::default(),
            verifier: crate::config::VerifierConfig::default(),
            registrar: crate::config::RegistrarConfig::default(),
            tls: TlsConfig {
                client_cert: None,
                client_key: None,
                client_key_password: None,
                trusted_ca: vec![],
                verify_server_cert: false, // Disable for testing
                enable_agent_mtls: true,
                accept_invalid_hostnames: true,
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
        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://127.0.0.1:9002");
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
        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://[::1]:9002");

        // Test IPv6 with brackets
        let result = AgentClient::new_without_version_detection(
            "[2001:db8::1]",
            9002,
            &config,
        );
        assert!(result.is_ok());
        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://[2001:db8::1]:9002");
    }

    #[test]
    fn test_is_pull_model() {
        let config = create_test_config();
        let mut client = AgentClient::new_without_version_detection(
            "127.0.0.1",
            9002,
            &config,
        )
        .unwrap(); //#[allow_ci]

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
                SUPPORTED_AGENT_API_VERSIONS[i - 1].parse().unwrap(); //#[allow_ci]
            let curr: f32 = SUPPORTED_AGENT_API_VERSIONS[i].parse().unwrap(); //#[allow_ci]
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
        .unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://192.168.1.100:9002");

        // IPv6 without brackets
        let client = AgentClient::new_without_version_detection(
            "2001:db8::1",
            9002,
            &config,
        )
        .unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://[2001:db8::1]:9002");

        // IPv6 with brackets
        let client = AgentClient::new_without_version_detection(
            "[2001:db8::1]",
            9002,
            &config,
        )
        .unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://[2001:db8::1]:9002");

        // Hostname
        let client = AgentClient::new_without_version_detection(
            "agent.example.com",
            9002,
            &config,
        )
        .unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://agent.example.com:9002");
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
            let prev: f32 = versions[i - 1].parse().unwrap(); //#[allow_ci]
            let curr: f32 = versions[i].parse().unwrap(); //#[allow_ci]
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
        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());

        // Test with mTLS enabled but no certificates
        config.tls.enable_agent_mtls = true;
        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok()); // Should still work, just warn about missing certs

        // Test with server verification disabled
        config.tls.verify_server_cert = false;
        let result = BaseClient::create_http_client(&config);
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
        .unwrap(); //#[allow_ci]

        assert_eq!(client.base.base_url, "https://127.0.0.1:9002");
        assert_eq!(client.api_version, "2.1");
    }
}
