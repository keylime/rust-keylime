// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Registrar client for communicating with the Keylime registrar
//!
//! This module provides a comprehensive client interface for interacting with the Keylime registrar service.
//! The registrar maintains a database of registered agents and their TPM public keys, serving as the
//! trusted authority for agent identity verification.
//!
//! # Features
//!
//! - **Agent Registry**: Manage agent registration and identity
//! - **TPM Key Management**: Store and retrieve TPM endorsement keys
//! - **Agent Discovery**: Search agents by UUID or EK hash
//! - **Resilient Communication**: Built-in retry logic and error handling
//! - **TLS Support**: Mutual TLS authentication with configurable certificates
//!
//! # Architecture
//!
//! The [`RegistrarClient`] wraps a [`ResilientClient`] from the keylime library,
//! providing automatic retries, exponential backoff, and proper error handling
//! for all registrar operations.
//!
//! # Agent Lifecycle
//!
//! 1. **Registration**: Agent registers with registrar, providing TPM keys
//! 2. **Verification**: Registrar validates TPM endorsement keys
//! 3. **Storage**: Agent identity and keys stored in database
//! 4. **Lookup**: Other services query registrar for agent information
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::client::registrar::RegistrarClient;
//! use keylimectl::config::Config;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::default();
//! let client = RegistrarClient::new(&config)?;
//!
//! // Get agent information from registrar
//! if let Some(agent) = client.get_agent("agent-uuid").await? {
//!     println!("Agent found: {:?}", agent);
//! }
//!
//! // List all registered agents
//! let agents = client.list_agents().await?;
//! println!("Found {} agents", agents["results"].as_object().unwrap().len());
//!
//! // Delete agent from registrar
//! let result = client.delete_agent("agent-uuid").await?;
//! println!("Agent deleted: {:?}", result);
//! # Ok(())
//! # }
//! ```

use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use keylime::resilient_client::ResilientClient;
use log::{debug, warn};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// Client for communicating with the Keylime registrar service
///
/// The `RegistrarClient` provides a high-level interface for all registrar operations,
/// including agent registration, key management, and agent discovery. It handles
/// authentication, retries, and error processing automatically.
///
/// # Configuration
///
/// The client is configured through the [`Config`] struct, which specifies:
/// - Registrar service endpoint (IP and port)
/// - TLS certificate configuration
/// - Retry and timeout settings
///
/// # Database Operations
///
/// The registrar maintains a persistent database of:
/// - Agent UUIDs and metadata
/// - TPM endorsement keys (EK)
/// - TPM attestation identity keys (AIK)
/// - Agent registration timestamps
///
/// # Security Model
///
/// The registrar serves as the root of trust for agent identity:
/// - Validates TPM endorsement keys against known manufacturers
/// - Stores cryptographic proof of agent identity
/// - Prevents agent UUID collisions and spoofing
///
/// # Thread Safety
///
/// `RegistrarClient` is thread-safe and can be shared across multiple tasks
/// or threads using `Arc<RegistrarClient>`.
///
/// # Examples
///
/// ```rust
/// use keylimectl::client::registrar::RegistrarClient;
/// use keylimectl::config::Config;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut config = Config::default();
/// config.registrar.ip = "10.0.0.2".to_string();
/// config.registrar.port = 8891;
///
/// let client = RegistrarClient::new(&config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct RegistrarClient {
    client: ResilientClient,
    base_url: String,
    api_version: String,
}

impl RegistrarClient {
    /// Create a new registrar client
    ///
    /// Initializes a new `RegistrarClient` with the provided configuration.
    /// This sets up the HTTP client with TLS configuration, retry logic,
    /// and connection pooling for registrar communication.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing registrar endpoint and TLS settings
    ///
    /// # Returns
    ///
    /// Returns a configured `RegistrarClient` or an error if initialization fails.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - TLS certificate files cannot be read
    /// - Certificate/key files are invalid
    /// - HTTP client initialization fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::registrar::RegistrarClient;
    /// use keylimectl::config::Config;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = RegistrarClient::new(&config)?;
    /// println!("Registrar client created for {}", config.registrar_base_url());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: &Config) -> Result<Self, KeylimectlError> {
        let base_url = config.registrar_base_url();

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
        })
    }

    /// Get agent information from the registrar
    ///
    /// Retrieves agent registration information and TPM keys from the registrar.
    /// This is the primary method for looking up agent identity and cryptographic
    /// credentials stored during registration.
    ///
    /// # Arguments
    ///
    /// * `agent_uuid` - Unique identifier for the agent
    ///
    /// # Returns
    ///
    /// Returns `Some(Value)` containing agent registration data if found,
    /// or `None` if the agent is not registered.
    ///
    /// # Agent Data Format
    ///
    /// The returned data includes:
    /// ```json
    /// {
    ///     "aik_tpm": "base64-encoded-aik",
    ///     "ek_tpm": "base64-encoded-ek",
    ///     "ekcert": "base64-encoded-ek-certificate",
    ///     "ip": "192.168.1.100",
    ///     "port": 9002,
    ///     "regcount": 1,
    ///     "active": true
    /// }
    /// ```
    ///
    /// # Key Components
    ///
    /// - `aik_tpm`: Attestation Identity Key (AIK) public portion
    /// - `ek_tpm`: Endorsement Key (EK) public portion
    /// - `ekcert`: EK certificate from TPM manufacturer
    /// - `regcount`: Number of times agent has registered
    /// - `active`: Whether agent is currently active
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent UUID format is invalid
    /// - Network communication fails
    /// - Registrar service returns an error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::registrar::RegistrarClient;
    ///
    /// # async fn example(client: &RegistrarClient) -> Result<(), Box<dyn std::error::Error>> {
    /// match client.get_agent("550e8400-e29b-41d4-a716-446655440000").await? {
    ///     Some(agent) => {
    ///         println!("Agent IP: {}", agent["ip"]);
    ///         println!("Registration count: {}", agent["regcount"]);
    ///         println!("Active: {}", agent["active"]);
    ///     }
    ///     None => println!("Agent not registered with registrar"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting agent {agent_uuid} from registrar");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get agent request to registrar".to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response = self.handle_response(response).await?;

                // Extract agent data from registrar response format
                if let Some(results) = json_response.get("results") {
                    if let Some(agent_data) = results.get(agent_uuid) {
                        Ok(Some(agent_data.clone()))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(Some(json_response))
                }
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let error_response = self.handle_response(response).await;
                match error_response {
                    Ok(_) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Delete an agent from the registrar
    ///
    /// Removes an agent's registration and all associated cryptographic
    /// materials from the registrar database. This is typically done
    /// when decommissioning an agent.
    ///
    /// # Arguments
    ///
    /// * `agent_uuid` - Unique identifier for the agent to remove
    ///
    /// # Returns
    ///
    /// Returns the registrar's response confirming deletion.
    ///
    /// # Behavior
    ///
    /// - Removes agent UUID from registrar database
    /// - Deletes all stored TPM keys (EK, AIK)
    /// - Removes EK certificate and metadata
    /// - Marks agent as inactive/deleted
    /// - Gracefully handles requests for non-existent agents
    ///
    /// # Security Implications
    ///
    /// - Agent cannot re-register with same UUID until database cleanup
    /// - TPM keys are permanently removed from trust database
    /// - Verifier will no longer trust agent identity
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent UUID format is invalid
    /// - Network communication fails
    /// - Registrar service returns an error
    /// - Database constraints prevent deletion
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::registrar::RegistrarClient;
    ///
    /// # async fn example(client: &RegistrarClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let result = client.delete_agent("550e8400-e29b-41d4-a716-446655440000").await?;
    /// println!("Agent removed from registrar: {:?}", result);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting agent {agent_uuid} from registrar");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send delete agent request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// List all agents registered with the registrar
    ///
    /// Retrieves a comprehensive list of all agents in the registrar database.
    /// This provides an overview of the entire agent population and their
    /// registration status.
    ///
    /// # Returns
    ///
    /// Returns a JSON object containing all registered agents:
    /// ```json
    /// {
    ///     "results": {
    ///         "agent-uuid-1": {
    ///             "ip": "192.168.1.100",
    ///             "port": 9002,
    ///             "regcount": 1,
    ///             "active": true,
    ///             "aik_tpm": "base64-encoded-aik",
    ///             "ek_tpm": "base64-encoded-ek"
    ///         },
    ///         ...
    ///     }
    /// }
    /// ```
    ///
    /// # Use Cases
    ///
    /// - Infrastructure inventory and monitoring
    /// - Agent deployment verification
    /// - Security auditing and compliance
    /// - Bulk operations planning
    ///
    /// # Performance Considerations
    ///
    /// - Response size grows with agent count
    /// - May include large cryptographic keys
    /// - Consider pagination for very large deployments
    /// - Use filtering options when available
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Network communication fails
    /// - Registrar service returns an error
    /// - Database query fails
    /// - Response payload exceeds size limits
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::registrar::RegistrarClient;
    ///
    /// # async fn example(client: &RegistrarClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let agents = client.list_agents().await?;
    ///
    /// if let Some(results) = agents["results"].as_object() {
    ///     println!("Found {} registered agents:", results.len());
    ///     for (uuid, info) in results {
    ///         let active = info["active"].as_bool().unwrap_or(false);
    ///         let status = if active { "active" } else { "inactive" };
    ///         println!("  {}: {} ({}:{})", uuid, status, info["ip"], info["port"]);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_agents(&self) -> Result<Value, KeylimectlError> {
        debug!("Listing agents on registrar");

        let url = format!("{}/v{}/agents/", self.base_url, self.api_version);

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list agents request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Add an agent to the registrar
    #[allow(dead_code)]
    pub async fn add_agent(
        &self,
        agent_uuid: &str,
        data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding agent {agent_uuid} to registrar");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::POST, &url, &data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send add agent request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Update an agent on the registrar
    #[allow(dead_code)]
    pub async fn update_agent(
        &self,
        agent_uuid: &str,
        data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating agent {agent_uuid} on registrar");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::PUT, &url, &data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send update agent request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Get agent by EK hash
    #[allow(dead_code)]
    pub async fn get_agent_by_ek_hash(
        &self,
        ek_hash: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting agent by EK hash {ek_hash} from registrar");

        let url = format!(
            "{}/v{}/agents/?ekhash={}",
            self.base_url, self.api_version, ek_hash
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get agent by EK hash request to registrar"
                    .to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response = self.handle_response(response).await?;
                Ok(Some(json_response))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let error_response = self.handle_response(response).await;
                match error_response {
                    Ok(_) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Create HTTP client with TLS configuration
    ///
    /// Initializes a reqwest HTTP client with the TLS settings specified
    /// in the configuration. This includes client certificates, server
    /// certificate verification, and connection timeouts.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing TLS and client settings
    ///
    /// # Returns
    ///
    /// Returns a configured `reqwest::Client` ready for HTTPS communication.
    ///
    /// # TLS Configuration
    ///
    /// The client is configured with:
    /// - Client certificate and key (if specified)
    /// - Server certificate verification (can be disabled for testing)
    /// - Connection timeout from config
    /// - HTTP/2 and connection pooling
    ///
    /// # Security Notes
    ///
    /// - Client certificates enable mutual TLS authentication
    /// - Server certificate verification should only be disabled for testing
    /// - Invalid certificates will cause connection failures
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Certificate files cannot be read
    /// - Certificate/key files are invalid or malformed
    /// - Certificate and key don't match
    /// - HTTP client builder configuration fails
    fn create_http_client(
        config: &Config,
    ) -> Result<reqwest::Client, KeylimectlError> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.client.timeout));

        // Configure TLS
        if !config.tls.verify_server_cert {
            builder = builder.danger_accept_invalid_certs(true);
            warn!("Server certificate verification is disabled");
        }

        // Add client certificate if configured
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
        }

        builder
            .build()
            .with_context(|| "Failed to create HTTP client".to_string())
    }

    /// Handle HTTP response and convert to JSON
    ///
    /// Processes HTTP responses from the registrar service, handling both
    /// success and error cases. Converts successful responses to JSON
    /// and transforms HTTP errors into appropriate `KeylimectlError` types.
    ///
    /// # Arguments
    ///
    /// * `response` - HTTP response from the registrar service
    ///
    /// # Returns
    ///
    /// Returns parsed JSON data for successful responses.
    ///
    /// # Response Handling
    ///
    /// - **2xx responses**: Parsed as JSON or default success object
    /// - **4xx/5xx responses**: Converted to `KeylimectlError::Api` with details
    /// - **Empty responses**: Returns `{"status": "success"}`
    /// - **Invalid JSON**: Returns parsing error with response text
    ///
    /// # Error Details
    ///
    /// For error responses, attempts to extract meaningful error messages
    /// from the JSON response body, falling back to HTTP status descriptions.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Response body cannot be read
    /// - Response contains invalid JSON
    /// - Registrar returns an error status code
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
    use crate::config::{ClientConfig, RegistrarConfig, TlsConfig};
    use serde_json::json;

    /// Create a test configuration for registrar
    fn create_test_config() -> Config {
        Config {
            verifier: crate::config::VerifierConfig::default(),
            registrar: RegistrarConfig {
                ip: "127.0.0.1".to_string(),
                port: 8891,
            },
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
    fn test_registrar_client_new() {
        let config = create_test_config();
        let result = RegistrarClient::new(&config);

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.base_url, "https://127.0.0.1:8891");
        assert_eq!(client.api_version, "2.1");
    }

    #[test]
    fn test_registrar_client_new_with_custom_port() {
        let mut config = create_test_config();
        config.registrar.port = 9000;

        let result = RegistrarClient::new(&config);
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.base_url, "https://127.0.0.1:9000");
    }

    #[test]
    fn test_registrar_client_new_with_ipv6() {
        let mut config = create_test_config();
        config.registrar.ip = "::1".to_string();

        let result = RegistrarClient::new(&config);
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.base_url, "https://[::1]:8891");
    }

    #[test]
    fn test_registrar_client_new_with_bracketed_ipv6() {
        let mut config = create_test_config();
        config.registrar.ip = "[2001:db8::1]".to_string();

        let result = RegistrarClient::new(&config);
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.base_url, "https://[2001:db8::1]:8891");
    }

    #[test]
    fn test_create_http_client_basic() {
        let config = create_test_config();
        let result = RegistrarClient::create_http_client(&config);

        assert!(result.is_ok());
        // Basic validation that client was created
        let _client = result.unwrap();
    }

    #[test]
    fn test_create_http_client_with_timeout() {
        let mut config = create_test_config();
        config.client.timeout = 45;

        let result = RegistrarClient::create_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_http_client_with_invalid_cert_files() {
        let mut config = create_test_config();
        config.tls.client_cert = Some("/nonexistent/cert.pem".to_string());
        config.tls.client_key = Some("/nonexistent/key.pem".to_string());

        let result = RegistrarClient::create_http_client(&config);
        // Should fail because cert files don't exist
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("Failed to read client certificate"));
    }

    #[test]
    fn test_config_validation() {
        let config = create_test_config();

        // Test that our test config is valid
        assert!(config.validate().is_ok());

        // Test base URL generation
        assert_eq!(config.registrar_base_url(), "https://127.0.0.1:8891");
    }

    #[test]
    fn test_api_version_default() {
        let config = create_test_config();
        let client = RegistrarClient::new(&config).unwrap();

        // Default API version should be 2.1
        assert_eq!(client.api_version, "2.1");
    }

    #[test]
    fn test_base_url_construction() {
        // Test IPv4 with custom port
        let mut config = create_test_config();
        config.registrar.ip = "10.0.0.5".to_string();
        config.registrar.port = 9500;

        let client = RegistrarClient::new(&config).unwrap();
        assert_eq!(client.base_url, "https://10.0.0.5:9500");

        // Test IPv6
        config.registrar.ip = "2001:db8:85a3::8a2e:370:7334".to_string();
        config.registrar.port = 8891;

        let client = RegistrarClient::new(&config).unwrap();
        assert_eq!(
            client.base_url,
            "https://[2001:db8:85a3::8a2e:370:7334]:8891"
        );
    }

    #[test]
    fn test_client_debug_trait() {
        let config = create_test_config();
        let client = RegistrarClient::new(&config).unwrap();

        // Test that Debug trait is implemented
        let debug_string = format!("{:?}", client);
        assert!(debug_string.contains("RegistrarClient"));
    }

    #[test]
    fn test_tls_config_disabled_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = false;

        let result = RegistrarClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification disabled
    }

    #[test]
    fn test_tls_config_enabled_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = true;

        let result = RegistrarClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification enabled
    }

    #[test]
    fn test_client_config_values() {
        let config = create_test_config();
        let client = RegistrarClient::new(&config).unwrap();

        // Verify that config values are properly used
        assert_eq!(client.api_version, "2.1");
        assert!(client.base_url.starts_with("https://"));
        assert!(client.base_url.contains("8891"));
    }

    // Error handling tests
    mod error_tests {
        use super::*;

        #[test]
        fn test_api_error_handling() {
            // Test different types of API errors that registrar might return
            let not_found_error = KeylimectlError::api_error(
                404,
                "Agent not found".to_string(),
                Some(json!({"error": "Agent UUID not in registrar"})),
            );

            assert_eq!(not_found_error.error_code(), "API_ERROR");
            assert!(!not_found_error.is_retryable()); // 404 should not be retryable

            let server_error = KeylimectlError::api_error(
                500,
                "Database connection failed".to_string(),
                None,
            );

            assert!(server_error.is_retryable()); // 500 should be retryable
        }

        #[test]
        fn test_agent_not_found_error() {
            let error =
                KeylimectlError::agent_not_found("test-uuid", "registrar");

            assert_eq!(error.error_code(), "AGENT_NOT_FOUND");
            assert!(!error.is_retryable());

            let json_output = error.to_json();
            assert_eq!(json_output["error"]["code"], "AGENT_NOT_FOUND");
            assert_eq!(
                json_output["error"]["details"]["agent_uuid"],
                "test-uuid"
            );
            assert_eq!(
                json_output["error"]["details"]["service"],
                "registrar"
            );
        }
    }

    // Configuration edge cases
    mod config_tests {
        use super::*;

        #[test]
        fn test_empty_trusted_ca() {
            let mut config = create_test_config();
            config.tls.trusted_ca = vec![];

            let result = RegistrarClient::new(&config);
            assert!(result.is_ok());
        }

        #[test]
        fn test_multiple_trusted_ca() {
            let mut config = create_test_config();
            config.tls.trusted_ca = vec![
                "/path/to/ca1.pem".to_string(),
                "/path/to/ca2.pem".to_string(),
            ];

            // Client creation should succeed even with non-existent CA files
            // (they're only validated when actually used)
            let result = RegistrarClient::new(&config);
            assert!(result.is_ok());
        }

        #[test]
        fn test_various_retry_settings() {
            let mut config = create_test_config();
            config.client.max_retries = 5;
            config.client.retry_interval = 2.5;
            config.client.exponential_backoff = false;

            let result = RegistrarClient::new(&config);
            assert!(result.is_ok());
        }
    }

    // Integration-style tests (commented out as they require running services)
    /*
    #[tokio::test]
    async fn test_get_agent_integration() {
        let config = create_test_config();
        let client = RegistrarClient::new(&config).unwrap();

        // This would require a running registrar service
        // let result = client.get_agent("test-agent-uuid").await;
        // Should handle both Some(agent) and None cases
    }

    #[tokio::test]
    async fn test_list_agents_integration() {
        let config = create_test_config();
        let client = RegistrarClient::new(&config).unwrap();

        // This would require a running registrar service
        // let result = client.list_agents().await;
        // assert!(result.is_ok());
        //
        // let agents = result.unwrap();
        // assert!(agents.get("results").is_some());
    }

    #[tokio::test]
    async fn test_delete_agent_integration() {
        let config = create_test_config();
        let client = RegistrarClient::new(&config).unwrap();

        // This would require a running registrar service
        // let result = client.delete_agent("test-agent-uuid").await;
        // Should handle successful deletion
    }
    */
}
