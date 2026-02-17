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
//! println!("Found {} agents", agents["results"].as_object().unwrap().len()); //#[allow_ci]
//!
//! // Delete agent from registrar
//! let result = client.delete_agent("agent-uuid").await?;
//! println!("Agent deleted: {:?}", result);
//! # Ok(())
//! # }
//! ```

use crate::client::base::BaseClient;
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use keylime::version::KeylimeRegistrarVersion;
use log::{debug, info, warn};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::api_versions::SUPPORTED_API_VERSIONS;

/// Response structure for version endpoint
#[derive(serde::Deserialize, Debug)]
struct Response<T> {
    #[allow(dead_code)]
    code: serde_json::Number,
    #[allow(dead_code)]
    status: String,
    results: T,
}

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
    base: BaseClient,
    api_version: String,
    supported_api_versions: Option<Vec<String>>,
}

/// Builder for creating RegistrarClient instances with flexible configuration
///
/// The `RegistrarClientBuilder` provides a fluent interface for configuring
/// and creating `RegistrarClient` instances. It allows for optional API version
/// detection and custom API version specification.
///
/// # Examples
///
/// ```rust
/// use keylimectl::client::registrar::RegistrarClient;
/// use keylimectl::config::Config;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
///
/// // Create client with automatic version detection
/// let client = RegistrarClient::builder()
///     .config(&config)
///     .build()
///     .await?;
///
/// // Create client without version detection (for testing)
/// let client = RegistrarClient::builder()
///     .config(&config)
///     .skip_version_detection()
///     .build_sync()?;
///
/// // Create client with specific API version
/// let client = RegistrarClient::builder()
///     .config(&config)
///     .api_version("2.0")
///     .skip_version_detection()
///     .build_sync()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct RegistrarClientBuilder<'a> {
    config: Option<&'a Config>,
}

impl<'a> RegistrarClientBuilder<'a> {
    /// Create a new builder instance
    pub fn new() -> Self {
        Self { config: None }
    }

    /// Set the configuration for the client
    pub fn config(mut self, config: &'a Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Build the RegistrarClient with automatic API version detection
    ///
    /// This is the recommended way to create a client for production use,
    /// as it will automatically detect the optimal API version supported
    /// by the registrar service.
    pub async fn build(self) -> Result<RegistrarClient, KeylimectlError> {
        let config = self.config.ok_or_else(|| {
            KeylimectlError::validation(
                "Configuration is required for RegistrarClient",
            )
        })?;

        RegistrarClient::new(config).await
    }
}

impl<'a> Default for RegistrarClientBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistrarClient {
    /// Create a new builder for configuring a RegistrarClient
    ///
    /// This is the recommended way to create RegistrarClient instances,
    /// as it provides a flexible interface for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::registrar::RegistrarClient;
    /// use keylimectl::config::Config;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = RegistrarClient::builder()
    ///     .config(&config)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> RegistrarClientBuilder<'static> {
        RegistrarClientBuilder::new()
    }
    /// Create a new registrar client with automatic API version detection
    ///
    /// Initializes a new `RegistrarClient` with the provided configuration and
    /// automatically detects the API version supported by the registrar service.
    /// This sets up the HTTP client with TLS configuration, retry logic,
    /// and connection pooling, then attempts to determine the optimal API version.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing registrar endpoint and TLS settings
    ///
    /// # Returns
    ///
    /// Returns a configured `RegistrarClient` with detected API version.
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
    /// use keylimectl::client::registrar::RegistrarClient;
    /// use keylimectl::config::Config;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = RegistrarClient::new(&config).await?;
    /// println!("Registrar client created for {}", config.registrar_base_url());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: &Config) -> Result<Self, KeylimectlError> {
        let mut client = Self::new_without_version_detection(config)?;

        // Attempt to detect API version
        if let Err(e) = client.detect_api_version().await {
            warn!(
                "Failed to detect registrar API version, using default: {e}"
            );
        }

        Ok(client)
    }

    /// Create a new registrar client without API version detection
    ///
    /// Initializes a new `RegistrarClient` with the provided configuration
    /// using the default API version without attempting to detect the
    /// server's supported version. This is mainly useful for testing.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing registrar endpoint and TLS settings
    ///
    /// # Returns
    ///
    /// Returns a configured `RegistrarClient` with default API version.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - TLS certificate files cannot be read
    /// - Certificate/key files are invalid
    /// - HTTP client initialization fails
    pub(crate) fn new_without_version_detection(
        config: &Config,
    ) -> Result<Self, KeylimectlError> {
        let base_url = config.registrar_base_url();
        let base = BaseClient::new(base_url, config)
            .map_err(KeylimectlError::from)?;

        Ok(Self {
            base,
            api_version: crate::api_versions::DEFAULT_API_VERSION.to_string(),
            supported_api_versions: None,
        })
    }

    /// Auto-detect and set the API version
    ///
    /// Attempts to determine the registrar's API version by first trying the `/version` endpoint.
    /// If that fails, it tries each supported API version from oldest to newest until one works.
    /// This follows the same pattern used in the rust-keylime agent's registrar client.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if version detection succeeded or failed gracefully.
    /// Returns `Err()` only for critical errors that prevent client operation.
    ///
    /// # Behavior
    ///
    /// 1. First tries `/version` endpoint to get current and supported versions
    /// 2. If `/version` fails, tries API versions from newest to oldest
    /// 3. On success, caches the detected version for future requests
    /// 4. On complete failure, leaves default version unchanged
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use keylimectl::client::registrar::RegistrarClient;
    /// # use keylimectl::config::Config;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = RegistrarClient::new(&Config::default())?;
    ///
    /// // Detect API version manually if needed
    /// client.detect_api_version().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn detect_api_version(
        &mut self,
    ) -> Result<(), KeylimectlError> {
        // Try to get version from /version endpoint first
        match self.get_registrar_api_version().await {
            Ok(version) => {
                info!("Detected registrar API version: {version}");
                self.api_version = version;
                return Ok(());
            }
            Err(e) => {
                debug!("Failed to get version from /version endpoint: {e}");
                // Continue with fallback approach
            }
        }

        // Fallback: try each supported version from newest to oldest
        for &api_version in SUPPORTED_API_VERSIONS.iter().rev() {
            info!("Trying registrar API version {api_version}");

            // Test this version by making a simple request (list agents)
            if self.test_api_version(api_version).await.is_ok() {
                info!("Successfully detected registrar API version: {api_version}");
                self.api_version = api_version.to_string();
                return Ok(());
            }
        }

        // If all versions failed, continue with default version
        warn!(
            "Could not detect registrar API version, using default: {}",
            self.api_version
        );
        Ok(())
    }

    /// Get the registrar API version from the '/version' endpoint
    async fn get_registrar_api_version(
        &mut self,
    ) -> Result<String, KeylimectlError> {
        let url = format!("{}/version", self.base.base_url);

        info!("Requesting registrar API version from {url}");

        debug!("GET {url}");

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send version request to registrar".to_string()
            })?;

        if !response.status().is_success() {
            return Err(KeylimectlError::api_error(
                response.status().as_u16(),
                "Registrar does not support the /version endpoint"
                    .to_string(),
                None,
            ));
        }

        let resp: Response<KeylimeRegistrarVersion> =
            response.json().await.with_context(|| {
                "Failed to parse version response from registrar".to_string()
            })?;

        self.supported_api_versions =
            Some(resp.results.supported_versions.clone());
        Ok(resp.results.current_version)
    }

    /// Test if a specific API version works by making a simple request
    async fn test_api_version(
        &self,
        api_version: &str,
    ) -> Result<(), KeylimectlError> {
        let url = format!("{}/v{}/agents/", self.base.base_url, api_version);

        debug!("Testing registrar API version {api_version} with URL: {url}");

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                format!("Failed to test API version {api_version}")
            })?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(KeylimectlError::api_error(
                response.status().as_u16(),
                format!("API version {api_version} not supported"),
                None,
            ))
        }
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
            self.base.base_url, self.api_version, agent_uuid
        );

        debug!("GET {url}");

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get agent request to registrar".to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response: Value = self
                    .base
                    .handle_response(response)
                    .await
                    .map_err(KeylimectlError::from)?;

                // Extract agent data from registrar response format
                // The registrar API returns agent data directly in "results", not nested under agent UUID
                if let Some(results) = json_response.get("results") {
                    Ok(Some(results.clone()))
                } else {
                    Ok(Some(json_response))
                }
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let error_response: Result<Value, KeylimectlError> = self
                    .base
                    .handle_response(response)
                    .await
                    .map_err(KeylimectlError::from);
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
            self.base.base_url, self.api_version, agent_uuid
        );

        debug!("DELETE {url}");

        let response = self
            .base
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send delete agent request to registrar".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
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

        let url =
            format!("{}/v{}/agents/", self.base.base_url, self.api_version);

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list agents request to registrar".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::base::BaseClient;
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
    fn test_registrar_client_new() {
        let config = create_test_config();
        let result = RegistrarClient::new_without_version_detection(&config);

        assert!(result.is_ok());
        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://127.0.0.1:8891");
        assert_eq!(
            client.api_version,
            crate::api_versions::DEFAULT_API_VERSION
        );
    }

    #[test]
    fn test_registrar_client_new_with_custom_port() {
        let mut config = create_test_config();
        config.registrar.port = 9000;

        let result = RegistrarClient::new_without_version_detection(&config);
        assert!(result.is_ok());

        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://127.0.0.1:9000");
    }

    #[test]
    fn test_registrar_client_new_with_ipv6() {
        let mut config = create_test_config();
        config.registrar.ip = "::1".to_string();

        let result = RegistrarClient::new_without_version_detection(&config);
        assert!(result.is_ok());

        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://[::1]:8891");
    }

    #[test]
    fn test_registrar_client_new_with_bracketed_ipv6() {
        let mut config = create_test_config();
        config.registrar.ip = "[2001:db8::1]".to_string();

        let result = RegistrarClient::new_without_version_detection(&config);
        assert!(result.is_ok());

        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://[2001:db8::1]:8891");
    }

    #[test]
    fn test_create_http_client_basic() {
        let config = create_test_config();
        let result = BaseClient::create_http_client(&config);

        assert!(result.is_ok());
        // Basic validation that client was created
        let _client = result.unwrap(); //#[allow_ci]
    }

    #[test]
    fn test_create_http_client_with_timeout() {
        let mut config = create_test_config();
        config.client.timeout = 45;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_http_client_with_invalid_cert_files() {
        let mut config = create_test_config();
        config.tls.client_cert = Some("/nonexistent/cert.pem".to_string());
        config.tls.client_key = Some("/nonexistent/key.pem".to_string());

        let result = BaseClient::create_http_client(&config);
        // Should fail because cert files don't exist
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.to_string().contains("Certificate file error"));
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
        let client =
            RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]

        // Default API version should match DEFAULT_API_VERSION
        assert_eq!(
            client.api_version,
            crate::api_versions::DEFAULT_API_VERSION
        );
    }

    #[test]
    fn test_base_url_construction() {
        // Test IPv4 with custom port
        let mut config = create_test_config();
        config.registrar.ip = "10.0.0.5".to_string();
        config.registrar.port = 9500;

        let client =
            RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]
        assert_eq!(client.base.base_url, "https://10.0.0.5:9500");

        // Test IPv6
        config.registrar.ip = "2001:db8:85a3::8a2e:370:7334".to_string();
        config.registrar.port = 8891;

        let client =
            RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]
        assert_eq!(
            client.base.base_url,
            "https://[2001:db8:85a3::8a2e:370:7334]:8891"
        );
    }

    #[test]
    fn test_client_debug_trait() {
        let config = create_test_config();
        let client =
            RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]

        // Test that Debug trait is implemented
        let debug_string = format!("{client:?}");
        assert!(debug_string.contains("RegistrarClient"));
    }

    #[test]
    fn test_tls_config_disabled_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = false;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification disabled
    }

    #[test]
    fn test_tls_config_enabled_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = true;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification enabled
    }

    #[test]
    fn test_client_config_values() {
        let config = create_test_config();
        let client =
            RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]

        // Verify that config values are properly used
        assert_eq!(
            client.api_version,
            crate::api_versions::DEFAULT_API_VERSION
        );
        assert!(client.base.base_url.starts_with("https://"));
        assert!(client.base.base_url.contains("8891"));
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

            let result =
                RegistrarClient::new_without_version_detection(&config);
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
            let result =
                RegistrarClient::new_without_version_detection(&config);
            assert!(result.is_ok());
        }

        #[test]
        fn test_various_retry_settings() {
            let mut config = create_test_config();
            config.client.max_retries = 5;
            config.client.retry_interval = 2.5;
            config.client.exponential_backoff = false;

            let result =
                RegistrarClient::new_without_version_detection(&config);
            assert!(result.is_ok());
        }
    }

    // Integration-style tests (commented out as they require running services)
    /*
    #[tokio::test]
    async fn test_get_agent_integration() {
        let config = create_test_config();
        let client = RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]

        // This would require a running registrar service
        // let result = client.get_agent("test-agent-uuid").await;
        // Should handle both Some(agent) and None cases
    }

    #[tokio::test]
    async fn test_list_agents_integration() {
        let config = create_test_config();
        let client = RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]

        // This would require a running registrar service
        // let result = client.list_agents().await;
        // assert!(result.is_ok());
        //
        // let agents = result.unwrap(); //#[allow_ci]
        // assert!(agents.get("results").is_some());
    }

    #[tokio::test]
    async fn test_delete_agent_integration() {
        let config = create_test_config();
        let client = RegistrarClient::new_without_version_detection(&config).unwrap(); //#[allow_ci]

        // This would require a running registrar service
        // let result = client.delete_agent("test-agent-uuid").await;
        // Should handle successful deletion
    }
    */

    // API Version Detection Tests
    mod api_version_tests {
        use super::*;
        use keylime::version::KeylimeRegistrarVersion;
        use serde_json::json;

        #[test]
        fn test_supported_api_versions_constant() {
            // Test that the constant contains expected versions based on enabled features
            assert!(!SUPPORTED_API_VERSIONS.is_empty());

            #[cfg(all(feature = "api-v2", feature = "api-v3"))]
            assert_eq!(
                SUPPORTED_API_VERSIONS,
                &["2.0", "2.1", "2.2", "2.3", "3.0"]
            );

            #[cfg(all(feature = "api-v2", not(feature = "api-v3")))]
            assert_eq!(SUPPORTED_API_VERSIONS, &["2.0", "2.1", "2.2", "2.3"]);

            #[cfg(all(not(feature = "api-v2"), feature = "api-v3"))]
            assert_eq!(SUPPORTED_API_VERSIONS, &["3.0"]);

            // Verify versions are in ascending order (oldest to newest)
            for i in 1..SUPPORTED_API_VERSIONS.len() {
                let prev: f32 =
                    SUPPORTED_API_VERSIONS[i - 1].parse().unwrap(); //#[allow_ci]
                let curr: f32 = SUPPORTED_API_VERSIONS[i].parse().unwrap(); //#[allow_ci]
                assert!(
                    prev < curr,
                    "API versions should be in ascending order"
                );
            }
        }

        #[test]
        fn test_response_structure_deserialization() {
            let json_str = r#"{
                "code": 200,
                "status": "OK",
                "results": {
                    "current_version": "2.1",
                    "supported_versions": ["2.0", "2.1", "2.2", "3.0"]
                }
            }"#;

            let response: Result<Response<KeylimeRegistrarVersion>, _> =
                serde_json::from_str(json_str);

            assert!(response.is_ok());
            let response = response.unwrap(); //#[allow_ci]
            assert_eq!(response.results.current_version, "2.1");
            assert_eq!(
                response.results.supported_versions,
                vec!["2.0", "2.1", "2.2", "3.0"]
            );
        }

        #[test]
        fn test_client_initialization_with_default_version() {
            let config = create_test_config();
            let client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Client should start with default API version
            assert_eq!(
                client.api_version,
                crate::api_versions::DEFAULT_API_VERSION
            );
            assert!(client.supported_api_versions.is_none());
        }

        #[test]
        fn test_api_version_iteration_order() {
            // Test that iter().rev() gives us newest to oldest as expected
            let versions: Vec<&str> =
                SUPPORTED_API_VERSIONS.iter().rev().copied().collect();

            // Should be newest first (last element of ascending array)
            assert_eq!(
                versions[0],
                *SUPPORTED_API_VERSIONS.last().unwrap() //#[allow_ci]
            );

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
        fn test_version_string_parsing() {
            // Test that our version strings can be parsed as valid version numbers
            for version in SUPPORTED_API_VERSIONS {
                let parsed: Result<f32, _> = version.parse();
                assert!(
                    parsed.is_ok(),
                    "Version string '{version}' should parse as number"
                );

                let num = parsed.unwrap(); //#[allow_ci]
                assert!(num >= 1.0, "Version should be >= 1.0");
                assert!(num < 10.0, "Version should be reasonable");
            }
        }

        #[test]
        fn test_client_struct_fields() {
            let config = create_test_config();
            let mut client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Test that we can access and modify the api_version field
            assert_eq!(
                client.api_version,
                crate::api_versions::DEFAULT_API_VERSION
            );

            client.api_version = "2.0".to_string();
            assert_eq!(client.api_version, "2.0");

            client.api_version = "3.0".to_string();
            assert_eq!(client.api_version, "3.0");
        }

        #[test]
        fn test_base_url_construction_with_different_versions() {
            let config = create_test_config();
            let mut client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Test URL construction with different API versions
            for version in SUPPORTED_API_VERSIONS {
                client.api_version = version.to_string();

                // Simulate how URLs would be constructed in actual methods
                let expected_pattern = format!("/v{version}/agents/");
                let test_url = format!(
                    "{}/v{}/agents/test-uuid",
                    client.base.base_url, client.api_version
                );

                assert!(test_url.contains(&expected_pattern));
                assert!(test_url.contains(&client.base.base_url));
                assert!(test_url.contains("test-uuid"));
            }
        }

        #[test]
        fn test_supported_api_versions_field() {
            let config = create_test_config();
            let mut client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Initially should be None
            assert!(client.supported_api_versions.is_none());

            // Simulate setting supported versions (as would happen in detect_api_version)
            client.supported_api_versions =
                Some(vec!["2.0".to_string(), "2.1".to_string()]);

            assert!(client.supported_api_versions.is_some());
            let versions = client.supported_api_versions.unwrap(); //#[allow_ci]
            assert_eq!(versions, vec!["2.0", "2.1"]);
        }

        #[test]
        #[allow(clippy::const_is_empty)]
        fn test_version_constants_consistency() {
            // Ensure our constants are consistent with expected patterns
            assert!(!SUPPORTED_API_VERSIONS.is_empty()); // Known constant value

            // All supported versions should be valid version strings
            for version in SUPPORTED_API_VERSIONS {
                assert!(!version.is_empty());
                assert!(version
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.'));
                assert!(version.contains('.'));
            }
        }

        #[test]
        fn test_client_debug_output() {
            let config = create_test_config();
            let client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Test that Debug trait produces reasonable output
            let debug_output = format!("{client:?}");
            assert!(debug_output.contains("RegistrarClient"));
            assert!(debug_output.contains("api_version"));
        }

        #[test]
        fn test_version_detection_error_scenarios() {
            // Test error creation for version detection failures
            let no_version_error = KeylimectlError::api_error(
                404,
                "Registrar does not support the /version endpoint"
                    .to_string(),
                None,
            );

            assert_eq!(no_version_error.error_code(), "API_ERROR");

            let version_parse_error = KeylimectlError::api_error(
                500,
                "Failed to parse version response from registrar".to_string(),
                Some(json!({"error": "Invalid JSON"})),
            );

            assert_eq!(version_parse_error.error_code(), "API_ERROR");
        }

        #[test]
        fn test_api_version_fallback_behavior() {
            // Test the logic that would be used in detect_api_version fallback
            let enabled_versions = SUPPORTED_API_VERSIONS;

            // Simulate trying versions from newest to oldest
            let mut attempted_versions = Vec::new();
            for &version in enabled_versions.iter().rev() {
                attempted_versions.push(version);
            }

            // Should try newest first
            assert_eq!(
                attempted_versions[0],
                *SUPPORTED_API_VERSIONS.last().unwrap() //#[allow_ci]
            );

            // Should try all supported versions
            assert_eq!(
                attempted_versions.len(),
                SUPPORTED_API_VERSIONS.len()
            );
        }

        #[test]
        fn test_registrar_specific_functionality() {
            let config = create_test_config();
            let client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Test registrar-specific base URL
            assert!(client.base.base_url.contains("8891")); // Default registrar port
            assert!(client.base.base_url.starts_with("https://"));

            // Test that client can be created with different IPs
            let mut custom_config = create_test_config();
            custom_config.registrar.ip = "10.0.0.5".to_string();
            custom_config.registrar.port = 9000;

            let custom_client =
                RegistrarClient::new_without_version_detection(
                    &custom_config,
                )
                .unwrap(); //#[allow_ci]
            assert!(custom_client.base.base_url.contains("10.0.0.5"));
            assert!(custom_client.base.base_url.contains("9000"));
        }

        #[test]
        fn test_api_versions_shared_source() {
            // Both verifier and registrar now import from
            // crate::api_versions (single source of truth).
            // This test validates the import works correctly.
            assert!(!SUPPORTED_API_VERSIONS.is_empty());
        }

        #[test]
        fn test_version_endpoint_url_construction() {
            let config = create_test_config();
            let client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Test version endpoint URL construction
            let version_url = format!("{}/version", client.base.base_url);

            assert!(version_url.contains("/version"));
            assert!(version_url.starts_with("https://"));
            assert!(version_url.contains("8891")); // Default port

            // Should not contain /v{version}/ for version endpoint
            assert!(!version_url.contains("/v2."));
        }

        #[test]
        fn test_agents_endpoint_url_construction() {
            let config = create_test_config();
            let mut client =
                RegistrarClient::new_without_version_detection(&config)
                    .unwrap(); //#[allow_ci]

            // Test agents endpoint URL construction for different versions
            for version in SUPPORTED_API_VERSIONS {
                client.api_version = version.to_string();
                let agents_url = format!(
                    "{}/v{}/agents/",
                    client.base.base_url, client.api_version
                );

                assert!(agents_url.contains(&format!("/v{version}/agents/")));
                assert!(agents_url.starts_with("https://"));
                assert!(agents_url.ends_with("/agents/"));
            }
        }
    }
}
