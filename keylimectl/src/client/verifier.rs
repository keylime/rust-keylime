// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Verifier client for communicating with the Keylime verifier
//!
//! This module provides a comprehensive client interface for interacting with the Keylime verifier service.
//! The verifier is responsible for continuously monitoring agent integrity, managing attestation policies,
//! and providing cryptographic bootstrapping capabilities.
//!
//! # Features
//!
//! - **Agent Management**: Add, remove, and monitor agents
//! - **Policy Management**: Runtime and measured boot policy operations
//! - **Resilient Communication**: Built-in retry logic and error handling
//! - **TLS Support**: Mutual TLS authentication with configurable certificates
//! - **Bulk Operations**: Efficient batch operations for multiple agents
//!
//! # Architecture
//!
//! The [`VerifierClient`] wraps a [`ResilientClient`] from the keylime library,
//! providing automatic retries, exponential backoff, and proper error handling
//! for all verifier operations.
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::client::verifier::VerifierClient;
//! use keylimectl::config::Config;
//! use serde_json::json;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::default();
//! let client = VerifierClient::new(&config)?;
//!
//! // Add an agent to the verifier
//! let agent_data = json!({
//!     "ip": "192.168.1.100",
//!     "port": 9002,
//!     "tpm_policy": "{}",
//!     "ima_policy": "{}"
//! });
//! let result = client.add_agent("agent-uuid", agent_data).await?;
//!
//! // Get agent information
//! if let Some(agent) = client.get_agent("agent-uuid").await? {
//!     println!("Agent status: {:?}", agent);
//! }
//!
//! // List all agents
//! let agents = client.list_agents(None).await?;
//! println!("Found {} agents", agents["results"].as_object().unwrap().len());
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

/// Unknown API version constant for when version detection fails
pub const UNKNOWN_API_VERSION: &str = "unknown";

/// Supported API versions in order from oldest to newest (fallback tries newest first)
pub const SUPPORTED_API_VERSIONS: &[&str] =
    &["2.0", "2.1", "2.2", "2.3", "3.0"];

/// Response structure for version endpoint
#[derive(serde::Deserialize, Debug)]
struct Response<T> {
    #[allow(dead_code)]
    code: serde_json::Number,
    #[allow(dead_code)]
    status: String,
    results: T,
}

/// Client for communicating with the Keylime verifier service
///
/// The `VerifierClient` provides a high-level interface for all verifier operations,
/// including agent management, policy operations, and bulk queries. It handles
/// authentication, retries, and error processing automatically.
///
/// # Configuration
///
/// The client is configured through the [`Config`] struct, which specifies:
/// - Verifier service endpoint (IP and port)
/// - TLS certificate configuration
/// - Retry and timeout settings
///
/// # Connection Management
///
/// The client maintains a persistent HTTP connection pool and automatically
/// handles connection failures with exponential backoff retry logic.
///
/// # Thread Safety
///
/// `VerifierClient` is thread-safe and can be shared across multiple tasks
/// or threads using `Arc<VerifierClient>`.
///
/// # Examples
///
/// ```rust
/// use keylimectl::client::verifier::VerifierClient;
/// use keylimectl::config::Config;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut config = Config::default();
/// config.verifier.ip = "10.0.0.1".to_string();
/// config.verifier.port = 8881;
///
/// let client = VerifierClient::new(&config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct VerifierClient {
    base: BaseClient,
    api_version: String,
    supported_api_versions: Option<Vec<String>>,
}

/// Builder for creating VerifierClient instances with flexible configuration
///
/// The `VerifierClientBuilder` provides a fluent interface for configuring
/// and creating `VerifierClient` instances. It allows for optional API version
/// detection and custom API version specification.
///
/// # Examples
///
/// ```rust
/// use keylimectl::client::verifier::VerifierClient;
/// use keylimectl::config::Config;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
///
/// // Create client with automatic version detection
/// let client = VerifierClient::builder()
///     .config(&config)
///     .build()
///     .await?;
///
/// // Create client without version detection (for testing)
/// let client = VerifierClient::builder()
///     .config(&config)
///     .skip_version_detection()
///     .build_sync()?;
///
/// // Create client with specific API version
/// let client = VerifierClient::builder()
///     .config(&config)
///     .api_version("2.0")
///     .skip_version_detection()
///     .build_sync()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct VerifierClientBuilder<'a> {
    config: Option<&'a Config>,
}

impl<'a> VerifierClientBuilder<'a> {
    /// Create a new builder instance
    pub fn new() -> Self {
        Self { config: None }
    }

    /// Set the configuration for the client
    pub fn config(mut self, config: &'a Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Build the VerifierClient with automatic API version detection
    ///
    /// This is the recommended way to create a client for production use,
    /// as it will automatically detect the optimal API version supported
    /// by the verifier service.
    pub async fn build(self) -> Result<VerifierClient, KeylimectlError> {
        let config = self.config.ok_or_else(|| {
            KeylimectlError::validation(
                "Configuration is required for VerifierClient",
            )
        })?;

        VerifierClient::new(config).await
    }
}

impl<'a> Default for VerifierClientBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierClient {
    /// Create a new builder for configuring a VerifierClient
    ///
    /// This is the recommended way to create VerifierClient instances,
    /// as it provides a flexible interface for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::verifier::VerifierClient;
    /// use keylimectl::config::Config;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = VerifierClient::builder()
    ///     .config(&config)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> VerifierClientBuilder<'static> {
        VerifierClientBuilder::new()
    }
    /// Create a new verifier client with automatic API version detection
    ///
    /// Initializes a new `VerifierClient` with the provided configuration and
    /// automatically detects the API version supported by the verifier service.
    /// This sets up the HTTP client with TLS configuration, retry logic,
    /// and connection pooling, then attempts to determine the optimal API version.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing verifier endpoint and TLS settings
    ///
    /// # Returns
    ///
    /// Returns a configured `VerifierClient` with detected API version.
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
    /// use keylimectl::client::verifier::VerifierClient;
    /// use keylimectl::config::Config;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = VerifierClient::new(&config).await?;
    /// println!("Verifier client created for {}", config.verifier_base_url());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: &Config) -> Result<Self, KeylimectlError> {
        debug!("Creating VerifierClient with config: client_cert={:?}, client_key={:?}, trusted_ca={:?}",
               config.tls.client_cert, config.tls.client_key, config.tls.trusted_ca);
        let mut client = Self::new_without_version_detection(config)?;

        // Attempt to detect API version
        if let Err(e) = client.detect_api_version().await {
            warn!(
                "Failed to detect verifier API version, using default: {e}"
            );
        }

        Ok(client)
    }

    /// Create a new verifier client without API version detection
    ///
    /// Initializes a new `VerifierClient` with the provided configuration
    /// using the default API version without attempting to detect the
    /// server's supported version. This is mainly useful for testing.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing verifier endpoint and TLS settings
    ///
    /// # Returns
    ///
    /// Returns a configured `VerifierClient` with default API version.
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
        let base_url = config.verifier_base_url();
        let base = BaseClient::new(base_url, config)
            .map_err(KeylimectlError::from)?;

        Ok(Self {
            base,
            api_version: "2.1".to_string(), // Default API version
            supported_api_versions: None,
        })
    }

    /// Auto-detect and set the API version
    ///
    /// Attempts to determine the verifier's API version by first trying the `/version` endpoint.
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
    /// # use keylimectl::client::verifier::VerifierClient;
    /// # use keylimectl::config::Config;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = VerifierClient::new(&Config::default())?;
    ///
    /// // Version detection happens automatically during client creation,
    /// // but can be called manually if needed
    /// client.detect_api_version().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn detect_api_version(
        &mut self,
    ) -> Result<(), KeylimectlError> {
        // Try to get version from /version endpoint first
        match self.get_verifier_api_version().await {
            Ok(version) => {
                info!("Detected verifier API version: {version}");
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
            info!("Trying verifier API version {api_version}");

            // Test this version by making a simple request (list agents)
            if self.test_api_version(api_version).await.is_ok() {
                info!("Successfully detected verifier API version: {api_version}");
                self.api_version = api_version.to_string();
                return Ok(());
            }
        }

        // If all versions failed, set to unknown and continue with default
        warn!(
            "Could not detect verifier API version, using default: {}",
            self.api_version
        );
        self.api_version = UNKNOWN_API_VERSION.to_string();
        Ok(())
    }

    /// Get the verifier API version from the '/version' endpoint
    async fn get_verifier_api_version(
        &mut self,
    ) -> Result<String, KeylimectlError> {
        let url = format!("{}/version", self.base.base_url);

        info!("Requesting verifier API version from {url}");

        debug!("Sending version request to: {url}");

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                format!("Failed to send version request to verifier at {url}")
            })?;

        if !response.status().is_success() {
            return Err(KeylimectlError::api_error(
                response.status().as_u16(),
                "Verifier does not support the /version endpoint".to_string(),
                None,
            ));
        }

        let resp: Response<KeylimeRegistrarVersion> =
            response.json().await.with_context(|| {
                "Failed to parse version response from verifier".to_string()
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

        debug!("Testing verifier API version {api_version} with URL: {url}");

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

    /// Add an agent to the verifier for attestation monitoring
    ///
    /// Registers an agent with the verifier service, enabling continuous
    /// integrity monitoring and attestation. The agent must already be
    /// registered with the registrar before being added to the verifier.
    ///
    /// # Arguments
    ///
    /// * `agent_uuid` - Unique identifier for the agent
    /// * `data` - Agent configuration including IP, port, and policies
    ///
    /// # Expected Data Format
    ///
    /// The `data` parameter should contain:
    /// ```json
    /// {
    ///     "ip": "192.168.1.100",
    ///     "port": 9002,
    ///     "tpm_policy": "{}",
    ///     "ima_policy": "{}",
    ///     "mb_refstate": null,
    ///     "allowlist": null,
    ///     "revocation_key": "",
    ///     "accept_tpm_hash_algs": ["sha1", "sha256"],
    ///     "accept_tpm_encryption_algs": ["ecc", "rsa"]
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// Returns the verifier's response containing agent status and configuration.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent UUID is invalid or already exists
    /// - Required agent data is missing or invalid
    /// - Agent is not registered with the registrar
    /// - Network communication fails
    /// - Verifier service returns an error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::verifier::VerifierClient;
    /// use serde_json::json;
    ///
    /// # async fn example(client: &VerifierClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let agent_data = json!({
    ///     "ip": "192.168.1.100",
    ///     "port": 9002,
    ///     "tpm_policy": "{}",
    ///     "ima_policy": "{}"
    /// });
    ///
    /// let result = client.add_agent("550e8400-e29b-41d4-a716-446655440000", agent_data).await?;
    /// println!("Agent added successfully: {:?}", result);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_agent(
        &self,
        agent_uuid: &str,
        data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding agent {agent_uuid} to verifier");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base.base_url, self.api_version, agent_uuid
        );

        let response = self
            .base
            .client
            .get_json_request_from_struct(Method::POST, &url, &data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send add agent request to verifier".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Get agent information from the verifier
    ///
    /// Retrieves detailed information about a specific agent, including its
    /// current operational state, attestation status, and configuration.
    ///
    /// # Arguments
    ///
    /// * `agent_uuid` - Unique identifier for the agent
    ///
    /// # Returns
    ///
    /// Returns `Some(Value)` containing agent information if found,
    /// or `None` if the agent doesn't exist on the verifier.
    ///
    /// # Agent Information
    ///
    /// The returned data includes:
    /// - `operational_state`: Current state ("Start", "Tenant Start", "Get Quote", etc.)
    /// - `ip`: Agent IP address
    /// - `port`: Agent port
    /// - `verifier_ip`: Verifier IP address
    /// - `verifier_port`: Verifier port
    /// - `tpm_policy`: Current TPM policy
    /// - `ima_policy`: Current IMA policy
    /// - `last_event_id`: Latest event identifier
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent UUID format is invalid
    /// - Network communication fails
    /// - Verifier service returns an error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::verifier::VerifierClient;
    ///
    /// # async fn example(client: &VerifierClient) -> Result<(), Box<dyn std::error::Error>> {
    /// match client.get_agent("550e8400-e29b-41d4-a716-446655440000").await? {
    ///     Some(agent) => {
    ///         println!("Agent state: {}", agent["operational_state"]);
    ///         println!("Agent IP: {}", agent["ip"]);
    ///     }
    ///     None => println!("Agent not found on verifier"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting agent {agent_uuid} from verifier");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base.base_url, self.api_version, agent_uuid
        );

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get agent request to verifier".to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response: Value = self
                    .base
                    .handle_response(response)
                    .await
                    .map_err(KeylimectlError::from)?;
                Ok(Some(json_response))
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

    /// Delete an agent from the verifier
    ///
    /// Removes an agent from verifier monitoring, stopping all attestation
    /// activities for that agent. The agent will no longer be monitored
    /// for integrity violations.
    ///
    /// # Arguments
    ///
    /// * `agent_uuid` - Unique identifier for the agent to remove
    ///
    /// # Returns
    ///
    /// Returns the verifier's response confirming deletion.
    ///
    /// # Behavior
    ///
    /// - Stops all active monitoring for the agent
    /// - Removes agent from verifier's active agent list
    /// - Does NOT remove agent from registrar (separate operation)
    /// - Gracefully handles requests for non-existent agents
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Agent UUID format is invalid
    /// - Network communication fails
    /// - Verifier service returns an error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::verifier::VerifierClient;
    ///
    /// # async fn example(client: &VerifierClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let result = client.delete_agent("550e8400-e29b-41d4-a716-446655440000").await?;
    /// println!("Agent removed: {:?}", result);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting agent {agent_uuid} from verifier");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base.base_url, self.api_version, agent_uuid
        );

        let response = self
            .base
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send delete agent request to verifier".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Reactivate an agent on the verifier
    pub async fn reactivate_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Reactivating agent {agent_uuid} on verifier");

        let url = format!(
            "{}/v{}/agents/{}/reactivate",
            self.base.base_url, self.api_version, agent_uuid
        );

        let response = self
            .base
            .client
            .get_request(Method::PUT, &url)
            .body("")
            .send()
            .await
            .with_context(|| {
                "Failed to send reactivate agent request to verifier"
                    .to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// List all agents on the verifier
    ///
    /// Retrieves a list of all agents currently being monitored by the verifier.
    /// This provides a high-level overview of the attestation infrastructure.
    ///
    /// # Arguments
    ///
    /// * `verifier_id` - Optional verifier instance identifier for multi-verifier setups
    ///
    /// # Returns
    ///
    /// Returns a JSON object containing:
    /// ```json
    /// {
    ///     "results": {
    ///         "agent-uuid-1": "operational_state",
    ///         "agent-uuid-2": "operational_state",
    ///         ...
    ///     }
    /// }
    /// ```
    ///
    /// # Operational States
    ///
    /// Common operational states include:
    /// - `"Start"`: Agent initialization
    /// - `"Tenant Start"`: Verifier-side initialization
    /// - `"Get Quote"`: Requesting TPM quote
    /// - `"Provide V"`: Providing verification data
    /// - `"Provide V (Retry)"`: Retrying verification
    /// - `"Failed"`: Agent failed attestation
    /// - `"Terminated"`: Agent was terminated
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Network communication fails
    /// - Verifier service returns an error
    /// - Invalid verifier_id specified
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::verifier::VerifierClient;
    ///
    /// # async fn example(client: &VerifierClient) -> Result<(), Box<dyn std::error::Error>> {
    /// // List all agents
    /// let agents = client.list_agents(None).await?;
    /// let agent_count = agents["results"].as_object().unwrap().len();
    /// println!("Monitoring {} agents", agent_count);
    ///
    /// // List agents for specific verifier
    /// let agents = client.list_agents(Some("verifier-1")).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_agents(
        &self,
        verifier_id: Option<&str>,
    ) -> Result<Value, KeylimectlError> {
        debug!("Listing agents on verifier");

        let mut url =
            format!("{}/v{}/agents/", self.base.base_url, self.api_version);

        if let Some(vid) = verifier_id {
            url.push_str(&format!("?verifier={vid}"));
        }

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list agents request to verifier".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Get bulk information for all agents
    ///
    /// Retrieves detailed information for all agents in a single request.
    /// This is more efficient than calling `get_agent()` for each agent
    /// individually when you need comprehensive agent data.
    ///
    /// # Arguments
    ///
    /// * `verifier_id` - Optional verifier instance identifier for multi-verifier setups
    ///
    /// # Returns
    ///
    /// Returns detailed information for all agents:
    /// ```json
    /// {
    ///     "results": {
    ///         "agent-uuid-1": {
    ///             "operational_state": "Get Quote",
    ///             "ip": "192.168.1.100",
    ///             "port": 9002,
    ///             "verifier_ip": "192.168.1.1",
    ///             "verifier_port": 8881,
    ///             "tpm_policy": "{}",
    ///             "ima_policy": "{}"
    ///         },
    ///         ...
    ///     }
    /// }
    /// ```
    ///
    /// # Performance
    ///
    /// This method is optimized for bulk operations and should be preferred
    /// over multiple individual `get_agent()` calls when retrieving data
    /// for multiple agents.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Network communication fails
    /// - Verifier service returns an error
    /// - Invalid verifier_id specified
    /// - Response payload is too large (very large deployments)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::verifier::VerifierClient;
    ///
    /// # async fn example(client: &VerifierClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let bulk_info = client.get_bulk_info(None).await?;
    ///
    /// if let Some(results) = bulk_info["results"].as_object() {
    ///     for (uuid, info) in results {
    ///         println!("Agent {}: {}", uuid, info["operational_state"]);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_bulk_info(
        &self,
        verifier_id: Option<&str>,
    ) -> Result<Value, KeylimectlError> {
        debug!("Getting bulk agent info from verifier");

        let mut url = format!(
            "{}/v{}/agents/?bulk=true",
            self.base.base_url, self.api_version
        );

        if let Some(vid) = verifier_id {
            url.push_str(&format!("&verifier={vid}"));
        }

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send bulk info request to verifier".to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Add a runtime policy
    pub async fn add_runtime_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding runtime policy {policy_name} to verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base
            .client
            .get_json_request_from_struct(
                Method::POST,
                &url,
                &policy_data,
                None,
            )
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send add runtime policy request to verifier"
                    .to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Get a runtime policy
    pub async fn get_runtime_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting runtime policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get runtime policy request to verifier"
                    .to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response: Value = self
                    .base
                    .handle_response(response)
                    .await
                    .map_err(KeylimectlError::from)?;
                Ok(Some(json_response))
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

    /// Update a runtime policy
    pub async fn update_runtime_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating runtime policy {policy_name} on verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base
            .client
            .get_json_request_from_struct(
                Method::PUT,
                &url,
                &policy_data,
                None,
            )
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send update runtime policy request to verifier"
                    .to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Delete a runtime policy
    pub async fn delete_runtime_policy(
        &self,
        policy_name: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting runtime policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send delete runtime policy request to verifier"
                    .to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// List runtime policies
    pub async fn list_runtime_policies(
        &self,
    ) -> Result<Value, KeylimectlError> {
        debug!("Listing runtime policies on verifier");

        let url = format!(
            "{}/v{}/allowlists/",
            self.base.base_url, self.api_version
        );

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list runtime policies request to verifier"
                    .to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Add a measured boot policy
    pub async fn add_mb_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding measured boot policy {policy_name} to verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base
            .client
            .get_json_request_from_struct(
                Method::POST,
                &url,
                &policy_data,
                None,
            )
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send add measured boot policy request to verifier"
                    .to_string()
            })?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Get a measured boot policy
    pub async fn get_mb_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting measured boot policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get measured boot policy request to verifier"
                    .to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response: Value = self
                    .base
                    .handle_response(response)
                    .await
                    .map_err(KeylimectlError::from)?;
                Ok(Some(json_response))
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

    /// Update a measured boot policy
    pub async fn update_mb_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating measured boot policy {policy_name} on verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base.client
            .get_json_request_from_struct(Method::PUT, &url, &policy_data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| "Failed to send update measured boot policy request to verifier".to_string())?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Delete a measured boot policy
    pub async fn delete_mb_policy(
        &self,
        policy_name: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting measured boot policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base.base_url, self.api_version, policy_name
        );

        let response = self
            .base.client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| "Failed to send delete measured boot policy request to verifier".to_string())?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// List measured boot policies
    pub async fn list_mb_policies(&self) -> Result<Value, KeylimectlError> {
        debug!("Listing measured boot policies on verifier");

        let url = format!(
            "{}/v{}/mbpolicies/",
            self.base.base_url, self.api_version
        );

        let response = self
            .base.client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| "Failed to send list measured boot policies request to verifier".to_string())?;

        self.base
            .handle_response(response)
            .await
            .map_err(KeylimectlError::from)
    }

    /// Get the detected API version
    pub fn api_version(&self) -> &str {
        &self.api_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::base::BaseClient;
    use crate::config::{ClientConfig, TlsConfig, VerifierConfig};

    /// Create a test configuration
    fn create_test_config() -> Config {
        Config {
            verifier: VerifierConfig {
                ip: "127.0.0.1".to_string(),
                port: 8881,
                id: Some("test-verifier".to_string()),
            },
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
    fn test_verifier_client_new() {
        let config = create_test_config();
        let result = VerifierClient::new_without_version_detection(&config);

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.base.base_url, "https://127.0.0.1:8881");
        assert_eq!(client.api_version, "2.1");
    }

    #[test]
    fn test_verifier_client_new_with_ipv6() {
        let mut config = create_test_config();
        config.verifier.ip = "::1".to_string();

        let result = VerifierClient::new_without_version_detection(&config);
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.base.base_url, "https://[::1]:8881");
    }

    #[test]
    fn test_verifier_client_new_with_bracketed_ipv6() {
        let mut config = create_test_config();
        config.verifier.ip = "[2001:db8::1]".to_string();

        let result = VerifierClient::new_without_version_detection(&config);
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.base.base_url, "https://[2001:db8::1]:8881");
    }

    #[test]
    fn test_create_http_client_basic() {
        let config = create_test_config();
        let result = BaseClient::create_http_client(&config);

        assert!(result.is_ok());
        // Basic validation that client was created
        let _client = result.unwrap();
    }

    #[test]
    fn test_create_http_client_with_timeout() {
        let mut config = create_test_config();
        config.client.timeout = 60;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_http_client_with_cert_files_nonexistent() {
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
        assert_eq!(config.verifier_base_url(), "https://127.0.0.1:8881");
    }

    #[test]
    fn test_api_version() {
        let config = create_test_config();
        let client =
            VerifierClient::new_without_version_detection(&config).unwrap();

        // Default API version should be 2.1
        assert_eq!(client.api_version, "2.1");
    }

    #[test]
    fn test_base_url_construction() {
        // Test IPv4
        let mut config = create_test_config();
        config.verifier.ip = "192.168.1.100".to_string();
        config.verifier.port = 9001;

        let client =
            VerifierClient::new_without_version_detection(&config).unwrap();
        assert_eq!(client.base.base_url, "https://192.168.1.100:9001");

        // Test IPv6
        config.verifier.ip = "2001:db8::1".to_string();
        config.verifier.port = 8881;

        let client =
            VerifierClient::new_without_version_detection(&config).unwrap();
        assert_eq!(client.base.base_url, "https://[2001:db8::1]:8881");
    }

    #[test]
    fn test_client_config_values() {
        let config = create_test_config();
        let client =
            VerifierClient::new_without_version_detection(&config).unwrap();

        // Verify that config values are properly used
        // Note: We can't directly access the internal reqwest client config,
        // but we can verify our config was accepted
        assert_eq!(client.api_version, "2.1");
        assert!(client.base.base_url.starts_with("https://"));
    }

    #[test]
    fn test_tls_config_no_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = false;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification disabled
    }

    #[test]
    fn test_tls_config_with_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = true;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification enabled
    }

    // Mock response handler tests
    mod response_tests {
        use super::*;
        use serde_json::json;

        // Note: Testing handle_response requires mocking HTTP responses
        // which is complex with reqwest. In a real implementation, we would
        // use a mocking library like wiremock or mockito.

        #[test]
        fn test_error_codes() {
            // Test error code constants and behavior
            let api_error = KeylimectlError::api_error(
                404,
                "Agent not found".to_string(),
                Some(json!({"error": "Agent does not exist"})),
            );

            assert_eq!(api_error.error_code(), "API_ERROR");

            let json_output = api_error.to_json();
            assert_eq!(json_output["error"]["code"], "API_ERROR");
            assert_eq!(json_output["error"]["details"]["http_status"], 404);
        }

        #[test]
        fn test_api_error_creation() {
            let error = KeylimectlError::api_error(
                500,
                "Internal server error".to_string(),
                None,
            );

            assert_eq!(error.error_code(), "API_ERROR");
            assert!(error.is_retryable()); // 5xx errors should be retryable

            let error_400 = KeylimectlError::api_error(
                400,
                "Bad request".to_string(),
                None,
            );
            assert!(!error_400.is_retryable()); // 4xx errors should not be retryable
        }
    }

    // Integration-style tests that would require a running verifier
    // These are commented out as they require actual network connectivity
    /*
    #[tokio::test]
    async fn test_add_agent_integration() {
        let config = create_test_config();
        let client = VerifierClient::new_without_version_detection(&config).unwrap();

        let agent_data = json!({
            "ip": "192.168.1.100",
            "port": 9002,
            "tpm_policy": "{}",
            "ima_policy": "{}"
        });

        // This would require a running verifier service
        // let result = client.add_agent("test-agent-uuid", agent_data).await;
        // assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_agent_integration() {
        let config = create_test_config();
        let client = VerifierClient::new_without_version_detection(&config).unwrap();

        // This would require a running verifier service
        // let result = client.get_agent("test-agent-uuid").await;
        // Should handle both Some(agent) and None cases
    }

    #[tokio::test]
    async fn test_list_agents_integration() {
        let config = create_test_config();
        let client = VerifierClient::new_without_version_detection(&config).unwrap();

        // This would require a running verifier service
        // let result = client.list_agents(None).await;
        // assert!(result.is_ok());
        //
        // let agents = result.unwrap();
        // assert!(agents.get("results").is_some());
    }
    */

    // API Version Detection Tests
    mod api_version_tests {
        use super::*;
        use keylime::version::KeylimeRegistrarVersion;
        use serde_json::json;

        #[test]
        fn test_supported_api_versions_constant() {
            // Test that the constant contains expected versions in correct order
            assert_eq!(
                SUPPORTED_API_VERSIONS,
                &["2.0", "2.1", "2.2", "2.3", "3.0"]
            );
            assert!(SUPPORTED_API_VERSIONS.len() >= 2);

            // Verify versions are in ascending order (oldest to newest)
            for i in 1..SUPPORTED_API_VERSIONS.len() {
                let prev: f32 =
                    SUPPORTED_API_VERSIONS[i - 1].parse().unwrap();
                let curr: f32 = SUPPORTED_API_VERSIONS[i].parse().unwrap();
                assert!(
                    prev < curr,
                    "API versions should be in ascending order"
                );
            }
        }

        #[test]
        fn test_unknown_api_version_constant() {
            assert_eq!(UNKNOWN_API_VERSION, "unknown");
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
            let response = response.unwrap();
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
                VerifierClient::new_without_version_detection(&config)
                    .unwrap();

            // Client should start with default API version
            assert_eq!(client.api_version, "2.1");
            assert!(client.supported_api_versions.is_none());
        }

        #[test]
        fn test_api_version_iteration_order() {
            // Test that iter().rev() gives us newest to oldest as expected
            let versions: Vec<&str> =
                SUPPORTED_API_VERSIONS.iter().rev().copied().collect();

            // Should be newest first
            assert_eq!(versions[0], "3.0");
            assert_eq!(versions[1], "2.3");
            assert_eq!(versions[2], "2.2");
            assert_eq!(versions[3], "2.1");
            assert_eq!(versions[4], "2.0");

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
        fn test_version_string_parsing() {
            // Test that our version strings can be parsed as valid version numbers
            for version in SUPPORTED_API_VERSIONS {
                let parsed: Result<f32, _> = version.parse();
                assert!(
                    parsed.is_ok(),
                    "Version string '{version}' should parse as number"
                );

                let num = parsed.unwrap();
                assert!(num >= 1.0, "Version should be >= 1.0");
                assert!(num < 10.0, "Version should be reasonable");
            }
        }

        #[test]
        fn test_client_struct_fields() {
            let config = create_test_config();
            let mut client =
                VerifierClient::new_without_version_detection(&config)
                    .unwrap();

            // Test that we can access and modify the api_version field
            assert_eq!(client.api_version, "2.1");

            client.api_version = "2.0".to_string();
            assert_eq!(client.api_version, "2.0");

            client.api_version = UNKNOWN_API_VERSION.to_string();
            assert_eq!(client.api_version, "unknown");
        }

        #[test]
        fn test_base_url_construction_with_different_versions() {
            let config = create_test_config();
            let mut client =
                VerifierClient::new_without_version_detection(&config)
                    .unwrap();

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
                VerifierClient::new_without_version_detection(&config)
                    .unwrap();

            // Initially should be None
            assert!(client.supported_api_versions.is_none());

            // Simulate setting supported versions (as would happen in detect_api_version)
            client.supported_api_versions =
                Some(vec!["2.0".to_string(), "2.1".to_string()]);

            assert!(client.supported_api_versions.is_some());
            let versions = client.supported_api_versions.unwrap();
            assert_eq!(versions, vec!["2.0", "2.1"]);
        }

        #[test]
        #[allow(clippy::const_is_empty)]
        fn test_version_constants_consistency() {
            // Ensure our constants are consistent with expected patterns
            assert!(!UNKNOWN_API_VERSION.is_empty()); // Known constant value
            assert!(!SUPPORTED_API_VERSIONS.is_empty()); // Known constant value

            // UNKNOWN_API_VERSION should not be in SUPPORTED_API_VERSIONS
            assert!(!SUPPORTED_API_VERSIONS.contains(&UNKNOWN_API_VERSION));

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
                VerifierClient::new_without_version_detection(&config)
                    .unwrap();

            // Test that Debug trait produces reasonable output
            let debug_output = format!("{client:?}");
            assert!(debug_output.contains("VerifierClient"));
            assert!(debug_output.contains("api_version"));
        }

        #[test]
        fn test_version_detection_error_scenarios() {
            // Test error creation for version detection failures
            let no_version_error = KeylimectlError::api_error(
                404,
                "Verifier does not support the /version endpoint".to_string(),
                None,
            );

            assert_eq!(no_version_error.error_code(), "API_ERROR");

            let version_parse_error = KeylimectlError::api_error(
                500,
                "Failed to parse version response from verifier".to_string(),
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

            // Should try 3.0 first, then 2.3, then 2.2, then 2.1, then 2.0
            assert_eq!(attempted_versions[0], "3.0");
            assert_eq!(attempted_versions[1], "2.3");
            assert_eq!(attempted_versions[2], "2.2");
            assert_eq!(attempted_versions[3], "2.1");
            assert_eq!(attempted_versions[4], "2.0");

            // Should try all supported versions
            assert_eq!(
                attempted_versions.len(),
                SUPPORTED_API_VERSIONS.len()
            );
        }
    }
}
