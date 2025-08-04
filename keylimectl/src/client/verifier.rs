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

// API version detection temporarily removed - will be implemented later
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use keylime::resilient_client::ResilientClient;
use log::{debug, warn};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

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
    client: ResilientClient,
    base_url: String,
    api_version: String,
}

impl VerifierClient {
    /// Create a new verifier client
    ///
    /// Initializes a new `VerifierClient` with the provided configuration.
    /// This sets up the HTTP client with TLS configuration, retry logic,
    /// and connection pooling.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing verifier endpoint and TLS settings
    ///
    /// # Returns
    ///
    /// Returns a configured `VerifierClient` or an error if initialization fails.
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
    /// use keylimectl::client::verifier::VerifierClient;
    /// use keylimectl::config::Config;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let client = VerifierClient::new(&config)?;
    /// println!("Verifier client created for {}", config.verifier_base_url());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: &Config) -> Result<Self, KeylimectlError> {
        let base_url = config.verifier_base_url();

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

    /// Auto-detect and set the API version
    #[allow(dead_code)]
    pub async fn detect_api_version(
        &mut self,
    ) -> Result<(), KeylimectlError> {
        // API version detection temporarily disabled
        // Will be implemented in a future version
        Ok(())
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
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::POST, &url, &data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| {
                "Failed to send add agent request to verifier".to_string()
            })?;

        self.handle_response(response).await
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
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get agent request to verifier".to_string()
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
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send delete agent request to verifier".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Reactivate an agent on the verifier
    pub async fn reactivate_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Reactivating agent {agent_uuid} on verifier");

        let url = format!(
            "{}/v{}/agents/{}/reactivate",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::PUT, &url)
            .body("")
            .send()
            .await
            .with_context(|| {
                "Failed to send reactivate agent request to verifier"
                    .to_string()
            })?;

        self.handle_response(response).await
    }

    /// Stop an agent on the verifier
    #[allow(dead_code)]
    pub async fn stop_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Stopping agent {agent_uuid} on verifier");

        let url = format!(
            "{}/v{}/agents/{}/stop",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::PUT, &url)
            .body("")
            .send()
            .await
            .with_context(|| {
                "Failed to send stop agent request to verifier".to_string()
            })?;

        self.handle_response(response).await
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
            format!("{}/v{}/agents/", self.base_url, self.api_version);

        if let Some(vid) = verifier_id {
            url.push_str(&format!("?verifier={vid}"));
        }

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list agents request to verifier".to_string()
            })?;

        self.handle_response(response).await
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
            self.base_url, self.api_version
        );

        if let Some(vid) = verifier_id {
            url.push_str(&format!("&verifier={vid}"));
        }

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send bulk info request to verifier".to_string()
            })?;

        self.handle_response(response).await
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
            self.base_url, self.api_version, policy_name
        );

        let response = self
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

        self.handle_response(response).await
    }

    /// Get a runtime policy
    pub async fn get_runtime_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting runtime policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
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

    /// Update a runtime policy
    pub async fn update_runtime_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating runtime policy {policy_name} on verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
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

        self.handle_response(response).await
    }

    /// Delete a runtime policy
    pub async fn delete_runtime_policy(
        &self,
        policy_name: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting runtime policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send delete runtime policy request to verifier"
                    .to_string()
            })?;

        self.handle_response(response).await
    }

    /// List runtime policies
    pub async fn list_runtime_policies(
        &self,
    ) -> Result<Value, KeylimectlError> {
        debug!("Listing runtime policies on verifier");

        let url =
            format!("{}/v{}/allowlists/", self.base_url, self.api_version);

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list runtime policies request to verifier"
                    .to_string()
            })?;

        self.handle_response(response).await
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
            self.base_url, self.api_version, policy_name
        );

        let response = self
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

        self.handle_response(response).await
    }

    /// Get a measured boot policy
    pub async fn get_mb_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting measured boot policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
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

    /// Update a measured boot policy
    pub async fn update_mb_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating measured boot policy {policy_name} on verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::PUT, &url, &policy_data, None)
            .map_err(KeylimectlError::Json)?
            .send()
            .await
            .with_context(|| "Failed to send update measured boot policy request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// Delete a measured boot policy
    pub async fn delete_mb_policy(
        &self,
        policy_name: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting measured boot policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| "Failed to send delete measured boot policy request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// List measured boot policies
    pub async fn list_mb_policies(&self) -> Result<Value, KeylimectlError> {
        debug!("Listing measured boot policies on verifier");

        let url =
            format!("{}/v{}/mbpolicies/", self.base_url, self.api_version);

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| "Failed to send list measured boot policies request to verifier".to_string())?;

        self.handle_response(response).await
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
    /// Processes HTTP responses from the verifier service, handling both
    /// success and error cases. Converts successful responses to JSON
    /// and transforms HTTP errors into appropriate `KeylimectlError` types.
    ///
    /// # Arguments
    ///
    /// * `response` - HTTP response from the verifier service
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
    /// - Verifier returns an error status code
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
        let result = VerifierClient::new(&config);

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.base_url, "https://127.0.0.1:8881");
        assert_eq!(client.api_version, "2.1");
    }

    #[test]
    fn test_verifier_client_new_with_ipv6() {
        let mut config = create_test_config();
        config.verifier.ip = "::1".to_string();

        let result = VerifierClient::new(&config);
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.base_url, "https://[::1]:8881");
    }

    #[test]
    fn test_verifier_client_new_with_bracketed_ipv6() {
        let mut config = create_test_config();
        config.verifier.ip = "[2001:db8::1]".to_string();

        let result = VerifierClient::new(&config);
        assert!(result.is_ok());

        let client = result.unwrap();
        assert_eq!(client.base_url, "https://[2001:db8::1]:8881");
    }

    #[test]
    fn test_create_http_client_basic() {
        let config = create_test_config();
        let result = VerifierClient::create_http_client(&config);

        assert!(result.is_ok());
        // Basic validation that client was created
        let _client = result.unwrap();
    }

    #[test]
    fn test_create_http_client_with_timeout() {
        let mut config = create_test_config();
        config.client.timeout = 60;

        let result = VerifierClient::create_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_http_client_with_cert_files_nonexistent() {
        let mut config = create_test_config();
        config.tls.client_cert = Some("/nonexistent/cert.pem".to_string());
        config.tls.client_key = Some("/nonexistent/key.pem".to_string());

        let result = VerifierClient::create_http_client(&config);
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
        assert_eq!(config.verifier_base_url(), "https://127.0.0.1:8881");
    }

    #[test]
    fn test_api_version() {
        let config = create_test_config();
        let client = VerifierClient::new(&config).unwrap();

        // Default API version should be 2.1
        assert_eq!(client.api_version, "2.1");
    }

    #[test]
    fn test_base_url_construction() {
        // Test IPv4
        let mut config = create_test_config();
        config.verifier.ip = "192.168.1.100".to_string();
        config.verifier.port = 9001;

        let client = VerifierClient::new(&config).unwrap();
        assert_eq!(client.base_url, "https://192.168.1.100:9001");

        // Test IPv6
        config.verifier.ip = "2001:db8::1".to_string();
        config.verifier.port = 8881;

        let client = VerifierClient::new(&config).unwrap();
        assert_eq!(client.base_url, "https://[2001:db8::1]:8881");
    }

    #[test]
    fn test_client_config_values() {
        let config = create_test_config();
        let client = VerifierClient::new(&config).unwrap();

        // Verify that config values are properly used
        // Note: We can't directly access the internal reqwest client config,
        // but we can verify our config was accepted
        assert_eq!(client.api_version, "2.1");
        assert!(client.base_url.starts_with("https://"));
    }

    #[test]
    fn test_tls_config_no_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = false;

        let result = VerifierClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification disabled
    }

    #[test]
    fn test_tls_config_with_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = true;

        let result = VerifierClient::create_http_client(&config);
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
        let client = VerifierClient::new(&config).unwrap();

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
        let client = VerifierClient::new(&config).unwrap();

        // This would require a running verifier service
        // let result = client.get_agent("test-agent-uuid").await;
        // Should handle both Some(agent) and None cases
    }

    #[tokio::test]
    async fn test_list_agents_integration() {
        let config = create_test_config();
        let client = VerifierClient::new(&config).unwrap();

        // This would require a running verifier service
        // let result = client.list_agents(None).await;
        // assert!(result.is_ok());
        //
        // let agents = result.unwrap();
        // assert!(agents.get("results").is_some());
    }
    */
}
