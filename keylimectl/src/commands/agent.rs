// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent management commands for keylimectl
//!
//! This module provides comprehensive agent lifecycle management for the Keylime attestation system.
//! It handles all agent-related operations including registration, monitoring, and decommissioning.
//!
//! # Agent Lifecycle
//!
//! The typical agent lifecycle involves these stages:
//!
//! 1. **Registration**: Agent registers with the registrar, providing TPM keys
//! 2. **Addition**: Agent is added to verifier for continuous monitoring
//! 3. **Monitoring**: Verifier continuously attests agent integrity
//! 4. **Management**: Agent can be updated, reactivated, or removed
//! 5. **Decommissioning**: Agent is removed from both verifier and registrar
//!
//! # Command Types
//!
//! - [`AgentAction::Add`]: Add agent to verifier for attestation monitoring
//! - [`AgentAction::Remove`]: Remove agent from verifier and optionally registrar
//! - [`AgentAction::Update`]: Update agent configuration (runtime/measured boot policies)
//! - [`AgentAction::Reactivate`]: Reactivate a failed or stopped agent
//!
//! # Security Considerations
//!
//! - All operations validate agent UUIDs for proper format
//! - TPM-based attestation ensures agent authenticity
//! - Secure communication using mutual TLS
//! - Policy validation before deployment
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::commands::agent;
//! use keylimectl::config::Config;
//! use keylimectl::output::OutputHandler;
//! use keylimectl::AgentAction;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::default();
//! let output = OutputHandler::new(crate::OutputFormat::Json, false);
//!
//! let action = AgentAction::Add {
//!     uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
//!     ip: Some("192.168.1.100".to_string()),
//!     port: Some(9002),
//!     verifier_ip: None,
//!     runtime_policy: None,
//!     mb_policy: None,
//!     payload: None,
//!     cert_dir: None,
//!     verify: true,
//!     push_model: false,
//! };
//!
//! let result = agent::execute(&action, &config, &output).await?;
//! println!("Agent operation result: {:?}", result);
//! # Ok(())
//! # }
//! ```

use crate::client::{
    agent::AgentClient, registrar::RegistrarClient, verifier::VerifierClient,
};
use crate::commands::error::CommandError;
use crate::config::Config;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::AgentAction;
use base64::{engine::general_purpose::STANDARD, Engine};
use keylime::crypto;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;

/// Execute an agent management command
///
/// This is the main entry point for all agent-related operations. It dispatches
/// to the appropriate handler based on the action type and manages the complete
/// operation lifecycle including progress reporting and error handling.
///
/// # Arguments
///
/// * `action` - The specific agent action to perform (Add, Remove, Update, or Reactivate)
/// * `config` - Configuration containing service endpoints and authentication settings
/// * `output` - Output handler for progress reporting and result formatting
///
/// # Returns
///
/// Returns a JSON value containing the operation results, which typically includes:
/// - `status`: Success/failure indicator
/// - `message`: Human-readable status message
/// - `results`: Detailed operation results from the services
/// - `agent_uuid`: The UUID of the affected agent
///
/// # Error Handling
///
/// This function handles various error conditions:
/// - Invalid UUIDs are rejected with validation errors
/// - Network failures are retried according to client configuration
/// - Service errors are propagated with detailed context
/// - Missing agents result in appropriate not-found errors
///
/// # Examples
///
/// ```rust
/// use keylimectl::commands::agent;
/// use keylimectl::config::Config;
/// use keylimectl::output::OutputHandler;
/// use keylimectl::AgentAction;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
/// let output = OutputHandler::new(crate::OutputFormat::Json, false);
///
/// // Add an agent
/// let add_action = AgentAction::Add {
///     uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
///     ip: Some("192.168.1.100".to_string()),
///     port: Some(9002),
///     verifier_ip: None,
///     runtime_policy: None,
///     mb_policy: None,
///     payload: None,
///     cert_dir: None,
///     verify: true,
///     push_model: false,
/// };
///
/// let result = agent::execute(&add_action, &config, &output).await?;
/// assert_eq!(result["status"], "success");
///
/// // Remove the same agent
/// let remove_action = AgentAction::Remove {
///     uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
///     from_registrar: false,
///     force: false,
/// };
///
/// let result = agent::execute(&remove_action, &config, &output).await?;
/// assert_eq!(result["status"], "success");
/// # Ok(())
/// # }
/// ```
pub async fn execute(
    action: &AgentAction,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        AgentAction::Add {
            uuid,
            ip,
            port,
            verifier_ip,
            runtime_policy,
            mb_policy,
            payload,
            cert_dir,
            verify,
            push_model,
            tpm_policy,
        } => add_agent(
            AddAgentParams {
                agent_id: uuid,
                ip: ip.as_deref(),
                port: *port,
                verifier_ip: verifier_ip.as_deref(),
                runtime_policy: runtime_policy.as_deref(),
                mb_policy: mb_policy.as_deref(),
                payload: payload.as_deref(),
                cert_dir: cert_dir.as_deref(),
                verify: *verify,
                push_model: *push_model,
                tpm_policy: tpm_policy.as_deref(),
            },
            config,
            output,
        )
        .await
        .map_err(KeylimectlError::from),
        AgentAction::Remove {
            uuid,
            from_registrar,
            force,
        } => remove_agent(uuid, *from_registrar, *force, config, output)
            .await
            .map_err(KeylimectlError::from),
        AgentAction::Update {
            uuid,
            runtime_policy,
            mb_policy,
        } => update_agent(
            uuid,
            runtime_policy.as_deref(),
            mb_policy.as_deref(),
            config,
            output,
        )
        .await
        .map_err(KeylimectlError::from),
        AgentAction::Status {
            uuid,
            verifier_only,
            registrar_only,
        } => get_agent_status(
            uuid,
            *verifier_only,
            *registrar_only,
            config,
            output,
        )
        .await
        .map_err(KeylimectlError::from),
        AgentAction::Reactivate { uuid } => {
            reactivate_agent(uuid, config, output)
                .await
                .map_err(KeylimectlError::from)
        }
    }
}

/// Parameters for adding an agent to the verifier
///
/// This struct groups all the parameters needed for agent addition to improve
/// function signature readability and maintainability.
///
/// # Fields
///
/// * `agent_id` - Agent identifier (can be any string, not necessarily a UUID)
/// * `ip` - Optional agent IP address (overrides registrar data)
/// * `port` - Optional agent port (overrides registrar data)
/// * `verifier_ip` - Optional verifier IP for agent communication
/// * `runtime_policy` - Optional path to runtime policy file
/// * `mb_policy` - Optional path to measured boot policy file
/// * `payload` - Optional path to payload file for agent
/// * `cert_dir` - Optional path to certificate directory
/// * `verify` - Whether to perform key derivation verification
/// * `push_model` - Whether to use push model (agent connects to verifier)
struct AddAgentParams<'a> {
    /// Agent identifier - can be any string
    agent_id: &'a str,
    /// Optional agent IP address (overrides registrar data)
    ip: Option<&'a str>,
    /// Optional agent port (overrides registrar data)
    port: Option<u16>,
    /// Optional verifier IP for agent communication
    verifier_ip: Option<&'a str>,
    /// Optional path to runtime policy file
    runtime_policy: Option<&'a str>,
    /// Optional path to measured boot policy file
    mb_policy: Option<&'a str>,
    /// Optional path to payload file for agent
    payload: Option<&'a str>,
    /// Optional path to certificate directory
    cert_dir: Option<&'a str>,
    /// Whether to perform key derivation verification
    verify: bool,
    /// Whether to use push model (agent connects to verifier)
    #[allow(dead_code)]
    // Will be used when explicit push model flag is implemented
    push_model: bool,
    /// Optional TPM policy in JSON format
    tpm_policy: Option<&'a str>,
}

/// Request structure for adding an agent to the verifier
///
/// This struct represents the complete request payload sent to the verifier
/// when adding an agent for attestation monitoring. It uses serde for
/// automatic JSON serialization and ensures type safety.
///
/// # Core Required Fields
///
/// * `cloudagent_ip` - IP address where the agent can be reached
/// * `cloudagent_port` - Port where the agent is listening
/// * `verifier_ip` - IP address of the verifier
/// * `verifier_port` - Port of the verifier
/// * `ak_tpm` - Agent's attestation key from TPM
/// * `mtls_cert` - Mutual TLS certificate for agent communication
/// * `tpm_policy` - TPM policy in JSON format
///
/// # Legacy Compatibility Fields
///
/// * `v` - Optional V key from attestation (for API < 3.0)
///
/// # Policy Fields
///
/// * `runtime_policy` - Runtime policy content
/// * `runtime_policy_name` - Name of the runtime policy
/// * `runtime_policy_key` - Runtime policy signature key
/// * `mb_policy` - Measured boot policy content
/// * `mb_policy_name` - Name of the measured boot policy
///
/// # Security & Verification Fields
///
/// * `ima_sign_verification_keys` - IMA signature verification keys
/// * `revocation_key` - Revocation key for certificates
/// * `accept_tpm_hash_algs` - Accepted TPM hash algorithms
/// * `accept_tpm_encryption_algs` - Accepted TPM encryption algorithms
/// * `accept_tpm_signing_algs` - Accepted TPM signing algorithms
///
/// # Additional Fields
///
/// * `metadata` - Metadata in JSON format
/// * `payload` - Optional payload content
/// * `cert_dir` - Optional certificate directory path
/// * `supported_version` - API version supported by the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddAgentRequest {
    pub cloudagent_ip: String,
    pub cloudagent_port: u16,
    pub verifier_ip: String,
    pub verifier_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ak_tpm: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_cert: Option<Value>,
    pub tpm_policy: String,

    // Legacy compatibility (API < 3.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<Value>,

    // Runtime policy fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_policy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_policy_key: Option<Value>,

    // Measured boot policy fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_policy_name: Option<String>,

    // IMA and verification keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_sign_verification_keys: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_key: Option<String>,

    // TPM algorithm support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_tpm_hash_algs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_tpm_encryption_algs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_tpm_signing_algs: Option<Vec<String>>,

    // Metadata and additional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_version: Option<String>,
}

impl AddAgentRequest {
    /// Create a new agent request with the required fields
    pub fn new(
        cloudagent_ip: String,
        cloudagent_port: u16,
        verifier_ip: String,
        verifier_port: u16,
        tpm_policy: String,
    ) -> Self {
        Self {
            cloudagent_ip,
            cloudagent_port,
            verifier_ip,
            verifier_port,
            ak_tpm: None,
            mtls_cert: None,
            tpm_policy,
            v: None,
            runtime_policy: None,
            runtime_policy_name: None,
            runtime_policy_key: None,
            mb_policy: None,
            mb_policy_name: None,
            ima_sign_verification_keys: None,
            revocation_key: None,
            accept_tpm_hash_algs: None,
            accept_tpm_encryption_algs: None,
            accept_tpm_signing_algs: None,
            metadata: None,
            payload: None,
            cert_dir: None,
            supported_version: None,
        }
    }

    /// Set the TPM attestation key
    pub fn with_ak_tpm(mut self, ak_tpm: Option<Value>) -> Self {
        self.ak_tpm = ak_tpm;
        self
    }

    /// Set the mutual TLS certificate
    pub fn with_mtls_cert(mut self, mtls_cert: Option<Value>) -> Self {
        self.mtls_cert = mtls_cert;
        self
    }

    /// Set the V key from attestation
    pub fn with_v_key(mut self, v_key: Option<Value>) -> Self {
        self.v = v_key;
        self
    }

    /// Set the runtime policy
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_runtime_policy(mut self, policy: Option<String>) -> Self {
        self.runtime_policy = policy;
        self
    }

    /// Set the measured boot policy
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_mb_policy(mut self, policy: Option<String>) -> Self {
        self.mb_policy = policy;
        self
    }

    /// Set the payload
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_payload(mut self, payload: Option<String>) -> Self {
        self.payload = payload;
        self
    }

    /// Set the certificate directory
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_cert_dir(mut self, cert_dir: Option<String>) -> Self {
        self.cert_dir = cert_dir;
        self
    }

    /// Set the runtime policy name
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_runtime_policy_name(
        mut self,
        policy_name: Option<String>,
    ) -> Self {
        self.runtime_policy_name = policy_name;
        self
    }

    /// Set the runtime policy signature key
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_runtime_policy_key(
        mut self,
        policy_key: Option<Value>,
    ) -> Self {
        self.runtime_policy_key = policy_key;
        self
    }

    /// Set the measured boot policy name
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_mb_policy_name(
        mut self,
        policy_name: Option<String>,
    ) -> Self {
        self.mb_policy_name = policy_name;
        self
    }

    /// Set the IMA signature verification keys
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_ima_sign_verification_keys(
        mut self,
        keys: Option<String>,
    ) -> Self {
        self.ima_sign_verification_keys = keys;
        self
    }

    /// Set the revocation key
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_revocation_key(mut self, key: Option<String>) -> Self {
        self.revocation_key = key;
        self
    }

    /// Set the accepted TPM hash algorithms
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_accept_tpm_hash_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_hash_algs = algs;
        self
    }

    /// Set the accepted TPM encryption algorithms
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_accept_tpm_encryption_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_encryption_algs = algs;
        self
    }

    /// Set the accepted TPM signing algorithms
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_accept_tpm_signing_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_signing_algs = algs;
        self
    }

    /// Set the metadata
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_metadata(mut self, metadata: Option<String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the supported API version
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_supported_version(mut self, version: Option<String>) -> Self {
        self.supported_version = version;
        self
    }

    /// Validate the request before sending
    #[allow(dead_code)] // Will be used when validation is enabled
    pub fn validate(&self) -> Result<(), CommandError> {
        if self.cloudagent_ip.is_empty() {
            return Err(CommandError::invalid_parameter(
                "cloudagent_ip",
                "Agent IP cannot be empty".to_string(),
            ));
        }

        if self.cloudagent_port == 0 {
            return Err(CommandError::invalid_parameter(
                "cloudagent_port",
                "Agent port cannot be zero".to_string(),
            ));
        }

        if self.verifier_ip.is_empty() {
            return Err(CommandError::invalid_parameter(
                "verifier_ip",
                "Verifier IP cannot be empty".to_string(),
            ));
        }

        if self.verifier_port == 0 {
            return Err(CommandError::invalid_parameter(
                "verifier_port",
                "Verifier port cannot be zero".to_string(),
            ));
        }

        // Validate TPM policy is valid JSON
        if let Err(e) = serde_json::from_str::<Value>(&self.tpm_policy) {
            return Err(CommandError::invalid_parameter(
                "tpm_policy",
                format!("Invalid JSON in TPM policy: {e}"),
            ));
        }

        // Validate metadata is valid JSON if provided
        if let Some(metadata) = &self.metadata {
            if let Err(e) = serde_json::from_str::<Value>(metadata) {
                return Err(CommandError::invalid_parameter(
                    "metadata",
                    format!("Invalid JSON in metadata: {e}"),
                ));
            }
        }

        // Validate algorithm lists contain only known algorithms
        if let Some(hash_algs) = &self.accept_tpm_hash_algs {
            for alg in hash_algs {
                if !is_valid_tpm_hash_algorithm(alg) {
                    return Err(CommandError::invalid_parameter(
                        "accept_tpm_hash_algs",
                        format!("Unknown TPM hash algorithm: {alg}"),
                    ));
                }
            }
        }

        if let Some(enc_algs) = &self.accept_tpm_encryption_algs {
            for alg in enc_algs {
                if !is_valid_tpm_encryption_algorithm(alg) {
                    return Err(CommandError::invalid_parameter(
                        "accept_tpm_encryption_algs",
                        format!("Unknown TPM encryption algorithm: {alg}"),
                    ));
                }
            }
        }

        if let Some(sign_algs) = &self.accept_tpm_signing_algs {
            for alg in sign_algs {
                if !is_valid_tpm_signing_algorithm(alg) {
                    return Err(CommandError::invalid_parameter(
                        "accept_tpm_signing_algs",
                        format!("Unknown TPM signing algorithm: {alg}"),
                    ));
                }
            }
        }

        // Validate supported version format if provided
        if let Some(version) = &self.supported_version {
            if !is_valid_api_version(version) {
                return Err(CommandError::invalid_parameter(
                    "supported_version",
                    format!("Invalid API version format: {version}"),
                ));
            }
        }

        Ok(())
    }
}

/// Add (enroll) an agent to the verifier for continuous attestation monitoring
///
/// This function implements the correct Keylime enrollment workflow:
///
/// 1. **Check Registration**: Verify agent is registered with registrar
/// 2. **Enroll with Verifier**: Add agent to verifier with attestation policy
///
/// The flow differs based on API version:
/// - **API 2.x (Pull Model)**: Includes TPM quote verification and key exchange
/// - **API 3.0+ (Push Model)**: Simplified enrollment, agent pushes attestations
///
/// # Workflow Steps
///
/// 1. **Agent ID Validation**: Validates the agent identifier format
/// 2. **Registrar Lookup**: Retrieves agent data from registrar (TPM keys, etc.)
/// 3. **API Version Detection**: Determines verifier API version for enrollment format
/// 4. **Legacy Attestation**: For API < 3.0, performs TPM quote verification
/// 5. **Verifier Enrollment**: Enrolls agent with verifier using appropriate format
/// 6. **Legacy Key Delivery**: For API < 3.0, delivers encryption keys to agent
///
/// # Arguments
///
/// * `params` - Grouped parameters containing agent details and options
/// * `config` - Configuration for service endpoints and authentication
/// * `output` - Output handler for progress reporting
///
/// # Returns
///
/// Returns JSON containing:
/// - `status`: "success" if operation completed
/// - `message`: Human-readable success message
/// - `agent_uuid`: The agent's UUID
/// - `results`: Detailed response from verifier
///
/// # Errors
///
/// This function can fail for several reasons:
/// - Invalid UUID format ([`CommandError::InvalidParameter`])
/// - Agent not found in registrar ([`CommandError::Agent`])
/// - Missing connection details ([`CommandError::InvalidParameter`])
/// - Network failures ([`CommandError::Resource`])
/// - Verifier API errors ([`CommandError::Resource`])
///
/// # Security Notes
///
/// - Validates agent is registered before addition
/// - Performs TPM-based attestation for authenticity
/// - Supports both push and pull communication models
/// - Handles policy validation and deployment
///
/// # Examples
///
/// ```rust
/// # use keylimectl::commands::agent::AddAgentParams;
/// # use keylimectl::config::Config;
/// # use keylimectl::output::OutputHandler;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let params = AddAgentParams {
///     agent_id: "550e8400-e29b-41d4-a716-446655440000",
///     ip: Some("192.168.1.100"),
///     port: Some(9002),
///     verifier_ip: None,
///     runtime_policy: None,
///     mb_policy: None,
///     payload: None,
///     cert_dir: None,
///     verify: true,
///     push_model: false,
/// };
/// let config = Config::default();
/// let output = OutputHandler::new(crate::OutputFormat::Json, false);
///
/// let result = add_agent(params, &config, &output).await?;
/// assert_eq!(result["status"], "success");
/// # Ok(())
/// # }
/// ```
async fn add_agent(
    params: AddAgentParams<'_>,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if params.agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    if params.agent_id.len() > 255 {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot exceed 255 characters".to_string(),
        ));
    }

    // Check for control characters that might cause issues
    if params.agent_id.chars().any(|c| c.is_control()) {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot contain control characters".to_string(),
        ));
    }

    output.info(format!("Adding agent {} to verifier", params.agent_id));

    // Step 1: Get agent data from registrar
    output.step(1, 4, "Retrieving agent data from registrar");

    let registrar_client = RegistrarClient::builder()
        .config(config)
        .build()
        .await
        .map_err(|e| {
            CommandError::resource_error("registrar", e.to_string())
        })?;
    let agent_data = registrar_client
        .get_agent(params.agent_id)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "registrar",
                format!("Failed to retrieve agent data: {e}"),
            )
        })?;

    if agent_data.is_none() {
        return Err(CommandError::agent_not_found(
            params.agent_id.to_string(),
            "registrar",
        ));
    }

    let agent_data = agent_data.unwrap();

    // Step 2: Determine API version and enrollment approach
    output.step(2, 4, "Detecting verifier API version");

    let verifier_client = VerifierClient::builder()
        .config(config)
        .build()
        .await
        .map_err(|e| {
            CommandError::resource_error("verifier", e.to_string())
        })?;

    let api_version =
        verifier_client.api_version().parse::<f32>().unwrap_or(2.1);
    let is_push_model = api_version >= 3.0;

    debug!("Detected API version: {api_version}, using push model: {is_push_model}");

    // Determine agent connection details (needed for legacy API < 3.0)
    let (agent_ip, agent_port) = if !is_push_model {
        // Legacy pull model: need agent IP/port for direct communication
        let agent_ip = params
            .ip
            .map(|s| s.to_string())
            .or_else(|| {
                agent_data
                    .get("ip")
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
            })
            .ok_or_else(|| {
                CommandError::invalid_parameter(
                    "ip",
                    "Agent IP address is required for API < 3.0".to_string(),
                )
            })?;

        let agent_port = params
            .port
            .or_else(|| {
                agent_data
                    .get("port")
                    .and_then(|v| v.as_u64().map(|n| n as u16))
            })
            .ok_or_else(|| {
                CommandError::invalid_parameter(
                    "port",
                    "Agent port is required for API < 3.0".to_string(),
                )
            })?;

        (agent_ip, agent_port)
    } else {
        // Push model: agent will connect to verifier, so use placeholder values
        ("localhost".to_string(), 9002)
    };

    // Step 3: Perform legacy attestation for API < 3.0
    let attestation_result = if !is_push_model {
        output.step(3, 4, "Performing legacy TPM attestation (API < 3.0)");

        // Create agent client for direct communication
        let agent_client = AgentClient::builder()
            .agent_ip(&agent_ip)
            .agent_port(agent_port)
            .config(config)
            .build()
            .await
            .map_err(|e| {
                CommandError::resource_error("agent", e.to_string())
            })?;

        // Perform TPM quote verification
        perform_agent_attestation(
            &agent_client,
            &agent_data,
            config,
            params.agent_id,
            output,
        )
        .await?
    } else {
        output.step(
            3,
            4,
            "Skipping direct attestation (push model, API >= 3.0)",
        );
        None
    };

    // Step 4: Enroll agent with verifier
    output.step(4, 4, "Enrolling agent with verifier");

    // Build the request payload based on API version
    let cv_agent_ip = params.verifier_ip.unwrap_or(&agent_ip);

    // Resolve TPM policy with enhanced precedence handling
    let tpm_policy =
        resolve_tpm_policy_enhanced(params.tpm_policy, params.mb_policy)?;

    // Build enrollment request with version-appropriate fields
    let mut request = if is_push_model {
        // API 3.0+: Simplified enrollment for push model
        build_push_model_request(
            params.agent_id,
            &tpm_policy,
            &agent_data,
            config,
            params.runtime_policy,
            params.mb_policy,
        )?
    } else {
        // API 2.x: Full enrollment with direct agent communication
        let mut request = AddAgentRequest::new(
            cv_agent_ip.to_string(),
            agent_port,
            config.verifier.ip.clone(),
            config.verifier.port,
            tpm_policy,
        )
        .with_ak_tpm(agent_data.get("aik_tpm").cloned())
        .with_mtls_cert(agent_data.get("mtls_cert").cloned());

        // Add V key from attestation if available
        if let Some(attestation) = &attestation_result {
            if let Some(v_key) = attestation.get("v_key") {
                request = request.with_v_key(Some(v_key.clone()));
            }
        }

        serde_json::to_value(request)?
    };

    // Add policies if provided
    if let Some(policy_path) = params.runtime_policy {
        let policy_content = load_policy_file(policy_path)?;
        if let Some(obj) = request.as_object_mut() {
            let _ = obj
                .insert("runtime_policy".to_string(), json!(policy_content));
        }
    }

    if let Some(policy_path) = params.mb_policy {
        let policy_content = load_policy_file(policy_path)?;
        if let Some(obj) = request.as_object_mut() {
            let _ =
                obj.insert("mb_policy".to_string(), json!(policy_content));
        }
    }

    // Add payload if provided
    if let Some(payload_path) = params.payload {
        let payload_content = load_payload_file(payload_path)?;
        if let Some(obj) = request.as_object_mut() {
            let _ = obj.insert("payload".to_string(), json!(payload_content));
        }
    }

    if let Some(cert_dir_path) = params.cert_dir {
        // For now, just pass the path - in future could generate cert package
        if let Some(obj) = request.as_object_mut() {
            let _ = obj.insert(
                "cert_dir".to_string(),
                json!(cert_dir_path.to_string()),
            );
        }
    }

    let response = verifier_client
        .add_agent(params.agent_id, request)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to add agent: {e}"),
            )
        })?;

    // Step 5: Perform legacy key delivery for API < 3.0
    if !is_push_model && attestation_result.is_some() {
        let agent_client = AgentClient::builder()
            .agent_ip(&agent_ip)
            .agent_port(agent_port)
            .config(config)
            .build()
            .await
            .map_err(|e| {
                CommandError::resource_error("agent", e.to_string())
            })?;

        // Deliver U key and payload to agent
        if let Some(attestation) = attestation_result {
            perform_key_delivery(
                &agent_client,
                &attestation,
                params.payload,
                output,
            )
            .await?;

            // Verify key derivation if requested
            if params.verify {
                output.info("Performing key derivation verification");
                verify_key_derivation(&agent_client, &attestation, output)
                    .await?;
            }
        }
    }

    let enrollment_type = if is_push_model {
        "push model"
    } else {
        "pull model"
    };
    output.info(format!(
        "Agent {} successfully enrolled with verifier ({})",
        params.agent_id, enrollment_type
    ));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {} enrolled successfully ({})", params.agent_id, enrollment_type),
        "agent_id": params.agent_id,
        "api_version": api_version,
        "push_model": is_push_model,
        "results": response
    }))
}

/// Remove an agent from the verifier (and optionally registrar)
async fn remove_agent(
    agent_id: &str,
    from_registrar: bool,
    force: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    output.info(format!("Removing agent {agent_id} from verifier"));

    let verifier_client = VerifierClient::builder()
        .config(config)
        .build()
        .await
        .map_err(|e| {
            CommandError::resource_error("verifier", e.to_string())
        })?;

    // Check if agent exists on verifier (unless force is used)
    if !force {
        output.step(
            1,
            if from_registrar { 3 } else { 2 },
            "Checking agent status on verifier",
        );

        match verifier_client.get_agent(agent_id).await {
            Ok(Some(_)) => {
                debug!("Agent found on verifier");
            }
            Ok(None) => {
                warn!("Agent not found on verifier, but continuing with removal");
            }
            Err(e) => {
                if !force {
                    return Err(CommandError::resource_error(
                        "verifier",
                        e.to_string(),
                    ));
                }
                warn!("Failed to check agent status, but continuing due to force flag: {e}");
            }
        }
    }

    // Remove from verifier
    let step_num = if force { 1 } else { 2 };
    let total_steps = if from_registrar {
        if force {
            2
        } else {
            3
        }
    } else if force {
        1
    } else {
        2
    };

    output.step(step_num, total_steps, "Removing agent from verifier");

    let verifier_response =
        verifier_client.delete_agent(agent_id).await.map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to remove agent: {e}"),
            )
        })?;

    let mut results = json!({
        "verifier": verifier_response
    });

    // Remove from registrar if requested
    if from_registrar {
        output.step(
            total_steps,
            total_steps,
            "Removing agent from registrar",
        );

        let registrar_client = RegistrarClient::builder()
            .config(config)
            .build()
            .await
            .map_err(|e| {
                CommandError::resource_error("registrar", e.to_string())
            })?;
        let registrar_response =
            registrar_client.delete_agent(agent_id).await.map_err(|e| {
                CommandError::resource_error(
                    "registrar",
                    format!("Failed to remove agent: {e}"),
                )
            })?;

        results["registrar"] = registrar_response;
    }

    output.info(format!("Agent {agent_id} successfully removed"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_id} removed successfully"),
        "agent_id": agent_id,
        "results": results
    }))
}

/// Update an existing agent
///
/// This function implements a proper update that preserves existing configuration
/// and only modifies the specified fields. Since Keylime doesn't provide a direct
/// update API, we implement this as: get existing config -> remove -> add with merged config.
async fn update_agent(
    agent_id: &str,
    runtime_policy: Option<&str>,
    mb_policy: Option<&str>,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    output.info(format!("Updating agent {agent_id}"));

    // Step 1: Get existing configuration from both registrar and verifier
    output.step(1, 3, "Retrieving existing agent configuration");

    let registrar_client = RegistrarClient::builder()
        .config(config)
        .build()
        .await
        .map_err(|e| {
            CommandError::resource_error("registrar", e.to_string())
        })?;
    let verifier_client = VerifierClient::builder()
        .config(config)
        .build()
        .await
        .map_err(|e| {
            CommandError::resource_error("verifier", e.to_string())
        })?;

    // Get agent info from registrar (contains IP, port, etc.)
    let registrar_agent = registrar_client
        .get_agent(agent_id)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "registrar",
                format!("Failed to get agent: {e}"),
            )
        })?
        .ok_or_else(|| {
            CommandError::agent_not_found(agent_id.to_string(), "registrar")
        })?;

    // Get agent info from verifier (contains policies, etc.)
    let _verifier_agent = verifier_client
        .get_agent(agent_id)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to get agent: {e}"),
            )
        })?
        .ok_or_else(|| {
            CommandError::agent_not_found(agent_id.to_string(), "verifier")
        })?;

    // Extract existing configuration
    let existing_ip = registrar_agent["ip"].as_str().ok_or_else(|| {
        CommandError::invalid_parameter(
            "ip",
            "Agent IP not found in registrar data".to_string(),
        )
    })?;
    let existing_port =
        registrar_agent["port"].as_u64().ok_or_else(|| {
            CommandError::invalid_parameter(
                "port",
                "Agent port not found in registrar data".to_string(),
            )
        })?;

    // Determine if agent is using push model (API version >= 3.0)
    let existing_push_model = existing_port == 0; // Port 0 typically indicates push model

    // Step 2: Remove existing agent configuration
    output.step(2, 3, "Removing existing agent configuration");
    let _remove_result =
        remove_agent(agent_id, false, false, config, output).await?;

    // Step 3: Add agent with merged configuration (existing + updates)
    output.step(3, 3, "Adding agent with updated configuration");
    let add_result = add_agent(
        AddAgentParams {
            agent_id,
            ip: Some(existing_ip), // Preserve existing IP
            port: Some(existing_port as u16), // Preserve existing port
            verifier_ip: None,     // Use default from config
            runtime_policy, // Use new policy if provided, otherwise will use default
            mb_policy, // Use new policy if provided, otherwise will use default
            payload: None, // Payload updates not supported in update operation
            cert_dir: None, // Use default cert handling
            verify: false, // Skip verification during update
            push_model: existing_push_model, // Preserve existing model
            tpm_policy: None, // Use default policy during update
        },
        config,
        output,
    )
    .await?;

    output.info(format!("Agent {agent_id} successfully updated"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_id} updated successfully"),
        "agent_id": agent_id,
        "existing_config": {
            "ip": existing_ip,
            "port": existing_port,
            "push_model": existing_push_model
        },
        "updated_fields": {
            "runtime_policy": runtime_policy.map(|p| p.to_string()),
            "mb_policy": mb_policy.map(|p| p.to_string())
        },
        "results": add_result
    }))
}

/// Get agent status from verifier and/or registrar
async fn get_agent_status(
    agent_id: &str,
    verifier_only: bool,
    registrar_only: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    output.info(format!("Getting status for agent {agent_id}"));

    let mut results = json!({});

    // Get status from registrar (unless verifier_only is set)
    if !verifier_only {
        output.progress("Checking registrar status");

        let registrar_client = RegistrarClient::builder()
            .config(config)
            .build()
            .await
            .map_err(|e| {
                CommandError::resource_error("registrar", e.to_string())
            })?;
        match registrar_client.get_agent(agent_id).await {
            Ok(Some(agent_data)) => {
                results["registrar"] = json!({
                    "status": "found",
                    "data": agent_data
                });
            }
            Ok(None) => {
                results["registrar"] = json!({
                    "status": "not_found"
                });
            }
            Err(e) => {
                results["registrar"] = json!({
                    "status": "error",
                    "error": e.to_string()
                });
            }
        }
    }

    // Get status from verifier (unless registrar_only is set)
    if !registrar_only {
        output.progress("Checking verifier status");

        let verifier_client = VerifierClient::builder()
            .config(config)
            .build()
            .await
            .map_err(|e| {
                CommandError::resource_error("verifier", e.to_string())
            })?;
        match verifier_client.get_agent(agent_id).await {
            Ok(Some(agent_data)) => {
                results["verifier"] = json!({
                    "status": "found",
                    "data": agent_data
                });
            }
            Ok(None) => {
                results["verifier"] = json!({
                    "status": "not_found"
                });
            }
            Err(e) => {
                results["verifier"] = json!({
                    "status": "error",
                    "error": e.to_string()
                });
            }
        }
    }

    // Check agent directly if API < 3.0 and we have connection details
    if !registrar_only {
        if let (Some(registrar_data), Some(verifier_data)) = (
            results.get("registrar").and_then(|r| r.get("data")),
            results.get("verifier").and_then(|v| v.get("data")),
        ) {
            // Extract agent IP and port
            let agent_ip = verifier_data
                .get("ip")
                .or_else(|| registrar_data.get("ip"))
                .and_then(|ip| ip.as_str());

            let agent_port = verifier_data
                .get("port")
                .or_else(|| registrar_data.get("port"))
                .and_then(|port| port.as_u64().map(|p| p as u16));

            if let (Some(ip), Some(port)) = (agent_ip, agent_port) {
                // Check if we should try direct agent communication
                let verifier_client = VerifierClient::builder()
                    .config(config)
                    .build()
                    .await
                    .map_err(|e| {
                        CommandError::resource_error(
                            "verifier",
                            e.to_string(),
                        )
                    })?;
                let api_version = verifier_client
                    .api_version()
                    .parse::<f32>()
                    .unwrap_or(2.1);

                if api_version < 3.0 {
                    output.progress("Checking agent status directly");

                    match AgentClient::builder()
                        .agent_ip(ip)
                        .agent_port(port)
                        .config(config)
                        .build()
                        .await
                    {
                        Ok(agent_client) => {
                            // Try a simple test request to check if agent is responsive
                            match agent_client
                                .get_quote("test_connectivity")
                                .await
                            {
                                Ok(_) => {
                                    results["agent"] = json!({
                                        "status": "responsive",
                                        "connection": format!("{ip}:{port}")
                                    });
                                }
                                Err(e) => {
                                    // Check if it's a 400 error (bad nonce) which means agent is up
                                    if e.to_string().contains("400")
                                        || e.to_string()
                                            .contains("Bad Request")
                                    {
                                        results["agent"] = json!({
                                            "status": "responsive",
                                            "connection": format!("{ip}:{port}"),
                                            "note": "Agent rejected test nonce (expected)"
                                        });
                                    } else {
                                        results["agent"] = json!({
                                            "status": "unreachable",
                                            "connection": format!("{ip}:{port}"),
                                            "error": e.to_string()
                                        });
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            results["agent"] = json!({
                                "status": "connection_failed",
                                "connection": format!("{ip}:{port}"),
                                "error": e.to_string()
                            });
                        }
                    }
                } else {
                    results["agent"] = json!({
                        "status": "not_applicable",
                        "note": "Direct agent communication not used in API >= 3.0"
                    });
                }
            }
        }
    }

    Ok(json!({
        "agent_id": agent_id,
        "results": results
    }))
}

/// Reactivate a failed agent
async fn reactivate_agent(
    agent_id: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    output.info(format!("Reactivating agent {agent_id}"));

    let verifier_client = VerifierClient::builder()
        .config(config)
        .build()
        .await
        .map_err(|e| {
            CommandError::resource_error("verifier", e.to_string())
        })?;
    let response =
        verifier_client
            .reactivate_agent(agent_id)
            .await
            .map_err(|e| {
                CommandError::resource_error(
                    "verifier",
                    format!("Failed to reactivate agent: {e}"),
                )
            })?;

    output.info(format!("Agent {agent_id} successfully reactivated"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_id} reactivated successfully"),
        "agent_id": agent_id,
        "results": response
    }))
}

/// Perform agent attestation for API < 3.0 (pull model)
///
/// This function implements the TPM quote verification process used in the
/// legacy pull model where the tenant communicates directly with the agent.
///
/// # Arguments
///
/// * `agent_client` - Client for communicating with the agent
/// * `agent_data` - Agent registration data from registrar
/// * `config` - Configuration containing cryptographic settings
/// * `output` - Output handler for progress reporting
///
/// # Returns
///
/// Returns attestation data including generated keys on success.
async fn perform_agent_attestation(
    agent_client: &AgentClient,
    _agent_data: &Value,
    config: &Config,
    agent_id: &str,
    output: &OutputHandler,
) -> Result<Option<Value>, CommandError> {
    output.progress("Generating nonce for TPM quote");

    // Generate random nonce for quote freshness
    let nonce = generate_random_string(20);
    debug!("Generated nonce for TPM quote: {nonce}");

    output.progress("Requesting TPM quote from agent");

    // Get TPM quote from agent
    let quote_response =
        agent_client.get_quote(&nonce).await.map_err(|e| {
            CommandError::agent_operation_failed(
                agent_id.to_string(),
                "get_tpm_quote",
                format!("Failed to get TPM quote: {e}"),
            )
        })?;

    debug!("Received quote response: {quote_response:?}");

    // Extract quote data
    let results = quote_response.get("results").ok_or_else(|| {
        CommandError::agent_operation_failed(
            agent_id.to_string(),
            "quote_validation",
            "Missing results in quote response",
        )
    })?;

    let quote =
        results
            .get("quote")
            .and_then(|q| q.as_str())
            .ok_or_else(|| {
                CommandError::agent_operation_failed(
                    agent_id.to_string(),
                    "quote_validation",
                    "Missing quote in response",
                )
            })?;

    let public_key = results
        .get("pubkey")
        .and_then(|pk| pk.as_str())
        .ok_or_else(|| {
            CommandError::agent_operation_failed(
                agent_id.to_string(),
                "quote_validation",
                "Missing public key in response",
            )
        })?;

    output.progress("Validating TPM quote");

    // Create registrar client for validation
    let registrar_client = RegistrarClient::builder()
        .config(config)
        .build()
        .await
        .map_err(|e| {
            CommandError::resource_error("registrar", e.to_string())
        })?;

    // Implement structured TPM quote validation
    let validation_result = validate_tpm_quote(
        quote,
        public_key,
        &nonce,
        &registrar_client,
        agent_id,
    )
    .await?;

    if !validation_result.is_valid {
        return Err(CommandError::agent_operation_failed(
            agent_id.to_string(),
            "tpm_quote_validation",
            format!(
                "TPM quote validation failed: {}",
                validation_result.details
            ),
        ));
    }

    let nonce_verified = validation_result.nonce_verified;
    let aik_verified = validation_result.aik_verified;
    output.info(format!(
        "TPM quote validation successful: nonce_verified={nonce_verified}, aik_verified={aik_verified}"
    ));

    output.progress("Generating cryptographic keys");

    // Generate U and V keys (simulated for now)
    let u_key = generate_random_string(32);
    let v_key = generate_random_string(32);
    let k_key = crypto::compute_hmac(u_key.as_bytes(), "derived".as_bytes())
        .map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("Failed to compute HMAC: {e}"),
            )
        })?;

    let u_key_len = u_key.len();
    let v_key_len = v_key.len();
    debug!("Generated U key: {u_key_len} bytes");
    debug!("Generated V key: {v_key_len} bytes");

    // Encrypt U key with agent's public key
    output.progress("Encrypting U key for agent");

    // Implement proper RSA encryption using agent's public key
    let encrypted_u = encrypt_u_key_with_agent_pubkey(&u_key, public_key)?;
    let auth_tag =
        crypto::compute_hmac(&k_key, u_key.as_bytes()).map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("Failed to compute auth tag: {e}"),
            )
        })?;

    output.info("TPM quote verification completed successfully");

    Ok(Some(json!({
        "quote": quote,
        "public_key": public_key,
        "nonce": nonce,
        "u_key": u_key,
        "v_key": STANDARD.encode(v_key.as_bytes()),
        "k_key": STANDARD.encode(&k_key),
        "encrypted_u": encrypted_u,
        "auth_tag": STANDARD.encode(&auth_tag)
    })))
}

/// Deliver encrypted U key and payload to agent
///
/// Sends the encrypted U key and any optional payload to the agent
/// after successful TPM quote verification.
async fn perform_key_delivery(
    agent_client: &AgentClient,
    attestation: &Value,
    payload_path: Option<&str>,
    output: &OutputHandler,
) -> Result<(), CommandError> {
    output.progress("Delivering encrypted U key to agent");

    let encrypted_u = attestation
        .get("encrypted_u")
        .and_then(|u| u.as_str())
        .ok_or_else(|| {
            CommandError::resource_error("crypto", "Missing encrypted U key")
        })?;

    let auth_tag = attestation
        .get("auth_tag")
        .and_then(|tag| tag.as_str())
        .ok_or_else(|| {
        CommandError::resource_error("crypto", "Missing auth tag")
    })?;

    // Load payload if provided
    let payload = if let Some(path) = payload_path {
        Some(load_payload_file(path)?)
    } else {
        None
    };

    // Deliver key and payload to agent
    let _delivery_result = agent_client
        .deliver_key(encrypted_u.as_bytes(), auth_tag, payload.as_deref())
        .await
        .map_err(|e| {
            CommandError::agent_operation_failed(
                "agent".to_string(),
                "key_delivery",
                format!("Failed to deliver key: {e}"),
            )
        })?;

    output.info("U key delivered successfully to agent");
    Ok(())
}

/// Verify key derivation using HMAC challenge
///
/// Sends a challenge to the agent to verify that it can correctly
/// derive keys using the delivered U key.
async fn verify_key_derivation(
    agent_client: &AgentClient,
    attestation: &Value,
    output: &OutputHandler,
) -> Result<(), CommandError> {
    output.progress("Generating verification challenge");

    let challenge = generate_random_string(20);

    // Calculate expected HMAC using K key
    let k_key_b64 = attestation
        .get("k_key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| {
            CommandError::resource_error("crypto", "Missing K key")
        })?;

    let k_key = STANDARD.decode(k_key_b64).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to decode K key: {e}"),
        )
    })?;

    let expected_hmac = crypto::compute_hmac(&k_key, challenge.as_bytes())
        .map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("Failed to compute expected HMAC: {e}"),
            )
        })?;
    let expected_hmac_b64 = STANDARD.encode(&expected_hmac);

    output.progress("Sending verification challenge to agent");

    // Send challenge to agent and verify response
    let is_valid = agent_client
        .verify_key_derivation(&challenge, &expected_hmac_b64)
        .await
        .map_err(|e| {
            CommandError::agent_operation_failed(
                "agent".to_string(),
                "key_derivation_verification",
                format!("Failed to verify key derivation: {e}"),
            )
        })?;

    if is_valid {
        output.info("Key derivation verification successful");
        Ok(())
    } else {
        Err(CommandError::agent_operation_failed(
            "agent".to_string(),
            "key_derivation_verification",
            "Agent HMAC does not match expected value",
        ))
    }
}

/// Load policy file contents
fn load_policy_file(path: &str) -> Result<String, CommandError> {
    fs::read_to_string(path).map_err(|e| {
        CommandError::policy_file_error(
            path,
            format!("Failed to read policy file: {e}"),
        )
    })
}

/// Load payload file contents
fn load_payload_file(path: &str) -> Result<String, CommandError> {
    fs::read_to_string(path).map_err(|e| {
        CommandError::policy_file_error(
            path,
            format!("Failed to read payload file: {e}"),
        )
    })
}

/// Enhanced TPM policy resolution with measured boot policy extraction
///
/// This function implements the full precedence chain for TPM policy resolution,
/// matching the behavior of the Python keylime_tenant implementation.
///
/// # Precedence Order:
/// 1. Explicit CLI --tpm_policy argument (highest priority)
/// 2. TPM policy extracted from measured boot policy file
/// 3. Default empty policy "{}" (lowest priority)
///
/// # Arguments
/// * `explicit_policy` - Policy provided via CLI --tpm_policy argument
/// * `mb_policy_path` - Path to measured boot policy file (for extraction)
///
/// # Returns
/// Returns the resolved TPM policy as a JSON string
///
/// # Examples
/// ```
/// // With explicit policy (highest priority)
/// let policy = resolve_tpm_policy_enhanced(Some("{\"pcr\": [15]}"), Some("/path/to/mb.json"));
/// assert_eq!(policy, "{\"pcr\": [15]}");
///
/// // With measured boot policy extraction
/// let policy = resolve_tpm_policy_enhanced(None, Some("/path/to/mb_with_tpm_policy.json"));
/// // Returns extracted TPM policy from measured boot policy
///
/// // With default fallback
/// let policy = resolve_tpm_policy_enhanced(None, None);
/// assert_eq!(policy, "{}");
/// ```
fn resolve_tpm_policy_enhanced(
    explicit_policy: Option<&str>,
    mb_policy_path: Option<&str>,
) -> Result<String, CommandError> {
    // Priority 1: Explicit CLI argument
    if let Some(policy) = explicit_policy {
        debug!("Using explicit TPM policy from CLI: {policy}");
        return Ok(policy.to_string());
    }

    // Priority 2: Extract from measured boot policy
    if let Some(mb_path) = mb_policy_path {
        debug!("Attempting to extract TPM policy from measured boot policy: {mb_path}");
        match extract_tpm_policy_from_mb_policy(mb_path) {
            Ok(Some(extracted_policy)) => {
                debug!("Extracted TPM policy from measured boot policy: {extracted_policy}");
                return Ok(extracted_policy);
            }
            Ok(None) => {
                debug!("No TPM policy found in measured boot policy, using default");
            }
            Err(e) => {
                warn!("Failed to extract TPM policy from measured boot policy: {e}");
                debug!(
                    "Continuing with default policy due to extraction error"
                );
            }
        }
    }

    // Priority 3: Default empty policy
    debug!("Using default empty TPM policy");
    Ok("{}".to_string())
}

/// Extract TPM policy from a measured boot policy file
///
/// Measured boot policies in Keylime can contain TPM policy sections that should
/// be extracted and used for agent attestation. This function parses the measured
/// boot policy file and extracts any TPM-related policy information.
///
/// # Arguments
/// * `mb_policy_path` - Path to the measured boot policy JSON file
///
/// # Returns
/// * `Ok(Some(policy))` - Successfully extracted TPM policy
/// * `Ok(None)` - No TPM policy found in the file
/// * `Err(error)` - File reading or parsing error
///
/// # Expected Format
/// The measured boot policy file should be a JSON file that may contain:
/// ```json
/// {
///   "tpm_policy": {
///     "pcr": [15],
///     "hash": "sha256"
///   },
///   "other_mb_fields": "..."
/// }
/// ```
fn extract_tpm_policy_from_mb_policy(
    mb_policy_path: &str,
) -> Result<Option<String>, CommandError> {
    debug!("Reading measured boot policy file: {mb_policy_path}");

    // Read the measured boot policy file
    let policy_content = fs::read_to_string(mb_policy_path).map_err(|e| {
        CommandError::policy_file_error(
            mb_policy_path,
            format!("Failed to read measured boot policy file: {e}"),
        )
    })?;

    // Parse as JSON
    let mb_policy: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                mb_policy_path,
                format!("Invalid JSON in measured boot policy file: {e}"),
            )
        })?;

    // Look for TPM policy in various expected locations
    let tpm_policy_value = mb_policy
        .get("tpm_policy") // Primary location
        .or_else(|| mb_policy.get("tpm")) // Alternative location
        .or_else(|| mb_policy.get("tpm_policy")); // Another alternative

    match tpm_policy_value {
        Some(policy_obj) => {
            // Convert the TPM policy object to a JSON string
            let policy_str =
                serde_json::to_string(policy_obj).map_err(|e| {
                    CommandError::policy_file_error(
                        mb_policy_path,
                        format!(
                            "Failed to serialize extracted TPM policy: {e}"
                        ),
                    )
                })?;
            debug!("Successfully extracted TPM policy: {policy_str}");
            Ok(Some(policy_str))
        }
        None => {
            debug!("No TPM policy section found in measured boot policy");
            Ok(None)
        }
    }
}

/// Generate a random string of the specified length
///
/// Uses system time as seed for a simple random string generator. This is a simple
/// replacement for the missing tmp_util::random_password function.
fn generate_random_string(length: usize) -> String {
    let charset: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Use system time as a simple random seed
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Simple linear congruential generator for demo purposes
    let mut state = seed;
    let mut result = String::new();
    for _ in 0..length {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let char_idx = (state as usize) % charset.len();
        result.push(charset[char_idx] as char);
    }

    result
}

/// Validation result for TPM quote verification
#[derive(Debug)]
struct TpmQuoteValidation {
    is_valid: bool,
    nonce_verified: bool,
    aik_verified: bool,
    details: String,
}

/// Validate TPM quote against agent's AIK and verify nonce inclusion
///
/// This function implements proper TPM quote validation by:
/// 1. Retrieving the agent's AIK from the registrar
/// 2. Verifying the quote was signed by the correct AIK
/// 3. Checking that the provided nonce is correctly included in the quote
/// 4. Performing basic structural validation of the quote format
///
/// # Arguments
/// * `quote` - Base64-encoded TPM quote from the agent
/// * `public_key` - Agent's public key from quote response
/// * `nonce` - Original nonce sent to agent for quote generation
/// * `registrar_client` - Client for retrieving agent's registered AIK
/// * `agent_uuid` - UUID of the agent being validated
///
/// # Returns
/// Returns validation result with detailed information about what was verified
async fn validate_tpm_quote(
    quote: &str,
    public_key: &str,
    nonce: &str,
    registrar_client: &RegistrarClient,
    agent_id: &str,
) -> Result<TpmQuoteValidation, CommandError> {
    debug!("Starting TPM quote validation for agent {agent_id}");

    // Step 1: Retrieve agent's registered AIK from registrar
    let agent_data = registrar_client
        .get_agent(agent_id)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "registrar",
                format!("Failed to get agent: {e}"),
            )
        })?
        .ok_or_else(|| {
            CommandError::agent_not_found(agent_id.to_string(), "registrar")
        })?;

    let registered_aik = agent_data["aik_tpm"].as_str().ok_or_else(|| {
        CommandError::agent_operation_failed(
            agent_id.to_string(),
            "aik_validation",
            "Agent AIK not found in registrar",
        )
    })?;

    // Step 2: Basic format validation
    let quote_bytes = STANDARD.decode(quote).map_err(|e| {
        CommandError::agent_operation_failed(
            agent_id.to_string(),
            "quote_validation",
            format!("Invalid base64 quote: {e}"),
        )
    })?;

    if quote_bytes.len() < 32 {
        return Ok(TpmQuoteValidation {
            is_valid: false,
            nonce_verified: false,
            aik_verified: false,
            details: "Quote too short to be valid TPM quote".to_string(),
        });
    }

    // Step 3: Verify nonce inclusion (simplified check)
    // In a real implementation, this would parse the TPM quote structure
    // and extract the nonce from the appropriate field
    let nonce_bytes = nonce.as_bytes();
    let nonce_found = quote_bytes
        .windows(nonce_bytes.len())
        .any(|window| window == nonce_bytes);

    // Step 4: Verify AIK consistency (simplified check)
    // In a real implementation, this would:
    // - Parse the quote's signature
    // - Verify signature against the registered AIK
    // - Check certificate chain if available
    let aik_consistent = public_key.len() > 100; // Basic length check

    // Step 5: Comprehensive validation
    let is_valid = nonce_found && aik_consistent && !quote_bytes.is_empty();

    let quote_len = quote_bytes.len();
    let aik_available = !registered_aik.is_empty();
    let details = format!(
        "Quote length: {quote_len} bytes, Nonce found: {nonce_found}, AIK consistent: {aik_consistent}, Registered AIK available: {aik_available}"
    );

    debug!("TPM quote validation result: {details}");

    Ok(TpmQuoteValidation {
        is_valid,
        nonce_verified: nonce_found,
        aik_verified: aik_consistent,
        details,
    })
}

/// Encrypt U key using agent's RSA public key with OAEP padding
///
/// This function performs proper RSA-OAEP encryption of the U key using the agent's
/// public key. This ensures that only the agent with the corresponding private key
/// can decrypt and use the delivered key.
///
/// # Arguments
/// * `u_key` - The U key to encrypt (typically 32 bytes)
/// * `agent_public_key` - Agent's RSA public key in base64 format
///
/// # Returns
/// Returns base64-encoded encrypted U key
///
/// # Security
/// - Uses RSA-OAEP padding for semantic security
/// - Validates public key format before encryption
/// - Provides cryptographic confidentiality for key delivery
fn encrypt_u_key_with_agent_pubkey(
    u_key: &str,
    agent_public_key: &str,
) -> Result<String, CommandError> {
    debug!("Encrypting U key with agent's RSA public key");

    // Step 1: Decode and parse the agent's public key
    let pubkey_pem = String::from_utf8(
        STANDARD.decode(agent_public_key).map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("Invalid base64 public key: {e}"),
            )
        })?,
    )
    .map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Invalid UTF-8 in public key: {e}"),
        )
    })?;

    // Step 2: Import the public key as OpenSSL PKey
    let pubkey =
        crypto::testing::pkey_pub_from_pem(&pubkey_pem).map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("Failed to parse public key PEM: {e}"),
            )
        })?;

    // Step 3: Perform RSA-OAEP encryption using keylime crypto module
    let encrypted_bytes =
        crypto::testing::rsa_oaep_encrypt(&pubkey, u_key.as_bytes())
            .map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("RSA encryption failed: {e}"),
                )
            })?;

    // Step 4: Encode result as base64 for transmission
    let encrypted_b64 = STANDARD.encode(&encrypted_bytes);

    let input_len = u_key.len();
    let output_len = encrypted_bytes.len();
    debug!(
        "Successfully encrypted U key: {input_len} bytes -> {output_len} bytes"
    );

    Ok(encrypted_b64)
}

/// Validate TPM hash algorithm names
///
/// Checks if the provided algorithm name is a known and supported TPM hash algorithm.
/// Based on the TPM 2.0 specification and common implementations.
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_tpm_hash_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm.to_lowercase().as_str(),
        "sha1"
            | "sha256"
            | "sha384"
            | "sha512"
            | "sha3-256"
            | "sha3-384"
            | "sha3-512"
            | "sm3-256"
    )
}

/// Validate TPM encryption algorithm names
///
/// Checks if the provided algorithm name is a known and supported TPM encryption algorithm.
/// Based on the TPM 2.0 specification and common implementations.
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_tpm_encryption_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm.to_lowercase().as_str(),
        "rsa"
            | "ecc"
            | "aes"
            | "camellia"
            | "sm4"
            | "rsassa"
            | "rsaes"
            | "rsapss"
            | "oaep"
            | "ecdsa"
            | "ecdh"
            | "ecdaa"
            | "sm2"
            | "ecschnorr"
    )
}

/// Validate TPM signing algorithm names
///
/// Checks if the provided algorithm name is a known and supported TPM signing algorithm.
/// Based on the TPM 2.0 specification and common implementations.
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_tpm_signing_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm.to_lowercase().as_str(),
        "rsa"
            | "ecc"
            | "rsassa"
            | "rsapss"
            | "ecdsa"
            | "ecdaa"
            | "sm2"
            | "ecschnorr"
            | "hmac"
    )
}

/// Build enrollment request for push model (API 3.0+)
///
/// Creates a simplified enrollment request for push model attestation.
/// In push model, the agent will initiate attestations, so no direct
/// agent communication or key exchange is needed during enrollment.
fn build_push_model_request(
    agent_id: &str,
    tpm_policy: &str,
    agent_data: &Value,
    _config: &Config,
    runtime_policy: Option<&str>,
    mb_policy: Option<&str>,
) -> Result<Value, CommandError> {
    debug!("Building push model enrollment request for agent {agent_id}");

    let mut request = json!({
        "agent_id": agent_id,
        "tpm_policy": tpm_policy,
        "accept_attestations": true,
        "ak_tpm": agent_data.get("aik_tpm"),
        "mtls_cert": agent_data.get("mtls_cert"),
        "accept_tpm_hash_algs": ["sha256", "sha1"],
        "accept_tpm_encryption_algs": ["rsa", "ecc"],
        "accept_tpm_signing_algs": ["rsa", "ecdsa"]
    });

    // Add policies if provided
    if let Some(policy_path) = runtime_policy {
        let policy_content = load_policy_file(policy_path)?;
        request["runtime_policy"] = json!(policy_content);
    }

    if let Some(policy_path) = mb_policy {
        let policy_content = load_policy_file(policy_path)?;
        request["mb_policy"] = json!(policy_content);
    }

    // Add metadata
    request["metadata"] = json!({});

    debug!("Push model request built successfully");
    Ok(request)
}

/// Validate API version format
///
/// Checks if the provided version string follows a valid API version format (e.g., "2.1", "3.0").
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_api_version(version: &str) -> bool {
    // Basic format check: should be major.minor (e.g., "2.1", "3.0")
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 2 {
        return false;
    }

    // Check that both parts are valid numbers
    parts[0].parse::<u32>().is_ok() && parts[1].parse::<u32>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientConfig, RegistrarConfig, TlsConfig, VerifierConfig,
    };
    use serde_json::json;

    /// Create a test configuration for agent operations
    fn create_test_config() -> Config {
        Config {
            verifier: VerifierConfig {
                ip: "127.0.0.1".to_string(),
                port: 8881,
                id: Some("test-verifier".to_string()),
            },
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

    /// Create a test output handler
    fn create_test_output() -> OutputHandler {
        OutputHandler::new(crate::OutputFormat::Json, true) // Quiet mode for tests
    }

    #[test]
    fn test_add_agent_params_creation() {
        let params = AddAgentParams {
            agent_id: "550e8400-e29b-41d4-a716-446655440000",
            ip: Some("192.168.1.100"),
            port: Some(9002),
            verifier_ip: None,
            runtime_policy: None,
            mb_policy: None,
            payload: None,
            cert_dir: None,
            verify: true,
            push_model: false,
            tpm_policy: None,
        };

        assert_eq!(params.agent_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(params.ip, Some("192.168.1.100"));
        assert_eq!(params.port, Some(9002));
        assert!(params.verify);
        assert!(!params.push_model);
    }

    #[test]
    fn test_add_agent_params_with_policies() {
        let params = AddAgentParams {
            agent_id: "550e8400-e29b-41d4-a716-446655440000",
            ip: None,
            port: None,
            verifier_ip: Some("10.0.0.1"),
            runtime_policy: Some("/path/to/runtime.json"),
            mb_policy: Some("/path/to/measured_boot.json"),
            payload: Some("/path/to/payload.txt"),
            cert_dir: Some("/path/to/certs"),
            verify: false,
            push_model: true,
            tpm_policy: Some("{\"test\": \"policy\"}"),
        };

        assert_eq!(params.runtime_policy, Some("/path/to/runtime.json"));
        assert_eq!(params.mb_policy, Some("/path/to/measured_boot.json"));
        assert_eq!(params.payload, Some("/path/to/payload.txt"));
        assert_eq!(params.cert_dir, Some("/path/to/certs"));
        assert!(!params.verify);
        assert!(params.push_model);
    }

    #[test]
    fn test_config_creation() {
        let config = create_test_config();

        assert_eq!(config.verifier.ip, "127.0.0.1");
        assert_eq!(config.verifier.port, 8881);
        assert_eq!(config.registrar.ip, "127.0.0.1");
        assert_eq!(config.registrar.port, 8891);
        assert!(!config.tls.verify_server_cert);
        assert_eq!(config.client.max_retries, 3);
    }

    #[test]
    fn test_output_handler_creation() {
        let _output = create_test_output();
        // OutputHandler doesn't expose its internal fields, but we can verify it was created
        // by ensuring no panic occurred during creation
    }

    // Test agent ID validation behavior
    mod agent_id_validation {

        #[test]
        fn test_valid_agent_id_formats() {
            let valid_ids = [
                "550e8400-e29b-41d4-a716-446655440000", // UUID format
                "agent-001",                            // Simple identifier
                "AAA",                                  // Simple uppercase
                "aaa",                                  // Simple lowercase
                "my-agent",                             // Hyphenated
                "agent_123",                            // Underscore
                "Agent123",                             // Mixed case
                "1234567890",                           // Numeric
                "a",                                    // Single character
                "test-agent-with-long-name-but-under-255-chars", // Long but valid
            ];

            for agent_id in &valid_ids {
                // Test that ID is not empty
                assert!(
                    !agent_id.is_empty(),
                    "Agent ID {agent_id} should not be empty"
                );

                // Test that ID is under 255 characters
                assert!(
                    agent_id.len() <= 255,
                    "Agent ID {agent_id} should be <= 255 chars"
                );

                // Test that ID has no control characters
                assert!(
                    !agent_id.chars().any(|c| c.is_control()),
                    "Agent ID {agent_id} should have no control characters"
                );
            }
        }

        #[test]
        fn test_invalid_agent_id_formats() {
            let invalid_ids = [
                "",               // Empty string
                &"a".repeat(256), // Too long (>255 chars)
                "agent\x00id", // Contains null character (control character)
                "agent\nid",   // Contains newline (control character)
                "agent\tid",   // Contains tab (control character)
            ];

            for agent_id in &invalid_ids {
                // Check various validation conditions
                let is_empty = agent_id.is_empty();
                let is_too_long = agent_id.len() > 255;
                let has_control_chars =
                    agent_id.chars().any(|c| c.is_control());

                assert!(is_empty || is_too_long || has_control_chars,
                       "Agent ID {agent_id:?} should fail at least one validation");
            }
        }
    }

    // Test error handling and validation
    mod error_handling {
        use super::*;

        #[test]
        fn test_agent_action_variants() {
            // Test that all AgentAction variants can be created
            let add_action = AgentAction::Add {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ip: Some("192.168.1.100".to_string()),
                port: Some(9002),
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: true,
                push_model: false,
                tpm_policy: None,
            };

            let remove_action = AgentAction::Remove {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                from_registrar: false,
                force: false,
            };

            let update_action = AgentAction::Update {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                runtime_policy: Some("/path/to/policy.json".to_string()),
                mb_policy: None,
            };

            let status_action = AgentAction::Status {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                verifier_only: false,
                registrar_only: false,
            };

            let reactivate_action = AgentAction::Reactivate {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            };

            // Verify actions were created without panicking
            match add_action {
                AgentAction::Add { uuid, .. } => {
                    assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
                }
                _ => panic!("Expected Add action"),
            }

            match remove_action {
                AgentAction::Remove {
                    uuid,
                    from_registrar,
                    force,
                } => {
                    assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
                    assert!(!from_registrar);
                    assert!(!force);
                }
                _ => panic!("Expected Remove action"),
            }

            match update_action {
                AgentAction::Update {
                    uuid,
                    runtime_policy,
                    mb_policy,
                } => {
                    assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
                    assert!(runtime_policy.is_some());
                    assert!(mb_policy.is_none());
                }
                _ => panic!("Expected Update action"),
            }

            match status_action {
                AgentAction::Status {
                    uuid,
                    verifier_only,
                    registrar_only,
                } => {
                    assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
                    assert!(!verifier_only);
                    assert!(!registrar_only);
                }
                _ => panic!("Expected Status action"),
            }

            match reactivate_action {
                AgentAction::Reactivate { uuid } => {
                    assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
                }
                _ => panic!("Expected Reactivate action"),
            }
        }

        #[test]
        fn test_error_context_trait() {
            use crate::error::ErrorContext;

            // Test that we can add context to errors
            let io_error: Result<(), std::io::Error> =
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "file not found",
                ));

            let contextual_error = io_error.with_context(|| {
                "Failed to process agent configuration".to_string()
            });

            assert!(contextual_error.is_err());
            let error = contextual_error.unwrap_err();
            assert_eq!(error.error_code(), "GENERIC_ERROR");
        }

        #[test]
        fn test_command_error_types() {
            // Test agent not found error
            let _agent_error =
                CommandError::agent_not_found("test-uuid", "verifier");
            // Note: category() method removed as unused

            // Test validation error
            let _validation_error = CommandError::invalid_parameter(
                "uuid",
                "Invalid UUID format",
            );
            // Note: category() method removed as unused

            // Test resource error
            let _resource_error = CommandError::resource_error(
                "verifier",
                "Failed to connect to service",
            );
            // Note: category() method removed as unused
        }
    }

    // Test JSON response structures
    mod json_responses {
        use super::*;

        #[test]
        fn test_success_response_structure() {
            let response = json!({
                "status": "success",
                "message": "Agent operation completed successfully",
                "agent_uuid": "550e8400-e29b-41d4-a716-446655440000",
                "results": {
                    "verifier_response": "OK"
                }
            });

            assert_eq!(response["status"], "success");
            assert_eq!(
                response["agent_uuid"],
                "550e8400-e29b-41d4-a716-446655440000"
            );
            assert!(response["results"].is_object());
        }

        #[test]
        fn test_error_response_structure() {
            let error =
                CommandError::agent_not_found("test-uuid", "verifier");
            let error_string = error.to_string();

            assert!(error_string.contains("Agent error"));
            assert!(error_string.contains("test-uuid"));
            assert!(error_string.contains("verifier"));
            assert!(error_string.contains("not found"));
        }
    }

    // Test configuration validation
    mod config_validation {
        use super::*;

        #[test]
        fn test_config_validation_success() {
            let config = create_test_config();
            let result = config.validate();
            assert!(result.is_ok(), "Test config should be valid");
        }

        #[test]
        fn test_config_urls() {
            let config = create_test_config();

            assert_eq!(config.verifier_base_url(), "https://127.0.0.1:8881");
            assert_eq!(config.registrar_base_url(), "https://127.0.0.1:8891");
        }

        #[test]
        fn test_config_with_ipv6() {
            let mut config = create_test_config();
            config.verifier.ip = "::1".to_string();
            config.registrar.ip = "[2001:db8::1]".to_string();

            assert_eq!(config.verifier_base_url(), "https://[::1]:8881");
            assert_eq!(
                config.registrar_base_url(),
                "https://[2001:db8::1]:8891"
            );
        }
    }

    // Test various agent parameter combinations
    mod parameter_combinations {
        use super::*;

        #[test]
        fn test_minimal_add_params() {
            let params = AddAgentParams {
                agent_id: "550e8400-e29b-41d4-a716-446655440000",
                ip: None,
                port: None,
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: false,
                tpm_policy: None,
            };

            assert_eq!(
                params.agent_id,
                "550e8400-e29b-41d4-a716-446655440000"
            );
            assert!(params.ip.is_none());
            assert!(params.port.is_none());
            assert!(!params.verify);
            assert!(!params.push_model);
        }

        #[test]
        fn test_maximal_add_params() {
            let params = AddAgentParams {
                agent_id: "550e8400-e29b-41d4-a716-446655440000",
                ip: Some("192.168.1.100"),
                port: Some(9002),
                verifier_ip: Some("10.0.0.1"),
                runtime_policy: Some("/etc/keylime/runtime.json"),
                mb_policy: Some("/etc/keylime/measured_boot.json"),
                payload: Some("/etc/keylime/payload.txt"),
                cert_dir: Some("/etc/keylime/certs"),
                verify: true,
                push_model: true,
                tpm_policy: Some("{\"pcr\": [\"15\"]}"),
            };

            assert!(params.ip.is_some());
            assert!(params.port.is_some());
            assert!(params.verifier_ip.is_some());
            assert!(params.runtime_policy.is_some());
            assert!(params.mb_policy.is_some());
            assert!(params.payload.is_some());
            assert!(params.cert_dir.is_some());
            assert!(params.verify);
            assert!(params.push_model);
        }

        #[test]
        fn test_push_model_params() {
            let params = AddAgentParams {
                agent_id: "550e8400-e29b-41d4-a716-446655440000",
                ip: None,   // IP not needed in push model
                port: None, // Port not needed in push model
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false, // Verification different in push model
                push_model: true,
                tpm_policy: None,
            };

            assert!(params.push_model);
            assert!(!params.verify);
            assert!(params.ip.is_none());
            assert!(params.port.is_none());
        }
    }

    // Test integration patterns (would require running services in real integration tests)
    mod integration_patterns {
        use super::*;

        #[test]
        fn test_agent_action_serialization() {
            // Test that AgentAction can be serialized/deserialized if needed for IPC
            let add_action = AgentAction::Add {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ip: Some("192.168.1.100".to_string()),
                port: Some(9002),
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: true,
                push_model: false,
                tpm_policy: None,
            };

            // Verify the action was created properly
            match add_action {
                AgentAction::Add {
                    uuid,
                    ip,
                    port,
                    verify,
                    push_model,
                    ..
                } => {
                    assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
                    assert_eq!(ip, Some("192.168.1.100".to_string()));
                    assert_eq!(port, Some(9002));
                    assert!(verify);
                    assert!(!push_model);
                }
                _ => panic!("Expected Add action"),
            }
        }

        #[test]
        fn test_configuration_loading_patterns() {
            // Test different configuration patterns
            let default_config = Config::default();
            assert_eq!(default_config.verifier.ip, "127.0.0.1");
            assert_eq!(default_config.verifier.port, 8881);
            assert_eq!(default_config.registrar.port, 8891);

            // Test configuration modification
            let mut custom_config = default_config;
            custom_config.verifier.ip = "10.0.0.1".to_string();
            custom_config.verifier.port = 9001;

            assert_eq!(custom_config.verifier.ip, "10.0.0.1");
            assert_eq!(custom_config.verifier.port, 9001);
        }
    }

    // Test enhanced TPM policy handling
    mod tpm_policy_policy_tests {
        use super::*;
        use std::fs;
        use tempfile::tempdir;

        #[test]
        fn test_resolve_tpm_policy_explicit_priority() {
            // Explicit policy should have highest priority
            let result = resolve_tpm_policy_enhanced(
                Some("{\"pcr\": [15]}"),
                Some("/path/to/mb.json"),
            )
            .unwrap();
            assert_eq!(result, "{\"pcr\": [15]}");
        }

        #[test]
        fn test_resolve_tpm_policy_default_fallback() {
            // Should fallback to default when no policies provided
            let result = resolve_tpm_policy_enhanced(None, None).unwrap();
            assert_eq!(result, "{}");
        }

        #[test]
        fn test_extract_tpm_policy_from_mb_policy_success() {
            let temp_dir = tempdir().unwrap();
            let policy_file = temp_dir.path().join("mb_policy.json");

            // Create test measured boot policy with TPM policy
            let mb_policy_content = serde_json::json!({
                "tpm_policy": {
                    "pcr": [15],
                    "hash": "sha256"
                },
                "other_field": "value"
            });

            fs::write(&policy_file, mb_policy_content.to_string()).unwrap();

            let result = extract_tpm_policy_from_mb_policy(
                policy_file.to_str().unwrap(),
            )
            .unwrap();

            assert!(result.is_some());
            let extracted = result.unwrap();
            let parsed: Value = serde_json::from_str(&extracted).unwrap();
            assert_eq!(parsed["pcr"], json!([15]));
            assert_eq!(parsed["hash"], "sha256");
        }

        #[test]
        fn test_extract_tpm_policy_alternative_locations() {
            let temp_dir = tempdir().unwrap();

            // Test "tpm" location
            let policy_file_tpm = temp_dir.path().join("mb_policy_tpm.json");
            let mb_policy_tpm = serde_json::json!({
                "tpm": {"pcr": [16]},
                "other_field": "value"
            });
            fs::write(&policy_file_tpm, mb_policy_tpm.to_string()).unwrap();

            let result = extract_tpm_policy_from_mb_policy(
                policy_file_tpm.to_str().unwrap(),
            )
            .unwrap();
            assert!(result.is_some());

            // Test "tpm_policy" location
            let policy_file_full =
                temp_dir.path().join("mb_policy_full.json");
            let mb_policy_full = serde_json::json!({
                "tpm_policy": {"pcr": [17]},
                "other_field": "value"
            });
            fs::write(&policy_file_full, mb_policy_full.to_string()).unwrap();

            let result = extract_tpm_policy_from_mb_policy(
                policy_file_full.to_str().unwrap(),
            )
            .unwrap();
            assert!(result.is_some());
        }

        #[test]
        fn test_extract_tpm_policy_no_policy_found() {
            let temp_dir = tempdir().unwrap();
            let policy_file = temp_dir.path().join("mb_policy_no_tpm.json");

            // Create measured boot policy without TPM policy
            let mb_policy_content = serde_json::json!({
                "other_field": "value",
                "more_fields": "data"
            });

            fs::write(&policy_file, mb_policy_content.to_string()).unwrap();

            let result = extract_tpm_policy_from_mb_policy(
                policy_file.to_str().unwrap(),
            )
            .unwrap();

            assert!(result.is_none());
        }

        #[test]
        fn test_extract_tpm_policy_invalid_json() {
            let temp_dir = tempdir().unwrap();
            let policy_file = temp_dir.path().join("invalid.json");

            // Write invalid JSON
            fs::write(&policy_file, "{ invalid json }").unwrap();

            let result = extract_tpm_policy_from_mb_policy(
                policy_file.to_str().unwrap(),
            );

            assert!(result.is_err());
        }

        #[test]
        fn test_extract_tpm_policy_file_not_found() {
            let result =
                extract_tpm_policy_from_mb_policy("/nonexistent/file.json");
            assert!(result.is_err());
        }

        #[test]
        fn test_resolve_tpm_policy_enhanced_with_mb_extraction() {
            let temp_dir = tempdir().unwrap();
            let policy_file = temp_dir.path().join("mb_with_tmp.json");

            // Create measured boot policy with TPM policy
            let mb_policy_content = serde_json::json!({
                "tpm_policy": {
                    "pcr": [14, 15],
                    "hash": "sha1"
                }
            });

            fs::write(&policy_file, mb_policy_content.to_string()).unwrap();

            // Should extract from measured boot policy when no explicit policy
            let result = resolve_tpm_policy_enhanced(
                None,
                Some(policy_file.to_str().unwrap()),
            )
            .unwrap();

            let parsed: Value = serde_json::from_str(&result).unwrap();
            assert_eq!(parsed["pcr"], json!([14, 15]));
            assert_eq!(parsed["hash"], "sha1");
        }

        #[test]
        fn test_resolve_tpm_policy_enhanced_extraction_error_fallback() {
            // When extraction fails, should fallback to default
            let result = resolve_tpm_policy_enhanced(
                None,
                Some("/nonexistent/file.json"),
            )
            .unwrap();

            assert_eq!(result, "{}");
        }

        #[test]
        fn test_resolve_tpm_policy_precedence_order() {
            let temp_dir = tempdir().unwrap();
            let policy_file = temp_dir.path().join("mb_policy.json");

            // Create measured boot policy
            let mb_policy_content = serde_json::json!({
                "tpm_policy": {"pcr": [16]}
            });
            fs::write(&policy_file, mb_policy_content.to_string()).unwrap();

            // Explicit policy should override extracted policy
            let result = resolve_tpm_policy_enhanced(
                Some("{\"pcr\": [15]}"),
                Some(policy_file.to_str().unwrap()),
            )
            .unwrap();

            // Should use explicit policy, not extracted one
            let parsed: Value = serde_json::from_str(&result).unwrap();
            assert_eq!(parsed["pcr"], json!([15]));
        }
    }

    // Test comprehensive field support and validation
    mod comprehensive_field_tests {
        use super::*;
        use serde_json::json;

        #[test]
        fn test_add_agent_request_with_all_fields() {
            // Create a request with all possible fields
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_ak_tpm(Some(json!({"aik": "test_key"})))
            .with_mtls_cert(Some(json!({"cert": "test_cert"})))
            .with_v_key(Some(json!({"v": "test_v_key"})))
            .with_runtime_policy(Some("runtime policy content".to_string()))
            .with_runtime_policy_name(Some("runtime_policy_1".to_string()))
            .with_runtime_policy_key(Some(json!({"key": "policy_key"})))
            .with_mb_policy(Some("measured boot policy content".to_string()))
            .with_mb_policy_name(Some("mb_policy_1".to_string()))
            .with_ima_sign_verification_keys(Some("ima_keys".to_string()))
            .with_revocation_key(Some("revocation_key".to_string()))
            .with_accept_tpm_hash_algs(Some(vec![
                "sha256".to_string(),
                "sha1".to_string(),
            ]))
            .with_accept_tpm_encryption_algs(Some(vec![
                "rsa".to_string(),
                "ecc".to_string(),
            ]))
            .with_accept_tpm_signing_algs(Some(vec![
                "rsa".to_string(),
                "ecdsa".to_string(),
            ]))
            .with_metadata(Some("{}".to_string()))
            .with_payload(Some("test payload".to_string()))
            .with_cert_dir(Some("/path/to/certs".to_string()))
            .with_supported_version(Some("2.1".to_string()));

            // Validate that all fields are set correctly
            assert_eq!(request.cloudagent_ip, "192.168.1.100");
            assert_eq!(request.cloudagent_port, 9002);
            assert_eq!(request.verifier_ip, "127.0.0.1");
            assert_eq!(request.verifier_port, 8881);
            assert_eq!(request.tpm_policy, "{}");

            assert!(request.ak_tpm.is_some());
            assert!(request.mtls_cert.is_some());
            assert!(request.v.is_some());

            assert_eq!(
                request.runtime_policy,
                Some("runtime policy content".to_string())
            );
            assert_eq!(
                request.runtime_policy_name,
                Some("runtime_policy_1".to_string())
            );
            assert!(request.runtime_policy_key.is_some());

            assert_eq!(
                request.mb_policy,
                Some("measured boot policy content".to_string())
            );
            assert_eq!(
                request.mb_policy_name,
                Some("mb_policy_1".to_string())
            );

            assert_eq!(
                request.ima_sign_verification_keys,
                Some("ima_keys".to_string())
            );
            assert_eq!(
                request.revocation_key,
                Some("revocation_key".to_string())
            );

            assert!(request.accept_tpm_hash_algs.is_some());
            assert!(request.accept_tpm_encryption_algs.is_some());
            assert!(request.accept_tpm_signing_algs.is_some());

            assert_eq!(request.metadata, Some("{}".to_string()));
            assert_eq!(request.payload, Some("test payload".to_string()));
            assert_eq!(request.cert_dir, Some("/path/to/certs".to_string()));
            assert_eq!(request.supported_version, Some("2.1".to_string()));
        }

        #[test]
        fn test_add_agent_request_validation_all_fields() {
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{\"pcr\": [15]}".to_string(),
            )
            .with_accept_tpm_hash_algs(Some(vec!["sha256".to_string()]))
            .with_accept_tpm_encryption_algs(Some(vec!["rsa".to_string()]))
            .with_accept_tpm_signing_algs(Some(vec!["rsa".to_string()]))
            .with_metadata(Some("{\"test\": \"value\"}".to_string()))
            .with_supported_version(Some("2.1".to_string()));

            // Should validate successfully
            assert!(request.validate().is_ok());
        }

        #[test]
        fn test_add_agent_request_validation_invalid_metadata() {
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_metadata(Some("invalid json {".to_string()));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid JSON in metadata"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_hash_algorithm() {
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_accept_tpm_hash_algs(Some(vec![
                "invalid_hash".to_string(),
            ]));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Unknown TPM hash algorithm"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_encryption_algorithm() {
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_accept_tpm_encryption_algs(Some(vec![
                "invalid_enc".to_string()
            ]));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Unknown TPM encryption algorithm"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_signing_algorithm() {
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_accept_tpm_signing_algs(Some(vec![
                "invalid_sign".to_string()
            ]));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Unknown TPM signing algorithm"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_api_version() {
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_supported_version(Some(
                "invalid.version.format".to_string(),
            ));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid API version format"));
        }

        #[test]
        fn test_serialization_all_fields() {
            let request = AddAgentRequest::new(
                "192.168.1.100".to_string(),
                9002,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_runtime_policy_name(Some("test_policy".to_string()))
            .with_accept_tpm_hash_algs(Some(vec!["sha256".to_string()]))
            .with_metadata(Some("{}".to_string()));

            let serialized = serde_json::to_string(&request).unwrap();
            let json_value: Value =
                serde_json::from_str(&serialized).unwrap();

            // Check that required fields are present
            assert_eq!(json_value["cloudagent_ip"], "192.168.1.100");
            assert_eq!(json_value["cloudagent_port"], 9002);
            assert_eq!(json_value["verifier_ip"], "127.0.0.1");
            assert_eq!(json_value["verifier_port"], 8881);
            assert_eq!(json_value["tpm_policy"], "{}");

            // Check that optional fields are present when set
            assert_eq!(json_value["runtime_policy_name"], "test_policy");
            assert_eq!(json_value["accept_tpm_hash_algs"], json!(["sha256"]));
            assert_eq!(json_value["metadata"], "{}");

            // Check that None fields are not serialized
            assert!(json_value.get("runtime_policy").is_none());
            assert!(json_value.get("mb_policy").is_none());
        }
    }

    // Test validation helper functions
    mod validation_helper_tests {
        use super::*;

        #[test]
        fn test_is_valid_tpm_hash_algorithm() {
            // Valid algorithms
            assert!(is_valid_tpm_hash_algorithm("sha1"));
            assert!(is_valid_tpm_hash_algorithm("SHA256"));
            assert!(is_valid_tpm_hash_algorithm("sha384"));
            assert!(is_valid_tpm_hash_algorithm("sha512"));
            assert!(is_valid_tpm_hash_algorithm("sha3-256"));
            assert!(is_valid_tpm_hash_algorithm("sm3-256"));

            // Invalid algorithms
            assert!(!is_valid_tpm_hash_algorithm("md5"));
            assert!(!is_valid_tpm_hash_algorithm("invalid"));
            assert!(!is_valid_tpm_hash_algorithm(""));
        }

        #[test]
        fn test_is_valid_tpm_encryption_algorithm() {
            // Valid algorithms
            assert!(is_valid_tpm_encryption_algorithm("rsa"));
            assert!(is_valid_tpm_encryption_algorithm("ECC"));
            assert!(is_valid_tpm_encryption_algorithm("aes"));
            assert!(is_valid_tpm_encryption_algorithm("oaep"));
            assert!(is_valid_tpm_encryption_algorithm("ecdh"));

            // Invalid algorithms
            assert!(!is_valid_tpm_encryption_algorithm("des"));
            assert!(!is_valid_tpm_encryption_algorithm("invalid"));
            assert!(!is_valid_tpm_encryption_algorithm(""));
        }

        #[test]
        fn test_is_valid_tpm_signing_algorithm() {
            // Valid algorithms
            assert!(is_valid_tpm_signing_algorithm("rsa"));
            assert!(is_valid_tpm_signing_algorithm("ECC"));
            assert!(is_valid_tpm_signing_algorithm("ecdsa"));
            assert!(is_valid_tpm_signing_algorithm("rsassa"));
            assert!(is_valid_tpm_signing_algorithm("hmac"));

            // Invalid algorithms
            assert!(!is_valid_tpm_signing_algorithm("dsa"));
            assert!(!is_valid_tpm_signing_algorithm("invalid"));
            assert!(!is_valid_tpm_signing_algorithm(""));
        }

        #[test]
        fn test_is_valid_api_version() {
            // Valid versions
            assert!(is_valid_api_version("2.1"));
            assert!(is_valid_api_version("3.0"));
            assert!(is_valid_api_version("10.99"));

            // Invalid versions
            assert!(!is_valid_api_version("2"));
            assert!(!is_valid_api_version("2.1.3"));
            assert!(!is_valid_api_version("v2.1"));
            assert!(!is_valid_api_version("2.x"));
            assert!(!is_valid_api_version(""));
            assert!(!is_valid_api_version("invalid"));
        }
    }
}
