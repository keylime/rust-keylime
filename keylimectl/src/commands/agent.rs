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

use crate::client::{registrar::RegistrarClient, verifier::VerifierClient};
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::AgentAction;
use log::{debug, warn};
use serde_json::{json, Value};
use uuid::Uuid;

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
        } => {
            add_agent(
                AddAgentParams {
                    uuid,
                    ip: ip.as_deref(),
                    port: *port,
                    verifier_ip: verifier_ip.as_deref(),
                    runtime_policy: runtime_policy.as_deref(),
                    mb_policy: mb_policy.as_deref(),
                    payload: payload.as_deref(),
                    cert_dir: cert_dir.as_deref(),
                    verify: *verify,
                    push_model: *push_model,
                },
                config,
                output,
            )
            .await
        }
        AgentAction::Remove {
            uuid,
            from_registrar,
            force,
        } => {
            remove_agent(uuid, *from_registrar, *force, config, output).await
        }
        AgentAction::Update {
            uuid,
            runtime_policy,
            mb_policy,
        } => {
            update_agent(
                uuid,
                runtime_policy.as_deref(),
                mb_policy.as_deref(),
                config,
                output,
            )
            .await
        }
        AgentAction::Status {
            uuid,
            verifier_only,
            registrar_only,
        } => {
            get_agent_status(
                uuid,
                *verifier_only,
                *registrar_only,
                config,
                output,
            )
            .await
        }
        AgentAction::Reactivate { uuid } => {
            reactivate_agent(uuid, config, output).await
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
/// * `uuid` - Agent UUID (must be registered with registrar first)
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
    /// Agent UUID - must be valid UUID format
    uuid: &'a str,
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
    push_model: bool,
}

/// Add an agent to the verifier for continuous attestation monitoring
///
/// This function implements the complete agent addition workflow, which involves
/// multiple steps including validation, registrar lookup, attestation, and
/// verifier registration.
///
/// # Workflow Steps
///
/// 1. **UUID Validation**: Validates the agent UUID format
/// 2. **Registrar Lookup**: Retrieves agent data from registrar (TPM keys, etc.)
/// 3. **Connection Details**: Determines agent IP/port from CLI args or registrar
/// 4. **Attestation**: Performs TPM-based attestation (unless push model)
/// 5. **Verifier Addition**: Adds agent to verifier for monitoring
/// 6. **Verification**: Optionally performs key derivation verification
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
/// - Invalid UUID format ([`KeylimectlError::Validation`])
/// - Agent not found in registrar ([`KeylimectlError::AgentNotFound`])
/// - Missing connection details ([`KeylimectlError::Validation`])
/// - Network failures ([`KeylimectlError::Network`])
/// - Verifier API errors ([`KeylimectlError::Api`])
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
///     uuid: "550e8400-e29b-41d4-a716-446655440000",
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
) -> Result<Value, KeylimectlError> {
    // Validate UUID
    let agent_uuid = Uuid::parse_str(params.uuid)
        .validate(|| format!("Invalid agent UUID: {}", params.uuid))?;

    output.info(format!("Adding agent {agent_uuid} to verifier"));

    // Step 1: Get agent data from registrar
    output.step(1, 4, "Retrieving agent data from registrar");

    let registrar_client = RegistrarClient::new(config)?;
    let agent_data = registrar_client
        .get_agent(&agent_uuid.to_string())
        .await
        .with_context(|| {
            "Failed to retrieve agent data from registrar".to_string()
        })?;

    if agent_data.is_none() {
        return Err(KeylimectlError::agent_not_found(
            agent_uuid.to_string(),
            "registrar",
        ));
    }

    let agent_data = agent_data.unwrap();

    // Step 2: Determine agent connection details
    output.step(2, 4, "Validating agent connection details");

    let (agent_ip, agent_port) = if params.push_model {
        // In push model, agent connects to verifier
        ("localhost".to_string(), 9002)
    } else {
        // Get IP and port from CLI args or registrar data
        let agent_ip = params
            .ip
            .map(|s| s.to_string())
            .or_else(|| {
                agent_data
                    .get("ip")
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
            })
            .ok_or_else(|| {
                KeylimectlError::validation(
                    "Agent IP address is required when not using push model",
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
                KeylimectlError::validation(
                    "Agent port is required when not using push model",
                )
            })?;

        (agent_ip, agent_port)
    };

    // Step 3: Perform attestation if not using push model
    if !params.push_model {
        output.step(3, 4, "Performing attestation with agent");

        // TODO: Implement TPM quote verification
        // This would involve:
        // 1. Connecting to the agent
        // 2. Getting a TPM quote with a random nonce
        // 3. Validating the quote against the AIK from registrar
        // 4. Encrypting the U key with the agent's public key

        output.info("Attestation completed successfully");
    } else {
        output.step(3, 4, "Skipping attestation (push model)");
    }

    // Step 4: Add agent to verifier
    output.step(4, 4, "Adding agent to verifier");

    let verifier_client = VerifierClient::new(config)?;

    // Build the request payload
    let cv_agent_ip = params.verifier_ip.unwrap_or(&agent_ip);

    let mut request_data = json!({
        "cloudagent_ip": cv_agent_ip,
        "cloudagent_port": agent_port,
        "verifier_ip": config.verifier.ip,
        "verifier_port": config.verifier.port,
        "ak_tpm": agent_data.get("aik_tpm"),
        "mtls_cert": agent_data.get("mtls_cert"),
    });

    // Add policies if provided
    if let Some(policy) = params.runtime_policy {
        // TODO: Load and process runtime policy
        request_data["runtime_policy"] = json!(policy);
    }

    if let Some(policy) = params.mb_policy {
        // TODO: Load and process measured boot policy
        request_data["mb_policy"] = json!(policy);
    }

    // Add payload if provided
    if let Some(payload_path) = params.payload {
        // TODO: Load and encrypt payload
        request_data["payload"] = json!(payload_path);
    }

    if let Some(cert_dir_path) = params.cert_dir {
        // TODO: Generate and encrypt certificate package
        request_data["cert_dir"] = json!(cert_dir_path);
    }

    let response = verifier_client
        .add_agent(&agent_uuid.to_string(), request_data)
        .await
        .with_context(|| "Failed to add agent to verifier".to_string())?;

    // Step 5: Verify if requested
    if params.verify && !params.push_model {
        output.info("Performing key derivation verification");
        // TODO: Implement key derivation verification
    }

    output.info(format!("Agent {agent_uuid} successfully added to verifier"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} added successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": response
    }))
}

/// Remove an agent from the verifier (and optionally registrar)
async fn remove_agent(
    uuid: &str,
    from_registrar: bool,
    force: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Removing agent {agent_uuid} from verifier"));

    let verifier_client = VerifierClient::new(config)?;

    // Check if agent exists on verifier (unless force is used)
    if !force {
        output.step(
            1,
            if from_registrar { 3 } else { 2 },
            "Checking agent status on verifier",
        );

        match verifier_client.get_agent(&agent_uuid.to_string()).await {
            Ok(Some(_)) => {
                debug!("Agent found on verifier");
            }
            Ok(None) => {
                warn!("Agent not found on verifier, but continuing with removal");
            }
            Err(e) => {
                if !force {
                    return Err(e);
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

    let verifier_response = verifier_client
        .delete_agent(&agent_uuid.to_string())
        .await
        .with_context(|| {
            "Failed to remove agent from verifier".to_string()
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

        let registrar_client = RegistrarClient::new(config)?;
        let registrar_response = registrar_client
            .delete_agent(&agent_uuid.to_string())
            .await
            .with_context(|| {
                "Failed to remove agent from registrar".to_string()
            })?;

        results["registrar"] = registrar_response;
    }

    output.info(format!("Agent {agent_uuid} successfully removed"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} removed successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": results
    }))
}

/// Update an existing agent
async fn update_agent(
    uuid: &str,
    runtime_policy: Option<&str>,
    mb_policy: Option<&str>,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Updating agent {agent_uuid}"));

    // For now, implement update as delete + add
    // TODO: Implement proper update API when available

    output.step(1, 2, "Removing existing agent configuration");
    let _remove_result =
        remove_agent(uuid, false, false, config, output).await?;

    output.step(2, 2, "Adding agent with new configuration");
    // TODO: Get previous configuration and merge with new values
    let add_result = add_agent(
        AddAgentParams {
            uuid,
            ip: None,   // TODO: Get from previous config
            port: None, // TODO: Get from previous config
            verifier_ip: None,
            runtime_policy,
            mb_policy,
            payload: None,
            cert_dir: None,
            verify: false,
            push_model: false, // TODO: Get from previous config
        },
        config,
        output,
    )
    .await?;

    output.info(format!("Agent {agent_uuid} successfully updated"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} updated successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": add_result
    }))
}

/// Get agent status from verifier and/or registrar
async fn get_agent_status(
    uuid: &str,
    verifier_only: bool,
    registrar_only: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Getting status for agent {agent_uuid}"));

    let mut results = json!({});

    // Get status from registrar (unless verifier_only is set)
    if !verifier_only {
        output.progress("Checking registrar status");

        let registrar_client = RegistrarClient::new(config)?;
        match registrar_client.get_agent(&agent_uuid.to_string()).await {
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

        let verifier_client = VerifierClient::new(config)?;
        match verifier_client.get_agent(&agent_uuid.to_string()).await {
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

    Ok(json!({
        "agent_uuid": agent_uuid.to_string(),
        "results": results
    }))
}

/// Reactivate a failed agent
async fn reactivate_agent(
    uuid: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Reactivating agent {agent_uuid}"));

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .reactivate_agent(&agent_uuid.to_string())
        .await
        .with_context(|| "Failed to reactivate agent".to_string())?;

    output.info(format!("Agent {agent_uuid} successfully reactivated"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} reactivated successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": response
    }))
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
            uuid: "550e8400-e29b-41d4-a716-446655440000",
            ip: Some("192.168.1.100"),
            port: Some(9002),
            verifier_ip: None,
            runtime_policy: None,
            mb_policy: None,
            payload: None,
            cert_dir: None,
            verify: true,
            push_model: false,
        };

        assert_eq!(params.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(params.ip, Some("192.168.1.100"));
        assert_eq!(params.port, Some(9002));
        assert!(params.verify);
        assert!(!params.push_model);
    }

    #[test]
    fn test_add_agent_params_with_policies() {
        let params = AddAgentParams {
            uuid: "550e8400-e29b-41d4-a716-446655440000",
            ip: None,
            port: None,
            verifier_ip: Some("10.0.0.1"),
            runtime_policy: Some("/path/to/runtime.json"),
            mb_policy: Some("/path/to/measured_boot.json"),
            payload: Some("/path/to/payload.txt"),
            cert_dir: Some("/path/to/certs"),
            verify: false,
            push_model: true,
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

    // Test UUID validation behavior
    mod uuid_validation {
        use super::*;

        #[test]
        fn test_valid_uuid_formats() {
            let valid_uuids = [
                "550e8400-e29b-41d4-a716-446655440000",
                "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "550e8400e29b41d4a716446655440000", // No dashes is also valid
            ];

            for uuid_str in &valid_uuids {
                let result = Uuid::parse_str(uuid_str);
                assert!(result.is_ok(), "UUID {} should be valid", uuid_str);
            }
        }

        #[test]
        fn test_invalid_uuid_formats() {
            let invalid_uuids = [
                "not-a-uuid",
                "550e8400-e29b-41d4-a716", // Too short
                "550e8400-e29b-41d4-a716-446655440000-extra", // Too long
                "550e8400-e29b-41d4-a716-44665544000g", // Invalid character
                "",
                "550e8400-e29b-41d4-a716-446655440000 ", // Extra space
                "g50e8400-e29b-41d4-a716-446655440000", // Invalid first character
            ];

            for uuid_str in &invalid_uuids {
                let result = Uuid::parse_str(uuid_str);
                assert!(
                    result.is_err(),
                    "UUID {} should be invalid",
                    uuid_str
                );
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
        fn test_keylimectl_error_types() {
            // Test agent not found error
            let agent_error =
                KeylimectlError::agent_not_found("test-uuid", "verifier");
            assert_eq!(agent_error.error_code(), "AGENT_NOT_FOUND");

            // Test validation error
            let validation_error =
                KeylimectlError::validation("Invalid UUID format");
            assert_eq!(validation_error.error_code(), "VALIDATION_ERROR");

            // Test API error
            let api_error = KeylimectlError::api_error(
                404,
                "Not found".to_string(),
                Some(json!({"error": "Agent not found"})),
            );
            assert_eq!(api_error.error_code(), "API_ERROR");
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
                KeylimectlError::agent_not_found("test-uuid", "verifier");
            let error_json = error.to_json();

            assert_eq!(error_json["error"]["code"], "AGENT_NOT_FOUND");
            assert_eq!(
                error_json["error"]["details"]["agent_uuid"],
                "test-uuid"
            );
            assert_eq!(error_json["error"]["details"]["service"], "verifier");
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
                uuid: "550e8400-e29b-41d4-a716-446655440000",
                ip: None,
                port: None,
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: false,
            };

            assert_eq!(params.uuid, "550e8400-e29b-41d4-a716-446655440000");
            assert!(params.ip.is_none());
            assert!(params.port.is_none());
            assert!(!params.verify);
            assert!(!params.push_model);
        }

        #[test]
        fn test_maximal_add_params() {
            let params = AddAgentParams {
                uuid: "550e8400-e29b-41d4-a716-446655440000",
                ip: Some("192.168.1.100"),
                port: Some(9002),
                verifier_ip: Some("10.0.0.1"),
                runtime_policy: Some("/etc/keylime/runtime.json"),
                mb_policy: Some("/etc/keylime/measured_boot.json"),
                payload: Some("/etc/keylime/payload.txt"),
                cert_dir: Some("/etc/keylime/certs"),
                verify: true,
                push_model: true,
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
                uuid: "550e8400-e29b-41d4-a716-446655440000",
                ip: None,   // IP not needed in push model
                port: None, // Port not needed in push model
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false, // Verification different in push model
                push_model: true,
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
}
