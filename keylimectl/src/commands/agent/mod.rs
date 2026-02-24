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
//!     pull_model: false,
//!     tpm_policy: None,
//!     wait_for_attestation: false,
//!     attestation_timeout: 60,
//! };
//!
//! let result = agent::execute(&action, &config, &output).await?;
//! println!("Agent operation result: {:?}", result);
//! # Ok(())
//! # }
//! ```

mod add;
#[cfg(feature = "api-v2")]
mod attestation;
mod helpers;
mod reactivate;
mod remove;
mod status;
pub mod types;
mod update;

#[allow(unused_imports)] // Re-export for downstream use
pub use types::AddAgentRequest;

use add::add_agent;
use reactivate::reactivate_agent;
use remove::remove_agent;
use status::get_agent_status;
use types::AddAgentParams;
use update::update_agent;

use crate::client::factory;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::AgentAction;
use serde_json::{json, Value};

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
///     pull_model: false,
///     tpm_policy: None,
///     wait_for_attestation: false,
///     attestation_timeout: 60,
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
            pull_model,
            tpm_policy,
            wait_for_attestation,
            attestation_timeout,
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
                pull_model: *pull_model,
                tpm_policy: tpm_policy.as_deref(),
                wait_for_attestation: *wait_for_attestation,
                attestation_timeout: *attestation_timeout,
            },
            output,
        )
        .await
        .map_err(KeylimectlError::from),
        AgentAction::Remove {
            uuid,
            from_registrar,
            force,
        } => remove_agent(uuid, *from_registrar, *force, output)
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
            output,
        )
        .await
        .map_err(KeylimectlError::from),
        AgentAction::Status {
            uuid,
            verifier_only,
            registrar_only,
        } => get_agent_status(uuid, *verifier_only, *registrar_only, output)
            .await
            .map_err(KeylimectlError::from),
        AgentAction::Reactivate { uuid } => reactivate_agent(uuid, output)
            .await
            .map_err(KeylimectlError::from),
        AgentAction::List {
            detailed,
            registrar_only,
        } => list_agents(*detailed, *registrar_only, output).await,
    }
}

/// List all agents
async fn list_agents(
    detailed: bool,
    registrar_only: bool,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    if registrar_only {
        output.info("Listing agents from registrar only");

        let registrar_client = factory::get_registrar().await?;
        let registrar_data =
            registrar_client.list_agents().await.with_context(|| {
                "Failed to list agents from registrar".to_string()
            })?;

        Ok(registrar_data)
    } else if detailed {
        output.info("Retrieving detailed agent information from both verifier and registrar");

        let verifier_client = factory::get_verifier().await?;

        // Get detailed info from verifier
        let verifier_data = verifier_client
            .get_bulk_info(
                crate::config::singleton::get_config()
                    .verifier
                    .id
                    .as_deref(),
            )
            .await
            .with_context(|| {
                "Failed to get bulk agent info from verifier".to_string()
            })?;

        // Also get registrar data for complete picture
        let registrar_client = factory::get_registrar().await?;
        let registrar_data =
            registrar_client.list_agents().await.with_context(|| {
                "Failed to list agents from registrar".to_string()
            })?;

        Ok(json!({
            "detailed": true,
            "verifier": verifier_data,
            "registrar": registrar_data
        }))
    } else {
        output.info("Listing agents from verifier");

        let verifier_client = factory::get_verifier().await?;

        // Just get basic list from verifier
        let verifier_data = verifier_client
            .list_agents(
                crate::config::singleton::get_config()
                    .verifier
                    .id
                    .as_deref(),
            )
            .await
            .with_context(|| {
                "Failed to list agents from verifier".to_string()
            })?;

        Ok(verifier_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::error::CommandError;
    use crate::config::{
        CliOverrides, ClientConfig, Config, RegistrarConfig, TlsConfig,
        VerifierConfig,
    };
    use crate::output::OutputHandler;
    use crate::AgentAction;
    use serde_json::json;

    /// Create a test configuration for agent operations
    fn create_test_config() -> Config {
        Config {
            loaded_from: None,
            cli_overrides: CliOverrides::default(),
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

    /// Create a test output handler
    fn _create_test_output() -> OutputHandler {
        OutputHandler::new(
            crate::OutputFormat::Json,
            true,
            crate::ColorMode::Never,
        ) // Quiet mode for tests
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
        let _output = _create_test_output();
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
                pull_model: false,
                tpm_policy: None,
                wait_for_attestation: false,
                attestation_timeout: 60,
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
                _ => panic!("Expected Add action"), //#[allow_ci]
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
                _ => panic!("Expected Remove action"), //#[allow_ci]
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
                _ => panic!("Expected Update action"), //#[allow_ci]
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
                _ => panic!("Expected Status action"), //#[allow_ci]
            }

            match reactivate_action {
                AgentAction::Reactivate { uuid } => {
                    assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
                }
                _ => panic!("Expected Reactivate action"), //#[allow_ci]
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
                pull_model: false,
                tpm_policy: None,
                wait_for_attestation: false,
                attestation_timeout: 60,
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
                _ => panic!("Expected Add action"), //#[allow_ci]
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
