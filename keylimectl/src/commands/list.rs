// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! List commands for various Keylime resources
//!
//! This module provides comprehensive listing functionality for all major Keylime resources,
//! including agents, runtime policies, and measured boot policies. It offers both basic
//! and detailed views depending on user requirements.
//!
//! # Resource Types
//!
//! The list command supports several resource types:
//!
//! 1. **Agents**: List all agents registered with the system
//!    - Basic view: Shows agent status from verifier
//!    - Detailed view: Combines data from both verifier and registrar
//! 2. **Runtime Policies**: List all runtime/IMA policies
//! 3. **Measured Boot Policies**: List all measured boot policies
//!
//! # Agent Listing Modes
//!
//! ## Basic Mode
//! - Retrieves agent list from verifier only
//! - Shows operational state and basic status
//! - Faster operation, suitable for quick status checks
//! - Shows: UUID, operational state
//!
//! ## Detailed Mode
//! - Retrieves comprehensive data from both verifier and registrar
//! - Shows complete agent information including TPM data
//! - Slower operation but provides complete picture
//! - Shows: UUID, operational state, IP, port, TPM keys, registration info
//!
//! # Policy Listing
//!
//! Policy listing provides an overview of all configured policies:
//! - Policy names and metadata
//! - Creation and modification timestamps
//! - Policy status and validation state
//!
//! # Performance Considerations
//!
//! - Basic agent listing is optimized for speed
//! - Detailed listing may take longer with many agents
//! - Policy listing is generally fast as policies are typically fewer
//! - Results are paginated automatically for large deployments
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::commands::list;
//! use keylimectl::config::Config;
//! use keylimectl::output::OutputHandler;
//! use keylimectl::ListResource;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::default();
//! let output = OutputHandler::new(crate::OutputFormat::Json, false);
//!
//! // List agents with basic information
//! let basic_agents = ListResource::Agents { detailed: false };
//! let result = list::execute(&basic_agents, &config, &output).await?;
//!
//! // List agents with detailed information
//! let detailed_agents = ListResource::Agents { detailed: true };
//! let result = list::execute(&detailed_agents, &config, &output).await?;
//!
//! // List runtime policies
//! let policies = ListResource::Policies;
//! let result = list::execute(&policies, &config, &output).await?;
//!
//! // List measured boot policies
//! let mb_policies = ListResource::MeasuredBootPolicies;
//! let result = list::execute(&mb_policies, &config, &output).await?;
//! # Ok(())
//! # }
//! ```

use crate::client::{registrar::RegistrarClient, verifier::VerifierClient};
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::ListResource;
use serde_json::{json, Value};

/// Execute a resource listing command
///
/// This is the main entry point for all resource listing operations. It dispatches
/// to the appropriate handler based on the resource type and manages the complete
/// operation lifecycle including data retrieval, formatting, and result reporting.
///
/// # Arguments
///
/// * `resource` - The specific resource type to list (Agents, Policies, or MeasuredBootPolicies)
/// * `config` - Configuration containing service endpoints and authentication settings
/// * `output` - Output handler for progress reporting and result formatting
///
/// # Returns
///
/// Returns a JSON value containing the listing results. The structure varies by resource type:
///
/// ## Agent Listing (Basic)
/// ```json
/// {
///   "results": {
///     "agent-uuid-1": "operational_state",
///     "agent-uuid-2": "operational_state"
///   }
/// }
/// ```
///
/// ## Agent Listing (Detailed)
/// ```json
/// {
///   "detailed": true,
///   "verifier": {
///     "results": {
///       "agent-uuid-1": {
///         "operational_state": "Get Quote",
///         "ip": "192.168.1.100",
///         "port": 9002
///       }
///     }
///   },
///   "registrar": {
///     "results": {
///       "agent-uuid-1": {
///         "aik_tpm": "base64-encoded-key",
///         "ek_tpm": "base64-encoded-key",
///         "ip": "192.168.1.100",
///         "port": 9002,
///         "active": true
///       }
///     }
///   }
/// }
/// ```
///
/// ## Policy Listing
/// ```json
/// {
///   "results": {
///     "policy-name-1": {
///       "created": "2025-01-01T00:00:00Z",
///       "last_modified": "2025-01-02T12:00:00Z"
///     }
///   }
/// }
/// ```
///
/// # Error Handling
///
/// This function handles various error conditions:
/// - Network failures when communicating with services
/// - Service unavailability (verifier or registrar down)
/// - Authentication/authorization failures
/// - Empty result sets (no resources found)
///
/// # Performance Notes
///
/// - Basic agent listing is optimized for speed
/// - Detailed agent listing requires two API calls (verifier + registrar)
/// - Policy listing is typically fast due to smaller data volumes
/// - Large deployments may experience longer response times
///
/// # Examples
///
/// ```rust
/// use keylimectl::commands::list;
/// use keylimectl::config::Config;
/// use keylimectl::output::OutputHandler;
/// use keylimectl::ListResource;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
/// let output = OutputHandler::new(crate::OutputFormat::Json, false);
///
/// // List agents (basic)
/// let agents = ListResource::Agents { detailed: false };
/// let result = list::execute(&agents, &config, &output).await?;
/// println!("Found {} agents", result["results"].as_object().unwrap().len());
///
/// // List policies
/// let policies = ListResource::Policies;
/// let result = list::execute(&policies, &config, &output).await?;
/// # Ok(())
/// # }
/// ```
pub async fn execute(
    resource: &ListResource,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match resource {
        ListResource::Agents { detailed } => {
            list_agents(*detailed, config, output).await
        }
        ListResource::Policies => list_runtime_policies(config, output).await,
        ListResource::MeasuredBootPolicies => {
            list_mb_policies(config, output).await
        }
    }
}

/// List all agents
async fn list_agents(
    detailed: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    if detailed {
        output.info("Retrieving detailed agent information from both verifier and registrar");
    } else {
        output.info("Listing agents from verifier");
    }

    let verifier_client = VerifierClient::builder()
        .config(config)
        .build()
        .await?;

    if detailed {
        // Get detailed info from verifier
        let verifier_data = verifier_client
            .get_bulk_info(config.verifier.id.as_deref())
            .await
            .with_context(|| {
                "Failed to get bulk agent info from verifier".to_string()
            })?;

        // Also get registrar data for complete picture
        let registrar_client = RegistrarClient::builder()
            .config(config)
            .build()
            .await?;
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
        // Just get basic list from verifier
        let verifier_data = verifier_client
            .list_agents(config.verifier.id.as_deref())
            .await
            .with_context(|| {
                "Failed to list agents from verifier".to_string()
            })?;

        Ok(verifier_data)
    }
}

/// List runtime policies
async fn list_runtime_policies(
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info("Listing runtime policies");

    let verifier_client = VerifierClient::builder()
        .config(config)
        .build()
        .await?;
    let policies = verifier_client
        .list_runtime_policies()
        .await
        .with_context(|| {
            "Failed to list runtime policies from verifier".to_string()
        })?;

    Ok(policies)
}

/// List measured boot policies
async fn list_mb_policies(
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info("Listing measured boot policies");

    let verifier_client = VerifierClient::builder()
        .config(config)
        .build()
        .await?;
    let policies =
        verifier_client.list_mb_policies().await.with_context(|| {
            "Failed to list measured boot policies from verifier".to_string()
        })?;

    Ok(policies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientConfig, RegistrarConfig, TlsConfig, VerifierConfig,
    };
    use serde_json::json;

    /// Create a test configuration for list operations
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
    fn test_config_creation() {
        let config = create_test_config();

        assert_eq!(config.verifier.ip, "127.0.0.1");
        assert_eq!(config.verifier.port, 8881);
        assert_eq!(config.verifier.id, Some("test-verifier".to_string()));
        assert_eq!(config.registrar.ip, "127.0.0.1");
        assert_eq!(config.registrar.port, 8891);
        assert!(!config.tls.verify_server_cert);
        assert_eq!(config.client.max_retries, 3);
    }

    #[test]
    fn test_output_handler_creation() {
        let _output = create_test_output();
        // OutputHandler creation should not panic
    }

    // Test list resource variants
    mod resource_variants {
        use super::*;

        #[test]
        fn test_agents_basic_resource() {
            let resource = ListResource::Agents { detailed: false };

            match resource {
                ListResource::Agents { detailed } => {
                    assert!(!detailed);
                }
                _ => panic!("Expected Agents resource"),
            }
        }

        #[test]
        fn test_agents_detailed_resource() {
            let resource = ListResource::Agents { detailed: true };

            match resource {
                ListResource::Agents { detailed } => {
                    assert!(detailed);
                }
                _ => panic!("Expected Agents resource"),
            }
        }

        #[test]
        fn test_policies_resource() {
            let resource = ListResource::Policies;

            match resource {
                ListResource::Policies => {
                    // Expected variant
                }
                _ => panic!("Expected Policies resource"),
            }
        }

        #[test]
        fn test_measured_boot_policies_resource() {
            let resource = ListResource::MeasuredBootPolicies;

            match resource {
                ListResource::MeasuredBootPolicies => {
                    // Expected variant
                }
                _ => panic!("Expected MeasuredBootPolicies resource"),
            }
        }
    }

    // Test JSON response structures
    mod json_responses {
        use super::*;

        #[test]
        fn test_basic_agent_list_response_structure() {
            let response = json!({
                "results": {
                    "agent-uuid-1": "Get Quote",
                    "agent-uuid-2": "Provide V",
                    "agent-uuid-3": "Start"
                }
            });

            assert!(response["results"].is_object());
            let results = response["results"].as_object().unwrap();
            assert_eq!(results.len(), 3);
            assert_eq!(results["agent-uuid-1"], "Get Quote");
            assert_eq!(results["agent-uuid-2"], "Provide V");
            assert_eq!(results["agent-uuid-3"], "Start");
        }

        #[test]
        fn test_detailed_agent_list_response_structure() {
            let response = json!({
                "detailed": true,
                "verifier": {
                    "results": {
                        "agent-uuid-1": {
                            "operational_state": "Get Quote",
                            "ip": "192.168.1.100",
                            "port": 9002,
                            "verifier_ip": "192.168.1.1",
                            "verifier_port": 8881
                        }
                    }
                },
                "registrar": {
                    "results": {
                        "agent-uuid-1": {
                            "aik_tpm": "base64-encoded-aik",
                            "ek_tpm": "base64-encoded-ek",
                            "ip": "192.168.1.100",
                            "port": 9002,
                            "active": true,
                            "regcount": 1
                        }
                    }
                }
            });

            assert_eq!(response["detailed"], true);
            assert!(response["verifier"]["results"].is_object());
            assert!(response["registrar"]["results"].is_object());

            let verifier_results =
                response["verifier"]["results"].as_object().unwrap();
            let registrar_results =
                response["registrar"]["results"].as_object().unwrap();

            assert_eq!(verifier_results.len(), 1);
            assert_eq!(registrar_results.len(), 1);

            assert_eq!(
                verifier_results["agent-uuid-1"]["operational_state"],
                "Get Quote"
            );
            assert_eq!(registrar_results["agent-uuid-1"]["active"], true);
        }

        #[test]
        fn test_runtime_policies_response_structure() {
            let response = json!({
                "results": {
                    "production-policy": {
                        "created": "2025-01-01T00:00:00Z",
                        "last_modified": "2025-01-02T12:00:00Z",
                        "size": 1024
                    },
                    "development-policy": {
                        "created": "2025-01-03T00:00:00Z",
                        "last_modified": "2025-01-03T06:00:00Z",
                        "size": 512
                    }
                }
            });

            assert!(response["results"].is_object());
            let results = response["results"].as_object().unwrap();
            assert_eq!(results.len(), 2);

            assert!(results.contains_key("production-policy"));
            assert!(results.contains_key("development-policy"));

            assert_eq!(results["production-policy"]["size"], 1024);
            assert_eq!(results["development-policy"]["size"], 512);
        }

        #[test]
        fn test_measured_boot_policies_response_structure() {
            let response = json!({
                "results": {
                    "secure-boot-policy": {
                        "created": "2025-01-01T00:00:00Z",
                        "mb_policy_size": 2048,
                        "pcr_count": 8
                    },
                    "legacy-boot-policy": {
                        "created": "2025-01-02T00:00:00Z",
                        "mb_policy_size": 1536,
                        "pcr_count": 4
                    }
                }
            });

            assert!(response["results"].is_object());
            let results = response["results"].as_object().unwrap();
            assert_eq!(results.len(), 2);

            assert!(results.contains_key("secure-boot-policy"));
            assert!(results.contains_key("legacy-boot-policy"));

            assert_eq!(results["secure-boot-policy"]["pcr_count"], 8);
            assert_eq!(results["legacy-boot-policy"]["pcr_count"], 4);
        }

        #[test]
        fn test_empty_results_response() {
            let response = json!({
                "results": {}
            });

            assert!(response["results"].is_object());
            let results = response["results"].as_object().unwrap();
            assert_eq!(results.len(), 0);
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
        fn test_verifier_url_construction() {
            let config = create_test_config();
            assert_eq!(config.verifier_base_url(), "https://127.0.0.1:8881");
        }

        #[test]
        fn test_registrar_url_construction() {
            let config = create_test_config();
            assert_eq!(config.registrar_base_url(), "https://127.0.0.1:8891");
        }

        #[test]
        fn test_config_with_different_ports() {
            let mut config = create_test_config();
            config.verifier.port = 9001;
            config.registrar.port = 9002;

            assert_eq!(config.verifier_base_url(), "https://127.0.0.1:9001");
            assert_eq!(config.registrar_base_url(), "https://127.0.0.1:9002");
        }

        #[test]
        fn test_config_with_ipv6() {
            let mut config = create_test_config();
            config.verifier.ip = "::1".to_string();
            config.registrar.ip = "2001:db8::1".to_string();

            assert_eq!(config.verifier_base_url(), "https://[::1]:8881");
            assert_eq!(
                config.registrar_base_url(),
                "https://[2001:db8::1]:8891"
            );
        }

        #[test]
        fn test_config_with_verifier_id() {
            let config = create_test_config();
            assert_eq!(config.verifier.id, Some("test-verifier".to_string()));
        }

        #[test]
        fn test_config_without_verifier_id() {
            let mut config = create_test_config();
            config.verifier.id = None;

            assert!(config.verifier.id.is_none());
        }
    }

    // Test error handling scenarios
    mod error_handling {
        use super::*;

        #[test]
        fn test_error_context_trait() {
            use crate::error::ErrorContext;

            let io_error: Result<(), std::io::Error> =
                Err(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    "network unreachable",
                ));

            let contextual_error = io_error.with_context(|| {
                "Failed to connect to verifier service".to_string()
            });

            assert!(contextual_error.is_err());
            let error = contextual_error.unwrap_err();
            assert_eq!(error.error_code(), "GENERIC_ERROR");
        }

        #[test]
        fn test_api_error_creation() {
            let error = KeylimectlError::api_error(
                500,
                "Internal server error".to_string(),
                Some(json!({"details": "Database connection failed"})),
            );

            assert_eq!(error.error_code(), "API_ERROR");
            assert!(error.is_retryable()); // 5xx errors should be retryable

            let json_output = error.to_json();
            assert_eq!(json_output["error"]["code"], "API_ERROR");
            assert_eq!(json_output["error"]["details"]["http_status"], 500);
        }

        #[test]
        fn test_client_creation_errors() {
            // Test with invalid configuration
            let mut config = create_test_config();
            config.verifier.port = 0; // Invalid port

            let validation_result = config.validate();
            assert!(validation_result.is_err());
            assert!(validation_result
                .unwrap_err()
                .to_string()
                .contains("Verifier port cannot be 0"));
        }

        #[test]
        fn test_network_error_scenarios() {
            // Test error codes that should be retryable
            let retryable_codes = [500, 502, 503, 504];
            for code in &retryable_codes {
                let error = KeylimectlError::api_error(
                    *code,
                    format!("HTTP {code} error"),
                    None,
                );
                assert!(
                    error.is_retryable(),
                    "HTTP {code} should be retryable"
                );
            }

            // Test error codes that should not be retryable
            let non_retryable_codes = [400, 401, 403, 404];
            for code in &non_retryable_codes {
                let error = KeylimectlError::api_error(
                    *code,
                    format!("HTTP {code} error"),
                    None,
                );
                assert!(
                    !error.is_retryable(),
                    "HTTP {code} should not be retryable"
                );
            }
        }
    }

    // Test operational states and agent status
    mod agent_states {
        use super::*;

        #[test]
        fn test_operational_state_values() {
            let operational_states = [
                "Start",
                "Tenant Start",
                "Get Quote",
                "Provide V",
                "Provide V (Retry)",
                "Failed",
                "Terminated",
                "Invalid Quote",
                "Pending",
            ];

            for state in &operational_states {
                // Verify that operational states are valid strings
                assert!(!state.is_empty());
                assert!(state.is_ascii());
            }
        }

        #[test]
        fn test_agent_status_combinations() {
            // Test various combinations of agent data that might be returned
            let agent_data = json!({
                "operational_state": "Get Quote",
                "ip": "192.168.1.100",
                "port": 9002,
                "verifier_ip": "192.168.1.1",
                "verifier_port": 8881,
                "tpm_policy": "{}",
                "ima_policy": "{}",
                "last_event_id": "12345"
            });

            assert_eq!(agent_data["operational_state"], "Get Quote");
            assert_eq!(agent_data["ip"], "192.168.1.100");
            assert_eq!(agent_data["port"], 9002);
            assert_eq!(agent_data["verifier_ip"], "192.168.1.1");
            assert_eq!(agent_data["verifier_port"], 8881);
        }

        #[test]
        fn test_registrar_agent_data() {
            let registrar_data = json!({
                "aik_tpm": "base64-encoded-aik-key-data",
                "ek_tpm": "base64-encoded-ek-key-data",
                "ekcert": "base64-encoded-ek-certificate",
                "ip": "192.168.1.100",
                "port": 9002,
                "active": true,
                "regcount": 3
            });

            assert_eq!(registrar_data["active"], true);
            assert_eq!(registrar_data["regcount"], 3);
            assert_eq!(registrar_data["ip"], "192.168.1.100");
            assert_eq!(registrar_data["port"], 9002);
        }
    }

    // Test policy structures and metadata
    mod policy_structures {
        use super::*;

        #[test]
        fn test_runtime_policy_metadata() {
            let policy_metadata = json!({
                "name": "production-ima-policy",
                "created": "2025-01-01T00:00:00Z",
                "last_modified": "2025-01-02T12:00:00Z",
                "size": 2048,
                "version": "1.2",
                "allowlist_entries": 156,
                "exclude_entries": 12
            });

            assert_eq!(policy_metadata["name"], "production-ima-policy");
            assert_eq!(policy_metadata["size"], 2048);
            assert_eq!(policy_metadata["allowlist_entries"], 156);
            assert_eq!(policy_metadata["exclude_entries"], 12);
        }

        #[test]
        fn test_measured_boot_policy_metadata() {
            let mb_policy_metadata = json!({
                "name": "secure-boot-v3",
                "created": "2025-01-01T00:00:00Z",
                "mb_policy_size": 4096,
                "pcr_count": 16,
                "components_count": 8,
                "settings": {
                    "secure_boot": true,
                    "tpm_version": "2.0"
                }
            });

            assert_eq!(mb_policy_metadata["name"], "secure-boot-v3");
            assert_eq!(mb_policy_metadata["pcr_count"], 16);
            assert_eq!(mb_policy_metadata["components_count"], 8);
            assert_eq!(mb_policy_metadata["settings"]["secure_boot"], true);
            assert_eq!(mb_policy_metadata["settings"]["tpm_version"], "2.0");
        }

        #[test]
        fn test_policy_naming_conventions() {
            let policy_names = [
                "production-policy",
                "development_policy",
                "test-env-policy",
                "policy123",
                "secure-boot-v2",
                "ima-allowlist-prod",
            ];

            for name in &policy_names {
                // Verify policy names follow expected patterns
                assert!(!name.is_empty());
                assert!(name.len() <= 64); // Reasonable name length limit
                assert!(name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
            }
        }
    }

    // Test listing scenarios with different result sets
    mod listing_scenarios {
        use super::*;

        #[test]
        fn test_empty_agent_list() {
            let empty_response = json!({
                "results": {}
            });

            let results = empty_response["results"].as_object().unwrap();
            assert_eq!(results.len(), 0);
        }

        #[test]
        fn test_single_agent_list() {
            let single_agent_response = json!({
                "results": {
                    "550e8400-e29b-41d4-a716-446655440000": "Get Quote"
                }
            });

            let results =
                single_agent_response["results"].as_object().unwrap();
            assert_eq!(results.len(), 1);
            assert!(
                results.contains_key("550e8400-e29b-41d4-a716-446655440000")
            );
        }

        #[test]
        fn test_multiple_agents_list() {
            let multiple_agents_response = json!({
                "results": {
                    "550e8400-e29b-41d4-a716-446655440000": "Get Quote",
                    "550e8400-e29b-41d4-a716-446655440001": "Provide V",
                    "550e8400-e29b-41d4-a716-446655440002": "Start",
                    "550e8400-e29b-41d4-a716-446655440003": "Failed"
                }
            });

            let results =
                multiple_agents_response["results"].as_object().unwrap();
            assert_eq!(results.len(), 4);

            // Verify all expected agents are present
            assert_eq!(
                results["550e8400-e29b-41d4-a716-446655440000"],
                "Get Quote"
            );
            assert_eq!(
                results["550e8400-e29b-41d4-a716-446655440001"],
                "Provide V"
            );
            assert_eq!(
                results["550e8400-e29b-41d4-a716-446655440002"],
                "Start"
            );
            assert_eq!(
                results["550e8400-e29b-41d4-a716-446655440003"],
                "Failed"
            );
        }

        #[test]
        fn test_large_scale_agent_list_structure() {
            // Simulate structure for large-scale deployments
            let mut agents = serde_json::Map::new();
            for i in 0..100 {
                let uuid = format!("550e8400-e29b-41d4-a716-44665544{i:04}");
                let state = match i % 4 {
                    0 => "Get Quote",
                    1 => "Provide V",
                    2 => "Start",
                    _ => "Tenant Start",
                };
                let _ = agents.insert(uuid, json!(state));
            }

            let large_response = json!({
                "results": agents
            });

            let results = large_response["results"].as_object().unwrap();
            assert_eq!(results.len(), 100);

            // Verify structure integrity
            for (uuid, state) in results {
                assert!(uuid.starts_with("550e8400-e29b-41d4-a716-"));
                assert!(state.is_string());
                let state_str = state.as_str().unwrap();
                assert!(["Get Quote", "Provide V", "Start", "Tenant Start"]
                    .contains(&state_str));
            }
        }
    }

    // Test performance and optimization considerations
    mod performance_tests {
        use super::*;

        #[test]
        fn test_response_size_estimation() {
            // Test response size calculations for capacity planning
            let detailed_agent = json!({
                "operational_state": "Get Quote",
                "ip": "192.168.1.100",
                "port": 9002,
                "verifier_ip": "192.168.1.1",
                "verifier_port": 8881,
                "tmp_policy": "{}",
                "ima_policy": "{}",
                "aik_tpm": "a".repeat(1024), // 1KB key
                "ek_tpm": "b".repeat(1024),   // 1KB key
                "ekcert": "c".repeat(2048)    // 2KB certificate
            });

            let response_str =
                serde_json::to_string(&detailed_agent).unwrap();

            // Detailed agent response should be several KB due to TPM keys
            assert!(response_str.len() > 4000); // At least 4KB
            assert!(response_str.len() < 10000); // But not excessive
        }

        #[test]
        fn test_basic_vs_detailed_response_difference() {
            let basic_agent = json!("Get Quote");
            let detailed_agent = json!({
                "operational_state": "Get Quote",
                "ip": "192.168.1.100",
                "port": 9002,
                "aik_tpm": "base64-encoded-key-data",
                "ek_tpm": "base64-encoded-key-data"
            });

            let basic_size =
                serde_json::to_string(&basic_agent).unwrap().len();
            let detailed_size =
                serde_json::to_string(&detailed_agent).unwrap().len();

            // Detailed response should be significantly larger
            assert!(detailed_size > basic_size * 10);
        }
    }
}
