// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Measured boot policy management commands for keylimectl
//!
//! This module provides comprehensive management of measured boot policies for the Keylime
//! attestation system. Measured boot policies define the expected boot state of agents
//! by specifying trusted boot components, kernel modules, and system configuration.
//!
//! # Measured Boot Overview
//!
//! Measured boot leverages the TPM (Trusted Platform Module) to measure and record
//! the boot process, creating an immutable chain of trust from firmware to OS:
//!
//! 1. **BIOS/UEFI**: Initial measurements stored in PCR 0-7
//! 2. **Boot Loader**: Measurements of boot components in PCR 8-9
//! 3. **Kernel**: OS kernel and initrd measurements in PCR 10-15
//! 4. **Applications**: Runtime measurements in PCR 16-23
//!
//! # Policy Structure
//!
//! Measured boot policies are JSON documents that specify:
//! - Expected PCR values for different boot stages
//! - Allowed boot components and their hashes
//! - Acceptable kernel configurations
//! - Trusted modules and drivers
//!
//! # Command Types
//!
//! - [`MeasuredBootAction::Push`]: Push a measured boot policy to the verifier
//! - [`MeasuredBootAction::Show`]: Display an existing policy
//! - [`MeasuredBootAction::Update`]: Update an existing policy
//! - [`MeasuredBootAction::Delete`]: Remove a policy
//! - [`MeasuredBootAction::List`]: List all available policies
//!
//! # Security Considerations
//!
//! - Policies must be validated before deployment
//! - Changes to policies affect agent attestation immediately
//! - Invalid policies can prevent agent enrollment
//! - Policy management requires proper authorization
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::commands::measured_boot;
//! use keylimectl::config::Config;
//! use keylimectl::output::OutputHandler;
//! use keylimectl::MeasuredBootAction;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::default();
//! let output = OutputHandler::new(crate::OutputFormat::Json, false);
//!
//! // Push a measured boot policy to the verifier
//! let push_action = MeasuredBootAction::Push {
//!     name: "secure-boot-policy".to_string(),
//!     file: "/etc/keylime/policies/secure-boot.json".to_string(),
//! };
//!
//! let result = measured_boot::execute(&push_action, &config, &output).await?;
//! println!("Policy pushed: {:?}", result);
//!
//! // List all policies
//! let list_action = MeasuredBootAction::List;
//! let policies = measured_boot::execute(&list_action, &config, &output).await?;
//! # Ok(())
//! # }
//! ```

use crate::client::factory;
use crate::commands::error::CommandError;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::MeasuredBootAction;
use chrono;
use log::debug;
use serde_json::{json, Value};
use std::fs;

/// Execute a measured boot policy management command
///
/// This is the main entry point for all measured boot policy operations. It dispatches
/// to the appropriate handler based on the action type and manages the complete
/// operation lifecycle including file validation, policy processing, and result reporting.
///
/// # Arguments
///
/// * `action` - The specific measured boot action to perform (Push, Show, Update, Delete, or List)
/// * `config` - Configuration containing verifier endpoint and authentication settings
/// * `output` - Output handler for progress reporting and result formatting
///
/// # Returns
///
/// Returns a JSON value containing the operation results:
/// - `status`: "success" if operation completed successfully
/// - `message`: Human-readable status message
/// - `policy_name`: Name of the affected policy (for single-policy operations)
/// - `results`: Detailed operation results from the verifier service
///
/// # Policy File Format
///
/// Policy files must be valid JSON documents containing measured boot specifications:
/// ```json
/// {
///   "pcrs": {
///     "0": "expected_pcr0_value",
///     "1": "expected_pcr1_value"
///   },
///   "components": [
///     {
///       "name": "bootloader",
///       "hash": "sha256_hash_value"
///     }
///   ]
/// }
/// ```
///
/// # Error Handling
///
/// This function handles various error conditions:
/// - Invalid policy file paths or unreadable files
/// - Malformed JSON in policy files
/// - Network failures when communicating with verifier
/// - Policy validation errors from the verifier
/// - Missing or duplicate policy names
///
/// # Examples
///
/// ```rust
/// use keylimectl::commands::measured_boot;
/// use keylimectl::config::Config;
/// use keylimectl::output::OutputHandler;
/// use keylimectl::MeasuredBootAction;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
/// let output = OutputHandler::new(crate::OutputFormat::Json, false);
///
/// // Push a policy
/// let push_action = MeasuredBootAction::Push {
///     name: "production-policy".to_string(),
///     file: "/etc/keylime/mb-policy.json".to_string(),
/// };
/// let result = measured_boot::execute(&push_action, &config, &output).await?;
/// assert_eq!(result["status"], "success");
///
/// // Show the policy
/// let show_action = MeasuredBootAction::Show {
///     name: "production-policy".to_string(),
/// };
/// let policy = measured_boot::execute(&show_action, &config, &output).await?;
///
/// // List all policies
/// let list_action = MeasuredBootAction::List;
/// let policies = measured_boot::execute(&list_action, &config, &output).await?;
/// # Ok(())
/// # }
/// ```
pub async fn execute(
    action: &MeasuredBootAction,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        MeasuredBootAction::List => list_mb_policies(output)
            .await
            .map_err(KeylimectlError::from),
        MeasuredBootAction::Push { name, file } => {
            push_mb_policy(name, file, output)
                .await
                .map_err(KeylimectlError::from)
        }
        MeasuredBootAction::Show { name } => show_mb_policy(name, output)
            .await
            .map_err(KeylimectlError::from),
        MeasuredBootAction::Update { name, file } => {
            update_mb_policy(name, file, output)
                .await
                .map_err(KeylimectlError::from)
        }
        MeasuredBootAction::Delete { name } => delete_mb_policy(name, output)
            .await
            .map_err(KeylimectlError::from),
    }
}

/// Push a measured boot policy to the verifier
async fn push_mb_policy(
    name: &str,
    file_path: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Pushing measured boot policy '{name}'"));

    // Load policy from file
    let policy_content = fs::read_to_string(file_path).map_err(|e| {
        CommandError::policy_file_error(
            file_path,
            format!("Failed to read measured boot policy file: {e}"),
        )
    })?;

    // Parse policy content (basic validation)
    let _policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse measured boot policy as JSON: {e}"),
            )
        })?;

    debug!(
        "Loaded measured boot policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    // Parse the policy to extract metadata and validate structure
    let policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse measured boot policy as JSON: {e}"),
            )
        })?;

    // Extract policy metadata for enhanced API payload
    let mut policy_data = json!({
        "mb_policy": policy_content,
        "policy_type": "measured_boot",
        "format_version": "1.0",
        "upload_timestamp": chrono::Utc::now().to_rfc3339()
    });

    // Add metadata based on policy content structure
    if let Some(pcrs) = policy_json.get("pcrs").and_then(|v| v.as_object()) {
        policy_data["pcr_count"] = json!(pcrs.len());
        policy_data["pcr_list"] = json!(pcrs.keys().collect::<Vec<_>>());
    }

    if let Some(components) =
        policy_json.get("components").and_then(|v| v.as_array())
    {
        policy_data["components_count"] = json!(components.len());
    }

    if let Some(settings) = policy_json.get("settings") {
        policy_data["mb_settings"] = settings.clone();
        if let Some(secure_boot) = settings.get("secure_boot") {
            policy_data["secure_boot_enabled"] = secure_boot.clone();
        }
        if let Some(tpm_version) = settings.get("tpm_version") {
            policy_data["tpm_version"] = tpm_version.clone();
        }
    }

    if let Some(meta) = policy_json.get("meta") {
        policy_data["policy_metadata"] = meta.clone();
    }

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to connect to verifier: {e}"),
        )
    })?;
    let response = verifier_client
        .add_mb_policy(name, policy_data)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to push measured boot policy '{name}': {e}"),
            )
        })?;

    output.info(format!("Measured boot policy '{name}' pushed successfully"));

    Ok(json!({
        "status": "success",
        "message": format!("Measured boot policy '{name}' pushed successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// Show a measured boot policy
async fn show_mb_policy(
    name: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Retrieving measured boot policy '{name}'"));

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to connect to verifier: {e}"),
        )
    })?;
    let policy = verifier_client.get_mb_policy(name).await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to retrieve measured boot policy '{name}': {e}"),
        )
    })?;

    match policy {
        Some(policy_data) => Ok(json!({
            "policy_name": name,
            "results": policy_data
        })),
        None => Err(CommandError::policy_not_found(name)),
    }
}

/// Update an existing measured boot policy
async fn update_mb_policy(
    name: &str,
    file_path: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Updating measured boot policy '{name}'"));

    // Load policy from file
    let policy_content = fs::read_to_string(file_path).map_err(|e| {
        CommandError::policy_file_error(
            file_path,
            format!("Failed to read measured boot policy file: {e}"),
        )
    })?;

    // Parse policy content (basic validation)
    let _policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse measured boot policy as JSON: {e}"),
            )
        })?;

    debug!(
        "Loaded measured boot policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    // Parse the policy to extract metadata and validate structure
    let policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse measured boot policy as JSON: {e}"),
            )
        })?;

    // Extract policy metadata for enhanced API payload
    let mut policy_data = json!({
        "mb_policy": policy_content,
        "policy_type": "measured_boot",
        "format_version": "1.0",
        "update_timestamp": chrono::Utc::now().to_rfc3339()
    });

    // Add metadata based on policy content structure
    if let Some(pcrs) = policy_json.get("pcrs").and_then(|v| v.as_object()) {
        policy_data["pcr_count"] = json!(pcrs.len());
        policy_data["pcr_list"] = json!(pcrs.keys().collect::<Vec<_>>());
    }

    if let Some(components) =
        policy_json.get("components").and_then(|v| v.as_array())
    {
        policy_data["components_count"] = json!(components.len());
    }

    if let Some(settings) = policy_json.get("settings") {
        policy_data["mb_settings"] = settings.clone();
        if let Some(secure_boot) = settings.get("secure_boot") {
            policy_data["secure_boot_enabled"] = secure_boot.clone();
        }
        if let Some(tpm_version) = settings.get("tpm_version") {
            policy_data["tpm_version"] = tpm_version.clone();
        }
    }

    if let Some(meta) = policy_json.get("meta") {
        policy_data["policy_metadata"] = meta.clone();
    }

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to connect to verifier: {e}"),
        )
    })?;
    let response = verifier_client
        .update_mb_policy(name, policy_data)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!(
                    "Failed to update measured boot policy '{name}': {e}"
                ),
            )
        })?;

    output.info(format!(
        "Measured boot policy '{name}' updated successfully"
    ));

    Ok(json!({
        "status": "success",
        "message": format!("Measured boot policy '{name}' updated successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// Delete a measured boot policy
async fn delete_mb_policy(
    name: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Deleting measured boot policy '{name}'"));

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to connect to verifier: {e}"),
        )
    })?;
    let response =
        verifier_client.delete_mb_policy(name).await.map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!(
                    "Failed to delete measured boot policy '{name}': {e}"
                ),
            )
        })?;

    output.info(format!(
        "Measured boot policy '{name}' deleted successfully"
    ));

    Ok(json!({
        "status": "success",
        "message": format!("Measured boot policy '{name}' deleted successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// List measured boot policies
async fn list_mb_policies(
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info("Listing measured boot policies");

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to connect to verifier: {e}"),
        )
    })?;
    let policies = verifier_client.list_mb_policies().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!(
                "Failed to list measured boot policies from verifier: {e}"
            ),
        )
    })?;

    Ok(policies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientConfig, Config, RegistrarConfig, TlsConfig, VerifierConfig,
    };
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Create a test configuration for measured boot operations
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

    /// Create a test measured boot policy file
    fn create_test_policy_file() -> Result<NamedTempFile, std::io::Error> {
        let mut file = NamedTempFile::new()?;
        let policy_content = json!({
            "pcrs": {
                "0": "3a3f5c1f5b9e8f2a1d7e9b4a2c6f8e1d3a5b7c9e",
                "1": "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c",
                "2": "9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5"
            },
            "components": [
                {
                    "name": "bootloader",
                    "hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                },
                {
                    "name": "kernel",
                    "hash": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                }
            ],
            "settings": {
                "secure_boot": true,
                "tpm_version": "2.0",
                "expected_state": "trusted"
            }
        });

        file.write_all(
            serde_json::to_string_pretty(&policy_content)?.as_bytes(),
        )?;
        file.flush()?;
        Ok(file)
    }

    /// Create a test invalid policy file
    fn create_invalid_policy_file() -> Result<NamedTempFile, std::io::Error> {
        let mut file = NamedTempFile::new()?;
        file.write_all(b"{ invalid json content")?;
        file.flush()?;
        Ok(file)
    }

    #[test]
    fn test_config_creation() {
        let config = create_test_config();

        assert_eq!(config.verifier.ip, "127.0.0.1");
        assert_eq!(config.verifier.port, 8881);
        assert!(!config.tls.verify_server_cert);
        assert_eq!(config.client.max_retries, 3);
    }

    #[test]
    fn test_output_handler_creation() {
        let _output = create_test_output();
        // OutputHandler creation should not panic
    }

    #[test]
    fn test_valid_policy_file_creation() {
        let policy_file = create_test_policy_file()
            .expect("Failed to create test policy file");

        // Verify file exists and can be read
        let content = fs::read_to_string(policy_file.path())
            .expect("Failed to read policy file");
        let parsed: Value =
            serde_json::from_str(&content).expect("Failed to parse JSON");

        assert!(parsed["pcrs"].is_object());
        assert!(parsed["components"].is_array());
        assert_eq!(parsed["settings"]["secure_boot"], true);
    }

    #[test]
    fn test_invalid_policy_file_creation() {
        let invalid_file = create_invalid_policy_file()
            .expect("Failed to create invalid file");

        // Verify file exists but contains invalid JSON
        let content = fs::read_to_string(invalid_file.path())
            .expect("Failed to read file");
        let parse_result: Result<Value, _> = serde_json::from_str(&content);
        assert!(parse_result.is_err());
    }

    // Test measured boot action variants
    mod action_variants {
        use super::*;

        #[test]
        fn test_push_action() {
            let action = MeasuredBootAction::Push {
                name: "test-policy".to_string(),
                file: "/path/to/policy.json".to_string(),
            };

            match action {
                MeasuredBootAction::Push { name, file } => {
                    assert_eq!(name, "test-policy");
                    assert_eq!(file, "/path/to/policy.json");
                }
                _ => panic!("Expected Push action"), //#[allow_ci]
            }
        }

        #[test]
        fn test_show_action() {
            let action = MeasuredBootAction::Show {
                name: "test-policy".to_string(),
            };

            match action {
                MeasuredBootAction::Show { name } => {
                    assert_eq!(name, "test-policy");
                }
                _ => panic!("Expected Show action"), //#[allow_ci]
            }
        }

        #[test]
        fn test_update_action() {
            let action = MeasuredBootAction::Update {
                name: "test-policy".to_string(),
                file: "/path/to/updated-policy.json".to_string(),
            };

            match action {
                MeasuredBootAction::Update { name, file } => {
                    assert_eq!(name, "test-policy");
                    assert_eq!(file, "/path/to/updated-policy.json");
                }
                _ => panic!("Expected Update action"), //#[allow_ci]
            }
        }

        #[test]
        fn test_delete_action() {
            let action = MeasuredBootAction::Delete {
                name: "test-policy".to_string(),
            };

            match action {
                MeasuredBootAction::Delete { name } => {
                    assert_eq!(name, "test-policy");
                }
                _ => panic!("Expected Delete action"), //#[allow_ci]
            }
        }
    }

    // Test policy file validation
    mod policy_validation {
        use super::*;

        #[test]
        fn test_valid_policy_structure() {
            let policy = json!({
                "pcrs": {
                    "0": "abc123",
                    "1": "def456"
                },
                "components": [
                    {
                        "name": "bootloader",
                        "hash": "sha256:abcdef"
                    }
                ]
            });

            // Verify policy structure
            assert!(policy["pcrs"].is_object());
            assert!(policy["components"].is_array());
            assert_eq!(policy["components"].as_array().unwrap().len(), 1); //#[allow_ci]
        }

        #[test]
        fn test_policy_with_different_pcrs() {
            let policy = json!({
                "pcrs": {
                    "0": "pcr0_value",
                    "1": "pcr1_value",
                    "2": "pcr2_value",
                    "3": "pcr3_value",
                    "7": "pcr7_value"
                }
            });

            let pcrs = policy["pcrs"].as_object().unwrap(); //#[allow_ci]
            assert_eq!(pcrs.len(), 5);
            assert_eq!(pcrs["0"], "pcr0_value");
            assert_eq!(pcrs["7"], "pcr7_value");
        }

        #[test]
        fn test_policy_with_multiple_components() {
            let policy = json!({
                "components": [
                    {
                        "name": "bootloader",
                        "hash": "sha256:bootloader_hash"
                    },
                    {
                        "name": "kernel",
                        "hash": "sha256:kernel_hash"
                    },
                    {
                        "name": "initrd",
                        "hash": "sha256:initrd_hash"
                    }
                ]
            });

            let components = policy["components"].as_array().unwrap(); //#[allow_ci]
            assert_eq!(components.len(), 3);
            assert_eq!(components[0]["name"], "bootloader");
            assert_eq!(components[1]["name"], "kernel");
            assert_eq!(components[2]["name"], "initrd");
        }

        #[test]
        fn test_policy_with_settings() {
            let policy = json!({
                "settings": {
                    "secure_boot": true,
                    "tpm_version": "2.0",
                    "expected_state": "trusted",
                    "allow_debug": false
                }
            });

            let settings = policy["settings"].as_object().unwrap(); //#[allow_ci]
            assert_eq!(settings["secure_boot"], true);
            assert_eq!(settings["tpm_version"], "2.0");
            assert_eq!(settings["expected_state"], "trusted");
            assert_eq!(settings["allow_debug"], false);
        }
    }

    // Test JSON response structures
    mod json_responses {
        use super::*;

        #[test]
        fn test_success_response_structure() {
            let response = json!({
                "status": "success",
                "message": "Measured boot policy 'test-policy' pushed successfully",
                "policy_name": "test-policy",
                "results": {
                    "verifier_response": "OK",
                    "policy_id": "12345"
                }
            });

            assert_eq!(response["status"], "success");
            assert_eq!(response["policy_name"], "test-policy");
            assert!(response["results"].is_object());
            assert!(response["message"]
                .as_str()
                .unwrap() //#[allow_ci]
                .contains("pushed successfully"));
        }

        #[test]
        fn test_list_response_structure() {
            // Test a simulated list response structure since List is not an action variant
            let response = json!({
                "status": "success",
                "message": "Listed 3 measured boot policies",
                "results": {
                    "policies": [
                        {
                            "name": "policy1",
                            "created": "2025-01-01T00:00:00Z"
                        },
                        {
                            "name": "policy2",
                            "created": "2025-01-02T00:00:00Z"
                        },
                        {
                            "name": "policy3",
                            "created": "2025-01-03T00:00:00Z"
                        }
                    ]
                }
            });

            assert_eq!(response["status"], "success");
            assert!(response["results"]["policies"].is_array());
            assert_eq!(
                response["results"]["policies"].as_array().unwrap().len(), //#[allow_ci]
                3
            );
        }

        #[test]
        fn test_error_response_structure() {
            let error = KeylimectlError::policy_not_found("missing-policy");
            let error_json = error.to_json();

            assert_eq!(error_json["error"]["code"], "POLICY_NOT_FOUND");
            assert_eq!(
                error_json["error"]["details"]["policy_name"],
                "missing-policy"
            );
        }
    }

    // Test error handling scenarios
    mod error_handling {
        use super::*;

        #[test]
        fn test_policy_not_found_error() {
            let error =
                KeylimectlError::policy_not_found("nonexistent-policy");

            match &error {
                KeylimectlError::PolicyNotFound { name } => {
                    assert_eq!(name, "nonexistent-policy");
                }
                _ => panic!("Expected PolicyNotFound error"), //#[allow_ci]
            }

            assert_eq!(error.error_code(), "POLICY_NOT_FOUND");
            assert!(!error.is_retryable());
        }

        #[test]
        fn test_validation_error() {
            let error = KeylimectlError::validation("Invalid policy format");

            assert_eq!(error.error_code(), "VALIDATION_ERROR");
            assert!(!error.is_retryable());
            assert!(error.to_string().contains("Invalid policy format"));
        }

        #[test]
        fn test_io_error_context() {
            use crate::error::ErrorContext;

            let io_error: Result<(), std::io::Error> =
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "file not found",
                ));

            let contextual_error = io_error.with_context(|| {
                "Failed to read measured boot policy file".to_string()
            });

            assert!(contextual_error.is_err());
            let error = contextual_error.unwrap_err();
            assert_eq!(error.error_code(), "GENERIC_ERROR");
        }
    }

    // Test file operations
    mod file_operations {
        use super::*;

        #[test]
        fn test_read_valid_policy_file() {
            let policy_file = create_test_policy_file()
                .expect("Failed to create test file");
            let file_path = policy_file.path().to_str().unwrap(); //#[allow_ci]

            // Test reading the file
            let content =
                fs::read_to_string(file_path).expect("Failed to read file");
            assert!(!content.is_empty());

            // Test parsing the content
            let parsed: Value =
                serde_json::from_str(&content).expect("Failed to parse JSON");
            assert!(parsed.is_object());
        }

        #[test]
        fn test_read_invalid_policy_file() {
            let invalid_file = create_invalid_policy_file()
                .expect("Failed to create invalid file");
            let file_path = invalid_file.path().to_str().unwrap(); //#[allow_ci]

            // Test reading the file succeeds
            let content =
                fs::read_to_string(file_path).expect("Failed to read file");
            assert!(!content.is_empty());

            // Test parsing the content fails
            let parse_result: Result<Value, _> =
                serde_json::from_str(&content);
            assert!(parse_result.is_err());
        }

        #[test]
        fn test_nonexistent_file() {
            let nonexistent_path = "/path/that/does/not/exist/policy.json";
            let read_result = fs::read_to_string(nonexistent_path);
            assert!(read_result.is_err());
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
        fn test_config_with_different_ports() {
            let mut config = create_test_config();
            config.verifier.port = 9001;

            assert_eq!(config.verifier_base_url(), "https://127.0.0.1:9001");
        }
    }

    // Test measured boot specific scenarios
    mod measured_boot_scenarios {

        #[test]
        fn test_policy_name_validation() {
            // Test valid policy names
            let valid_names = [
                "production-policy",
                "test_policy",
                "policy123",
                "secure-boot-v2",
                "minimal",
            ];

            for name in &valid_names {
                // Policy names should be non-empty strings
                assert!(!name.is_empty());
                assert!(name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
            }
        }

        #[test]
        fn test_pcr_value_formats() {
            // Test different PCR value formats
            let pcr_values = [
                "3a3f5c1f5b9e8f2a1d7e9b4a2c6f8e1d3a5b7c9e", // 40 chars (SHA-1)
                "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", // 64 chars (SHA-256)
                "0000000000000000000000000000000000000000", // All zeros
                "ffffffffffffffffffffffffffffffffffffffff", // All Fs
            ];

            for pcr_value in &pcr_values {
                assert!(!pcr_value.is_empty());
                assert!(pcr_value.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }

        #[test]
        fn test_hash_algorithm_formats() {
            let hash_formats = [
                "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha384:38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                "md5:d41d8cd98f00b204e9800998ecf8427e",
            ];

            for hash_format in &hash_formats {
                assert!(hash_format.contains(':'));
                let parts: Vec<&str> = hash_format.split(':').collect();
                assert_eq!(parts.len(), 2);

                let algorithm = parts[0];
                let hash_value = parts[1];

                assert!(!algorithm.is_empty());
                assert!(!hash_value.is_empty());
                assert!(hash_value.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
    }
}
