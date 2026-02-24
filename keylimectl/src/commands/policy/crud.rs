// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Runtime policy CRUD operations (verifier-side management).
//!
//! This module handles push, show, update, and delete operations for
//! runtime policies stored on the Keylime verifier.

use crate::client::factory;
use crate::commands::error::CommandError;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::PolicyAction;
use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use chrono;
use log::debug;
use serde_json::{json, Value};
use std::fs;

/// Execute a runtime policy CRUD command.
pub async fn execute(
    action: &PolicyAction,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        PolicyAction::List => list_runtime_policies(output).await,
        PolicyAction::Push { name, file } => push_policy(name, file, output)
            .await
            .map_err(KeylimectlError::from),
        PolicyAction::Show { name } => show_policy(name, output)
            .await
            .map_err(KeylimectlError::from),
        PolicyAction::Update { name, file } => {
            update_policy(name, file, output)
                .await
                .map_err(KeylimectlError::from)
        }
        PolicyAction::Delete { name } => delete_policy(name, output)
            .await
            .map_err(KeylimectlError::from),
        // Non-CRUD actions are handled by the parent module
        _ => unreachable!(
            "Non-CRUD policy actions should be dispatched by the parent module"
        ),
    }
}

/// Push a runtime policy to the verifier
async fn push_policy(
    name: &str,
    file_path: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Pushing runtime policy '{name}'"));

    // Load policy from file
    let policy_content = fs::read_to_string(file_path).map_err(|e| {
        CommandError::policy_file_error(
            file_path,
            format!("Failed to read policy file: {e}"),
        )
    })?;

    // Parse policy content (basic validation)
    let _policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse policy as JSON: {e}"),
            )
        })?;

    debug!(
        "Loaded policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    // Parse the policy to extract metadata and validate structure
    let policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse policy as JSON: {e}"),
            )
        })?;

    // Extract policy metadata for enhanced API payload
    // Note: The verifier expects runtime_policy to be base64-encoded
    let encoded_policy = Base64.encode(policy_content.as_bytes());
    let mut policy_data = json!({
        "runtime_policy": encoded_policy,
        "policy_type": "runtime",
        "format_version": "1.0",
        "upload_timestamp": chrono::Utc::now().to_rfc3339()
    });

    // Add metadata based on policy content structure
    if let Some(allowlist) =
        policy_json.get("allowlist").and_then(|v| v.as_array())
    {
        policy_data["allowlist_count"] = json!(allowlist.len());
    }

    if let Some(exclude) =
        policy_json.get("exclude").and_then(|v| v.as_array())
    {
        policy_data["exclude_count"] = json!(exclude.len());
    }

    if let Some(ima) = policy_json.get("ima") {
        policy_data["ima_enabled"] = json!(true);
        if let Some(require_sigs) = ima.get("require_signatures") {
            policy_data["ima_require_signatures"] = require_sigs.clone();
        }
    } else {
        policy_data["ima_enabled"] = json!(false);
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
        .add_runtime_policy(name, policy_data)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to push runtime policy '{name}': {e}"),
            )
        })?;

    output.info(format!("Runtime policy '{name}' pushed successfully"));

    Ok(json!({
        "status": "success",
        "message": format!("Runtime policy '{name}' pushed successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// Show a runtime policy
async fn show_policy(
    name: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Retrieving runtime policy '{name}'"));

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to connect to verifier: {e}"),
        )
    })?;
    let policy =
        verifier_client
            .get_runtime_policy(name)
            .await
            .map_err(|e| {
                CommandError::resource_error(
                    "verifier",
                    format!(
                        "Failed to retrieve runtime policy '{name}': {e}"
                    ),
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

/// Update an existing runtime policy
async fn update_policy(
    name: &str,
    file_path: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Updating runtime policy '{name}'"));

    // Load policy from file
    let policy_content = fs::read_to_string(file_path).map_err(|e| {
        CommandError::policy_file_error(
            file_path,
            format!("Failed to read policy file: {e}"),
        )
    })?;

    // Parse policy content (basic validation)
    let _policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse policy as JSON: {e}"),
            )
        })?;

    debug!(
        "Loaded policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    // Parse the policy to extract metadata and validate structure
    let policy_json: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                file_path,
                format!("Failed to parse policy as JSON: {e}"),
            )
        })?;

    // Extract policy metadata for enhanced API payload
    // Note: The verifier expects runtime_policy to be base64-encoded
    let encoded_policy = Base64.encode(policy_content.as_bytes());
    let mut policy_data = json!({
        "runtime_policy": encoded_policy,
        "policy_type": "runtime",
        "format_version": "1.0",
        "update_timestamp": chrono::Utc::now().to_rfc3339()
    });

    // Add metadata based on policy content structure
    if let Some(allowlist) =
        policy_json.get("allowlist").and_then(|v| v.as_array())
    {
        policy_data["allowlist_count"] = json!(allowlist.len());
    }

    if let Some(exclude) =
        policy_json.get("exclude").and_then(|v| v.as_array())
    {
        policy_data["exclude_count"] = json!(exclude.len());
    }

    if let Some(ima) = policy_json.get("ima") {
        policy_data["ima_enabled"] = json!(true);
        if let Some(require_sigs) = ima.get("require_signatures") {
            policy_data["ima_require_signatures"] = require_sigs.clone();
        }
    } else {
        policy_data["ima_enabled"] = json!(false);
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
        .update_runtime_policy(name, policy_data)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to update runtime policy '{name}': {e}"),
            )
        })?;

    output.info(format!("Runtime policy '{name}' updated successfully"));

    Ok(json!({
        "status": "success",
        "message": format!("Runtime policy '{name}' updated successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// Delete a runtime policy
async fn delete_policy(
    name: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!("Deleting runtime policy '{name}'"));

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error(
            "verifier",
            format!("Failed to connect to verifier: {e}"),
        )
    })?;
    let response = verifier_client
        .delete_runtime_policy(name)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to delete runtime policy '{name}': {e}"),
            )
        })?;

    output.info(format!("Runtime policy '{name}' deleted successfully"));

    Ok(json!({
        "status": "success",
        "message": format!("Runtime policy '{name}' deleted successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// List runtime policies from the verifier
async fn list_runtime_policies(
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info("Listing runtime policies");

    let verifier_client = factory::get_verifier().await?;
    let policies = verifier_client
        .list_runtime_policies()
        .await
        .with_context(|| {
            "Failed to list runtime policies from verifier".to_string()
        })?;

    Ok(policies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CliOverrides, ClientConfig, Config, RegistrarConfig, TlsConfig,
        VerifierConfig,
    };
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Create a test configuration for runtime policy operations
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
    fn create_test_output() -> OutputHandler {
        OutputHandler::new(
            crate::OutputFormat::Json,
            true,
            crate::ColorMode::Never,
        ) // Quiet mode for tests
    }

    /// Create a test runtime policy file
    fn create_test_policy_file() -> Result<NamedTempFile, std::io::Error> {
        let mut file = NamedTempFile::new()?;
        let policy_content = json!({
            "allowlist": [
                {
                    "path": "/usr/bin/bash",
                    "hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                },
                {
                    "path": "/lib/x86_64-linux-gnu/libc.so.6",
                    "hash": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                },
                {
                    "path": "/usr/sbin/sshd",
                    "hash": "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
                }
            ],
            "exclude": [
                "/tmp/*",
                "/var/cache/*",
                "/proc/*",
                "/sys/*"
            ],
            "ima": {
                "require_signatures": true,
                "allowed_keyrings": ["builtin_trusted_keys", "_ima"],
                "fail_action": "log"
            },
            "meta": {
                "version": "1.0",
                "description": "Test runtime policy for web server",
                "created": "2025-01-01T00:00:00Z"
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

        assert!(parsed["allowlist"].is_array());
        assert!(parsed["exclude"].is_array());
        assert!(parsed["ima"].is_object());
        assert_eq!(parsed["ima"]["require_signatures"], true);
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

    // Test policy action variants
    mod action_variants {
        use super::*;

        #[test]
        fn test_push_action() {
            let action = PolicyAction::Push {
                name: "test-policy".to_string(),
                file: "/path/to/policy.json".to_string(),
            };

            match action {
                PolicyAction::Push { name, file } => {
                    assert_eq!(name, "test-policy");
                    assert_eq!(file, "/path/to/policy.json");
                }
                _ => panic!("Expected Push action"), //#[allow_ci]
            }
        }

        #[test]
        fn test_show_action() {
            let action = PolicyAction::Show {
                name: "test-policy".to_string(),
            };

            match action {
                PolicyAction::Show { name } => {
                    assert_eq!(name, "test-policy");
                }
                _ => panic!("Expected Show action"), //#[allow_ci]
            }
        }

        #[test]
        fn test_update_action() {
            let action = PolicyAction::Update {
                name: "test-policy".to_string(),
                file: "/path/to/updated-policy.json".to_string(),
            };

            match action {
                PolicyAction::Update { name, file } => {
                    assert_eq!(name, "test-policy");
                    assert_eq!(file, "/path/to/updated-policy.json");
                }
                _ => panic!("Expected Update action"), //#[allow_ci]
            }
        }

        #[test]
        fn test_delete_action() {
            let action = PolicyAction::Delete {
                name: "test-policy".to_string(),
            };

            match action {
                PolicyAction::Delete { name } => {
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
        fn test_valid_allowlist_structure() {
            let policy = json!({
                "allowlist": [
                    {
                        "path": "/bin/ls",
                        "hash": "sha256:abc123"
                    },
                    {
                        "path": "/usr/bin/cat",
                        "hash": "sha256:def456"
                    }
                ]
            });

            // Verify policy structure
            assert!(policy["allowlist"].is_array());
            let allowlist = policy["allowlist"].as_array().unwrap(); //#[allow_ci]
            assert_eq!(allowlist.len(), 2);
            assert_eq!(allowlist[0]["path"], "/bin/ls");
            assert_eq!(allowlist[1]["hash"], "sha256:def456");
        }

        #[test]
        fn test_exclude_patterns() {
            let policy = json!({
                "exclude": [
                    "/tmp/*",
                    "/var/log/*",
                    "/proc/*",
                    "/sys/*",
                    "*.pyc",
                    "*.swp"
                ]
            });

            let excludes = policy["exclude"].as_array().unwrap(); //#[allow_ci]
            assert_eq!(excludes.len(), 6);
            assert_eq!(excludes[0], "/tmp/*");
            assert_eq!(excludes[4], "*.pyc");
        }

        #[test]
        fn test_ima_configuration() {
            let policy = json!({
                "ima": {
                    "require_signatures": true,
                    "allowed_keyrings": ["builtin_trusted_keys", "_ima", "custom_keyring"],
                    "fail_action": "log",
                    "hash_algorithm": "sha256"
                }
            });

            let ima = policy["ima"].as_object().unwrap(); //#[allow_ci]
            assert_eq!(ima["require_signatures"], true);
            assert_eq!(ima["fail_action"], "log");
            assert_eq!(ima["hash_algorithm"], "sha256");

            let keyrings = ima["allowed_keyrings"].as_array().unwrap(); //#[allow_ci]
            assert_eq!(keyrings.len(), 3);
            assert!(keyrings.contains(&json!("builtin_trusted_keys")));
        }

        #[test]
        fn test_complex_policy_structure() {
            let policy = json!({
                "allowlist": [
                    {
                        "path": "/usr/bin/python3",
                        "hash": "sha256:python_hash",
                        "flags": ["executable"]
                    }
                ],
                "exclude": ["/tmp/*"],
                "ima": {
                    "require_signatures": false,
                    "allowed_keyrings": ["_ima"]
                },
                "meta": {
                    "version": "2.1",
                    "description": "Production policy for Python applications",
                    "environment": "production"
                }
            });

            // Verify all sections exist
            assert!(policy["allowlist"].is_array());
            assert!(policy["exclude"].is_array());
            assert!(policy["ima"].is_object());
            assert!(policy["meta"].is_object());

            // Verify specific values
            assert_eq!(policy["meta"]["version"], "2.1");
            assert_eq!(policy["ima"]["require_signatures"], false);
        }
    }

    // Test JSON response structures
    mod json_responses {
        use super::*;

        #[test]
        fn test_success_response_structure() {
            let response = json!({
                "status": "success",
                "message": "Runtime policy 'test-policy' pushed successfully",
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
        fn test_policy_show_response() {
            let response = json!({
                "policy_name": "web-server-policy",
                "results": {
                    "policy": {
                        "allowlist": [
                            {
                                "path": "/usr/bin/nginx",
                                "hash": "sha256:nginx_hash"
                            }
                        ],
                        "exclude": ["/var/log/*"],
                        "ima": {
                            "require_signatures": true
                        }
                    },
                    "metadata": {
                        "created": "2025-01-01T12:00:00Z",
                        "last_modified": "2025-01-02T14:30:00Z"
                    }
                }
            });

            assert_eq!(response["policy_name"], "web-server-policy");
            assert!(response["results"]["policy"].is_object());
            assert!(response["results"]["metadata"].is_object());
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
                "Failed to read runtime policy file".to_string()
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

    // Test base64 encoding of policy data
    mod base64_encoding {
        #[test]
        fn test_policy_content_is_base64_encoded() {
            use base64::{
                engine::general_purpose::STANDARD as Base64, Engine,
            };

            let policy_content = r#"{"allowlist": [{"path": "/bin/ls"}]}"#;
            let encoded_policy = Base64.encode(policy_content.as_bytes());

            // Verify it's base64 encoded
            assert!(!encoded_policy.contains("{"));
            assert!(!encoded_policy.contains("}"));
            assert!(!encoded_policy.contains("allowlist"));

            // Verify it can be decoded back
            let decoded = Base64.decode(&encoded_policy).unwrap(); //#[allow_ci]
            let decoded_str = String::from_utf8(decoded).unwrap(); //#[allow_ci]
            assert_eq!(decoded_str, policy_content);
        }

        #[test]
        fn test_base64_roundtrip() {
            use base64::{
                engine::general_purpose::STANDARD as Base64, Engine,
            };

            let original = r#"{"ima": {"require_signatures": true}}"#;
            let encoded = Base64.encode(original.as_bytes());
            let decoded = Base64.decode(&encoded).unwrap(); //#[allow_ci]
            let result = String::from_utf8(decoded).unwrap(); //#[allow_ci]

            assert_eq!(original, result);
        }
    }

    // Test runtime policy specific scenarios
    mod runtime_policy_scenarios {

        #[test]
        fn test_policy_name_validation() {
            // Test valid policy names
            let valid_names = [
                "production-policy",
                "dev_environment",
                "policy123",
                "web-server-v2",
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
        fn test_hash_formats() {
            // Test different hash formats used in allowlists
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

        #[test]
        fn test_path_patterns() {
            // Test different path patterns used in allowlists and excludes
            let path_patterns = [
                "/usr/bin/bash",
                "/lib/x86_64-linux-gnu/libc.so.6",
                "/tmp/*",
                "/var/cache/*",
                "*.pyc",
                "*.tmp",
                "/proc/*/stat",
                "/sys/devices/*/*",
            ];

            for pattern in &path_patterns {
                assert!(!pattern.is_empty());
                // All patterns should start with / or *
                assert!(pattern.starts_with('/') || pattern.starts_with('*'));
            }
        }

        #[test]
        fn test_ima_keyring_names() {
            // Test valid IMA keyring names
            let keyring_names = [
                "builtin_trusted_keys",
                "_ima",
                "_evm",
                "custom_keyring",
                "platform_keyring",
            ];

            for keyring in &keyring_names {
                assert!(!keyring.is_empty());
                // Keyring names should contain only alphanumeric, underscore, or hyphen
                assert!(keyring
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-'));
            }
        }
    }
}
