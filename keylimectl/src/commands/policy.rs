// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Runtime policy management commands

use crate::client::verifier::VerifierClient;
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::PolicyAction;
use log::debug;
use serde_json::{json, Value};
use std::fs;

/// Execute a policy command
pub async fn execute(
    action: &PolicyAction,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        PolicyAction::Create { name, file } => {
            create_policy(name, file, config, output).await
        }
        PolicyAction::Show { name } => {
            show_policy(name, config, output).await
        }
        PolicyAction::Update { name, file } => {
            update_policy(name, file, config, output).await
        }
        PolicyAction::Delete { name } => {
            delete_policy(name, config, output).await
        }
    }
}

/// Create a new runtime policy
async fn create_policy(
    name: &str,
    file_path: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Creating runtime policy '{name}'"));

    // Load policy from file
    let policy_content =
        fs::read_to_string(file_path).with_context(|| {
            format!("Failed to read policy file: {file_path}")
        })?;

    // Parse policy content (basic validation)
    let _policy_json: Value = serde_json::from_str(&policy_content)
        .with_context(|| {
            format!("Failed to parse policy as JSON: {file_path}")
        })?;

    debug!(
        "Loaded policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    let policy_data = json!({
        "runtime_policy": policy_content,
        // TODO: Add other policy-related fields as needed
    });

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .add_runtime_policy(name, policy_data)
        .await
        .with_context(|| {
            format!("Failed to create runtime policy '{name}'")
        })?;

    output.info(format!("Runtime policy '{name}' created successfully"));

    Ok(json!({
        "status": "success",
        "message": format!("Runtime policy '{name}' created successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// Show a runtime policy
async fn show_policy(
    name: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Retrieving runtime policy '{name}'"));

    let verifier_client = VerifierClient::new(config)?;
    let policy = verifier_client
        .get_runtime_policy(name)
        .await
        .with_context(|| {
            format!("Failed to retrieve runtime policy '{name}'")
        })?;

    match policy {
        Some(policy_data) => Ok(json!({
            "policy_name": name,
            "results": policy_data
        })),
        None => Err(KeylimectlError::policy_not_found(name)),
    }
}

/// Update an existing runtime policy
async fn update_policy(
    name: &str,
    file_path: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Updating runtime policy '{name}'"));

    // Load policy from file
    let policy_content =
        fs::read_to_string(file_path).with_context(|| {
            format!("Failed to read policy file: {file_path}")
        })?;

    // Parse policy content (basic validation)
    let _policy_json: Value = serde_json::from_str(&policy_content)
        .with_context(|| {
            format!("Failed to parse policy as JSON: {file_path}")
        })?;

    debug!(
        "Loaded policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    let policy_data = json!({
        "runtime_policy": policy_content,
        // TODO: Add other policy-related fields as needed
    });

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .update_runtime_policy(name, policy_data)
        .await
        .with_context(|| {
            format!("Failed to update runtime policy '{name}'")
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
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Deleting runtime policy '{name}'"));

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .delete_runtime_policy(name)
        .await
        .with_context(|| {
            format!("Failed to delete runtime policy '{name}'")
        })?;

    output.info(format!("Runtime policy '{name}' deleted successfully"));

    Ok(json!({
        "status": "success",
        "message": format!("Runtime policy '{name}' deleted successfully"),
        "policy_name": name,
        "results": response
    }))
}
