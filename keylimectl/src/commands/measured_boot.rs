// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Measured boot policy management commands

use crate::client::verifier::VerifierClient;
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::MeasuredBootAction;
use log::debug;
use serde_json::{json, Value};
use std::fs;

/// Execute a measured boot policy command
pub async fn execute(
    action: &MeasuredBootAction,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        MeasuredBootAction::Create { name, file } => {
            create_mb_policy(name, file, config, output).await
        }
        MeasuredBootAction::Show { name } => {
            show_mb_policy(name, config, output).await
        }
        MeasuredBootAction::Update { name, file } => {
            update_mb_policy(name, file, config, output).await
        }
        MeasuredBootAction::Delete { name } => {
            delete_mb_policy(name, config, output).await
        }
    }
}

/// Create a new measured boot policy
async fn create_mb_policy(
    name: &str,
    file_path: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Creating measured boot policy '{name}'"));

    // Load policy from file
    let policy_content =
        fs::read_to_string(file_path).with_context(|| {
            format!("Failed to read measured boot policy file: {file_path}")
        })?;

    // Parse policy content (basic validation)
    let _policy_json: Value = serde_json::from_str(&policy_content)
        .with_context(|| {
            format!(
                "Failed to parse measured boot policy as JSON: {}",
                file_path
            )
        })?;

    debug!(
        "Loaded measured boot policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    let policy_data = json!({
        "mb_policy": policy_content,
        // TODO: Add other measured boot policy-related fields as needed
    });

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .add_mb_policy(name, policy_data)
        .await
        .with_context(|| {
            format!("Failed to create measured boot policy '{name}'")
        })?;

    output.info(format!(
        "Measured boot policy '{}' created successfully",
        name
    ));

    Ok(json!({
        "status": "success",
        "message": format!("Measured boot policy '{name}' created successfully"),
        "policy_name": name,
        "results": response
    }))
}

/// Show a measured boot policy
async fn show_mb_policy(
    name: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Retrieving measured boot policy '{name}'"));

    let verifier_client = VerifierClient::new(config)?;
    let policy =
        verifier_client.get_mb_policy(name).await.with_context(|| {
            format!("Failed to retrieve measured boot policy '{name}'")
        })?;

    match policy {
        Some(policy_data) => Ok(json!({
            "policy_name": name,
            "results": policy_data
        })),
        None => Err(KeylimectlError::policy_not_found(name)),
    }
}

/// Update an existing measured boot policy
async fn update_mb_policy(
    name: &str,
    file_path: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Updating measured boot policy '{name}'"));

    // Load policy from file
    let policy_content =
        fs::read_to_string(file_path).with_context(|| {
            format!("Failed to read measured boot policy file: {file_path}")
        })?;

    // Parse policy content (basic validation)
    let _policy_json: Value = serde_json::from_str(&policy_content)
        .with_context(|| {
            format!(
                "Failed to parse measured boot policy as JSON: {}",
                file_path
            )
        })?;

    debug!(
        "Loaded measured boot policy from {}: {} bytes",
        file_path,
        policy_content.len()
    );

    // Create policy data structure for the API
    let policy_data = json!({
        "mb_policy": policy_content,
        // TODO: Add other measured boot policy-related fields as needed
    });

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .update_mb_policy(name, policy_data)
        .await
        .with_context(|| {
            format!("Failed to update measured boot policy '{name}'")
        })?;

    output.info(format!(
        "Measured boot policy '{}' updated successfully",
        name
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
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info(format!("Deleting measured boot policy '{name}'"));

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .delete_mb_policy(name)
        .await
        .with_context(|| {
            format!("Failed to delete measured boot policy '{name}'")
        })?;

    output.info(format!(
        "Measured boot policy '{}' deleted successfully",
        name
    ));

    Ok(json!({
        "status": "success",
        "message": format!("Measured boot policy '{name}' deleted successfully"),
        "policy_name": name,
        "results": response
    }))
}
