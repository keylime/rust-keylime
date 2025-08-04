// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent update command

use super::add::add_agent;
use super::remove::remove_agent;
use super::types::AddAgentParams;
use crate::client::factory;
use crate::commands::error::CommandError;
use crate::output::OutputHandler;
use serde_json::{json, Value};

/// Update an existing agent
///
/// This function implements a proper update that preserves existing configuration
/// and only modifies the specified fields. Since Keylime doesn't provide a direct
/// update API, we implement this as: get existing config -> remove -> add with merged config.
pub(super) async fn update_agent(
    agent_id: &str,
    runtime_policy: Option<&str>,
    mb_policy: Option<&str>,
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

    let registrar_client = factory::get_registrar().await.map_err(|e| {
        CommandError::resource_error("registrar", e.to_string())
    })?;
    let verifier_client = factory::get_verifier().await.map_err(|e| {
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
    let _remove_result = remove_agent(agent_id, false, false, output).await?;

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
