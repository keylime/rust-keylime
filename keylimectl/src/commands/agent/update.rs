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
/// update API, we implement this as: get existing config -> remove -> add with
/// merged config.
///
/// The remove step blocks until the agent is fully gone from the verifier,
/// handling the case where DELETE returns 202 (async deletion while an in-flight
/// attestation cycle is still completing). Only then is the agent re-added to
/// avoid a 409 Conflict.
pub(super) async fn update_agent(
    agent_id: &str,
    runtime_policy: Option<&str>,
    runtime_policy_name: Option<&str>,
    runtime_policy_sig_key: Option<&str>,
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
        CommandError::connection_error("registrar", e.to_string())
    })?;
    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::connection_error("verifier", e.to_string())
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
    let verifier_agent = verifier_client
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

    // Determine if agent is using push model from verifier data.
    // The verifier stores ip=null and port=null for push-mode agents
    // (matching Python verifier's is_push_mode_agent() logic).
    let verifier_ip_is_null = verifier_agent
        .pointer("/results/ip")
        .is_none_or(|v| v.is_null());
    let verifier_port_is_null = verifier_agent
        .pointer("/results/port")
        .is_none_or(|v| v.is_null());
    let existing_push_model = verifier_ip_is_null && verifier_port_is_null;

    // Extract existing configuration from registrar.
    // Push-model agents may not have a reachable IP/port, so use
    // defaults when the registrar data is missing or empty.
    let existing_ip = registrar_agent["ip"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("0.0.0.0");
    let existing_port = registrar_agent["port"].as_u64().unwrap_or(0);

    // Step 2: Remove existing agent; blocks until fully gone (handles 202)
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
            runtime_policy_name,
            runtime_policy_sig_key,
            mb_policy, // Use new policy if provided, otherwise will use default
            payload: None, // Payload updates not supported in update operation
            cert_dir: None, // Use default cert handling
            verify: false, // Skip verification during update
            push_model: existing_push_model, // Preserve existing model
            pull_model: false, // Let auto-detection handle it
            tpm_policy: None, // Use default policy during update
            allow_unverified_quote: false, // Do not bypass quote verification during update
            wait_for_attestation: false,   // Don't wait during update
            attestation_timeout: 60,
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
