// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent removal command

use crate::client::factory;
use crate::commands::error::CommandError;
use crate::output::OutputHandler;
use log::{debug, warn};
use serde_json::{json, Value};

/// Remove an agent from the verifier (and optionally registrar)
pub(super) async fn remove_agent(
    agent_id: &str,
    registrar: bool,
    force: bool,
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

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error("verifier", e.to_string())
    })?;

    // Check if agent exists on verifier (unless force is used)
    if !force {
        output.step(
            1,
            if registrar { 3 } else { 2 },
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
    let total_steps = if registrar {
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
    if registrar {
        output.step(
            total_steps,
            total_steps,
            "Removing agent from registrar",
        );

        let registrar_client =
            factory::get_registrar().await.map_err(|e| {
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
