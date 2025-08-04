// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent reactivation command

use crate::client::factory;
use crate::commands::error::CommandError;
use crate::output::OutputHandler;
use serde_json::{json, Value};

/// Reactivate a failed agent
pub(super) async fn reactivate_agent(
    agent_id: &str,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    output.info(format!("Reactivating agent {agent_id}"));

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error("verifier", e.to_string())
    })?;
    let response =
        verifier_client
            .reactivate_agent(agent_id)
            .await
            .map_err(|e| {
                CommandError::resource_error(
                    "verifier",
                    format!("Failed to reactivate agent: {e}"),
                )
            })?;

    output.info(format!("Agent {agent_id} successfully reactivated"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_id} reactivated successfully"),
        "agent_id": agent_id,
        "results": response
    }))
}
