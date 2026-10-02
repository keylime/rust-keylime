// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent status query command

use crate::client::factory;
use crate::commands::error::CommandError;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use serde_json::{json, Value};

/// Get agent status from verifier and/or registrar
pub(super) async fn get_agent_status(
    agent_id: &str,
    verifier: bool,
    registrar_only: bool,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(KeylimectlError::validation("Agent ID cannot be empty"));
    }

    output.info(format!("Getting status for agent {agent_id}"));

    let mut results = json!({});

    // Get status from registrar (unless verifier is set)
    if !verifier {
        output.progress("Checking registrar status");

        let registrar_client =
            factory::get_registrar().await.map_err(|e| {
                CommandError::connection_error("registrar", e.to_string())
            })?;
        match registrar_client.get_agent(agent_id).await {
            Ok(Some(agent_data)) => {
                results["registrar"] = json!({
                    "status": "found",
                    "data": agent_data
                });
            }
            Ok(None) => {
                results["registrar"] = json!({
                    "status": "not_found"
                });
            }
            Err(e) => {
                results["registrar"] = json!({
                    "status": "error",
                    "error": e.to_string()
                });
            }
        }
    }

    // Get status from verifier (unless registrar_only is set)
    if !registrar_only {
        output.progress("Checking verifier status");

        let verifier_client = factory::get_verifier().await.map_err(|e| {
            CommandError::connection_error("verifier", e.to_string())
        })?;
        match verifier_client.get_agent(agent_id).await {
            Ok(Some(agent_data)) => {
                results["verifier"] = json!({
                    "status": "found",
                    "data": agent_data
                });
            }
            Ok(None) => {
                results["verifier"] = json!({
                    "status": "not_found"
                });
            }
            Err(e) => {
                results["verifier"] = json!({
                    "status": "error",
                    "error": e.to_string()
                });
            }
        }
    }

    // Determine agent model (push vs pull) from verifier data.
    // Push-mode agents have ip=null and port=null in the verifier DB,
    // matching the Python verifier's is_push_mode_agent() logic.
    // Direct agent contact is not performed: the verifier's attestation_status,
    // last_received_quote, and last_successful_attestation fields provide
    // authoritative liveness information without requiring mTLS client certificates.
    if !registrar_only {
        let verifier_data =
            results.get("verifier").and_then(|v| v.get("data"));

        let is_push_mode = verifier_data.is_none_or(|data| {
            let ip_null = data.get("ip").is_none_or(|v| v.is_null());
            let port_null = data.get("port").is_none_or(|v| v.is_null());
            ip_null && port_null
        });

        results["model"] = if is_push_mode {
            json!("push")
        } else {
            json!("pull")
        };
    }

    let result_map = results.as_object().expect("results is an object");
    let failed_statuses = ["error", "not_found"];
    let any_failed = result_map.values().any(|v| {
        v.get("status")
            .and_then(|s| s.as_str())
            .is_some_and(|s| failed_statuses.contains(&s))
    });

    if any_failed {
        return Err(KeylimectlError::validation_failed(
            format!("Agent {agent_id} status check found issues"),
            json!({
                "agent_id": agent_id,
                "results": results
            }),
        ));
    }

    Ok(json!({
        "agent_id": agent_id,
        "results": results
    }))
}
