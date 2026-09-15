// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent status query command

#[cfg(feature = "api-v2")]
use crate::client::agent::AgentClient;
use crate::client::factory;
use crate::commands::error::CommandError;
#[cfg(feature = "api-v2")]
use crate::config::singleton::get_config;
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

    // Check agent directly for pull-model agents only.
    // Push-mode agents have ip=null and port=null in the verifier DB,
    // matching the Python verifier's is_push_mode_agent() logic.
    #[cfg(feature = "api-v2")]
    if !registrar_only {
        let verifier_data =
            results.get("verifier").and_then(|v| v.get("data"));

        // Determine push vs pull from verifier-stored ip/port.
        let is_push_mode = verifier_data.is_none_or(|data| {
            let ip_null = data.get("ip").is_none_or(|v| v.is_null());
            let port_null = data.get("port").is_none_or(|v| v.is_null());
            ip_null && port_null
        });

        if is_push_mode {
            results["agent"] = json!({
                "status": "not_applicable",
                "note": "Direct agent communication is not used with push model. \
                         Agent attestation status is managed by the verifier."
            });
            results["model"] = json!("push");
        } else {
            // Pull model: extract IP/port from verifier data for direct agent check.
            let agent_connection = verifier_data.and_then(|data| {
                let ip = data
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let port = data
                    .get("port")
                    .and_then(|v| v.as_u64().map(|p| p as u16));
                ip.zip(port)
            });

            if let Some((ip, port)) = agent_connection {
                results["model"] = json!("pull");
                output.progress("Checking agent status directly");

                match AgentClient::builder()
                    .agent_ip(&ip)
                    .agent_port(port)
                    .config(get_config())
                    .build()
                    .await
                {
                    Ok(agent_client) => {
                        match agent_client
                            .get_quote("test_connectivity")
                            .await
                        {
                            Ok(_) => {
                                results["agent"] = json!({
                                    "status": "responsive",
                                    "connection": format!("{ip}:{port}")
                                });
                            }
                            Err(e) => {
                                if e.to_string().contains("400")
                                    || e.to_string().contains("Bad Request")
                                {
                                    results["agent"] = json!({
                                        "status": "responsive",
                                        "connection": format!("{ip}:{port}"),
                                        "note": "Agent rejected test nonce (expected)"
                                    });
                                } else {
                                    results["agent"] = json!({
                                        "status": "unreachable",
                                        "connection": format!("{ip}:{port}"),
                                        "error": e.to_string()
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => {
                        results["agent"] = json!({
                            "status": "connection_failed",
                            "connection": format!("{ip}:{port}"),
                            "error": e.to_string()
                        });
                    }
                }
            }
        }
    }

    let result_map = results.as_object().expect("results is an object");
    let failed_statuses =
        ["error", "connection_failed", "not_found", "unreachable"];
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
