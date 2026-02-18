// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent status query command

#[cfg(feature = "api-v2")]
use crate::client::agent::AgentClient;
use crate::client::factory;
use crate::commands::error::CommandError;
#[cfg(feature = "api-v2")]
use crate::config::singleton::get_config;
use crate::output::OutputHandler;
use serde_json::{json, Value};

/// Get agent status from verifier and/or registrar
pub(super) async fn get_agent_status(
    agent_id: &str,
    verifier_only: bool,
    registrar_only: bool,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    output.info(format!("Getting status for agent {agent_id}"));

    let mut results = json!({});

    // Get status from registrar (unless verifier_only is set)
    if !verifier_only {
        output.progress("Checking registrar status");

        let registrar_client =
            factory::get_registrar().await.map_err(|e| {
                CommandError::resource_error("registrar", e.to_string())
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
            CommandError::resource_error("verifier", e.to_string())
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

    // Check agent directly if API < 3.0 and we have connection details
    // This is only applicable for pull model (api-v2)
    #[cfg(feature = "api-v2")]
    if !registrar_only {
        // Extract IP and port from results (clone to avoid borrow conflicts)
        let agent_connection = {
            let registrar_data =
                results.get("registrar").and_then(|r| r.get("data"));
            let verifier_data =
                results.get("verifier").and_then(|v| v.get("data"));
            match (registrar_data, verifier_data) {
                (Some(reg), Some(ver)) => {
                    let ip = ver
                        .get("ip")
                        .or_else(|| reg.get("ip"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let port = ver
                        .get("port")
                        .or_else(|| reg.get("port"))
                        .and_then(|v| v.as_u64().map(|p| p as u16));
                    ip.zip(port)
                }
                _ => None,
            }
        };

        if let Some((ip, port)) = agent_connection {
            let verifier_client =
                factory::get_verifier().await.map_err(|e| {
                    CommandError::resource_error("verifier", e.to_string())
                })?;
            let api_version =
                verifier_client.api_version().parse::<f32>().unwrap_or(2.1);

            if api_version < 3.0 {
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
            } else {
                results["agent"] = json!({
                    "status": "not_applicable",
                    "note": "Direct agent communication is not used with push model (API >= 3.0). \
                             Agent attestation status is managed by the verifier."
                });
                results["model"] = json!("push");
            }
        }
    }

    Ok(json!({
        "agent_id": agent_id,
        "results": results
    }))
}
