// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent status query command

use crate::client::agent::AgentClient;
use crate::client::factory;
use crate::commands::error::CommandError;
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
    if !registrar_only {
        if let (Some(registrar_data), Some(verifier_data)) = (
            results.get("registrar").and_then(|r| r.get("data")),
            results.get("verifier").and_then(|v| v.get("data")),
        ) {
            // Extract agent IP and port
            let agent_ip = verifier_data
                .get("ip")
                .or_else(|| registrar_data.get("ip"))
                .and_then(|ip| ip.as_str());

            let agent_port = verifier_data
                .get("port")
                .or_else(|| registrar_data.get("port"))
                .and_then(|port| port.as_u64().map(|p| p as u16));

            if let (Some(ip), Some(port)) = (agent_ip, agent_port) {
                // Check if we should try direct agent communication
                let verifier_client =
                    factory::get_verifier().await.map_err(|e| {
                        CommandError::resource_error(
                            "verifier",
                            e.to_string(),
                        )
                    })?;
                let api_version = verifier_client
                    .api_version()
                    .parse::<f32>()
                    .unwrap_or(2.1);

                if api_version < 3.0 {
                    output.progress("Checking agent status directly");

                    match AgentClient::builder()
                        .agent_ip(ip)
                        .agent_port(port)
                        .config(get_config())
                        .build()
                        .await
                    {
                        Ok(agent_client) => {
                            // Try a simple test request to check if agent is responsive
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
                                    // Check if it's a 400 error (bad nonce) which means agent is up
                                    if e.to_string().contains("400")
                                        || e.to_string()
                                            .contains("Bad Request")
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
                        "note": "Direct agent communication not used in API >= 3.0"
                    });
                }
            }
        }
    }

    Ok(json!({
        "agent_id": agent_id,
        "results": results
    }))
}
