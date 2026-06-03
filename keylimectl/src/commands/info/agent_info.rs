// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Per-agent diagnostic information.
//!
//! Combines verifier and registrar data into a unified diagnostic view.
//! Each query is independent — one failing does not prevent others.

#[cfg(feature = "api-v2")]
use crate::client::agent::AgentClient;
use crate::client::factory;
#[cfg(feature = "api-v2")]
use crate::config::singleton::get_config;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use log::debug;
use serde_json::{json, Value};

/// Execute the `info agent <AGENT_ID>` subcommand.
pub async fn execute(
    agent_id: &str,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    if agent_id.is_empty() {
        return Err(KeylimectlError::Validation(
            "Agent ID cannot be empty".into(),
        ));
    }

    output.progress(format!("Gathering diagnostics for agent {agent_id}"));

    let mut result = json!({
        "agent_id": agent_id,
    });

    // Query registrar
    let registrar_data = query_registrar(agent_id, output).await;
    result["registrar"] = registrar_data;

    // Query verifier
    let verifier_data = query_verifier(agent_id, output).await;
    result["verifier"] = verifier_data;

    // Build summary from collected data
    result["summary"] = build_summary(&result);

    // Attempt direct agent contact for pull model (api-v2)
    result["agent_direct"] = query_agent_direct(&result, output).await;

    Ok(result)
}

/// Query registrar for agent data.
async fn query_registrar(agent_id: &str, output: &OutputHandler) -> Value {
    output.progress("Querying registrar");
    match factory::get_registrar().await {
        Ok(client) => match client.get_agent(agent_id).await {
            Ok(Some(data)) => json!({
                "status": "found",
                "data": data,
            }),
            Ok(None) => json!({
                "status": "not_found",
            }),
            Err(e) => {
                debug!("Registrar query error: {e}");
                json!({
                    "status": "error",
                    "error": e.to_string(),
                })
            }
        },
        Err(e) => {
            debug!("Failed to connect to registrar: {e}");
            json!({
                "status": "unreachable",
                "error": e.to_string(),
            })
        }
    }
}

/// Query verifier for agent data.
async fn query_verifier(agent_id: &str, output: &OutputHandler) -> Value {
    output.progress("Querying verifier");
    match factory::get_verifier().await {
        Ok(client) => match client.get_agent(agent_id).await {
            Ok(Some(data)) => json!({
                "status": "found",
                "data": data,
            }),
            Ok(None) => json!({
                "status": "not_found",
            }),
            Err(e) => {
                debug!("Verifier query error: {e}");
                json!({
                    "status": "error",
                    "error": e.to_string(),
                })
            }
        },
        Err(e) => {
            debug!("Failed to connect to verifier: {e}");
            json!({
                "status": "unreachable",
                "error": e.to_string(),
            })
        }
    }
}

/// Build a summary from collected verifier and registrar data.
fn build_summary(result: &Value) -> Value {
    let registered = result["registrar"]["status"].as_str() == Some("found");
    let monitored = result["verifier"]["status"].as_str() == Some("found");

    let operational_state = result["verifier"]["data"]
        .get("operational_state")
        .and_then(|v| v.as_str())
        .or_else(|| {
            result["verifier"]["data"]
                .get("operational_state_description")
                .and_then(|v| v.as_str())
        });

    let mut summary = json!({
        "registered": registered,
        "monitored": monitored,
    });

    if let Some(state) = operational_state {
        summary["operational_state"] = Value::String(state.to_string());
    }

    summary
}

/// Attempt direct agent communication (pull model, api-v2 only).
async fn query_agent_direct(
    result: &Value,
    _output: &OutputHandler,
) -> Value {
    #[cfg(feature = "api-v2")]
    {
        // Check if the verifier is using a pre-v3 API (pull model)
        match factory::get_verifier().await {
            Ok(client) => {
                let api_version =
                    client.api_version().parse::<f32>().unwrap_or(2.1);

                if api_version >= 3.0 {
                    return json!({
                        "status": "not_applicable",
                        "model": "push",
                    });
                }

                // Extract agent IP/port from available data
                let agent_connection = extract_agent_connection(result);
                match agent_connection {
                    Some((ip, port)) => {
                        _output.progress(format!(
                            "Testing direct agent connection {ip}:{port}"
                        ));
                        test_agent_connection(&ip, port).await
                    }
                    None => json!({
                        "status": "unknown",
                        "model": "pull",
                        "note": "Agent IP/port not found in registrar or verifier data",
                    }),
                }
            }
            Err(_) => json!({
                "status": "unknown",
                "note": "Cannot determine model — verifier unreachable",
            }),
        }
    }

    #[cfg(not(feature = "api-v2"))]
    {
        // Suppress unused variable warning
        let _ = result;
        json!({
            "status": "not_applicable",
            "model": "push",
        })
    }
}

/// Extract agent IP and port from registrar/verifier data.
#[cfg(feature = "api-v2")]
fn extract_agent_connection(result: &Value) -> Option<(String, u16)> {
    let registrar_data = result.get("registrar").and_then(|r| r.get("data"));
    let verifier_data = result.get("verifier").and_then(|v| v.get("data"));

    // Prefer verifier data, fall back to registrar
    let ip = verifier_data
        .and_then(|d| d.get("ip"))
        .or_else(|| registrar_data.and_then(|d| d.get("ip")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let port = verifier_data
        .and_then(|d| d.get("port"))
        .or_else(|| registrar_data.and_then(|d| d.get("port")))
        .and_then(|v| v.as_u64())
        .map(|p| p as u16);

    ip.zip(port)
}

/// Test direct agent connectivity.
#[cfg(feature = "api-v2")]
async fn test_agent_connection(ip: &str, port: u16) -> Value {
    match AgentClient::builder()
        .agent_ip(ip)
        .agent_port(port)
        .config(get_config())
        .build()
        .await
    {
        Ok(agent_client) => {
            match agent_client.get_quote("test_connectivity").await {
                Ok(_) => json!({
                    "status": "responsive",
                    "model": "pull",
                    "connection": format!("{ip}:{port}"),
                }),
                Err(e) => {
                    // A 400 Bad Request means the agent is reachable
                    // but rejected our test nonce (expected behavior)
                    if e.to_string().contains("400")
                        || e.to_string().contains("Bad Request")
                    {
                        json!({
                            "status": "responsive",
                            "model": "pull",
                            "connection": format!("{ip}:{port}"),
                            "note": "Agent rejected test nonce (expected)",
                        })
                    } else {
                        json!({
                            "status": "unreachable",
                            "model": "pull",
                            "connection": format!("{ip}:{port}"),
                            "error": e.to_string(),
                        })
                    }
                }
            }
        }
        Err(e) => json!({
            "status": "connection_failed",
            "model": "pull",
            "connection": format!("{ip}:{port}"),
            "error": e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_summary_both_found() {
        let result = json!({
            "registrar": { "status": "found", "data": {} },
            "verifier": {
                "status": "found",
                "data": { "operational_state": "Get Quote" }
            },
        });
        let summary = build_summary(&result);
        assert_eq!(summary["registered"], true);
        assert_eq!(summary["monitored"], true);
        assert_eq!(summary["operational_state"], "Get Quote");
    }

    #[test]
    fn test_build_summary_not_found() {
        let result = json!({
            "registrar": { "status": "not_found" },
            "verifier": { "status": "not_found" },
        });
        let summary = build_summary(&result);
        assert_eq!(summary["registered"], false);
        assert_eq!(summary["monitored"], false);
        assert!(summary.get("operational_state").is_none());
    }

    #[test]
    fn test_build_summary_registrar_only() {
        let result = json!({
            "registrar": { "status": "found", "data": {} },
            "verifier": { "status": "error", "error": "connection refused" },
        });
        let summary = build_summary(&result);
        assert_eq!(summary["registered"], true);
        assert_eq!(summary["monitored"], false);
    }

    #[cfg(feature = "api-v2")]
    #[test]
    fn test_extract_agent_connection_from_verifier() {
        let result = json!({
            "registrar": { "status": "found", "data": { "ip": "10.0.0.1", "port": 9002 } },
            "verifier": { "status": "found", "data": { "ip": "10.0.0.2", "port": 9003 } },
        });
        let conn = extract_agent_connection(&result);
        // Should prefer verifier data
        assert_eq!(conn, Some(("10.0.0.2".to_string(), 9003)));
    }

    #[cfg(feature = "api-v2")]
    #[test]
    fn test_extract_agent_connection_from_registrar_fallback() {
        let result = json!({
            "registrar": { "status": "found", "data": { "ip": "10.0.0.1", "port": 9002 } },
            "verifier": { "status": "not_found" },
        });
        let conn = extract_agent_connection(&result);
        assert_eq!(conn, Some(("10.0.0.1".to_string(), 9002)));
    }

    #[cfg(feature = "api-v2")]
    #[test]
    fn test_extract_agent_connection_none() {
        let result = json!({
            "registrar": { "status": "not_found" },
            "verifier": { "status": "not_found" },
        });
        let conn = extract_agent_connection(&result);
        assert_eq!(conn, None);
    }
}
