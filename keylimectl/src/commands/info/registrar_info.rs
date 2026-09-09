// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Registrar diagnostic information.
//!
//! Queries the registrar for status, API version, and agent count.

use log::debug;
use serde_json::{json, Value};

use crate::client::factory;
use crate::config;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;

/// Execute the `info registrar` subcommand.
pub async fn execute(
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let cfg = config::singleton::get_config();
    let url = cfg.registrar_base_url();

    output.progress("Connecting to registrar");

    match factory::get_registrar().await {
        Ok(client) => {
            let api_version = client.api_version().to_string();
            debug!("Connected to registrar, API version: {api_version}");

            // Try to get agent count
            let agent_count = match client.list_agents().await {
                Ok(response) => extract_agent_count(&response),
                Err(e) => {
                    debug!("Failed to list agents: {e}");
                    None
                }
            };

            let mut result = json!({
                "registrar": {
                    "url": url,
                    "reachable": true,
                    "api_version": api_version,
                }
            });

            if let Some(count) = agent_count {
                result["registrar"]["agents"] = json!({ "count": count });
            }

            Ok(result)
        }
        Err(e) => {
            debug!("Failed to connect to registrar: {e}");
            Ok(json!({
                "registrar": {
                    "url": url,
                    "reachable": false,
                    "error": e.to_string(),
                }
            }))
        }
    }
}

/// Extract the agent count from a list_agents response.
fn extract_agent_count(response: &Value) -> Option<usize> {
    if let Some(results) = response.get("results") {
        if let Some(uuids) = results.get("uuids") {
            return uuids.as_array().map(|a| a.len());
        }
        if let Some(agents) = results.as_array() {
            return Some(agents.len());
        }
    }
    if let Some(agents) = response.get("agents") {
        return agents.as_array().map(|a| a.len());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_agent_count_uuids() {
        let response = json!({
            "results": {
                "uuids": ["uuid-1", "uuid-2"]
            }
        });
        assert_eq!(extract_agent_count(&response), Some(2));
    }

    #[test]
    fn test_extract_agent_count_empty() {
        let response = json!({});
        assert_eq!(extract_agent_count(&response), None);
    }

    #[test]
    fn test_extract_agent_count_empty_list() {
        let response = json!({
            "results": {
                "uuids": []
            }
        });
        assert_eq!(extract_agent_count(&response), Some(0));
    }
}
