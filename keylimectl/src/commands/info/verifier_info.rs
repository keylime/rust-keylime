// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Verifier diagnostic information.
//!
//! Queries the verifier for status, API version, and agent count.

use log::debug;
use serde_json::{json, Value};

use crate::client::factory;
use crate::config;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;

/// Execute the `info verifier` subcommand.
pub async fn execute(
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let cfg = config::singleton::get_config();
    let url = cfg.verifier_base_url();

    output.progress("Connecting to verifier");

    match factory::get_verifier().await {
        Ok(client) => {
            let api_version = client.api_version().to_string();
            debug!("Connected to verifier, API version: {api_version}");

            // Try to get agent count
            let verifier_id = cfg.verifier.id.as_deref();
            let agent_count = match client.list_agents(verifier_id).await {
                Ok(response) => extract_agent_count(&response),
                Err(e) => {
                    debug!("Failed to list agents: {e}");
                    None
                }
            };

            let mut result = json!({
                "verifier": {
                    "url": url,
                    "reachable": true,
                    "api_version": api_version,
                }
            });

            if let Some(count) = agent_count {
                result["verifier"]["agents"] = json!({ "count": count });
            }

            Ok(result)
        }
        Err(e) => {
            debug!("Failed to connect to verifier: {e}");
            Ok(json!({
                "verifier": {
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
    // The response may have different structures depending on API version.
    // Try common locations for the agent list.
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
                "uuids": ["uuid-1", "uuid-2", "uuid-3"]
            }
        });
        assert_eq!(extract_agent_count(&response), Some(3));
    }

    #[test]
    fn test_extract_agent_count_results_array() {
        let response = json!({
            "results": [
                {"agent_id": "uuid-1"},
                {"agent_id": "uuid-2"},
            ]
        });
        assert_eq!(extract_agent_count(&response), Some(2));
    }

    #[test]
    fn test_extract_agent_count_agents_array() {
        let response = json!({
            "agents": [
                {"id": "uuid-1"},
            ]
        });
        assert_eq!(extract_agent_count(&response), Some(1));
    }

    #[test]
    fn test_extract_agent_count_empty() {
        let response = json!({});
        assert_eq!(extract_agent_count(&response), None);
    }

    #[test]
    fn test_extract_agent_count_empty_uuids() {
        let response = json!({
            "results": {
                "uuids": []
            }
        });
        assert_eq!(extract_agent_count(&response), Some(0));
    }
}
