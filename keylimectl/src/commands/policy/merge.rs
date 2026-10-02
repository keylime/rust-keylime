// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy merge command — combines two runtime policies into one.

use crate::commands::error::CommandError;
use crate::output::OutputHandler;
use crate::policy_tools::merge::merge_policies;
use crate::policy_tools::runtime_policy::RuntimePolicy;
use serde_json::Value;

/// Execute the `policy merge` command.
pub async fn execute(
    base: &str,
    other: &str,
    output_file: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Read and parse base policy
    let base_content = std::fs::read_to_string(base).map_err(|e| {
        CommandError::InvalidParameter {
            parameter: "base".to_string(),
            reason: format!("Failed to read base policy '{base}': {e}"),
        }
    })?;
    let base_policy: RuntimePolicy = serde_json::from_str(&base_content)
        .map_err(|e| CommandError::InvalidParameter {
            parameter: "base".to_string(),
            reason: format!(
                "Base policy '{base}' is not a valid runtime policy: {e}"
            ),
        })?;

    // Read and parse other policy
    let other_content = std::fs::read_to_string(other).map_err(|e| {
        CommandError::InvalidParameter {
            parameter: "other".to_string(),
            reason: format!("Failed to read policy '{other}': {e}"),
        }
    })?;
    let other_policy: RuntimePolicy = serde_json::from_str(&other_content)
        .map_err(|e| CommandError::InvalidParameter {
            parameter: "other".to_string(),
            reason: format!(
                "Policy '{other}' is not a valid runtime policy: {e}"
            ),
        })?;

    output.info(format!(
        "Merging: {} ({} digests) + {} ({} digests)",
        base,
        base_policy.digest_count(),
        other,
        other_policy.digest_count(),
    ));

    let merged = merge_policies(&base_policy, &other_policy);

    output.info(format!(
        "Merged policy: {} digests, {} excludes",
        merged.digest_count(),
        merged.exclude_count(),
    ));

    let merged_json = serde_json::to_value(&merged)?;

    if let Some(out_path) = output_file {
        let json_str = serde_json::to_string_pretty(&merged_json)?;
        std::fs::write(out_path, &json_str).map_err(|e| {
            CommandError::InvalidParameter {
                parameter: "output".to_string(),
                reason: format!("Failed to write merged policy: {e}"),
            }
        })?;
        output.info(format!("Merged policy written to {out_path}"));
    }

    Ok(merged_json)
}
