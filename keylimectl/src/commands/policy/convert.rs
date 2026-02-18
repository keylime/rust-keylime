// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Legacy policy format conversion.

use crate::commands::error::CommandError;
use crate::output::OutputHandler;
use crate::policy_tools::conversion;
use crate::policy_tools::ima_parser;
use serde_json::Value;
use std::path::Path;

/// Execute the policy convert command.
pub async fn execute(
    file: &str,
    output_file: &str,
    excludelist: Option<&str>,
    verification_keys: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    output.info(format!(
        "Converting legacy allowlist '{file}' to runtime policy"
    ));

    // Convert the input file
    let mut policy = conversion::convert_allowlist_file(Path::new(file))?;

    output.info(format!("Converted {} file entries", policy.digest_count()));

    // Merge exclude list if provided
    if let Some(excl_path) = excludelist {
        let excludes = ima_parser::parse_excludelist(Path::new(excl_path))?;
        conversion::merge_excludelist(&mut policy, &excludes);
        output.info(format!(
            "Added {} exclude patterns from '{excl_path}'",
            excludes.len()
        ));
    }

    // Add verification keys if provided
    if let Some(key_path) = verification_keys {
        conversion::add_verification_keys(&mut policy, key_path)?;
        output.info(format!("Added verification keys from '{key_path}'"));
    }

    // Serialize and write
    let json_val = serde_json::to_value(&policy)?;
    let json_str = serde_json::to_string_pretty(&json_val)?;

    std::fs::write(output_file, &json_str)?;

    output.info(format!("Runtime policy written to {output_file}"));

    Ok(json_val)
}
