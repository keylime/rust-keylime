// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Local policy generation commands.
//!
//! Generates runtime, measured boot, and TPM policies from local
//! input sources without requiring network connectivity.

use crate::commands::error::CommandError;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::policy_tools::ima_parser;
use crate::policy_tools::runtime_policy::RuntimePolicy;
use crate::GenerateSubcommand;
use serde_json::Value;
use std::path::Path;

/// Execute a policy generation subcommand.
pub async fn execute(
    subcommand: &GenerateSubcommand,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match subcommand {
        GenerateSubcommand::Runtime {
            ima_measurement_list,
            allowlist,
            rootfs: _,    // Step 4
            skip_path: _, // Step 4
            base_policy,
            excludelist,
            output: output_file,
            keyrings,
            ima_buf,
            ignored_keyrings,
            add_ima_signature_verification_key: _, // Step 5
            hash_alg,
        } => generate_runtime(
            ima_measurement_list.as_deref(),
            allowlist.as_deref(),
            base_policy.as_deref(),
            excludelist.as_deref(),
            output_file.as_deref(),
            *keyrings,
            *ima_buf,
            ignored_keyrings,
            hash_alg.as_deref(),
            output,
        )
        .await
        .map_err(KeylimectlError::from),
        GenerateSubcommand::MeasuredBoot { .. } => {
            Err(KeylimectlError::validation(
                "policy generate measured-boot is not yet implemented",
            ))
        }
        GenerateSubcommand::Tpm { .. } => Err(KeylimectlError::validation(
            "policy generate tpm is not yet implemented",
        )),
    }
}

/// Generate a runtime policy from IMA logs, allowlists, and other sources.
#[allow(clippy::too_many_arguments)]
async fn generate_runtime(
    ima_measurement_list: Option<&str>,
    allowlist: Option<&str>,
    base_policy: Option<&str>,
    excludelist: Option<&str>,
    output_file: Option<&str>,
    get_keyrings: bool,
    get_ima_buf: bool,
    ignored_keyrings: &[String],
    hash_alg: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    let mut policy = if let Some(base_path) = base_policy {
        load_base_policy(base_path)?
    } else {
        RuntimePolicy::new()
    };

    let mut detected_algorithm: Option<String> = hash_alg.map(String::from);

    // Parse IMA measurement list
    if let Some(ima_path) = ima_measurement_list {
        let path = Path::new(ima_path);
        if path.exists() {
            output.info(format!("Parsing IMA measurement list: {ima_path}"));

            let ima_data = ima_parser::parse_ima_measurement_list(
                path,
                get_keyrings,
                get_ima_buf,
                ignored_keyrings,
            )?;

            // Use detected algorithm if not explicitly specified
            if detected_algorithm.is_none() {
                detected_algorithm = ima_data.detected_algorithm;
            }

            // Merge digests
            for (file_path, digests) in &ima_data.digests {
                for digest in digests {
                    policy.add_digest(file_path.clone(), digest.clone());
                }
            }

            // Merge keyrings
            for (keyring, digests) in &ima_data.keyrings {
                for digest in digests {
                    policy.add_keyring(keyring.clone(), digest.clone());
                }
            }

            // Merge ima-buf
            for (name, digests) in &ima_data.ima_buf {
                for digest in digests {
                    policy.add_ima_buf(name.clone(), digest.clone());
                }
            }

            output.info(format!(
                "Extracted {} file digests from IMA log",
                ima_data.digests.len()
            ));
        } else {
            log::debug!("IMA measurement list not found: {ima_path}");
        }
    }

    // Parse allowlist
    if let Some(allowlist_path) = allowlist {
        let path = Path::new(allowlist_path);
        output.info(format!("Parsing allowlist: {allowlist_path}"));

        // Auto-detect format: try JSON first, fall back to flat text
        let allowlist_digests = if allowlist_path.ends_with(".json") {
            ima_parser::parse_json_allowlist(path)?
        } else {
            match ima_parser::parse_json_allowlist(path) {
                Ok(d) => d,
                Err(_) => ima_parser::parse_flat_allowlist(path)?,
            }
        };

        for (file_path, digests) in &allowlist_digests {
            for digest in digests {
                policy.add_digest(file_path.clone(), digest.clone());
            }
        }

        output.info(format!(
            "Loaded {} entries from allowlist",
            allowlist_digests.len()
        ));
    }

    // Parse exclude list
    if let Some(excludelist_path) = excludelist {
        let path = Path::new(excludelist_path);
        output.info(format!("Parsing exclude list: {excludelist_path}"));

        let excludes = ima_parser::parse_excludelist(path)?;
        for pattern in &excludes {
            policy.add_exclude(pattern.clone());
        }

        output.info(format!("Loaded {} exclude patterns", excludes.len()));
    }

    // Set ignored keyrings
    for keyring in ignored_keyrings {
        policy.add_ignored_keyring(keyring.clone());
    }

    // Set hash algorithm
    if let Some(alg) = &detected_algorithm {
        policy.set_log_hash_alg(alg.clone());
    }

    // Serialize the policy
    let policy_json = serde_json::to_value(&policy)?;

    // Write to file or return for stdout display
    if let Some(out_path) = output_file {
        let json_str = serde_json::to_string_pretty(&policy_json)?;
        std::fs::write(out_path, &json_str).map_err(|e| {
            CommandError::from(
                crate::commands::error::PolicyGenerationError::Output {
                    path: std::path::PathBuf::from(out_path),
                    reason: e.to_string(),
                },
            )
        })?;
        output.info(format!("Policy written to {out_path}"));
        output.info(format!(
            "Policy contains {} file digests, {} exclude patterns",
            policy.digest_count(),
            policy.exclude_count()
        ));
    } else {
        // Output to stdout via the output handler
        output.success(policy_json.clone());
    }

    Ok(policy_json)
}

/// Load a base policy from a JSON file.
fn load_base_policy(path: &str) -> Result<RuntimePolicy, CommandError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        CommandError::from(
            crate::commands::error::PolicyGenerationError::AllowlistParse {
                path: std::path::PathBuf::from(path),
                reason: format!("Failed to read base policy: {e}"),
            },
        )
    })?;

    let policy: RuntimePolicy =
        serde_json::from_str(&content).map_err(|e| {
            CommandError::from(
                crate::commands::error::PolicyGenerationError::AllowlistParse {
                    path: std::path::PathBuf::from(path),
                    reason: format!(
                        "Failed to parse base policy: {e}"
                    ),
                },
            )
        })?;

    Ok(policy)
}
