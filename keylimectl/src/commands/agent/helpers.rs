// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Helper utilities for agent commands
//!
//! Policy file loading, TPM policy resolution, and measured boot
//! policy extraction.

use crate::commands::error::CommandError;
use log::{debug, warn};
use serde_json::Value;
use std::fs;

/// Load policy file contents
#[must_use = "policy content must be used after loading"]
pub(super) fn load_policy_file(path: &str) -> Result<String, CommandError> {
    fs::read_to_string(path).map_err(|e| {
        CommandError::policy_file_error(
            path,
            format!("Failed to read policy file: {e}"),
        )
    })
}

/// Load payload file contents as string
#[must_use = "payload content must be used after loading"]
pub(super) fn load_payload_file(path: &str) -> Result<String, CommandError> {
    fs::read_to_string(path).map_err(|e| {
        CommandError::policy_file_error(
            path,
            format!("Failed to read payload file: {e}"),
        )
    })
}

/// Load payload file contents as raw bytes
///
/// Used for payload encryption where the file content needs to be
/// encrypted before being sent to the agent. Reads as bytes to
/// support both text and binary payloads.
#[cfg(feature = "api-v2")]
#[must_use = "payload bytes must be used after loading"]
pub(super) fn load_payload_bytes(
    path: &str,
) -> Result<Vec<u8>, CommandError> {
    fs::read(path).map_err(|e| {
        CommandError::policy_file_error(
            path,
            format!("Failed to read payload file: {e}"),
        )
    })
}

/// Enhanced TPM policy resolution with measured boot policy extraction
///
/// This function implements the full precedence chain for TPM policy resolution,
/// matching the behavior of the Python keylime_tenant implementation.
///
/// # Precedence Order:
/// 1. Explicit CLI --tpm_policy argument (highest priority)
/// 2. TPM policy extracted from measured boot policy file
/// 3. Default empty policy "{}" (lowest priority)
///
/// # Arguments
/// * `explicit_policy` - Policy provided via CLI --tpm_policy argument
/// * `mb_policy_path` - Path to measured boot policy file (for extraction)
///
/// # Returns
/// Returns the resolved TPM policy as a JSON string
///
/// # Examples
/// ```
/// // With explicit policy (highest priority)
/// let policy = resolve_tpm_policy_enhanced(Some("{\"pcr\": [15]}"), Some("/path/to/mb.json"));
/// assert_eq!(policy, "{\"pcr\": [15]}");
///
/// // With measured boot policy extraction
/// let policy = resolve_tpm_policy_enhanced(None, Some("/path/to/mb_with_tpm_policy.json"));
/// // Returns extracted TPM policy from measured boot policy
///
/// // With default fallback (empty policy with no PCRs)
/// let policy = resolve_tpm_policy_enhanced(None, None);
/// assert_eq!(policy, r#"{"mask":"0x0"}"#);
/// ```
#[must_use = "resolved policy must be used in the request"]
pub(super) fn resolve_tpm_policy_enhanced(
    explicit_policy: Option<&str>,
    mb_policy_path: Option<&str>,
) -> Result<String, CommandError> {
    // Priority 1: Explicit CLI argument
    if let Some(policy) = explicit_policy {
        debug!("Using explicit TPM policy from CLI: {policy}");
        return Ok(policy.to_string());
    }

    // Priority 2: Extract from measured boot policy
    if let Some(mb_path) = mb_policy_path {
        debug!("Attempting to extract TPM policy from measured boot policy: {mb_path}");
        match extract_tpm_policy_from_mb_policy(mb_path) {
            Ok(Some(extracted_policy)) => {
                debug!("Extracted TPM policy from measured boot policy: {extracted_policy}");
                return Ok(extracted_policy);
            }
            Ok(None) => {
                debug!("No TPM policy found in measured boot policy, using default");
            }
            Err(e) => {
                warn!("Failed to extract TPM policy from measured boot policy: {e}");
                debug!(
                    "Continuing with default policy due to extraction error"
                );
            }
        }
    }

    // Priority 3: Default empty policy with zeroed mask (no PCRs)
    debug!("Using default empty TPM policy with zeroed mask");
    Ok(r#"{"mask":"0x0"}"#.to_string())
}

/// Extract TPM policy from a measured boot policy file
///
/// Measured boot policies in Keylime can contain TPM policy sections that should
/// be extracted and used for agent attestation. This function parses the measured
/// boot policy file and extracts any TPM-related policy information.
///
/// # Arguments
/// * `mb_policy_path` - Path to the measured boot policy JSON file
///
/// # Returns
/// * `Ok(Some(policy))` - Successfully extracted TPM policy
/// * `Ok(None)` - No TPM policy found in the file
/// * `Err(error)` - File reading or parsing error
///
/// # Expected Format
/// The measured boot policy file should be a JSON file that may contain:
/// ```json
/// {
///   "tpm_policy": {
///     "pcr": [15],
///     "hash": "sha256"
///   },
///   "other_mb_fields": "..."
/// }
/// ```
#[must_use = "extracted policy must be checked and used"]
fn extract_tpm_policy_from_mb_policy(
    mb_policy_path: &str,
) -> Result<Option<String>, CommandError> {
    debug!("Reading measured boot policy file: {mb_policy_path}");

    // Read the measured boot policy file
    let policy_content = fs::read_to_string(mb_policy_path).map_err(|e| {
        CommandError::policy_file_error(
            mb_policy_path,
            format!("Failed to read measured boot policy file: {e}"),
        )
    })?;

    // Parse as JSON
    let mb_policy: Value =
        serde_json::from_str(&policy_content).map_err(|e| {
            CommandError::policy_file_error(
                mb_policy_path,
                format!("Invalid JSON in measured boot policy file: {e}"),
            )
        })?;

    // Look for TPM policy in various expected locations
    let tpm_policy_value = mb_policy
        .get("tpm_policy") // Primary location
        .or_else(|| mb_policy.get("tpm")) // Alternative location
        .or_else(|| mb_policy.get("tpm_policy")); // Another alternative

    match tpm_policy_value {
        Some(policy_obj) => {
            // Convert the TPM policy object to a JSON string
            let policy_str =
                serde_json::to_string(policy_obj).map_err(|e| {
                    CommandError::policy_file_error(
                        mb_policy_path,
                        format!(
                            "Failed to serialize extracted TPM policy: {e}"
                        ),
                    )
                })?;
            debug!("Successfully extracted TPM policy: {policy_str}");
            Ok(Some(policy_str))
        }
        None => {
            debug!("No TPM policy section found in measured boot policy");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_resolve_tpm_policy_explicit_priority() {
        // Explicit policy should have highest priority
        let result = resolve_tpm_policy_enhanced(
            Some("{\"pcr\": [15]}"),
            Some("/path/to/mb.json"),
        )
        .unwrap(); //#[allow_ci]
        assert_eq!(result, "{\"pcr\": [15]}");
    }

    #[test]
    fn test_resolve_tpm_policy_default_fallback() {
        // Should fallback to default when no policies provided (empty policy with no PCRs)
        let result = resolve_tpm_policy_enhanced(None, None).unwrap(); //#[allow_ci]
        assert_eq!(result, r#"{"mask":"0x0"}"#);
    }

    #[test]
    fn test_extract_tpm_policy_from_mb_policy_success() {
        let temp_dir = tempdir().unwrap(); //#[allow_ci]
        let policy_file = temp_dir.path().join("mb_policy.json");

        // Create test measured boot policy with TPM policy
        let mb_policy_content = json!({
            "tpm_policy": {
                "pcr": [15],
                "hash": "sha256"
            },
            "other_field": "value"
        });

        fs::write(&policy_file, mb_policy_content.to_string()).unwrap(); //#[allow_ci]

        let result =
            extract_tpm_policy_from_mb_policy(policy_file.to_str().unwrap()) //#[allow_ci]
                .unwrap(); //#[allow_ci]

        assert!(result.is_some());
        let extracted = result.unwrap(); //#[allow_ci]
        let parsed: Value = serde_json::from_str(&extracted).unwrap(); //#[allow_ci]
        assert_eq!(parsed["pcr"], json!([15]));
        assert_eq!(parsed["hash"], "sha256");
    }

    #[test]
    fn test_extract_tpm_policy_alternative_locations() {
        let temp_dir = tempdir().unwrap(); //#[allow_ci]

        // Test "tpm" location
        let policy_file_tpm = temp_dir.path().join("mb_policy_tpm.json");
        let mb_policy_tpm = json!({
            "tpm": {"pcr": [16]},
            "other_field": "value"
        });
        fs::write(&policy_file_tpm, mb_policy_tpm.to_string()).unwrap(); //#[allow_ci]

        let result = extract_tpm_policy_from_mb_policy(
            policy_file_tpm.to_str().unwrap(), //#[allow_ci]
        )
        .unwrap(); //#[allow_ci]
        assert!(result.is_some());

        // Test "tpm_policy" location
        let policy_file_full = temp_dir.path().join("mb_policy_full.json");
        let mb_policy_full = json!({
            "tpm_policy": {"pcr": [17]},
            "other_field": "value"
        });
        fs::write(&policy_file_full, mb_policy_full.to_string()).unwrap(); //#[allow_ci]

        let result = extract_tpm_policy_from_mb_policy(
            policy_file_full.to_str().unwrap(), //#[allow_ci]
        )
        .unwrap(); //#[allow_ci]
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_tpm_policy_no_policy_found() {
        let temp_dir = tempdir().unwrap(); //#[allow_ci]
        let policy_file = temp_dir.path().join("mb_policy_no_tpm.json");

        // Create measured boot policy without TPM policy
        let mb_policy_content = json!({
            "other_field": "value",
            "more_fields": "data"
        });

        fs::write(&policy_file, mb_policy_content.to_string()).unwrap(); //#[allow_ci]

        let result =
            extract_tpm_policy_from_mb_policy(policy_file.to_str().unwrap()) //#[allow_ci]
                .unwrap(); //#[allow_ci]

        assert!(result.is_none());
    }

    #[test]
    fn test_extract_tpm_policy_invalid_json() {
        let temp_dir = tempdir().unwrap(); //#[allow_ci]
        let policy_file = temp_dir.path().join("invalid.json");

        // Write invalid JSON
        fs::write(&policy_file, "{ invalid json }").unwrap(); //#[allow_ci]

        let result =
            extract_tpm_policy_from_mb_policy(policy_file.to_str().unwrap()); //#[allow_ci]

        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tpm_policy_file_not_found() {
        let result =
            extract_tpm_policy_from_mb_policy("/nonexistent/file.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_tpm_policy_enhanced_with_mb_extraction() {
        let temp_dir = tempdir().unwrap(); //#[allow_ci]
        let policy_file = temp_dir.path().join("mb_with_tmp.json");

        // Create measured boot policy with TPM policy
        let mb_policy_content = json!({
            "tpm_policy": {
                "pcr": [14, 15],
                "hash": "sha1"
            }
        });

        fs::write(&policy_file, mb_policy_content.to_string()).unwrap(); //#[allow_ci]

        // Should extract from measured boot policy when no explicit policy
        let result = resolve_tpm_policy_enhanced(
            None,
            Some(policy_file.to_str().unwrap()), //#[allow_ci]
        )
        .unwrap(); //#[allow_ci]

        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["pcr"], json!([14, 15]));
        assert_eq!(parsed["hash"], "sha1");
    }

    #[test]
    fn test_resolve_tpm_policy_enhanced_extraction_error_fallback() {
        // When extraction fails, should fallback to default (empty policy with no PCRs)
        let result =
            resolve_tpm_policy_enhanced(None, Some("/nonexistent/file.json"))
                .unwrap(); //#[allow_ci]

        assert_eq!(result, r#"{"mask":"0x0"}"#);
    }

    #[test]
    fn test_resolve_tpm_policy_precedence_order() {
        let temp_dir = tempdir().unwrap(); //#[allow_ci]
        let policy_file = temp_dir.path().join("mb_policy.json");

        // Create measured boot policy
        let mb_policy_content = json!({
            "tpm_policy": {"pcr": [16]}
        });
        fs::write(&policy_file, mb_policy_content.to_string()).unwrap(); //#[allow_ci]

        // Explicit policy should override extracted policy
        let result = resolve_tpm_policy_enhanced(
            Some("{\"pcr\": [15]}"),
            Some(policy_file.to_str().unwrap()), //#[allow_ci]
        )
        .unwrap(); //#[allow_ci]

        // Should use explicit policy, not extracted one
        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["pcr"], json!([15]));
    }
}
