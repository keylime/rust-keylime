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

/// IMA PCR index (matches keylime config.IMA_PCR)
const IMA_PCR: u32 = 10;

/// Measured boot PCR indices (matches keylime config.MEASUREDBOOT_PCRS)
const MEASUREDBOOT_PCRS: &[u32] =
    &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15];

/// Enhanced TPM policy resolution with measured boot policy extraction
///
/// This function implements the full precedence chain for TPM policy resolution,
/// matching the behavior of the Python keylime_tenant implementation.
///
/// After resolving the base policy, it auto-enables PCRs based on which
/// attestation policies are provided (matching `process_policy()` in the
/// Python tenant):
/// - runtime policy → enables IMA PCR (10)
/// - measured boot policy → enables measured boot PCRs (0-9, 11-15)
///
/// # Precedence Order:
/// 1. Explicit CLI --tpm_policy argument (highest priority)
/// 2. TPM policy extracted from measured boot policy file
/// 3. Default empty policy "{}" (lowest priority)
///
/// # Arguments
/// * `explicit_policy` - Policy provided via CLI --tpm_policy argument
/// * `mb_policy_path` - Path to measured boot policy file (for extraction)
/// * `has_runtime_policy` - Whether a runtime (IMA) policy is being provided
/// * `has_mb_policy` - Whether a measured boot policy is being provided
///
/// # Returns
/// Returns the resolved TPM policy as a JSON string
#[must_use = "resolved policy must be used in the request"]
pub(super) fn resolve_tpm_policy_enhanced(
    explicit_policy: Option<&str>,
    mb_policy_path: Option<&str>,
    has_runtime_policy: bool,
    has_mb_policy: bool,
) -> Result<String, CommandError> {
    // Priority 1: Explicit CLI argument
    let mut tpm_policy: Value = if let Some(policy) = explicit_policy {
        debug!("Using explicit TPM policy from CLI: {policy}");
        serde_json::from_str(policy).map_err(|e| {
            CommandError::invalid_parameter(
                "tpm_policy",
                format!("Invalid JSON in TPM policy: {e}"),
            )
        })?
    } else {
        // Priority 2: Extract from measured boot policy
        let mut resolved = None;
        if let Some(mb_path) = mb_policy_path {
            debug!("Attempting to extract TPM policy from measured boot policy: {mb_path}");
            match extract_tpm_policy_from_mb_policy(mb_path) {
                Ok(Some(extracted_policy)) => {
                    debug!("Extracted TPM policy from measured boot policy: {extracted_policy}");
                    resolved = Some(
                        serde_json::from_str(&extracted_policy)
                            .unwrap_or(serde_json::json!({"mask": "0x0"})),
                    );
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
        resolved.unwrap_or_else(|| {
            debug!("Using default empty TPM policy with zeroed mask");
            serde_json::json!({"mask": "0x0"})
        })
    };

    // Auto-enable PCRs based on provided policies (matching Python tenant)
    let obj = tpm_policy.as_object_mut().ok_or_else(|| {
        CommandError::invalid_parameter(
            "tpm_policy",
            "TPM policy must be a JSON object".to_string(),
        )
    })?;

    let mut mask: u32 = obj
        .get("mask")
        .and_then(|v| v.as_str())
        .and_then(|s| {
            u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()
        })
        .unwrap_or(0);

    if has_runtime_policy {
        mask |= 1 << IMA_PCR;
        debug!("Auto-enabled IMA PCR {IMA_PCR} in TPM policy mask");
    }

    if has_mb_policy {
        for &pcr in MEASUREDBOOT_PCRS {
            mask |= 1 << pcr;
        }
        debug!("Auto-enabled measured boot PCRs in TPM policy mask");
    }

    let _ = obj
        .insert("mask".to_string(), serde_json::json!(format!("0x{mask:x}")));

    let policy_str = serde_json::to_string(&tpm_policy).map_err(|e| {
        CommandError::invalid_parameter(
            "tpm_policy",
            format!("Failed to serialize TPM policy: {e}"),
        )
    })?;

    debug!("Resolved TPM policy: {policy_str}");
    Ok(policy_str)
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
        // Explicit policy should have highest priority.
        // The mask is updated by auto-enable logic even for explicit policies.
        let result = resolve_tpm_policy_enhanced(
            Some("{\"pcr\": [15], \"mask\": \"0x0\"}"),
            Some("/path/to/mb.json"),
            true,
            false,
        )
        .unwrap(); //#[allow_ci]
        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["pcr"], json!([15]));
        // IMA PCR 10 should be auto-enabled (has_runtime_policy=true)
        assert_eq!(parsed["mask"], "0x400");
    }

    #[test]
    fn test_resolve_tpm_policy_default_fallback() {
        // Should fallback to default when no policies provided (empty policy with no PCRs)
        let result =
            resolve_tpm_policy_enhanced(None, None, false, false).unwrap(); //#[allow_ci]
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
            false,
            false,
        )
        .unwrap(); //#[allow_ci]

        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["pcr"], json!([14, 15]));
        assert_eq!(parsed["hash"], "sha1");
    }

    #[test]
    fn test_resolve_tpm_policy_enhanced_extraction_error_fallback() {
        // When extraction fails, should fallback to default (empty policy with no PCRs)
        let result = resolve_tpm_policy_enhanced(
            None,
            Some("/nonexistent/file.json"),
            false,
            false,
        )
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
            Some("{\"pcr\": [15], \"mask\": \"0x0\"}"),
            Some(policy_file.to_str().unwrap()), //#[allow_ci]
            false,
            false,
        )
        .unwrap(); //#[allow_ci]

        // Should use explicit policy, not extracted one
        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["pcr"], json!([15]));
    }

    #[test]
    fn test_resolve_tpm_policy_auto_enable_ima_pcr() {
        // When has_runtime_policy=true, IMA PCR 10 should be auto-enabled
        let has_runtime_policy = true;
        let has_mb_policy = false;
        let result = resolve_tpm_policy_enhanced(
            None,
            None,
            has_runtime_policy,
            has_mb_policy,
        )
        .unwrap(); //#[allow_ci]

        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["mask"], "0x400"); // IMA PCR 10: 1 << 10 = 0x400
    }

    #[test]
    fn test_resolve_tpm_policy_auto_enable_mb_pcrs() {
        // When has_mb_policy=true, measured boot PCRs (0-9,11-15) should be auto-enabled
        let has_runtime_policy = false;
        let has_mb_policy = true;
        let result = resolve_tpm_policy_enhanced(
            None,
            None,
            has_runtime_policy,
            has_mb_policy,
        )
        .unwrap(); //#[allow_ci]

        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["mask"], "0xfbff"); // MB PCRs 0-9,11-15: 0xfbff
    }

    #[test]
    fn test_resolve_tpm_policy_auto_enable_both() {
        // When both policies are provided, both IMA and MB PCRs should be enabled
        let has_runtime_policy = true;
        let has_mb_policy = true;
        let result = resolve_tpm_policy_enhanced(
            None,
            None,
            has_runtime_policy,
            has_mb_policy,
        )
        .unwrap(); //#[allow_ci]

        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["mask"], "0xffff"); // IMA + MB PCRs: 0xffff
    }

    #[test]
    fn test_resolve_tpm_policy_auto_enable_preserves_existing_mask() {
        // Existing mask bits should be preserved when auto-enabling
        let has_runtime_policy = true;
        let has_mb_policy = false;
        let result = resolve_tpm_policy_enhanced(
            Some("{\"mask\": \"0x800000\"}"), // PCR 23
            None,
            has_runtime_policy,
            has_mb_policy,
        )
        .unwrap(); //#[allow_ci]

        let parsed: Value = serde_json::from_str(&result).unwrap(); //#[allow_ci]
        assert_eq!(parsed["mask"], "0x800400"); // PCR 23 | PCR 10
    }
}
