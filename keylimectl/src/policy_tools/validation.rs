// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy validation for runtime, measured boot, and TPM policies.
//!
//! Provides structural and content validation for all policy types,
//! checking required fields, digest formats, and schema compatibility.

use crate::policy_tools::measured_boot_policy::MeasuredBootPolicy;
use crate::policy_tools::runtime_policy::{
    RuntimePolicy, RUNTIME_POLICY_VERSION,
};
use crate::policy_tools::tpm_policy::TpmPolicy;

/// A single validation issue (error or warning).
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// A machine-readable code for the issue.
    pub code: String,
    /// A human-readable description.
    pub message: String,
}

/// Result of policy validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the policy is valid (no errors).
    pub valid: bool,
    /// Validation errors (policy is invalid if non-empty).
    pub errors: Vec<ValidationIssue>,
    /// Validation warnings (policy is valid but may have issues).
    pub warnings: Vec<ValidationIssue>,
}

impl ValidationResult {
    fn new() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn add_error(&mut self, code: &str, message: String) {
        self.valid = false;
        self.errors.push(ValidationIssue {
            code: code.to_string(),
            message,
        });
    }

    fn add_warning(&mut self, code: &str, message: String) {
        self.warnings.push(ValidationIssue {
            code: code.to_string(),
            message,
        });
    }
}

/// Known hash algorithm names and their expected hex digest lengths.
const KNOWN_ALGORITHMS: &[(&str, usize)] = &[
    ("sha1", 40),
    ("sha256", 64),
    ("sha384", 96),
    ("sha512", 128),
    ("sm3_256", 64),
];

/// Validate a runtime policy.
pub fn validate_runtime_policy(policy: &RuntimePolicy) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check meta version
    if policy.meta.version != RUNTIME_POLICY_VERSION {
        result.add_warning(
            "version_mismatch",
            format!(
                "Policy version {} does not match expected version {}",
                policy.meta.version, RUNTIME_POLICY_VERSION
            ),
        );
    }

    // Check digest format: bare lowercase hex
    for (path, digests) in &policy.digests {
        if digests.is_empty() {
            result.add_warning(
                "empty_digests",
                format!("Path '{path}' has no digests"),
            );
            continue;
        }

        for digest in digests {
            validate_digest_string(digest, path, &mut result);
        }
    }

    // Check keyring digests
    for (keyring, digests) in &policy.keyrings {
        if keyring.is_empty() {
            result.add_error(
                "empty_keyring_name",
                "Keyring name must not be empty".to_string(),
            );
        }
        for digest in digests {
            validate_digest_string(digest, keyring, &mut result);
        }
    }

    // Check ima-buf digests
    for (name, digests) in &policy.ima_buf {
        if name.is_empty() {
            result.add_error(
                "empty_ima_buf_name",
                "IMA-buf entry name must not be empty".to_string(),
            );
        }
        for digest in digests {
            validate_digest_string(digest, name, &mut result);
        }
    }

    // Check exclude patterns are non-empty
    for exclude in &policy.excludes {
        if exclude.is_empty() {
            result.add_error(
                "empty_exclude",
                "Exclude pattern must not be empty".to_string(),
            );
        }
    }

    // Check IMA config hash algorithm
    let alg = &policy.ima.log_hash_alg;
    if !KNOWN_ALGORITHMS.iter().any(|(name, _)| *name == alg) {
        result.add_warning(
            "unknown_hash_alg",
            format!(
                "IMA log hash algorithm '{alg}' is not a recognized algorithm"
            ),
        );
    }

    result
}

/// Validate a measured boot policy.
pub fn validate_measured_boot_policy(
    policy: &MeasuredBootPolicy,
) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check Secure Boot signature entries
    for sig in &policy.pk {
        if sig.signature_owner.is_empty() {
            result.add_error(
                "empty_pk_owner",
                "PK signature owner must not be empty".to_string(),
            );
        }
        if sig.signature_data.is_empty() {
            result.add_error(
                "empty_pk_data",
                "PK signature data must not be empty".to_string(),
            );
        }
    }

    for sig in &policy.kek {
        if sig.signature_owner.is_empty() {
            result.add_error(
                "empty_kek_owner",
                "KEK signature owner must not be empty".to_string(),
            );
        }
    }

    for sig in &policy.db {
        if sig.signature_owner.is_empty() {
            result.add_error(
                "empty_db_owner",
                "DB signature owner must not be empty".to_string(),
            );
        }
    }

    // Warn if no kernels are defined
    if policy.kernels.is_empty() {
        result.add_warning(
            "no_kernels",
            "No kernel boot chain entries defined".to_string(),
        );
    }

    // Check kernel entries have at least one hash
    for (i, kernel) in policy.kernels.iter().enumerate() {
        if kernel.shim_authcode_sha256.is_none()
            && kernel.grub_authcode_sha256.is_none()
            && kernel.kernel_authcode_sha256.is_none()
            && kernel.initrd_plain_sha256.is_none()
        {
            result.add_warning(
                "kernel_no_hashes",
                format!("Kernel entry {i} has no digest values"),
            );
        }
    }

    result
}

/// Validate a TPM policy.
pub fn validate_tpm_policy(policy: &TpmPolicy) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Validate mask format
    match TpmPolicy::parse_mask(&policy.mask) {
        Ok(indices) => {
            // Check that each PCR index in the mask has a
            // corresponding value
            for idx in &indices {
                let key = idx.to_string();
                if !policy.pcr_values.contains_key(&key) {
                    result.add_error(
                        "missing_pcr_value",
                        format!("PCR {idx} is set in mask but has no value"),
                    );
                }
            }

            // Check for PCR values not in the mask
            for key in policy.pcr_values.keys() {
                if let Ok(idx) = key.parse::<u32>() {
                    if !indices.contains(&idx) {
                        result.add_warning(
                            "extra_pcr_value",
                            format!(
                                "PCR {idx} has a value but is not set in mask"
                            ),
                        );
                    }
                } else {
                    result.add_error(
                        "invalid_pcr_key",
                        format!("PCR key '{key}' is not a valid integer"),
                    );
                }
            }
        }
        Err(e) => {
            result
                .add_error("invalid_mask", format!("Invalid PCR mask: {e}"));
        }
    }

    // Validate PCR values are valid hex
    for (key, value) in &policy.pcr_values {
        if value.is_empty() {
            result.add_error(
                "empty_pcr_value",
                format!("PCR {key} value is empty"),
            );
        } else if !value.chars().all(|c| c.is_ascii_hexdigit()) {
            result.add_error(
                "invalid_pcr_hex",
                format!("PCR {key} value is not valid hex"),
            );
        }
    }

    result
}

/// Try to auto-detect the policy type from a JSON value.
pub fn detect_policy_type(value: &serde_json::Value) -> Option<&'static str> {
    if let Some(obj) = value.as_object() {
        // Runtime policy: has "meta" and "digests" keys
        if obj.contains_key("meta") && obj.contains_key("digests") {
            return Some("runtime");
        }
        // Measured boot: has "has_secureboot" key
        if obj.contains_key("has_secureboot") {
            return Some("measured-boot");
        }
        // TPM policy: has "mask" key
        if obj.contains_key("mask") {
            return Some("tpm");
        }
    }
    None
}

/// Validate a bare hex digest string.
///
/// The verifier schema requires digests to match `^[0-9a-f]{40,128}$`:
/// lowercase hex characters only, length between 40 and 128.
fn validate_digest_string(
    digest: &str,
    context: &str,
    result: &mut ValidationResult,
) {
    if digest.is_empty() {
        result.add_error(
            "invalid_digest_format",
            format!("Digest for '{context}' is empty"),
        );
        return;
    }

    if !digest
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        result.add_error(
            "invalid_hex",
            format!(
                "Digest for '{context}' contains non-lowercase-hex characters: '{digest}'"
            ),
        );
        return;
    }

    if digest.len() < 40 || digest.len() > 128 {
        result.add_warning(
            "digest_length_mismatch",
            format!(
                "Digest for '{context}' has length {} (expected 40-128): '{digest}'",
                digest.len()
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_tools::measured_boot_policy::{
        KernelEntry, SecureBootSignature,
    };

    #[test]
    fn test_valid_runtime_policy() {
        let mut policy = RuntimePolicy::new();
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        );
        policy.add_exclude("/tmp/*".to_string());
        policy.set_log_hash_alg("sha256".to_string());

        let result = validate_runtime_policy(&policy);
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_invalid_digest_format_non_hex() {
        let mut policy = RuntimePolicy::new();
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "not_a_valid_hex_digest!".to_string(),
        );

        let result = validate_runtime_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "invalid_hex"));
    }

    #[test]
    fn test_invalid_digest_format_uppercase() {
        let mut policy = RuntimePolicy::new();
        // Uppercase hex is not allowed by the verifier schema
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890".to_string(),
        );

        let result = validate_runtime_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "invalid_hex"));
    }

    #[test]
    fn test_empty_exclude_pattern() {
        let mut policy = RuntimePolicy::new();
        policy.excludes.push(String::new());

        let result = validate_runtime_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "empty_exclude"));
    }

    #[test]
    fn test_empty_keyring_name() {
        let mut policy = RuntimePolicy::new();
        let _ = policy.keyrings.insert(
            String::new(),
            vec!["aabbccddeeff00112233aabbccddeeff0011223344".to_string()],
        );

        let result = validate_runtime_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "empty_keyring_name"));
    }

    #[test]
    fn test_version_mismatch_warning() {
        let mut policy = RuntimePolicy::new();
        policy.meta.version = 99;

        let result = validate_runtime_policy(&policy);
        assert!(result.valid); // warning, not error
        assert!(result.warnings.iter().any(|e| e.code == "version_mismatch"));
    }

    #[test]
    fn test_unknown_hash_alg_warning() {
        let mut policy = RuntimePolicy::new();
        policy.set_log_hash_alg("blake2b".to_string());

        let result = validate_runtime_policy(&policy);
        assert!(result.valid); // warning, not error
        assert!(result.warnings.iter().any(|e| e.code == "unknown_hash_alg"));
    }

    #[test]
    fn test_digest_length_mismatch_warning() {
        let mut policy = RuntimePolicy::new();
        // Verifier expects 40-128 hex chars, provide only 8
        policy
            .add_digest("/usr/bin/test".to_string(), "aabbccdd".to_string());

        let result = validate_runtime_policy(&policy);
        assert!(result.valid); // warning, not error
        assert!(result
            .warnings
            .iter()
            .any(|e| e.code == "digest_length_mismatch"));
    }

    #[test]
    fn test_valid_tpm_policy() {
        let policy = TpmPolicy::from_pcrs(&[
            (0, "aabbccdd".to_string()),
            (7, "eeff0011".to_string()),
        ]);

        let result = validate_tpm_policy(&policy);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_tpm_missing_pcr_value() {
        let mut policy = TpmPolicy::new();
        policy.mask = "0x3".to_string(); // PCR 0 and 1
        let _ = policy
            .pcr_values
            .insert("0".to_string(), "aabb".to_string());
        // PCR 1 is in mask but has no value

        let result = validate_tpm_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "missing_pcr_value"));
    }

    #[test]
    fn test_tpm_invalid_mask() {
        let mut policy = TpmPolicy::new();
        policy.mask = "invalid".to_string();

        let result = validate_tpm_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "invalid_mask"));
    }

    #[test]
    fn test_tpm_invalid_pcr_hex() {
        let policy = TpmPolicy::from_pcrs(&[(0, "not_hex!".to_string())]);

        let result = validate_tpm_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "invalid_pcr_hex"));
    }

    #[test]
    fn test_tpm_extra_pcr_value_warning() {
        let mut policy = TpmPolicy::new();
        policy.mask = "0x1".to_string(); // Only PCR 0
        let _ = policy
            .pcr_values
            .insert("0".to_string(), "aabb".to_string());
        let _ = policy
            .pcr_values
            .insert("7".to_string(), "ccdd".to_string());

        let result = validate_tpm_policy(&policy);
        assert!(result.valid); // warning, not error
        assert!(result.warnings.iter().any(|e| e.code == "extra_pcr_value"));
    }

    #[test]
    fn test_valid_measured_boot_policy() {
        let mut policy = MeasuredBootPolicy::new(true);
        policy.pk.push(SecureBootSignature {
            signature_owner: "guid-1".to_string(),
            signature_data: "0xaabb".to_string(),
        });
        policy.kernels.push(KernelEntry {
            shim_authcode_sha256: Some("0xshimhash".to_string()),
            grub_authcode_sha256: None,
            kernel_authcode_sha256: Some("0xkernhash".to_string()),
            initrd_plain_sha256: None,
            vmlinuz_plain_sha256: None,
            kernel_cmdline: Some("root=/dev/sda1".to_string()),
        });

        let result = validate_measured_boot_policy(&policy);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_measured_boot_empty_pk_owner() {
        let mut policy = MeasuredBootPolicy::new(true);
        policy.pk.push(SecureBootSignature {
            signature_owner: String::new(),
            signature_data: "0xaabb".to_string(),
        });

        let result = validate_measured_boot_policy(&policy);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.code == "empty_pk_owner"));
    }

    #[test]
    fn test_measured_boot_no_kernels_warning() {
        let policy = MeasuredBootPolicy::new(true);

        let result = validate_measured_boot_policy(&policy);
        assert!(result.valid); // warning, not error
        assert!(result.warnings.iter().any(|e| e.code == "no_kernels"));
    }

    #[test]
    fn test_detect_policy_type_runtime() {
        let val = serde_json::json!({
            "meta": {"version": 5},
            "digests": {}
        });
        assert_eq!(detect_policy_type(&val), Some("runtime"));
    }

    #[test]
    fn test_detect_policy_type_measured_boot() {
        let val = serde_json::json!({
            "has_secureboot": true,
            "kernels": []
        });
        assert_eq!(detect_policy_type(&val), Some("measured-boot"));
    }

    #[test]
    fn test_detect_policy_type_tpm() {
        let val = serde_json::json!({
            "mask": "0x87",
            "0": "aabb"
        });
        assert_eq!(detect_policy_type(&val), Some("tpm"));
    }

    #[test]
    fn test_detect_policy_type_unknown() {
        let val = serde_json::json!({
            "unknown_field": true
        });
        assert_eq!(detect_policy_type(&val), None);
    }
}
