// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Legacy allowlist format conversion to v1 runtime policy.
//!
//! Converts JSON and flat-text allowlists (from the older Python
//! `keylime_create_allowlist` tool) into the v1 runtime policy format
//! used by `keylimectl`.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::ima_parser;
use crate::policy_tools::runtime_policy::RuntimePolicy;
use std::path::Path;

/// Auto-detect the allowlist format and convert to a runtime policy.
///
/// Tries JSON first, then falls back to flat-text format.
pub fn convert_allowlist(
    input: &[u8],
) -> Result<RuntimePolicy, PolicyGenerationError> {
    // Try JSON first
    if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(input) {
        return convert_json_allowlist(&json_val);
    }

    // Fall back to flat-text
    let text = std::str::from_utf8(input).map_err(|e| {
        PolicyGenerationError::AllowlistParse {
            path: "<input>".into(),
            reason: format!("Input is not valid UTF-8: {e}"),
        }
    })?;

    convert_flat_allowlist(text)
}

/// Convert a JSON allowlist to a runtime policy.
///
/// Accepts the legacy format: `{"hashes": {"/path": ["digest"]}}`
/// or the newer: `{"digests": {"/path": ["algorithm:hex"]}}`.
pub fn convert_json_allowlist(
    json: &serde_json::Value,
) -> Result<RuntimePolicy, PolicyGenerationError> {
    let digests = ima_parser::parse_json_allowlist_value(json)?;

    let mut policy = RuntimePolicy::new();
    for (path, digest_list) in &digests {
        for digest in digest_list {
            policy.add_digest(path.clone(), digest.clone());
        }
    }

    Ok(policy)
}

/// Convert a flat-text allowlist to a runtime policy.
///
/// Format: one entry per line, each line is `hex_digest<whitespace>path`.
pub fn convert_flat_allowlist(
    text: &str,
) -> Result<RuntimePolicy, PolicyGenerationError> {
    let digests = ima_parser::parse_flat_allowlist_str(text)?;

    let mut policy = RuntimePolicy::new();
    for (path, digest_list) in &digests {
        for digest in digest_list {
            policy.add_digest(path.clone(), digest.clone());
        }
    }

    Ok(policy)
}

/// Merge an exclude list into a policy.
pub fn merge_excludelist(policy: &mut RuntimePolicy, excludes: &[String]) {
    for exclude in excludes {
        policy.add_exclude(exclude.clone());
    }
}

/// Add verification keys from a file to a policy.
pub fn add_verification_keys(
    policy: &mut RuntimePolicy,
    key_path: &str,
) -> Result<(), PolicyGenerationError> {
    let key_content = std::fs::read_to_string(key_path).map_err(|e| {
        PolicyGenerationError::Output {
            path: key_path.into(),
            reason: format!("Failed to read verification key: {e}"),
        }
    })?;

    // Append to existing verification keys (JSON-encoded)
    if policy.verification_keys.is_empty() {
        policy.verification_keys = key_content;
    } else {
        policy.verification_keys.push('\n');
        policy.verification_keys.push_str(&key_content);
    }

    Ok(())
}

/// Convert an allowlist file (auto-detect format) to a runtime policy.
pub fn convert_allowlist_file(
    path: &Path,
) -> Result<RuntimePolicy, PolicyGenerationError> {
    let content = std::fs::read(path).map_err(|e| {
        PolicyGenerationError::AllowlistParse {
            path: path.to_path_buf(),
            reason: format!("Failed to read file: {e}"),
        }
    })?;

    convert_allowlist(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_convert_json_allowlist_hashes_key() {
        let json = json!({
            "hashes": {
                "/usr/bin/bash": ["sha256:aabbccdd"],
                "/usr/bin/ls": ["sha256:eeff0011", "sha1:aabb"]
            }
        });

        let policy = convert_json_allowlist(&json).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 2);
        // Algorithm prefix is stripped during conversion
        assert_eq!(policy.digests["/usr/bin/bash"], vec!["aabbccdd"]);
        assert_eq!(policy.digests["/usr/bin/ls"].len(), 2);
    }

    #[test]
    fn test_convert_json_allowlist_digests_key() {
        let json = json!({
            "digests": {
                "/usr/bin/test": ["sha256:1234"]
            }
        });

        let policy = convert_json_allowlist(&json).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 1);
    }

    #[test]
    fn test_convert_flat_allowlist() {
        let text =
            "sha256:aabb1122\t/usr/bin/bash\nsha256:ccdd3344\t/usr/bin/ls\n";

        let policy = convert_flat_allowlist(text).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 2);
        // Algorithm prefix is stripped during conversion
        assert_eq!(policy.digests["/usr/bin/bash"], vec!["aabb1122"]);
    }

    #[test]
    fn test_auto_detect_json() {
        let input = br#"{"hashes": {"/test": ["sha256:abcd"]}}"#;

        let policy = convert_allowlist(input).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 1);
    }

    #[test]
    fn test_auto_detect_flat() {
        let input = b"sha256:abcd\t/test\n";

        let policy = convert_allowlist(input).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 1);
    }

    #[test]
    fn test_merge_excludelist() {
        let mut policy = RuntimePolicy::new();
        merge_excludelist(
            &mut policy,
            &["/tmp/*".to_string(), "/proc/*".to_string()],
        );
        assert_eq!(policy.exclude_count(), 2);
    }

    #[test]
    fn test_merge_excludelist_dedup() {
        let mut policy = RuntimePolicy::new();
        policy.add_exclude("/tmp/*".to_string());
        merge_excludelist(
            &mut policy,
            &["/tmp/*".to_string(), "/proc/*".to_string()],
        );
        assert_eq!(policy.exclude_count(), 2);
    }

    #[test]
    fn test_add_verification_keys() {
        let mut policy = RuntimePolicy::new();

        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), "PEM KEY DATA").unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_eq!(policy.verification_keys, "PEM KEY DATA");
    }

    #[test]
    fn test_convert_nonexistent_file() {
        let result = convert_allowlist_file(Path::new("/nonexistent/file"));
        assert!(result.is_err());
    }
}
