// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! IMA measurement list and allowlist parsing for policy generation.
//!
//! Parses IMA ASCII runtime measurement lists to extract file digests,
//! keyring entries, and ima-buf entries for building runtime policies.
//! Also handles legacy flat-text and JSON allowlist formats.

use crate::commands::error::PolicyGenerationError;
use std::collections::HashMap;
use std::path::Path;

/// Map from file path (or entry name) to list of digest strings.
pub type DigestMap = HashMap<String, Vec<String>>;

/// Parsed data from an IMA measurement list.
pub struct ParsedImaData {
    /// File path -> list of digest strings (bare hex, e.g., `"abcdef1234..."`)
    pub digests: DigestMap,

    /// Keyring name -> list of digest strings
    pub keyrings: DigestMap,

    /// ima-buf entry name -> list of digest strings
    pub ima_buf: DigestMap,

    /// Detected hash algorithm name (from the first valid entry)
    pub detected_algorithm: Option<String>,
}

/// Parse an IMA ASCII measurement list file.
///
/// Reads the file line by line and extracts digests for entries
/// with `ima`, `ima-ng`, and `ima-sig` templates. Also extracts
/// `ima-buf` entries into separate maps based on whether they
/// appear to be keyring entries.
///
/// # Arguments
///
/// * `path` - Path to the IMA measurement list file
/// * `get_keyrings` - Whether to extract keyring entries from ima-buf
/// * `get_ima_buf` - Whether to extract non-keyring ima-buf entries
/// * `ignored_keyrings` - Keyring names to skip
pub fn parse_ima_measurement_list(
    path: &Path,
    get_keyrings: bool,
    get_ima_buf: bool,
    ignored_keyrings: &[String],
) -> Result<ParsedImaData, PolicyGenerationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        PolicyGenerationError::ImaParse {
            path: path.to_path_buf(),
            reason: format!("Failed to read file: {e}"),
        }
    })?;

    let mut digests: DigestMap = HashMap::new();
    let mut keyrings: DigestMap = HashMap::new();
    let mut ima_buf: DigestMap = HashMap::new();
    let mut detected_algorithm: Option<String> = None;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // IMA log format: <pcr> <template_hash> <template_name> <template_data...>
        let tokens: Vec<&str> = line.splitn(4, ' ').collect();
        if tokens.len() < 4 {
            // Skip malformed lines
            log::debug!(
                "Skipping malformed IMA line {}: too few fields",
                line_num + 1
            );
            continue;
        }

        let template_name = tokens[2];
        let template_data = tokens[3];

        match template_name {
            "ima" => {
                // Legacy template: <digest_hex> <path>
                if let Some((digest_hex, file_path)) =
                    parse_ima_template(template_data)
                {
                    // Detect algorithm from hex length
                    if detected_algorithm.is_none() {
                        detected_algorithm =
                            detect_algorithm_from_hex(digest_hex);
                    }
                    add_digest(
                        &mut digests,
                        file_path.to_string(),
                        digest_hex.to_string(),
                    );
                }
            }
            "ima-ng" | "ima-sig" => {
                // Modern templates: <alg:digest> <path> [signature]
                if let Some((digest_str, file_path)) =
                    parse_ima_ng_template(template_data)
                {
                    // Split "sha256:hex" into algorithm and bare hex
                    if let Some((alg, hex_value)) = digest_str.split_once(':')
                    {
                        if detected_algorithm.is_none() {
                            detected_algorithm = Some(alg.to_string());
                        }
                        add_digest(
                            &mut digests,
                            file_path.to_string(),
                            hex_value.to_string(),
                        );
                    }
                }
            }
            "ima-buf" => {
                if get_keyrings || get_ima_buf {
                    if let Some((digest_str, name, data_hex)) =
                        parse_ima_buf_template(template_data)
                    {
                        // Strip algorithm prefix from "sha256:hex"
                        let hex_value = digest_str
                            .split_once(':')
                            .map(|(_, h)| h)
                            .unwrap_or(digest_str);

                        // Check if this is a keyring entry by attempting
                        // to detect ASN.1 DER structure in the data
                        let is_keyring = is_asn1_data(data_hex);

                        if is_keyring && get_keyrings {
                            if !ignored_keyrings.contains(&name.to_string()) {
                                add_digest(
                                    &mut keyrings,
                                    name.to_string(),
                                    hex_value.to_string(),
                                );
                            }
                        } else if !is_keyring && get_ima_buf {
                            add_digest(
                                &mut ima_buf,
                                name.to_string(),
                                hex_value.to_string(),
                            );
                        }
                    }
                }
            }
            _ => {
                // Skip unrecognized templates
                log::debug!(
                    "Skipping unrecognized IMA template '{}' at line {}",
                    template_name,
                    line_num + 1
                );
            }
        }
    }

    Ok(ParsedImaData {
        digests,
        keyrings,
        ima_buf,
        detected_algorithm,
    })
}

/// Parse a flat-text allowlist file (hash whitespace path format).
///
/// Each line contains a digest value and a file path separated by whitespace.
/// Lines starting with `#` are treated as comments. Empty lines are skipped.
pub fn parse_flat_allowlist(
    path: &Path,
) -> Result<DigestMap, PolicyGenerationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        PolicyGenerationError::AllowlistParse {
            path: path.to_path_buf(),
            reason: format!("Failed to read file: {e}"),
        }
    })?;

    let mut digests: DigestMap = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split into hash and path
        let parts: Vec<&str> =
            line.splitn(2, |c: char| c.is_whitespace()).collect();
        if parts.len() != 2 {
            continue;
        }

        let hash = parts[0].trim();
        let file_path = parts[1].trim().replace(' ', "_");

        if !hash.is_empty() && !file_path.is_empty() {
            // Strip algorithm prefix if present (e.g., "sha256:hex" → "hex")
            let bare_hex =
                hash.split_once(':').map(|(_, h)| h).unwrap_or(hash);
            add_digest(&mut digests, file_path, bare_hex.to_string());
        }
    }

    Ok(digests)
}

/// Parse a JSON allowlist file.
///
/// Accepts either the legacy format with a `"hashes"` key or
/// the current format with a `"digests"` key.
pub fn parse_json_allowlist(
    path: &Path,
) -> Result<DigestMap, PolicyGenerationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        PolicyGenerationError::AllowlistParse {
            path: path.to_path_buf(),
            reason: format!("Failed to read file: {e}"),
        }
    })?;

    let value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| {
            PolicyGenerationError::AllowlistParse {
                path: path.to_path_buf(),
                reason: format!("Invalid JSON: {e}"),
            }
        })?;

    // Try "digests" key first, then "hashes" for legacy format
    let hashes = value
        .get("digests")
        .or_else(|| value.get("hashes"))
        .ok_or_else(|| PolicyGenerationError::AllowlistParse {
            path: path.to_path_buf(),
            reason: "Missing 'digests' or 'hashes' key".to_string(),
        })?;

    let hashes_map = hashes.as_object().ok_or_else(|| {
        PolicyGenerationError::AllowlistParse {
            path: path.to_path_buf(),
            reason: "'digests'/'hashes' is not an object".to_string(),
        }
    })?;

    let mut digests: DigestMap = HashMap::new();

    for (file_path, digest_list) in hashes_map {
        if let Some(arr) = digest_list.as_array() {
            for digest_val in arr {
                if let Some(digest_str) = digest_val.as_str() {
                    // Strip algorithm prefix if present (e.g., "sha256:hex" → "hex")
                    let bare_hex = digest_str
                        .split_once(':')
                        .map(|(_, h)| h)
                        .unwrap_or(digest_str);
                    add_digest(
                        &mut digests,
                        file_path.clone(),
                        bare_hex.to_string(),
                    );
                }
            }
        }
    }

    Ok(digests)
}

/// Parse an exclude list file (one glob pattern per line).
pub fn parse_excludelist(
    path: &Path,
) -> Result<Vec<String>, PolicyGenerationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        PolicyGenerationError::AllowlistParse {
            path: path.to_path_buf(),
            reason: format!("Failed to read exclude list: {e}"),
        }
    })?;

    let mut excludes = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            excludes.push(line.to_string());
        }
    }

    Ok(excludes)
}

/// Detect hash algorithm name from hex digest length.
///
/// Returns `None` for ambiguous lengths (SHA-256 and SM3-256 both produce
/// 64 hex characters).
pub fn detect_algorithm_from_hex(hex_digest: &str) -> Option<String> {
    match hex_digest.len() {
        40 => Some("sha1".to_string()),
        64 => Some("sha256".to_string()), // Could also be sm3_256
        96 => Some("sha384".to_string()),
        128 => Some("sha512".to_string()),
        _ => None,
    }
}

/// Merge two digest maps, appending new digests without duplicates.
#[allow(dead_code)] // Used in later steps (filesystem scanning, policy merging)
pub fn merge_digest_maps(base: &mut DigestMap, other: &DigestMap) {
    for (path, new_digests) in other {
        let entry = base.entry(path.clone()).or_default();
        for digest in new_digests {
            if !entry.contains(digest) {
                entry.push(digest.clone());
            }
        }
    }
}

/// Parse a JSON allowlist from a `serde_json::Value`.
///
/// Accepts either the legacy format with a `"hashes"` key or
/// the current format with a `"digests"` key.
pub fn parse_json_allowlist_value(
    value: &serde_json::Value,
) -> Result<DigestMap, PolicyGenerationError> {
    let hashes = value
        .get("digests")
        .or_else(|| value.get("hashes"))
        .ok_or_else(|| PolicyGenerationError::AllowlistParse {
            path: "<input>".into(),
            reason: "Missing 'digests' or 'hashes' key".to_string(),
        })?;

    let hashes_map = hashes.as_object().ok_or_else(|| {
        PolicyGenerationError::AllowlistParse {
            path: "<input>".into(),
            reason: "'digests'/'hashes' is not an object".to_string(),
        }
    })?;

    let mut digests: DigestMap = HashMap::new();

    for (file_path, digest_list) in hashes_map {
        if let Some(arr) = digest_list.as_array() {
            for digest_val in arr {
                if let Some(digest_str) = digest_val.as_str() {
                    // Strip algorithm prefix if present (e.g., "sha256:hex" → "hex")
                    let bare_hex = digest_str
                        .split_once(':')
                        .map(|(_, h)| h)
                        .unwrap_or(digest_str);
                    add_digest(
                        &mut digests,
                        file_path.clone(),
                        bare_hex.to_string(),
                    );
                }
            }
        }
    }

    Ok(digests)
}

/// Parse a flat-text allowlist from a string.
///
/// Each line contains a digest value and a file path separated by whitespace.
/// Lines starting with `#` are treated as comments. Empty lines are skipped.
pub fn parse_flat_allowlist_str(
    text: &str,
) -> Result<DigestMap, PolicyGenerationError> {
    let mut digests: DigestMap = HashMap::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> =
            line.splitn(2, |c: char| c.is_whitespace()).collect();
        if parts.len() != 2 {
            continue;
        }

        let hash = parts[0].trim();
        let file_path = parts[1].trim().replace(' ', "_");

        if !hash.is_empty() && !file_path.is_empty() {
            // Strip algorithm prefix if present (e.g., "sha256:hex" → "hex")
            let bare_hex =
                hash.split_once(':').map(|(_, h)| h).unwrap_or(hash);
            add_digest(&mut digests, file_path, bare_hex.to_string());
        }
    }

    Ok(digests)
}

// --- Internal parsing helpers ---

/// Parse legacy `ima` template data: `<digest_hex> <path>`
fn parse_ima_template(data: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = data.splitn(2, ' ').collect();
    if parts.len() == 2 {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

/// Parse `ima-ng` or `ima-sig` template data: `<alg:digest> <path> [signature]`
fn parse_ima_ng_template(data: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = data.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

/// Parse `ima-buf` template data: `<alg:digest> <name> <data_hex>`
fn parse_ima_buf_template(data: &str) -> Option<(&str, &str, &str)> {
    let parts: Vec<&str> = data.splitn(3, ' ').collect();
    if parts.len() == 3 {
        Some((parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// Check if hex-encoded data starts with an ASN.1 DER structure.
///
/// A simple heuristic: ASN.1 DER sequences start with tag 0x30 (SEQUENCE).
/// This is used to distinguish keyring entries (certificates/keys) from
/// other ima-buf entries.
fn is_asn1_data(hex_data: &str) -> bool {
    // ASN.1 SEQUENCE tag
    hex_data.starts_with("30")
}

/// Add a digest to a digest map, avoiding duplicates.
fn add_digest(map: &mut DigestMap, path: String, digest: String) {
    let entry = map.entry(path).or_default();
    if !entry.contains(&digest) {
        entry.push(digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap(); //#[allow_ci]
        f.write_all(content.as_bytes()).unwrap(); //#[allow_ci]
        f
    }

    #[test]
    fn test_parse_ima_ng_line() {
        let data = "sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /usr/bin/bash";
        let result = parse_ima_ng_template(data);
        assert!(result.is_some());
        let (digest, path) = result.unwrap(); //#[allow_ci]
        assert_eq!(digest, "sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e");
        assert_eq!(path, "/usr/bin/bash");
    }

    #[test]
    fn test_parse_ima_sig_line() {
        let data = "sha256:abcdef1234567890 /usr/bin/foo 030202531f40250048";
        let result = parse_ima_ng_template(data);
        assert!(result.is_some());
        let (digest, path) = result.unwrap(); //#[allow_ci]
        assert_eq!(digest, "sha256:abcdef1234567890");
        assert_eq!(path, "/usr/bin/foo");
    }

    #[test]
    fn test_parse_ima_buf_line() {
        let data = "sha256:abcdef1234567890 device_resume 6e616d653d54455354";
        let result = parse_ima_buf_template(data);
        assert!(result.is_some());
        let (digest, name, buf) = result.unwrap(); //#[allow_ci]
        assert_eq!(digest, "sha256:abcdef1234567890");
        assert_eq!(name, "device_resume");
        assert_eq!(buf, "6e616d653d54455354");
    }

    #[test]
    fn test_parse_legacy_ima_line() {
        let data = "6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e /usr/bin/kmod";
        let result = parse_ima_template(data);
        assert!(result.is_some());
        let (digest, path) = result.unwrap(); //#[allow_ci]
        assert_eq!(digest, "6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e");
        assert_eq!(path, "/usr/bin/kmod");
    }

    #[test]
    fn test_detect_algorithm_from_hex() {
        assert_eq!(
            detect_algorithm_from_hex(
                "6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e"
            ),
            Some("sha1".to_string())
        );
        assert_eq!(
            detect_algorithm_from_hex(
                "f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e"
            ),
            Some("sha256".to_string())
        );
        assert_eq!(detect_algorithm_from_hex("abcd"), None);
    }

    #[test]
    fn test_parse_ima_measurement_list() {
        let content = "\
10 d7026dc672344d3ee372217bdbc7395947788671 ima 6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e /usr/bin/kmod
10 7936eb315fb4e74b99e7d461bc5c96049e1ee092 ima-ng sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /usr/bin/bash
10 06e804489a77ddab51b9ef27e17053c0e5d503bd ima-sig sha256:1cb84b12db45d7da8de58ba6744187db84082f0e1cb84b12db45d7da8de58ba6 /usr/bin/ls 030202531f402500
";
        let f = write_temp_file(content);
        let result =
            parse_ima_measurement_list(f.path(), false, false, &[]).unwrap(); //#[allow_ci]

        assert_eq!(result.digests.len(), 3);
        assert!(result.digests.contains_key("/usr/bin/kmod"));
        assert!(result.digests.contains_key("/usr/bin/bash"));
        assert!(result.digests.contains_key("/usr/bin/ls"));
        // Digests are stored as bare hex (algorithm prefix stripped)
        assert_eq!(
            result.digests["/usr/bin/bash"],
            vec!["f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e"]
        );
    }

    #[test]
    fn test_parse_ima_measurement_list_with_ima_buf() {
        let content = "\
10 aaaa ima-ng sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 /usr/bin/foo
10 bbbb ima-buf sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef device_resume 6e616d653d54455354
10 cccc ima-buf sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321 .builtin_trusted_keys 308201a2
";
        let f = write_temp_file(content);
        let result =
            parse_ima_measurement_list(f.path(), true, true, &[]).unwrap(); //#[allow_ci]

        assert_eq!(result.digests.len(), 1);
        // device_resume is not ASN.1, so it goes to ima_buf
        assert_eq!(result.ima_buf.len(), 1);
        assert!(result.ima_buf.contains_key("device_resume"));
        // .builtin_trusted_keys starts with 0x30 (ASN.1 SEQUENCE), so it goes to keyrings
        assert_eq!(result.keyrings.len(), 1);
        assert!(result.keyrings.contains_key(".builtin_trusted_keys"));
    }

    #[test]
    fn test_parse_ima_measurement_list_ignored_keyrings() {
        let content = "\
10 cccc ima-buf sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321 .builtin_trusted_keys 308201a2
10 dddd ima-buf sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 _ima 308201b3
";
        let f = write_temp_file(content);
        let result = parse_ima_measurement_list(
            f.path(),
            true,
            false,
            &["_ima".to_string()],
        )
        .unwrap(); //#[allow_ci]

        assert_eq!(result.keyrings.len(), 1);
        assert!(result.keyrings.contains_key(".builtin_trusted_keys"));
        assert!(!result.keyrings.contains_key("_ima"));
    }

    #[test]
    fn test_parse_flat_allowlist() {
        let content = "\
# Comment line
6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e  /usr/bin/kmod
abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  /usr/bin/bash

";
        let f = write_temp_file(content);
        let result = parse_flat_allowlist(f.path()).unwrap(); //#[allow_ci]

        assert_eq!(result.len(), 2);
        assert_eq!(
            result["/usr/bin/kmod"],
            vec!["6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e"]
        );
    }

    #[test]
    fn test_parse_json_allowlist_digests_key() {
        let content = r#"{
            "digests": {
                "/usr/bin/bash": ["sha256:abcdef1234567890"],
                "/usr/bin/ls": ["sha256:1234567890abcdef", "sha1:aabbccddee"]
            }
        }"#;
        let f = write_temp_file(content);
        let result = parse_json_allowlist(f.path()).unwrap(); //#[allow_ci]

        assert_eq!(result.len(), 2);
        // Algorithm prefix is stripped
        assert_eq!(result["/usr/bin/bash"], vec!["abcdef1234567890"]);
        assert_eq!(result["/usr/bin/ls"].len(), 2);
    }

    #[test]
    fn test_parse_json_allowlist_hashes_key() {
        let content = r#"{
            "hashes": {
                "/usr/bin/foo": ["sha256:deadbeef"]
            }
        }"#;
        let f = write_temp_file(content);
        let result = parse_json_allowlist(f.path()).unwrap(); //#[allow_ci]

        assert_eq!(result.len(), 1);
        // Algorithm prefix is stripped
        assert_eq!(result["/usr/bin/foo"], vec!["deadbeef"]);
    }

    #[test]
    fn test_parse_excludelist() {
        let content = "\
# Skip boot aggregate
boot_aggregate
/tmp/*
/proc/*
";
        let f = write_temp_file(content);
        let result = parse_excludelist(f.path()).unwrap(); //#[allow_ci]

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "boot_aggregate");
        assert_eq!(result[1], "/tmp/*");
        assert_eq!(result[2], "/proc/*");
    }

    #[test]
    fn test_merge_digest_maps() {
        let mut base: DigestMap = HashMap::new();
        let _ = base
            .insert("/usr/bin/bash".to_string(), vec!["aaaa".to_string()]);

        let mut other: DigestMap = HashMap::new();
        let _ = other.insert(
            "/usr/bin/bash".to_string(),
            vec![
                "aaaa".to_string(), // duplicate
                "bbbb".to_string(), // new
            ],
        );
        let _ =
            other.insert("/usr/bin/ls".to_string(), vec!["cccc".to_string()]);

        merge_digest_maps(&mut base, &other);

        assert_eq!(base.len(), 2);
        // Duplicate should not be added
        assert_eq!(base["/usr/bin/bash"].len(), 2);
        assert_eq!(base["/usr/bin/bash"][0], "aaaa");
        assert_eq!(base["/usr/bin/bash"][1], "bbbb");
        assert_eq!(base["/usr/bin/ls"], vec!["cccc"]);
    }

    #[test]
    fn test_is_asn1_data() {
        // ASN.1 SEQUENCE starts with 0x30
        assert!(is_asn1_data("308201a2"));
        // Not ASN.1
        assert!(!is_asn1_data("6e616d653d54455354"));
        assert!(!is_asn1_data(""));
    }

    #[test]
    fn test_flat_allowlist_space_in_path_replaced() {
        // Flat allowlists may have paths with spaces; IMA uses underscores
        let content = "\
abcdef1234567890  /path/with space/file
";
        let f = write_temp_file(content);
        let result = parse_flat_allowlist(f.path()).unwrap(); //#[allow_ci]

        // Spaces in paths should be replaced with underscores
        assert!(result.contains_key("/path/with_space/file"));
    }

    #[test]
    fn test_detected_algorithm() {
        let content = "\
10 aaaa ima-ng sha384:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 /usr/bin/foo
";
        let f = write_temp_file(content);
        let result =
            parse_ima_measurement_list(f.path(), false, false, &[]).unwrap(); //#[allow_ci]

        assert_eq!(result.detected_algorithm, Some("sha384".to_string()));
    }
}
