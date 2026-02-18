// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! TPM policy generation from PCR values.
//!
//! Generates a TPM policy by reading PCR values from a file
//! or (behind a feature flag) from the local TPM.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::tpm_policy::TpmPolicy;
use std::path::Path;

/// Generate a TPM policy from a PCR values file.
///
/// The file should contain one PCR value per line in the format:
/// ```text
/// PCR_INDEX HEX_VALUE
/// ```
/// or simply one hex value per line (index is inferred from line number).
pub fn generate_from_file(
    path: &Path,
    pcr_indices: &[u32],
) -> Result<TpmPolicy, PolicyGenerationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: format!("Failed to read PCR file: {e}"),
        }
    })?;

    let mut pcrs: Vec<(u32, String)> = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Try "INDEX VALUE" format first
        let parts: Vec<&str> =
            line.splitn(2, |c: char| c.is_whitespace()).collect();

        let (index, value) = if parts.len() == 2 {
            let idx = parts[0].trim().parse::<u32>().map_err(|e| {
                PolicyGenerationError::Output {
                    path: path.to_path_buf(),
                    reason: format!(
                        "Invalid PCR index on line {}: {e}",
                        line_idx + 1
                    ),
                }
            })?;
            (idx, parts[1].trim().to_string())
        } else {
            // Single value per line - index from line number
            let idx = line_idx as u32;
            (idx, line.to_string())
        };

        // Only include if it's in the requested indices
        if pcr_indices.contains(&index) {
            // Validate hex value
            if !value.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(PolicyGenerationError::Output {
                    path: path.to_path_buf(),
                    reason: format!(
                        "Invalid hex value for PCR {index}: '{value}'"
                    ),
                });
            }
            pcrs.push((index, value));
        }
    }

    if pcrs.is_empty() {
        return Err(PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: "No PCR values found for the requested indices"
                .to_string(),
        });
    }

    Ok(TpmPolicy::from_pcrs(&pcrs))
}

/// Parse a comma-separated list of PCR indices.
pub fn parse_pcr_indices(
    pcrs_str: &str,
) -> Result<Vec<u32>, PolicyGenerationError> {
    let mut indices = Vec::new();
    for part in pcrs_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let idx = part.parse::<u32>().map_err(|e| {
            PolicyGenerationError::Output {
                path: "<pcrs>".into(),
                reason: format!("Invalid PCR index '{part}': {e}"),
            }
        })?;
        if idx > 23 {
            return Err(PolicyGenerationError::Output {
                path: "<pcrs>".into(),
                reason: format!("PCR index {idx} out of range (0-23)"),
            });
        }
        indices.push(idx);
    }
    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_from_file_indexed() {
        let mut tmp = NamedTempFile::new().unwrap(); //#[allow_ci]
        writeln!(tmp, "0 aabbccdd").unwrap(); //#[allow_ci]
        writeln!(tmp, "7 eeff0011").unwrap(); //#[allow_ci]
        writeln!(tmp, "14 22334455").unwrap(); //#[allow_ci]

        let policy = generate_from_file(tmp.path(), &[0, 7, 14]).unwrap(); //#[allow_ci]

        assert_eq!(policy.pcr_values.len(), 3);
        assert_eq!(policy.pcr_values["0"], "aabbccdd");
        assert_eq!(policy.pcr_values["7"], "eeff0011");
    }

    #[test]
    fn test_generate_from_file_sequential() {
        let mut tmp = NamedTempFile::new().unwrap(); //#[allow_ci]
        writeln!(tmp, "aaaa").unwrap(); //#[allow_ci]
        writeln!(tmp, "bbbb").unwrap(); //#[allow_ci]
        writeln!(tmp, "cccc").unwrap(); //#[allow_ci]

        let policy = generate_from_file(tmp.path(), &[0, 1, 2]).unwrap(); //#[allow_ci]

        assert_eq!(policy.pcr_values.len(), 3);
        assert_eq!(policy.pcr_values["0"], "aaaa");
        assert_eq!(policy.pcr_values["1"], "bbbb");
        assert_eq!(policy.pcr_values["2"], "cccc");
    }

    #[test]
    fn test_generate_from_file_filter_indices() {
        let mut tmp = NamedTempFile::new().unwrap(); //#[allow_ci]
        writeln!(tmp, "0 aaaa").unwrap(); //#[allow_ci]
        writeln!(tmp, "1 bbbb").unwrap(); //#[allow_ci]
        writeln!(tmp, "7 cccc").unwrap(); //#[allow_ci]

        // Only request PCR 0 and 7
        let policy = generate_from_file(tmp.path(), &[0, 7]).unwrap(); //#[allow_ci]

        assert_eq!(policy.pcr_values.len(), 2);
        assert!(policy.pcr_values.contains_key("0"));
        assert!(policy.pcr_values.contains_key("7"));
        assert!(!policy.pcr_values.contains_key("1"));
    }

    #[test]
    fn test_generate_from_file_comments() {
        let mut tmp = NamedTempFile::new().unwrap(); //#[allow_ci]
        writeln!(tmp, "# PCR values").unwrap(); //#[allow_ci]
        writeln!(tmp, "0 aaaa").unwrap(); //#[allow_ci]
        writeln!(tmp).unwrap(); //#[allow_ci]
        writeln!(tmp, "7 bbbb").unwrap(); //#[allow_ci]

        let policy = generate_from_file(tmp.path(), &[0, 7]).unwrap(); //#[allow_ci]

        assert_eq!(policy.pcr_values.len(), 2);
    }

    #[test]
    fn test_generate_from_file_invalid_hex() {
        let mut tmp = NamedTempFile::new().unwrap(); //#[allow_ci]
        writeln!(tmp, "0 not_hex!").unwrap(); //#[allow_ci]

        let result = generate_from_file(tmp.path(), &[0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_from_file_no_matching_pcrs() {
        let mut tmp = NamedTempFile::new().unwrap(); //#[allow_ci]
        writeln!(tmp, "0 aaaa").unwrap(); //#[allow_ci]

        let result = generate_from_file(
            tmp.path(),
            &[7], // PCR 7 not in file
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pcr_indices() {
        assert_eq!(
            parse_pcr_indices("0,1,2,7").unwrap(), //#[allow_ci]
            vec![0, 1, 2, 7]
        );
    }

    #[test]
    fn test_parse_pcr_indices_with_spaces() {
        assert_eq!(
            parse_pcr_indices("0, 1, 7").unwrap(), //#[allow_ci]
            vec![0, 1, 7]
        );
    }

    #[test]
    fn test_parse_pcr_indices_out_of_range() {
        assert!(parse_pcr_indices("0,1,25").is_err());
    }

    #[test]
    fn test_parse_pcr_indices_invalid() {
        assert!(parse_pcr_indices("0,abc,7").is_err());
    }
}
