// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! TPM policy generation from PCR values.
//!
//! Generates a TPM policy by reading PCR values from a file
//! or (behind a feature flag) from the local TPM.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::tpm_policy::TpmPolicy;
#[cfg(any(feature = "tpm-local", feature = "tpm-quote-validation"))]
use std::env;
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

/// Map a hash algorithm name to `tss_esapi::interface_types::algorithm::HashingAlgorithm`.
#[cfg(any(feature = "tpm-local", feature = "tpm-quote-validation"))]
fn map_hash_algorithm(
    alg: &str,
) -> Result<
    tss_esapi::interface_types::algorithm::HashingAlgorithm,
    PolicyGenerationError,
> {
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    match alg.to_lowercase().as_str() {
        "sha1" => Ok(HashingAlgorithm::Sha1),
        "sha256" => Ok(HashingAlgorithm::Sha256),
        "sha384" => Ok(HashingAlgorithm::Sha384),
        "sha512" => Ok(HashingAlgorithm::Sha512),
        other => Err(PolicyGenerationError::UnsupportedAlgorithm {
            algorithm: format!("Unsupported TPM hash algorithm: {other}"),
        }),
    }
}

/// Map a u32 PCR index to a `tss_esapi::structures::PcrSlot`.
#[cfg(any(feature = "tpm-local", feature = "tpm-quote-validation"))]
fn map_pcr_slot(
    index: u32,
) -> Result<tss_esapi::structures::PcrSlot, PolicyGenerationError> {
    use tss_esapi::structures::PcrSlot;
    match index {
        0 => Ok(PcrSlot::Slot0),
        1 => Ok(PcrSlot::Slot1),
        2 => Ok(PcrSlot::Slot2),
        3 => Ok(PcrSlot::Slot3),
        4 => Ok(PcrSlot::Slot4),
        5 => Ok(PcrSlot::Slot5),
        6 => Ok(PcrSlot::Slot6),
        7 => Ok(PcrSlot::Slot7),
        8 => Ok(PcrSlot::Slot8),
        9 => Ok(PcrSlot::Slot9),
        10 => Ok(PcrSlot::Slot10),
        11 => Ok(PcrSlot::Slot11),
        12 => Ok(PcrSlot::Slot12),
        13 => Ok(PcrSlot::Slot13),
        14 => Ok(PcrSlot::Slot14),
        15 => Ok(PcrSlot::Slot15),
        16 => Ok(PcrSlot::Slot16),
        17 => Ok(PcrSlot::Slot17),
        18 => Ok(PcrSlot::Slot18),
        19 => Ok(PcrSlot::Slot19),
        20 => Ok(PcrSlot::Slot20),
        21 => Ok(PcrSlot::Slot21),
        22 => Ok(PcrSlot::Slot22),
        23 => Ok(PcrSlot::Slot23),
        _ => Err(PolicyGenerationError::Output {
            path: "<pcrs>".into(),
            reason: format!("PCR index {index} out of range (0-23)"),
        }),
    }
}

/// Generate a TPM policy by reading PCR values from the local TPM.
///
/// Requires the `tpm-local` or `tpm-quote-validation` feature flag.
#[cfg(any(feature = "tpm-local", feature = "tpm-quote-validation"))]
pub fn generate_from_tpm(
    pcr_indices: &[u32],
    hash_alg: &str,
) -> Result<TpmPolicy, PolicyGenerationError> {
    use crate::policy_tools::privilege;
    use tss_esapi::structures::PcrSelectionListBuilder;
    use tss_esapi::tcti_ldr::TctiNameConf;

    let hashing_alg = map_hash_algorithm(hash_alg)?;

    // Map indices to PcrSlots
    let slots: Vec<tss_esapi::structures::PcrSlot> = pcr_indices
        .iter()
        .map(|&idx| map_pcr_slot(idx))
        .collect::<Result<Vec<_>, _>>()?;

    // Build PCR selection list
    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(hashing_alg, &slots)
        .build()
        .map_err(|e| PolicyGenerationError::Output {
            path: "<tpm>".into(),
            reason: format!("Failed to build PCR selection: {e}"),
        })?;

    // Determine TCTI path
    let tcti_str = env::var("TPM2TOOLS_TCTI")
        .or_else(|_| env::var("TCTI"))
        .unwrap_or_else(|_| "device:/dev/tpmrm0".to_string());

    let tcti: TctiNameConf =
        tcti_str
            .parse()
            .map_err(|e| PolicyGenerationError::Output {
                path: "<tpm>".into(),
                reason: format!(
                    "Failed to parse TCTI configuration '{tcti_str}': {e}"
                ),
            })?;

    // Open TPM context
    let mut context = tss_esapi::Context::new(tcti).map_err(|e| {
        if privilege::is_permission_error(&std::io::Error::new(
            if e.to_string().contains("Permission")
                || e.to_string().contains("EACCES")
            {
                std::io::ErrorKind::PermissionDenied
            } else {
                std::io::ErrorKind::Other
            },
            e.to_string(),
        )) {
            PolicyGenerationError::PrivilegeRequired {
                operation: "policy generate tpm --from-tpm".to_string(),
                path: std::path::PathBuf::from("/dev/tpmrm0"),
                hint: privilege::suggest_sudo(
                    "policy generate tpm --from-tpm",
                ),
            }
        } else {
            PolicyGenerationError::Output {
                path: "<tpm>".into(),
                reason: format!("Failed to open TPM context: {e}"),
            }
        }
    })?;

    // Read PCR values
    let (_, _, pcr_digests) = context
        .execute_without_session(|ctx| ctx.pcr_read(pcr_selection.clone()))
        .map_err(|e| PolicyGenerationError::Output {
            path: "<tpm>".into(),
            reason: format!("Failed to read PCR values: {e}"),
        })?;

    // Extract digest bytes and build PCR value pairs
    let mut pcrs: Vec<(u32, String)> = Vec::new();

    for (slot_idx, digest) in pcr_digests.value().iter().enumerate() {
        if slot_idx < pcr_indices.len() {
            let hex_value = hex::encode(digest.value());
            pcrs.push((pcr_indices[slot_idx], hex_value));
        }
    }

    if pcrs.is_empty() {
        return Err(PolicyGenerationError::Output {
            path: "<tpm>".into(),
            reason: "No PCR values read from TPM".to_string(),
        });
    }

    Ok(TpmPolicy::from_pcrs(&pcrs))
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
