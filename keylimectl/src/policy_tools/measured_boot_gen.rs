// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Measured boot policy generation from UEFI event logs.
//!
//! Uses the shared `keylime::uefi::UefiLogHandler` to parse binary
//! event logs and extract Secure Boot variables, firmware measurements,
//! and kernel boot chain entries into a measured boot policy.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::measured_boot_policy::{
    MeasuredBootPolicy, ScrtmBiosEntry,
};
use keylime::uefi::UefiLogHandler;
use std::collections::HashMap;
use std::path::Path;

/// Generate a measured boot policy from a UEFI event log file.
pub fn generate_from_eventlog(
    path: &Path,
    include_secureboot: bool,
) -> Result<MeasuredBootPolicy, PolicyGenerationError> {
    let path_str =
        path.to_str().ok_or_else(|| PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: "Invalid path encoding".to_string(),
        })?;

    let handler = UefiLogHandler::new(path_str).map_err(|e| {
        PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: format!("Failed to parse UEFI event log: {e}"),
        }
    })?;

    let mut policy = MeasuredBootPolicy::new(include_secureboot);

    // Extract S-CRTM and BIOS measurements (PCR 0)
    extract_scrtm_bios(&handler, &mut policy);

    // Extract Secure Boot variables (PCR 7) if requested
    if include_secureboot {
        extract_secureboot_events(&handler, &mut policy);
    }

    Ok(policy)
}

/// Extract S-CRTM and platform firmware measurements.
fn extract_scrtm_bios(
    handler: &UefiLogHandler,
    policy: &mut MeasuredBootPolicy,
) {
    let pcr0_events = handler.get_events_for_pcr_index(0);

    let mut scrtm: HashMap<String, String> = HashMap::new();
    let mut platform_firmware: Vec<HashMap<String, String>> = Vec::new();

    for event in &pcr0_events {
        match event.event_type.as_str() {
            "EV_S_CRTM_VERSION" => {
                for (alg, digest) in &event.digests {
                    let _ = scrtm.insert(
                        alg.clone(),
                        format!("0x{}", hex::encode(digest)),
                    );
                }
            }
            "EV_S_CRTM_CONTENTS"
            | "EV_EFI_PLATFORM_FIRMWARE_BLOB"
            | "EV_POST_CODE" => {
                let mut fw_entry: HashMap<String, String> = HashMap::new();
                for (alg, digest) in &event.digests {
                    let _ = fw_entry.insert(
                        alg.clone(),
                        format!("0x{}", hex::encode(digest)),
                    );
                }
                if !fw_entry.is_empty() {
                    platform_firmware.push(fw_entry);
                }
            }
            _ => {}
        }
    }

    if !scrtm.is_empty() || !platform_firmware.is_empty() {
        policy.scrtm_and_bios.push(ScrtmBiosEntry {
            scrtm,
            platform_firmware,
        });
    }
}

/// Extract Secure Boot variable events from PCR 7.
fn extract_secureboot_events(
    handler: &UefiLogHandler,
    policy: &mut MeasuredBootPolicy,
) {
    let pcr7_events = handler.get_events_for_pcr_index(7);

    for event in &pcr7_events {
        // EFI variable events on PCR 7 contain Secure Boot variable
        // measurements. The event_data contains the variable name and
        // content but parsing the full UEFI_VARIABLE_DATA structure
        // requires additional work. For now, we record them as
        // raw digests in the policy for reference.
        if event.event_type == "EV_EFI_VARIABLE_DRIVER_CONFIG"
            || event.event_type == "EV_EFI_VARIABLE_BOOT"
        {
            // The event data starts with the EFI variable name
            // GUID (16 bytes) + name length (8 bytes) + data length (8 bytes)
            // + Unicode name + data. We extract what we can.
            let event_data_hex = hex::encode(&event.event_data);

            // Try to detect variable name from event data
            let var_name = detect_efi_variable_name(&event.event_data);

            // Get the digest for the first available algorithm
            let digest = event
                .digests
                .iter()
                .next()
                .map(|(_, d)| hex::encode(d))
                .unwrap_or_default();

            // Classify based on variable name
            match var_name.as_deref() {
                Some("PK") => {
                    policy.pk.push(
                        crate::policy_tools::measured_boot_policy::SecureBootSignature {
                            signature_owner: "uefi-var".to_string(),
                            signature_data: format!("0x{digest}"),
                        },
                    );
                }
                Some("KEK") => {
                    policy.kek.push(
                        crate::policy_tools::measured_boot_policy::SecureBootSignature {
                            signature_owner: "uefi-var".to_string(),
                            signature_data: format!("0x{digest}"),
                        },
                    );
                }
                Some("db") => {
                    policy.db.push(
                        crate::policy_tools::measured_boot_policy::SecureBootSignature {
                            signature_owner: "uefi-var".to_string(),
                            signature_data: format!("0x{digest}"),
                        },
                    );
                }
                Some("dbx") => {
                    policy.dbx.push(
                        crate::policy_tools::measured_boot_policy::SecureBootSignature {
                            signature_owner: "uefi-var".to_string(),
                            signature_data: format!("0x{digest}"),
                        },
                    );
                }
                _ => {
                    // Other Secure Boot variable - skip for now
                    log::debug!(
                        "Skipping EFI variable event: data=0x{}...",
                        &event_data_hex
                            [..std::cmp::min(32, event_data_hex.len())]
                    );
                }
            }
        }
    }
}

/// Try to extract the EFI variable name from event data.
///
/// UEFI_VARIABLE_DATA structure:
/// - VariableName (GUID, 16 bytes)
/// - UnicodeNameLength (u64, 8 bytes)
/// - VariableDataLength (u64, 8 bytes)
/// - UnicodeName (UnicodeNameLength * 2 bytes, UTF-16LE)
/// - VariableData (VariableDataLength bytes)
fn detect_efi_variable_name(event_data: &[u8]) -> Option<String> {
    // Need at least GUID (16) + name_len (8) + data_len (8) = 32 bytes
    if event_data.len() < 32 {
        return None;
    }

    // Read UnicodeNameLength at offset 16
    let name_len_bytes: [u8; 8] = event_data[16..24].try_into().ok()?;
    let name_len = u64::from_le_bytes(name_len_bytes) as usize;

    if name_len == 0 || event_data.len() < 32 + name_len * 2 {
        return None;
    }

    // Read Unicode name starting at offset 32
    let name_bytes = &event_data[32..32 + name_len * 2];

    // Decode UTF-16LE
    let u16_chars: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16(&u16_chars)
        .ok()
        .map(|s| s.trim_end_matches('\0').to_string())
}

/// Summary statistics for a generated measured boot policy.
#[allow(dead_code)]
pub struct MeasuredBootStats {
    /// Total number of events processed.
    pub total_events: usize,
    /// Number of S-CRTM/BIOS entries.
    pub scrtm_entries: usize,
    /// Number of Secure Boot variable entries.
    pub secureboot_entries: usize,
    /// Active hash algorithms.
    pub algorithms: Vec<String>,
}

/// Get statistics from the UEFI event log.
#[allow(dead_code)]
pub fn get_eventlog_stats(
    path: &Path,
) -> Result<MeasuredBootStats, PolicyGenerationError> {
    let path_str =
        path.to_str().ok_or_else(|| PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: "Invalid path encoding".to_string(),
        })?;

    let handler = UefiLogHandler::new(path_str).map_err(|e| {
        PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: format!("Failed to parse UEFI event log: {e}"),
        }
    })?;

    Ok(MeasuredBootStats {
        total_events: handler.get_entry_count(),
        scrtm_entries: handler.get_events_for_pcr_index(0).len(),
        secureboot_entries: handler.get_events_for_pcr_index(7).len(),
        algorithms: handler.get_active_algorithms().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_efi_variable_name_pk() {
        // Build a fake UEFI_VARIABLE_DATA for "PK"
        let mut data = Vec::new();
        // GUID (16 bytes) - EFI_GLOBAL_VARIABLE_GUID
        data.extend_from_slice(&[
            0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00,
            0xe0, 0x98, 0x03, 0x2b, 0x8c,
        ]);
        // UnicodeNameLength = 2 (for "PK")
        data.extend_from_slice(&2u64.to_le_bytes());
        // VariableDataLength = 0
        data.extend_from_slice(&0u64.to_le_bytes());
        // UnicodeName "PK" in UTF-16LE
        data.extend_from_slice(&[b'P', 0, b'K', 0]);

        let name = detect_efi_variable_name(&data);
        assert_eq!(name, Some("PK".to_string()));
    }

    #[test]
    fn test_detect_efi_variable_name_secureboot() {
        let mut data = Vec::new();
        // GUID
        data.extend_from_slice(&[0u8; 16]);
        // Name "SecureBoot" = 10 chars
        data.extend_from_slice(&10u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        // UTF-16LE "SecureBoot"
        for c in "SecureBoot".chars() {
            data.push(c as u8);
            data.push(0);
        }

        let name = detect_efi_variable_name(&data);
        assert_eq!(name, Some("SecureBoot".to_string()));
    }

    #[test]
    fn test_detect_efi_variable_name_too_short() {
        let data = vec![0u8; 16]; // Too short
        assert!(detect_efi_variable_name(&data).is_none());
    }

    #[test]
    fn test_detect_efi_variable_name_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 16]); // GUID
        data.extend_from_slice(&0u64.to_le_bytes()); // name len = 0
        data.extend_from_slice(&0u64.to_le_bytes()); // data len = 0

        assert!(detect_efi_variable_name(&data).is_none());
    }

    #[test]
    fn test_nonexistent_eventlog() {
        let result =
            generate_from_eventlog(Path::new("/nonexistent/event.log"), true);
        assert!(result.is_err());
    }
}
