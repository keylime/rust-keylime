// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Measured boot policy generation from UEFI event logs.
//!
//! Uses the shared `keylime::uefi::UefiLogHandler` to parse binary
//! event logs and extract Secure Boot variables, firmware measurements,
//! and kernel boot chain entries into a measured boot policy.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::measured_boot_policy::{
    KernelEntry, MeasuredBootPolicy, ScrtmBiosEntry, SecureBootSignature,
};
use crate::policy_tools::uefi_event_data;
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

    // Extract kernel boot chain (PCR 4, 8, 9)
    extract_kernel_entries(&handler, &mut policy, include_secureboot);

    // Extract MOK (Machine Owner Key) digests
    extract_mok(&handler, &mut policy);

    // Extract vendor_db from EV_EFI_VARIABLE_AUTHORITY events
    extract_vendor_db(&handler, &mut policy);

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
            | "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
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
        if event.event_type != "EV_EFI_VARIABLE_DRIVER_CONFIG"
            && event.event_type != "EV_EFI_VARIABLE_BOOT"
        {
            continue;
        }

        let var_data =
            uefi_event_data::parse_efi_variable_data(&event.event_data);

        let var_name = var_data.as_ref().map(|v| v.variable_name.as_str());

        // Get the digest for the first available algorithm
        let digest = event
            .digests
            .iter()
            .next()
            .map(|(_, d)| hex::encode(d))
            .unwrap_or_default();

        let sig = SecureBootSignature {
            signature_owner: "uefi-var".to_string(),
            signature_data: format!("0x{digest}"),
        };

        match var_name {
            Some("PK") => policy.pk.push(sig),
            Some("KEK") => policy.kek.push(sig),
            Some("db") => policy.db.push(sig),
            Some("dbx") => policy.dbx.push(sig),
            _ => {
                log::debug!("Skipping EFI variable event: {:?}", var_name);
            }
        }
    }
}

/// Extract kernel boot chain entries from PCRs 4, 8, and 9.
///
/// Following the Python `create_mb_policy.get_kernel()` logic:
/// - PCR 4 `EV_EFI_BOOT_SERVICES_APPLICATION` events: shim (0), grub (1), kernel (2)
/// - PCR 8 `EV_IPL` events: kernel command line
/// - PCR 9 `EV_IPL` events: initrd/initramfs and vmlinuz digests
fn extract_kernel_entries(
    handler: &UefiLogHandler,
    policy: &mut MeasuredBootPolicy,
    has_secureboot: bool,
) {
    let mut entry = KernelEntry {
        shim_authcode_sha256: None,
        grub_authcode_sha256: None,
        kernel_authcode_sha256: None,
        initrd_plain_sha256: None,
        vmlinuz_plain_sha256: None,
        kernel_cmdline: None,
    };

    // --- PCR 4: Boot services applications (shim, grub, kernel) ---
    let pcr4_boot_apps: Vec<_> = handler
        .get_events_for_pcr_index(4)
        .into_iter()
        .filter(|e| e.event_type == "EV_EFI_BOOT_SERVICES_APPLICATION")
        .collect();

    // Extract sha256 digests in order: [0]=shim, [1]=grub, [2]=kernel
    for (idx, event) in pcr4_boot_apps.iter().enumerate() {
        let sha256_digest = event
            .digests
            .get("sha256")
            .map(|d| format!("0x{}", hex::encode(d)));

        match idx {
            0 => {
                entry.shim_authcode_sha256 = sha256_digest;
            }
            1 => {
                entry.grub_authcode_sha256 = sha256_digest;
            }
            2 if has_secureboot => {
                entry.kernel_authcode_sha256 = sha256_digest;
            }
            _ => break,
        }
    }

    // --- PCR 8: Kernel command line ---
    let pcr8_ipl: Vec<_> = handler
        .get_events_for_pcr_index(8)
        .into_iter()
        .filter(|e| e.event_type == "EV_IPL")
        .collect();

    for event in &pcr8_ipl {
        if let Some(s) = uefi_event_data::parse_ipl_string(&event.event_data)
        {
            // GRUB prefixes the command line with "kernel_cmdline: "
            // or the string itself IS the command line
            if s.contains("kernel_cmdline") {
                // Extract the actual command line after the prefix
                let cmdline = s
                    .strip_prefix("kernel_cmdline: ")
                    .or_else(|| s.strip_prefix("kernel_cmdline:"))
                    .unwrap_or(&s);
                entry.kernel_cmdline = Some(cmdline.to_string());
                break;
            }
        }
    }

    // If no "kernel_cmdline" prefix found, try the last PCR 8 EV_IPL event
    if entry.kernel_cmdline.is_none() {
        if let Some(event) = pcr8_ipl.last() {
            if let Some(s) =
                uefi_event_data::parse_ipl_string(&event.event_data)
            {
                if !s.is_empty() {
                    entry.kernel_cmdline = Some(s);
                }
            }
        }
    }

    // --- PCR 9: initrd/initramfs and vmlinuz ---
    let pcr9_ipl: Vec<_> = handler
        .get_events_for_pcr_index(9)
        .into_iter()
        .filter(|e| e.event_type == "EV_IPL")
        .collect();

    for event in &pcr9_ipl {
        let event_str = uefi_event_data::parse_ipl_string(&event.event_data);

        let sha256_digest = event
            .digests
            .get("sha256")
            .map(|d| format!("0x{}", hex::encode(d)));

        if let Some(ref s) = event_str {
            let s_lower = s.to_lowercase();
            if s_lower.contains("initrd") || s_lower.contains("initramfs") {
                if entry.initrd_plain_sha256.is_none() {
                    entry.initrd_plain_sha256 = sha256_digest;
                }
            } else if !has_secureboot
                && s_lower.contains("vmlinuz")
                && entry.vmlinuz_plain_sha256.is_none()
            {
                entry.vmlinuz_plain_sha256 = sha256_digest;
            }
        }
    }

    // Only add the entry if we extracted something meaningful
    if entry.shim_authcode_sha256.is_some()
        || entry.grub_authcode_sha256.is_some()
        || entry.kernel_authcode_sha256.is_some()
        || entry.initrd_plain_sha256.is_some()
        || entry.vmlinuz_plain_sha256.is_some()
        || entry.kernel_cmdline.is_some()
    {
        policy.kernels.push(entry);
    }
}

/// Extract MOK (Machine Owner Key) digests from EV_IPL events.
///
/// Shim measures MokList and MokListX as EV_IPL events.
/// The event_data contains the string "MokList" or "MokListX".
fn extract_mok(handler: &UefiLogHandler, policy: &mut MeasuredBootPolicy) {
    let ipl_events = handler.get_events_by_type("EV_IPL");

    for event in &ipl_events {
        let event_str = uefi_event_data::parse_ipl_string(&event.event_data);

        if let Some(ref s) = event_str {
            let sha256_digest = event
                .digests
                .get("sha256")
                .map(|d| format!("0x{}", hex::encode(d)));

            if s == "MokList" || s == "MokListRT" {
                if let Some(digest) = sha256_digest {
                    let mut entry = serde_json::Map::new();
                    let _ = entry.insert(
                        "sha256".to_string(),
                        serde_json::Value::String(digest),
                    );
                    policy.mokdig.push(serde_json::Value::Object(entry));
                }
            } else if s == "MokListX" || s == "MokListXRT" {
                if let Some(digest) = sha256_digest {
                    let mut entry = serde_json::Map::new();
                    let _ = entry.insert(
                        "sha256".to_string(),
                        serde_json::Value::String(digest),
                    );
                    policy.mokxdig.push(serde_json::Value::Object(entry));
                }
            }
        }
    }
}

/// Extract vendor_db signatures from `EV_EFI_VARIABLE_AUTHORITY` events.
///
/// These events on PCR 7 contain the variable name and signature data
/// used to verify boot components against vendor-provided databases.
fn extract_vendor_db(
    handler: &UefiLogHandler,
    policy: &mut MeasuredBootPolicy,
) {
    let authority_events =
        handler.get_events_by_type("EV_EFI_VARIABLE_AUTHORITY");

    for event in &authority_events {
        if let Some(var_data) =
            uefi_event_data::parse_efi_variable_data(&event.event_data)
        {
            if var_data.variable_name == "vendor_db" {
                let digest = event
                    .digests
                    .iter()
                    .next()
                    .map(|(_, d)| hex::encode(d))
                    .unwrap_or_default();

                policy.vendor_db.push(SecureBootSignature {
                    signature_owner: "vendor".to_string(),
                    signature_data: format!("0x{digest}"),
                });
            }
        }
    }
}

/// Summary statistics for a generated measured boot policy.
#[cfg_attr(not(feature = "wizard"), allow(dead_code))]
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
#[cfg_attr(not(feature = "wizard"), allow(dead_code))]
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
    use crate::policy_tools::uefi_event_data::{
        parse_efi_variable_data, parse_ipl_string,
    };

    /// Helper: build a UEFI_VARIABLE_DATA byte buffer for testing.
    fn build_variable_data(name: &str, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // GUID (16 bytes)
        buf.extend_from_slice(&[
            0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00,
            0xe0, 0x98, 0x03, 0x2b, 0x8c,
        ]);
        // UnicodeNameLength
        buf.extend_from_slice(&(name.len() as u64).to_le_bytes());
        // VariableDataLength
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        // UnicodeName in UTF-16LE
        for c in name.chars() {
            buf.push(c as u8);
            buf.push(0);
        }
        // VariableData
        buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn test_parse_efi_variable_name_pk() {
        let data = build_variable_data("PK", &[]);
        let parsed = parse_efi_variable_data(&data).unwrap(); //#[allow_ci]
        assert_eq!(parsed.variable_name, "PK");
    }

    #[test]
    fn test_parse_efi_variable_name_secureboot() {
        let data = build_variable_data("SecureBoot", &[0x01]);
        let parsed = parse_efi_variable_data(&data).unwrap(); //#[allow_ci]
        assert_eq!(parsed.variable_name, "SecureBoot");
        assert_eq!(parsed.variable_data, vec![0x01]);
    }

    #[test]
    fn test_parse_efi_variable_too_short() {
        let data = vec![0u8; 16];
        assert!(parse_efi_variable_data(&data).is_none());
    }

    #[test]
    fn test_parse_efi_variable_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        assert!(parse_efi_variable_data(&data).is_none());
    }

    #[test]
    fn test_parse_ipl_string_cmdline() {
        let data = b"kernel_cmdline: root=/dev/sda1 ro quiet";
        let result = parse_ipl_string(data);
        assert_eq!(
            result.as_deref(),
            Some("kernel_cmdline: root=/dev/sda1 ro quiet")
        );
    }

    #[test]
    fn test_parse_ipl_string_moklist() {
        let mut data = b"MokList".to_vec();
        data.push(0);
        let result = parse_ipl_string(&data);
        assert_eq!(result, Some("MokList".to_string()));
    }

    #[test]
    fn test_nonexistent_eventlog() {
        let result =
            generate_from_eventlog(Path::new("/nonexistent/event.log"), true);
        assert!(result.is_err());
    }
}
