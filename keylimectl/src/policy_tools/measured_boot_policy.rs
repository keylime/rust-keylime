// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Measured boot policy reference state types.
//!
//! These types represent the measured boot reference state structure
//! generated from UEFI event logs, matching the Python
//! `create_mb_policy.py` output format.

#![allow(dead_code)] // Types used in later implementation steps

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A measured boot policy reference state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeasuredBootPolicy {
    /// Whether Secure Boot was detected as enabled.
    pub has_secureboot: bool,

    /// S-CRTM and BIOS firmware measurements.
    #[serde(default)]
    pub scrtm_and_bios: Vec<ScrtmBiosEntry>,

    /// Platform Key (PK) signatures.
    #[serde(default, rename = "pk")]
    pub pk: Vec<SecureBootSignature>,

    /// Key Exchange Key (KEK) signatures.
    #[serde(default, rename = "kek")]
    pub kek: Vec<SecureBootSignature>,

    /// Authorized signature database (db).
    #[serde(default, rename = "db")]
    pub db: Vec<SecureBootSignature>,

    /// Forbidden signature database (dbx).
    #[serde(default, rename = "dbx")]
    pub dbx: Vec<SecureBootSignature>,

    /// Vendor-provided authorized signature database.
    #[serde(default)]
    pub vendor_db: Vec<SecureBootSignature>,

    /// Kernel boot chain entries (shim, grub, kernel, initrd).
    #[serde(default)]
    pub kernels: Vec<KernelEntry>,

    /// Machine Owner Key digests.
    #[serde(default)]
    pub mokdig: Vec<serde_json::Value>,

    /// Machine Owner Key exclusion digests.
    #[serde(default)]
    pub mokxdig: Vec<serde_json::Value>,
}

/// S-CRTM and platform firmware measurement entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScrtmBiosEntry {
    /// S-CRTM version measurement.
    #[serde(default)]
    pub scrtm: HashMap<String, String>,

    /// Platform firmware blob measurements.
    #[serde(default)]
    pub platform_firmware: Vec<HashMap<String, String>>,
}

/// UEFI Secure Boot signature entry (PK, KEK, db, dbx).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct SecureBootSignature {
    /// Signature owner GUID.
    pub signature_owner: String,

    /// Hex-encoded signature data.
    pub signature_data: String,
}

/// Kernel boot chain entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KernelEntry {
    /// SHIM bootloader authenticode SHA-256 digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim_authcode_sha256: Option<String>,

    /// GRUB bootloader authenticode SHA-256 digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grub_authcode_sha256: Option<String>,

    /// Kernel authenticode SHA-256 digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_authcode_sha256: Option<String>,

    /// Initrd plain SHA-256 digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd_plain_sha256: Option<String>,

    /// Kernel command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_cmdline: Option<String>,
}

impl MeasuredBootPolicy {
    /// Create a new empty measured boot policy.
    pub fn new(has_secureboot: bool) -> Self {
        Self {
            has_secureboot,
            scrtm_and_bios: Vec::new(),
            pk: Vec::new(),
            kek: Vec::new(),
            db: Vec::new(),
            dbx: Vec::new(),
            vendor_db: Vec::new(),
            kernels: Vec::new(),
            mokdig: Vec::new(),
            mokxdig: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_policy() {
        let policy = MeasuredBootPolicy::new(true);
        assert!(policy.has_secureboot);
        assert!(policy.kernels.is_empty());
        assert!(policy.pk.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut policy = MeasuredBootPolicy::new(true);
        policy.pk.push(SecureBootSignature {
            signature_owner: "owner-guid".to_string(),
            signature_data: "0xaabbccdd".to_string(),
        });
        policy.kernels.push(KernelEntry {
            shim_authcode_sha256: Some("0xabcdef".to_string()),
            grub_authcode_sha256: None,
            kernel_authcode_sha256: Some("0x123456".to_string()),
            initrd_plain_sha256: None,
            kernel_cmdline: Some("root=/dev/sda1".to_string()),
        });

        let json_str = serde_json::to_string(&policy).unwrap(); //#[allow_ci]
        let deserialized: MeasuredBootPolicy =
            serde_json::from_str(&json_str).unwrap(); //#[allow_ci]

        assert_eq!(policy, deserialized);
    }

    #[test]
    fn test_deserialize_reference_format() {
        let reference = json!({
            "has_secureboot": true,
            "scrtm_and_bios": [{
                "scrtm": {"sha256": "0xaabb"},
                "platform_firmware": [{"sha256": "0xccdd"}]
            }],
            "pk": [{"SignatureOwner": "guid1", "SignatureData": "0x1234"}],
            "kek": [],
            "db": [{"SignatureOwner": "guid2", "SignatureData": "0x5678"}],
            "dbx": [],
            "vendor_db": [],
            "kernels": [{
                "shim_authcode_sha256": "0xshim",
                "grub_authcode_sha256": "0xgrub",
                "kernel_authcode_sha256": "0xkernel",
                "initrd_plain_sha256": "0xinitrd",
                "kernel_cmdline": "root=/dev/sda1 quiet"
            }],
            "mokdig": [],
            "mokxdig": []
        });

        let policy: MeasuredBootPolicy =
            serde_json::from_value(reference).unwrap(); //#[allow_ci]

        assert!(policy.has_secureboot);
        assert_eq!(policy.pk.len(), 1);
        assert_eq!(policy.pk[0].signature_owner, "guid1");
        assert_eq!(policy.kernels.len(), 1);
        assert_eq!(
            policy.kernels[0].kernel_cmdline.as_deref(),
            Some("root=/dev/sda1 quiet")
        );
    }
}
