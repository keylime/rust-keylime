// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! TPM policy types.
//!
//! A TPM policy specifies a PCR mask and expected PCR values
//! for a given hash algorithm.

#![allow(dead_code)] // Types used in later implementation steps

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A TPM policy specifying expected PCR values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TpmPolicy {
    /// PCR mask as a hex string (e.g., `"0x408000"`).
    pub mask: String,

    /// PCR index -> expected hex digest value.
    #[serde(flatten)]
    pub pcr_values: HashMap<String, String>,
}

impl TpmPolicy {
    /// Create a new empty TPM policy.
    pub fn new() -> Self {
        Self {
            mask: "0x0".to_string(),
            pcr_values: HashMap::new(),
        }
    }

    /// Create a TPM policy from PCR indices and values.
    pub fn from_pcrs(pcrs: &[(u32, String)]) -> Self {
        let mut mask: u32 = 0;
        let mut pcr_values = HashMap::new();

        for (index, value) in pcrs {
            mask |= 1 << index;
            let _ = pcr_values.insert(index.to_string(), value.clone());
        }

        Self {
            mask: format!("0x{mask:x}"),
            pcr_values,
        }
    }

    /// Calculate the PCR mask from a set of PCR indices.
    pub fn calculate_mask(indices: &[u32]) -> String {
        let mask: u32 = indices.iter().fold(0u32, |acc, &i| acc | (1 << i));
        format!("0x{mask:x}")
    }

    /// Parse a PCR mask string to get the set of selected indices.
    pub fn parse_mask(mask: &str) -> Result<Vec<u32>, String> {
        let hex_str = mask
            .strip_prefix("0x")
            .or_else(|| mask.strip_prefix("0X"))
            .unwrap_or(mask);

        let value = u32::from_str_radix(hex_str, 16)
            .map_err(|e| format!("Invalid PCR mask '{mask}': {e}"))?;

        let mut indices = Vec::new();
        for i in 0..24 {
            if value & (1 << i) != 0 {
                indices.push(i);
            }
        }
        Ok(indices)
    }
}

impl Default for TpmPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_policy() {
        let policy = TpmPolicy::new();
        assert_eq!(policy.mask, "0x0");
        assert!(policy.pcr_values.is_empty());
    }

    #[test]
    fn test_from_pcrs() {
        let pcrs = vec![
            (0, "aabb".to_string()),
            (1, "ccdd".to_string()),
            (7, "eeff".to_string()),
        ];

        let policy = TpmPolicy::from_pcrs(&pcrs);

        // Mask should be 0x83 (bits 0, 1, 7)
        assert_eq!(policy.mask, "0x83");
        assert_eq!(policy.pcr_values["0"], "aabb");
        assert_eq!(policy.pcr_values["1"], "ccdd");
        assert_eq!(policy.pcr_values["7"], "eeff");
    }

    #[test]
    fn test_calculate_mask() {
        assert_eq!(TpmPolicy::calculate_mask(&[0, 1, 2, 7]), "0x87");
        assert_eq!(TpmPolicy::calculate_mask(&[]), "0x0");
        assert_eq!(TpmPolicy::calculate_mask(&[0]), "0x1");
    }

    #[test]
    fn test_parse_mask() {
        assert_eq!(TpmPolicy::parse_mask("0x87").unwrap(), vec![0, 1, 2, 7]); //#[allow_ci]
        assert_eq!(TpmPolicy::parse_mask("0x0").unwrap(), Vec::<u32>::new()); //#[allow_ci]
        assert_eq!(TpmPolicy::parse_mask("0x1").unwrap(), vec![0]); //#[allow_ci]
                                                                    // Without prefix
        assert_eq!(
            TpmPolicy::parse_mask("ff").unwrap(), //#[allow_ci]
            vec![0, 1, 2, 3, 4, 5, 6, 7]
        );
    }

    #[test]
    fn test_parse_mask_invalid() {
        assert!(TpmPolicy::parse_mask("invalid").is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let pcrs =
            vec![(0, "aabbccdd".to_string()), (7, "eeff0011".to_string())];
        let policy = TpmPolicy::from_pcrs(&pcrs);

        let json_str = serde_json::to_string(&policy).unwrap(); //#[allow_ci]
        let deserialized: TpmPolicy =
            serde_json::from_str(&json_str).unwrap(); //#[allow_ci]

        assert_eq!(policy, deserialized);
    }

    #[test]
    fn test_mask_roundtrip() {
        let indices = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let mask = TpmPolicy::calculate_mask(&indices);
        let parsed = TpmPolicy::parse_mask(&mask).unwrap(); //#[allow_ci]
        assert_eq!(indices, parsed);
    }
}
