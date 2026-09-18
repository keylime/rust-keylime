// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy tools library for local policy operations.
//!
//! This module provides the core logic for policy generation, signing,
//! validation, and conversion. It is used by the CLI command handlers
//! in `commands::policy` and `commands::verify` but contains no CLI
//! concerns itself.

use std::collections::HashMap;

/// Map from file path (or entry name) to list of digest strings.
pub type DigestMap = HashMap<String, Vec<String>>;

/// Merge `src` into `dst`, appending new digests without duplicates.
#[cfg_attr(not(feature = "rpm-repo"), allow(dead_code))]
pub fn merge_digest_maps(dst: &mut DigestMap, src: &DigestMap) {
    for (path, digests) in src {
        let entry = dst.entry(path.clone()).or_default();
        for digest in digests {
            if !entry.contains(digest) {
                entry.push(digest.clone());
            }
        }
    }
}

pub mod conversion;
pub mod digest;
pub mod dsse;
pub mod filesystem;
#[cfg(feature = "rpm-repo")]
pub mod gpg_verify;
pub mod ima_parser;
pub mod initrd;
pub mod measured_boot_gen;
pub mod measured_boot_policy;
pub mod merge;
pub mod privilege;
#[cfg(feature = "rpm-repo")]
pub mod rpm_repo;
pub mod runtime_policy;
pub mod tpm_policy;
pub mod tpm_policy_gen;
pub mod uefi_event_data;
pub mod validation;
