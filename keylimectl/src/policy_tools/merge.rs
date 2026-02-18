// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy merging utilities.
//!
//! Merges two runtime policies by taking the union of their digests,
//! excludes, keyrings, and ima-buf entries.

#![allow(dead_code)] // Used in later implementation steps

use crate::policy_tools::runtime_policy::RuntimePolicy;

/// Merge two runtime policies.
///
/// The resulting policy contains the union of all digests, excludes,
/// keyrings, and ima-buf entries from both policies. The metadata
/// from the `base` policy is preserved.
pub fn merge_policies(
    base: &RuntimePolicy,
    other: &RuntimePolicy,
) -> RuntimePolicy {
    let mut merged = base.clone();

    // Merge digests
    for (path, other_digests) in &other.digests {
        for digest in other_digests {
            merged.add_digest(path.clone(), digest.clone());
        }
    }

    // Merge excludes
    for pattern in &other.excludes {
        merged.add_exclude(pattern.clone());
    }

    // Merge keyrings
    for (keyring, other_digests) in &other.keyrings {
        for digest in other_digests {
            merged.add_keyring(keyring.clone(), digest.clone());
        }
    }

    // Merge ima-buf
    for (name, other_digests) in &other.ima_buf {
        for digest in other_digests {
            merged.add_ima_buf(name.clone(), digest.clone());
        }
    }

    // Merge ignored keyrings
    for keyring in &other.ima.ignored_keyrings {
        merged.add_ignored_keyring(keyring.clone());
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_empty_policies() {
        let base = RuntimePolicy::new();
        let other = RuntimePolicy::new();
        let merged = merge_policies(&base, &other);

        assert!(merged.digests.is_empty());
        assert!(merged.excludes.is_empty());
        assert!(merged.keyrings.is_empty());
        assert!(merged.ima_buf.is_empty());
    }

    #[test]
    fn test_merge_non_overlapping() {
        let mut base = RuntimePolicy::new();
        base.add_digest(
            "/usr/bin/bash".to_string(),
            "sha256:aaa".to_string(),
        );

        let mut other = RuntimePolicy::new();
        other.add_digest("/usr/bin/ls".to_string(), "sha256:bbb".to_string());

        let merged = merge_policies(&base, &other);

        assert_eq!(merged.digest_count(), 2);
        assert_eq!(merged.digests["/usr/bin/bash"], vec!["sha256:aaa"]);
        assert_eq!(merged.digests["/usr/bin/ls"], vec!["sha256:bbb"]);
    }

    #[test]
    fn test_merge_overlapping_digests() {
        let mut base = RuntimePolicy::new();
        base.add_digest(
            "/usr/bin/bash".to_string(),
            "sha256:aaa".to_string(),
        );

        let mut other = RuntimePolicy::new();
        other.add_digest(
            "/usr/bin/bash".to_string(),
            "sha256:aaa".to_string(), // duplicate
        );
        other.add_digest(
            "/usr/bin/bash".to_string(),
            "sha256:bbb".to_string(), // new
        );

        let merged = merge_policies(&base, &other);

        assert_eq!(merged.digest_count(), 1);
        // Should have both digests, no duplicates
        assert_eq!(merged.digests["/usr/bin/bash"].len(), 2);
    }

    #[test]
    fn test_merge_excludes() {
        let mut base = RuntimePolicy::new();
        base.add_exclude("/tmp/*".to_string());

        let mut other = RuntimePolicy::new();
        other.add_exclude("/tmp/*".to_string()); // duplicate
        other.add_exclude("/proc/*".to_string());

        let merged = merge_policies(&base, &other);

        assert_eq!(merged.exclude_count(), 2);
    }

    #[test]
    fn test_merge_keyrings_and_ima_buf() {
        let mut base = RuntimePolicy::new();
        base.add_keyring("_ima".to_string(), "sha256:key1".to_string());

        let mut other = RuntimePolicy::new();
        other.add_keyring("_ima".to_string(), "sha256:key2".to_string());
        other.add_ima_buf("dm_table".to_string(), "sha256:buf1".to_string());

        let merged = merge_policies(&base, &other);

        assert_eq!(merged.keyrings.len(), 1);
        assert_eq!(merged.keyrings["_ima"].len(), 2);
        assert_eq!(merged.ima_buf.len(), 1);
    }

    #[test]
    fn test_merge_preserves_base_metadata() {
        let base = RuntimePolicy::new();
        let other = RuntimePolicy::new();
        let merged = merge_policies(&base, &other);

        // Metadata should come from base
        assert_eq!(merged.meta.version, base.meta.version);
    }
}
