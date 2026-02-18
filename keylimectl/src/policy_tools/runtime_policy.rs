// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Runtime policy v1 schema types.
//!
//! These types match the Python `RuntimePolicyType` TypedDict definition
//! from `keylime.ima.types`, ensuring compatibility between the Python
//! and Rust implementations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The current runtime policy schema version.
/// Must match `RUNTIME_POLICY_CURRENT_VERSION` in the Python verifier.
pub const RUNTIME_POLICY_VERSION: u32 = 1;

/// Generator identifier (integer matching the Python
/// `RUNTIME_POLICY_GENERATOR` enum: Unknown=0, EmptyAllowList=1,
/// CompatibleAllowList=2, LegacyAllowList=3).
pub const RUNTIME_POLICY_GENERATOR: u32 = 0;

/// A v1 runtime policy.
///
/// All fields marked `Required` in the Python `RuntimePolicyType` are
/// non-optional here. Fields marked `NotRequired` use `Option` or have
/// serde defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimePolicy {
    /// Policy metadata (version, generator, timestamp).
    pub meta: PolicyMeta,

    /// Policy release number (incremented on updates).
    #[serde(default)]
    pub release: u32,

    /// File path -> list of acceptable digests (bare hex, e.g., `"abcd1234..."`).
    pub digests: HashMap<String, Vec<String>>,

    /// Glob patterns for paths to exclude from verification.
    #[serde(default)]
    pub excludes: Vec<String>,

    /// Keyring name -> list of acceptable digests.
    #[serde(default)]
    pub keyrings: HashMap<String, Vec<String>>,

    /// IMA-specific configuration.
    #[serde(default)]
    pub ima: ImaPolicyConfig,

    /// IMA-buf entry name -> list of acceptable digests.
    #[serde(default, rename = "ima-buf")]
    pub ima_buf: HashMap<String, Vec<String>>,

    /// JSON-encoded IMA signature verification keys.
    #[serde(default, rename = "verification-keys")]
    pub verification_keys: String,
}

/// Policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyMeta {
    /// Schema version number.
    pub version: u32,

    /// Generator identifier (integer matching the Python
    /// `RUNTIME_POLICY_GENERATOR` enum).
    pub generator: u32,

    /// ISO 8601 timestamp of when the policy was generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// IMA-specific policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImaPolicyConfig {
    /// Keyring names to ignore during verification.
    #[serde(default)]
    pub ignored_keyrings: Vec<String>,

    /// Hash algorithm used in the IMA measurement log.
    #[serde(default = "default_log_hash_alg")]
    pub log_hash_alg: String,

    /// Device-mapper policy configuration (dm-verity, dm-crypt).
    /// Always serialized (as null when None) because the verifier schema
    /// requires the field to be present.
    #[serde(default)]
    pub dm_policy: Option<serde_json::Value>,
}

impl Default for ImaPolicyConfig {
    fn default() -> Self {
        Self {
            ignored_keyrings: Vec::new(),
            log_hash_alg: default_log_hash_alg(),
            dm_policy: None,
        }
    }
}

fn default_log_hash_alg() -> String {
    "sha1".to_string()
}

impl RuntimePolicy {
    /// Create a new empty runtime policy with default metadata.
    pub fn new() -> Self {
        Self {
            meta: PolicyMeta {
                version: RUNTIME_POLICY_VERSION,
                generator: RUNTIME_POLICY_GENERATOR,
                timestamp: Some(chrono::Utc::now().to_rfc3339()),
            },
            release: 0,
            digests: HashMap::new(),
            excludes: Vec::new(),
            keyrings: HashMap::new(),
            ima: ImaPolicyConfig::default(),
            ima_buf: HashMap::new(),
            verification_keys: String::new(),
        }
    }

    /// Add a digest entry for a file path.
    pub fn add_digest(&mut self, path: String, digest: String) {
        self.digests.entry(path).or_default().push(digest);
    }

    /// Add an exclude pattern.
    pub fn add_exclude(&mut self, pattern: String) {
        if !self.excludes.contains(&pattern) {
            self.excludes.push(pattern);
        }
    }

    /// Add a keyring entry.
    pub fn add_keyring(&mut self, keyring: String, digest: String) {
        self.keyrings.entry(keyring).or_default().push(digest);
    }

    /// Add an ima-buf entry.
    pub fn add_ima_buf(&mut self, name: String, digest: String) {
        self.ima_buf.entry(name).or_default().push(digest);
    }

    /// Set the hash algorithm used in the IMA log.
    pub fn set_log_hash_alg(&mut self, alg: String) {
        self.ima.log_hash_alg = alg;
    }

    /// Add a keyring name to the ignored keyrings list.
    pub fn add_ignored_keyring(&mut self, keyring: String) {
        if !self.ima.ignored_keyrings.contains(&keyring) {
            self.ima.ignored_keyrings.push(keyring);
        }
    }

    /// Return the total number of unique file paths with digests.
    pub fn digest_count(&self) -> usize {
        self.digests.len()
    }

    /// Return the total number of exclude patterns.
    pub fn exclude_count(&self) -> usize {
        self.excludes.len()
    }
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_policy_has_correct_defaults() {
        let policy = RuntimePolicy::new();
        assert_eq!(policy.meta.version, RUNTIME_POLICY_VERSION);
        assert_eq!(policy.release, 0);
        assert!(policy.digests.is_empty());
        assert!(policy.excludes.is_empty());
        assert!(policy.keyrings.is_empty());
        assert!(policy.ima_buf.is_empty());
        assert_eq!(policy.ima.log_hash_alg, "sha1");
        assert!(policy.ima.ignored_keyrings.is_empty());
        assert!(policy.ima.dm_policy.is_none());
        assert!(policy.verification_keys.is_empty());
        assert!(policy.meta.timestamp.is_some());
    }

    #[test]
    fn test_add_digest() {
        let mut policy = RuntimePolicy::new();
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "abc123def456abc123def456abc123def456abc123".to_string(),
        );
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "def456abc123def456abc123def456abc123def456".to_string(),
        );
        policy.add_digest(
            "/usr/bin/ls".to_string(),
            "789abcdef012789abcdef012789abcdef012789abc".to_string(),
        );

        assert_eq!(policy.digest_count(), 2);
        assert_eq!(policy.digests["/usr/bin/bash"].len(), 2);
        assert_eq!(policy.digests["/usr/bin/ls"].len(), 1);
    }

    #[test]
    fn test_add_exclude_no_duplicates() {
        let mut policy = RuntimePolicy::new();
        policy.add_exclude("/tmp/*".to_string());
        policy.add_exclude("/proc/*".to_string());
        policy.add_exclude("/tmp/*".to_string());

        assert_eq!(policy.exclude_count(), 2);
    }

    #[test]
    fn test_add_keyring() {
        let mut policy = RuntimePolicy::new();
        policy.add_keyring(
            ".builtin_trusted_keys".to_string(),
            "aabbccddeeff00112233aabbccddeeff00112233".to_string(),
        );

        assert_eq!(policy.keyrings.len(), 1);
        assert_eq!(
            policy.keyrings[".builtin_trusted_keys"],
            vec!["aabbccddeeff00112233aabbccddeeff00112233"]
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut policy = RuntimePolicy::new();
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "abc123def456abc123def456abc123def456abc123".to_string(),
        );
        policy.add_exclude("/tmp/*".to_string());
        policy.add_keyring(
            "_ima".to_string(),
            "aabbccddeeff00112233aabbccddeeff00112233".to_string(),
        );
        policy.add_ima_buf(
            "dm_table".to_string(),
            "1122334455667788990011223344556677889900".to_string(),
        );
        policy.set_log_hash_alg("sha256".to_string());

        let json_str = serde_json::to_string(&policy).unwrap(); //#[allow_ci]
        let deserialized: RuntimePolicy =
            serde_json::from_str(&json_str).unwrap(); //#[allow_ci]

        assert_eq!(policy, deserialized);
    }

    #[test]
    fn test_deserialize_python_compatible_policy() {
        // Simulate a policy generated by the Python implementation
        let python_policy = json!({
            "meta": {
                "version": 1,
                "generator": 3,
                "timestamp": "2025-01-01T00:00:00Z"
            },
            "release": 1,
            "digests": {
                "/usr/bin/bash": ["abcdef1234567890abcdef1234567890abcdef1234"],
                "/usr/bin/ls": ["1234567890abcdef1234567890abcdef12345678901234567890abcdef12345678", "aabbccddee112233445566778899001122334455"]
            },
            "excludes": ["/tmp/*", "/proc/*"],
            "keyrings": {
                ".builtin_trusted_keys": ["a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a"]
            },
            "ima": {
                "ignored_keyrings": ["_evm"],
                "log_hash_alg": "sha256",
                "dm_policy": null
            },
            "ima-buf": {
                "dm_table": ["abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"]
            },
            "verification-keys": ""
        });

        let policy: RuntimePolicy =
            serde_json::from_value(python_policy).unwrap(); //#[allow_ci]

        assert_eq!(policy.meta.version, 1);
        // Python generator is numeric (3 = LegacyAllowList)
        assert_eq!(policy.meta.generator, 3);
        assert_eq!(policy.release, 1);
        assert_eq!(policy.digest_count(), 2);
        assert_eq!(policy.digests["/usr/bin/ls"].len(), 2);
        assert_eq!(policy.exclude_count(), 2);
        assert_eq!(policy.ima.log_hash_alg, "sha256");
        assert_eq!(policy.ima.ignored_keyrings, vec!["_evm"]);
        assert!(policy.ima.dm_policy.is_none());
        assert!(policy.verification_keys.is_empty());
    }

    #[test]
    fn test_deserialize_minimal_policy() {
        // Only required fields
        let minimal = json!({
            "meta": { "version": 1, "generator": 0 },
            "digests": {},
            "excludes": [],
            "keyrings": {},
            "ima": {
                "ignored_keyrings": [],
                "log_hash_alg": "sha1"
            },
            "ima-buf": {},
            "verification-keys": ""
        });

        let policy: RuntimePolicy = serde_json::from_value(minimal).unwrap(); //#[allow_ci]

        assert_eq!(policy.meta.version, 1);
        assert_eq!(policy.release, 0);
        assert!(policy.digests.is_empty());
    }

    #[test]
    fn test_serialized_json_has_correct_keys() {
        let policy = RuntimePolicy::new();
        let json_val: serde_json::Value =
            serde_json::to_value(&policy).unwrap(); //#[allow_ci]

        // Verify hyphenated key names (Rust uses underscores internally)
        assert!(json_val.get("ima-buf").is_some());
        assert!(json_val.get("verification-keys").is_some());
        // These should NOT appear
        assert!(json_val.get("ima_buf").is_none());
        assert!(json_val.get("verification_keys").is_none());

        // dm_policy must always be present (verifier schema requires it)
        let ima = json_val.get("ima").unwrap(); //#[allow_ci]
        assert!(
            ima.get("dm_policy").is_some(),
            "dm_policy must be serialized even when None"
        );
        assert!(ima.get("dm_policy").unwrap().is_null()); //#[allow_ci]
    }

    #[test]
    fn test_set_log_hash_alg() {
        let mut policy = RuntimePolicy::new();
        assert_eq!(policy.ima.log_hash_alg, "sha1");
        policy.set_log_hash_alg("sha256".to_string());
        assert_eq!(policy.ima.log_hash_alg, "sha256");
    }

    #[test]
    fn test_add_ignored_keyring_no_duplicates() {
        let mut policy = RuntimePolicy::new();
        policy.add_ignored_keyring("_evm".to_string());
        policy.add_ignored_keyring("_ima".to_string());
        policy.add_ignored_keyring("_evm".to_string());

        assert_eq!(policy.ima.ignored_keyrings.len(), 2);
    }
}
