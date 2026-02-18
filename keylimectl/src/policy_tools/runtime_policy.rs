// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Runtime policy v1 schema types.
//!
//! These types match the Python `RuntimePolicyType` TypedDict definition
//! from `keylime.ima.types`, ensuring compatibility between the Python
//! and Rust implementations.

#![allow(dead_code)] // Types used in later implementation steps

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The current runtime policy schema version.
pub const RUNTIME_POLICY_VERSION: u32 = 5;

/// Generator identifier for keylimectl.
pub const RUNTIME_POLICY_GENERATOR: &str = "keylimectl";

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

    /// File path -> list of acceptable digests (e.g., `"sha256:abcd..."`).
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

    /// Generator identifier (numeric in Python, string in keylimectl).
    /// We use `serde_json::Value` to accept both.
    #[serde(default)]
    pub generator: serde_json::Value,

    /// ISO 8601 timestamp of when the policy was generated.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none"
    )]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
                generator: serde_json::Value::String(
                    RUNTIME_POLICY_GENERATOR.to_string(),
                ),
                timestamp: Some(
                    chrono::Utc::now().to_rfc3339(),
                ),
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
    pub fn add_digest(
        &mut self,
        path: String,
        digest: String,
    ) {
        self.digests
            .entry(path)
            .or_default()
            .push(digest);
    }

    /// Add an exclude pattern.
    pub fn add_exclude(&mut self, pattern: String) {
        if !self.excludes.contains(&pattern) {
            self.excludes.push(pattern);
        }
    }

    /// Add a keyring entry.
    pub fn add_keyring(
        &mut self,
        keyring: String,
        digest: String,
    ) {
        self.keyrings
            .entry(keyring)
            .or_default()
            .push(digest);
    }

    /// Add an ima-buf entry.
    pub fn add_ima_buf(
        &mut self,
        name: String,
        digest: String,
    ) {
        self.ima_buf
            .entry(name)
            .or_default()
            .push(digest);
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
            "sha256:abc123".to_string(),
        );
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "sha256:def456".to_string(),
        );
        policy.add_digest(
            "/usr/bin/ls".to_string(),
            "sha256:789abc".to_string(),
        );

        assert_eq!(policy.digest_count(), 2);
        assert_eq!(
            policy.digests["/usr/bin/bash"].len(),
            2
        );
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
            "sha256:key_hash".to_string(),
        );

        assert_eq!(policy.keyrings.len(), 1);
        assert_eq!(
            policy.keyrings[".builtin_trusted_keys"],
            vec!["sha256:key_hash"]
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut policy = RuntimePolicy::new();
        policy.add_digest(
            "/usr/bin/bash".to_string(),
            "sha256:abc123".to_string(),
        );
        policy.add_exclude("/tmp/*".to_string());
        policy.add_keyring(
            "_ima".to_string(),
            "sha256:keydata".to_string(),
        );
        policy.add_ima_buf(
            "dm_table".to_string(),
            "sha256:bufhash".to_string(),
        );
        policy.set_log_hash_alg("sha256".to_string());

        let json_str =
            serde_json::to_string(&policy).unwrap();
        let deserialized: RuntimePolicy =
            serde_json::from_str(&json_str).unwrap();

        assert_eq!(policy, deserialized);
    }

    #[test]
    fn test_deserialize_python_compatible_policy() {
        // Simulate a policy generated by the Python implementation
        let python_policy = json!({
            "meta": {
                "version": 5,
                "generator": 0,
                "timestamp": "2025-01-01T00:00:00Z"
            },
            "release": 1,
            "digests": {
                "/usr/bin/bash": ["sha256:abcdef1234567890"],
                "/usr/bin/ls": ["sha256:1234567890abcdef", "sha1:aabbccddee"]
            },
            "excludes": ["/tmp/*", "/proc/*"],
            "keyrings": {
                ".builtin_trusted_keys": ["sha256:keyhash"]
            },
            "ima": {
                "ignored_keyrings": ["_evm"],
                "log_hash_alg": "sha256",
                "dm_policy": null
            },
            "ima-buf": {
                "dm_table": ["sha256:bufhash"]
            },
            "verification-keys": ""
        });

        let policy: RuntimePolicy =
            serde_json::from_value(python_policy).unwrap();

        assert_eq!(policy.meta.version, 5);
        // Python generator is numeric (0 = EmptyAllowList)
        assert_eq!(policy.meta.generator, json!(0));
        assert_eq!(policy.release, 1);
        assert_eq!(policy.digest_count(), 2);
        assert_eq!(
            policy.digests["/usr/bin/ls"].len(),
            2
        );
        assert_eq!(policy.exclude_count(), 2);
        assert_eq!(
            policy.keyrings[".builtin_trusted_keys"],
            vec!["sha256:keyhash"]
        );
        assert_eq!(policy.ima.log_hash_alg, "sha256");
        assert_eq!(
            policy.ima.ignored_keyrings,
            vec!["_evm"]
        );
        assert!(policy.ima.dm_policy.is_none());
        assert_eq!(
            policy.ima_buf["dm_table"],
            vec!["sha256:bufhash"]
        );
        assert!(policy.verification_keys.is_empty());
    }

    #[test]
    fn test_deserialize_minimal_policy() {
        // Only required fields
        let minimal = json!({
            "meta": { "version": 5 },
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

        let policy: RuntimePolicy =
            serde_json::from_value(minimal).unwrap();

        assert_eq!(policy.meta.version, 5);
        assert_eq!(policy.release, 0);
        assert!(policy.digests.is_empty());
    }

    #[test]
    fn test_serialized_json_has_correct_keys() {
        let policy = RuntimePolicy::new();
        let json_val: serde_json::Value =
            serde_json::to_value(&policy).unwrap();

        // Verify hyphenated key names (Rust uses underscores internally)
        assert!(json_val.get("ima-buf").is_some());
        assert!(json_val.get("verification-keys").is_some());
        // These should NOT appear
        assert!(json_val.get("ima_buf").is_none());
        assert!(
            json_val.get("verification_keys").is_none()
        );
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
