// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! API version constants — single source of truth for all clients
//!
//! Version lists are derived from enabled feature flags at compile time.
//! This module eliminates version constant duplication across the verifier,
//! registrar, and agent clients.

/// All supported API versions for verifier and registrar communication.
///
/// The array is conditionally compiled based on enabled features:
/// - `api-v2`: includes 2.0, 2.1, 2.2, 2.3
/// - `api-v3`: includes 3.0
/// - both (default): includes all versions
///
/// Versions are ordered oldest to newest. Version detection iterates in
/// reverse (newest first) for optimal detection.
pub const SUPPORTED_API_VERSIONS: &[&str] = &[
    #[cfg(feature = "api-v2")]
    "2.0",
    #[cfg(feature = "api-v2")]
    "2.1",
    #[cfg(feature = "api-v2")]
    "2.2",
    #[cfg(feature = "api-v2")]
    "2.3",
    #[cfg(feature = "api-v3")]
    "3.0",
];

/// Supported API versions for direct agent communication (pull model only).
///
/// Only compiled when `api-v2` is enabled, since direct agent communication
/// is exclusively a pull-model operation.
#[cfg(feature = "api-v2")]
pub const SUPPORTED_AGENT_API_VERSIONS: &[&str] = &["2.0", "2.1", "2.2"];

/// Default API version used when version detection fails.
///
/// When `api-v2` is enabled (with or without `api-v3`), defaults to "2.1"
/// for backward compatibility. When only `api-v3` is enabled, defaults
/// to "3.0".
pub const DEFAULT_API_VERSION: &str = if cfg!(feature = "api-v2") {
    "2.1"
} else {
    "3.0"
};

/// Check if a version string represents a v3.0+ API version.
#[must_use]
#[allow(dead_code)] // Used in later steps when v2/v3 branching is gated
pub fn is_v3(version: &str) -> bool {
    version.parse::<f32>().unwrap_or(2.0) >= 3.0 //#[allow_ci]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_versions_not_empty() {
        assert!(
            !SUPPORTED_API_VERSIONS.is_empty(),
            "At least one API version must be supported"
        );
    }

    #[test]
    fn test_supported_versions_ascending_order() {
        for i in 1..SUPPORTED_API_VERSIONS.len() {
            let prev: f32 = SUPPORTED_API_VERSIONS[i - 1].parse().unwrap(); //#[allow_ci]
            let curr: f32 = SUPPORTED_API_VERSIONS[i].parse().unwrap(); //#[allow_ci]
            assert!(
                prev < curr,
                "Versions must be in ascending order: {} >= {}",
                SUPPORTED_API_VERSIONS[i - 1],
                SUPPORTED_API_VERSIONS[i]
            );
        }
    }

    #[test]
    fn test_default_api_version_is_supported() {
        assert!(
            SUPPORTED_API_VERSIONS.contains(&DEFAULT_API_VERSION),
            "Default version {} must be in supported versions",
            DEFAULT_API_VERSION
        );
    }

    #[test]
    fn test_is_v3() {
        assert!(!is_v3("2.0"));
        assert!(!is_v3("2.1"));
        assert!(!is_v3("2.3"));
        assert!(is_v3("3.0"));
        assert!(is_v3("3.1"));
        assert!(!is_v3("invalid"));
    }

    #[cfg(all(feature = "api-v2", feature = "api-v3"))]
    #[test]
    fn test_both_features_all_versions() {
        assert_eq!(
            SUPPORTED_API_VERSIONS,
            &["2.0", "2.1", "2.2", "2.3", "3.0"]
        );
    }

    #[cfg(all(feature = "api-v2", not(feature = "api-v3")))]
    #[test]
    fn test_v2_only_versions() {
        assert_eq!(SUPPORTED_API_VERSIONS, &["2.0", "2.1", "2.2", "2.3"]);
    }

    #[cfg(all(feature = "api-v3", not(feature = "api-v2")))]
    #[test]
    fn test_v3_only_versions() {
        assert_eq!(SUPPORTED_API_VERSIONS, &["3.0"]);
    }

    #[cfg(feature = "api-v2")]
    #[test]
    fn test_agent_api_versions() {
        assert_eq!(SUPPORTED_AGENT_API_VERSIONS, &["2.0", "2.1", "2.2"]);
    }
}
