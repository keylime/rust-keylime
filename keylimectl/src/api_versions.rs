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

/// Parse a `"major.minor"` version string into a `(major, minor)` tuple.
///
/// Returns `(2, 1)` as the fallback when the string is malformed, matching
/// `DEFAULT_API_VERSION`. Using integer tuples avoids floating-point
/// representation issues (e.g. `"2.10"` must compare greater than `"2.9"`).
#[must_use]
pub fn parse_version(s: &str) -> (u32, u32) {
    let mut parts = s.splitn(2, '.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(2);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(1);
    (major, minor)
}

/// Check if a version string represents a v3.0+ API version.
///
/// When the `api-v3` feature is disabled, this always returns `false`
/// so call sites can use a simple `if is_v3()` without `#[cfg]` blocks.
/// The compiler optimises the dead branch away.
#[must_use]
pub fn is_v3(version: &str) -> bool {
    if cfg!(feature = "api-v3") {
        parse_version(version).0 >= 3
    } else {
        let _ = version; // suppress unused warning
        false
    }
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
            let prev = parse_version(SUPPORTED_API_VERSIONS[i - 1]);
            let curr = parse_version(SUPPORTED_API_VERSIONS[i]);
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
        // When api-v3 is enabled, 3.x returns true; otherwise always false
        assert_eq!(is_v3("3.0"), cfg!(feature = "api-v3"));
        assert_eq!(is_v3("3.1"), cfg!(feature = "api-v3"));
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
