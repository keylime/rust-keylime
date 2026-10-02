// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Persistent cache for detected API versions
//!
//! Stores detected API versions on disk so subsequent keylimectl invocations
//! can skip the HTTP version-detection probes. This eliminates race conditions
//! caused by version-detection requests interleaving with actual command
//! requests when the server runs multiple worker processes.
//!
//! All cache operations are best-effort: failures are logged and silently
//! ignored, falling back to live version detection.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use log::{debug, warn};
use serde::{Deserialize, Serialize};

use crate::api_versions::SUPPORTED_API_VERSIONS;

/// Default time-to-live for cache entries (24 hours).
pub const DEFAULT_TTL_SECS: u64 = 86400;

/// Current cache file schema version.
const CACHE_SCHEMA_VERSION: u32 = 1;

/// On-disk cache file structure.
#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    entries: HashMap<String, CacheEntry>,
}

/// A single cached API version entry.
#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    api_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supported_versions: Option<Vec<String>>,
    detected_at: DateTime<Utc>,
}

/// Result of a successful cache lookup.
#[derive(Debug)]
pub struct CachedVersion {
    pub api_version: String,
    pub supported_versions: Option<Vec<String>>,
    pub detected_at: DateTime<Utc>,
}

/// Resolve the cache file path.
///
/// Uses `$XDG_CACHE_HOME/keylimectl/api_versions.json`, falling back to
/// `$HOME/.cache/keylimectl/api_versions.json`.
fn cache_file_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        let path = PathBuf::from(xdg);
        if path.is_absolute() {
            return Some(path.join("keylimectl").join("api_versions.json"));
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        return Some(
            PathBuf::from(home)
                .join(".cache")
                .join("keylimectl")
                .join("api_versions.json"),
        );
    }

    debug!("Version cache disabled: neither XDG_CACHE_HOME nor HOME is set");
    None
}

/// Load the cache file from disk, returning an empty cache on any error.
fn load_cache() -> CacheFile {
    let path = match cache_file_path() {
        Some(p) => p,
        None => return CacheFile::empty(),
    };

    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                debug!(
                    "Failed to read version cache {}: {e}",
                    path.display()
                );
            }
            return CacheFile::empty();
        }
    };

    match serde_json::from_str::<CacheFile>(&contents) {
        Ok(cache) if cache.version == CACHE_SCHEMA_VERSION => cache,
        Ok(cache) => {
            debug!(
                "Version cache schema version {} != expected {}, ignoring",
                cache.version, CACHE_SCHEMA_VERSION
            );
            CacheFile::empty()
        }
        Err(e) => {
            debug!("Failed to parse version cache: {e}");
            CacheFile::empty()
        }
    }
}

/// Save the cache file to disk atomically (write tmp + rename).
fn save_cache(cache: &CacheFile) {
    let path = match cache_file_path() {
        Some(p) => p,
        None => return,
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            warn!(
                "Failed to create cache directory {}: {e}",
                parent.display()
            );
            return;
        }
    }

    let tmp_path = path.with_extension(format!("tmp.{}", std::process::id()));

    let json = match serde_json::to_string_pretty(cache) {
        Ok(j) => j,
        Err(e) => {
            warn!("Failed to serialize version cache: {e}");
            return;
        }
    };

    if let Err(e) = fs::write(&tmp_path, &json) {
        warn!("Failed to write version cache: {e}");
        let _ = fs::remove_file(&tmp_path);
        return;
    }

    if let Err(e) = fs::rename(&tmp_path, &path) {
        warn!("Failed to rename version cache: {e}");
        let _ = fs::remove_file(&tmp_path);
    }
}

/// Look up a cached API version for the given server URL.
///
/// Returns `None` on cache miss, expired entry, or if the cached version
/// is not in the current binary's `SUPPORTED_API_VERSIONS` (e.g., after
/// recompiling with different feature flags).
pub fn lookup(base_url: &str, ttl_secs: u64) -> Option<CachedVersion> {
    let cache = load_cache();
    let entry = cache.entries.get(base_url)?;

    let age = Utc::now()
        .signed_duration_since(entry.detected_at)
        .num_seconds();

    if age < 0 || age as u64 > ttl_secs {
        debug!(
            "Version cache expired for {base_url} (age {age}s, TTL {ttl_secs}s)"
        );
        return None;
    }

    if !SUPPORTED_API_VERSIONS.contains(&entry.api_version.as_str()) {
        debug!(
            "Cached version {} for {base_url} not in compiled SUPPORTED_API_VERSIONS, ignoring",
            entry.api_version
        );
        return None;
    }

    Some(CachedVersion {
        api_version: entry.api_version.clone(),
        supported_versions: entry.supported_versions.clone(),
        detected_at: entry.detected_at,
    })
}

/// Store a detected API version in the cache.
pub fn store(
    base_url: &str,
    api_version: &str,
    supported_versions: Option<Vec<String>>,
) {
    let mut cache = load_cache();
    let _ = cache.entries.insert(
        base_url.to_string(),
        CacheEntry {
            api_version: api_version.to_string(),
            supported_versions,
            detected_at: Utc::now(),
        },
    );
    save_cache(&cache);
}

/// Remove a cached entry for the given server URL.
///
/// Called when a request fails with a version-mismatch error so the next
/// invocation will re-detect.
#[allow(dead_code)]
pub fn invalidate(base_url: &str) {
    let mut cache = load_cache();
    if cache.entries.remove(base_url).is_some() {
        debug!("Invalidated version cache entry for {base_url}");
        save_cache(&cache);
    }
}

impl CacheFile {
    fn empty() -> Self {
        Self {
            version: CACHE_SCHEMA_VERSION,
            entries: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Run a test with XDG_CACHE_HOME pointing to a temporary directory.
    /// Holds ENV_LOCK for the duration to prevent concurrent env-var mutation.
    fn with_temp_cache<F: FnOnce(&TempDir)>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap(); //#[allow_ci]
        let dir = TempDir::new().unwrap(); //#[allow_ci]
        std::env::set_var("XDG_CACHE_HOME", dir.path());
        f(&dir);
        std::env::remove_var("XDG_CACHE_HOME");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut cache = CacheFile::empty();
        let _ = cache.entries.insert(
            "https://127.0.0.1:8881".to_string(),
            CacheEntry {
                api_version: SUPPORTED_API_VERSIONS
                    .last()
                    .unwrap() //#[allow_ci]
                    .to_string(),
                supported_versions: Some(
                    SUPPORTED_API_VERSIONS
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
                detected_at: Utc::now(),
            },
        );

        let json = serde_json::to_string(&cache).unwrap(); //#[allow_ci]
        let parsed: CacheFile = serde_json::from_str(&json).unwrap(); //#[allow_ci]

        assert_eq!(parsed.version, CACHE_SCHEMA_VERSION);
        assert!(parsed.entries.contains_key("https://127.0.0.1:8881"));
    }

    #[test]
    fn test_lookup_cache_miss() {
        with_temp_cache(|_| {
            assert!(
                lookup("https://unknown:9999", DEFAULT_TTL_SECS).is_none()
            );
        });
    }

    #[test]
    fn test_store_and_lookup() {
        with_temp_cache(|_| {
            let version = SUPPORTED_API_VERSIONS.last().unwrap().to_string(); //#[allow_ci]
            store(
                "https://127.0.0.1:8881",
                &version,
                Some(vec![version.clone()]),
            );

            let cached = lookup("https://127.0.0.1:8881", DEFAULT_TTL_SECS)
                .expect("should find cached entry"); //#[allow_ci]
            assert_eq!(cached.api_version, version);
            assert_eq!(cached.supported_versions, Some(vec![version]));
        });
    }

    #[test]
    fn test_lookup_expired_entry() {
        with_temp_cache(|_| {
            let mut cache = CacheFile::empty();
            let version = SUPPORTED_API_VERSIONS.last().unwrap().to_string(); //#[allow_ci]
            let _ = cache.entries.insert(
                "https://old:8881".to_string(),
                CacheEntry {
                    api_version: version,
                    supported_versions: None,
                    detected_at: Utc::now() - chrono::Duration::hours(25),
                },
            );
            save_cache(&cache);

            assert!(lookup("https://old:8881", DEFAULT_TTL_SECS).is_none());
        });
    }

    #[test]
    fn test_lookup_unsupported_version() {
        with_temp_cache(|_| {
            let mut cache = CacheFile::empty();
            let _ = cache.entries.insert(
                "https://future:8881".to_string(),
                CacheEntry {
                    api_version: "99.0".to_string(),
                    supported_versions: None,
                    detected_at: Utc::now(),
                },
            );
            save_cache(&cache);

            assert!(lookup("https://future:8881", DEFAULT_TTL_SECS).is_none());
        });
    }

    #[test]
    fn test_schema_version_mismatch() {
        with_temp_cache(|dir| {
            let cache_dir = dir.path().join("keylimectl");
            fs::create_dir_all(&cache_dir).unwrap(); //#[allow_ci]
            let path = cache_dir.join("api_versions.json");
            let mut f = fs::File::create(&path).unwrap(); //#[allow_ci]
            writeln!(f, r#"{{"version": 99, "entries": {{}}}}"#).unwrap(); //#[allow_ci]

            let cache = load_cache();
            assert!(cache.entries.is_empty());
        });
    }

    #[test]
    fn test_corrupt_json() {
        with_temp_cache(|dir| {
            let cache_dir = dir.path().join("keylimectl");
            fs::create_dir_all(&cache_dir).unwrap(); //#[allow_ci]
            let path = cache_dir.join("api_versions.json");
            fs::write(&path, "not json at all").unwrap(); //#[allow_ci]

            let cache = load_cache();
            assert!(cache.entries.is_empty());
        });
    }

    #[test]
    fn test_invalidate() {
        with_temp_cache(|_| {
            let version = SUPPORTED_API_VERSIONS.last().unwrap().to_string(); //#[allow_ci]
            store("https://127.0.0.1:8881", &version, None);
            assert!(
                lookup("https://127.0.0.1:8881", DEFAULT_TTL_SECS).is_some()
            );

            invalidate("https://127.0.0.1:8881");
            assert!(
                lookup("https://127.0.0.1:8881", DEFAULT_TTL_SECS).is_none()
            );
        });
    }

    #[test]
    fn test_invalidate_nonexistent() {
        with_temp_cache(|_| {
            invalidate("https://nonexistent:9999");
        });
    }

    #[test]
    fn test_multiple_entries() {
        with_temp_cache(|_| {
            let version = SUPPORTED_API_VERSIONS.last().unwrap().to_string(); //#[allow_ci]
            store("https://server1:8881", &version, None);
            store("https://server2:8882", &version, None);

            assert!(
                lookup("https://server1:8881", DEFAULT_TTL_SECS).is_some()
            );
            assert!(
                lookup("https://server2:8882", DEFAULT_TTL_SECS).is_some()
            );

            invalidate("https://server1:8881");
            assert!(
                lookup("https://server1:8881", DEFAULT_TTL_SECS).is_none()
            );
            assert!(
                lookup("https://server2:8882", DEFAULT_TTL_SECS).is_some()
            );
        });
    }
}
