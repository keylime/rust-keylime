// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Filesystem scanning for policy generation.
//!
//! Walks a filesystem tree to calculate file digests, skipping
//! symlinks, non-regular files, and excluded paths.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::digest::calculate_file_digest;
use crate::policy_tools::ima_parser::DigestMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Scan a filesystem tree and calculate digests for all regular files.
///
/// # Arguments
///
/// * `root` - Root directory to scan
/// * `skip_paths` - Absolute paths to skip (directories)
/// * `algorithm` - Hash algorithm name (e.g., "sha256")
///
/// # Returns
///
/// A `DigestMap` where keys are file paths relative to `root`
/// (prefixed with `/`), and values are lists of digest strings.
pub fn scan_filesystem(
    root: &Path,
    skip_paths: &[String],
    algorithm: &str,
) -> Result<DigestMap, PolicyGenerationError> {
    let root = root.canonicalize().map_err(|e| {
        PolicyGenerationError::FilesystemScan {
            path: root.to_path_buf(),
            reason: format!("Failed to resolve path: {e}"),
        }
    })?;

    let mut digests: DigestMap = HashMap::new();
    let skip_set: Vec<PathBuf> =
        skip_paths.iter().map(PathBuf::from).collect();

    walk_directory(&root, &root, &skip_set, algorithm, &mut digests)?;

    Ok(digests)
}

/// Recursively walk a directory tree.
fn walk_directory(
    dir: &Path,
    root: &Path,
    skip_paths: &[PathBuf],
    algorithm: &str,
    digests: &mut DigestMap,
) -> Result<(), PolicyGenerationError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        PolicyGenerationError::FilesystemScan {
            path: dir.to_path_buf(),
            reason: format!("Failed to read directory: {e}"),
        }
    })?;

    for entry in entries {
        let entry =
            entry.map_err(|e| PolicyGenerationError::FilesystemScan {
                path: dir.to_path_buf(),
                reason: format!("Failed to read entry: {e}"),
            })?;

        let path = entry.path();

        // Skip symlinks
        if path.is_symlink() {
            continue;
        }

        // Check if path should be skipped
        if should_skip(&path, skip_paths) {
            log::debug!("Skipping: {}", path.display());
            continue;
        }

        if path.is_dir() {
            walk_directory(&path, root, skip_paths, algorithm, digests)?;
        } else if path.is_file() {
            // Calculate digest and store with path relative to root
            match calculate_file_digest(&path, algorithm) {
                Ok(digest) => {
                    let relative_path = make_policy_path(&path, root);
                    let entry = digests.entry(relative_path).or_default();
                    if !entry.contains(&digest) {
                        entry.push(digest);
                    }
                }
                Err(e) => {
                    // Log and skip files we can't read (permission denied, etc.)
                    log::warn!("Skipping {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(())
}

/// Check if a path should be skipped based on the skip list.
fn should_skip(path: &Path, skip_paths: &[PathBuf]) -> bool {
    skip_paths.iter().any(|skip| path.starts_with(skip))
}

/// Convert an absolute file path to a policy-relative path.
///
/// If the root is `/mnt/rootfs`, then `/mnt/rootfs/usr/bin/bash`
/// becomes `/usr/bin/bash`.
fn make_policy_path(path: &Path, root: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(relative) => format!("/{}", relative.display()),
        Err(_) => path.display().to_string(),
    }
}

/// Read `/proc/mounts` to detect non-root mount points that should
/// typically be excluded from filesystem scanning.
#[allow(dead_code)] // Available for future auto-exclude features
pub fn detect_non_root_mounts() -> Result<Vec<String>, PolicyGenerationError>
{
    let content = std::fs::read_to_string("/proc/mounts").map_err(|e| {
        PolicyGenerationError::FilesystemScan {
            path: PathBuf::from("/proc/mounts"),
            reason: format!("Failed to read /proc/mounts: {e}"),
        }
    })?;

    let mut mounts = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let mount_point = parts[1];
            // Skip root and common virtual filesystems
            if mount_point != "/"
                && !mount_point.starts_with("/proc")
                && !mount_point.starts_with("/sys")
                && !mount_point.starts_with("/dev")
                && !mount_point.starts_with("/run")
            {
                mounts.push(mount_point.to_string());
            }
        }
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_scan_filesystem_basic() {
        let dir = TempDir::new().unwrap(); //#[allow_ci]
        let root = dir.path();

        // Create test files
        fs::write(root.join("file1.txt"), "hello").unwrap(); //#[allow_ci]
        fs::write(root.join("file2.txt"), "world").unwrap(); //#[allow_ci]

        let result = scan_filesystem(root, &[], "sha256").unwrap(); //#[allow_ci]

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("/file1.txt"));
        assert!(result.contains_key("/file2.txt"));
        // Each file should have exactly one bare hex digest (sha256 = 64 chars)
        assert_eq!(result["/file1.txt"].len(), 1);
        assert_eq!(result["/file1.txt"][0].len(), 64);
        assert!(result["/file1.txt"][0]
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_scan_filesystem_with_subdirs() {
        let dir = TempDir::new().unwrap(); //#[allow_ci]
        let root = dir.path();

        fs::create_dir_all(root.join("usr/bin")).unwrap(); //#[allow_ci]
        fs::write(root.join("usr/bin/bash"), "bash content").unwrap(); //#[allow_ci]
        fs::write(root.join("usr/bin/ls"), "ls content").unwrap(); //#[allow_ci]

        let result = scan_filesystem(root, &[], "sha256").unwrap(); //#[allow_ci]

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("/usr/bin/bash"));
        assert!(result.contains_key("/usr/bin/ls"));
    }

    #[test]
    fn test_scan_filesystem_skip_paths() {
        let dir = TempDir::new().unwrap(); //#[allow_ci]
        let root = dir.path();

        fs::create_dir_all(root.join("include")).unwrap(); //#[allow_ci]
        fs::create_dir_all(root.join("exclude")).unwrap(); //#[allow_ci]
        fs::write(root.join("include/file.txt"), "include").unwrap(); //#[allow_ci]
        fs::write(root.join("exclude/file.txt"), "exclude").unwrap(); //#[allow_ci]

        let skip = vec![root.join("exclude").to_string_lossy().to_string()];
        let result = scan_filesystem(root, &skip, "sha256").unwrap(); //#[allow_ci]

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("/include/file.txt"));
        assert!(!result.contains_key("/exclude/file.txt"));
    }

    #[test]
    fn test_scan_filesystem_empty_dir() {
        let dir = TempDir::new().unwrap(); //#[allow_ci]

        let result = scan_filesystem(dir.path(), &[], "sha256").unwrap(); //#[allow_ci]

        assert!(result.is_empty());
    }

    #[test]
    fn test_make_policy_path() {
        assert_eq!(
            make_policy_path(
                Path::new("/mnt/rootfs/usr/bin/bash"),
                Path::new("/mnt/rootfs")
            ),
            "/usr/bin/bash"
        );
        assert_eq!(
            make_policy_path(Path::new("/usr/bin/bash"), Path::new("/")),
            "/usr/bin/bash"
        );
    }

    #[test]
    fn test_should_skip() {
        let skip = vec![PathBuf::from("/tmp"), PathBuf::from("/proc")];

        assert!(should_skip(Path::new("/tmp/foo"), &skip));
        assert!(should_skip(Path::new("/proc/1"), &skip));
        assert!(!should_skip(Path::new("/usr/bin/bash"), &skip));
    }
}
