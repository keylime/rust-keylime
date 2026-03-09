// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Filesystem scanning for policy generation.
//!
//! Walks a filesystem tree to calculate file digests, skipping
//! symlinks, non-regular files, and excluded paths.  Digest
//! calculation is parallelised with Rayon.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::digest::calculate_file_digest;
use crate::policy_tools::ima_parser::DigestMap;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Directories excluded by default during root filesystem scans.
///
/// These directories contain volatile, virtual, or temporary data
/// that is not expected to be stable across boots and therefore has
/// no meaningful integrity to verify.
///
/// Matches the `BASE_EXCLUDE_DIRS` used by Python `keylime-policy`.
pub const BASE_EXCLUDE_DIRS: &[&str] = &[
    "/sys",
    "/run",
    "/proc",
    "/lost+found",
    "/dev",
    "/media",
    "/snap",
    "/mnt",
    "/var",
    "/tmp",
];

/// Build the effective list of skip paths by merging user-provided
/// paths with the default excluded directories.
///
/// Each default directory is resolved relative to `rootfs` so that
/// scanning `/mnt/image` correctly skips `/mnt/image/sys`, etc.
///
/// Returns `(effective_paths, redundant_user_paths)` where
/// `redundant_user_paths` lists any user-supplied paths that are
/// already covered by the defaults.
pub fn build_effective_skip_paths(
    rootfs: &Path,
    user_paths: &[String],
) -> (Vec<String>, Vec<String>) {
    // Build default paths relative to rootfs
    let default_paths: Vec<PathBuf> = BASE_EXCLUDE_DIRS
        .iter()
        .map(|d| {
            // Strip leading '/' so join works correctly:
            //   rootfs=/mnt/img, d=/sys  → /mnt/img/sys
            //   rootfs=/,       d=/sys  → /sys
            let relative = d.strip_prefix('/').unwrap_or(d);
            rootfs.join(relative)
        })
        .collect();

    // Detect user paths that are already covered by a default
    let mut redundant = Vec::new();
    for user in user_paths {
        let user_pb = PathBuf::from(user);
        let is_covered = default_paths
            .iter()
            .any(|dp| user_pb == *dp || user_pb.starts_with(dp));
        if is_covered {
            redundant.push(user.clone());
        }
    }

    // Merge: defaults first, then user paths that add something new
    let mut effective: Vec<String> = default_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    for user in user_paths {
        if !redundant.contains(user) {
            effective.push(user.clone());
        }
    }

    (effective, redundant)
}

/// Scan a filesystem tree and calculate digests for all regular files.
///
/// File discovery is sequential (I/O-bound) but digest calculation
/// is parallelised across available CPU cores using Rayon.
///
/// # Arguments
///
/// * `root` - Root directory to scan
/// * `skip_paths` - Absolute paths to skip (directories and their contents)
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

    let skip_set: Vec<PathBuf> =
        skip_paths.iter().map(PathBuf::from).collect();

    // Phase 1: collect all file paths (sequential, I/O-bound)
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(&root, &skip_set, &mut files)?;

    // Phase 2: calculate digests in parallel (CPU-bound)
    let results: Vec<_> = files
        .par_iter()
        .filter_map(|path| match calculate_file_digest(path, algorithm) {
            Ok(digest) => {
                let relative = make_policy_path(path, &root);
                Some((relative, digest))
            }
            Err(e) => {
                log::warn!("Skipping {}: {e}", path.display());
                None
            }
        })
        .collect();

    // Phase 3: merge into DigestMap (sequential, fast)
    let mut digests: DigestMap = HashMap::new();
    for (path, digest) in results {
        let entry = digests.entry(path).or_default();
        if !entry.contains(&digest) {
            entry.push(digest);
        }
    }

    Ok(digests)
}

/// Recursively collect all regular file paths, skipping symlinks
/// and excluded directories.
fn collect_files(
    dir: &Path,
    skip_paths: &[PathBuf],
    files: &mut Vec<PathBuf>,
) -> Result<(), PolicyGenerationError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            // Permission denied on a subdirectory is not fatal
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                log::warn!("Skipping directory {}: {}", dir.display(), e);
                return Ok(());
            }
            return Err(PolicyGenerationError::FilesystemScan {
                path: dir.to_path_buf(),
                reason: format!("Failed to read directory: {e}"),
            });
        }
    };

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
            collect_files(&path, skip_paths, files)?;
        } else if path.is_file() {
            files.push(path);
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

    #[test]
    fn test_build_effective_skip_paths_root() {
        let (effective, redundant) =
            build_effective_skip_paths(Path::new("/"), &[]);

        // All base dirs should be present
        assert!(effective.contains(&"/sys".to_string()));
        assert!(effective.contains(&"/run".to_string()));
        assert!(effective.contains(&"/proc".to_string()));
        assert!(effective.contains(&"/tmp".to_string()));
        assert!(effective.contains(&"/var".to_string()));
        assert!(redundant.is_empty());
    }

    #[test]
    fn test_build_effective_skip_paths_custom_rootfs() {
        let (effective, _) =
            build_effective_skip_paths(Path::new("/mnt/rootfs"), &[]);

        assert!(effective.contains(&"/mnt/rootfs/sys".to_string()));
        assert!(effective.contains(&"/mnt/rootfs/run".to_string()));
        assert!(effective.contains(&"/mnt/rootfs/tmp".to_string()));
    }

    #[test]
    fn test_build_effective_skip_paths_redundant() {
        let user = vec!["/var/log".to_string(), "/home".to_string()];
        let (effective, redundant) =
            build_effective_skip_paths(Path::new("/"), &user);

        // /var/log is under /var (a default) so it's redundant
        assert_eq!(redundant, vec!["/var/log".to_string()]);
        // /home is NOT a default so it should be added
        assert!(effective.contains(&"/home".to_string()));
        // /var/log should NOT be in effective (it's redundant)
        assert!(!effective.contains(&"/var/log".to_string()));
    }

    #[test]
    fn test_build_effective_skip_paths_exact_match() {
        let user = vec!["/tmp".to_string()];
        let (_, redundant) =
            build_effective_skip_paths(Path::new("/"), &user);

        // /tmp exactly matches a default
        assert_eq!(redundant, vec!["/tmp".to_string()]);
    }

    #[test]
    fn test_scan_filesystem_parallel_produces_correct_results() {
        let dir = TempDir::new().unwrap(); //#[allow_ci]
        let root = dir.path();

        // Create many files to exercise parallel paths
        for i in 0..50 {
            fs::write(
                root.join(format!("file_{i}.txt")),
                format!("content {i}"),
            )
            .unwrap(); //#[allow_ci]
        }

        let result = scan_filesystem(root, &[], "sha256").unwrap(); //#[allow_ci]
        assert_eq!(result.len(), 50);
    }
}
