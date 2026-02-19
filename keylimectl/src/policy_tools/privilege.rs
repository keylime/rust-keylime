// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Privilege detection utilities.
//!
//! Provides helpers for detecting permission errors and suggesting
//! that the user retry the command with `sudo`.

#![allow(dead_code)] // Used by subsequent Phase 6b steps (initrd, TPM, measured boot)

use crate::commands::error::PolicyGenerationError;
use std::path::Path;

/// Check if an I/O error is a permission error (`EACCES` or `EPERM`).
pub fn is_permission_error(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::PermissionDenied)
}

/// Format a suggestion to retry a command with `sudo`.
///
/// Returns a string like:
/// `"Insufficient privileges. Try: sudo keylimectl <operation>"`
pub fn suggest_sudo(operation: &str) -> String {
    format!("Insufficient privileges. Try: sudo keylimectl {operation}")
}

/// Check that `path` is readable, returning a
/// [`PolicyGenerationError::PrivilegeRequired`] on permission errors.
///
/// Other I/O errors (e.g. file not found) are returned as
/// [`PolicyGenerationError::Output`].
pub fn check_file_readable(
    path: &Path,
    operation: &str,
) -> Result<(), PolicyGenerationError> {
    match std::fs::metadata(path) {
        Ok(_) => {
            // metadata() succeeded, but we may still fail to read.
            // Try opening the file to confirm read access.
            match std::fs::File::open(path) {
                Ok(_) => Ok(()),
                Err(e) if is_permission_error(&e) => {
                    Err(PolicyGenerationError::PrivilegeRequired {
                        operation: operation.to_string(),
                        path: path.to_path_buf(),
                        hint: suggest_sudo(operation),
                    })
                }
                Err(e) => Err(PolicyGenerationError::Output {
                    path: path.to_path_buf(),
                    reason: format!("Failed to read file: {e}"),
                }),
            }
        }
        Err(e) if is_permission_error(&e) => {
            Err(PolicyGenerationError::PrivilegeRequired {
                operation: operation.to_string(),
                path: path.to_path_buf(),
                hint: suggest_sudo(operation),
            })
        }
        Err(e) => Err(PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: format!("Failed to access file: {e}"),
        }),
    }
}

/// Check that `path` (a directory) is readable and listable.
///
/// Returns [`PolicyGenerationError::PrivilegeRequired`] on permission errors.
pub fn check_dir_readable(
    path: &Path,
    operation: &str,
) -> Result<(), PolicyGenerationError> {
    match std::fs::read_dir(path) {
        Ok(_) => Ok(()),
        Err(e) if is_permission_error(&e) => {
            Err(PolicyGenerationError::PrivilegeRequired {
                operation: operation.to_string(),
                path: path.to_path_buf(),
                hint: suggest_sudo(operation),
            })
        }
        Err(e) => Err(PolicyGenerationError::Output {
            path: path.to_path_buf(),
            reason: format!("Failed to access directory: {e}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_permission_error_true() {
        let err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        );
        assert!(is_permission_error(&err));
    }

    #[test]
    fn test_is_permission_error_false_not_found() {
        let err = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        );
        assert!(!is_permission_error(&err));
    }

    #[test]
    fn test_is_permission_error_false_other() {
        let err = std::io::Error::other("something else");
        assert!(!is_permission_error(&err));
    }

    #[test]
    fn test_suggest_sudo_format() {
        let msg = suggest_sudo("policy generate runtime --ramdisk-dir /boot");
        assert!(msg.contains("sudo keylimectl"));
        assert!(msg.contains("--ramdisk-dir /boot"));
        assert!(msg.starts_with("Insufficient privileges"));
    }

    #[test]
    fn test_check_file_readable_not_found() {
        let result = check_file_readable(
            Path::new("/nonexistent/path/12345"),
            "test operation",
        );
        assert!(result.is_err());
        let err = result.unwrap_err(); //#[allow_ci]
                                       // Should be Output (not PrivilegeRequired) for NotFound
        match err {
            PolicyGenerationError::Output { path, reason } => {
                assert_eq!(
                    path,
                    std::path::PathBuf::from("/nonexistent/path/12345")
                );
                assert!(reason.contains("Failed to access"));
            }
            PolicyGenerationError::PrivilegeRequired { .. } => {
                // On some systems / might return PermissionDenied
                // before NotFound -- that's also acceptable
            }
            other => {
                panic!("Expected Output or PrivilegeRequired, got: {other}") //#[allow_ci]
            }
        }
    }

    #[test]
    fn test_check_dir_readable_not_found() {
        let result = check_dir_readable(
            Path::new("/nonexistent/dir/12345"),
            "test operation",
        );
        assert!(result.is_err());
    }
}
