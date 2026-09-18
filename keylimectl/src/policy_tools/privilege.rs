// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Privilege detection utilities.
//!
//! Provides helpers for detecting permission errors and suggesting
//! that the user retry the command with `sudo`.

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

/// Write sensitive data to a file with restricted permissions (0o600).
///
/// On Unix, the file is created atomically with `0o600` mode using
/// [`OpenOptions::mode`], preventing a TOCTOU race where the file would be
/// world-readable between creation and a subsequent `chmod` call.
///
/// On non-Unix platforms, falls back to a standard write.
pub fn write_sensitive_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .mode(0o600)
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        file.write_all(data)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
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
    fn test_write_sensitive_file_content() {
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        let path = tmp.path();
        let data = b"sensitive content";

        write_sensitive_file(path, data).unwrap(); //#[allow_ci]

        let read_back = std::fs::read(path).unwrap(); //#[allow_ci]
        assert_eq!(read_back, data);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_sensitive_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        let path = tmp.path();

        write_sensitive_file(path, b"secret").unwrap(); //#[allow_ci]

        let metadata = std::fs::metadata(path).unwrap(); //#[allow_ci]
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:#o}");
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
