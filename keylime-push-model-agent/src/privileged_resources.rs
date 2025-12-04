// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Resources that require root privileges to initialize
//!
//! This module handles opening files and resources that require elevated
//! privileges (typically root) to access. These operations must be performed
//! before dropping privileges to an unprivileged user.
//!
//! The main resources that require root access are:
//! - IMA measurement log (`/sys/kernel/security/ima/ascii_runtime_measurements`)
//! - Measured boot log (`/sys/kernel/security/tpm0/binary_bios_measurements`)
//!
//! After these resources are opened, the process can safely drop privileges
//! to run as an unprivileged user (typically `keylime:keylime`). The user
//! must be a member of the `tss` group to access TPM devices.

use anyhow::Result;
use keylime::ima::MeasurementList;
use log::{info, warn};
use std::fs::File;
use std::path::Path;
use std::sync::Mutex;

/// Resources that require root privileges to initialize
///
/// This structure holds file handles and other resources that must be
/// opened while the process is running with elevated privileges (root).
/// After initialization, these resources are passed down to the rest of
/// the application, which runs as an unprivileged user.
#[derive(Debug)]
pub struct PrivilegedResources {
    /// IMA measurement log file handle (if available)
    ///
    /// This file requires root access to `/sys/kernel/security/ima/`.
    /// If the file doesn't exist or can't be opened, this will be None
    /// and IMA attestation will be unavailable.
    pub ima_ml_file: Option<Mutex<File>>,

    /// IMA measurement list state tracker
    ///
    /// This maintains state between IMA log reads, tracking which entries
    /// have been read to enable efficient incremental updates.
    pub ima_ml: Mutex<MeasurementList>,

    /// Measured boot (UEFI) log file handle (if available)
    ///
    /// This file requires root access to `/sys/kernel/security/tpm0/`.
    /// If the file doesn't exist or can't be opened, this will be None
    /// and measured boot attestation will be unavailable.
    pub measuredboot_ml_file: Option<Mutex<File>>,
}

impl PrivilegedResources {
    /// Initialize all privileged resources while running as root
    ///
    /// This function should be called early in main(), before dropping
    /// privileges. It opens files that require root access to
    /// `/sys/kernel/security/`.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing paths to measurement logs
    ///
    /// # Returns
    ///
    /// Returns a `PrivilegedResources` structure with file handles.
    /// Individual file handles may be None if the files don't exist or
    /// can't be opened, but the function will not fail - it will log
    /// warnings and continue.
    ///
    /// # Errors
    ///
    /// Currently does not return errors - missing files are treated as
    /// warnings and the agent continues without that capability.
    pub fn new(config: &keylime::config::AgentConfig) -> Result<Self> {
        // Open IMA log (requires root for /sys/kernel/security/ima/)
        let ima_ml_path = Path::new(config.ima_ml_path.as_str());
        let ima_ml_file = if ima_ml_path.exists() {
            match File::open(ima_ml_path) {
                Ok(file) => {
                    info!(
                        "Opened IMA measurement log: {}",
                        ima_ml_path.display()
                    );
                    Some(Mutex::new(file))
                }
                Err(e) => {
                    warn!(
                        "IMA measurement list not accessible: {} - {}",
                        ima_ml_path.display(),
                        e
                    );
                    warn!("IMA attestation will be unavailable");
                    None
                }
            }
        } else {
            warn!(
                "IMA measurement list not available: {}",
                ima_ml_path.display()
            );
            warn!("IMA attestation will be unavailable");
            None
        };

        // Open measured boot log (requires root for /sys/kernel/security/tpm0/)
        let measuredboot_ml_path =
            Path::new(config.measuredboot_ml_path.as_str());
        let measuredboot_ml_file = if measuredboot_ml_path.exists() {
            match File::open(measuredboot_ml_path) {
                Ok(file) => {
                    info!(
                        "Opened measured boot log: {}",
                        measuredboot_ml_path.display()
                    );
                    Some(Mutex::new(file))
                }
                Err(e) => {
                    warn!(
                        "Measured boot measurement list not accessible: {} - {}",
                        measuredboot_ml_path.display(),
                        e
                    );
                    warn!("Measured boot attestation will be unavailable");
                    None
                }
            }
        } else {
            warn!(
                "Measured boot measurement list not available: {}",
                measuredboot_ml_path.display()
            );
            warn!("Measured boot attestation will be unavailable");
            None
        };

        Ok(PrivilegedResources {
            ima_ml_file,
            ima_ml: Mutex::new(MeasurementList::new()),
            measuredboot_ml_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keylime::config::AgentConfig;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_privileged_resources_new_with_missing_files() {
        // Test with paths that don't exist
        let config = AgentConfig {
            ima_ml_path: "/nonexistent/ima/log".to_string(),
            measuredboot_ml_path: "/nonexistent/uefi/log".to_string(),
            ..Default::default()
        };

        let resources = PrivilegedResources::new(&config)
            .expect("Should succeed even with missing files");

        assert!(resources.ima_ml_file.is_none());
        assert!(resources.measuredboot_ml_file.is_none());
        // IMA MeasurementList should always be initialized
        assert!(resources.ima_ml.lock().is_ok());
    }

    #[test]
    fn test_privileged_resources_new_with_existing_files() {
        // Create temporary files
        let mut ima_file =
            NamedTempFile::new().expect("Failed to create temp file");
        let mut uefi_file =
            NamedTempFile::new().expect("Failed to create temp file");

        // Write some test data
        ima_file
            .write_all(b"test ima data")
            .expect("Failed to write");
        uefi_file
            .write_all(b"test uefi data")
            .expect("Failed to write");

        let config = AgentConfig {
            ima_ml_path: ima_file.path().to_string_lossy().to_string(),
            measuredboot_ml_path: uefi_file
                .path()
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        };

        let resources = PrivilegedResources::new(&config)
            .expect("Should succeed with existing files");

        assert!(resources.ima_ml_file.is_some());
        assert!(resources.measuredboot_ml_file.is_some());
        assert!(resources.ima_ml.lock().is_ok());
    }

    #[test]
    fn test_privileged_resources_new_with_mixed_availability() {
        // Create only one temporary file
        let mut ima_file =
            NamedTempFile::new().expect("Failed to create temp file");
        ima_file
            .write_all(b"test ima data")
            .expect("Failed to write");

        let config = AgentConfig {
            ima_ml_path: ima_file.path().to_string_lossy().to_string(),
            measuredboot_ml_path: "/nonexistent/uefi/log".to_string(),
            ..Default::default()
        };

        let resources = PrivilegedResources::new(&config)
            .expect("Should succeed with partial availability");

        assert!(resources.ima_ml_file.is_some());
        assert!(resources.measuredboot_ml_file.is_none());
        assert!(resources.ima_ml.lock().is_ok());
    }
}
