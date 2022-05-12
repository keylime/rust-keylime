// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use super::*;

use crate::error::{Error, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
/*
 * Input: secure mount directory
 * Return: Result wrap boolean with error message
 *         - true if directory is mounted
 *         - false if not mounted
 *
 * Check the mount status of the secure mount directory. Same
 * implementation as the original python version.
 */
fn check_mount(secure_dir: &Path) -> Result<bool> {
    let output = Command::new("mount").output()?;

    let mount_result = String::from_utf8(output.stdout)?;

    let lines: Vec<&str> = mount_result.split('\n').collect();

    // Check mount list for secure directory
    for line in lines {
        let tokens: Vec<&str> = line.split(' ').collect();

        if tokens.len() < 3 {
            continue;
        }

        if Path::new(tokens[2]) == secure_dir {
            if tokens[0] != "tmpfs" {
                let msg = format!("secure storage location {:?} already mounted as wrong file system type: {}. Unmount to continue", &secure_dir, tokens[0]);
                error!("{}", msg);
                return Err(Error::SecureMount(msg));
            } else {
                info!(
                    "Using existing secure storage tmpsfs mount {:?}",
                    &secure_dir
                );
            }
            return Ok(true);
        }
    }

    info!("secure storage location {:?} not mounted.", &secure_dir);
    Ok(false)
}

/*
 * Return: Result wrap secure mount directory or error code
 *
 * Mounted the work directory as tmpfs, which is owned by root. Same
 * implementation as the original python version, but the chown/geteuid
 * functions are unsafe function in Rust to use.
 */
#[allow(clippy::unwrap_used)]
pub(crate) fn mount(work_dir: &Path, secure_size: &str) -> Result<PathBuf> {
    // Use /tmpfs-dev directory if MOUNT_SECURE flag is not set. This
    // is for development environment and does not mount to the system.
    if !MOUNT_SECURE {
        warn!("Using /tmpfs-dev (dev environment)");
        let secure_dir_path = Path::new(work_dir).join("tmpfs-dev");
        if !secure_dir_path.exists() {
            fs::create_dir(&secure_dir_path).map_err(|e| {
                Error::SecureMount(format!(
                    "unable to create secure dir path: {:?}",
                    e
                ))
            })?;
            info!("Directory {:?} created.", &secure_dir_path);
        }

        return Ok(secure_dir_path);
    }

    // Mount the directory to file system
    let secure_dir_path = Path::new(work_dir).join("secure");

    // If the directory is not mount to file system, mount the directory to
    // file system.
    if !check_mount(&secure_dir_path)? {
        // Create directory if the directory is not exist. The
        // directory permission is set to 448.
        if !secure_dir_path.exists() {
            fs::create_dir(&secure_dir_path).map_err(|e| {
                Error::SecureMount(format!(
                    "unable to create secure dir path: {:?}",
                    e
                ))
            })?;

            info!("Directory {:?} created.", secure_dir_path);
            let metadata = fs::metadata(&secure_dir_path).map_err(|e| {
                Error::SecureMount(format!(
                    "unable to get metadata for secure dir path: {:?}",
                    e
                ))
            })?;
            metadata.permissions().set_mode(0o750); // decimal 488
        }

        info!(
            "Mounting secure storage location {:?} on tmpfs.",
            &secure_dir_path
        );

        // change the secure path directory owner to root
        match chownroot(&secure_dir_path) {
            Ok(_) => {
                info!("Changed path {:?} owner to root.", &secure_dir_path);
            }
            Err(e) => {
                return Err(Error::SecureMount(
                    format!(
                        "unable to change secure path dir owner to root: received exit code {}",
                        e.exe_code()?.unwrap() // because this is an Option
                    ),
                ));
            }
        }

        // mount tmpfs with secure directory
        match Command::new("mount")
            .args([
                "-t",
                "tmpfs",
                "-o",
                format!("size={},mode=0700", secure_size).as_str(),
                "tmpfs",
                secure_dir_path.to_str().unwrap(),
            ])
            .output()
        {
            Ok(output) => {
                if !output.status.success() {
                    return Err(Error::SecureMount(format!(
                        "unable to mount tmpfs with secure dir: exit status code {}",
                        output.status
                    )));
                }
            }
            Err(e) => {
                return Err(Error::SecureMount(format!(
                    "unable to mount tmpfs with secure dir: {}",
                    e
                )));
            }
        }
    }

    Ok(secure_dir_path)
}
