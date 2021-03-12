// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use super::*;

use crate::cmd_exec;
use crate::error::{Error, Result};
use common::config_get;
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
fn check_mount(secure_dir: &str) -> Result<bool> {
    let output = Command::new("mount").output()?;

    let mount_result = String::from_utf8(output.stdout)?;

    let lines: Vec<&str> = mount_result.split('\n').collect();

    // Check mount list for secure directory
    for line in lines {
        let tokens: Vec<&str> = line.split(' ').collect();

        if tokens.len() < 3 {
            continue;
        }

        if tokens[2] == secure_dir {
            if tokens[0] != "tmpfs" {
                let msg = format!("secure storage location {} already mounted as wrong file system type: {}. Unmount to continue", secure_dir, tokens[0]);
                error!("{}", msg);
                return Err(Error::SecureMount(msg));
            } else {
                info!(
                    "Using existing secure storage tmpsfs mount {}",
                    secure_dir
                );
            }
            return Ok(true);
        }
    }

    info!("secure storage location {} not mounted.", secure_dir);
    Ok(false)
}

/*
 * Return: Result wrap secure mount directory or error code
 *
 * Mounted the work directory as tmpfs, which is owned by root. Same
 * implementation as the original python version, but the chown/geteuid
 * functions are unsafe function in Rust to use.
 */
pub(crate) fn mount() -> Result<String> {
    // Use /tmpfs-dev directory if MOUNT_SECURE flag is not set. This
    // is for development environment and does not mount to the system.
    if !MOUNT_SECURE {
        info!("Using /tmpfs-dev (dev environment)");
        let secure_dir = format!("{}{}", WORK_DIR, "/tmpfs-dev");
        let secure_dir_path = Path::new(secure_dir.as_str());
        if !secure_dir_path.exists() {
            fs::create_dir(secure_dir_path).map_err(|e| {
                Error::SecureMount(format!(
                    "unable to create secure dir path: {:?}",
                    e
                ))
            })?;
            info!("Directory {:?} created.", secure_dir_path);
        }

        return Ok(secure_dir_path.to_str().unwrap().to_string()); //#[allow_ci] : because this is an Option
    }

    // Mount the directory to file system
    let secure_dir = format!("{}/secure", WORK_DIR);
    let secure_size = config_get("cloud_agent", "secure_size")?;

    match check_mount(&secure_dir)? {
        false => {
            // If the directory is not mount to file system, mount the directory to
            // file system.
            let secure_dir_clone = secure_dir.clone();
            let secure_dir_path = Path::new(secure_dir_clone.as_str());

            // Create directory if the directory is not exist. The
            // directory permission is set to 448.

            if !secure_dir_path.exists() {
                fs::create_dir(secure_dir_path).map_err(|e| {
                    Error::SecureMount(format!(
                        "unable to create secure dir path: {:?}",
                        e
                    ))
                })?;

                info!("Directory {:?} created.", secure_dir_path);
                let metadata =
                    fs::metadata(secure_dir_path).map_err(|e| {
                        Error::SecureMount(format!("unable to get metadata for secure dir path: {:?}", e))
                    })?;
                metadata.permissions().set_mode(488);
            }

            match secure_dir_path.to_str() {
                Some(s) => {
                    info!("Mounting secure storage location {} on tmpfs.", s);

                    // change the secure path directory owner to root
                    if let Err(e) = chownroot(s.to_string()).map(|path| {
                        info!("Changed path {} owner to root.", path);
                    }) {
                        return Err(Error::SecureMount(
                                format!(
                                    "unable to change secure path dir owner to root: received exit code {}",
                                    e.exe_code()?.unwrap() //#[allow_ci] : because this is an Option
                                ),
                            ));
                    }

                    // mount tmpfs with secure directory
                    if let Err(e) = cmd_exec::run(
                        format!(
                            "mount -t tmpfs -o size={},mode=0700 tmpfs {}",
                            secure_size, s,
                        ),
                        None,
                    ) {
                        return Err(Error::SecureMount(
                            format!(
                                "unable to mount tmpfs with secure dir: received exit code {}",
                                e.exe_code()?.unwrap() //#[allow_ci] : because this is an Option
                            ),
                        ));
                    }

                    Ok(s.to_string())
                }
                None => Err(Error::SecureMount(
                    "Error mounting secure storage location on tmpfs"
                        .to_string(),
                )),
            }
        }

        true => Ok(secure_dir),
    }
}
