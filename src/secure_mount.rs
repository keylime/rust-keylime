use super::*;

use common::config_get;
use common::emsg;
use std::error::Error;
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
fn check_mount(secure_dir: &str) -> Result<bool, Box<String>> {
    let output = Command::new("mount").output().map_err(|e| {
        Box::new(format!("Failed to execute mount command. Error {}.", e))
    })?;

    let mount_result = String::from_utf8(output.stdout).map_err(|e| {
        Box::new(format!("Failed to get output to string. Error {}.", e))
    })?;

    let lines: Vec<&str> = mount_result.split("\n").collect();

    // Check mount list for secure directory
    for line in lines {
        let tokens: Vec<&str> = line.split(' ').collect();

        if tokens.len() < 3 {
            continue;
        }

        if tokens[2] == secure_dir {
            if tokens[0] != "tmpfs" {
                return emsg(
                    format!(
                        "secure storage location {} already mounted on wrong file system type: {}.  Unmount to continue.", 
                        secure_dir,
                        tokens[0]).as_str(),
                        None::<String>
                    );
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
pub fn mount() -> Result<String, Box<String>> {
    // Use /tmpfs-dev directory if MOUNT_SECURE flag is set, which doesn't
    // mount to the system. This is for developement envrionment. No need to
    // mount to file system.
    if !common::MOUNT_SECURE {
        let secure_dir = format!("{}{}", common::WORK_DIR, "/tmpfs-dev");
        let secure_dir_path = Path::new(secure_dir.as_str());
        if !secure_dir_path.exists() {
            match fs::create_dir(secure_dir_path) {
                Ok(()) => {
                    info!("Directory {:?} created.", secure_dir_path);
                }
                Err(e) => {
                    return emsg("Failed to create directory.", Some(e));
                }
            }
        }

        if let Some(s) = secure_dir_path.to_str() {
            return Ok(s.to_string());
        }

        return emsg("Failed to get the path string.", None::<String>);
    }

    // Mount the directory to file system
    let secure_dir = format!("{}/secure", common::WORK_DIR);
    let secure_size =
        config_get("/etc/keylime.conf", "cloud_agent", "secure_size");

    match check_mount(&secure_dir) {
        Ok(false) => {
            // If the directory is not mount to file system, mount the directory to
            // file system.
            let secure_dir_clone = secure_dir.clone();
            let secure_dir_path = Path::new(secure_dir_clone.as_str());

            // Create directory if the directory is not exist. The
            // directory permission is set to 448.

            if !secure_dir_path.exists() {
                if let Err(e) = fs::create_dir(secure_dir_path) {
                    return emsg("Failed to create directory.", Some(e));
                }

                info!("Directory {:?} created.", secure_dir_path);
                let metadata =
                    fs::metadata(secure_dir_path).map_err(|e| {
                        Box::new(format!(
                            "Failed to get file metadata. Error {}",
                            e
                        ))
                    })?;
                metadata.permissions().set_mode(488);
            }

            match secure_dir_path.to_str() {
                Some(s) => {
                    info!("Mounting secure storage location {} on tmpfs.", s);

                    // change the secure path directory owner to root
                    common::chownroot(s.to_string())
                        .map(|path| {
                            info!("Changed path {} owner to root.", path);
                        })
                        .map_err(|e| {
                            format!(
                            "Failed to change path owner with error code {}.",
                            e
                        )
                        })?;

                    // mount tmpfs with secure directory
                    tpm::run(
                        format!(
                            "mount -t tmpfs -o size={},mode=0700 tmpfs {}",
                            secure_size, s,
                        ),
                        None,
                    )
                    .map_err(|e| e.description().to_string())?;

                    Ok(s.to_string())
                }
                None => emsg(
                    "Failed to get path to String for mount the file system.",
                    None::<String>,
                ),
            }
        }

        Ok(true) => Ok(secure_dir),
        Err(e) => emsg("Failed to check file system mount.", Some(e)),
    }
}
