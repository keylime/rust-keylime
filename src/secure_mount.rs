use super::*;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/*
 * Input: secure mount directory
 * Return: boolean
 *         - true if directory is mounted
 *         - false if not mounted
 *
 * Check the mount status of the secure mount directory. Same
 * implementation as the original python version.
 */
fn check_mount(secure_dir: &str) -> bool {
    let output = Command::new("mount")
        .output()
        .expect("Failed to execute mount command");

    let mount_result = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = mount_result.split("\n").collect();

    // Check mount list for secure directory
    for line in lines {
        let tokens: Vec<&str> = line.split('/').collect();

        if tokens.len() < 3 {
            continue;
        }

        if tokens[2] == secure_dir {
            if &tokens[0] != &"tmpfs" {
                error!("secure storage location {} already mounted on wrong file system type: {}.  Unmount to continue.", secure_dir, tokens[0]);
                debug!(
                    "secure storage location {} aleady mounted on tmpfs",
                    secure_dir
                );
            } else {
                return true;
            }
        }
    }
    debug!("secure storage location {} not mounted.", secure_dir);
    false
}

/*
 * Return: Result contains secure mount directory or error code
 *
 * Mounted the work directory as tmpfs, which is owned by root. Same
 * implementation as the original python version, but the chown/geteuid
 * functions are unsafe function in Rust to use.
 */
fn mount() -> Result<String, i32> {
    // use /tmpfs-dev directory if MOUNT_SECURE flag is setm, which doesn't
    // mount to the system. This is for developement envrionment.
    if !common::MOUNT_SECURE {
        let secure_dir = format!("{}{}", common::WORK_DIR, "/tmpfs-dev");
        let secure_dir_path = Path::new(secure_dir.as_str());
        if !secure_dir_path.exists() {
            match fs::create_dir(secure_dir_path) {
                Ok(()) => {
                    return Ok(secure_dir_path.to_str().unwrap().to_string())
                }
                Err(e) => {
                    error!("Failed to create directory, error {}", e);
                    return Err(-1);
                }
            }
        }
    }

    let secure_dir = format!("{}{}", common::WORK_DIR, "/secure");

    // if the directory is not mount to file system, mount the directory to
    // file system
    if !check_mount(&secure_dir) {
        let secure_dir_clone = secure_dir.clone();
        let secure_dir_path = Path::new(secure_dir_clone.as_str());

        // create directory if the directory is not exist
        if !secure_dir_path.exists() {
            match fs::create_dir(secure_dir_path) {
                Ok(()) => {
                    let metadata = fs::metadata(secure_dir_path).unwrap();
                    let mut perm = metadata.permissions();

                    // This function support unix only
                    perm.set_mode(448);
                }

                Err(e) => {
                    error!("Failed to create directory, error {}", e);
                    return Err(-1);
                }
            }
        }

        info!(
            "Mounting secure storage location {} on tmpfs.",
            secure_dir_path.to_str().unwrap()
        );

        // change the secure path directory owner to root
        match common::chownroot(secure_dir_path.to_str().unwrap().to_string())
        {
            Ok(path) => info!("Changed path {} owner to root.", path),
            Err(e) => {
                error!("Failed to path owner with error code {}.", e);
                return Err(-1);
            }
        }

        // mount tmpfs with secure directory
        tpm::run(
            format!(
                "mount -t tmpfs -o size={},mode=0700 tmpfs {}",
                common::SECURE_SIZE,
                secure_dir_path.to_str().unwrap()
            ),
            tpm::EXIT_SUCCESS,
            true,
            false,
            String::new(),
        );
    }
    Ok(secure_dir)
}
