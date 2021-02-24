// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::error::{Error, Result};
use ini::Ini;
use log::*;
use std::env;

/*
 * Constants and static variables
 */
pub const STUB_VTPM: bool = false;
pub const STUB_IMA: bool = true;
pub const TPM_DATA_PCR: usize = 16;
pub const IMA_PCR: usize = 10;
pub static DEFAULT_CONFIG: &str = "/etc/keylime.conf";
pub static RSA_PUBLICKEY_EXPORTABLE: &str = "rsa placeholder";
pub static TPM_TOOLS_PATH: &str = "/usr/local/bin/";
pub static IMA_ML_STUB: &str = "../scripts/ima/ascii_runtime_measurements";
pub static IMA_ML: &str =
    "/sys/kernel/security/ima/ascii_runtime_measurements";
pub static KEY: &str = "secret";
pub static WORK_DIR: &str = "/tmp";

// Secure mount of tpmfs (False is generally used for development environments)
pub static MOUNT_SECURE: bool = true;

/*
 * Return: Returns the configuration file provided in the environment variable
 * KEYLIME_CONFIG or defaults to /etc/keylime.conf
 *
 * Example call:
 * let config = config_file_get();
 */
pub(crate) fn config_file_get() -> String {
    match env::var("KEYLIME_CONFIG") {
        Ok(cfg) => {
            // The variable length must be larger than 0 to accept
            if !cfg.is_empty() {
                cfg
            } else {
                String::from(DEFAULT_CONFIG)
            }
        }
        _ => String::from(DEFAULT_CONFIG),
    }
}

/*
 * Input: [section] and key
 * Return: Returns the matched key
 *
 * Example call:
 * let port = common::config_get("general","cloudagent_port");
 */
pub(crate) fn config_get(section: &str, key: &str) -> Result<String> {
    let conf_name = config_file_get();
    let conf = Ini::load_from_file(&conf_name)?;
    let section = match conf.section(Some(section.to_owned())) {
        Some(section) => section,
        None =>
        // TODO: Make Error::Configuration an alternative with data instead of string
        {
            return Err(Error::Configuration(format!(
                "Cannot find section called {} in file {}",
                section, conf_name
            )))
        }
    };
    let value = match section.get(key) {
        Some(value) => value,
        None =>
        // TODO: Make Error::Configuration an alternative with data instead of string
        {
            return Err(Error::Configuration(format!(
                "Cannot find key {} in fine {}",
                key, conf_name
            )))
        }
    };

    Ok(value.clone())
}

/*
 * Input: path directory to be changed owner to root
 * Return: Result contains execution result
 *         - directory name for successful execution
 *         - -1 code for failure execution.
 *
 * If privilege requirement is met, change the owner of the path to root
 * This function is unsafely using libc. Result is returned indicating
 * execution result.
 */
pub(crate) fn chownroot(path: String) -> Result<String> {
    unsafe {
        // check privilege
        if libc::geteuid() != 0 {
            error!("Privilege level unable to change ownership to root for file: {}", path);
            return Err(Error::Permission);
        }

        // change directory owner to root
        if libc::chown(path.as_bytes().as_ptr() as *const i8, 0, 0) != 0 {
            error!("Failed to change file {} owner.", path);
            return Err(Error::Permission);
        }

        info!("Changed file {} owner to root.", path);
        Ok(path)
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_get_parameters_exist() {
        //let result = config_get("keylime.conf", "general", "cloudagent_port");
        //assert_eq!(result, "9002");
    }

    #[test]
    fn test_config_file_get() {
        // Test with no environment variable
        env::set_var("KEYLIME_CONFIG", "");
        assert_eq!(config_file_get(), String::from("/etc/keylime.conf"));

        // Test with an environment variable
        env::set_var("KEYLIME_CONFIG", "/tmp/testing.conf");
        assert_eq!(config_file_get(), String::from("/tmp/testing.conf"));
        // Reset environment
        env::set_var("KEYLIME_CONFIG", "");
    }
}
