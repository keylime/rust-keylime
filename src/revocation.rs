// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#[macro_use]
use log::*;

use crate::common::{KeylimeConfig, REV_CERT, WORK_DIR};
use crate::crypto;
use crate::error::*;
use crate::secure_mount;

use std::convert::TryInto;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// Runs a script with a json value as argument (used for revocation actions)
pub(crate) fn run_action(
    dir: &Path,
    script: &str,
    json: Value,
) -> Result<Output> {
    let raw_json = serde_json::value::to_raw_value(&json)?;

    let mut child = Command::new(format!("{}{}", "./", script))
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_ref_mut = match child.stdin.as_mut() {
        Some(c) => c,
        None => {
            return Err(Error::Other(format!(
                "unable to get mut ref to child stdin in {}",
                script
            )));
        }
    };

    child_ref_mut.write_all(raw_json.get().as_bytes());
    let output = child.wait_with_output()?;

    if !output.status.success() {
        return Err(output.try_into()?);
    }

    info!(
        "{}",
        format!("INFO: revocation action {:?} successful", script)
    );
    Ok(output)
}

/// Runs revocation actions received from tenant post-attestation
///
/// An OK result indicates all actions were run successfully.
/// Otherwise, an Error will be returned from the first action that
/// did not run successfully.
pub(crate) fn run_revocation_actions(
    json: Value,
    secure_size: &str,
) -> Result<Vec<Output>> {
    #[cfg(not(test))]
    pretty_env_logger::init();

    #[cfg(test)]
    let mount = concat!(env!("CARGO_MANIFEST_DIR"), "/tests");

    #[cfg(not(test))]
    let mount = secure_mount::mount(secure_size)?;
    let unzipped = format!("{}/unzipped", mount);
    let action_file = format!("{}/unzipped/action_list", mount);

    let mut outputs = Vec::new();

    if Path::new(&action_file).exists() {
        let action_data = std::fs::read_to_string(action_file)
            .expect("unable to read action_list");

        let action_list = action_data
            .split('\n')
            .filter(|&script| !script.is_empty())
            .map(|script| script.trim())
            .collect::<Vec<&str>>();

        if !action_list.is_empty() {
            for action in action_list {
                match run_action(Path::new(&unzipped), action, json.clone()) {
                    Ok(output) => {
                        outputs.push(output);
                    }
                    Err(e) => {
                        let msg = format!(
                            "error executing revocation script {}: {:?}",
                            action, e
                        );
                        error!("{}", msg);
                        return Err(Error::Script(
                            String::from(action),
                            e.exe_code()?,
                            e.stderr()?,
                        ));
                    }
                }
            }
        } else {
            warn!("WARNING: no actions found in revocation action list");
        }
    } else {
        warn!("WARNING: no action_list found in secure directory");
    }

    Ok(outputs)
}

/// Get the revocation certificate path according to the revocation_cert entry
/// from the configuration file
///
/// If the revocation_cert entry is "default", then use the default path;
/// If the revocation_cert entry is an absolute path, then use the specified path;
/// If the revocation_cert entry is a relative path, then expand from the WORK_DIR;
/// If the revocation_cert is empty, fallback to the default path.
fn get_revocation_cert_path(config: &KeylimeConfig) -> Result<PathBuf> {
    let default_path = &format!("{}/secure/unzipped/{}", WORK_DIR, REV_CERT);

    // Unlike the python agent we do not attempt lazy loading. We either
    // have the certificate, or we don't. If we don't have a key or can't load
    // the key we return a Configuration error as the service will not work.
    let mut cert_path_buf = match config.revocation_cert.trim() {
        "default" => PathBuf::from(&default_path),
        "" => {
            error!("revocation_cert is not set in configuration");
            return Err(Error::Configuration(String::from(
                "revocation_cert is not set in configuration",
            )));
        }
        _ => PathBuf::from(config.revocation_cert.trim()),
    };

    // If the path is not absolute, expand from the WORK_DIR
    if cert_path_buf.as_path().is_relative() {
        let rel_path = cert_path_buf;
        cert_path_buf = PathBuf::from(WORK_DIR);
        cert_path_buf.push(rel_path);
    }

    Ok(cert_path_buf)
}

/// Handles revocation messages via 0mq
/// See:
/// - URL: https://github.com/keylime/keylime/blob/master/keylime/revocation_notifier.py
///   Function: await_notifications
pub(crate) async fn run_revocation_service(
    config: &KeylimeConfig,
) -> Result<()> {
    let mount = secure_mount::mount(&config.secure_size)?;

    // Connect to the service via 0mq
    let context = zmq::Context::new();
    let mysock = context.socket(zmq::SUB)?;

    mysock.set_subscribe(b"")?;

    let endpoint =
        format!("tcp://{}:{}", config.revocation_ip, config.revocation_port);

    info!("Connecting to revocation endpoint at {}...", endpoint);

    mysock.connect(endpoint.as_str())?;

    // Get the path to the certificate and canonicalize to obtain an absolute path
    let revocation_cert_path =
        get_revocation_cert_path(config)?.canonicalize()?;

    let cert_key = if revocation_cert_path.exists() {
        info!(
            "Loading the revocation certificate from {}",
            revocation_cert_path.display()
        );
        match crypto::import_x509(revocation_cert_path.display().to_string())
        {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::Configuration(String::from(
                    "Cannot load pubkey",
                )))
            }
        }
    } else {
        error!(
            "Path {} for the 0mq socket doesn't exist",
            revocation_cert_path.display()
        );
        return Err(Error::Configuration(format!(
            "Path {} for the 0mq socket socket doesn't exist",
            revocation_cert_path.display(),
        )));
    };

    info!("Waiting for revocation messages on 0mq {}", endpoint);

    // Main revocation service loop. If a message is malformed or
    // can not be verified the loop continues.
    loop {
        let mut rawbody = match mysock.recv_string(0) {
            Ok(v) => match v {
                Ok(v) => v,
                _ => {
                    warn!("Unable to read message from 0mq");
                    continue;
                }
            },
            Err(e) => {
                warn!("Unable to read message from 0mq");
                continue;
            }
        };

        let body: Value = serde_json::from_str(rawbody.as_str())?;

        // Ensure we have a signature, otherwise continue the loop
        let signature = match body["signature"].as_str() {
            Some(v) => v,
            _ => {
                warn!("No signature on revocation message from server");
                continue;
            }
        };

        // Ensure we have a msg, otherwise continue the loop
        let message = match body["msg"].as_str() {
            Some(v) => v,
            _ => {
                warn!("No msg on revocation message from server");
                continue;
            }
        };

        // Verify the message and signature with our key
        let mut verified = crypto::asym_verify(&cert_key, message, signature);

        match verified {
            Ok(true) => {
                let msg = body["msg"].as_str();
                let msg_payload: Value = serde_json::from_str(match msg {
                    Some(v) => v,
                    _ => {
                        warn!("Unable to decode json in msg");
                        continue;
                    }
                })?;
                debug!(
                    "Revocation signature validated for revocation: {}",
                    msg_payload
                );
                let _ =
                    run_revocation_actions(msg_payload, &config.secure_size)?;
            }
            _ => {
                error!("Invalid revocation message signature {}", body);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_scripts_ok() {
        let test_config = KeylimeConfig::default();
        let json_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/unzipped/test_ok.json"
        );
        let json_str = std::fs::read_to_string(json_file).unwrap(); //#[allow_ci]
        let json = serde_json::from_str(&json_str).unwrap(); //#[allow_ci]
        let outputs = run_revocation_actions(json, &test_config.secure_size);
        assert!(outputs.is_ok());
        let outputs = outputs.unwrap(); //#[allow_ci]
        assert!(outputs.len() == 2);

        for output in outputs {
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(), //#[allow_ci]
                "there\n"
            );
        }
    }

    #[test]
    fn revocation_scripts_err() {
        let test_config = KeylimeConfig::default();
        let json_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/unzipped/test_err.json"
        );
        let json_str = std::fs::read_to_string(json_file).unwrap(); //#[allow_ci]
        let json = serde_json::from_str(&json_str).unwrap(); //#[allow_ci]

        let outputs = run_revocation_actions(json, &test_config.secure_size);
        assert!(outputs.is_err());
    }

    #[test]
    fn get_revocation_cert_path_default() {
        let test_config = KeylimeConfig::default();
        let revocation_cert_path =
            get_revocation_cert_path(&test_config).unwrap(); //#[allow_ci]
        let mut expected = PathBuf::from(WORK_DIR);
        expected.push("secure/unzipped/");
        expected.push(REV_CERT);
        assert_eq!(*revocation_cert_path, expected);
    }

    #[test]
    fn get_revocation_cert_path_absolute() {
        let mut test_config = KeylimeConfig {
            revocation_cert: String::from("/test/cert.crt"),
            ..Default::default()
        };
        let revocation_cert_path =
            get_revocation_cert_path(&test_config).unwrap(); //#[allow_ci]
        assert_eq!(revocation_cert_path, PathBuf::from("/test/cert.crt"));
    }

    #[test]
    fn get_revocation_cert_path_relative() {
        let mut test_config = KeylimeConfig {
            revocation_cert: String::from("cert.crt"),
            ..Default::default()
        };
        let revocation_cert_path =
            get_revocation_cert_path(&test_config).unwrap(); //#[allow_ci]
        let mut expected = PathBuf::from(WORK_DIR);
        expected.push("cert.crt");
        assert_eq!(revocation_cert_path, expected);
    }

    #[test]
    fn get_revocation_cert_path_empty() {
        let mut test_config = KeylimeConfig {
            revocation_cert: String::from(""),
            ..Default::default()
        };
        assert!(
            get_revocation_cert_path(&test_config).is_err(),
            "revocation_cert is not set in configuration"
        );
    }
}
