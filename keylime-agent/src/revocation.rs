// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#[macro_use]
use log::*;

use crate::config::{AgentConfig, KeylimeConfig};
use crate::crypto;
use crate::error::*;
use crate::secure_mount;

use std::convert::TryInto;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use serde_json::Value;

/// Lookup for the action to be executed and return the command string
///
/// The lookup goes in the following order:
/// 1. Look for pre-installed action
/// 2. Look for the action in the tenant-provided initial payload
/// Then, if python revocation actions are allowed:
/// 3. Look for pre-installed Python action
/// 4. Look for the Python action in the tenant-provided initial payload
fn lookup_action(
    payload_dir: &Path,
    actions_dir: &Path,
    action: &str,
    allow_payload_actions: bool,
) -> Result<(String, bool, bool)> {
    let mut py_action = PathBuf::from(action);
    if !py_action.set_extension("py") {
        return Err(Error::Other(format!(
            "unable to set action {} extension",
            &action
        )));
    }

    // This creates four possible paths that will be searched to see if the script exists. The
    // order corresponds to the lookup order described in the documentation for this function.
    // The tuple is considered as (script, is_python, is_payload)
    let possible_paths = [
        (actions_dir.join(action), false, false),
        (payload_dir.join(action), false, true),
        #[cfg(feature = "legacy-python-actions")]
        (actions_dir.join(&py_action), true, false),
        #[cfg(feature = "legacy-python-actions")]
        (payload_dir.join(&py_action), true, true),
    ];

    match possible_paths
        .iter()
        .filter(|(_, _, is_payload)| {
            // Ignore payload actions if not allowed
            (!*is_payload || allow_payload_actions)
        })
        .find(|(path, _, _)| path.exists())
    {
        None => Err(Error::Io(std::io::Error::new(
            ErrorKind::NotFound,
            format!("Could not find action {action}"),
        ))),
        Some((script, is_python, is_payload)) => {
            // If the script is python, add the shim to the command.  It is expected to be
            // installed on pre-installed actions directory.
            let command = if *is_python {
                let shim = actions_dir.join("shim.py");
                format!("{}", shim.as_path().display())
            } else {
                format!("{}", script.as_path().display())
            };
            Ok((command, *is_python, *is_payload))
        }
    }
}

/// Runs a script with a json value as argument (used for revocation actions)
pub(crate) fn run_action(
    payload_dir: &Path,
    actions_dir: &Path,
    action: &str,
    json: Value,
    allow_payload_actions: bool,
    work_dir: &Path,
) -> Result<Output> {
    // Lookup for command and get command line
    let (command, is_python, is_payload) = lookup_action(
        payload_dir,
        actions_dir,
        action,
        allow_payload_actions,
    )?;

    info!("Executing revocation action {}", action);

    // Write JSON argument to a temporary file
    let raw_json = serde_json::value::to_raw_value(&json)?;
    let mut json_dump = tempfile::NamedTempFile::new_in(work_dir)?;
    json_dump.write_all(raw_json.get().as_bytes());

    //TODO check if it is possible to not keep the file when passing to another process
    let (json_dump, json_path) = json_dump.keep()?;

    let child = if is_python {
        let python_path = if is_payload { payload_dir } else { actions_dir };

        Command::new(command)
            .arg(action)
            .arg(&json_path)
            .current_dir(work_dir)
            .env("PYTHONPATH", python_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?
    } else {
        Command::new(command)
            .arg(&json_path)
            .current_dir(work_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?
    };

    let output = match child.wait_with_output() {
        Ok(output) => {
            fs::remove_file(json_path)?;
            output
        }
        Err(err) => {
            fs::remove_file(json_path)?;
            return Err(err.try_into()?);
        }
    };

    if !output.status.success() {
        return Err(output.try_into()?);
    }

    info!("INFO: revocation action {} successful", action);

    Ok(output)
}

/// Runs revocation actions received from tenant post-attestation
///
/// An OK result indicates all actions were run successfully.
/// Otherwise, an Error will be returned from the first action that
/// did not run successfully.
///
/// # Arguments
///
/// * `json` - The revocation message content
/// * `secure_size` - The size of the secure mount
/// * `config_actions` - Actions from the configuration file
/// * `actions_dir` - Location of the pre-installed actions
pub(crate) fn run_revocation_actions(
    json: Value,
    secure_size: &str,
    config_actions: &str,
    actions_dir: &Path,
    allow_payload_actions: bool,
    work_dir: &Path,
    mount: &Path,
) -> Result<Vec<Output>> {
    // The actions from the configuration file takes precedence over the actions from the
    // actions_list file
    let mut action_list = config_actions
        .split(',')
        .map(|script| script.trim())
        .filter(|script| !script.is_empty())
        .collect::<Vec<&str>>();

    let action_data;
    let unzipped = mount.join("unzipped");
    let action_file = unzipped.join("action_list");

    if action_file.exists() {
        action_data = std::fs::read_to_string(&action_file)
            .expect("unable to read action_list");

        let file_actions = action_data
            .split('\n')
            .map(|script| script.trim())
            .filter(|script| !script.is_empty());

        action_list.extend(file_actions);
    } else {
        warn!("WARNING: no action_list found in secure directory");
    }

    let mut outputs = Vec::new();

    if !action_list.is_empty() {
        for action in action_list {
            match run_action(
                &unzipped,
                actions_dir,
                action,
                json.clone(),
                allow_payload_actions,
                work_dir,
            ) {
                Ok(output) => {
                    outputs.push(output);
                }
                Err(e) => {
                    let msg = format!(
                        "error executing revocation script {action}: {e:?}"
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

    Ok(outputs)
}

/// Process revocation message received from REST API or 0mq
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_revocation(
    body: Value,
    cert_path: &Path,
    secure_size: &str,
    config_actions: &str,
    actions_dir: &Path,
    allow_payload_revocation_actions: bool,
    work_dir: &Path,
    mount: &Path,
) -> Result<()> {
    // Ensure we have a signature, otherwise continue the loop
    let signature = match body["signature"].as_str() {
        Some(v) => v,
        _ => {
            warn!("No signature on revocation message from server");
            return Err(Error::InvalidRequest);
        }
    };

    // Ensure we have a msg, otherwise continue the loop
    let message = match body["msg"].as_str() {
        Some(v) => v,
        _ => {
            warn!("No msg on revocation message from server");
            return Err(Error::InvalidRequest);
        }
    };

    // Canonicalize will fail it the file is not found
    let cert_absolute_path = cert_path.canonicalize()?;
    info!(
        "Loading the revocation certificate from {}",
        cert_absolute_path.display()
    );

    let cert_key = match crypto::load_x509(&cert_absolute_path) {
        Ok(v) => v.public_key().map_err(Error::Crypto)?,
        Err(e) => {
            return Err(Error::Configuration(String::from(
                "Cannot load pubkey from revocation certificate",
            )))
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
                    return Err(Error::InvalidRequest);
                }
            })?;
            debug!(
                "Revocation signature validated for revocation: {}",
                msg_payload
            );
            let outputs = run_revocation_actions(
                msg_payload,
                secure_size,
                config_actions,
                actions_dir,
                allow_payload_revocation_actions,
                work_dir,
                mount,
            )?;

            for output in outputs {
                if !output.stdout.is_empty() {
                    info!(
                        "Action stdout: {}",
                        String::from_utf8(output.stdout).unwrap() //#[allow_ci]
                    );
                }
                if !output.stderr.is_empty() {
                    warn!(
                        "Action stderr: {}",
                        String::from_utf8(output.stderr).unwrap() //#[allow_ci])
                    );
                }
            }
            Ok(())
        }
        _ => {
            error!("Invalid revocation message signature {}", body);
            Err(Error::InvalidRequest)
        }
    }
}

/// Handles revocation messages via 0mq
/// See:
/// - URL: https://github.com/keylime/keylime/blob/master/keylime/revocation_notifier.py
///   Function: await_notifications
#[cfg(feature = "with-zmq")]
pub(crate) async fn run_revocation_service(
    config: &KeylimeConfig,
    mount: &Path,
) -> Result<()> {
    let work_dir = Path::new(&config.agent.keylime_dir);

    // Connect to the service via 0mq
    let context = zmq::Context::new();
    let mysock = context.socket(zmq::SUB)?;

    mysock.set_subscribe(b"")?;

    let ip = if let Some(i) = &config.agent.revocation_notification_ip {
        i
    } else {
        error!("No IP set in 'revocation_notification_ip' option");
        return Err(Error::Configuration(
            "No IP set in 'revocation_notification_ip' option".to_string(),
        ));
    };

    let port = if let Some(p) = &config.agent.revocation_notification_port {
        p
    } else {
        error!("No port set in 'revocation_notification_port' option");
        return Err(Error::Configuration(
            "No port set in 'revocation_notification_port' option"
                .to_string(),
        ));
    };

    let endpoint = format!("tcp://{ip}:{port}");

    info!(
        "Connecting to revocation notification endpoint at {}...",
        endpoint
    );

    mysock.connect(endpoint.as_str())?;

    let revocation_cert = if let Some(cert) = &config.agent.revocation_cert {
        Path::new(cert)
    } else {
        error!("No revocation certificate set in 'revocation_cert' option");
        return Err(Error::Configuration(
            "No revocation certificate set in 'revocation_cert' option"
                .to_string(),
        ));
    };

    let actions_dir = if let Some(dir) = &config.agent.revocation_actions_dir
    {
        Path::new(dir)
    } else {
        error!("No revocation actions directory set in 'revocation_actions_dir' option");
        return Err(Error::Configuration("No revocation actions directory set in 'revocation_actions_dir' option".to_string()));
    };

    let actions = if let Some(a) = &config.agent.revocation_actions {
        a
    } else {
        ""
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
        let _ = process_revocation(
            body,
            revocation_cert,
            &config.agent.secure_size,
            actions,
            actions_dir,
            config.agent.allow_payload_revocation_actions,
            work_dir,
            mount,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Used to create symbolic links
    use std::os::unix::fs::symlink;

    #[test]
    fn revocation_scripts_ok() {
        let test_config = KeylimeConfig::default();
        let json_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/unzipped/test_ok.json"
        );
        let json_str = std::fs::read_to_string(json_file).unwrap(); //#[allow_ci]
        let json = serde_json::from_str(&json_str).unwrap(); //#[allow_ci]
        let actions_dir =
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions/");
        let work_dir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let tmpfs_dir = work_dir.path().join("tmpfs-dev"); //#[allow_ci]
        fs::create_dir(&tmpfs_dir).unwrap(); //#[allow_ci]
        let unzipped_dir =
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unzipped");
        symlink(unzipped_dir, tmpfs_dir.join("unzipped")).unwrap(); //#[allow_ci]
        let outputs = run_revocation_actions(
            json,
            &test_config.agent.secure_size,
            "",
            actions_dir,
            true,
            work_dir.path(),
            &tmpfs_dir,
        );

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
        let actions_dir =
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions/");
        let work_dir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let tmpfs_dir = work_dir.path().join("tmpfs-dev"); //#[allow_ci]
        fs::create_dir(&tmpfs_dir).unwrap(); //#[allow_ci]
        let unzipped_dir =
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unzipped");
        symlink(unzipped_dir, tmpfs_dir.join("unzipped")).unwrap(); //#[allow_ci]
        let outputs = run_revocation_actions(
            json,
            &test_config.agent.secure_size,
            "",
            actions_dir,
            true,
            work_dir.path(),
            &tmpfs_dir,
        );
        assert!(outputs.is_err());
    }

    #[test]
    fn revocation_scripts_from_config() {
        let mut test_config = KeylimeConfig::default();
        let json_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/unzipped/test_ok.json"
        );
        cfg_if::cfg_if! {
            if #[cfg(feature = "legacy-python-actions")] {
                let revocation_actions = "local_action_hello, local_action_payload, local_action_stand_alone.py, local_action_rev_script1.py";
            } else {
                let revocation_actions = "local_action_stand_alone.py, local_action_rev_script1.py";
            }
        }
        let json_str = std::fs::read_to_string(json_file).unwrap(); //#[allow_ci]
        let json = serde_json::from_str(&json_str).unwrap(); //#[allow_ci]
        let actions_dir =
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions/");
        let work_dir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let tmpfs_dir = work_dir.path().join("tmpfs-dev"); //#[allow_ci]
        fs::create_dir(&tmpfs_dir).unwrap(); //#[allow_ci]
        let unzipped_dir =
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unzipped");
        symlink(unzipped_dir, tmpfs_dir.join("unzipped")).unwrap(); //#[allow_ci]
        let outputs = run_revocation_actions(
            json,
            &test_config.agent.secure_size,
            revocation_actions,
            actions_dir,
            true,
            work_dir.path(),
            &tmpfs_dir,
        );

        assert!(outputs.is_ok());
        let outputs = outputs.unwrap(); //#[allow_ci]

        cfg_if::cfg_if! {
            if #[cfg(feature = "legacy-python-actions")] {
                assert!(outputs.len() == 6);
            } else {
                assert!(outputs.len() == 4);
            }
        }

        for output in outputs {
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(), //#[allow_ci]
                "there\n"
            );
        }
    }

    #[test]
    fn test_lookup_action() {
        let work_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let payload_dir = Path::new(&work_dir).join("unzipped/");
        let actions_dir = Path::new(&work_dir).join("actions/");

        cfg_if::cfg_if! {
            if #[cfg(feature = "legacy-python-actions")] {
                // Test local python action
                let expected =
                    format!("{}", &actions_dir.join("shim.py").display(),);

                assert_eq!(
                    lookup_action(
                        &payload_dir,
                        &actions_dir,
                        "local_action_hello",
                        true
                    )
                    .unwrap(), //#[allow_ci]
                    (expected, true, false)
                );
            }
        }

        // Test local non-python action
        let expected = format!(
            "{}",
            &actions_dir.join("local_action_hello_shell.sh").display()
        );

        assert_eq!(
            lookup_action(
                &payload_dir,
                &actions_dir,
                "local_action_hello_shell.sh",
                true
            )
            .unwrap(), //#[allow_ci]
            (expected, false, false)
        );

        cfg_if::cfg_if! {
            if #[cfg(feature = "legacy-python-actions")] {
                // Test payload python action
                let expected =
                    format!("{}", &actions_dir.join("shim.py").display(),);

                assert_eq!(
                    lookup_action(
                        &payload_dir,
                        &actions_dir,
                        "local_action_payload",
                        true,
                    )
                    .unwrap(), //#[allow_ci]
                    (expected, true, true),
                );
            }
        }

        // Test payload non-python action
        let expected = format!(
            "{}",
            &payload_dir.join("local_action_payload_shell.sh").display()
        );

        assert_eq!(
            lookup_action(
                &payload_dir,
                &actions_dir,
                "local_action_payload_shell.sh",
                true
            )
            .unwrap(), //#[allow_ci]
            (expected, false, true)
        );

        // Test that disallowing payload works
        let expected: Result<(String, bool)> =
            Err(Error::Io(std::io::Error::new(
                ErrorKind::NotFound,
                "Could not find action local_action_payload_shell.sh"
                    .to_string(),
            )));

        assert!(matches!(
            lookup_action(
                &payload_dir,
                &actions_dir,
                "local_action_payload_shell.sh",
                false
            ),
            expected,
        ));

        // Test non-existent action
        let expected: Result<(String, bool)> =
            Err(Error::Io(std::io::Error::new(
                ErrorKind::NotFound,
                "Could not find action local_action_non_existent".to_string(),
            )));

        assert!(matches!(
            lookup_action(
                &payload_dir,
                &actions_dir,
                "local_action_non_existent",
                true
            ),
            expected,
        ));
    }

    #[test]
    fn test_process_revocation() {
        let test_config = KeylimeConfig::default();

        let sig_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data/revocation.sig");
        let signature = fs::read_to_string(sig_path).unwrap(); //#[allow_ci]

        let message_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data/test_ok.json");
        let message = fs::read_to_string(message_path).unwrap(); //#[allow_ci]

        let body = json!({
            "msg": message,
            "signature": signature,
        });

        let cert_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data/test-cert.pem");

        let actions_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions");

        let work_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let tmpfs_dir = work_dir.join("tmpfs-dev");

        let result = process_revocation(
            body,
            &cert_path,
            &test_config.agent.secure_size,
            "",
            &actions_dir,
            test_config.agent.allow_payload_revocation_actions,
            &work_dir,
            &tmpfs_dir,
        );

        assert!(result.is_ok());
    }
}
