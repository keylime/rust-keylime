// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#[macro_use]
use actix_web::rt;
use crate::config::{AgentConfig, KeylimeConfig};
use crate::crypto;
use crate::error::*;
use crate::secure_mount;
use keylime::list_parser::parse_list;
use log::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    convert::TryInto,
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::Duration,
};
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
    time::sleep,
};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct Revocation {
    pub(crate) msg: String,
    pub(crate) signature: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub(crate) enum RevocationMessage {
    PayloadDecrypted,
    Revocation(Revocation),
    Shutdown,
}

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
/// * `config_actions` - Actions from the configuration file
/// * `actions_dir` - Location of the pre-installed actions
fn run_revocation_actions(
    json: Value,
    config_actions: Option<String>,
    actions_dir: &Path,
    allow_payload_actions: bool,
    work_dir: &Path,
    mount: &Path,
) -> Result<Vec<Output>> {
    // The actions from the configuration file takes precedence over the actions from the
    // actions_list file
    let actions = config_actions.unwrap_or_default();
    let mut action_list = parse_list(&actions)?;
    let action_data;
    let unzipped = mount.join("unzipped");
    let action_file = unzipped.join("action_list");

    if action_file.exists() {
        action_data = std::fs::read_to_string(&action_file)
            .expect("unable to read action_list");

        let file_actions = parse_list(&action_data)?;

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
                        action.to_string(),
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

/// Process revocation message received from REST API
fn process_revocation(
    revocation: Revocation,
    revocation_cert: &openssl::x509::X509,
    revocation_actions_dir: &Path,
    revocation_actions: Option<String>,
    allow_payload_revocation_actions: bool,
    work_dir: &Path,
    mount: &Path,
) -> Result<()> {
    let cert_key = revocation_cert.public_key()?;

    // Verify the message and signature with our key
    let mut verified = crypto::asym_verify(
        &cert_key,
        &revocation.msg,
        &revocation.signature,
    )?;

    if verified {
        let msg = revocation.msg.as_str();
        let msg_payload: Value = serde_json::from_str(msg)?;

        debug!(
            "Revocation signature validated for revocation: {}",
            msg_payload
        );

        let outputs = run_revocation_actions(
            msg_payload,
            revocation_actions,
            revocation_actions_dir,
            allow_payload_revocation_actions,
            work_dir,
            mount,
        )?;

        for output in outputs {
            if !output.stdout.is_empty() {
                let out = String::from_utf8(output.stdout)?;
                info!("Action stdout: {}", out);
            }
            if !output.stderr.is_empty() {
                let out = String::from_utf8(output.stderr)?;
                warn!("Action stderr: {}", out);
            }
        }
        Ok(())
    } else {
        error!("Invalid revocation message signature");
        Err(Error::InvalidRequest)
    }
}

pub(crate) async fn worker(
    mut revocation_rx: Receiver<RevocationMessage>,
    revocation_cert_path: impl AsRef<Path>,
    revocation_actions_dir: impl AsRef<Path>,
    revocation_actions: Option<String>,
    allow_payload_revocation_actions: bool,
    work_dir: impl AsRef<Path>,
    mount: impl AsRef<Path>,
) -> Result<()> {
    debug!("Starting revocation worker");

    let mut revocation_cert: Option<openssl::x509::X509> = None;

    // Receive message
    while let Some(message) = revocation_rx.recv().await {
        match message {
            RevocationMessage::Revocation(revocation) => {
                match &revocation_cert {
                    None => {
                        warn!("Revocation certificate not yet available");
                    }
                    Some(cert) => {
                        // Process revocation
                        match process_revocation(
                            revocation,
                            cert,
                            revocation_actions_dir.as_ref(),
                            revocation_actions.clone(),
                            allow_payload_revocation_actions,
                            work_dir.as_ref(),
                            mount.as_ref(),
                        ) {
                            Ok(_) => {
                                info!("Revocation processed successfully");
                            }
                            Err(e) => {
                                error!("Failed to process revocation: {}", e);
                            }
                        }
                    }
                }
            }
            RevocationMessage::PayloadDecrypted => {
                // The payload worker will send this message after decrypting and optionally
                // unzipping the payload
                let cert_absolute_path =
                    match revocation_cert_path.as_ref().canonicalize() {
                        Ok(path) => path,
                        Err(e) => {
                            error!("Certicate not available");
                            continue;
                        }
                    };

                info!(
                    "Loading the revocation certificate from {}",
                    cert_absolute_path.display()
                );

                revocation_cert = match crypto::load_x509(&cert_absolute_path)
                {
                    Ok(cert) => Some(cert),
                    Err(e) => None,
                };
            }
            RevocationMessage::Shutdown => {
                revocation_rx.close();
            }
        }
    }

    debug!("Shutting down revocation worker");
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
            Some("".to_string()),
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
            Some("".to_string()),
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
            Some(revocation_actions.to_string()),
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
        let msg = fs::read_to_string(message_path).unwrap(); //#[allow_ci]

        let revocation = Revocation { msg, signature };

        let cert_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data/test-cert.pem");

        let cert = crypto::load_x509(&cert_path).unwrap(); //#[allow_ci]

        let actions_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions");

        let work_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let tmpfs_dir = work_dir.join("tmpfs-dev");

        let result = process_revocation(
            revocation,
            &cert,
            &actions_dir,
            None,
            test_config.agent.allow_payload_revocation_actions,
            &work_dir,
            &tmpfs_dir,
        );

        assert!(result.is_ok());
    }
}
