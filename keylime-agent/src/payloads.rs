// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{common::SymmKey, config, crypto, Error, Result};
use compress_tools::*;
use log::*;
use std::{
    fs,
    io::{BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex},
};

// Parameters are based on Python codebase:
// https://github.com/keylime/keylime/blob/1ed43ac8f75d5c3bc3a3bbbbb5037f20cf3c5a6a/ \
// keylime/crypto.py#L189
fn decrypt_payload(
    encr: Arc<Mutex<Vec<u8>>>,
    symm_key: &SymmKey,
) -> Result<Vec<u8>> {
    let payload = encr.lock().unwrap(); //#[allow_ci]

    let decrypted = crypto::decrypt_aead(symm_key.bytes(), &payload)?;

    info!("Successfully decrypted payload");
    Ok(decrypted)
}

// sets up unzipped directory in secure mount location in preparation for
// writing out symmetric key and encrypted payload. returns file paths for
// both.
fn setup_unzipped(
    config: &config::KeylimeConfig,
    mount: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let unzipped = mount.join("unzipped");

    // clear any old data
    if Path::new(&unzipped).exists() {
        fs::remove_dir_all(&unzipped)?;
    }

    let dec_payload_path = unzipped.join(&config.agent.dec_payload_file);
    let key_path = unzipped.join(&config.agent.enc_keyname);

    fs::create_dir(&unzipped)?;

    Ok((unzipped, dec_payload_path, key_path))
}

// write symm key data and decrypted payload data out to specified files
fn write_out_key_and_payload(
    dec_payload: &[u8],
    dec_payload_path: &Path,
    key: &SymmKey,
    key_path: &Path,
) -> Result<()> {
    let mut key_file = fs::File::create(key_path)?;
    let bytes = key_file.write(key.bytes())?;
    if bytes != key.bytes().len() {
        return Err(Error::Other(format!("Error writing symm key to {:?}: key len is {}, but {} bytes were written", key_path, key.bytes().len(), bytes)));
    }
    info!("Wrote payload decryption key to {:?}", key_path);

    let mut dec_payload_file = fs::File::create(dec_payload_path)?;
    let bytes = dec_payload_file.write(dec_payload)?;
    if bytes != dec_payload.len() {
        return Err(Error::Other(format!("Error writing decrypted payload to {:?}: payload len is {}, but {} bytes were written", dec_payload_path, dec_payload.len(), bytes)));
    }
    info!("Wrote decrypted payload to {:?}", dec_payload_path);

    Ok(())
}

// run a script (such as the init script, if any) and check the status
fn run(dir: &Path, script: &str, uuid: &str) -> Result<()> {
    let script_path = dir.join(script);
    info!("Running script: {:?}", script_path);

    if !script_path.exists() {
        info!("No payload script {} found in {}", script, dir.display());
        return Ok(());
    }

    if fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .is_err()
    {
        return Err(Error::Other(format!(
            "unable to set {:?} as executable",
            &script_path
        )));
    }

    info!("Executing payload script: {}", script_path.display());

    match Command::new("sh")
        .arg("-c")
        .arg(script_path.to_str().unwrap()) //#[allow_ci]
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
    {
        Ok(_) => {
            info!("{:?} ran successfully", &script_path);
            Ok(())
        }
        Err(e) => Err(Error::Other(format!(
            "{:?} failed during run: {}",
            &script_path, e
        ))),
    }
}

// checks if keylime-agent.conf indicates the payload should be unzipped, and does so if needed.
// the input string is the directory where the unzipped file(s) should be stored.
fn optional_unzip_payload(
    unzipped: &Path,
    config: &config::KeylimeConfig,
) -> Result<()> {
    if config.agent.extract_payload_zip {
        let zipped_payload = &config.agent.dec_payload_file;
        let zipped_payload_path = unzipped.join(zipped_payload);

        info!("Unzipping payload {} to {:?}", &zipped_payload, unzipped);

        let mut source = fs::File::open(zipped_payload_path)?;
        uncompress_archive(&mut source, unzipped, Ownership::Ignore)?;
    }

    Ok(())
}

async fn run_encrypted_payload(
    symm_key: Arc<Mutex<Option<SymmKey>>>,
    symm_key_cvar: Arc<Condvar>,
    payload: Arc<Mutex<Vec<u8>>>,
    config: &config::KeylimeConfig,
    mount: &Path,
) -> Result<()> {
    // do nothing until actix server's handlers have updated the symmetric key
    let mut key = symm_key.lock().unwrap(); //#[allow_ci]
    while key.is_none() {
        key = symm_key_cvar.wait(key).unwrap(); //#[allow_ci]
    }

    let key = key.as_ref().unwrap(); //#[allow_ci]
    let dec_payload = decrypt_payload(payload, key)?;

    let (unzipped, dec_payload_path, key_path) =
        setup_unzipped(config, mount)?;

    write_out_key_and_payload(
        &dec_payload,
        &dec_payload_path,
        key,
        &key_path,
    )?;

    optional_unzip_payload(&unzipped, config)?;
    // there may also be also a separate init script
    match config.agent.payload_script.as_str() {
        "" => {
            info!("No payload script specified, skipping");
        }
        script => {
            info!("Payload init script indicated: {}", script);
            run(&unzipped, script, config.agent.uuid.as_str())?;
        }
    }

    // Set execution permission for listed revocation actions
    let action_file = unzipped.join("action_list");

    if action_file.exists() {
        let action_data = std::fs::read_to_string(&action_file)
            .expect("unable to read action_list");

        action_data
            .split('\n')
            .filter(|&script| !script.is_empty())
            .map(|script| script.trim())
            .map(|script| unzipped.join(script))
            .filter(|script| script.exists())
            .try_for_each(|script| {
                if fs::set_permissions(
                    &script,
                    fs::Permissions::from_mode(0o700),
                )
                .is_err()
                {
                    error!(
                        "Could not set permission for action {}",
                        script.display()
                    );
                    Err(Error::Permission)
                } else {
                    info!("Permission set for action: {}", script.display());
                    Ok(())
                }
            })?
    }

    Ok(())
}

pub(crate) async fn worker(
    symm_key: Arc<Mutex<Option<SymmKey>>>,
    symm_key_cvar: Arc<Condvar>,
    payload: Arc<Mutex<Vec<u8>>>,
    config: config::KeylimeConfig,
    mount: impl AsRef<Path>,
) -> Result<()> {
    // Only run payload scripts if mTLS is enabled or 'enable_insecure_payload' option is set
    if config.agent.enable_agent_mtls || config.agent.enable_insecure_payload
    {
        run_encrypted_payload(
            symm_key,
            symm_key_cvar,
            payload,
            &config,
            mount.as_ref(),
        )
        .await?;
    } else {
        warn!("agent mTLS is disabled, and unless 'enable_insecure_payload' is set to 'True', payloads cannot be deployed'");
    }

    Ok(())
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run() {
        let dir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let script_path = dir.path().join("test-script.sh");
        {
            let mut script_file = fs::File::create(&script_path).unwrap(); //#[allow_ci]
            let script = r#"
#!/bin/sh

echo hello > test-output
"#;
            let _ = script_file.write(script.as_bytes()).unwrap(); //#[allow_ci]
        }
        run(
            dir.path(),
            script_path.file_name().unwrap().to_str().unwrap(), //#[allow_ci]
            "D432FBB3-D2F1-4A97-9EF7-75BD81C0000X",
        )
        .unwrap(); //#[allow_ci]
        assert!(dir.path().join("test-output").exists());
    }
}
