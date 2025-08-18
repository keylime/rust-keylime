// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{
    revocation::{Revocation, RevocationMessage},
    Error, Result,
};

#[cfg(feature = "with-zmq")]
use crate::revocation::ZmqMessage;

use keylime::{
    config,
    crypto::{
        self,
        encrypted_data::EncryptedData,
        symmkey::{KeySet, SymmKey},
    },
    permissions,
};
use log::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fmt::Display,
    fs,
    io::{BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex},
};
use tokio::sync::mpsc::{Receiver, Sender};
use zip::ZipArchive;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct Payload {
    pub symm_key: SymmKey,
    pub encrypted_payload: EncryptedData,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub(crate) enum PayloadMessage {
    RunPayload(Payload),
    Shutdown,
}

impl Display for PayloadMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadMessage::RunPayload(_) => write!(f, "RunPayload"),
            PayloadMessage::Shutdown => write!(f, "Shutdown"),
        }
    }
}

// Parameters are based on Python codebase:
// https://github.com/keylime/keylime/blob/1ed43ac8f75d5c3bc3a3bbbbb5037f20cf3c5a6a/ \
// keylime/crypto.py#L189
fn decrypt_payload(
    symm_key: &SymmKey,
    encrypted_payload: EncryptedData,
) -> Result<Vec<u8>> {
    let decrypted =
        crypto::decrypt_aead(symm_key.as_ref(), encrypted_payload.as_ref())?;

    info!("Successfully decrypted payload");
    Ok(decrypted)
}

// sets up unzipped directory in secure mount location in preparation for
// writing out symmetric key and encrypted payload. returns file paths for
// both.
fn setup_unzipped(
    config: &config::AgentConfig,
    mount: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let unzipped = mount.join("unzipped");

    // clear any old data
    if Path::new(&unzipped).exists() {
        fs::remove_dir_all(&unzipped)?;
    }

    match config.dec_payload_file.as_ref() {
        "" => Err(config::KeylimeConfigError::RequiredOption(
            "dec_payload_path".to_string(),
        )
        .into()),
        p => {
            let dec_payload_path = unzipped.join(p);
            match config.enc_keyname.as_ref() {
                "" => Err(config::KeylimeConfigError::RequiredOption(
                    "enc_keyname".to_string(),
                )
                .into()),
                k => {
                    let key_path = unzipped.join(k);
                    fs::create_dir(&unzipped)?;
                    Ok((unzipped, dec_payload_path, key_path))
                }
            }
        }
    }
}

// write symm key data and decrypted payload data out to specified files
fn write_out_key_and_payload(
    dec_payload: &[u8],
    dec_payload_path: &Path,
    key: &SymmKey,
    key_path: &Path,
) -> Result<()> {
    let mut key_file = fs::File::create(key_path)?;
    let bytes = key_file.write(key.as_ref())?;
    if bytes != key.as_ref().len() {
        return Err(Error::Other(format!("Error writing symm key to {:?}: key len is {}, but {bytes} bytes were written", key_path, key.as_ref().len())));
    }
    info!("Wrote payload decryption key to {key_path:?}");

    let mut dec_payload_file = fs::File::create(dec_payload_path)?;
    let bytes = dec_payload_file.write(dec_payload)?;
    if bytes != dec_payload.len() {
        return Err(Error::Other(format!("Error writing decrypted payload to {:?}: payload len is {}, but {bytes} bytes were written", dec_payload_path, dec_payload.len())));
    }
    info!("Wrote decrypted payload to {dec_payload_path:?}");

    Ok(())
}

// run a script (such as the init script, if any) and check the status
fn run(dir: &Path, script: &str) -> Result<()> {
    let script_path = dir.join(script);
    info!("Running script: {script_path:?}");

    if !script_path.exists() {
        info!("No payload script {script} found in {}", dir.display());
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
    config: &config::AgentConfig,
) -> Result<()> {
    if config.extract_payload_zip {
        match config.dec_payload_file.as_ref() {
            "" => {
                warn!("Configuration option dec_payload_file not set, not unzipping payload");
            }
            dec_file => {
                let zipped_payload_path = unzipped.join(dec_file);

                info!("Unzipping payload {dec_file} to {unzipped:?}");

                let mut source = fs::File::open(zipped_payload_path)?;
                let mut zip = ZipArchive::new(source)?;
                zip.extract(unzipped)?;
            }
        }
    }

    Ok(())
}

async fn run_encrypted_payload(
    symm_key: SymmKey,
    payload: EncryptedData,
    config: &config::AgentConfig,
    mount: &Path,
    revocation_tx: Sender<RevocationMessage>,
    #[cfg(feature = "with-zmq")] zmq_tx: Sender<ZmqMessage>,
) -> Result<()> {
    let dec_payload = decrypt_payload(&symm_key, payload)?;

    let (unzipped, dec_payload_path, key_path) =
        setup_unzipped(config, mount)?;

    write_out_key_and_payload(
        &dec_payload,
        &dec_payload_path,
        &symm_key,
        &key_path,
    )?;

    optional_unzip_payload(&unzipped, config)?;
    // there may also be also a separate init script
    match config.payload_script.as_ref() {
        "" => {
            info!("No payload script specified, skipping");
        }
        script => {
            info!("Payload init script indicated: {script}");
            run(&unzipped, script)?;
        }
    }

    // Set execution permission for listed revocation actions
    let action_file = unzipped.join("action_list");

    if action_file.exists() {
        let action_data = fs::read_to_string(&action_file)
            .expect("unable to read action_list");

        action_data
            .split('\n')
            .filter(|&script| !script.is_empty())
            .map(|script| script.trim())
            .map(|script| unzipped.join(script))
            .filter(|script| script.exists())
            .try_for_each(|script| {
                match permissions::set_mode(&script, 0o700) {
                    Ok(()) => {
                        info!(
                            "Permission set for action: {}",
                            script.display()
                        );
                        Ok(())
                    }
                    Err(e) => {
                        error!(
                            "Could not set permission for action {}",
                            script.display()
                        );
                        Err(e)
                    }
                }
            })?
    }

    debug!("Sending PayloadDecrypted message to revocation worker");
    if let Err(e) = revocation_tx
        .send(RevocationMessage::PayloadDecrypted)
        .await
    {
        warn!("Failed to send PayloadDecrypted mesage to revocation worker");
    };

    #[cfg(feature = "with-zmq")]
    {
        debug!("Sending StartListening message to ZMQ worker");
        if let Err(e) = zmq_tx.send(ZmqMessage::StartListening).await {
            warn!("Failed to send StartListening mesage to ZMQ worker");
        };
    }

    Ok(())
}

pub(crate) async fn worker(
    config: config::AgentConfig,
    mount: impl AsRef<Path>,
    mut payload_rx: Receiver<PayloadMessage>,
    mut revocation_tx: Sender<RevocationMessage>,
    #[cfg(feature = "with-zmq")] mut zmq_tx: Sender<ZmqMessage>,
) -> Result<()> {
    debug!("Starting payloads worker");

    // Receive message
    while let Some(message) = payload_rx.recv().await {
        match message {
            PayloadMessage::Shutdown => {
                payload_rx.close();
            }
            PayloadMessage::RunPayload(run_payload) => {
                // The keys worker will send this message only if mTLS is enabled or
                // 'enable_insecure_payload' configuration option is set
                match run_encrypted_payload(
                    run_payload.symm_key,
                    run_payload.encrypted_payload,
                    &config,
                    mount.as_ref(),
                    revocation_tx.clone(),
                    #[cfg(feature = "with-zmq")]
                    zmq_tx.clone(),
                )
                .await
                {
                    Ok(_) => {
                        info!("Successfully executed encrypted payload");
                    }
                    Err(e) => {
                        warn!("Failed to run encrypted payload: {e:?}");
                    }
                }
            }
        }
    }

    debug!("Shutting down payloads worker");
    Ok(())
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{AES_128_KEY_LEN, AES_256_KEY_LEN},
        payloads,
    };
    use actix_rt::Arbiter;
    use keylime::config::AgentConfig;
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };
    use tokio::sync::mpsc;

    #[cfg(feature = "testing")]
    use crate::crypto::testing::{
        encrypt_aead, pkey_pub_from_pem, rsa_oaep_encrypt,
    };
    #[cfg(feature = "testing")]
    use keylime::config::get_testing_config;
    #[cfg(feature = "testing")]
    use std::sync::OnceLock;
    #[cfg(feature = "testing")]
    use tokio::sync::Mutex as AsyncMutex;

    #[cfg(feature = "testing")]
    pub static MUTEX: OnceLock<Arc<AsyncMutex<()>>> = OnceLock::new();

    // Enough length for testing both AES-128 and AES-256
    const U: &[u8; AES_256_KEY_LEN] = b"01234567890123456789012345678901";
    const V: &[u8; AES_256_KEY_LEN] = b"ABCDEFGHIJABCDEFGHIJABCDEFGHIJAB";

    fn setup_key(key_len: usize) -> SymmKey {
        let u: SymmKey = U[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let v: SymmKey = V[..key_len][..].try_into().unwrap(); //#[allow_ci]
        u.xor(&v).unwrap() //#[allow_ci]
    }

    #[cfg(feature = "testing")]
    fn setup_key_and_payload(key_len: usize) -> (SymmKey, EncryptedData) {
        let u: SymmKey = U[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let v: SymmKey = V[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let k = u.xor(&v).unwrap(); //#[allow_ci]

        let payload_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("payload.zip");

        let payload = fs::read(payload_path).expect("unable to read payload");

        let payload = {
            let iv = b"ABCDEFGHIJKLMNOP";
            encrypt_aead(k.as_ref(), &iv[..], payload.as_slice()).unwrap() //#[allow_ci]
        };
        (k, payload.into())
    }

    #[actix_rt::test]
    async fn test_run() {
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
        )
        .unwrap(); //#[allow_ci]
        assert!(dir.path().join("test-output").exists());
    }

    #[cfg(feature = "testing")]
    #[test]
    fn test_decrypt_payload() {
        let (k, payload) = setup_key_and_payload(AES_128_KEY_LEN);
        let result = decrypt_payload(&k, payload);
        assert!(result.is_ok());
    }

    #[cfg(feature = "testing")]
    #[test]
    fn test_setup_unzipped() {
        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let test_config = get_testing_config(temp_workdir.path(), None);
        let secure_mount =
            PathBuf::from(&temp_workdir.path().join("tmpfs-dev"));
        fs::create_dir(&secure_mount).unwrap(); //#[allow_ci]
        let result = setup_unzipped(&test_config, &secure_mount);
        assert!(result.is_ok());
        let (unzipped, dec_payload_path, key_path) = result.unwrap(); //#[allow_ci]
        assert!(unzipped.exists());
        assert!(
            dec_payload_path == unzipped.join(test_config.dec_payload_file)
        );
        assert!(key_path == unzipped.join(test_config.enc_keyname));
    }

    #[test]
    fn test_write_out_key_and_payload() {
        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let k = setup_key(AES_128_KEY_LEN);
        let payload = b"Testing";
        let result = write_out_key_and_payload(
            payload,
            &temp_workdir.path().join("dec_payload"),
            &k,
            &temp_workdir.path().join("key"),
        );

        assert!(result.is_ok());
    }

    #[cfg(feature = "testing")]
    #[test]
    fn test_unzip_payload() {
        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let test_config = get_testing_config(temp_workdir.path(), None);
        let payload_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("payload.zip");

        let dec_payload_file = match test_config.dec_payload_file.as_ref() {
            "" => panic!("dec_payload_file not set by default"), //#[allow_ci]
            f => f,
        };

        let result = fs::copy(
            payload_path,
            temp_workdir.path().join(dec_payload_file),
        );
        assert!(result.is_ok());

        let dec_payload_path = temp_workdir.path().join(dec_payload_file);
        assert!(dec_payload_path.exists());

        let result =
            optional_unzip_payload(temp_workdir.path(), &test_config);
        assert!(result.is_ok());
        assert!(temp_workdir.path().join("autorun.sh").exists());
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn test_run_encrypted_payload() {
        let _mutex = MUTEX
            .get_or_init(|| Arc::new(AsyncMutex::new(())))
            .lock()
            .await;
        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let test_config = get_testing_config(temp_workdir.path(), None);
        let secure_mount =
            PathBuf::from(&temp_workdir.path().join("tmpfs-dev"));
        fs::create_dir(&secure_mount).unwrap(); //#[allow_ci]
        env::set_var("KEYLIME_TEST_DIR", temp_workdir.path());

        let (mut revocation_tx, mut revocation_rx) =
            mpsc::channel::<RevocationMessage>(1);

        #[cfg(feature = "with-zmq")]
        let (mut zmq_tx, mut zmq_rx) = mpsc::channel::<ZmqMessage>(1);

        let (k, payload) = setup_key_and_payload(AES_128_KEY_LEN);

        run_encrypted_payload(
            k,
            payload,
            &test_config,
            &secure_mount,
            revocation_tx,
            #[cfg(feature = "with-zmq")]
            zmq_tx,
        )
        .await;

        let msg = revocation_rx.recv().await;
        assert!(msg == Some(RevocationMessage::PayloadDecrypted));
        revocation_rx.close();

        #[cfg(feature = "with-zmq")]
        {
            let msg = zmq_rx.recv().await;
            assert!(msg == Some(ZmqMessage::StartListening));
            zmq_rx.close();
        }

        let timestamp_path = temp_workdir.path().join("timestamp");
        assert!(timestamp_path.exists());
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn test_payload_worker() {
        let _mutex = MUTEX
            .get_or_init(|| Arc::new(AsyncMutex::new(())))
            .lock()
            .await;
        use crate::{config::DEFAULT_PAYLOAD_SCRIPT, secure_mount};

        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let test_config = get_testing_config(temp_workdir.path(), None);
        let secure_mount =
            PathBuf::from(&temp_workdir.path().join("tmpfs-dev"));
        fs::create_dir(&secure_mount).unwrap(); //#[allow_ci]
        env::set_var("KEYLIME_TEST_DIR", temp_workdir.path());

        let (k, payload) = setup_key_and_payload(AES_128_KEY_LEN);

        let (mut payload_tx, mut payload_rx) =
            mpsc::channel::<PayloadMessage>(1);

        let (mut revocation_tx, mut revocation_rx) =
            mpsc::channel::<RevocationMessage>(1);

        #[cfg(feature = "with-zmq")]
        let (mut zmq_tx, mut zmq_rx) = mpsc::channel::<ZmqMessage>(1);

        let script = PathBuf::from(
            &secure_mount.join(format!("unzipped/{DEFAULT_PAYLOAD_SCRIPT}")),
        );

        let arbiter = Arbiter::new();
        assert!(arbiter.spawn(Box::pin(async move {
            let result = worker(
                test_config,
                secure_mount,
                payload_rx,
                revocation_tx,
                #[cfg(feature = "with-zmq")]
                zmq_tx,
            )
            .await;

            if result.is_err() {
                debug!("payloads worker failed: {result:?}");
            }

            let timestamp_path = temp_workdir.path().join("timestamp");
            assert!(timestamp_path.exists());

            if !Arbiter::current().stop() {
                debug!("couldn't stop current arbiter");
            }
        })));

        let run_payload = Payload {
            symm_key: k,
            encrypted_payload: payload,
        };

        let result = payload_tx
            .send(PayloadMessage::RunPayload(run_payload))
            .await;
        assert!(result.is_ok());

        let msg = revocation_rx.recv().await;
        assert!(msg == Some(RevocationMessage::PayloadDecrypted));
        revocation_rx.close();

        #[cfg(feature = "with-zmq")]
        {
            let msg = zmq_rx.recv().await;
            assert!(msg == Some(ZmqMessage::StartListening));
            zmq_rx.close();
        }

        let result = payload_tx.send(PayloadMessage::Shutdown).await;
        assert!(result.is_ok());

        arbiter.join();
    }
}
