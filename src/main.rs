// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    while_true,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
// Temporarily allow these until they can be fixed
//  unused: there is a lot of code that's for now unused because this codebase is still in development
//  missing_docs: there is many functions missing documentations for now
#![allow(unused, missing_docs)]

mod algorithms;
mod common;
mod crypto;
mod error;
mod ima;
mod keys_handler;
mod notifications_handler;
mod quotes_handler;
mod registrar_agent;
mod revocation;
mod secure_mount;
mod serialization;
mod tpm;
mod version_handler;

use actix_web::{dev::Service, middleware, web, App, HttpServer};
use clap::{App as ClapApp, Arg};
use common::*;
use compress_tools::*;
use error::{Error, Result};
use futures::{future::TryFutureExt, try_join};
use ima::ImaMeasurementList;
use log::*;
use openssl::pkey::{PKey, Private, Public};
use std::{
    convert::TryFrom,
    fs,
    io::{BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};
use tss_esapi::{
    handles::KeyHandle, interface_types::algorithm::AsymmetricAlgorithm,
    Context,
};
use uuid::Uuid;

#[macro_use]
extern crate static_assertions;

static NOTFOUND: &[u8] = b"Not Found";

// This data is passed in to the actix httpserver threads that
// handle quotes.
#[derive(Debug)]
pub struct QuoteData {
    tpmcontext: Mutex<Context>,
    priv_key: PKey<Private>,
    pub_key: PKey<Public>,
    ak_handle: KeyHandle,
    ukeys: Mutex<KeySet>,
    vkeys: Mutex<KeySet>,
    payload_symm_key: Arc<Mutex<Option<SymmKey>>>,
    payload_symm_key_cvar: Arc<Condvar>,
    encr_payload: Arc<Mutex<Vec<u8>>>,
    auth_tag: Mutex<[u8; AUTH_TAG_LEN]>,
    hash_alg: algorithms::HashAlgorithm,
    enc_alg: algorithms::EncryptionAlgorithm,
    sign_alg: algorithms::SignAlgorithm,
    agent_uuid: String,
    revocation_cert: PathBuf,
    revocation_actions: String,
    revocation_actions_dir: PathBuf,
    allow_payload_revocation_actions: bool,
    secure_size: String,
    work_dir: PathBuf,
    ima_ml_path: PathBuf,
    measuredboot_ml_path: PathBuf,
    ima_ml: Mutex<ImaMeasurementList>,
}

// Parameters are based on Python codebase:
// https://github.com/keylime/keylime/blob/1ed43ac8f75d5c3bc3a3bbbbb5037f20cf3c5a6a/ \
// keylime/crypto.py#L189
pub(crate) fn decrypt_payload(
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
pub(crate) fn setup_unzipped(
    config: &KeylimeConfig,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let work_dir = Path::new(&config.work_dir);
    let mount = secure_mount::mount(work_dir, &config.secure_size)?;
    let unzipped = mount.join("unzipped");

    // clear any old data
    if Path::new(&unzipped).exists() {
        fs::remove_dir_all(&unzipped)?;
    }

    let dec_payload_path = unzipped.join(&config.dec_payload_filename);
    let key_path = unzipped.join(&config.key_filename);

    fs::create_dir(&unzipped)?;

    Ok((unzipped, dec_payload_path, key_path))
}

// write symm key data and decrypted payload data out to specified files
pub(crate) fn write_out_key_and_payload(
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
pub(crate) fn run(dir: &Path, script: &str, agent_uuid: &str) -> Result<()> {
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

// checks if keylime.conf indicates the payload should be unzipped, and does so if needed.
// the input string is the directory where the unzipped file(s) should be stored.
pub(crate) fn optional_unzip_payload(
    unzipped: &Path,
    config: &KeylimeConfig,
) -> Result<()> {
    if config.extract_payload_zip {
        let zipped_payload = &config.dec_payload_filename;
        let zipped_payload_path = unzipped.join(zipped_payload);

        info!("Unzipping payload {} to {:?}", &zipped_payload, unzipped);

        let mut source = fs::File::open(&zipped_payload_path)?;
        uncompress_archive(&mut source, unzipped, Ownership::Preserve)?;
    }

    Ok(())
}

pub(crate) async fn run_encrypted_payload(
    symm_key: Arc<Mutex<Option<SymmKey>>>,
    symm_key_cvar: Arc<Condvar>,
    payload: Arc<Mutex<Vec<u8>>>,
    config: &KeylimeConfig,
) -> Result<()> {
    // do nothing until actix server's handlers have updated the symmetric key
    let mut key = symm_key.lock().unwrap(); //#[allow_ci]
    while key.is_none() {
        key = symm_key_cvar.wait(key).unwrap(); //#[allow_ci]
    }

    let key = key.as_ref().unwrap(); //#[allow_ci]
    let dec_payload = decrypt_payload(payload, key)?;

    let (unzipped, dec_payload_path, key_path) = setup_unzipped(config)?;

    write_out_key_and_payload(
        &dec_payload,
        &dec_payload_path,
        key,
        &key_path,
    )?;

    optional_unzip_payload(&unzipped, config)?;

    // there may also be also a separate init script
    match config.payload_script.as_str() {
        "" => {
            info!("No payload script specified, skipping");
        }
        script => {
            info!("Payload init script indicated: {}", script);
            run(&unzipped, script, config.agent_uuid.as_str())?;
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

async fn worker(
    symm_key: Arc<Mutex<Option<SymmKey>>>,
    symm_key_cvar: Arc<Condvar>,
    payload: Arc<Mutex<Vec<u8>>>,
    config: &KeylimeConfig,
) -> Result<()> {
    run_encrypted_payload(symm_key, symm_key_cvar, payload, config).await?;

    // If with-zmq feature is enabled, run the service listening for ZeroMQ messages
    #[cfg(feature = "with-zmq")]
    if config.run_revocation {
        return revocation::run_revocation_service(config).await;
    }

    Ok(())
}

#[actix_web::main]
async fn main() -> Result<()> {
    // Print --help information
    let matches = ClapApp::new("keylime_agent")
        .about("A Rust implementation of the Keylime agent")
        .override_usage(
            "sudo RUST_LOG=keylime_agent=trace ./target/debug/keylime_agent",
        )
        .get_matches();

    pretty_env_logger::init();
    let mut ctx = tpm::get_tpm2_ctx()?;

    //  Retrieve the TPM Vendor, this allows us to warn if someone is using a
    // Software TPM ("SW")
    if tss_esapi::utils::get_tpm_vendor(&mut ctx)?.contains("SW") {
        warn!("INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.");
        warn!("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.");
        warn!("INSECURE: Only use Keylime in this mode for testing or debugging purposes.");
    }

    info!("Starting server with API version {}...", API_VERSION);

    // Load config
    let config = KeylimeConfig::build()?;

    // Verify if the python shim is installed in the expected location
    let python_shim =
        PathBuf::from(&config.revocation_actions_dir).join("shim.py");
    if !python_shim.exists() {
        error!("Could not find python shim at {}", python_shim.display());
        return Err(Error::Configuration(format!(
            "Could not find python shim at {}",
            python_shim.display()
        )));
    }

    // Gather EK values and certs
    let (ek_handle, ek_cert, ek_tpm2b_pub) =
        tpm::create_ek(&mut ctx, config.enc_alg.into())?;

    // Try to load persistent TPM data
    let tpm_data = config.tpm_data.clone().and_then(|data|
        match data.valid(config.hash_alg, config.sign_alg) {
            true => Some(data),
            false => {
                warn!(
                    "Not using old {} because it is not valid with current configuration",
                    TPM_DATA
                );
                None
            },
        }
    );

    // Try to reuse old AK from TpmData
    let old_ak = tpm_data.and_then(|data| {
        match tpm::load_ak(&mut ctx, data.ak_context) {
            Ok(ak_data) => {
                info!("Loaded old AK context from {}", TPM_DATA);
                Some(ak_data)
            }
            Err(e) => {
                warn!(
                    "Loading old AK context from {} failed: {}",
                    TPM_DATA, e
                );
                None
            }
        }
    });

    // Use old AK or generate a new one and update the TpmData
    let (ak_handle, ak_name, ak_tpm2b_pub) = match old_ak {
        Some(data) => data,
        None => {
            info!("Generating new AK");
            let new_ak = tpm::create_ak(
                &mut ctx,
                ek_handle,
                config.hash_alg.into(),
                config.sign_alg.into(),
            )?;
            // Only updating tpmdata.json if a new AK was used
            info!("Storing updated TPM data in {}", TPM_DATA);
            TpmData {
                ak_hash_alg: config.hash_alg,
                ak_sign_alg: config.sign_alg,
                ak_context: tpm::store_ak(&mut ctx, new_ak.0)?,
            }
            .store(Path::new(&config.tpm_data_path))?;
            new_ak
        }
    };

    info!("Agent UUID: {}", config.agent_uuid);

    // Generate key pair for secure transmission of u, v keys. The u, v
    // keys are two halves of the key used to decrypt the workload after
    // the Identity and Integrity Quotes sent by the agent are validated
    // by the Tenant and Cloud Verifier, respectively.
    //
    // Since we store the u key in memory, discarding this key, which
    // safeguards u and v keys in transit, is not part of the threat model.
    let (nk_pub, nk_priv) = crypto::rsa_generate_pair(2048)?;

    let mtls_cert = crypto::generate_x509(&nk_priv, &config.agent_uuid)?;

    {
        // Request keyblob material
        let keyblob = registrar_agent::do_register_agent(
            &config.registrar_ip,
            &config.registrar_port,
            &config.agent_uuid,
            &ek_tpm2b_pub,
            ek_cert,
            &ak_tpm2b_pub,
            &mtls_cert,
            config.agent_contact_ip.clone(),
            config.agent_contact_port,
        )
        .await?;
        info!("SUCCESS: Agent {} registered", config.agent_uuid);

        let key = tpm::activate_credential(
            &mut ctx, keyblob, ak_handle, ek_handle,
        )?;
        let mackey = base64::encode(key.value());
        let auth_tag = crypto::compute_hmac(
            mackey.as_bytes(),
            config.agent_uuid.as_bytes(),
        )?;
        let auth_tag = hex::encode(&auth_tag);

        registrar_agent::do_activate_agent(
            &config.registrar_ip,
            &config.registrar_port,
            &config.agent_uuid,
            &auth_tag,
        )
        .await?;
        info!("SUCCESS: Agent {} activated", config.agent_uuid);
    }

    let keylime_ca_cert =
        crypto::load_x509(Path::new(&config.keylime_ca_path))?;
    let ssl_context =
        crypto::generate_mtls_context(&mtls_cert, &nk_priv, keylime_ca_cert)?;

    let mut encr_payload = Vec::new();

    let symm_key_arc = Arc::new(Mutex::new(None));
    let symm_key_cvar_arc = Arc::new(Condvar::new());
    let encr_payload_arc = Arc::new(Mutex::new(encr_payload));

    // these allow the arrays to be referenced later in this thread
    let symm_key = Arc::clone(&symm_key_arc);
    let symm_key_cvar = Arc::clone(&symm_key_cvar_arc);
    let payload = Arc::clone(&encr_payload_arc);

    let revocation_cert = revocation::get_revocation_cert_path(&config)?;
    let actions_dir =
        Path::new(&config.revocation_actions_dir).canonicalize()?;
    let work_dir = Path::new(&config.work_dir).canonicalize()?;
    let ima_ml_path = Path::new(&config.ima_ml_path).to_path_buf();
    let measuredboot_ml_path =
        Path::new(&config.measuredboot_ml_path).to_path_buf();

    let quotedata = web::Data::new(QuoteData {
        tpmcontext: Mutex::new(ctx),
        priv_key: nk_priv,
        pub_key: nk_pub,
        ak_handle,
        ukeys: Mutex::new(KeySet::default()),
        vkeys: Mutex::new(KeySet::default()),
        payload_symm_key: symm_key_arc,
        payload_symm_key_cvar: symm_key_cvar_arc,
        encr_payload: encr_payload_arc,
        auth_tag: Mutex::new([0u8; AUTH_TAG_LEN]),
        hash_alg: config.hash_alg,
        enc_alg: config.enc_alg,
        sign_alg: config.sign_alg,
        agent_uuid: config.agent_uuid.clone(),
        revocation_cert,
        revocation_actions: config.revocation_actions.clone(),
        revocation_actions_dir: actions_dir,
        allow_payload_revocation_actions: config
            .allow_payload_revocation_actions,
        secure_size: config.secure_size.clone(),
        work_dir,
        ima_ml_path,
        measuredboot_ml_path,
        ima_ml: Mutex::new(ImaMeasurementList::new()),
    });

    let actix_server =
        HttpServer::new(move || {
            App::new()
                .wrap(middleware::Logger::new(
                    "%r from %a result %s (took %D ms)",
                ))
                .wrap_fn(|req, srv| {
                    info!(
                        "{} invoked from {:?} with uri {}",
                        req.head().method,
                        req.connection_info().remote_addr().unwrap(), //#[allow_ci]
                        req.uri()
                    );
                    srv.call(req)
                })
                .app_data(quotedata.clone())
                .service(
                    web::scope(&format!("/{}", API_VERSION))
                        .service(
                            web::scope("/keys")
                                .service(web::resource("/pubkey").route(
                                    web::get().to(keys_handler::pubkey),
                                ))
                                .service(web::resource("/ukey").route(
                                    web::post().to(keys_handler::u_key),
                                ))
                                .service(web::resource("/verify").route(
                                    web::get().to(keys_handler::verify),
                                ))
                                .service(web::resource("/vkey").route(
                                    web::post().to(keys_handler::v_key),
                                )),
                        )
                        .service(
                            web::scope("/notifications").service(
                                web::resource("/revocation").route(
                                    web::post().to(
                                        notifications_handler::revocation,
                                    ),
                                ),
                            ),
                        )
                        .service(
                            web::scope("/quotes")
                                .service(web::resource("/identity").route(
                                    web::get().to(quotes_handler::identity),
                                ))
                                .service(web::resource("/integrity").route(
                                    web::get().to(quotes_handler::integrity),
                                )),
                        ),
                )
                .service(
                    web::resource("/version")
                        .route(web::get().to(version_handler::version)),
                )
        })
        .bind_openssl(
            format!("{}:{}", config.agent_ip, config.agent_port),
            ssl_context,
        )?
        .run()
        .map_err(Error::from);
    info!(
        "Listening on https://{}:{}",
        config.agent_ip, config.agent_port
    );

    try_join!(
        worker(symm_key, symm_key_cvar, payload, &config),
        actix_server
    )?;

    Ok(())
}

/*
 * Input: file path
 * Output: file content
 *
 * Helper function to help the keylime agent read file and get the file
 * content. It is not from the original python version. Because rust needs
 * to handle error in result, it is good to keep this function separate from
 * the main function.
 */
fn read_in_file(path: String) -> std::io::Result<String> {
    let file = fs::File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    let _ = buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(feature = "testing")]
mod testing {
    use super::*;

    impl QuoteData {
        pub(crate) fn fixture() -> Result<Self> {
            let test_config = KeylimeConfig::default();
            let mut ctx = tpm::get_tpm2_ctx()?;

            // Gather EK and AK key values and certs
            let (ek_handle, ek_cert, ek_tpm2b_pub) =
                tpm::create_ek(&mut ctx, test_config.enc_alg.into())?;

            let (ak_handle, ak_name, ak_tpm2b_pub) = tpm::create_ak(
                &mut ctx,
                ek_handle,
                test_config.hash_alg.into(),
                test_config.sign_alg.into(),
            )?;

            let rsa_key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data")
                .join("test-rsa.pem");

            let (nk_pub, nk_priv) =
                crypto::testing::rsa_import_pair(&rsa_key_path)?;

            let mut encr_payload = Vec::new();

            let symm_key_arc = Arc::new(Mutex::new(None));
            let symm_key_cvar_arc = Arc::new(Condvar::new());
            let encr_payload_arc = Arc::new(Mutex::new(encr_payload));

            // these allow the arrays to be referenced later in this thread
            let symm_key = Arc::clone(&symm_key_arc);
            let symm_key_cvar = Arc::clone(&symm_key_cvar_arc);
            let payload = Arc::clone(&encr_payload_arc);

            let revocation_cert =
                revocation::get_revocation_cert_path(&test_config)?;

            let actions_dir =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions/");

            let work_dir =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");

            let ima_ml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data/ima/ascii_runtime_measurements");

            let measuredboot_ml_path = Path::new(
                "/sys/kernel/security/tpm0/binary_bios_measurements",
            );

            Ok(QuoteData {
                tpmcontext: Mutex::new(ctx),
                priv_key: nk_priv,
                pub_key: nk_pub,
                ak_handle,
                ukeys: Mutex::new(KeySet::default()),
                vkeys: Mutex::new(KeySet::default()),
                payload_symm_key: symm_key_arc,
                payload_symm_key_cvar: symm_key_cvar_arc,
                encr_payload: encr_payload_arc,
                auth_tag: Mutex::new([0u8; AUTH_TAG_LEN]),
                hash_alg: algorithms::HashAlgorithm::Sha256,
                enc_alg: algorithms::EncryptionAlgorithm::Rsa,
                sign_alg: algorithms::SignAlgorithm::RsaSsa,
                agent_uuid: test_config.agent_uuid,
                revocation_cert,
                revocation_actions: String::from(""),
                revocation_actions_dir: actions_dir,
                allow_payload_revocation_actions: test_config
                    .allow_payload_revocation_actions,
                secure_size: test_config.secure_size,
                work_dir,
                ima_ml_path,
                measuredboot_ml_path: measuredboot_ml_path.to_path_buf(),
                ima_ml: Mutex::new(ImaMeasurementList::new()),
            })
        }
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    fn init_logger() {
        pretty_env_logger::init();
        info!("Initialized logger for testing suite.");
    }

    #[test]
    fn test_read_in_file() {
        assert_eq!(
            read_in_file("test-data/test_input.txt".to_string())
                .expect("File doesn't exist"),
            String::from("Hello World!\n")
        );
    }

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
