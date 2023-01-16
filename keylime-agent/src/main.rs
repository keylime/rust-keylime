// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#![deny(
    nonstandard_style,
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

mod common;
mod config;
mod crypto;
mod error;
mod errors_handler;
mod keys_handler;
mod notifications_handler;
mod permissions;
mod quotes_handler;
mod registrar_agent;
mod revocation;
mod secure_mount;
mod serialization;
mod version_handler;

use actix_web::{dev::Service, http, middleware, rt, web, App, HttpServer};
use clap::{Arg, Command as ClapApp};
use common::*;
use compress_tools::*;
use error::{Error, Result};
use futures::{future::TryFutureExt, try_join};
use keylime::ima::MeasurementList;
use keylime::tpm;
use log::*;
use openssl::{
    pkey::{PKey, Private, Public},
    x509::X509,
};
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
    handles::KeyHandle,
    interface_types::algorithm::AsymmetricAlgorithm,
    interface_types::resource_handles::Hierarchy,
    structures::{Auth, PublicBuffer},
    traits::Marshall,
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
    tpmcontext: Mutex<tpm::Context>,
    priv_key: PKey<Private>,
    pub_key: PKey<Public>,
    ak_handle: KeyHandle,
    ukeys: Mutex<KeySet>,
    vkeys: Mutex<KeySet>,
    payload_symm_key: Arc<Mutex<Option<SymmKey>>>,
    payload_symm_key_cvar: Arc<Condvar>,
    encr_payload: Arc<Mutex<Vec<u8>>>,
    auth_tag: Mutex<[u8; AUTH_TAG_LEN]>,
    hash_alg: keylime::algorithms::HashAlgorithm,
    enc_alg: keylime::algorithms::EncryptionAlgorithm,
    sign_alg: keylime::algorithms::SignAlgorithm,
    agent_uuid: String,
    revocation_cert: Option<PathBuf>,
    revocation_actions: Option<String>,
    revocation_actions_dir: Option<PathBuf>,
    allow_payload_revocation_actions: bool,
    secure_size: String,
    work_dir: PathBuf,
    ima_ml_file: Option<Mutex<fs::File>>,
    measuredboot_ml_file: Option<Mutex<fs::File>>,
    ima_ml: Mutex<MeasurementList>,
    secure_mount: PathBuf,
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
pub(crate) fn run(dir: &Path, script: &str, uuid: &str) -> Result<()> {
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
pub(crate) fn optional_unzip_payload(
    unzipped: &Path,
    config: &config::KeylimeConfig,
) -> Result<()> {
    if config.agent.extract_payload_zip {
        let zipped_payload = &config.agent.dec_payload_file;
        let zipped_payload_path = unzipped.join(zipped_payload);

        info!("Unzipping payload {} to {:?}", &zipped_payload, unzipped);

        let mut source = fs::File::open(&zipped_payload_path)?;
        uncompress_archive(&mut source, unzipped, Ownership::Ignore)?;
    }

    Ok(())
}

pub(crate) async fn run_encrypted_payload(
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

async fn worker(
    symm_key: Arc<Mutex<Option<SymmKey>>>,
    symm_key_cvar: Arc<Condvar>,
    payload: Arc<Mutex<Vec<u8>>>,
    config: config::KeylimeConfig,
    mount: PathBuf,
) -> Result<()> {
    // Only run payload scripts if mTLS is enabled or 'enable_insecure_payload' option is set
    if config.agent.enable_agent_mtls || config.agent.enable_insecure_payload
    {
        run_encrypted_payload(
            symm_key,
            symm_key_cvar,
            payload,
            &config,
            &mount,
        )
        .await?;
    } else {
        warn!("agent mTLS is disabled, and unless 'enable_insecure_payload' is set to 'True', payloads cannot be deployed'");
    }

    // If with-zmq feature is enabled, run the service listening for ZeroMQ messages
    #[cfg(feature = "with-zmq")]
    if config.agent.enable_revocation_notifications {
        return revocation::run_revocation_service(&config, &mount).await;
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

    let ima_ml_path = ima_ml_path_get();
    let ima_ml_file = if ima_ml_path.exists() {
        match fs::File::open(&ima_ml_path) {
            Ok(file) => Some(Mutex::new(file)),
            Err(e) => {
                warn!(
                    "IMA measurement list not accessible: {}",
                    ima_ml_path.display()
                );
                None
            }
        }
    } else {
        warn!(
            "IMA measurement list not available: {}",
            ima_ml_path.display()
        );
        None
    };

    let measuredboot_ml_path = Path::new(MEASUREDBOOT_ML);
    let measuredboot_ml_file = if measuredboot_ml_path.exists() {
        match fs::File::open(measuredboot_ml_path) {
            Ok(file) => Some(Mutex::new(file)),
            Err(e) => {
                warn!(
                    "Measured boot measurement list not accessible: {}",
                    measuredboot_ml_path.display()
                );
                None
            }
        }
    } else {
        warn!(
            "Measured boot measurement list not available: {}",
            measuredboot_ml_path.display()
        );
        None
    };

    // Load config
    let mut config = config::KeylimeConfig::new()?;

    // The agent cannot run when a payload script is defined, but mTLS is disabled and insecure
    // payloads are not explicitly enabled
    if !&config.agent.enable_agent_mtls
        && !&config.agent.enable_insecure_payload
        && !&config.agent.payload_script.is_empty()
    {
        let message = "The agent mTLS is disabled and 'payload_script' is not empty. To allow the agent to run, 'enable_insecure_payload' has to be set to 'True'".to_string();

        error!("Configuration error: {}", &message);
        return Err(Error::Configuration(message));
    }

    let work_dir = Path::new(&config.agent.keylime_dir);
    let mount = secure_mount::mount(work_dir, &config.agent.secure_size)?;

    let run_as = if permissions::get_euid() == 0 {
        if let Some(ref run_as) = config.agent.run_as {
            Some(run_as.to_string())
        } else {
            warn!("Cannot drop privileges since 'run_as' is empty in 'agent' section of 'keylime-agent.conf'.");
            None
        }
    } else {
        error!("Cannot drop privileges: not enough permission");
        return Err(Error::Configuration(
            "Cannot drop privileges: not enough permission".to_string(),
        ));
    };

    // Drop privileges
    if let Some(user_group) = &run_as {
        permissions::chown(user_group, &mount)?;
        if let Err(e) = permissions::run_as(user_group) {
            let message = "The user running the Keylime agent should be set in keylime-agent.conf, using the parameter `run_as`, with the format `user:group`".to_string();

            error!("Configuration error: {}", &message);
            return Err(Error::Configuration(message));
        }
        info!("Running the service as {}...", user_group);
    }

    info!("Starting server with API version {}...", API_VERSION);

    let mut ctx = tpm::Context::new()?;

    //  Retrieve the TPM Vendor, this allows us to warn if someone is using a
    // Software TPM ("SW")
    if tss_esapi::utils::get_tpm_vendor(ctx.as_mut())?.contains("SW") {
        warn!("INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.");
        warn!("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.");
        warn!("INSECURE: Only use Keylime in this mode for testing or debugging purposes.");
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "legacy-python-actions")] {
            match config.agent.revocation_actions_dir {
                Some(ref actions_dir) => {
                    // Verify if the python shim is installed in the expected location
                    let python_shim = Path::new(&actions_dir).join("shim.py");
                    if !python_shim.exists() {
                        error!("Could not find python shim at {}", python_shim.display());
                        return Err(Error::Configuration(format!(
                            "Could not find python shim at {}",
                            python_shim.display()
                        )));
                    }
                },
                None => {
                    error!("The revocation actions directory was not set in 'revocation_actions_dir'");
                    return Err(Error::Configuration("The revocation actions directory was not set in 'revocation_actions_dir'".to_string()));
                }
            }
        }
    }

    // When the tpm_ownerpassword is given, set auth for the Endorsement hierarchy.
    // Note in the Python implementation, tpm_ownerpassword option is also used for claiming
    // ownership of TPM access, which will not be implemented here.
    if let Some(ref v) = config.agent.tpm_ownerpassword {
        let auth = Auth::try_from(v.as_bytes())?;
        ctx.as_mut().tr_set_auth(Hierarchy::Endorsement.into(), auth)
            .map_err(|e| {
                Error::Configuration(format!(
                    "Failed to set TPM context password for Endorsement Hierarchy: {}",
                    e
                ))
            })?;
    };

    let tpm_encryption_alg =
        keylime::algorithms::EncryptionAlgorithm::try_from(
            config.agent.tpm_encryption_alg.as_str(),
        )?;
    let tpm_hash_alg = keylime::algorithms::HashAlgorithm::try_from(
        config.agent.tpm_hash_alg.as_str(),
    )?;
    let tpm_signing_alg = keylime::algorithms::SignAlgorithm::try_from(
        config.agent.tpm_signing_alg.as_str(),
    )?;

    // Gather EK values and certs
    let ek_result =
        ctx.create_ek(tpm_encryption_alg, config.agent.ek_handle.as_deref())?;

    // Calculate the SHA-256 hash of the public key in PEM format
    let ek_hash = hash_ek_pubkey(ek_result.public.clone())?;

    // Replace the uuid with the actual EK hash if the option was set.
    // We cannot do that when the configuration is loaded initially,
    // because only have later access to the the TPM.
    config.agent.uuid = match config.agent.uuid.as_str() {
        "hash_ek" => ek_hash.clone(),
        s => s.to_string(),
    };

    // Try to load persistent Agent data
    let old_ak = match &config.agent.agent_data_path {
        Some(path) => {
            let path = Path::new(&path);
            if path.exists() {
                match AgentData::load(path) {
                    Ok(data) => {
                        match data.valid(
                            tpm_hash_alg,
                            tpm_signing_alg,
                            ek_hash.as_bytes(),
                        ) {
                            true => {
                                let ak_result = data.get_ak()?;
                                match ctx
                                    .load_ak(ek_result.key_handle, &ak_result)
                                {
                                    Ok(ak_handle) => {
                                        info!(
                                            "Loaded old AK key from {}",
                                            path.display()
                                        );
                                        Some((ak_handle, ak_result))
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Loading old AK key from {} failed: {}",
                                            path.display(),
                                            e
                                        );
                                        None
                                    }
                                }
                            }
                            false => {
                                warn!(
                                    "Not using old {} because it is not valid with current configuration",
                                    path.display()
                                );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Could not load agent data: {}", e);
                        None
                    }
                }
            } else {
                info!("Agent Data not found in: {}", path.display());
                None
            }
        }
        None => {
            info!("Agent Data path not set in the configuration file");
            None
        }
    };

    // Use old AK or generate a new one and update the AgentData
    let (ak_handle, ak) = match old_ak {
        Some((ak_handle, ak)) => (ak_handle, ak),
        None => {
            let new_ak = ctx.create_ak(
                ek_result.key_handle,
                tpm_hash_alg,
                tpm_signing_alg,
            )?;
            let ak_handle = ctx.load_ak(ek_result.key_handle, &new_ak)?;
            (ak_handle, new_ak)
        }
    };

    // Store new AgentData
    let agent_data_new = AgentData::create(
        tpm_hash_alg,
        tpm_signing_alg,
        &ak,
        ek_hash.as_bytes(),
    )?;

    match &config.agent.agent_data_path {
        Some(path) => {
            agent_data_new.store(Path::new(&path))?;
        }
        None => {
            info!("Agent Data not stored");
        }
    }

    info!("Agent UUID: {}", config.agent.uuid);

    // Generate key pair for secure transmission of u, v keys. The u, v
    // keys are two halves of the key used to decrypt the workload after
    // the Identity and Integrity Quotes sent by the agent are validated
    // by the Tenant and Cloud Verifier, respectively.
    //
    // Since we store the u key in memory, discarding this key, which
    // safeguards u and v keys in transit, is not part of the threat model.

    let (nk_pub, nk_priv) = match config.agent.server_key {
        Some(ref path) => {
            let key_path = Path::new(&path);
            if key_path.exists() {
                debug!(
                    "Loading existing key pair from {}",
                    key_path.display()
                );
                crypto::load_key_pair(
                    key_path,
                    &config.agent.server_key_password,
                )?
            } else {
                debug!("Generating new key pair");
                let (public, private) = crypto::rsa_generate_pair(2048)?;
                // Write the generated key to the file
                crypto::write_key_pair(
                    &private,
                    key_path,
                    &config.agent.server_key_password,
                );
                (public, private)
            }
        }
        None => {
            debug!(
                "The server_key option was not set in the configuration file"
            );
            debug!("Generating new key pair");
            crypto::rsa_generate_pair(2048)?
        }
    };

    let cert: X509;
    let mtls_cert;
    let ssl_context;
    if config.agent.enable_agent_mtls {
        cert = match config.agent.server_cert {
            Some(ref path) => {
                let cert_path = Path::new(&path);
                if cert_path.exists() {
                    debug!(
                        "Loading existing mTLS certificate from {}",
                        cert_path.display()
                    );
                    crypto::load_x509(cert_path)?
                } else {
                    debug!("Generating new mTLS certificate");
                    let cert =
                        crypto::generate_x509(&nk_priv, &config.agent.uuid)?;
                    // Write the generated certificate
                    crypto::write_x509(&cert, cert_path)?;
                    cert
                }
            }
            None => {
                debug!("The server_cert option was not set in the configuration file");
                crypto::generate_x509(&nk_priv, &config.agent.uuid)?
            }
        };

        let ca_cert_path = match config.agent.trusted_client_ca {
            None => {
                error!("Agent mTLS is enabled, but trusted_client_ca option was not provided");
                return Err(Error::Configuration("Agent mTLS is enabled, but trusted_client_ca option was not provided".to_string()));
            }
            Some(ref path) => PathBuf::from(&path),
        };

        if !ca_cert_path.exists() {
            error!(
                "Trusted client CA certificate not found: {} does not exist",
                ca_cert_path.display()
            );
            return Err(Error::Configuration(format!(
                "Trusted client CA certificate not found: {} does not exist",
                ca_cert_path.display()
            )));
        }

        let keylime_ca_cert = match crypto::load_x509(&ca_cert_path) {
            Ok(t) => Ok(t),
            Err(e) => {
                error!(
                    "Failed to load trusted CA certificate {}: {}",
                    ca_cert_path.display(),
                    e
                );
                Err(e)
            }
        }?;

        mtls_cert = Some(&cert);
        ssl_context = Some(crypto::generate_mtls_context(
            &cert,
            &nk_priv,
            keylime_ca_cert,
        )?);
    } else {
        mtls_cert = None;
        ssl_context = None;
        warn!("mTLS disabled, Tenant and Verifier will reach out to agent via HTTP");
    }

    {
        // Request keyblob material
        let keyblob = registrar_agent::do_register_agent(
            &config.agent.registrar_ip,
            &config.agent.registrar_port.to_string(),
            &config.agent.uuid,
            &PublicBuffer::try_from(ek_result.public.clone())?.marshall()?,
            ek_result.ek_cert,
            &PublicBuffer::try_from(ak.public)?.marshall()?,
            mtls_cert,
            config.agent.contact_ip.clone(),
            config.agent.contact_port,
        )
        .await?;
        info!("SUCCESS: Agent {} registered", &config.agent.uuid);

        let key = ctx.activate_credential(
            keyblob,
            ak_handle,
            ek_result.key_handle,
        )?;
        // Flush EK if we created it
        if config.agent.ek_handle.is_none() {
            ctx.as_mut().flush_context(ek_result.key_handle.into())?;
        }
        let mackey = base64::encode(key.value());
        let auth_tag = crypto::compute_hmac(
            mackey.as_bytes(),
            config.agent.uuid.as_bytes(),
        )?;
        let auth_tag = hex::encode(&auth_tag);

        registrar_agent::do_activate_agent(
            &config.agent.registrar_ip,
            &config.agent.registrar_port.to_string(),
            &config.agent.uuid,
            &auth_tag,
        )
        .await?;
        info!("SUCCESS: Agent {} activated", &config.agent.uuid);
    }

    let mut encr_payload = Vec::new();

    let symm_key_arc = Arc::new(Mutex::new(None));
    let symm_key_cvar_arc = Arc::new(Condvar::new());
    let encr_payload_arc = Arc::new(Mutex::new(encr_payload));

    // these allow the arrays to be referenced later in this thread
    let symm_key = Arc::clone(&symm_key_arc);
    let symm_key_cvar = Arc::clone(&symm_key_cvar_arc);
    let payload = Arc::clone(&encr_payload_arc);

    let revocation_cert =
        config.agent.revocation_cert.as_ref().map(PathBuf::from);

    let actions_dir = config
        .agent
        .revocation_actions_dir
        .as_ref()
        .map(PathBuf::from);

    let work_dir = Path::new(&config.agent.keylime_dir)
        .canonicalize()
        .map_err(|e| {
            Error::Configuration(format!(
                "Path {} set in keylime_dir not found: {}",
                &config.agent.keylime_dir, e
            ))
        })?;

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
        hash_alg: tpm_hash_alg,
        enc_alg: tpm_encryption_alg,
        sign_alg: tpm_signing_alg,
        agent_uuid: config.agent.uuid.clone(),
        revocation_cert,
        revocation_actions: config.agent.revocation_actions.clone(),
        revocation_actions_dir: actions_dir,
        allow_payload_revocation_actions: config
            .agent
            .allow_payload_revocation_actions,
        secure_size: config.agent.secure_size.clone(),
        work_dir,
        ima_ml_file,
        measuredboot_ml_file,
        ima_ml: Mutex::new(MeasurementList::new()),
        secure_mount: PathBuf::from(&mount),
    });

    let actix_server =
        HttpServer::new(move || {
            App::new()
                .wrap(middleware::ErrorHandlers::new().handler(
                    http::StatusCode::NOT_FOUND,
                    errors_handler::wrap_404,
                ))
                .wrap(middleware::Logger::new(
                    "%r from %a result %s (took %D ms)",
                ))
                .wrap_fn(|req, srv| {
                    info!(
                        "{} invoked from {:?} with uri {}",
                        req.head().method,
                        req.connection_info().peer_addr().unwrap(), //#[allow_ci]
                        req.uri()
                    );
                    srv.call(req)
                })
                .app_data(quotedata.clone())
                .app_data(
                    web::JsonConfig::default()
                        .error_handler(errors_handler::json_parser_error),
                )
                .app_data(
                    web::QueryConfig::default()
                        .error_handler(errors_handler::query_parser_error),
                )
                .app_data(
                    web::PathConfig::default()
                        .error_handler(errors_handler::path_parser_error),
                )
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
                                ))
                                .default_service(web::to(
                                    errors_handler::keys_default,
                                )),
                        )
                        .service(
                            web::scope("/notifications")
                                .service(web::resource("/revocation").route(
                                    web::post().to(
                                        notifications_handler::revocation,
                                    ),
                                ))
                                .default_service(web::to(
                                    errors_handler::notifications_default,
                                )),
                        )
                        .service(
                            web::scope("/quotes")
                                .service(web::resource("/identity").route(
                                    web::get().to(quotes_handler::identity),
                                ))
                                .service(web::resource("/integrity").route(
                                    web::get().to(quotes_handler::integrity),
                                ))
                                .default_service(web::to(
                                    errors_handler::quotes_default,
                                )),
                        )
                        .default_service(web::to(
                            errors_handler::api_default,
                        )),
                )
                .service(
                    web::resource("/version")
                        .route(web::get().to(version_handler::version)),
                )
                .service(
                    web::resource(r"/v{major:\d+}.{minor:\d+}{tail}*")
                        .to(errors_handler::version_not_supported),
                )
                .default_service(web::to(errors_handler::app_default))
        })
        // Disable default signal handlers.  See:
        // https://github.com/actix/actix-web/issues/2739
        // for details.
        .disable_signals();

    let server;
    if config.agent.enable_agent_mtls && ssl_context.is_some() {
        server = actix_server
            .bind_openssl(
                format!("{}:{}", config.agent.ip, config.agent.port),
                ssl_context.unwrap(), //#[allow_ci]
            )?
            .run();

        info!(
            "Listening on https://{}:{}",
            config.agent.ip, config.agent.port
        );
    } else {
        server = actix_server
            .bind(format!("{}:{}", config.agent.ip, config.agent.port))?
            .run();

        info!(
            "Listening on http://{}:{}",
            config.agent.ip, config.agent.port
        );
    };

    let server_handle = server.handle();
    let server_task = rt::spawn(server).map_err(Error::from);
    let worker_task = rt::spawn(worker(
        symm_key,
        symm_key_cvar,
        payload,
        config.clone(),
        PathBuf::from(&mount),
    ))
    .map_err(Error::from);

    let result = try_join!(server_task, worker_task);
    server_handle.stop(true).await;
    result.map(|_| ())
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
    use crate::config::KeylimeConfig;

    impl QuoteData {
        pub(crate) fn fixture() -> Result<Self> {
            let test_config = KeylimeConfig::default();
            let mut ctx = tpm::Context::new()?;

            let tpm_encryption_alg =
                keylime::algorithms::EncryptionAlgorithm::try_from(
                    test_config.agent.tpm_encryption_alg.as_str(),
                )?;

            // Gather EK and AK key values and certs
            let ek_result = ctx.create_ek(tpm_encryption_alg, None)?;

            let tpm_hash_alg = keylime::algorithms::HashAlgorithm::try_from(
                test_config.agent.tpm_hash_alg.as_str(),
            )?;

            let tpm_signing_alg =
                keylime::algorithms::SignAlgorithm::try_from(
                    test_config.agent.tpm_signing_alg.as_str(),
                )?;

            let ak_result = ctx.create_ak(
                ek_result.key_handle,
                tpm_hash_alg,
                tpm_signing_alg,
            )?;
            let ak_handle = ctx.load_ak(ek_result.key_handle, &ak_result)?;
            let ak_tpm2b_pub =
                PublicBuffer::try_from(ak_result.public)?.marshall()?;

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
                test_config.agent.revocation_cert.map(PathBuf::from);

            let actions_dir = Some(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/actions/"),
            );

            let work_dir =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");

            let secure_mount = work_dir.join("tmpfs-dev");

            let ima_ml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data/ima/ascii_runtime_measurements");
            let ima_ml_file = match fs::File::open(ima_ml_path) {
                Ok(file) => Some(Mutex::new(file)),
                Err(err) => None,
            };

            let measuredboot_ml_path = Path::new(
                "/sys/kernel/security/tpm0/binary_bios_measurements",
            );
            let measuredboot_ml_file =
                match fs::File::open(measuredboot_ml_path) {
                    Ok(file) => Some(Mutex::new(file)),
                    Err(err) => None,
                };

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
                hash_alg: keylime::algorithms::HashAlgorithm::Sha256,
                enc_alg: keylime::algorithms::EncryptionAlgorithm::Rsa,
                sign_alg: keylime::algorithms::SignAlgorithm::RsaSsa,
                agent_uuid: test_config.agent.uuid,
                revocation_cert,
                revocation_actions: None,
                revocation_actions_dir: actions_dir,
                allow_payload_revocation_actions: test_config
                    .agent
                    .allow_payload_revocation_actions,
                secure_size: test_config.agent.secure_size,
                work_dir,
                ima_ml_file,
                measuredboot_ml_file,
                ima_ml: Mutex::new(MeasurementList::new()),
                secure_mount,
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
