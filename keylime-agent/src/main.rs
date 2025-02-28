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

mod agent_handler;
mod api;
mod common;
mod config;
mod error;
mod errors_handler;
mod keys_handler;
mod notifications_handler;
mod payloads;
mod permissions;
mod quotes_handler;
mod revocation;
mod secure_mount;

use actix_web::{dev::Service, http, middleware, rt, web, App, HttpServer};
use base64::{engine::general_purpose, Engine as _};
use clap::{Arg, Command as ClapApp};
use common::*;
use error::{Error, Result};
use futures::{
    future::{ok, TryFutureExt},
    try_join,
};
use keylime::{
    crypto::{self, x509::CertificateBuilder},
    device_id::{DeviceID, DeviceIDBuilder},
    ima::MeasurementList,
    list_parser::parse_list,
    registrar_client::RegistrarClientBuilder,
    serialization,
    tpm::{self, IAKResult, IDevIDResult},
};
use log::*;
use openssl::{
    pkey::{PKey, Private, Public},
    x509::X509,
};
use std::{
    convert::TryFrom,
    fs,
    io::{BufReader, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Mutex,
    time::Duration,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{mpsc, oneshot},
};
use tss_esapi::{
    handles::KeyHandle,
    interface_types::algorithm::{AsymmetricAlgorithm, HashingAlgorithm},
    interface_types::resource_handles::Hierarchy,
    structures::{Auth, Data, Digest, MaxBuffer, PublicBuffer},
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
pub struct QuoteData<'a> {
    agent_uuid: String,
    ak_handle: KeyHandle,
    allow_payload_revocation_actions: bool,
    api_versions: Vec<String>,
    enc_alg: keylime::algorithms::EncryptionAlgorithm,
    hash_alg: keylime::algorithms::HashAlgorithm,
    ima_ml: Mutex<MeasurementList>,
    ima_ml_file: Option<Mutex<fs::File>>,
    keys_tx: mpsc::Sender<(
        keys_handler::KeyMessage,
        Option<oneshot::Sender<keys_handler::SymmKeyMessage>>,
    )>,
    measuredboot_ml_file: Option<Mutex<fs::File>>,
    payload_tx: mpsc::Sender<payloads::PayloadMessage>,
    priv_key: PKey<Private>,
    pub_key: PKey<Public>,
    revocation_tx: mpsc::Sender<revocation::RevocationMessage>,
    secure_mount: PathBuf,
    secure_size: String,
    sign_alg: keylime::algorithms::SignAlgorithm,
    tpmcontext: Mutex<tpm::Context<'a>>,
    work_dir: PathBuf,
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

    // Load config
    let mut config = config::KeylimeConfig::new()?;

    // load path for IMA logfile
    #[cfg(test)]
    fn ima_ml_path_get(_: &String) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("ima")
            .join("ascii_runtime_measurements")
    }

    #[cfg(not(test))]
    fn ima_ml_path_get(s: &String) -> PathBuf {
        Path::new(&s).to_path_buf()
    }

    let ima_ml_path = ima_ml_path_get(&config.agent.ima_ml_path);

    // check whether anyone has overridden the default
    if ima_ml_path.as_os_str() != config::DEFAULT_IMA_ML_PATH {
        warn!(
            "IMA measurement list location override: {}",
            ima_ml_path.display()
        );
    }

    // check IMA logfile exists & accessible
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

    // load path for MBA logfile
    let mut measuredboot_ml_path =
        Path::new(&config.agent.measuredboot_ml_path);
    let env_mb_path: String;
    #[cfg(feature = "testing")]
    if let Ok(v) = std::env::var("TPM_BINARY_MEASUREMENTS") {
        env_mb_path = v;
        measuredboot_ml_path = Path::new(&env_mb_path);
    }

    // check whether anyone has overridden the default MBA logfile
    if measuredboot_ml_path.as_os_str()
        != config::DEFAULT_MEASUREDBOOT_ML_PATH
    {
        warn!(
            "Measured boot measurement list location override: {}",
            measuredboot_ml_path.display()
        );
    }

    // check MBA logfile exists & accessible
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

    // The agent cannot run when a payload script is defined, but mTLS is disabled and insecure
    // payloads are not explicitly enabled
    if !config.agent.enable_agent_mtls
        && !config.agent.enable_insecure_payload
        && !config.agent.payload_script.is_empty()
    {
        let message = "The agent mTLS is disabled and 'payload_script' is not empty. To allow the agent to run, 'enable_insecure_payload' has to be set to 'True'".to_string();

        error!("Configuration error: {}", &message);
        return Err(Error::Configuration(
            config::KeylimeConfigError::Generic(message),
        ));
    }

    let secure_size = config.agent.secure_size.clone();
    let work_dir = PathBuf::from(&config.agent.keylime_dir);
    let mount = secure_mount::mount(&work_dir, &config.agent.secure_size)?;

    let run_as = if permissions::get_euid() == 0 {
        if (config.agent.run_as).is_empty() {
            warn!("Cannot drop privileges since 'run_as' is empty in 'agent' section of 'keylime-agent.conf'.");
            None
        } else {
            Some(&config.agent.run_as)
        }
    } else {
        if !(config.agent.run_as).is_empty() {
            warn!("Ignoring 'run_as' option because Keylime agent has not been started as root.");
        }
        None
    };

    // Drop privileges
    if let Some(user_group) = run_as {
        permissions::chown(user_group, &mount)?;
        if let Err(e) = permissions::run_as(user_group) {
            let message = "The user running the Keylime agent should be set in keylime-agent.conf, using the parameter `run_as`, with the format `user:group`".to_string();

            error!("Configuration error: {}", &message);
            return Err(Error::Configuration(
                config::KeylimeConfigError::Generic(message),
            ));
        }
        info!("Running the service as {}...", user_group);
    }

    // Parse the configured API versions
    let api_versions = parse_list(&config.agent.api_versions)?
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    info!(
        "Starting server with API versions: {}",
        &config.agent.api_versions
    );

    let mut ctx = tpm::Context::new()?;

    cfg_if::cfg_if! {
        if #[cfg(feature = "legacy-python-actions")] {
            warn!("The support for legacy python revocation actions is deprecated and will be removed on next major release");

            let actions_dir = &config.agent.revocation_actions_dir;
            // Verify if the python shim is installed in the expected location
            let python_shim = Path::new(&actions_dir).join("shim.py");
            if !python_shim.exists() {
                error!("Could not find python shim at {}", python_shim.display());
                return Err(Error::Configuration(
                    config::KeylimeConfigError::Generic(format!(
                    "Could not find python shim at {}",
                    python_shim.display()
                ))));
            }
        }
    }

    // When the tpm_ownerpassword is given, set auth for the Endorsement hierarchy.
    // Note in the Python implementation, tpm_ownerpassword option is also used for claiming
    // ownership of TPM access, which will not be implemented here.
    let tpm_ownerpassword = &config.agent.tpm_ownerpassword;
    if !tpm_ownerpassword.is_empty() {
        let auth = if let Some(hex_ownerpassword) =
            tpm_ownerpassword.strip_prefix("hex:")
        {
            let decoded_ownerpassword =
                hex::decode(hex_ownerpassword).map_err(Error::from)?;
            Auth::try_from(decoded_ownerpassword)?
        } else {
            Auth::try_from(tpm_ownerpassword.as_bytes())?
        };
        ctx.tr_set_auth(Hierarchy::Endorsement.into(), auth)
            .map_err(|e| {
                Error::Configuration(config::KeylimeConfigError::Generic(format!(
                    "Failed to set TPM context password for Endorsement Hierarchy: {e}"
                )))
            })?;
    };

    let tpm_encryption_alg =
        keylime::algorithms::EncryptionAlgorithm::try_from(
            config.agent.tpm_encryption_alg.as_ref(),
        )?;
    let tpm_hash_alg = keylime::algorithms::HashAlgorithm::try_from(
        config.agent.tpm_hash_alg.as_ref(),
    )?;
    let tpm_signing_alg = keylime::algorithms::SignAlgorithm::try_from(
        config.agent.tpm_signing_alg.as_ref(),
    )?;

    // Gather EK values and certs
    let ek_result = match config.agent.ek_handle.as_ref() {
        "" => ctx.create_ek(tpm_encryption_alg, None)?,
        s => ctx.create_ek(tpm_encryption_alg, Some(s))?,
    };

    // Calculate the SHA-256 hash of the public key in PEM format
    let ek_hash = hash_ek_pubkey(ek_result.public.clone())?;

    // Replace the uuid with the actual EK hash if the option was set.
    // We cannot do that when the configuration is loaded initially,
    // because only have later access to the the TPM.
    config.agent.uuid = match config.agent.uuid.as_ref() {
        "hash_ek" => ek_hash.clone(),
        s => s.to_string(),
    };

    let agent_uuid = config.agent.uuid.clone();

    // Try to load persistent Agent data
    let old_ak = match config.agent.agent_data_path.as_ref() {
        "" => {
            info!("Agent Data path not set in the configuration file");
            None
        }
        path => {
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

    match config.agent.agent_data_path.as_ref() {
        "" => info!("Agent Data not stored"),
        path => agent_data_new.store(Path::new(&path))?,
    }

    info!("Agent UUID: {}", agent_uuid);

    // If using IAK/IDevID is enabled, obtain IAK/IDevID and respective certificates
    let mut device_id = if config.agent.enable_iak_idevid {
        let mut builder = DeviceIDBuilder::new()
            .iak_handle(&config.agent.iak_handle)
            .iak_password(&config.agent.iak_password)
            .iak_default_template(config::DEFAULT_IAK_IDEVID_TEMPLATE)
            .iak_template(&config.agent.iak_idevid_template)
            .iak_asym_alg(&config.agent.iak_idevid_asymmetric_alg)
            .iak_hash_alg(&config.agent.iak_idevid_name_alg)
            .idevid_handle(&config.agent.idevid_handle)
            .idevid_cert_path(&config.agent.idevid_cert)
            .idevid_password(&config.agent.idevid_password)
            .idevid_default_template(config::DEFAULT_IAK_IDEVID_TEMPLATE)
            .idevid_template(&config.agent.iak_idevid_template)
            .idevid_asym_alg(&config.agent.iak_idevid_asymmetric_alg)
            .idevid_hash_alg(&config.agent.iak_idevid_name_alg);

        if !&config.agent.iak_cert.is_empty() {
            builder = builder.iak_cert_path(&config.agent.iak_cert);
        }

        if !&config.agent.idevid_cert.is_empty() {
            builder = builder.idevid_cert_path(&config.agent.idevid_cert);
        }

        Some(builder.build(&mut ctx)?)
    } else {
        None
    };

    let (attest, signature) = if let Some(dev_id) = &mut device_id {
        let qualifying_data = Data::try_from(agent_uuid.as_bytes())?;
        let (attest, signature) =
            dev_id.certify(qualifying_data, ak_handle, &mut ctx)?;

        info!("AK certified with IAK.");

        // // For debugging certify(), the following checks the generated signature
        // let max_b = MaxBuffer::try_from(attest.clone().marshall()?)?;
        // let (hashed_attest, _) = ctx.inner.hash(max_b, HashingAlgorithm::Sha256, Hierarchy::Endorsement,)?;
        // println!("{:?}", hashed_attest);
        // println!("{:?}", signature);
        // println!("{:?}", ctx.inner.verify_signature(iak.as_ref().unwrap().handle, hashed_attest, signature.clone())?); //#[allow_ci]
        (Some(attest), Some(signature))
    } else {
        (None, None)
    };

    // Generate key pair for secure transmission of u, v keys. The u, v
    // keys are two halves of the key used to decrypt the workload after
    // the Identity and Integrity Quotes sent by the agent are validated
    // by the Tenant and Cloud Verifier, respectively.
    //
    // Since we store the u key in memory, discarding this key, which
    // safeguards u and v keys in transit, is not part of the threat model.

    let (nk_pub, nk_priv) = match config.agent.server_key.as_ref() {
        "" => {
            debug!(
                "The server_key option was not set in the configuration file"
            );
            debug!("Generating new key pair");
            crypto::rsa_generate_pair(2048)?
        }
        path => {
            let key_path = Path::new(&path);
            if key_path.exists() {
                debug!(
                    "Loading existing key pair from {}",
                    key_path.display()
                );
                crypto::load_key_pair(
                    key_path,
                    Some(config.agent.server_key_password.as_ref()),
                )?
            } else {
                debug!("Generating new key pair");
                let (public, private) = crypto::rsa_generate_pair(2048)?;
                // Write the generated key to the file
                crypto::write_key_pair(
                    &private,
                    key_path,
                    Some(config.agent.server_key_password.as_ref()),
                );
                (public, private)
            }
        }
    };

    let cert: X509;
    let mtls_cert;
    let ssl_context;
    if config.agent.enable_agent_mtls {
        let contact_ips = vec![config.agent.contact_ip.as_str()];
        cert = match config.agent.server_cert.as_ref() {
            "" => {
                debug!("The server_cert option was not set in the configuration file");

                crypto::x509::CertificateBuilder::new()
                    .private_key(&nk_priv)
                    .common_name(&agent_uuid)
                    .add_ips(contact_ips)
                    .build()?
            }
            path => {
                let cert_path = Path::new(&path);
                if cert_path.exists() {
                    debug!(
                        "Loading existing mTLS certificate from {}",
                        cert_path.display()
                    );
                    crypto::load_x509_pem(cert_path)?
                } else {
                    debug!("Generating new mTLS certificate");
                    let cert = crypto::x509::CertificateBuilder::new()
                        .private_key(&nk_priv)
                        .common_name(&agent_uuid)
                        .add_ips(contact_ips)
                        .build()?;
                    // Write the generated certificate
                    crypto::write_x509(&cert, cert_path)?;
                    cert
                }
            }
        };

        let trusted_client_ca = match config.agent.trusted_client_ca.as_ref()
        {
            "" => {
                error!("Agent mTLS is enabled, but trusted_client_ca option was not provided");
                return Err(Error::Configuration(config::KeylimeConfigError::Generic("Agent mTLS is enabled, but trusted_client_ca option was not provided".to_string())));
            }
            l => l,
        };

        // The trusted_client_ca config option is a list, parse to obtain a vector
        let certs_list = parse_list(trusted_client_ca)?;
        if certs_list.is_empty() {
            error!(
                "Trusted client CA certificate list is empty: could not load any certificate"
            );
            return Err(Error::Configuration(config::KeylimeConfigError::Generic(
                "Trusted client CA certificate list is empty: could not load any certificate".to_string()
            )));
        }

        let keylime_ca_certs = match crypto::load_x509_cert_list(
            certs_list.iter().map(Path::new).collect(),
        ) {
            Ok(t) => Ok(t),
            Err(e) => {
                error!("Failed to load trusted CA certificates: {}", e);
                Err(e)
            }
        }?;

        mtls_cert = Some(cert.clone());
        ssl_context = Some(crypto::generate_tls_context(
            &cert,
            &nk_priv,
            keylime_ca_certs,
        )?);
    } else {
        mtls_cert = None;
        ssl_context = None;
        warn!("mTLS disabled, Tenant and Verifier will reach out to agent via HTTP");
    }

    {
        // Declare here as these must live longer than the builder
        let iak_pub;
        let idevid_pub;
        let ak_pub = &PublicBuffer::try_from(ak.public)?.marshall()?;
        let ek_pub =
            &PublicBuffer::try_from(ek_result.public.clone())?.marshall()?;

        // Create a RegistrarClientBuilder and set the parameters
        let mut builder = RegistrarClientBuilder::new()
            .ak_pub(ak_pub)
            .ek_pub(ek_pub)
            .enabled_api_versions(
                api_versions.iter().map(|ver| ver.as_ref()).collect(),
            )
            .registrar_ip(config.agent.registrar_ip.clone())
            .registrar_port(config.agent.registrar_port)
            .uuid(&agent_uuid)
            .ip(config.agent.contact_ip.clone())
            .port(config.agent.contact_port);

        if let Some(mtls_cert) = mtls_cert {
            builder = builder.mtls_cert(mtls_cert);
        }

        // If the certificate is not None add it to the builder
        if let Some(ekchain) = ek_result.to_pem() {
            builder = builder.ek_cert(ekchain);
        }

        // Set the IAK/IDevID related fields, if enabled
        if config.agent.enable_iak_idevid {
            let (Some(dev_id), Some(attest), Some(signature)) =
                (&device_id, attest, signature)
            else {
                error!(
                    "IDevID and IAK are enabled but could not be generated"
                );
                return Err(Error::Configuration(config::KeylimeConfigError::Generic(
                    "IDevID and IAK are enabled but could not be generated"
                        .to_string(),
                )));
            };

            iak_pub = PublicBuffer::try_from(dev_id.iak_pubkey.clone())?
                .marshall()?;
            idevid_pub =
                PublicBuffer::try_from(dev_id.idevid_pubkey.clone())?
                    .marshall()?;
            builder = builder
                .iak_attest(attest.marshall()?)
                .iak_sign(signature.marshall()?)
                .iak_pub(&iak_pub)
                .idevid_pub(&idevid_pub);

            // If the IAK certificate was provided, set it
            if let Some(iak_cert) = dev_id.iak_cert.clone() {
                builder = builder.iak_cert(iak_cert);
            }

            // If the IDevID certificate was provided, set it
            if let Some(idevid_cert) = dev_id.idevid_cert.clone() {
                builder = builder.idevid_cert(idevid_cert);
            }
        }

        // Build the registrar client
        let mut registrar_client = builder.build().await?;

        // Request keyblob material
        let keyblob = registrar_client.register_agent().await?;

        info!("SUCCESS: Agent {} registered", &agent_uuid);

        let key = ctx.activate_credential(
            keyblob,
            ak_handle,
            ek_result.key_handle,
        )?;

        // Flush EK if we created it
        if config.agent.ek_handle.is_empty() {
            ctx.flush_context(ek_result.key_handle.into())?;
        }

        let mackey = general_purpose::STANDARD.encode(key.value());
        let auth_tag =
            crypto::compute_hmac(mackey.as_bytes(), agent_uuid.as_bytes())?;
        let auth_tag = hex::encode(&auth_tag);

        registrar_client.activate_agent(&auth_tag).await?;
        info!("SUCCESS: Agent {} activated", &agent_uuid);
    }

    let (mut payload_tx, mut payload_rx) =
        mpsc::channel::<payloads::PayloadMessage>(1);
    let (mut keys_tx, mut keys_rx) = mpsc::channel::<(
        keys_handler::KeyMessage,
        Option<oneshot::Sender<keys_handler::SymmKeyMessage>>,
    )>(1);
    let (mut revocation_tx, mut revocation_rx) =
        mpsc::channel::<revocation::RevocationMessage>(1);

    #[cfg(feature = "with-zmq")]
    let (mut zmq_tx, mut zmq_rx) = mpsc::channel::<revocation::ZmqMessage>(1);

    let revocation_cert = match config.agent.revocation_cert.as_ref() {
        "" => {
            error!(
                "No revocation certificate set in 'revocation_cert' option"
            );
            return Err(Error::Configuration(config::KeylimeConfigError::Generic(
                "No revocation certificate set in 'revocation_cert' option"
                    .to_string(),
            )));
        }
        s => PathBuf::from(s),
    };

    let revocation_actions_dir = config.agent.revocation_actions_dir.clone();

    let revocation_actions = match config.agent.revocation_actions.as_ref() {
        "" => None,
        s => Some(s.to_string()),
    };

    let allow_payload_revocation_actions =
        config.agent.allow_payload_revocation_actions;

    let revocation_task = rt::spawn(revocation::worker(
        revocation_rx,
        revocation_cert,
        revocation_actions_dir,
        revocation_actions,
        allow_payload_revocation_actions,
        work_dir.clone(),
        mount.clone(),
    ))
    .map_err(Error::from);

    let quotedata = web::Data::new(QuoteData {
        agent_uuid: agent_uuid.clone(),
        ak_handle,
        allow_payload_revocation_actions,
        api_versions: api_versions.clone(),
        enc_alg: tpm_encryption_alg,
        hash_alg: tpm_hash_alg,
        ima_ml: Mutex::new(MeasurementList::new()),
        ima_ml_file,
        keys_tx: keys_tx.clone(),
        measuredboot_ml_file,
        payload_tx: payload_tx.clone(),
        priv_key: nk_priv,
        pub_key: nk_pub,
        revocation_tx: revocation_tx.clone(),
        secure_mount: PathBuf::from(&mount),
        secure_size,
        sign_alg: tpm_signing_alg,
        tpmcontext: Mutex::new(ctx),
        work_dir,
    });

    let actix_server = HttpServer::new(move || {
        let mut app = App::new()
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
            );

        for version in &api_versions {
            // This should never fail, thus unwrap should never panic
            let scope = api::get_api_scope(version).unwrap(); //#[allow_ci]
            app = app.service(scope);
        }

        app.service(
            web::resource("/version").route(web::get().to(api::version)),
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

    // Try to parse as an IP address
    let ip = match config.agent.ip.parse::<IpAddr>() {
        Ok(ip_addr) => {
            // Add bracket if IPv6, otherwise use as it is
            if ip_addr.is_ipv6() {
                format!("[{}]", ip_addr)
            } else {
                ip_addr.to_string()
            }
        }
        Err(_) => {
            // If the address was not an IP address, treat as a hostname
            config.agent.ip.to_string()
        }
    };

    let port = config.agent.port;
    if config.agent.enable_agent_mtls && ssl_context.is_some() {
        server = actix_server
            .bind_openssl(
                format!("{ip}:{port}"),
                ssl_context.unwrap(), //#[allow_ci]
            )?
            .run();
        info!("Listening on https://{ip}:{port}");
    } else {
        server = actix_server.bind(format!("{ip}:{port}"))?.run();
        info!("Listening on http://{ip}:{port}");
    };

    let server_handle = server.handle();
    let server_task = rt::spawn(server).map_err(Error::from);

    // Only run payload scripts if mTLS is enabled or 'enable_insecure_payload' option is set
    let run_payload = config.agent.enable_agent_mtls
        || config.agent.enable_insecure_payload;

    let payload_task = rt::spawn(payloads::worker(
        config.clone(),
        PathBuf::from(&mount),
        payload_rx,
        revocation_tx.clone(),
        #[cfg(feature = "with-zmq")]
        zmq_tx.clone(),
    ))
    .map_err(Error::from);

    let key_task = rt::spawn(keys_handler::worker(
        run_payload,
        agent_uuid,
        keys_rx,
        payload_tx.clone(),
    ))
    .map_err(Error::from);

    // If with-zmq feature is enabled, run the service listening for ZeroMQ messages
    #[cfg(feature = "with-zmq")]
    let zmq_task = if config.agent.enable_revocation_notifications {
        warn!("The support for ZeroMQ revocation notifications is deprecated and will be removed on next major release");

        let zmq_ip = config.agent.revocation_notification_ip;
        let zmq_port = config.agent.revocation_notification_port;

        rt::spawn(revocation::zmq_worker(
            zmq_rx,
            revocation_tx.clone(),
            zmq_ip,
            zmq_port,
        ))
        .map_err(Error::from)
    } else {
        rt::spawn(ok(())).map_err(Error::from)
    };

    let shutdown_task = rt::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).unwrap(); //#[allow_ci]
        let mut sigterm = signal(SignalKind::terminate()).unwrap(); //#[allow_ci]

        tokio::select! {
            _ = sigint.recv() => {
                debug!("Received SIGINT signal");
            },
            _ = sigterm.recv() => {
                debug!("Received SIGTERM signal");
            },
        }

        info!("Shutting down keylime agent");

        // Shutdown tasks
        let server_stop = server_handle.stop(true);
        payload_tx.send(payloads::PayloadMessage::Shutdown);
        keys_tx.send((keys_handler::KeyMessage::Shutdown, None));

        #[cfg(feature = "with-zmq")]
        zmq_tx.send(revocation::ZmqMessage::Shutdown);

        revocation_tx.send(revocation::RevocationMessage::Shutdown);

        // Await tasks shutdown
        server_stop.await;
    })
    .map_err(Error::from);

    // If with-zmq feature is enabled, wait for the service listening for ZeroMQ messages
    #[cfg(feature = "with-zmq")]
    try_join!(zmq_task)?;

    let result = try_join!(
        server_task,
        payload_task,
        key_task,
        revocation_task,
        shutdown_task,
    );
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
#[cfg(test)]
mod testing {
    use super::*;
    use crate::{config::KeylimeConfig, crypto::CryptoError};
    use thiserror::Error;

    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};

    use keylime::tpm::testing::lock_tests;

    #[derive(Error, Debug)]
    pub(crate) enum MainTestError {
        /// Algorithm error
        #[error("AlgorithmError")]
        Error(#[from] keylime::algorithms::AlgorithmError),

        /// Crypto error
        #[error("CryptoError")]
        CryptoError(#[from] CryptoError),

        /// CryptoTest error
        #[error("CryptoTestError")]
        CryptoTestError(#[from] crypto::testing::CryptoTestError),

        /// IO error
        #[error("IOError")]
        IoError(#[from] std::io::Error),

        /// OpenSSL error
        #[error("IOError")]
        OpenSSLError(#[from] openssl::error::ErrorStack),

        /// TPM error
        #[error("TPMError")]
        TPMError(#[from] tpm::TpmError),

        /// TSS esapi error
        #[error("TSSError")]
        TSSError(#[from] tss_esapi::Error),
    }

    impl Drop for QuoteData<'_> {
        /// Flush the created AK when dropping
        fn drop(&mut self) {
            self.tpmcontext
                .lock()
                .unwrap() //#[allow_ci]
                .flush_context(self.ak_handle.into());
        }
    }

    impl QuoteData<'_> {
        pub(crate) async fn fixture() -> std::result::Result<
            (Self, AsyncMutexGuard<'static, ()>),
            MainTestError,
        > {
            let mutex = lock_tests().await;
            let test_config = KeylimeConfig::default();
            let mut ctx = tpm::Context::new()?;

            let tpm_encryption_alg =
                keylime::algorithms::EncryptionAlgorithm::try_from(
                    test_config.agent.tpm_encryption_alg.as_str(),
                )?;

            let tpm_hash_alg = keylime::algorithms::HashAlgorithm::try_from(
                test_config.agent.tpm_hash_alg.as_str(),
            )?;

            let tpm_signing_alg =
                keylime::algorithms::SignAlgorithm::try_from(
                    test_config.agent.tpm_signing_alg.as_str(),
                )?;

            // Gather EK and AK key values and certs
            let ek_result = ctx.create_ek(tpm_encryption_alg, None).unwrap(); //#[allow_ci]
            let ak_result = ctx
                .create_ak(
                    ek_result.key_handle,
                    tpm_hash_alg,
                    tpm_signing_alg,
                )
                .unwrap(); //#[allow_ci]
            let ak_handle =
                ctx.load_ak(ek_result.key_handle, &ak_result).unwrap(); //#[allow_ci]

            ctx.flush_context(ek_result.key_handle.into()).unwrap(); //#[allow_ci]

            let rsa_key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data")
                .join("test-rsa.pem");

            let (nk_pub, nk_priv) =
                crypto::testing::rsa_import_pair(rsa_key_path)?;

            let (mut payload_tx, mut payload_rx) =
                mpsc::channel::<payloads::PayloadMessage>(1);

            let (mut keys_tx, mut keys_rx) = mpsc::channel::<(
                keys_handler::KeyMessage,
                Option<oneshot::Sender<keys_handler::SymmKeyMessage>>,
            )>(1);

            let (mut revocation_tx, mut revocation_rx) =
                mpsc::channel::<revocation::RevocationMessage>(1);

            let revocation_cert =
                PathBuf::from(test_config.agent.revocation_cert);

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

            // Allow setting the binary bios measurements log path when testing
            let mut measuredboot_ml_path =
                Path::new(&test_config.agent.measuredboot_ml_path);
            let env_mb_path: String;
            #[cfg(feature = "testing")]
            if let Ok(v) = std::env::var("TPM_BINARY_MEASUREMENTS") {
                env_mb_path = v;
                measuredboot_ml_path = Path::new(&env_mb_path);
            }

            let measuredboot_ml_file =
                match fs::File::open(measuredboot_ml_path) {
                    Ok(file) => Some(Mutex::new(file)),
                    Err(err) => None,
                };

            let api_versions = api::SUPPORTED_API_VERSIONS
                .iter()
                .map(|&s| s.to_string())
                .collect::<Vec<String>>();

            Ok((
                QuoteData {
                    api_versions,
                    tpmcontext: Mutex::new(ctx),
                    priv_key: nk_priv,
                    pub_key: nk_pub,
                    ak_handle,
                    keys_tx,
                    payload_tx,
                    revocation_tx,
                    hash_alg: keylime::algorithms::HashAlgorithm::Sha256,
                    enc_alg: keylime::algorithms::EncryptionAlgorithm::Rsa,
                    sign_alg: keylime::algorithms::SignAlgorithm::RsaSsa,
                    agent_uuid: test_config.agent.uuid,
                    allow_payload_revocation_actions: test_config
                        .agent
                        .allow_payload_revocation_actions,
                    secure_size: test_config.agent.secure_size,
                    work_dir,
                    ima_ml_file,
                    measuredboot_ml_file,
                    ima_ml: Mutex::new(MeasurementList::new()),
                    secure_mount,
                },
                mutex,
            ))
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
}
