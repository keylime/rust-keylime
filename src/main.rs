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

mod cmd_exec;
mod common;
mod crypto;
mod error;
mod hash;
mod keys_handler;
mod quotes_handler;
mod registrar_agent;
mod revocation;
mod secure_mount;
mod tpm;

use actix_web::{web, App, HttpServer};
use common::*;
use error::{Error, Result};
use futures::{future::TryFutureExt, try_join};
use log::*;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use std::{
    convert::TryFrom,
    fs::File,
    io::{BufReader, Read},
    path::Path,
};
use tss_esapi::{
    interface_types::{
        algorithm::AsymmetricAlgorithm, resource_handles::Hierarchy,
    },
    utils,
};
use uuid::Uuid;

static NOTFOUND: &[u8] = b"Not Found";

fn get_uuid(agent_uuid_config: &str) -> String {
    match agent_uuid_config {
        "openstack" => {
            info!("Openstack placeholder...");
            "openstack".into()
        }
        "hash_ek" => {
            info!("hash_ek placeholder...");
            "hash_ek".into()
        }
        "generate" => {
            let agent_uuid = Uuid::new_v4();
            info!("Generated a new UUID: {}", &agent_uuid);
            agent_uuid.to_string()
        }
        uuid_config => match Uuid::parse_str(uuid_config) {
            Ok(uuid_config) => uuid_config.to_string(),
            Err(_) => {
                info!("Misformatted UUID: {}", &uuid_config);
                let agent_uuid = Uuid::new_v4();
                agent_uuid.to_string()
            }
        },
    }
}

#[actix_web::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    let mut ctx = tpm::get_tpm2_ctx()?;
    //  Retreive the TPM Vendor, this allows us to warn if someone is using a
    // Software TPM ("SW")
    if tss_esapi::utils::get_tpm_vendor(&mut ctx)?.contains("SW") {
        warn!("INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.");
        warn!("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.");
        warn!("INSECURE: Only use Keylime in this mode for testing or debugging purposes.");
    }

    info!("Starting server...");

    // Gather EK and AK key values and certs
    let (ek_handle, ek_cert, ek_tpm2b_pub) =
        tpm::create_ek(&mut ctx, Some(AsymmetricAlgorithm::Rsa))?;

    let (ak_handle, ak_name, ak_tpm2b_pub) =
        tpm::create_ak(&mut ctx, ek_handle)?;

    // Gather configs
    let cloudagent_ip = cloudagent_ip_get()?;
    let cloudagent_port = cloudagent_port_get()?;
    let registrar_ip = registrar_ip_get()?;
    let registrar_port = registrar_port_get()?;
    let agent_uuid_config = config_get("cloud_agent", "agent_uuid")?;
    let agent_uuid = get_uuid(&agent_uuid_config);

    {
        // Request keyblob material
        let keyblob = registrar_agent::do_register_agent(
            &registrar_ip,
            &registrar_port,
            &agent_uuid,
            &ek_tpm2b_pub,
            &ek_cert,
            &ak_tpm2b_pub,
        )
        .await?;
        info!("SUCCESS: agent registered");

        let key = tpm::activate_credential(
            &mut ctx, keyblob, ak_handle, ek_handle,
        )?;
        let mackey = base64::encode(key.value());
        let mackey = PKey::hmac(&mackey.as_bytes())?;
        let mut signer = Signer::new(MessageDigest::sha384(), &mackey)?;
        signer.update(agent_uuid.as_bytes());
        let auth_tag = signer.sign_to_vec()?;
        let auth_tag = hex::encode(&auth_tag);

        registrar_agent::do_activate_agent(
            &registrar_ip,
            &registrar_port,
            &agent_uuid,
            &auth_tag,
        )
        .await?;
        info!("SUCCESS: agent activated");
    }

    // Service identity quote requests from the tenant
    let identity_server = HttpServer::new(move || {
        App::new()
            .data(crate::crypto::rsa_generate(2048).unwrap()) //#[allow_ci]
            .service(
                web::resource("/keys/ukey")
                    .route(web::post().to(keys_handler::ukey)),
            )
            .service(
                web::resource("/quotes/identity")
                    .route(web::get().to(quotes_handler::identity)),
            )
    })
    .bind(format!("{}:{}", cloudagent_ip, cloudagent_port))?
    .run()
    .map_err(|x| x.into());

    // Service integrity quote requests from the verifier
    let integrity_server = HttpServer::new(move || {
        App::new()
            .data(crate::crypto::rsa_generate(2048).unwrap()) //#[allow_ci]
            // todo: add vkey request service
            .service(
                web::resource("/quotes/integrity")
                    .route(web::get().to(quotes_handler::integrity)),
            )
    })
    .bind(format!("{}:{}", cloudagent_ip, cloudagent_port))?
    .run()
    .map_err(|x| x.into());

    // Other
    let verify_server = HttpServer::new(move || {
        App::new().service(
            web::resource("/keys/verify")
                .route(web::get().to(keys_handler::verify)),
        )
    })
    .bind(format!("{}:{}", cloudagent_ip, cloudagent_port))?
    .run()
    .map_err(|x| x.into());

    info!("Listening on http://{}:{}", cloudagent_ip, cloudagent_port);
    try_join!(
        identity_server,
        integrity_server,
        verify_server,
        revocation::run_revocation_service()
    )?;
    Ok(())
}

/*
 * Input: file path
 * Output: file content
 *
 * Helper function to help the keylime agent read file and get the file
 * content. It is not from the original python version. Because rust needs
 * to handle error in result, it is good to keep this function seperate from
 * the main function.
 */
fn read_in_file(path: String) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    let _ = buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
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
    fn test_get_uuid() {
        assert_eq!(get_uuid("openstack"), "openstack");
        assert_eq!(get_uuid("hash_ek"), "hash_ek");
        let _ = Uuid::parse_str(&get_uuid("generate")).unwrap(); //#[allow_ci]
        assert_eq!(
            get_uuid("D432FBB3-D2F1-4A97-9EF7-75BD81C00000"),
            "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        );
        assert_ne!(
            get_uuid("D432FBB3-D2F1-4A97-9EF7-75BD81C0000X"),
            "d432fbb3-d2f1-4a97-9ef7-75bd81c0000X"
        );
        let _ = Uuid::parse_str(&get_uuid(
            "D432FBB3-D2F1-4A97-9EF7-75BD81C0000X",
        ))
        .unwrap(); //#[allow_ci]
    }
}
