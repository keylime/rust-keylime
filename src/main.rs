use actix_web::{web, App, HttpServer};
use common::config_get;
use error::{Error, Result};
use futures::future::TryFutureExt;
use futures::try_join;
use ini;
use log::*;
use pretty_env_logger;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

mod cmd_exec;
mod common;
mod crypto;
mod error;
mod hash;
mod keys_handler;
mod quotes_handler;
mod registrar_agent;
mod secure_mount;
mod tpm;

static NOTFOUND: &[u8] = b"Not Found";

#[actix_web::main]
async fn main() -> Result<()> {
    // Initialise Logger
    pretty_env_logger::init();

    // Initialise TPM connection
    let mut ctx = tpm::get_tpm2_ctx()?;

    //  Retreive the TPM Vendor, this allows us to warn if someone is using a
    // Software TPM ("SW")
    if tss_esapi::utils::get_tpm_vendor(&mut ctx)?.contains("SW") {
        warn!("INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.");
        warn!("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.");
        warn!("INSECURE: Only use Keylime in this mode for testing or debugging purposes.");
    }
    // Set up config params required
    let cloudagent_ip =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_ip")?;
    let cloudagent_port =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_port")?;
    let registrar_ip =
        config_get("/etc/keylime.conf", "registrar", "registrar_ip")?;
    let registrar_port =
        config_get("/etc/keylime.conf", "registrar", "registrar_port")?;
    let agent_uuid_confg =
        config_get("/etc/keylime.conf", "cloud_agent", "agent_uuid")?;

    // Setup the Agents UUID
    let section = match agent_uuid_confg.as_str() {
        "openstack" => {
            info!("Openstack placeholder...");
        }
        "hash_ek" => {
            info!("hash_ek placeholder...");
        }
        "generate" => {
            let agent_uuid = Uuid::new_v4();
            info!("Generated a new UUID: {}", &agent_uuid);
        }
        _ => {
            if Uuid::parse_str(&agent_uuid_confg).is_ok() == false {
                error!("Invalid UUID: {:?}", &agent_uuid_confg);
                let agent_uuid = Uuid::new_v4();
                info!("Generated a new UUID: {}", &agent_uuid);
            }
        }
    };
    // TODO: before we registar the agent, we require artifacts from the TPM (such as ek, aik etc)
    // register the agent
    // let keyblob = registrar_agent::doRegisterAgent(registrar_ip, registrar_port, agent_uuid, ek, ekcert, aik, ek_tpm, aik_name).await?;
    // TODO: After keyblob is returned we need to activate indentity
    // key = tpm.activate_identity(keyblob)

    let actix_server = HttpServer::new(move || {
        App::new()
            .service(
                web::resource("/keys/verify")
                    .route(web::get().to(keys_handler::verify)),
            )
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
    info!("Listening on http://{}:{}", cloudagent_ip, cloudagent_port);
    try_join!(actix_server, run_revocation_service())?;
    Ok(())
}

async fn run_revocation_service() -> Result<()> {
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
    buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    fn init_logger() {
        pretty_env_logger::init();
        info!("Initialized logger for testing suite.");
        assert!(true);
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
