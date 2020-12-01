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
use tss_esapi::constants::algorithm::AsymmetricAlgorithm;
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

    // Request keyblob material
    let (key, cert, tpm_pub) =
        tpm::create_ek(&mut ctx, Some(AsymmetricAlgorithm::Rsa))?;

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

    // Placeholder BEGIN
    // The following will be removed on the final commit, these are just placeholders for now
    let ek = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmYicaAAArcin6fRZmzkc\nssyW5VFDWuB+FXF1HdEmJR4jEMdhlp8H9uAMwExY/+6aujElLJgBSKYPPeC7d/nI\nUIYc71oBxQEn6l3DTJO+1Nl1Wq6xYvlGrJMcuAFlznJCo0IF3MVLd45zEgdDmG5T\ntQ+EMAl64eC+aIG9Zp6InLbuZd3oisjE16TiK4Rg5dHAnfU6YSo9CIVSGw6PuCqX\n3aEyeikKNLGwX7ENp+fIVxj9Y00I5JoxDgD9ufLF7V55JVXKdZ0F51NghMyJRSt+\nkyEiqHPRRVTHw+248uziY4ioaDb3EBNKjnC/xcAdUoNxE4I1W8IW8UF/4td/AU11\nfwIDAQAB\n-----END PUBLIC KEY-----\n";
    let aik = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvRI0YcjxLLHFzBmVxO6I\nwuGri5ejIBaCb/XqirXgryXQYATmStk4WgdaDbZtW8JuLdYiTQftCFSP9iIo5jGA\nU443s/zXlWv15raraOsRlSdtSXAKv4dUFOc18GvyiL4ubrkHF5MnbdDlNoG5gZNS\nBV5/MIka5h4p7fpji93neoHNjbm/L3rSPknJnX4TVdxeOOV5izbkfD2TYD+rZ2nx\nzxqox/++dtl4yZ8jLEQnGAyFPMhMLHg8uZKNki2+DPM1oB7hKCHcG3QspVi4mOCc\nvDBt5+2VHakDi8dfFeTncHAQFqAWAHQfvYTo+EUPZpP3+49zBll/DnGt2He/GEvT\nFwIDAQAB\n-----END PUBLIC KEY-----\n";
    let ekcert = "MIID8zCCAlugAwIBAgIBIDANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1zd3RwbS1sb2NhbGNhMB4XDTIwMTIwMTExMzgwMVoXDTMwMTEyOTExMzgwMVowEjEQMA4GA1UEAxMHdW5rbm93bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMLEHnYAAWJY7AQ3pf5Iq08PNYtZfBVU2cVqrgR18oc5tjFxORObM6haNTfMQLge9wqbpB/jdMzTipIUh6GwIqDuioLKbe1Ag7yJHYmBZuFq5j/EY4IGH9+Zy2mvTVDIkx1zV0zDCopliZC6pmFJtVA6oRQD1drIlMFAb7oX5SilqQE+++PWR9BCEmFxpRla32F/ejcFIbP1+DhtwSPXbXGcw885FjCjOlPhXTeDdXXkipf9KtKHblfFsx1DD4hEviiYqt1XwPtgOZlabIsHV+KLHRzLGvjUtVmOP4QKY00LfhFH9b0+8vCIRBlhdISMXWDiv8QIxm2iq/jSGPdPJo8CAwEAAaOBzTCByjAQBgNVHSUECTAHBgVngQUIATBSBgNVHREBAf8ESDBGpEQwQjEWMBQGBWeBBQIBDAtpZDowMDAwMTAxNDEQMA4GBWeBBQICDAVzd3RwbTEWMBQGBWeBBQIDDAtpZDoyMDE3MDYxOTAMBgNVHRMBAf8EAjAAMCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCWMB8GA1UdIwQYMBaAFNZCf4X9wlnqDfz4wdpgGhA40JZIMA8GA1UdDwEB/wQFAwMHIAAwDQYJKoZIhvcNAQELBQADggGBAKqAAL6rA9JotB5jVr4JiCT3tuKKMHx0dIn2ioYPd7LWahWKcgCgSWqrRziDOVgoTGcWp+Jc2exQ0Rsle3SrdY+Vp4EODsIN3TRkJ0HtzP6NoacEJheKkAdcMhfJfDCam25Wdv1unIDbbwkjSqYR4qfiPOKTFIH4+Dl+uypuvECw5OAyMG64EDTV5aWKtNYkYf7h60Yo77gYNmAP6XJhk2QrMKhWH4RsJvibcXp5CC7dhJEvnCUAnRE85zS3eoppaxssfd+4EIcCqQRCY7a9kIAKBGtemIFgkOwrynxhSBjpMSfcU99tsuNnMnSOhqJRLoJ3wKncTaBiJbzJDwuzPAOYNoBTOiBWLQNThv0Ky4KyuLFkxWM9Q3zcecpxR2PL0hVskB7c0H5+urwDid6SZ7VZ7nWY0z3WexqUY6xRp1C6BtBGVeh6w3Vlu60c31k89mR6eC6K1j/iNHXBdvgGPqH23wPhOr5MeB+g+UOOSaR+EYkr7NF+ekUvItXtB/tY7Q==";
    let ekcert = base64::decode(ekcert).unwrap();
    let ek_tpm = "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAEMAEAgAAAAAAAEAmYicaAAArcin6fRZmzkcssyW5VFDWuB+FXF1HdEmJR4jEMdhlp8H9uAMwExY/+6aujElLJgBSKYPPeC7d/nIUIYc71oBxQEn6l3DTJO+1Nl1Wq6xYvlGrJMcuAFlznJCo0IF3MVLd45zEgdDmG5TtQ+EMAl64eC+aIG9Zp6InLbuZd3oisjE16TiK4Rg5dHAnfU6YSo9CIVSGw6PuCqX3aEyeikKNLGwX7ENp+fIVxj9Y00I5JoxDgD9ufLF7V55JVXKdZ0F51NghMyJRSt+kyEiqHPRRVTHw+248uziY4ioaDb3EBNKjnC/xcAdUoNxE4I1W8IW8UF/4td/AU11fw==";
    let ek_tpm = base64::decode(ek_tpm).unwrap();
    let aik_name = "000bb35615c533f39df1f1a30d35a42c2f9dc5b8a6a3c5332ec59e702d8e04a288fa";
    let agent_uuid_tmp = "D432FBB3-D2F1-4A97-9EF7-75BD81C00000";
    // placeholder END
    let mut keyblob = registrar_agent::do_register_agent(
        &registrar_ip,
        &registrar_port,
        &agent_uuid_tmp,
        &ek,
        &ekcert,
        &aik,
        &ek_tpm,
        &aik_name,
    )
    .await;
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
