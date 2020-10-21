#[macro_use]
use log::*;

#[macro_use]
use futures::future::try_join;
use ini;
use pretty_env_logger;

mod cmd_exec;
mod common;
mod crypto;
mod error;
mod hash;
mod keys_handler;
mod quotes_handler;
mod secure_mount;
mod tpm;

use actix_web::{web, App, HttpServer};
use common::config_get;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use error::{Error, Result};

static NOTFOUND: &[u8] = b"Not Found";

#[actix_web::main]
async fn main() -> Result<()> {
    let cloudagent_ip =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_ip")?;
    let cloudagent_port =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_port")?;
    let endpoint = format!("{}:{}", cloudagent_ip, cloudagent_port);
    info!("Starting server...");
    let server = HttpServer::new(move || {
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
    .bind("127.0.0.1:8080")?
    .run();
    try_join(server, run_revocation_service()).await?;
    Ok(())
}

async fn run_revocation_service() -> Result<()> {
    // revoker.await?;
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
