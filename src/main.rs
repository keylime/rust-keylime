#[macro_use]
use log::*;

#[macro_use]
use futures::try_join;
use hyper;
use ini;
use pretty_env_logger;

mod cmd_exec;
mod common;
mod crypto;
mod error;
mod handlers;
mod hash;
mod secure_mount;
mod tpm;

use common::config_get;
use common::set_response_content;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use error::{Error, Result};

static NOTFOUND: &[u8] = b"Not Found";

#[tokio::main]
async fn main() -> Result<()> {
    match run().await {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("Error occured: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<()> {
    pretty_env_logger::init();
    // Get a context to work with the TPM
    let mut ctx = tpm::get_tpm2_ctx()?;

    // queue up future events
    let server = runWebServer();
    let revoker = runRevocationService();

    // run future events
    try_join!(server, revoker)?;
    Ok(())
}

async fn runWebServer() -> Result<()> {
    let cloudagent_ip =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_ip")?;
    let cloudagent_port =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_port")?;
    let endpoint = format!("{}:{}", cloudagent_ip, cloudagent_port);

    info!("Starting server...");

    let addr = (endpoint).parse().expect("Cannot parse IP & Port");

    let service = make_service_fn(|_| async {
        Ok::<_, Error>(service_fn(handlers::response_function))
    });
    let server = Server::bind(&addr).serve(service);

    info!("Listening on http://{}", addr);

    server.await?;
    Ok(())
}

async fn runRevocationService() -> Result<()> {
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
