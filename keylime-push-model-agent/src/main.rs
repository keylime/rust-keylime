// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use clap::Parser;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::time::Duration;
mod struct_filler;

const DEFAULT_TIMEOUT_MILLIS: &str = "5000";

fn get_id() -> String {
    "1234".to_string()
}

fn get_attestation_request_url(url: &str) -> String {
    let id = get_id();
    format!("{url}/agents/{id}/attestations")
}

fn get_https_client(args: &Args) -> Result<reqwest::Client, Box<dyn Error>> {
    let mut buf = Vec::new();
    File::open(args.certificate.clone())?.read_to_end(&mut buf)?;
    let id = reqwest::Certificate::from_pem(&buf)?;
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(id)
        .timeout(Duration::from_millis(args.timeout))
        .build()?)
}

fn get_client(args: &Args) -> Result<reqwest::Client, Box<dyn Error>> {
    if args.verifier_url.starts_with("https://") {
        return get_https_client(args);
    }
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout))
        .build()?)
}

async fn send_attestation_request(
    args: &Args,
) -> Result<String, Box<dyn Error>> {
    let request = struct_filler::get_attestation_request();
    let serialized = serde_json::to_string(&request).unwrap();
    println!("Serialized Request: {}", serialized);
    let client = get_client(args)?;

    let response = client
        .post(get_attestation_request_url(&args.verifier_url).as_str())
        .header("Content-Type", "application/json")
        .header("Content-Length", serialized.len().to_string())
        .body(serialized)
        .timeout(Duration::from_millis(args.timeout))
        .send()
        .await?;
    let response_body = response.text().await?;
    println!("Response body:{}", response_body);
    Ok(response_body)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, ignore_errors = true)]
struct Args {
    /// certificate file
    #[arg(short, long, default_value = "/etc/keylime/ca/cacert.pem")]
    certificate: String,
    /// Timeout in milliseconds
    /// Default: 5000
    #[arg(long, default_value = DEFAULT_TIMEOUT_MILLIS)]
    timeout: u64,
    /// Verifier URL
    #[arg(short, long, default_value = "https://127.0.0.1:8881")]
    verifier_url: String,
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("Verifier URL: {}", args.verifier_url);
    println!("Timeout: {}", args.timeout);
    println!("Certificate file: {}", args.certificate);
    let res = send_attestation_request(&args).await;
    match res {
        Ok(_) => println!("Request sent successfully"),
        Err(e) => eprintln!("Error: {}", e),
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_TIMEOUT_MILLIS: u64 = 100;

    #[actix_rt::test]
    async fn send_attestation_request_test() {
        match send_attestation_request(&Args {
            verifier_url: "http://1.2.3.4:5678".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/etc/keylime/ca/cacert.pem".to_string(),
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e.to_string().contains("error sending request"))
            }
        }
    }

    #[actix_rt::test]
    async fn send_attestation_request_test_no_cert_file() {
        match send_attestation_request(&Args {
            verifier_url: "https://1.2.3.4:5678".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/unexisting_cert_file".to_string(),
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e.to_string().contains("No such file or directory"))
            }
        }
    }

    #[actix_rt::test]
    async fn send_attestation_request_test_on_https() {
        use std::process::Command;
        let output = Command::new("/usr/bin/touch")
            .arg("/tmp/test_cert_file")
            .output()
            .unwrap();
        assert!(output.status.success());

        match send_attestation_request(&Args {
            verifier_url: "https://1.2.3.4:5678".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/test_cert_file".to_string(),
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e.to_string().contains("error sending request"))
            }
        }
        let output = Command::new("/usr/bin/rm")
            .arg("/tmp/test_cert_file")
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[actix_rt::test]
    async fn run_test() {
        let res = run();
        assert!(res.await.is_ok());
    }
}
