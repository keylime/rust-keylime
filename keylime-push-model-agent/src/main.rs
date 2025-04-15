// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use crate::struct_filler::StructureFiller;
use clap::Parser;
use log::{debug, error, info};
use std::{error::Error, fs::File, io::Read, time::Duration};
mod struct_filler;

const DEFAULT_TIMEOUT_MILLIS: &str = "5000";
const HTTPS_PREFIX: &str = "https://";
const DEFAULT_API_VERSION: &str = "v3.0";

fn get_api_version(args: &Args) -> String {
    if args.api_version.is_some() {
        return args.api_version.clone().unwrap();
    }
    DEFAULT_API_VERSION.to_string()
}

fn get_attestation_request_url(args: &Args) -> String {
    let id = args.id.clone();
    let verifier_url = args.verifier_url.clone();
    let api_version = get_api_version(args);
    if verifier_url.ends_with('/') {
        return format!(
            "{verifier_url}{api_version}/agents/{id}/attestations"
        );
    }
    format!("{verifier_url}/{api_version}/agents/{id}/attestations")
}

fn get_https_client(args: &Args) -> Result<reqwest::Client, Box<dyn Error>> {
    let mut builder = reqwest::Client::builder()
        .connection_verbose(true)
        .timeout(Duration::from_millis(args.timeout));

    if args.insecure.unwrap_or(false) {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        let mut buf = Vec::new();
        File::open(args.certificate.clone())?.read_to_end(&mut buf)?;
        let cert = reqwest::Certificate::from_pem(&buf)?;
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder.build()?)
}

fn get_client(args: &Args) -> Result<reqwest::Client, Box<dyn Error>> {
    if args.verifier_url.starts_with(HTTPS_PREFIX) {
        return get_https_client(args);
    }
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout))
        .build()?)
}

fn get_attestation_filler_request(args: &Args) -> Box<dyn StructureFiller> {
    if args.json_file.is_none() {
        return Box::new(struct_filler::AttestationRequestFillerFromCode {});
    }
    Box::new(struct_filler::AttestationRequestFillerFromFile {
        file_path: args.json_file.clone().unwrap(),
    })
}

fn get_request_builder_from_method(
    args: &Args,
) -> Result<reqwest::RequestBuilder, Box<dyn Error>> {
    let client = get_client(args)?;
    match args.method.as_deref() {
        Some("POST") => {
            Ok(client.post(get_attestation_request_url(args).as_str()))
        }
        Some("PUT") => {
            Ok(client.put(get_attestation_request_url(args).as_str()))
        }
        Some("DELETE") => {
            Ok(client.delete(get_attestation_request_url(args).as_str()))
        }
        Some("GET") => {
            Ok(client.get(get_attestation_request_url(args).as_str()))
        }
        Some("PATCH") => {
            Ok(client.patch(get_attestation_request_url(args).as_str()))
        }
        _ => Ok(client.post(get_attestation_request_url(args).as_str())),
    }
}

async fn send_attestation_request(
    args: &Args,
) -> Result<String, Box<dyn Error>> {
    let filler = get_attestation_filler_request(args);
    let request = filler.get_attestation_request();
    let serialized = serde_json::to_string(&request).unwrap();
    info!("Serialized Request: {}", serialized);
    let reqb = get_request_builder_from_method(args)?;

    let response = reqb
        .header("Content-Type", "application/json")
        .header("Content-Length", serialized.len().to_string())
        .body(serialized)
        .timeout(Duration::from_millis(args.timeout))
        .send()
        .await?;
    info!("Response code:{}", response.status());
    info!("Response headers: {:?}", response.headers());
    let response_body = response.text().await?;
    if !response_body.is_empty() {
        info!("Response body: {}", response_body);
    }
    Ok(response_body)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, ignore_errors = true)]
struct Args {
    /// API version
    /// Default: "v3.0"
    #[arg(long, default_value = DEFAULT_API_VERSION)]
    api_version: Option<String>,
    /// certificate file
    #[arg(short, long, default_value = "/etc/keylime/ca/cacert.crt")]
    certificate: String,
    /// json file
    #[arg(short, long, default_missing_value = "")]
    json_file: Option<String>,
    /// identifier
    /// Default: 12345678
    #[arg(long, default_value = "12345678")]
    id: String,
    /// insecure
    #[arg(long, action, default_missing_value = "true")]
    insecure: Option<bool>,
    /// Method
    /// Default: "POST"
    #[arg(long, default_value = "POST")]
    method: Option<String>,
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
    info!("API version: {}", get_api_version(&args));
    info!("Verifier URL: {}", args.verifier_url);
    debug!("Timeout: {}", args.timeout);
    debug!("Certificate file: {}", args.certificate);
    debug!("Insecure: {}", args.insecure.unwrap_or(false));
    let res = send_attestation_request(&args).await;
    match res {
        Ok(_) => info!("Request sent successfully"),
        Err(e) => error!("Error: {}", e),
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_TIMEOUT_MILLIS: u64 = 100;

    #[actix_rt::test]
    async fn send_attestation_request_test() {
        if (send_attestation_request(&Args {
            api_version: Some("v3.0".to_string()),
            verifier_url: "http://1.2.3.4:5678".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/does_not_exist.pem".to_string(),
            insecure: Some(false),
            id: "12345678".to_string(),
            json_file: None,
            method: None,
        })
        .await)
            .is_ok()
        {
            unreachable!()
        }
    }

    #[actix_rt::test]
    async fn send_attestation_request_test_no_cert_file() {
        match send_attestation_request(&Args {
            api_version: Some("v3.0".to_string()),
            verifier_url: "https://1.2.3.4:5678".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/unexisting_cert_file".to_string(),
            insecure: Some(false),
            id: "12345678".to_string(),
            json_file: None,
            method: None,
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
            api_version: Some("3.0".to_string()),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/test_cert_file".to_string(),
            insecure: Some(false),
            id: "12345678".to_string(),
            json_file: None,
            method: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert_eq!(e.to_string(), "builder error")
            }
        }
        match send_attestation_request(&Args {
            api_version: Some("3.0".to_string()),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/test_cert_file".to_string(),
            insecure: Some(true),
            id: "12345678".to_string(),
            json_file: None,
            method: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e.to_string().contains("error sending request"))
            }
        }
        match send_attestation_request(&Args {
            api_version: Some("3.0".to_string()),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/test_cert_file".to_string(),
            insecure: Some(true),
            id: "12345678".to_string(),
            json_file: Some(
                "./tests/evidence_supported_attestation_request.json"
                    .to_string(),
            ),
            method: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e.to_string().contains("error sending request"))
            }
        }
        // Clean up the test certificate file
        let output = Command::new("/usr/bin/rm")
            .arg("/tmp/test_cert_file")
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[actix_rt::test]
    async fn different_methods_test() {
        // array with the different methods:
        let methods = vec!["DELETE", "GET", "PATCH", "POST", "PUT"];
        for method in methods {
            match send_attestation_request(&Args {
                api_version: None,
                verifier_url: "http://1.2.3.4:5678".to_string(),
                timeout: TEST_TIMEOUT_MILLIS,
                certificate: "/tmp/does_not_exists.pem".to_string(),
                insecure: Some(false),
                id: "12345678".to_string(),
                json_file: None,
                method: Some(method.to_string()),
            })
            .await
            {
                Ok(_) => unreachable!(),
                Err(e) => {
                    assert!(e.to_string().contains("error sending request"));
                }
            }
        }
    }

    #[actix_rt::test]
    async fn get_attestation_request_url_test() {
        let url = get_attestation_request_url(&Args {
            api_version: None,
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            certificate: "/tmp/does_not_exists.pem".to_string(),
            insecure: Some(false),
            id: "12345678".to_string(),
            json_file: None,
            method: None,
        });
        assert_eq!(
            url,
            "https://1.2.3.4:5678/v3.0/agents/12345678/attestations"
        );
    } // get_attestation_request_url_test

    #[actix_rt::test]
    async fn run_test() {
        let res = run();
        assert!(res.await.is_ok());
    }
}
