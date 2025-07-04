// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use anyhow::{Context, Result};
use clap::Parser;
use keylime::config::PushModelConfigTrait;
use keylime::context_info;
use log::{debug, error, info};
use std::time::Duration;
mod json_dump;
mod registration;
mod struct_filler;
mod url_selector;
use std::sync::OnceLock;
static GLOBAL_CONTEXT: OnceLock<Result<Option<context_info::ContextInfo>>> =
    OnceLock::new();

const DEFAULT_TIMEOUT_MILLIS: &str = "5000";
const HTTPS_PREFIX: &str = "https://";
const DEFAULT_METHOD: &str = "POST";
const DEFAULT_MESSAGE_TYPE: MessageType = MessageType::Attestation;
const DEFAULT_MESSAGE_TYPE_STR: &str = "Attestation";

pub enum MessageType {
    Attestation,
    EvidenceHandling,
    Session,
}

pub struct ResponseInformation {
    pub status_code: reqwest::StatusCode,
    pub body: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, ignore_errors = true)]
struct Args {
    /// identifier
    /// Default: 12345678
    #[arg(long, default_missing_value = "12345678")]
    agent_identifier: Option<String>,
    /// API version
    /// Default: "v3.0"
    #[arg(long, default_value = url_selector::DEFAULT_API_VERSION)]
    api_version: Option<String>,
    /// CA certificate file
    #[arg(long, default_value = "/var/lib/keylime/cv_ca/cacert.crt")]
    ca_certificate: String,
    /// Client certificate file
    #[arg(
        short,
        long,
        default_value = "/var/lib/keylime/cv_ca/client-cert.crt"
    )]
    certificate: String,
    /// Client private key file
    #[arg(
        short,
        long,
        default_value = "/var/lib/keylime/cv_ca/client-private.pem"
    )]
    key: String,
    /// json file
    #[arg(short, long, default_missing_value = "")]
    json_file: Option<String>,
    /// index
    /// Default: 1
    #[arg(long, default_value = "1")]
    attestation_index: Option<String>,
    /// insecure
    #[arg(long, action, default_missing_value = "true")]
    insecure: Option<bool>,
    /// Type of message
    /// Default: "Attestation"
    #[arg(long, default_value = DEFAULT_MESSAGE_TYPE_STR)]
    message_type: Option<String>,
    /// Method
    /// Default: "POST"
    #[arg(long, default_missing_value = DEFAULT_METHOD)]
    method: Option<String>,
    /// Registrar URL
    /// Default: "http://127.0.0.1:8888"
    #[arg(long, default_value = "http://127.0.0.1:8888")]
    registrar_url: String,
    /// Session ID
    /// Default: 1
    #[arg(long, default_missing_value = "1", default_value = "1")]
    session_index: Option<String>,
    /// Timeout in milliseconds
    /// Default: 5000
    #[arg(long, default_value = DEFAULT_TIMEOUT_MILLIS)]
    timeout: u64,
    /// Verifier URL
    #[arg(short, long, default_value = "https://127.0.0.1:8881")]
    verifier_url: String,
    /// avoid tpm
    /// Default: false
    #[arg(long, action, default_missing_value = "false")]
    avoid_tpm: Option<bool>,
}

fn get_message_type(args: &Args) -> MessageType {
    if args.message_type.is_some() {
        match args.message_type.as_ref().unwrap().as_str() {
            "Attestation" => return MessageType::Attestation,
            "EvidenceHandling" => return MessageType::EvidenceHandling,
            "Session" => return MessageType::Session,
            _ => {}
        }
    }
    DEFAULT_MESSAGE_TYPE
}

fn get_client(args: &Args) -> Result<reqwest::Client> {
    if args.verifier_url.starts_with(HTTPS_PREFIX) {
        return keylime::https_client::get_https_client(
            &keylime::https_client::ClientArgs {
                ca_certificate: args.ca_certificate.clone(),
                certificate: args.certificate.clone(),
                key: args.key.clone(),
                insecure: args.insecure,
                timeout: args.timeout,
            },
        );
    }
    reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout))
        .build()
        .context("Failed to build plain HTTP client")
}

fn get_request_builder_from_method(
    args: &Args,
) -> Result<reqwest::RequestBuilder> {
    let client = get_client(args)?;
    // TODO: Change config obtaining here to avoid repetitions
    let agent_identifier = match &args.agent_identifier {
        Some(id) => id.clone(),
        None => keylime::config::PushModelConfig::default().get_uuid(),
    };
    let url_args = url_selector::UrlArgs {
        verifier_url: args.verifier_url.clone(),
        api_version: args.api_version.clone(),
        session_index: args.session_index.clone(),
        agent_identifier: Some(agent_identifier),
        attestation_index: args.attestation_index.clone(),
    };
    let url = url_selector::get_url_from_message_type(
        &url_args,
        &get_message_type(args),
    );
    debug!("Request builder URL: {}", url);
    match args.method.as_deref() {
        Some("POST") => Ok(client.post(url)),
        Some("PUT") => Ok(client.put(url)),
        Some("DELETE") => Ok(client.delete(url)),
        Some("GET") => Ok(client.get(url)),
        Some("PATCH") => Ok(client.patch(url)),
        _ => Ok(client.post(url)),
    }
}

async fn send_push_model_request(args: &Args) -> Result<ResponseInformation> {
    let mut context_info = get_context(args).map_err(|e| {
        error!("Error obtaining context information: {}", e);
        e
    })?;
    let mut filler = struct_filler::get_filler_request(
        args.json_file.clone(),
        context_info.as_mut(),
    );

    let message_type = get_message_type(args);
    let json_value = match message_type {
        MessageType::Attestation => {
            json_dump::dump_attestation_request_to_value(
                &filler.get_attestation_request(),
            )
        }
        MessageType::EvidenceHandling => {
            json_dump::dump_evidence_handling_request_to_value(
                &filler.get_evidence_handling_request(),
            )
        }
        MessageType::Session => json_dump::dump_session_request_to_value(
            &filler.get_session_request(),
        ),
    };
    let reqb = get_request_builder_from_method(args)?;
    let reqcontent = json_value.unwrap().to_string();
    debug!("Request body: {:?}", reqcontent);
    let response = reqb
        .body(reqcontent)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .timeout(Duration::from_millis(args.timeout))
        .send()
        .await?;
    let sc = response.status();
    info!("Response code:{}", response.status());
    info!("Response headers: {:?}", response.headers());
    let response_body = response.text().await?;
    if !response_body.is_empty() {
        info!("Response body: {}", response_body);
    }
    let rsp = ResponseInformation {
        status_code: sc,
        body: response_body,
    };
    Ok(rsp)
}

fn init_context(args: &Args) -> Result<()> {
    let result = GLOBAL_CONTEXT.set(
        || -> Result<Option<context_info::ContextInfo>> {
            if args.avoid_tpm.unwrap_or(false) {
                return Ok(None);
            }
            let config = keylime::config::PushModelConfig::default();
            debug!("Initializing unique TPM Context...");
            let context_info = context_info::ContextInfo::new_from_str(
                context_info::AlgorithmConfigurationString {
                    tpm_encryption_alg: config.get_tpm_encryption_alg(),
                    tpm_hash_alg: config.get_tpm_hash_alg(),
                    tpm_signing_alg: config.get_tpm_signing_alg(),
                    agent_data_path: config.get_agent_data_path(),
                },
            )?;
            Ok(Some(context_info))
        }(),
    );
    if result.is_err() {
        error!("Error: Agent context has already been initialized.");
    }
    Ok(())
}

fn get_context(args: &Args) -> Result<Option<context_info::ContextInfo>> {
    if args.avoid_tpm.unwrap_or(false) {
        return Ok(None);
    }
    match GLOBAL_CONTEXT.get() {
        Some(context_result) => {
            match context_result {
                Ok(Some(context_info)) => Ok(Some(context_info.clone())),
                Ok(None) => Ok(None),
                Err(e) => Err(anyhow::anyhow!("TPM Global context could not be initialized {}", e)),
            }
        },
        None => {
           Err(anyhow::anyhow!("TPM Global context has not been initialized yet. Please call init_context first."))
        }
    }
}

async fn run(args: &Args) -> Result<()> {
    info!("Verifier URL: {}", args.verifier_url);
    info!("Registrar URL: {}", args.registrar_url);
    debug!("Timeout: {}", args.timeout);
    debug!("CA certificate file: {}", args.ca_certificate);
    debug!(
        "Method: {}",
        args.method.clone().unwrap_or(DEFAULT_METHOD.to_string())
    );
    debug!("Certificate file: {}", args.certificate);
    debug!("Key file: {}", args.key);
    debug!("Insecure: {}", args.insecure.unwrap_or(false));
    debug!("Avoid TPM: {}", args.avoid_tpm.unwrap_or(false));
    init_context(args)?;
    let ctx_info = match get_context(args) {
        Ok(Some(context_info)) => Some(context_info),
        Ok(None) => {
            error!("No context");
            None
        }
        Err(e) => {
            error!("Error obtaining context information: {}", e);
            return Err(e);
        }
    };
    let res = crate::registration::check_registration(ctx_info).await;
    match res {
        Ok(_) => {}
        Err(ref e) => error!("Could not register appropriately: {}", e),
    }

    let res = send_push_model_request(args).await;
    match res {
        Ok(_) => {
            info!("Request sent successfully");
            info!(
                "Returned response code: {:?}",
                res.as_ref().unwrap().status_code
            );
            info!("Returned response body: {:?}", res.as_ref().unwrap().body);
        }
        Err(ref e) => error!("Error: {}", e),
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    run(&Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_TIMEOUT_MILLIS: u64 = 100;

    #[actix_rt::test]
    async fn send_attestation_request_test() {
        for att_idx in [None, Some("1".to_string())] {
            if (send_push_model_request(&Args {
                api_version: Some("v3.0".to_string()),
                avoid_tpm: Some(true),
                verifier_url: "http://1.2.3.4:5678".to_string(),
                registrar_url: "http://1.2.3.4:8888".to_string(),
                timeout: TEST_TIMEOUT_MILLIS,
                ca_certificate: "/tmp/does_not_exist.pem".to_string(),
                certificate: "/tmp/does_not_exist.pem".to_string(),
                key: "/tmp/does_not_exist.pem".to_string(),
                insecure: Some(false),
                agent_identifier: Some("12345678".to_string()),
                json_file: None,
                message_type: Some("Attestation".to_string()),
                method: None,
                attestation_index: att_idx,
                session_index: None,
            })
            .await)
                .is_ok()
            {
                unreachable!()
            }
        }
    }

    #[actix_rt::test]
    async fn send_attestation_request_test_no_cert_file() {
        match send_push_model_request(&Args {
            api_version: Some("v3.0".to_string()),
            avoid_tpm: Some(true),
            registrar_url: "http://1.2.3.4:8888".to_string(),
            verifier_url: "https://1.2.3.4:5678".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: "/tmp/unexisting_cert_file".to_string(),
            certificate: "/tmp/unexisting_cert_file".to_string(),
            key: "/tmp/unexisting_key_file".to_string(),
            insecure: Some(false),
            agent_identifier: Some("12345678".to_string()),
            json_file: None,
            method: None,
            message_type: Some("Attestation".to_string()),
            attestation_index: None,
            session_index: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(
                    e.to_string().contains(
                        "Failed to open '/tmp/unexisting_cert_file' file"
                    ),
                    "Unexpected error"
                )
            }
        }
    }

    #[actix_rt::test]
    async fn send_attestation_request_test_on_https() {
        use std::fs::File;
        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let ca_cert_file_path = temp_workdir.path().join("test_ca_cert_file");
        let _ca_cert_file = File::create(&ca_cert_file_path)
            .expect("Failed to create CA cert file");
        let cert_file_path = temp_workdir.path().join("test_cert_file");
        let _cert_file = File::create(&cert_file_path)
            .expect("Failed to create cert file");
        let key_file_path = temp_workdir.path().join("test_key_file");
        let _key_file =
            File::create(&key_file_path).expect("Failed to create key file");

        match send_push_model_request(&Args {
            api_version: Some("3.0".to_string()),
            avoid_tpm: Some(true),
            registrar_url: "http://1.2.3.4:8888".to_string(),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: ca_cert_file_path.display().to_string(),
            certificate: cert_file_path.display().to_string(),
            key: key_file_path.display().to_string(),
            insecure: Some(false),
            agent_identifier: Some("12345678".to_string()),
            json_file: None,
            message_type: Some("Attestation".to_string()),
            method: None,
            attestation_index: None,
            session_index: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    format!(
                        "Failed to parse certificate from PEM file '{}'",
                        ca_cert_file_path.display()
                    )
                )
            }
        }
        match send_push_model_request(&Args {
            api_version: Some("3.0".to_string()),
            avoid_tpm: Some(true),
            registrar_url: "http://1.2.3.4:8888".to_string(),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: ca_cert_file_path.display().to_string(),
            certificate: cert_file_path.display().to_string(),
            key: key_file_path.display().to_string(),
            insecure: Some(true),
            agent_identifier: Some("12345678".to_string()),
            attestation_index: None,
            json_file: None,
            message_type: Some("Attestation".to_string()),
            method: None,
            session_index: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("error sending request for url (https://1.2.3.4:5678/3.0/agents/12345678/attestations)"))
            }
        }
        match send_push_model_request(&Args {
            api_version: Some("3.0".to_string()),
            avoid_tpm: Some(true),
            registrar_url: "http://1.2.3.4:8888".to_string(),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: ca_cert_file_path.display().to_string(),
            certificate: cert_file_path.display().to_string(),
            key: key_file_path.display().to_string(),
            insecure: Some(true),
            agent_identifier: Some("12345678".to_string()),
            json_file: Some(
                "./test-data/evidence_supported_attestation_request.json"
                    .to_string(),
            ),
            message_type: Some("Attestation".to_string()),
            method: None,
            attestation_index: None,
            session_index: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("error sending request for url (https://1.2.3.4:5678/3.0/agents/12345678/attestations)"))
            }
        }
    }

    #[actix_rt::test]
    async fn send_evidence_handling_request_test() {
        for attestation_idx in [None, Some("3".to_string())] {
            match send_push_model_request(&Args {
                api_version: Some("3.0".to_string()),
                avoid_tpm: Some(true),
                registrar_url: "http://1.2.3.4:8888".to_string(),
                verifier_url: "https://1.2.3.4:5678/".to_string(),
                timeout: TEST_TIMEOUT_MILLIS,
                ca_certificate: "/tmp/does_not_exists.pem".to_string(),
                certificate: "/tmp/does_not_exists.pem".to_string(),
                key: "/tmp/does_not_exists.pem".to_string(),
                insecure: Some(true),
                agent_identifier: Some("12345678".to_string()),
                json_file: None,
                message_type: Some("EvidenceHandling".to_string()),
                method: None,
                attestation_index: attestation_idx,
                session_index: None,
            })
            .await
            {
                Ok(_) => unreachable!(),
                Err(e) => {
                    assert!(e
                        .to_string()
                        .contains("error sending request for url (https://1.2.3.4:5678/3.0/agents/12345678/attestations"))
                }
            }
        }
    } // send_evidence_handling_request_test

    #[actix_rt::test]
    async fn send_session_request_test() {
        match send_push_model_request(&Args {
            api_version: Some("3.0".to_string()),
            avoid_tpm: Some(true),
            registrar_url: "http://1.2.3.4:8888".to_string(),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: "/tmp/does_not_exists.pem".to_string(),
            certificate: "/tmp/does_not_exists.pem".to_string(),
            key: "/tmp/does_not_exists.pem".to_string(),
            insecure: Some(true),
            agent_identifier: Some("12345678".to_string()),
            json_file: None,
            message_type: Some("Session".to_string()),
            method: Some("POST".to_string()),
            attestation_index: None,
            session_index: None,
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("error sending request for url (https://1.2.3.4:5678/3.0/sessions)"))
            }
        }
        match send_push_model_request(&Args {
            api_version: Some("3.0".to_string()),
            avoid_tpm: Some(true),
            registrar_url: "http://1.2.3.4:8888".to_string(),
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: "/tmp/does_not_exists.pem".to_string(),
            certificate: "/tmp/does_not_exists.pem".to_string(),
            key: "/tmp/does_not_exists.pem".to_string(),
            insecure: Some(true),
            agent_identifier: Some("12345678".to_string()),
            json_file: None,
            message_type: Some("Session".to_string()),
            method: Some("PATCH".to_string()),
            attestation_index: None,
            session_index: Some("2244668800".to_string()),
        })
        .await
        {
            Ok(_) => unreachable!(),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    "error sending request for url (https://1.2.3.4:5678/3.0/sessions/2244668800)"
                );
            }
        }
    } // send_session_request_test

    #[actix_rt::test]
    async fn mockoon_based_test() {
        if std::env::var("MOCKOON").is_ok() {
            match send_push_model_request(&Args {
                api_version: None,
                avoid_tpm: Some(true),
                registrar_url: "http://1.2.3.4:8888".to_string(),
                verifier_url: "http://localhost:3000".to_string(),
                timeout: TEST_TIMEOUT_MILLIS,
                ca_certificate: "/tmp/does_not_exist.pem".to_string(),
                certificate: "/tmp/does_not_exist.pem".to_string(),
                key: "/tmp/does_not_exist.pem".to_string(),
                insecure: Some(false),
                agent_identifier: Some("12345678".to_string()),
                json_file: None,
                message_type: Some("Attestation".to_string()),
                method: Some("POST".to_string()),
                attestation_index: None,
                session_index: None,
            })
            .await
            {
                Ok(r) => {
                    assert!(r.status_code == reqwest::StatusCode::OK);
                }
                Err(_) => {
                    unreachable!()
                }
            }
            match send_push_model_request(&Args {
                api_version: Some("-1.2.3".to_string()),
                avoid_tpm: Some(true),
                registrar_url: "http://1.2.3.4:8888".to_string(),
                verifier_url: "http://localhost:3000".to_string(),
                timeout: TEST_TIMEOUT_MILLIS,
                ca_certificate: "/tmp/does_not_exist.pem".to_string(),
                certificate: "/tmp/does_not_exist.pem".to_string(),
                key: "/tmp/does_not_exist.pem".to_string(),
                insecure: Some(false),
                agent_identifier: Some("12345678".to_string()),
                json_file: None,
                message_type: Some("Attestation".to_string()),
                method: Some("POST".to_string()),
                attestation_index: None,
                session_index: None,
            })
            .await
            {
                Ok(r) => {
                    assert!(r.status_code == reqwest::StatusCode::NOT_FOUND);
                }
                Err(_) => {
                    unreachable!()
                }
            }
            match send_push_model_request(&Args {
                api_version: None,
                avoid_tpm: Some(true),
                registrar_url: "http://1.2.3.4:8888".to_string(),
                verifier_url: "http://localhost:3000".to_string(),
                timeout: TEST_TIMEOUT_MILLIS,
                ca_certificate: "/tmp/does_not_exist.pem".to_string(),
                certificate: "/tmp/does_not_exist.pem".to_string(),
                key: "/tmp/does_not_exist.pem".to_string(),
                insecure: Some(false),
                agent_identifier: None,
                json_file: None,
                message_type: Some("Session".to_string()),
                method: Some("POST".to_string()),
                attestation_index: None,
                session_index: None,
            })
            .await
            {
                Ok(r) => {
                    assert!(r.status_code == reqwest::StatusCode::OK);
                }
                Err(_) => {
                    unreachable!()
                }
            }
            match send_push_model_request(&Args {
                api_version: None,
                avoid_tpm: Some(true),
                registrar_url: "http://1.2.3.4:8888".to_string(),
                verifier_url: "http://localhost:3000".to_string(),
                timeout: TEST_TIMEOUT_MILLIS,
                ca_certificate: "/tmp/does_not_exist.pem".to_string(),
                certificate: "/tmp/does_not_exist.pem".to_string(),
                key: "/tmp/does_not_exist.pem".to_string(),
                insecure: Some(false),
                agent_identifier: None,
                json_file: None,
                message_type: Some("Session".to_string()),
                method: Some("PATCH".to_string()),
                attestation_index: None,
                session_index: Some("12345678".to_string()),
            })
            .await
            {
                Ok(r) => {
                    assert!(r.status_code == reqwest::StatusCode::OK);
                }
                Err(_) => {
                    unreachable!()
                }
            }
        } // MOCKOON enabled
    } // mockoon_based_test

    #[actix_rt::test]
    async fn get_message_type_test() {
        for mtype in [
            "Attestation".to_string(),
            "EvidenceHandling".to_string(),
            "Session".to_string(),
        ] {
            let args = Args {
                api_version: None,
                avoid_tpm: Some(true),
                registrar_url: "".to_string(),
                verifier_url: "".to_string(),
                timeout: 0,
                ca_certificate: "".to_string(),
                certificate: "".to_string(),
                key: "".to_string(),
                insecure: None,
                agent_identifier: None,
                json_file: None,
                message_type: Some(mtype.to_string()),
                method: None,
                attestation_index: None,
                session_index: None,
            };
            let msg_type = get_message_type(&args);
            match mtype.as_str() {
                "Attestation" => matches!(msg_type, MessageType::Attestation),
                "EvidenceHandling" => {
                    matches!(msg_type, MessageType::EvidenceHandling)
                }
                "Session" => matches!(msg_type, MessageType::Session),
                _ => unreachable!(),
            };
        }
    } // get_message_type_test

    #[actix_rt::test]
    async fn create_request_builder_test() {
        for method in [
            "POST".to_string(),
            "PUT".to_string(),
            "DELETE".to_string(),
            "GET".to_string(),
            "PATCH".to_string(),
        ] {
            let args = Args {
                api_version: None,
                avoid_tpm: Some(true),
                registrar_url: "".to_string(),
                verifier_url: "".to_string(),
                timeout: 0,
                ca_certificate: "".to_string(),
                certificate: "".to_string(),
                key: "".to_string(),
                insecure: None,
                agent_identifier: None,
                json_file: None,
                message_type: None,
                method: Some(method),
                attestation_index: None,
                session_index: None,
            };
            let reqb = get_request_builder_from_method(&args);
            assert!(reqb.is_ok());
        }
    }

    #[actix_rt::test]
    async fn run_test() {
        // Set arguments to avoid registration
        let args = Args {
            api_version: None,
            avoid_tpm: Some(true),
            registrar_url: "".to_string(),
            verifier_url: "".to_string(),
            timeout: 0,
            ca_certificate: "".to_string(),
            certificate: "".to_string(),
            key: "".to_string(),
            insecure: None,
            agent_identifier: None,
            json_file: None,
            message_type: None,
            method: None,
            attestation_index: None,
            session_index: None,
        };
        let res = run(&args);
        assert!(res.await.is_ok());
    }

    #[actix_rt::test]
    async fn test_context_with_avoid_tpm_flag() {
        let args = Args {
            api_version: None,
            avoid_tpm: Some(true),
            registrar_url: "http://1.2.3.4:8888".to_string(),
            verifier_url: "http://localhost:3000".to_string(),
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: "/tmp/does_not_exist.pem".to_string(),
            certificate: "/tmp/does_not_exist.pem".to_string(),
            key: "/tmp/does_not_exist.pem".to_string(),
            insecure: Some(false),
            agent_identifier: None,
            json_file: None,
            message_type: Some("Session".to_string()),
            method: Some("PATCH".to_string()),
            attestation_index: None,
            session_index: Some("12345678".to_string()),
        };

        let init_res = init_context(&args);
        assert!(init_res.is_ok());
        let context_res = get_context(&args);
        assert!(context_res.is_ok());
        assert!(
            context_res.unwrap().is_none(),
            "Context should be None when TPM is avoided"
        );
    }
}
