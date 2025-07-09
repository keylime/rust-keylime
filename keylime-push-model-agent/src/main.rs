// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use anyhow::Result;
use clap::Parser;
use keylime::config::{AgentConfig, PushModelConfigTrait};
use log::{debug, error, info};
mod attestation;
mod context_info_handler;
mod registration;
mod response_handler;
mod struct_filler;
mod url_selector;

const DEFAULT_TIMEOUT_MILLIS: &str = "5000";
const DEFAULT_METHOD: &str = "POST";
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

fn get_avoid_tpm_from_args(args: &Args) -> bool {
    args.avoid_tpm.unwrap_or(false)
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
    let config = AgentConfig::new()?;
    let avoid_tpm = get_avoid_tpm_from_args(args);
    context_info_handler::init_context_info(&config, avoid_tpm)?;
    debug!("Avoid TPM: {avoid_tpm}");
    let ctx_info = match context_info_handler::get_context_info(avoid_tpm) {
        Ok(Some(context_info)) => Some(context_info),
        Ok(None) => {
            error!("No context");
            None
        }
        Err(e) => {
            error!("Error obtaining context information: {e:?}");
            return Err(e);
        }
    };
    let res =
        crate::registration::check_registration(&config, ctx_info).await;
    match res {
        Ok(_) => {}
        Err(ref e) => error!("Could not register appropriately: {e:?}"),
    }
    let agent_identifier = match &args.agent_identifier {
        Some(id) => id.clone(),
        None => config.uuid().to_string(),
    };
    let negotiations_request_url =
        url_selector::get_negotiations_request_url(&url_selector::UrlArgs {
            verifier_url: args.verifier_url.clone(),
            api_version: args.api_version.clone(),
            agent_identifier: Some(agent_identifier.clone()),
            location: None,
        });
    debug!("Negotiations request URL: {negotiations_request_url}");
    let neg_config = attestation::NegotiationConfig {
        avoid_tpm,
        url: &negotiations_request_url,
        timeout: args.timeout,
        ca_certificate: &args.ca_certificate,
        client_certificate: &args.certificate,
        key: &args.key,
        insecure: args.insecure,
        ima_log_path: Some(config.ima_ml_path.as_str()),
        uefi_log_path: Some(config.measuredboot_ml_path.as_str()),
    };
    let attestation_client =
        attestation::AttestationClient::new(&neg_config)?;
    let neg_response = attestation_client.send_negotiation(&neg_config).await;

    let neg_response_data = match neg_response {
        Ok(ref neg) => {
            info!("Request sent successfully");
            info!(
                "Returned response code: {:?}",
                neg_response.as_ref().unwrap().status_code
            );
            info!(
                "Returned response headers: {:?}",
                neg_response.as_ref().unwrap().headers
            );
            info!(
                "Returned response body: {:?}",
                neg_response.as_ref().unwrap().body
            );
            neg
        }
        Err(ref e) => {
            error!("Error: {e:?}");
            &attestation::ResponseInformation {
                status_code: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                body: e.to_string(),
                headers: reqwest::header::HeaderMap::new(),
            }
        }
    };

    if neg_response_data.status_code != reqwest::StatusCode::CREATED {
        error!(
            "Negotiation failed with status code: {}",
            neg_response_data.status_code
        );
        return Err(anyhow::anyhow!(
            "Negotiation failed with status code: {}",
            neg_response_data.status_code
        ));
    }

    let evidence_config: attestation::NegotiationConfig<'_> =
        attestation::NegotiationConfig {
            url: &args.verifier_url,
            ..neg_config.clone()
        };

    let evidence_response = attestation_client
        .handle_evidence_submission(
            neg_response_data.clone(),
            &evidence_config,
        )
        .await?;

    if evidence_response.status_code == reqwest::StatusCode::ACCEPTED {
        info!("SUCCESS! Evidence accepted by the Verifier.");
        info!("Response body: {}", evidence_response.body);
    } else {
        error!(
            "Verifier rejected the evidence with code: {}",
            evidence_response.status_code
        );
        error!("Response body: {}", evidence_response.body);
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    run(&Args::parse()).await
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn run_test() {
        // Set arguments to avoid TPM
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
        assert!(res.await.is_err());
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn avoid_tpm_test() {
        // Set arguments to avoid TPM
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
        let avoid_tpm = get_avoid_tpm_from_args(&args);
        assert!(avoid_tpm);
    }
}
