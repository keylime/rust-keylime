// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use anyhow::Result;
use clap::Parser;
use keylime::config::PushModelConfigTrait;
use log::{debug, error, info};
mod attestation;
mod auth;
mod context_info_handler;
mod header_validation;
mod registration;
mod response_handler;
mod state_machine;
mod struct_filler;
mod url_selector;

const DEFAULT_TIMEOUT_MILLIS: &str = "5000";
const DEFAULT_METHOD: &str = "POST";
const DEFAULT_MESSAGE_TYPE_STR: &str = "Attestation";
const DEFAULT_ATTESTATION_INTERVAL_SECONDS: u64 = 60;

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
    #[arg(short, long)]
    verifier_url: Option<String>,
    /// avoid tpm
    /// Default: false
    #[arg(long, action, default_missing_value = "false")]
    avoid_tpm: Option<bool>,
    /// Interval in seconds between the attestations happening after the first successful attestation
    /// Default: 60
    #[arg(long, default_value_t = DEFAULT_ATTESTATION_INTERVAL_SECONDS)]
    attestation_interval_seconds: u64,
}

fn get_avoid_tpm_from_args(args: &Args) -> bool {
    args.avoid_tpm.unwrap_or(false)
}

async fn run(args: &Args) -> Result<()> {
    match args.verifier_url {
        Some(ref url) if url.is_empty() => {
            info!("Verifier URL: {url}");
        }
        _ => {}
    };
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
    let config = keylime::config::get_config();
    let avoid_tpm = get_avoid_tpm_from_args(args);
    context_info_handler::init_context_info(avoid_tpm)?;
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
    let agent_identifier = match &args.agent_identifier {
        Some(id) => id.clone(),
        None => config.uuid().to_string(),
    };
    let verifier_url = match args.verifier_url {
        Some(ref url) => url.clone(),
        _ => config.verifier_url().to_string(),
    };
    let negotiations_request_url =
        url_selector::get_negotiations_request_url(&url_selector::UrlArgs {
            verifier_url: verifier_url.clone(),
            api_version: args.api_version.clone(),
            agent_identifier: Some(agent_identifier.clone()),
            location: None,
        });
    if negotiations_request_url.starts_with("ERROR:") {
        return Err(anyhow::anyhow!(negotiations_request_url));
    }
    debug!("Negotiations request URL: {negotiations_request_url}");
    let neg_config = attestation::NegotiationConfig {
        avoid_tpm,
        ca_certificate: &args.ca_certificate,
        client_certificate: &args.certificate,
        ima_log_path: Some(config.ima_ml_path.as_str()),
        initial_delay_ms: config
            .exponential_backoff_initial_delay
            .unwrap_or(1000),
        insecure: args.insecure,
        key: &args.key,
        max_delay_ms: config.exponential_backoff_max_delay,
        max_retries: config.exponential_backoff_max_retries.unwrap_or(5),
        timeout: args.timeout,
        uefi_log_path: Some(config.measuredboot_ml_path.as_str()),
        url: &negotiations_request_url,
        verifier_url: verifier_url.as_str(),
    };
    let attestation_client =
        attestation::AttestationClient::new(&neg_config)?;
    let mut state_machine = state_machine::StateMachine::new(
        attestation_client,
        neg_config,
        ctx_info,
        args.attestation_interval_seconds,
    );
    state_machine.run().await;
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
            verifier_url: Some("".to_string()),
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
            attestation_interval_seconds:
                DEFAULT_ATTESTATION_INTERVAL_SECONDS,
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
            verifier_url: Some("".to_string()),
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
            attestation_interval_seconds:
                DEFAULT_ATTESTATION_INTERVAL_SECONDS,
        };
        let avoid_tpm = get_avoid_tpm_from_args(&args);
        assert!(avoid_tpm);
    }
}
