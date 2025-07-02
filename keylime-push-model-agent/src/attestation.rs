use crate::{context_info_handler, json_dump, struct_filler};
use actix_web::http::StatusCode;
use anyhow::{Context, Result};
use keylime::error::Error as KeylimeError;
use keylime::https_client;
use log::{debug, info};
use reqwest::header::HeaderMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ResponseInformation {
    pub status_code: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct NegotiationConfig<'a> {
    pub avoid_tpm: bool,
    pub url: &'a str,
    pub timeout: u64,
    pub ca_certificate: &'a str,
    pub client_certificate: &'a str,
    pub key: &'a str,
    pub insecure: Option<bool>,
}

const HTTPS_PREFIX: &str = "https://";

fn get_client(config: NegotiationConfig<'_>) -> Result<reqwest::Client> {
    if config.url.starts_with(HTTPS_PREFIX) {
        return https_client::get_https_client(
            &keylime::https_client::ClientArgs {
                ca_certificate: config.ca_certificate.to_string().clone(),
                certificate: config.client_certificate.to_string().clone(),
                key: config.key.to_string().clone(),
                insecure: config.insecure,
                timeout: config.timeout,
            },
        );
    }
    reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout))
        .build()
        .context("Failed to build plain HTTP client")
}

pub async fn send_negotiation(
    config: NegotiationConfig<'_>,
) -> Result<ResponseInformation, KeylimeError> {
    let mut context_info = context_info_handler::get_context_info(
        config.avoid_tpm,
    )
    .map_err(|e| {
        KeylimeError::Other(format!("Failed to get context info: {}", e))
    })?;
    let mut filler =
        struct_filler::get_filler_request(None, context_info.as_mut());

    let json_value = json_dump::dump_attestation_request_to_value(
        &filler.get_attestation_request(),
    );
    let reqcontent = json_value?.to_string();
    debug!("Request body: {:?}", reqcontent);

    let client = get_client(config.clone()).map_err(|e| {
        KeylimeError::Other(format!("Failed to create client: {}", e))
    })?;

    let response = client
        .post(config.url)
        .body(reqcontent)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .timeout(Duration::from_millis(config.timeout))
        .send()
        .await?;

    let sc = response.status();
    let headers = response.headers().clone();
    info!("Response code:{}", response.status());
    info!("Response headers: {:?}", headers);

    let response_body = response.text().await?;
    if !response_body.is_empty() {
        info!("Response body: {}", response_body);
    }

    let actix_status_code =
        actix_web::http::StatusCode::from_u16(sc.as_u16()).map_err(|e| {
            KeylimeError::Other(format!(
                "Invalid status code received: {}",
                e
            ))
        })?;

    let rsp = ResponseInformation {
        status_code: actix_status_code,
        headers,
        body: response_body,
    };
    Ok(rsp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_info_handler;
    use std::fs::File;
    use tempfile::tempdir;

    const TEST_TIMEOUT_MILLIS: u64 = 1000;

    fn create_test_config<'a>(
        url: &'a str,
        ca_path: &'a str,
        cert_path: &'a str,
        key_path: &'a str,
    ) -> NegotiationConfig<'a> {
        NegotiationConfig {
            avoid_tpm: true,
            url,
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: ca_path,
            client_certificate: cert_path,
            key: key_path,
            insecure: Some(false),
        }
    }

    #[actix_rt::test]
    async fn test_send_negotiation_http_error() {
        let config = create_test_config("http://1.2.3.4", "", "", "");

        let _ = context_info_handler::init_context_info(true);

        let result = send_negotiation(config).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("error sending request"));
    }

    #[actix_rt::test]
    async fn test_send_negotiation_no_cert_file() {
        let config = create_test_config(
            "https://1.2.3.4:9999",
            "/tmp/unexisting_ca_file_12345.pem",
            "/tmp/unexisting_cert_file_12345.pem",
            "/tmp/unexisting_key_file_12345.pem",
        );

        let _ = context_info_handler::init_context_info(true);

        let result = send_negotiation(config).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to open"));
    }

    #[actix_rt::test]
    async fn test_send_negotiation_bad_certs() {
        let temp_dir = tempdir().unwrap(); //#[allow(ci)]
        let ca_path = temp_dir.path().join("ca.pem");
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        File::create(&ca_path).unwrap(); //#[allow(ci)]
        File::create(&cert_path).unwrap(); //#[allow(ci)]
        File::create(&key_path).unwrap(); //#[allow(ci)]

        let config = create_test_config(
            "https://1.2.3.4:9999",
            ca_path.to_str().unwrap(), //#[allow(ci)]
            cert_path.to_str().unwrap(), //#[allow(ci)]
            key_path.to_str().unwrap(), //#[allow(ci)]
        );

        let _ = context_info_handler::init_context_info(true);

        let result = send_negotiation(config).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.to_lowercase().contains("certificate"));
    }

    #[actix_rt::test]
    async fn test_negotiation_with_mockoon() {
        if std::env::var("MOCKOON").is_err() {
            println!("Skipping mockoon test: MOCKOON env var not set.");
            return;
        }

        let mockoon_url = "http://localhost:3000/v3.0/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/attestations";

        let config = NegotiationConfig {
            avoid_tpm: true,
            url: mockoon_url,
            timeout: TEST_TIMEOUT_MILLIS,
            ca_certificate: "",
            client_certificate: "",
            key: "",
            insecure: Some(false),
        };

        let _ = context_info_handler::init_context_info(true);
        let result = send_negotiation(config).await;
        assert!(
            result.is_ok(),
            "Request to mockoon failed: {:?}",
            result.err()
        );
        let response_info = result.unwrap();
        assert_eq!(
            response_info.status_code,
            StatusCode::CREATED,
            "Expected 201 Created from Mockoon, but got {}",
            response_info.status_code
        );
        assert!(response_info.body.contains("evidence_requested"));
    }
}
