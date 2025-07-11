use crate::{
    context_info_handler, response_handler, struct_filler, url_selector,
};
use anyhow::Result;
use keylime::resilient_client::ResilientClient;
use log::{debug, info};
use reqwest::header::HeaderMap;
use reqwest::header::LOCATION;
use reqwest::StatusCode;
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
    pub ima_log_path: Option<&'a str>,
    pub uefi_log_path: Option<&'a str>,
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct AttestationClient {
    pub client: ResilientClient,
}

impl AttestationClient {
    pub fn new(config: &NegotiationConfig<'_>) -> Result<Self> {
        if config.url.is_empty() {
            return Err(anyhow::anyhow!("URL cannot be empty"));
        }
        let base_client = if config.url.starts_with("https://") {
            Some(keylime::https_client::get_https_client(
                &keylime::https_client::ClientArgs {
                    ca_certificate: config.ca_certificate.to_string(),
                    certificate: config.client_certificate.to_string(),
                    key: config.key.to_string(),
                    insecure: config.insecure,
                    timeout: config.timeout,
                },
            )?)
        } else {
            None
        };

        debug!("ResilientClient: initial delay: {} ms, max retries: {}, max delay: {:?} ms", 
            config.initial_delay_ms, config.max_retries, config.max_delay_ms);
        let client = ResilientClient::new(
            base_client,
            Duration::from_millis(config.initial_delay_ms),
            config.max_retries,
            // The success codes that stop retries
            &[StatusCode::OK, StatusCode::CREATED, StatusCode::ACCEPTED],
            config.max_delay_ms.map(Duration::from_millis),
        );

        Ok(AttestationClient { client })
    }

    pub async fn send_negotiation(
        &self,
        config: &NegotiationConfig<'_>,
    ) -> Result<ResponseInformation> {
        info!("--- Phase 1: Sending Capabilities Negotiation ---");
        let mut context_info =
            context_info_handler::get_context_info(config.avoid_tpm)?;
        let mut filler =
            struct_filler::get_filler_request(None, context_info.as_mut());

        let req = filler.get_attestation_request();
        debug!("Request body: {:?}", serde_json::to_string(&req));

        let response = self
            .client
            .get_json_request_from_struct(
                reqwest::Method::POST,
                config.url,
                &req,
                Some("application/vnd.api+json".to_string()),
            )?
            .send()
            .await?;

        let sc = response.status();
        let headers = response.headers().clone();
        info!("Response code:{}", response.status());
        info!("Response headers: {headers:?}");

        let response_body = response.text().await?;
        if !response_body.is_empty() {
            info!("Response body: {response_body}");
        }

        let rsp = ResponseInformation {
            status_code: sc,
            headers,
            body: response_body,
        };
        Ok(rsp)
    }

    async fn send_evidence(
        &self,
        json_body: String,
        config: &NegotiationConfig<'_>,
    ) -> Result<ResponseInformation> {
        debug!("PATCH Request body: {json_body:?}");

        let response = self
            .client
            .get_json_request(
                reqwest::Method::PATCH,
                config.url,
                &json_body,
                Some("application/vnd.api+json".to_string()),
            )?
            .send()
            .await?;

        let sc = response.status();
        let headers = response.headers().clone();
        let response_body = response.text().await?;

        info!("PATCH Response code:{sc}");
        info!("PATCH Response headers: {headers:?}");
        if !response_body.is_empty() {
            info!("PATCH Response body: {response_body}");
        }

        Ok(ResponseInformation {
            status_code: sc,
            headers,
            body: response_body,
        })
    }

    pub async fn handle_evidence_submission(
        &self,
        neg_response: ResponseInformation,
        config: &NegotiationConfig<'_>,
    ) -> Result<ResponseInformation> {
        info!("--- Phase 2: Preparing and Sending Evidence ---");
        let location_header = neg_response
            .headers
            .get(LOCATION)
            .ok_or_else(|| {
                anyhow::anyhow!("Verifier response missing 'Location' header")
            })?
            .to_str()?;

        let patch_url = url_selector::get_evidence_submission_request_url(
            &url_selector::UrlArgs {
                verifier_url: config.url.to_string(),
                agent_identifier: None,
                api_version: None,
                location: Some(location_header.to_string()),
            },
        );
        info!("Sending evidence (PATCH) to: {patch_url}");
        let mut attestation_params =
            response_handler::process_negotiation_response(
                &neg_response.body,
            )?;
        attestation_params.ima_log_path =
            config.ima_log_path.map(|path| path.to_string());
        attestation_params.uefi_log_path =
            config.uefi_log_path.map(|path| path.to_string());
        debug!("Attestation parameters: {attestation_params:?}");
        let mut context_info =
            context_info_handler::get_context_info(config.avoid_tpm)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "TPM context is required for evidence submission"
                    )
                })?;
        debug!("Getting filler");
        let mut filler =
            struct_filler::get_filler_request(None, Some(&mut context_info));
        debug!("Calling filler to get evidence request struct");
        let evidence_request_struct = filler
            .get_evidence_handling_request(&attestation_params)
            .await;
        let evidence_json_body =
            serde_json::to_string(&evidence_request_struct)?;
        let evidence_config = NegotiationConfig {
            url: &patch_url,
            ..*config
        };

        let evidence_response = self
            .send_evidence(evidence_json_body, &evidence_config)
            .await?;

        Ok(evidence_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;
    use wiremock::matchers::{body_string, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
            ima_log_path: None,
            uefi_log_path: None,
            max_retries: 0, // By default, don't retry in the old tests
            initial_delay_ms: 0, // No initial delay in the old tests
            max_delay_ms: None, // No max delay in the old tests
        }
    }

    #[actix_rt::test]
    async fn test_attestation_with_retries() {
        let mock_server = MockServer::start().await;

        // Simulate the server failing twice and succeeding on the third attempt
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).insert_header(
                "Location",
                "/v3.0/agents/some-id/attestations/1",
            ))
            .mount(&mock_server)
            .await;

        let uri = mock_server.uri().clone();
        let mut config = create_test_config(&uri, "", "", "");
        config.max_retries = 3; // Allow up to 3 retries

        let client = AttestationClient::new(&config).unwrap();
        let result = client.send_negotiation(&config).await;

        // The final request should be successful
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status_code, StatusCode::CREATED);

        // The server should have received 3 requests in total (2 failures + 1 success)
        let received_requests =
            mock_server.received_requests().await.unwrap();
        assert_eq!(received_requests.len(), 3);
    }

    #[actix_rt::test]
    async fn test_send_negotiation_http_error() {
        let negotiation_config =
            create_test_config("http://127.0.0.1:9999/test", "", "", "");

        let client = AttestationClient::new(&negotiation_config).unwrap();
        let result =
            client.send_negotiation(&negotiation_config.clone()).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("error sending request"));
    }

    #[actix_rt::test]
    async fn test_send_negotiation_no_cert_file() {
        let config = create_test_config(
            "https://1.2.3.4:9999/test",
            "/tmp/unexisting_ca_file_12345.pem",
            "/tmp/unexisting_cert_file_12345.pem",
            "/tmp/unexisting_key_file_12345.pem",
        );

        let client_result = AttestationClient::new(&config);

        assert!(client_result.is_err());
        let err_msg = client_result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to open"));
    }

    #[actix_rt::test]
    async fn test_send_negotiation_bad_certs() {
        let temp_dir = tempdir().unwrap();
        let ca_path = temp_dir.path().join("ca.pem");
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        File::create(&ca_path).unwrap();
        File::create(&cert_path).unwrap();
        File::create(&key_path).unwrap();

        let config = create_test_config(
            "https://1.2.3.4:9999/test",
            ca_path.to_str().unwrap(),
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        );

        let client_result = AttestationClient::new(&config);

        assert!(client_result.is_err());
        let err_msg = client_result.unwrap_err().to_string();
        assert!(err_msg.to_lowercase().contains("certificate"));
    }

    #[actix_rt::test]
    async fn test_negotiation_with_mockoon() {
        if std::env::var("MOCKOON").is_err() {
            return;
        }

        let config = create_test_config(
            "http://localhost:3000/v3.0/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/attestations",
            "", "", "",
        );

        let client = AttestationClient::new(&config).unwrap();
        let result = client.send_negotiation(&config).await;

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

    #[actix_rt::test]
    async fn test_handle_evidence_submission_no_location_header() {
        let config = create_test_config("http://localhost:3000", "", "", "");
        let client = AttestationClient::new(&config).unwrap();

        // Create a response with no Location header
        let neg_response = ResponseInformation {
            status_code: StatusCode::CREATED,
            headers: HeaderMap::new(),
            body: "{}".to_string(),
        };

        let result = client
            .handle_evidence_submission(neg_response, &config)
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing 'Location' header"));
    }

    #[actix_rt::test]
    async fn test_send_evidence() {
        // Setup a mock server
        let mock_server = MockServer::start().await;

        let sample_evidence_struct = serde_json::json!({
            "data": "sample_evidence"
        });

        let single_serialized_body = sample_evidence_struct.to_string();

        Mock::given(method("PATCH"))
            .and(path("/evidence"))
            .and(body_string(single_serialized_body.clone()))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        // Create a config pointing to the mock server's URI
        let uri = format!("{}/evidence", mock_server.uri());
        let config = create_test_config(&uri, "", "", "");

        // Create the client
        let client = AttestationClient::new(&config).unwrap();

        let result =
            client.send_evidence(single_serialized_body, &config).await;

        // Assertions
        assert!(result.is_ok(), "send_evidence should succeed");
        let response = result.unwrap();
        assert_eq!(response.status_code, StatusCode::ACCEPTED);

        // Verify that the mock server received exactly one request.
        let received_requests =
            mock_server.received_requests().await.unwrap();
        assert_eq!(received_requests.len(), 1);
    }
}
