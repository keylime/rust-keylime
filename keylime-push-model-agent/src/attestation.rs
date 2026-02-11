use crate::header_validation::HeaderValidator;
use crate::privileged_resources::PrivilegedResources;
use crate::{context_info_handler, struct_filler, url_selector};
use anyhow::Result;
use keylime::resilient_client::ResilientClient;
use log::{debug, info, warn};
use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ResponseInformation {
    pub status_code: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Default for ResponseInformation {
    fn default() -> Self {
        Self {
            status_code: StatusCode::OK,
            headers: HeaderMap::new(),
            body: String::new(),
        }
    }
}

/// Configuration for attestation negotiation with the verifier.
/// Push model uses TLS (server verification only) + mandatory PoP authentication.
/// Client certificates (mTLS) are NOT used.
#[derive(Debug, Clone)]
pub struct NegotiationConfig<'a> {
    pub avoid_tpm: bool,
    pub ca_certificate: &'a str,
    pub agent_id: &'a str,
    pub ima_log_path: Option<&'a str>,
    pub initial_delay_ms: u64,
    pub insecure: Option<bool>,
    pub max_delay_ms: Option<u64>,
    pub max_retries: u32,
    pub timeout: u64,
    pub uefi_log_path: Option<&'a str>,
    pub url: &'a str,
    pub verifier_url: &'a str,
    pub tls_accept_invalid_certs: bool,
    pub tls_accept_invalid_hostnames: bool,
}

#[derive(Debug, Clone)]
pub struct AttestationClient {
    pub client: ResilientClient,
}

impl AttestationClient {
    pub fn new(
        config: &NegotiationConfig<'_>,
        context_info: Option<keylime::context_info::ContextInfo>,
    ) -> Result<Self> {
        if config.url.is_empty() {
            return Err(anyhow::anyhow!("URL cannot be empty"));
        }

        // Push model uses TLS with server verification only (no client certificate/mTLS)
        let base_client = if config.url.starts_with("https://") {
            Some(keylime::https_client::get_tls_client(
                &keylime::https_client::TlsClientArgs {
                    ca_certificate: config.ca_certificate.to_string(),
                    insecure: config.insecure,
                    timeout: config.timeout,
                    accept_invalid_hostnames: config
                        .tls_accept_invalid_hostnames,
                },
            )?)
        } else {
            None
        };

        debug!("ResilientClient: initial delay: {} ms, max retries: {}, max delay: {:?} ms",
            config.initial_delay_ms, config.max_retries, config.max_delay_ms);

        // Push model always uses PoP authentication (mandatory)
        info!("Creating PoP authentication middleware");
        let auth_config = Some(keylime::auth::AuthConfig {
            verifier_base_url: config.verifier_url.to_string(),
            agent_id: config.agent_id.to_string(),
            api_version: None, // Use default v3.0
            avoid_tpm: config.avoid_tpm,
            timeout_ms: keylime::config::DEFAULT_AUTH_TIMEOUT_MS,
            max_auth_retries: keylime::config::DEFAULT_AUTH_MAX_RETRIES,
            ca_certificate: if config.ca_certificate.is_empty() {
                None
            } else {
                Some(config.ca_certificate.to_string())
            },
            accept_invalid_certs: config.tls_accept_invalid_certs,
            accept_invalid_hostnames: config.tls_accept_invalid_hostnames,
            context_info: context_info.clone(),
        });

        let client = ResilientClient::new_with_auth(
            base_client,
            auth_config,
            Duration::from_millis(config.initial_delay_ms),
            config.max_retries,
            // The success codes that stop retries
            &[StatusCode::OK, StatusCode::CREATED, StatusCode::ACCEPTED],
            config.max_delay_ms.map(Duration::from_millis),
        )
        .map_err(|e| {
            anyhow::anyhow!("Failed to create resilient client: {}", e)
        })?;

        Ok(AttestationClient { client })
    }

    pub async fn send_negotiation(
        &self,
        config: &NegotiationConfig<'_>,
        privileged_resources: &PrivilegedResources,
    ) -> Result<ResponseInformation> {
        info!("--- Phase 1: Sending Capabilities Negotiation ---");
        info!("Capabilities negotiation URL (POST): {}", config.url);
        let mut context_info =
            context_info_handler::get_context_info(config.avoid_tpm)?;
        let mut filler = struct_filler::get_filler_request(
            context_info.as_mut(),
            privileged_resources,
        );

        let req = filler.get_attestation_request();
        if let Ok(json_str) = serde_json::to_string(&req) {
            debug!("Request body: {json_str}");
        }

        let request_builder = self.client.get_json_request_from_struct(
            reqwest::Method::POST,
            config.url,
            &req,
            Some("application/vnd.api+json".to_string()),
        )?;

        let response = request_builder.send().await?;

        let sc = response.status();
        let headers = response.headers().clone();

        let response_body = response.text().await?;
        if !response_body.is_empty() {
            debug!("Response body: {response_body}");
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
        debug!("PATCH Request body: {json_body}");

        let request_builder = self.client.get_json_request(
            reqwest::Method::PATCH,
            config.url,
            &json_body,
            Some("application/vnd.api+json".to_string()),
        )?;

        let response = request_builder.send().await?;

        let sc = response.status();
        let headers = response.headers().clone();
        let response_body = response.text().await?;

        info!("PATCH Response code:{sc}");
        info!("PATCH Response headers: {headers:?}");

        // Only validate Location header for 201 Created responses per RFC 9110 Section 10.2.2
        if sc.as_u16() == 201 {
            if let Err(e) = HeaderValidator::validate_201_created_response(
                &headers,
                Some(config.url),
            ) {
                warn!("201 Created response validation failed: {e}");
                // Don't fail the request, just log the warning for now
            }
        }

        if !response_body.is_empty() {
            debug!("PATCH Response body: {response_body}");
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
        privileged_resources: &PrivilegedResources,
    ) -> Result<ResponseInformation> {
        info!("--- Phase 2: Preparing and Sending Evidence ---");

        // Use RFC-compliant Location header validation
        let location_header = match HeaderValidator::validate_location_header(
            &neg_response.headers,
            Some(config.verifier_url),
        ) {
            Ok(location) => location,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Location header validation failed: {}",
                    e
                ));
            }
        };

        let patch_url = url_selector::get_evidence_submission_request_url(
            &url_selector::UrlArgs {
                verifier_url: config.verifier_url.to_string(),
                agent_identifier: None,
                api_version: None,
                location: Some(location_header.to_string()),
            },
        );

        info!("Location header from 201 Created response: {location_header}");
        info!("Evidence handling URL (PATCH): {patch_url}");

        // Use struct_filler to handle evidence collection and construction
        let mut context_info =
            context_info_handler::get_context_info(config.avoid_tpm)?;
        let mut filler = struct_filler::get_filler_request(
            context_info.as_mut(),
            privileged_resources,
        );

        let evidence_request_struct = filler
            .get_evidence_handling_request(&neg_response, config)
            .await;

        let evidence_config = NegotiationConfig {
            url: &patch_url,
            ..*config
        };

        let evidence_json_body =
            serde_json::to_string(&evidence_request_struct)?;

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
    use wiremock::matchers::{body_string, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_TIMEOUT_MILLIS: u64 = 1000;

    /// Helper function to create empty PrivilegedResources for testing
    fn create_test_privileged_resources(
    ) -> crate::privileged_resources::PrivilegedResources {
        use keylime::ima::MeasurementList;
        use std::sync::Mutex;

        crate::privileged_resources::PrivilegedResources {
            ima_ml_file: None,
            ima_ml: Mutex::new(MeasurementList::new()),
            measuredboot_ml_file: None,
        }
    }

    fn create_test_config<'a>(
        url: &'a str,
        verifier_url: &'a str,
        ca_path: &'a str,
    ) -> NegotiationConfig<'a> {
        NegotiationConfig {
            avoid_tpm: true,
            ca_certificate: ca_path,
            agent_id: "test-agent-id",
            ima_log_path: None,
            initial_delay_ms: 0, // No initial delay in the old tests
            insecure: Some(false),
            max_delay_ms: None, // No max delay in the old tests
            max_retries: 0,     // By default, don't retry in the old tests
            timeout: TEST_TIMEOUT_MILLIS,
            uefi_log_path: None,
            url,
            verifier_url,
            tls_accept_invalid_certs: false,
            tls_accept_invalid_hostnames: false,
        }
    }

    #[actix_rt::test]
    async fn test_attestation_with_retries() {
        let mock_server = MockServer::start().await;

        // Mock the PoP authentication flow (POST /v3.0/sessions)
        Mock::given(method("POST"))
            .and(path("/v3.0/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
                        "attributes": {
                            "agent_id": "test-agent-id",
                            "authentication_requested": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "test-challenge-123"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2099-01-01T13:00:00Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

        // Mock the proof submission (PATCH /v3.0/sessions/1)
        Mock::given(method("PATCH"))
            .and(path("/v3.0/sessions/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
                        "attributes": {
                            "agent_id": "test-agent-id",
                            "evaluation": "pass",
                            "token": "test-token-xyz",
                            "authentication": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "test-challenge-123"
                                },
                                "data": {
                                    "message": "mock_message",
                                    "signature": "mock_signature"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2099-01-01T13:00:00Z",
                            "response_received_at": "2025-01-01T12:00:01Z",
                            "token_expires_at": "2099-01-01T14:00:00Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

        // Simulate the attestation server failing twice and succeeding on the third attempt
        Mock::given(method("POST"))
            .and(path_regex("/v3.0/agents/.*/attestations"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("/v3.0/agents/.*/attestations"))
            .respond_with(ResponseTemplate::new(201).insert_header(
                "Location",
                "/v3.0/agents/some-id/attestations/1",
            ))
            .mount(&mock_server)
            .await;

        // Build the full attestation URL with path
        let base_url = mock_server.uri();
        let attestation_url =
            format!("{}/v3.0/agents/test-agent-id/attestations", base_url);
        let mut config = create_test_config(&attestation_url, &base_url, "");
        config.max_retries = 3; // Allow up to 3 retries

        let client = AttestationClient::new(&config, None).unwrap();
        let result = client
            .send_negotiation(&config, &create_test_privileged_resources())
            .await;

        // The final request should be successful
        assert!(result.is_ok(), "Request failed: {:?}", result.err());
        let response = result.unwrap();
        assert_eq!(response.status_code, StatusCode::CREATED);
    }

    #[actix_rt::test]
    async fn test_send_negotiation_http_error() {
        let negotiation_config = create_test_config(
            "http://127.0.0.1:9999/test",
            "http://127.0.0.1:9999",
            "",
        );

        let client =
            AttestationClient::new(&negotiation_config, None).unwrap();
        let result = client
            .send_negotiation(
                &negotiation_config.clone(),
                &create_test_privileged_resources(),
            )
            .await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("error sending request"));
    }

    #[actix_rt::test]
    async fn test_send_negotiation_no_cert_file() {
        let config = create_test_config(
            "https://1.2.3.4:9999/test",
            "https://1.2.3.4:9999",
            "/tmp/unexisting_ca_file_12345.pem",
        );

        let client_result = AttestationClient::new(&config, None);

        assert!(client_result.is_err());
        let err_msg = client_result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to open"));
    }

    #[actix_rt::test]
    async fn test_send_negotiation_bad_certs() {
        let temp_dir = tempdir().unwrap();
        let ca_path = temp_dir.path().join("ca.pem");

        // Create empty CA file (invalid certificate)
        File::create(&ca_path).unwrap();

        let config = create_test_config(
            "https://1.2.3.4:9999/test",
            "https://1.2.3.4:9999",
            ca_path.to_str().unwrap(),
        );

        let client_result = AttestationClient::new(&config, None);

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
            "http://localhost:3000",
            "",
        );

        let client = AttestationClient::new(&config, None).unwrap();
        let result = client
            .send_negotiation(&config, &create_test_privileged_resources())
            .await;

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
    async fn test_rfc_compliance_with_mockoon() {
        if std::env::var("MOCKOON").is_err() {
            return;
        }

        let config = create_test_config(
            "http://localhost:3000/v3.0/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/attestations",
            "http://localhost:3000",
            "",
        );

        let client = AttestationClient::new(&config, None).unwrap();
        let result = client
            .send_negotiation(&config, &create_test_privileged_resources())
            .await;

        assert!(
            result.is_ok(),
            "Request to mockoon failed: {:?}",
            result.err()
        );

        let response_info = result.unwrap();

        // Test RFC 9110 Section 10.2.2 compliance - 201 Created must have Location header
        assert_eq!(
            response_info.status_code,
            StatusCode::CREATED,
            "Expected 201 Created from Mockoon, but got {}",
            response_info.status_code
        );

        // Validate Location header for 201 Created responses per RFC 9110 Section 10.2.2
        let validation_result = if response_info.status_code.as_u16() == 201 {
            HeaderValidator::validate_201_created_response(
                &response_info.headers,
                Some("http://localhost:3000"),
            )
            .map(|_| ())
        } else {
            Ok(())
        };

        assert!(
            validation_result.is_ok(),
            "RFC compliance validation failed: {:?}",
            validation_result.err()
        );

        // Specifically test Location header validation according to RFC 3986
        let location_validation = HeaderValidator::validate_location_header(
            &response_info.headers,
            Some("http://localhost:3000"),
        );

        assert!(
            location_validation.is_ok(),
            "Location header validation failed: {:?}",
            location_validation.err()
        );

        // Verify the Location header contains a valid URI
        let location = location_validation.unwrap();
        assert!(
            location.starts_with("http://")
                || location.starts_with("https://")
                || location.starts_with("/"),
            "Location header should be a valid URI reference: {location}"
        );

        // Test evidence submission with RFC-compliant Location header
        let has_location = response_info
            .headers
            .contains_key(reqwest::header::LOCATION);
        let response_body = response_info.body.clone(); // Clone the body for later use

        if has_location {
            let evidence_result = client
                .handle_evidence_submission(
                    response_info,
                    &config,
                    &create_test_privileged_resources(),
                )
                .await;

            // The evidence submission may fail due to mock data, but header validation should succeed
            // We're mainly testing that the RFC compliance validation doesn't prevent the request
            match evidence_result {
                Ok(evidence_response) => {
                    info!(
                        "Evidence submission succeeded with status: {}",
                        evidence_response.status_code
                    );

                    // Validate Location header for 201 Created responses per RFC 9110 Section 10.2.2
                    let evidence_validation =
                        if evidence_response.status_code.as_u16() == 201 {
                            HeaderValidator::validate_201_created_response(
                                &evidence_response.headers,
                                Some("http://localhost:3000"),
                            )
                            .map(|_| ())
                        } else {
                            Ok(())
                        };

                    if evidence_validation.is_err() {
                        warn!("Evidence response header validation failed: {:?}", evidence_validation.err());
                        // Don't fail the test, just log as this might be due to mock server limitations
                    }
                }
                Err(e) => {
                    // Evidence submission failure is acceptable for this test
                    // We're primarily testing RFC compliance validation
                    info!(
                        "Evidence submission failed (expected with mock): {e}"
                    );
                }
            }

            // Use the cloned body for the final assertion
            assert!(response_body.contains("evidence_requested"));
        } else {
            // If no Location header, just check the body directly
            assert!(response_info.body.contains("evidence_requested"));
        }
    }

    #[actix_rt::test]
    async fn test_handle_evidence_submission_no_location_header() {
        let config = create_test_config(
            "http://localhost:3000",
            "http://localhost:3000",
            "",
        );
        let client = AttestationClient::new(&config, None).unwrap();

        // Create a response with no Location header
        let neg_response = ResponseInformation {
            status_code: StatusCode::CREATED,
            headers: HeaderMap::new(),
            body: "{}".to_string(),
        };

        let result = client
            .handle_evidence_submission(
                neg_response,
                &config,
                &create_test_privileged_resources(),
            )
            .await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Location header validation failed")
                || error_msg.contains("missing 'Location' header")
        );
    }

    #[actix_rt::test]
    async fn test_send_evidence() {
        // Setup a mock server
        let mock_server = MockServer::start().await;

        // Mock the PoP authentication flow (POST /v3.0/sessions)
        Mock::given(method("POST"))
            .and(path("/v3.0/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
                        "attributes": {
                            "agent_id": "test-agent-id",
                            "authentication_requested": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "test-challenge-123"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2099-01-01T13:00:00Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

        // Mock the proof submission (PATCH /v3.0/sessions/1)
        Mock::given(method("PATCH"))
            .and(path("/v3.0/sessions/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
                        "attributes": {
                            "agent_id": "test-agent-id",
                            "evaluation": "pass",
                            "token": "test-token-xyz",
                            "authentication": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "test-challenge-123"
                                },
                                "data": {
                                    "message": "mock_message",
                                    "signature": "mock_signature"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2099-01-01T13:00:00Z",
                            "response_received_at": "2025-01-01T12:00:01Z",
                            "token_expires_at": "2099-01-01T14:00:00Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

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
        let base_url = mock_server.uri();
        let uri = format!("{}/evidence", base_url);
        let config = create_test_config(&uri, &base_url, "");

        // Create the client
        let client = AttestationClient::new(&config, None).unwrap();

        let result =
            client.send_evidence(single_serialized_body, &config).await;

        // Assertions
        assert!(result.is_ok(), "send_evidence should succeed");
        let response = result.unwrap();
        assert_eq!(response.status_code, StatusCode::ACCEPTED);
    }
}
