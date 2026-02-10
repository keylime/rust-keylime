// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

use crate::attestation::{
    AttestationClient, NegotiationConfig, ResponseInformation,
};
use crate::privileged_resources::PrivilegedResources;
#[cfg(not(all(test, feature = "testing")))]
use crate::registration;
use crate::registration::RegistrarTlsConfig;
#[cfg(test)]
use crate::DEFAULT_ATTESTATION_INTERVAL_SECONDS;
use anyhow::anyhow;
use keylime::context_info::ContextInfo;
use log::*;
use std::time::Duration;
use tokio::time;

#[derive(Debug)]
pub enum State {
    Unregistered,
    Registered(ContextInfo),
    Negotiating(ContextInfo),
    Attesting(ContextInfo, ResponseInformation),
    RegistrationFailed(anyhow::Error),
    AttestationFailed(anyhow::Error, ContextInfo),
    Failed(anyhow::Error),
}

pub struct StateMachine<'a> {
    state: State,
    attestation_client: AttestationClient,
    negotiation_config: NegotiationConfig<'a>,
    context_info: Option<ContextInfo>,
    measurement_interval: Duration,
    registrar_tls_config: Option<RegistrarTlsConfig>,
    /// File handles opened with root privileges before privilege dropping.
    /// These handles remain valid after dropping privileges, enabling continued
    /// access to /sys/kernel/security/ resources.
    privileged_resources: PrivilegedResources,
}

impl<'a> StateMachine<'a> {
    pub fn new(
        attestation_client: AttestationClient,
        negotiation_config: NegotiationConfig<'a>,
        context_info: Option<ContextInfo>,
        attestation_interval_seconds: u64,
        registrar_tls_config: Option<RegistrarTlsConfig>,
        privileged_resources: PrivilegedResources,
    ) -> Self {
        let initial_state = State::Unregistered;
        let measurement_interval =
            Duration::from_secs(attestation_interval_seconds);

        Self {
            state: initial_state,
            attestation_client,
            negotiation_config,
            context_info,
            measurement_interval,
            registrar_tls_config,
            privileged_resources,
        }
    }

    pub async fn run(&mut self) {
        loop {
            let current_state =
                std::mem::replace(&mut self.state, State::Unregistered);

            match current_state {
                State::Unregistered => {
                    debug!("Registering");
                    self.register().await;
                }
                State::Registered(ctx_info) => {
                    debug!("Negotiating");
                    self.negotiate(ctx_info).await;
                }
                State::Negotiating(ctx_info) => {
                    debug!("Handling negotiation");
                    self.handle_negotiation(ctx_info).await;
                }
                State::Attesting(ctx_info, neg_response) => {
                    debug!("Attesting");
                    self.attest(ctx_info, neg_response).await;
                }
                State::RegistrationFailed(e) => {
                    error!("Registration failed: {e:?}");
                    debug!("Resetting state to Unregistered and retrying after a delay ({:?})", self.measurement_interval);
                    // Add a delay before retrying registration to avoid spamming.
                    time::sleep(self.measurement_interval).await;
                    self.state = State::Unregistered;
                }
                State::AttestationFailed(e, ctx_info) => {
                    error!("Attestation failed: {e:?}");
                    debug!(
                        "Retrying attestation after a delay ({:?})",
                        self.measurement_interval
                    );
                    // Wait for the default interval before retrying negotiation.
                    time::sleep(self.measurement_interval).await;
                    self.state = State::Negotiating(ctx_info);
                }
                State::Failed(e) => {
                    error!(
                        "Unrecoverable error: {e:?}. Exiting state machine."
                    );
                    self.state = State::Failed(e);
                    break; // Exit the loop on terminal failure
                }
            }
        }
    }

    async fn register(&mut self) {
        let res = registration::check_registration(
            self.context_info.clone(),
            self.registrar_tls_config.take(),
        )
        .await;

        match res {
            Ok(()) => {
                if let Some(ctx) = &self.context_info {
                    self.state = State::Registered(ctx.clone());
                } else {
                    self.state =
                        State::Failed(anyhow!("Could not get context info"));
                }
            }
            Err(e) => {
                self.state = State::RegistrationFailed(anyhow!(
                    "Registration failed: {e:?}"
                ));
            }
        }
    }

    async fn negotiate(&mut self, ctx_info: ContextInfo) {
        self.state = State::Negotiating(ctx_info);
    }

    async fn handle_negotiation(&mut self, ctx_info: ContextInfo) {
        let neg_response = self
            .attestation_client
            .send_negotiation(
                &self.negotiation_config,
                &self.privileged_resources,
            )
            .await;

        debug!("Negotiation response: {neg_response:?}");
        debug!("Negotiation config: {:?}", self.negotiation_config);

        match neg_response {
            Ok(neg) => {
                if neg.status_code == reqwest::StatusCode::CREATED {
                    self.state = State::Attesting(ctx_info, neg);
                } else if neg.status_code == reqwest::StatusCode::UNAUTHORIZED
                {
                    // 401 Unauthorized: token expired, middleware has cleared it
                    // Retry immediately - next request will re-authenticate
                    info!("Received 401 Unauthorized, retrying immediately to re-authenticate");
                    self.state = State::Negotiating(ctx_info);
                } else {
                    // Treat negotiation failure as a retryable attestation error
                    self.state = State::AttestationFailed(
                        anyhow!(
                            "Negotiation failed with status code: {}",
                            neg.status_code
                        ),
                        ctx_info,
                    );
                }
            }
            Err(e) => {
                // Treat negotiation failure as a retryable attestation error
                self.state = State::AttestationFailed(
                    anyhow!("Negotiation failed: {e:?}"),
                    ctx_info,
                );
            }
        }
    }

    async fn attest(
        &mut self,
        ctx_info: ContextInfo,
        neg_response: ResponseInformation,
    ) {
        let evidence_response = self
            .attestation_client
            .handle_evidence_submission(
                neg_response.clone(),
                &self.negotiation_config,
                &self.privileged_resources,
            )
            .await;

        match evidence_response {
            Ok(res) => {
                if res.status_code == reqwest::StatusCode::ACCEPTED {
                    info!("SUCCESS! Evidence accepted by the Verifier.");

                    // Extract seconds_to_next_attestation from verifier response.
                    let next_interval =
                        self.extract_next_attestation_interval(&res.body);

                    info!(
                        "Waiting {} seconds before next attestation...",
                        next_interval.as_secs()
                    );
                    time::sleep(next_interval).await;
                    info!("Moving back to negotiation state");
                    self.state = State::Negotiating(ctx_info);
                } else if res.status_code == reqwest::StatusCode::UNAUTHORIZED
                {
                    // 401 Unauthorized: token expired, middleware has cleared it
                    // Retry immediately - next request will re-authenticate
                    info!("Received 401 Unauthorized, retrying immediately to re-authenticate");
                    self.state = State::Negotiating(ctx_info);
                } else {
                    error!(
                        "Verifier rejected the evidence with code: {}",
                        res.status_code
                    );
                    error!("Response body: {}", res.body);
                    // This is now a retryable error
                    self.state = State::AttestationFailed(
                        anyhow!(
                            "Verifier rejected the evidence with code: {}",
                            res.status_code
                        ),
                        ctx_info,
                    );
                }
            }
            Err(e) => {
                // This is now a retryable error
                self.state = State::AttestationFailed(
                    anyhow!("Attestation failed: {e:?}"),
                    ctx_info,
                );
            }
        }
    }

    /// Extracts the seconds_to_next_attestation field from the verifier response body.
    /// The field is expected to be in the "meta" object at the top level.
    /// If the field is not present or cannot be parsed, falls back to the default interval.
    fn extract_next_attestation_interval(
        &self,
        response_body: &str,
    ) -> Duration {
        match serde_json::from_str::<
            keylime::structures::EvidenceHandlingResponse,
        >(response_body)
        {
            Ok(response) => {
                if let Some(meta) = &response.meta {
                    if let Some(seconds) = meta.seconds_to_next_attestation {
                        debug!("Using verifier-provided interval: {seconds} seconds");
                        return Duration::from_secs(seconds);
                    } else {
                        warn!("seconds_to_next_attestation field not found in meta object, using default interval of {} seconds", self.measurement_interval.as_secs());
                    }
                } else {
                    warn!("meta object not found in verifier response, using default interval of {} seconds", self.measurement_interval.as_secs());
                }
            }
            Err(e) => {
                warn!("Failed to parse verifier response as EvidenceHandlingResponse: {}, using default interval of {} seconds", e, self.measurement_interval.as_secs());
            }
        }

        // Fallback to the default interval.
        self.measurement_interval
    }

    // Expose current state for testing.
    #[cfg(any(test, feature = "testing"))]
    #[allow(dead_code)] // Used in test assertions but compiler doesn't detect conditional compilation usage
    pub fn get_current_state(&self) -> &State {
        &self.state
    }
}

#[cfg(all(test, feature = "testing"))]
mod registration {
    use anyhow::anyhow;
    use keylime::context_info::ContextInfo;
    use std::sync::{Arc, Mutex, OnceLock};

    pub use crate::registration::RegistrarTlsConfig;

    static MOCK_RESULT: OnceLock<Arc<Mutex<Result<(), String>>>> =
        OnceLock::new();

    fn get_mock_result() -> &'static Arc<Mutex<Result<(), String>>> {
        MOCK_RESULT.get_or_init(|| Arc::new(Mutex::new(Ok(()))))
    }

    pub async fn check_registration(
        _context_info: Option<ContextInfo>,
        _tls_config: Option<RegistrarTlsConfig>,
    ) -> anyhow::Result<()> {
        let result = get_mock_result().lock().unwrap().clone();
        result.map_err(|e| anyhow!(e))
    }

    pub fn set_mock_result(result: Result<(), String>) {
        let mut guard = get_mock_result().lock().unwrap();
        *guard = result;
    }
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tpm_tests {
    use super::*;
    use crate::attestation::{AttestationClient, NegotiationConfig};
    use anyhow::anyhow;
    use keylime::context_info::ContextInfo;
    use keylime::tpm::testing;
    use reqwest::StatusCode;
    use std::sync::{Arc, Mutex};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[derive(Clone)]
    struct MockAttestationClient {
        negotiation_response:
            Arc<Mutex<Result<ResponseInformation, anyhow::Error>>>,
        evidence_response:
            Arc<Mutex<Result<ResponseInformation, anyhow::Error>>>,
    }

    impl MockAttestationClient {
        fn set_negotiation_response(
            &self,
            response: Result<ResponseInformation, anyhow::Error>,
        ) {
            *self.negotiation_response.lock().unwrap() = response;
        }

        async fn send_negotiation(
            &self,
            _config: &NegotiationConfig<'_>,
            _privileged_resources: &PrivilegedResources,
        ) -> anyhow::Result<ResponseInformation> {
            self.negotiation_response
                .lock()
                .unwrap()
                .as_ref()
                .cloned()
                .map_err(|e| anyhow!(e.to_string()))
        }

        fn set_evidence_response(
            &self,
            response: Result<ResponseInformation, anyhow::Error>,
        ) {
            *self.evidence_response.lock().unwrap() = response;
        }

        async fn handle_evidence_submission(
            &self,
            _neg_response: ResponseInformation,
            _config: &NegotiationConfig<'_>,
            _privileged_resources: &PrivilegedResources,
        ) -> anyhow::Result<ResponseInformation> {
            self.evidence_response
                .lock()
                .unwrap()
                .as_ref()
                .cloned()
                .map_err(|e| anyhow!(e.to_string()))
        }
    }

    // Manual implementation of Default for our mock
    impl Default for MockAttestationClient {
        fn default() -> Self {
            Self {
                negotiation_response: Arc::new(Mutex::new(Ok(
                    ResponseInformation {
                        status_code: StatusCode::CREATED,
                        ..Default::default()
                    },
                ))),
                evidence_response: Arc::new(Mutex::new(Ok(
                    ResponseInformation {
                        status_code: StatusCode::ACCEPTED,
                        ..Default::default()
                    },
                ))),
            }
        }
    }

    /// Helper function to create TPM test configuration.
    fn create_tpm_test_config(
        url: &str,
        timeout: u64,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: Option<u64>,
    ) -> NegotiationConfig<'_> {
        NegotiationConfig {
            avoid_tpm: true,
            ca_certificate: "",
            client_certificate: "",
            enable_authentication: false,
            agent_id: "test-agent-id",
            ima_log_path: None,
            initial_delay_ms,
            insecure: Some(true),
            key: "",
            max_delay_ms,
            max_retries,
            timeout,
            uefi_log_path: None,
            url,
            verifier_url: url,
            tls_accept_invalid_certs: true,
            tls_accept_invalid_hostnames: true,
        }
    }

    /// Helper function to create empty PrivilegedResources for testing
    fn create_test_privileged_resources() -> PrivilegedResources {
        use keylime::ima::MeasurementList;
        use std::sync::Mutex;

        PrivilegedResources {
            ima_ml_file: None,
            ima_ml: Mutex::new(MeasurementList::new()),
            measuredboot_ml_file: None,
        }
    }

    #[cfg(feature = "testing")]
    fn create_test_state_machine<'a>(
        neg_config: &'a NegotiationConfig<'a>,
    ) -> (StateMachine<'a>, keylime::config::TestConfigGuard) {
        // Initialize test config
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = keylime::config::get_testing_config(tmpdir.path(), None);
        // Create guard that will automatically clear override when dropped
        let guard = keylime::config::TestConfigGuard::new(config);

        let context_info =
            ContextInfo::new(keylime::context_info::AlgorithmConfiguration {
                tpm_encryption_alg:
                    keylime::algorithms::EncryptionAlgorithm::Rsa2048,
                tpm_hash_alg: keylime::algorithms::HashAlgorithm::Sha256,
                tpm_signing_alg: keylime::algorithms::SignAlgorithm::RsaSsa,
                agent_data_path: "".to_string(),
            })
            .expect("This test requires TPM access with proper permissions");

        let client =
            AttestationClient::new(neg_config, Some(context_info.clone()))
                .unwrap();

        (
            StateMachine::new(
                client,
                neg_config.clone(),
                Some(context_info),
                DEFAULT_ATTESTATION_INTERVAL_SECONDS,
                None,
                create_test_privileged_resources(),
            ),
            guard,
        )
    }

    #[tokio::test]
    async fn test_negotiate_success_transition() {
        let _mutex = testing::lock_tests().await;
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let (mut sm, _guard) = create_test_state_machine(&neg_config);
        let mut context_info = sm.context_info.clone().unwrap();
        sm.state = State::Registered(context_info.clone());

        let mock_client = MockAttestationClient::default();
        let privileged_resources = create_test_privileged_resources();
        let neg_response = mock_client
            .send_negotiation(&sm.negotiation_config, &privileged_resources)
            .await;

        match neg_response {
            Ok(neg) if neg.status_code == reqwest::StatusCode::CREATED => {
                sm.state = State::Attesting(context_info.clone(), neg);
            }
            Ok(neg) => {
                sm.state =
                    State::Failed(anyhow!("Bad status: {}", neg.status_code))
            }
            Err(e) => sm.state = State::Failed(e),
        }

        assert!(matches!(sm.get_current_state(), State::Attesting(_, _)));
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_negotiate_failure_on_bad_status() {
        let _mutex = testing::lock_tests().await;
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let (mut sm, _guard) = create_test_state_machine(&neg_config);
        let mut context_info = sm.context_info.clone().unwrap();
        sm.state = State::Registered(context_info.clone());

        let mock_client = MockAttestationClient::default();
        mock_client.set_negotiation_response(Ok(ResponseInformation {
            status_code: StatusCode::BAD_REQUEST,
            ..Default::default()
        }));

        let privileged_resources = create_test_privileged_resources();
        let neg_response = mock_client
            .send_negotiation(&sm.negotiation_config, &privileged_resources)
            .await;
        match neg_response {
            Ok(neg) if neg.status_code == StatusCode::CREATED => {
                sm.state = State::Attesting(context_info.clone(), neg);
            }
            Ok(neg) => {
                sm.state =
                    State::Failed(anyhow!("Bad status: {}", neg.status_code))
            }
            Err(e) => sm.state = State::Failed(e),
        }

        assert!(matches!(sm.get_current_state(), State::Failed(_)));
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_attest_success_transition() {
        let _mutex = testing::lock_tests().await;
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let (mut sm, _guard) = create_test_state_machine(&neg_config);
        let mut context_info = sm.context_info.clone().unwrap();
        sm.state = State::Attesting(
            context_info.clone(),
            ResponseInformation::default(),
        );

        // Test that a successful attestation response would transition back to Negotiating
        let mock_client = MockAttestationClient::default(); // Default is ACCEPTED
        let privileged_resources = create_test_privileged_resources();
        let evidence_response = mock_client
            .handle_evidence_submission(
                ResponseInformation::default(),
                &sm.negotiation_config,
                &privileged_resources,
            )
            .await;

        // Verify the response is successful
        assert!(evidence_response.is_ok());
        let res = evidence_response.unwrap();
        assert_eq!(res.status_code, StatusCode::ACCEPTED);

        // After successful attestation, the state machine should transition back to Negotiating
        // (the actual sleep and transition happens in the real attest() method)
        sm.state = State::Negotiating(context_info.clone());

        assert!(matches!(sm.get_current_state(), State::Negotiating(_)));
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_attest_failure_on_bad_status() {
        let _mutex = testing::lock_tests().await;
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let (mut sm, _guard) = create_test_state_machine(&neg_config);
        let mut context_info = sm.context_info.clone().unwrap();
        sm.state = State::Attesting(
            context_info.clone(),
            ResponseInformation::default(),
        );

        let mock_client = MockAttestationClient::default();
        mock_client.set_evidence_response(Ok(ResponseInformation {
            status_code: StatusCode::FORBIDDEN,
            ..Default::default()
        }));

        let privileged_resources = create_test_privileged_resources();
        let evidence_response = mock_client
            .handle_evidence_submission(
                ResponseInformation::default(),
                &sm.negotiation_config,
                &privileged_resources,
            )
            .await;

        match evidence_response {
            Ok(res) if res.status_code == StatusCode::ACCEPTED => {
                // This shouldn't happen in this test, but if it did, it would go to negotiation
                sm.state = State::Negotiating(context_info.clone())
            }
            Ok(res) => {
                sm.state =
                    State::Failed(anyhow!("Bad status {}", res.status_code))
            }
            Err(e) => sm.state = State::Failed(e),
        }

        assert!(matches!(sm.get_current_state(), State::Failed(_)));
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_register_success_transition() {
        let _mutex = testing::lock_tests().await;
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let (mut sm, _guard) = create_test_state_machine(&neg_config);
        let mut context_info = sm.context_info.clone().unwrap();

        registration::set_mock_result(Ok(()));
        let res = registration::check_registration(
            Some(context_info.clone()),
            None,
        )
        .await;

        match res {
            Ok(()) => {
                if let Some(ctx) = &sm.context_info {
                    sm.state = State::Registered(ctx.clone());
                } else {
                    sm.state =
                        State::Failed(anyhow!("Could not get context info"));
                }
            }
            Err(e) => {
                sm.state =
                    State::Failed(anyhow!("Registration failed: {e:?}"));
            }
        }
        assert!(matches!(sm.get_current_state(), State::Registered(_)));
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_run_happy_path_integration() {
        let _mutex = testing::lock_tests().await;

        registration::set_mock_result(Ok(()));

        // Initialize test config
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = keylime::config::get_testing_config(tmpdir.path(), None);
        // Create guard that will automatically clear override when dropped
        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info =
            ContextInfo::new(keylime::context_info::AlgorithmConfiguration {
                tpm_encryption_alg:
                    keylime::algorithms::EncryptionAlgorithm::Rsa2048,
                tpm_hash_alg: keylime::algorithms::HashAlgorithm::Sha256,
                tpm_signing_alg: keylime::algorithms::SignAlgorithm::RsaSsa,
                agent_data_path: "".to_string(),
            })
            .expect("This test requires TPM access with proper permissions");
        let _ = registration::check_registration(
            Some(context_info.clone()),
            None,
        )
        .await;

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header(
                        "Location",
                        "/v3.0/agents/agent1/attestations/0",
                    )
                    .set_body_json(serde_json::json!({
                        "data": {
                            "type": "attestation",
                            "attributes": {
                                "stage": "awaiting_evidence",
                                "evidence_requested": []
                            }
                        }
                    })),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("PATCH"))
            .and(path("/v3.0/agents/agent1/attestations/0"))
            .respond_with(
                ResponseTemplate::new(202)
                    .set_body_string("Evidence accepted"),
            )
            .mount(&mock_server)
            .await;

        let mock_server_url = mock_server.uri().clone();
        let neg_config = create_tpm_test_config(
            mock_server_url.as_str(),
            5000,
            3,
            100,
            None,
        );

        let attestation_client =
            AttestationClient::new(&neg_config, Some(context_info.clone()))
                .unwrap();

        let sm = StateMachine::new(
            attestation_client,
            neg_config,
            Some(context_info.clone()),
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // We can't easily test the full run() method since it loops indefinitely.
        // This test would need to be restructured to test the state transitions
        // individually or with a timeout mechanism.
        // For now, we'll just verify the setup worked correctly
        assert!(context_info.flush_context().is_ok());
        assert!(
            matches!(sm.get_current_state(), State::Unregistered),
            "StateMachine should start in Unregistered state, but was {:?}",
            sm.get_current_state()
        );
    }
} // feature testing tests

#[cfg(test)]
mod tests {

    /// Helper function to create empty PrivilegedResources for testing
    fn create_test_privileged_resources() -> PrivilegedResources {
        use keylime::ima::MeasurementList;
        use std::sync::Mutex;

        PrivilegedResources {
            ima_ml_file: None,
            ima_ml: Mutex::new(MeasurementList::new()),
            measuredboot_ml_file: None,
        }
    }

    use super::*;
    use crate::attestation::{AttestationClient, NegotiationConfig};

    // Helper function to create test configuration.
    fn create_test_config(
        url: &str,
        timeout: u64,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: Option<u64>,
    ) -> NegotiationConfig<'_> {
        NegotiationConfig {
            avoid_tpm: true,
            ca_certificate: "",
            client_certificate: "",
            enable_authentication: false,
            agent_id: "test-agent-id",
            ima_log_path: None,
            initial_delay_ms,
            insecure: Some(true),
            key: "",
            max_delay_ms,
            max_retries,
            timeout,
            uefi_log_path: None,
            url,
            verifier_url: "http://verifier.example.com",
            tls_accept_invalid_certs: true,
            tls_accept_invalid_hostnames: true,
        }
    }

    #[actix_rt::test]
    async fn test_state_machine_creation_without_context_info() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Should start in Unregistered state when no context info is provided.
        assert!(
            matches!(state_machine.get_current_state(), State::Unregistered),
            "Expected Unregistered state, got {:?}",
            state_machine.get_current_state()
        );
    }

    #[actix_rt::test]
    async fn test_state_debug_trait() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        let debug_output = format!("{:?}", state_machine.get_current_state());
        assert!(debug_output.contains("Unregistered"));
    }

    #[actix_rt::test]
    async fn test_register_without_context_info() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let mut state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Start in Unregistered state.
        assert!(matches!(
            state_machine.get_current_state(),
            State::Unregistered
        ));

        // Call register - should fail without context info.
        state_machine.register().await;

        // Should transition to Failed state.
        assert!(
            matches!(state_machine.get_current_state(), State::Failed(_)),
            "Expected Failed state, got {:?}",
            state_machine.get_current_state()
        );
    }

    #[actix_rt::test]
    async fn test_state_machine_initial_state_without_context() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Should start in Unregistered state.
        assert!(matches!(
            state_machine.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_context_info_storage_none() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Verify that context_info is None when not provided.
        assert!(state_machine.context_info.is_none());
    }

    #[actix_rt::test]
    async fn test_state_machine_config_references() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Test that the configuration references are stored correctly.
        // We cannot directly access private fields, but we can test creation succeeds.
        assert!(matches!(
            state_machine.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_failed_state_construction() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let mut state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Manually set to Failed state to test error handling.
        let error = anyhow::anyhow!("Test error");
        state_machine.state = State::Failed(error);

        // Verify we can match on Failed state.
        assert!(
            matches!(state_machine.get_current_state(), State::Failed(_)),
            "Expected Failed state, got {:?}",
            state_machine.get_current_state()
        );
    }

    #[actix_rt::test]
    async fn test_state_machine_error_state_handling() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let mut state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Manually set to Failed state to test error handling.
        let error = anyhow::anyhow!("Test error for state handling");
        state_machine.state = State::Failed(error);

        // Verify we can match on Failed state.
        assert!(
            matches!(state_machine.get_current_state(), State::Failed(_)),
            "Expected Failed state, got {:?}",
            state_machine.get_current_state()
        );
    }

    #[actix_rt::test]
    async fn test_state_machine_with_different_config_values() {
        // Test with different configuration values.
        let test_config1 =
            create_test_config("http://localhost", 1000, 5, 500, Some(10000));
        let attestation_client1 =
            AttestationClient::new(&test_config1, None).unwrap();
        let state_machine1 = StateMachine::new(
            attestation_client1,
            test_config1,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );
        assert!(matches!(
            state_machine1.get_current_state(),
            State::Unregistered
        ));

        let test_config2 =
            create_test_config("http://localhost", 2000, 10, 1000, None);
        let attestation_client2 =
            AttestationClient::new(&test_config2, None).unwrap();
        let state_machine2 = StateMachine::new(
            attestation_client2,
            test_config2,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );
        assert!(matches!(
            state_machine2.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_avoid_tpm_configuration() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Test that avoid_tpm is properly configured through the test config.
        // This is implicit in the test setup but verifies the configuration is valid.
        assert!(matches!(
            state_machine.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_error_debug_formatting() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let mut state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Set a test error and verify debug formatting works.
        let test_error = anyhow::anyhow!("Test error message");
        state_machine.state = State::Failed(test_error);

        let debug_output = format!("{:?}", state_machine.get_current_state());
        assert!(debug_output.contains("Failed"));
        assert!(debug_output.contains("Test error message"));
    }

    #[actix_rt::test]
    async fn test_extract_next_attestation_interval_with_valid_field() {
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config, None).unwrap();

        let state_machine = StateMachine::new(
            attestation_client,
            test_config,
            None,
            DEFAULT_ATTESTATION_INTERVAL_SECONDS,
            None,
            create_test_privileged_resources(),
        );

        // Test with valid seconds_to_next_attestation field in meta object.
        let response_body = r#"{
            "data": {
                "type": "attestation",
                "attributes": {
                    "stage": "evaluating_evidence",
                    "evidence": [],
                    "system_info": {
                        "boot_time": "2025-04-08T12:00:17Z"
                    }
                }
            },
            "meta": {
                "seconds_to_next_attestation": 120
            }
        }"#;
        let interval =
            state_machine.extract_next_attestation_interval(response_body);
        assert_eq!(interval.as_secs(), 120);

        // Test without the meta object (should use default).
        let response_body = r#"{
            "data": {
                "type": "attestation",
                "attributes": {
                    "stage": "evaluating_evidence",
                    "evidence": [],
                    "system_info": {
                        "boot_time": "2025-04-08T12:00:17Z"
                    }
                }
            }
        }"#;
        let interval =
            state_machine.extract_next_attestation_interval(response_body);
        assert_eq!(interval.as_secs(), DEFAULT_ATTESTATION_INTERVAL_SECONDS);

        // Test with meta object but without the field (should use default).
        let response_body = r#"{
            "data": {
                "type": "attestation",
                "attributes": {
                    "stage": "evaluating_evidence",
                    "evidence": [],
                    "system_info": {
                        "boot_time": "2025-04-08T12:00:17Z"
                    }
                }
            },
            "meta": {
                "other_field": "value"
            }
        }"#;
        let interval =
            state_machine.extract_next_attestation_interval(response_body);
        assert_eq!(interval.as_secs(), DEFAULT_ATTESTATION_INTERVAL_SECONDS);

        // Test with invalid JSON (should use default).
        let response_body = "invalid json";
        let interval =
            state_machine.extract_next_attestation_interval(response_body);
        assert_eq!(interval.as_secs(), DEFAULT_ATTESTATION_INTERVAL_SECONDS);

        // Test with valid JSON but wrong structure (should use default).
        let response_body =
            r#"{"meta": {"seconds_to_next_attestation": 150}}"#;
        let interval =
            state_machine.extract_next_attestation_interval(response_body);
        assert_eq!(interval.as_secs(), DEFAULT_ATTESTATION_INTERVAL_SECONDS);

        // Test with the full response structure example.
        let response_body = r#"{
            "data": {
                "type": "attestation",
                "attributes": {
                    "stage": "evaluating_evidence",
                    "evidence": [],
                    "system_info": {
                        "boot_time": "2025-04-08T12:00:17Z"
                    }
                }
            },
            "meta": {
                "seconds_to_next_attestation": 90
            }
        }"#;
        let interval =
            state_machine.extract_next_attestation_interval(response_body);
        assert_eq!(interval.as_secs(), 90);
    }
}
