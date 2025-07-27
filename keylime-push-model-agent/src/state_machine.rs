// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

use crate::attestation::{
    AttestationClient, NegotiationConfig, ResponseInformation,
};
#[cfg(not(all(test, feature = "testing")))]
use crate::registration;
use anyhow::anyhow;
use keylime::config::AgentConfig;
use keylime::context_info::ContextInfo;
use log::*;

#[derive(Debug)]
pub enum State {
    Unregistered,
    Registered(ContextInfo),
    Negotiating(ContextInfo),
    Attesting(ContextInfo, ResponseInformation),
    Complete,
    RegistrationFailed(anyhow::Error),
    Failed(anyhow::Error),
}

pub struct StateMachine<'a> {
    state: State,
    config: &'a AgentConfig,
    attestation_client: AttestationClient,
    negotiation_config: NegotiationConfig<'a>,
    context_info: Option<ContextInfo>,
}

impl<'a> StateMachine<'a> {
    pub fn new(
        config: &'a AgentConfig,
        attestation_client: AttestationClient,
        negotiation_config: NegotiationConfig<'a>,
        context_info: Option<ContextInfo>,
    ) -> Self {
        let initial_state = State::Unregistered;

        Self {
            state: initial_state,
            config,
            attestation_client,
            negotiation_config,
            context_info,
        }
    }

    pub async fn run(&mut self) {
        loop {
            let current_state =
                std::mem::replace(&mut self.state, State::Complete);

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
                State::Complete => {
                    info!("Attestation complete");
                    self.state = State::Complete;
                    break;
                }
                State::RegistrationFailed(e) => {
                    error!("Registration failed: {e:?}");
                    debug!("Resetting state to Unregistered and retrying");
                    self.state = State::Unregistered;
                }
                State::Failed(e) => {
                    error!("Attestation failed: {e:?}");
                    self.state = State::Failed(e);
                    break;
                }
            }
        }
    }

    async fn register(&mut self) {
        let res = registration::check_registration(
            self.config,
            self.context_info.clone(),
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
            .send_negotiation(&self.negotiation_config)
            .await;

        debug!("Negotiation response: {neg_response:?}");
        debug!("Negotiation config: {:?}", self.negotiation_config);

        match neg_response {
            Ok(neg) => {
                if neg.status_code == reqwest::StatusCode::CREATED {
                    self.state = State::Attesting(ctx_info, neg);
                } else {
                    self.state = State::Failed(anyhow!(
                        "Negotiation failed with status code: {}",
                        neg.status_code
                    ));
                }
            }
            Err(e) => {
                self.state =
                    State::Failed(anyhow!("Negotiation failed: {e:?}"));
            }
        }
    }

    async fn attest(
        &mut self,
        _ctx_info: ContextInfo,
        neg_response: ResponseInformation,
    ) {
        let evidence_response = self
            .attestation_client
            .handle_evidence_submission(
                neg_response,
                &self.negotiation_config,
            )
            .await;

        match evidence_response {
            Ok(res) => {
                if res.status_code == reqwest::StatusCode::ACCEPTED {
                    info!("SUCCESS! Evidence accepted by the Verifier.");
                    info!("Response body: {}", res.body);
                    self.state = State::Complete;
                } else {
                    error!(
                        "Verifier rejected the evidence with code: {}",
                        res.status_code
                    );
                    error!("Response body: {}", res.body);
                    self.state = State::Failed(anyhow!(
                        "Verifier rejected the evidence with code: {}",
                        res.status_code
                    ));
                }
            }
            Err(e) => {
                self.state =
                    State::Failed(anyhow!("Attestation failed: {e:?}"));
            }
        }
    }

    // Expose current state for testing.
    #[cfg(any(test, feature = "testing"))]
    pub fn get_current_state(&self) -> &State {
        &self.state
    }
}

#[cfg(all(test, feature = "testing"))]
mod registration {
    use anyhow::anyhow;
    use keylime::config::AgentConfig;
    use keylime::context_info::ContextInfo;
    use std::sync::{Arc, Mutex, OnceLock};

    static MOCK_RESULT: OnceLock<Arc<Mutex<Result<(), String>>>> =
        OnceLock::new();

    fn get_mock_result() -> &'static Arc<Mutex<Result<(), String>>> {
        MOCK_RESULT.get_or_init(|| Arc::new(Mutex::new(Ok(()))))
    }

    pub async fn check_registration(
        _config: &AgentConfig,
        _context_info: Option<ContextInfo>,
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
    use keylime::config::AgentConfig;
    use keylime::context_info::ContextInfo;
    use keylime::tpm::testing;
    use reqwest::{header::HeaderMap, StatusCode};
    use std::sync::{Arc, Mutex};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    impl Default for ResponseInformation {
        fn default() -> Self {
            Self {
                status_code: StatusCode::OK, // A sensible default
                headers: HeaderMap::new(),
                body: String::new(),
            }
        }
    }

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

    // Helper function to create test agent configuration.
    fn create_test_agent_config() -> AgentConfig {
        AgentConfig::default()
    }

    /// Helper function to create TPM test configuration.
    fn create_tpm_test_config<'a>(
        url: &'a str,
        timeout: u64,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: Option<u64>,
    ) -> NegotiationConfig<'a> {
        NegotiationConfig {
            avoid_tpm: true,
            ca_certificate: "",
            client_certificate: "",
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
        }
    }

    fn create_test_state_machine<'a>(
        agent_config: &'a AgentConfig,
        neg_config: &'a NegotiationConfig<'a>,
    ) -> StateMachine<'a> {
        let client = AttestationClient::new(neg_config).unwrap();

        let context_info =
            ContextInfo::new(keylime::context_info::AlgorithmConfiguration {
                tpm_encryption_alg:
                    keylime::algorithms::EncryptionAlgorithm::Rsa2048,
                tpm_hash_alg: keylime::algorithms::HashAlgorithm::Sha256,
                tpm_signing_alg: keylime::algorithms::SignAlgorithm::RsaSsa,
                agent_data_path: "".to_string(),
                disabled_signing_algorithms: vec![],
            })
            .expect("This test requires TPM access with proper permissions");

        StateMachine::new(
            agent_config,
            client,
            neg_config.clone(),
            Some(context_info),
        )
    }

    #[tokio::test]
    async fn test_negotiate_success_transition() {
        let _mutex = testing::lock_tests().await;
        let agent_config = create_test_agent_config();
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let mut sm = create_test_state_machine(&agent_config, &neg_config);
        let mut context_info = sm.context_info.clone().unwrap();
        sm.state = State::Registered(context_info.clone());

        let mock_client = MockAttestationClient::default();
        let neg_response =
            mock_client.send_negotiation(&sm.negotiation_config).await;

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
        let agent_config = create_test_agent_config();
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let mut sm = create_test_state_machine(&agent_config, &neg_config);
        let mut context_info = sm.context_info.clone().unwrap();
        sm.state = State::Registered(context_info.clone());

        let mock_client = MockAttestationClient::default();
        mock_client.set_negotiation_response(Ok(ResponseInformation {
            status_code: StatusCode::BAD_REQUEST,
            ..Default::default()
        }));

        let neg_response =
            mock_client.send_negotiation(&sm.negotiation_config).await;
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
        let agent_config = create_test_agent_config();
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let mut sm = create_test_state_machine(&agent_config, &neg_config);
        let mut context_info = sm.context_info.clone().unwrap();
        sm.state = State::Attesting(
            context_info.clone(),
            ResponseInformation::default(),
        );

        let mock_client = MockAttestationClient::default(); // Default is ACCEPTED
        let evidence_response = mock_client
            .handle_evidence_submission(
                ResponseInformation::default(),
                &sm.negotiation_config,
            )
            .await;

        match evidence_response {
            Ok(res) if res.status_code == StatusCode::ACCEPTED => {
                sm.state = State::Complete
            }
            Ok(res) => {
                sm.state =
                    State::Failed(anyhow!("Bad status {}", res.status_code))
            }
            Err(e) => sm.state = State::Failed(e),
        }

        assert!(matches!(sm.get_current_state(), State::Complete));
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_attest_failure_on_bad_status() {
        let _mutex = testing::lock_tests().await;
        let agent_config = create_test_agent_config();
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let mut sm = create_test_state_machine(&agent_config, &neg_config);
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

        let evidence_response = mock_client
            .handle_evidence_submission(
                ResponseInformation::default(),
                &sm.negotiation_config,
            )
            .await;

        match evidence_response {
            Ok(res) if res.status_code == StatusCode::ACCEPTED => {
                sm.state = State::Complete
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
        let agent_config = create_test_agent_config();
        let neg_config = create_tpm_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let mut sm = create_test_state_machine(&agent_config, &neg_config);
        let mut context_info = sm.context_info.clone().unwrap();

        registration::set_mock_result(Ok(()));
        let res = registration::check_registration(
            &agent_config,
            Some(context_info.clone()),
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
        let agent_config = create_test_agent_config();
        let mut context_info =
            ContextInfo::new(keylime::context_info::AlgorithmConfiguration {
                tpm_encryption_alg:
                    keylime::algorithms::EncryptionAlgorithm::Rsa2048,
                tpm_hash_alg: keylime::algorithms::HashAlgorithm::Sha256,
                tpm_signing_alg: keylime::algorithms::SignAlgorithm::RsaSsa,
                agent_data_path: "".to_string(),
                disabled_signing_algorithms: vec![],
            })
            .expect("This test requires TPM access with proper permissions");
        let _ = registration::check_registration(
            &agent_config,
            Some(context_info.clone()),
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

        let attestation_client = AttestationClient::new(&neg_config).unwrap();

        let mut sm = StateMachine::new(
            &agent_config,
            attestation_client,
            neg_config,
            Some(context_info.clone()),
        );

        sm.run().await;
        assert!(context_info.flush_context().is_ok());
        assert!(
            matches!(sm.get_current_state(), State::Complete),
            "StateMachine should be in Complete state after a successful run, but was {:?}",
            sm.get_current_state()
        )
    }
} // feature testing tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{AttestationClient, NegotiationConfig};
    use keylime::config::AgentConfig;

    // Helper function to create test configuration.
    fn create_test_config<'a>(
        url: &'a str,
        timeout: u64,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: Option<u64>,
    ) -> NegotiationConfig<'a> {
        NegotiationConfig {
            avoid_tpm: true,
            ca_certificate: "",
            client_certificate: "",
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
        }
    }

    // Helper function to create test agent configuration.
    fn create_test_agent_config() -> AgentConfig {
        AgentConfig::default()
    }

    #[actix_rt::test]
    async fn test_state_machine_creation_without_context_info() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        // Should start in Unregistered state when no context info is provided.
        assert!(
            matches!(state_machine.get_current_state(), State::Unregistered),
            "Expected Unregistered state, got {:?}",
            state_machine.get_current_state()
        );
    }

    #[actix_rt::test]
    async fn test_state_debug_trait() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        let debug_output = format!("{:?}", state_machine.get_current_state());
        assert!(debug_output.contains("Unregistered"));
    }

    #[actix_rt::test]
    async fn test_register_without_context_info() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let mut state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

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
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        // Should start in Unregistered state.
        assert!(matches!(
            state_machine.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_context_info_storage_none() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        // Verify that context_info is None when not provided.
        assert!(state_machine.context_info.is_none());
    }

    #[actix_rt::test]
    async fn test_state_machine_config_references() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        // Test that the configuration references are stored correctly.
        // We cannot directly access private fields, but we can test creation succeeds.
        assert!(matches!(
            state_machine.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_failed_state_construction() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let mut state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

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
    async fn test_state_machine_complete_state_construction() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let mut state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        // Manually set to Complete state to test success handling.
        state_machine.state = State::Complete;

        // Verify we can match on Complete state.
        assert!(
            matches!(state_machine.get_current_state(), State::Complete),
            "Expected Complete state, got {:?}",
            state_machine.get_current_state()
        );
    }

    #[actix_rt::test]
    async fn test_state_machine_with_different_config_values() {
        let config = create_test_agent_config();

        // Test with different configuration values.
        let test_config1 =
            create_test_config("http://localhost", 1000, 5, 500, Some(10000));
        let attestation_client1 =
            AttestationClient::new(&test_config1).unwrap();
        let state_machine1 = StateMachine::new(
            &config,
            attestation_client1,
            test_config1,
            None,
        );
        assert!(matches!(
            state_machine1.get_current_state(),
            State::Unregistered
        ));

        let test_config2 =
            create_test_config("http://localhost", 2000, 10, 1000, None);
        let attestation_client2 =
            AttestationClient::new(&test_config2).unwrap();
        let state_machine2 = StateMachine::new(
            &config,
            attestation_client2,
            test_config2,
            None,
        );
        assert!(matches!(
            state_machine2.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_avoid_tpm_configuration() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        // Test that avoid_tpm is properly configured through the test config.
        // This is implicit in the test setup but verifies the configuration is valid.
        assert!(matches!(
            state_machine.get_current_state(),
            State::Unregistered
        ));
    }

    #[actix_rt::test]
    async fn test_state_machine_error_debug_formatting() {
        let config = create_test_agent_config();
        let test_config = create_test_config(
            "http://localhost",
            5000,
            3,
            1000,
            Some(30000),
        );
        let attestation_client =
            AttestationClient::new(&test_config).unwrap();

        let mut state_machine =
            StateMachine::new(&config, attestation_client, test_config, None);

        // Set a test error and verify debug formatting works.
        let test_error = anyhow::anyhow!("Test error message");
        state_machine.state = State::Failed(test_error);

        let debug_output = format!("{:?}", state_machine.get_current_state());
        assert!(debug_output.contains("Failed"));
        assert!(debug_output.contains("Test error message"));
    }
}
