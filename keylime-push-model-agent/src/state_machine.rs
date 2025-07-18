// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

use crate::attestation::{
    AttestationClient, NegotiationConfig, ResponseInformation,
};
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
                self.state =
                    State::Failed(anyhow!("Registration failed: {e:?}"));
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
    #[cfg(test)]
    pub fn get_current_state(&self) -> &State {
        &self.state
    }
}

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
