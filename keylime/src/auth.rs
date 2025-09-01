// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Authentication types and utilities
//!
//! This module provides common types and utilities for authentication
//! that are shared between different components of the Keylime system.

use crate::structures::{
    ProofOfPossession, SessionIdResponse, SessionRequest,
    SessionRequestAttributes, SessionRequestData, SessionResponse,
    SupportedAuthMethod,
};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Configuration for authentication
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Base URL of the verifier (e.g., "https://verifier.example.com")
    pub verifier_base_url: String,
    /// Agent identifier for authentication
    pub agent_id: String,
    /// Whether to avoid TPM operations (for testing)
    pub avoid_tpm: bool,
    /// HTTP client timeout in milliseconds
    pub timeout_ms: u64,
    /// Buffer time before token expiration to refresh (in minutes)
    pub token_refresh_buffer_minutes: i64,
    /// Maximum number of authentication retries
    pub max_auth_retries: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            verifier_base_url: "https://127.0.0.1:8881".to_string(),
            agent_id: "test-agent".to_string(),
            avoid_tpm: true,
            timeout_ms: 5000,
            token_refresh_buffer_minutes: 5,
            max_auth_retries: 3,
        }
    }
}

/// Session token with expiration information
#[derive(Debug, Clone)]
pub struct SessionToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub session_id: u64,
}

impl SessionToken {
    pub fn is_valid(&self, buffer_minutes: i64) -> bool {
        let buffer = Duration::minutes(buffer_minutes);
        Utc::now() + buffer < self.expires_at
    }
}

/// Mock TPM operations for testing
pub trait TpmOperations: Send + Sync {
    fn generate_proof(
        &self,
        challenge: &str,
    ) -> Result<crate::structures::ProofOfPossession>;
}

/// Default mock TPM implementation
#[derive(Debug, Clone)]
pub struct MockTpmOperations;

impl TpmOperations for MockTpmOperations {
    fn generate_proof(
        &self,
        challenge: &str,
    ) -> Result<crate::structures::ProofOfPossession> {
        use log::debug;
        debug!("Generating mock TPM proof for challenge: {challenge}");

        // Create a deterministic but unique proof based on the challenge
        let message = format!("mock_message_for_{challenge}");
        let signature = format!("mock_signature_for_{challenge}");

        use base64::{engine::general_purpose, Engine as _};

        Ok(crate::structures::ProofOfPossession {
            message: general_purpose::STANDARD.encode(message),
            signature: general_purpose::STANDARD.encode(signature),
        })
    }
}

/// Standalone authentication client implementing the challenge-response protocol
pub struct AuthenticationClient {
    config: AuthConfig,
    http_client: Client,
    session_token: Arc<Mutex<Option<SessionToken>>>,
    tpm_ops: Box<dyn TpmOperations>,
}

impl std::fmt::Debug for AuthenticationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticationClient")
            .field("config", &self.config)
            .field("http_client", &"<Client>")
            .field("session_token", &"<Arc<Mutex<SessionToken>>>")
            .field("tpm_ops", &"<Box<dyn TpmOperations>>")
            .finish()
    }
}

impl AuthenticationClient {
    /// Create a new authentication client with the given configuration
    pub fn new(config: AuthConfig) -> Result<Self> {
        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let http_client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true) // For testing
            .build()?;

        Ok(Self {
            config,
            http_client,
            session_token: Arc::new(Mutex::new(None)),
            tpm_ops: Box::new(MockTpmOperations),
        })
    }

    /// Create a new authentication client with custom TPM operations
    pub fn with_tpm_ops(
        config: AuthConfig,
        tpm_ops: Box<dyn TpmOperations>,
    ) -> Result<Self> {
        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let http_client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true) // For testing
            .build()?;

        Ok(Self {
            config,
            http_client,
            session_token: Arc::new(Mutex::new(None)),
            tpm_ops,
        })
    }

    /// Create a raw authentication client with no middleware
    /// This is used internally by the authentication middleware to avoid infinite loops
    pub fn new_raw(config: AuthConfig) -> Result<Self> {
        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let http_client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true) // For testing
            .build()?;

        Ok(Self {
            config,
            http_client,
            session_token: Arc::new(Mutex::new(None)),
            tpm_ops: Box::new(MockTpmOperations),
        })
    }

    /// Create a raw authentication client with custom TPM operations and no middleware
    pub fn new_raw_with_tpm_ops(
        config: AuthConfig,
        tpm_ops: Box<dyn TpmOperations>,
    ) -> Result<Self> {
        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let http_client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true) // For testing
            .build()?;

        Ok(Self {
            config,
            http_client,
            session_token: Arc::new(Mutex::new(None)),
            tpm_ops,
        })
    }

    /// Get the authentication configuration
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Get a valid authentication token with metadata (token, expiration, session_id)
    /// This method is used by the authentication middleware to access token details
    pub async fn get_auth_token_with_metadata(
        &self,
    ) -> Result<(String, DateTime<Utc>, u64)> {
        let token_guard = self.session_token.lock().await;

        // Check if we have a valid token
        if let Some(ref token) = *token_guard {
            if token.is_valid(self.config.token_refresh_buffer_minutes) {
                debug!("Using existing valid token with metadata");
                return Ok((
                    token.token.clone(),
                    token.expires_at,
                    token.session_id,
                ));
            } else {
                debug!(
                    "Token expired or expiring soon, need to re-authenticate"
                );
            }
        } else {
            debug!("No token available, need to authenticate");
        }

        drop(token_guard); // Release lock before authentication

        // Perform authentication and return metadata
        let _token_string = self.authenticate().await?;

        // Get the token details from the newly stored token
        let token_guard = self.session_token.lock().await;
        if let Some(ref token) = *token_guard {
            Ok((token.token.clone(), token.expires_at, token.session_id))
        } else {
            Err(anyhow!(
                "Token was not stored properly after authentication"
            ))
        }
    }

    /// Perform the complete authentication flow
    async fn authenticate(&self) -> Result<String> {
        info!(
            "Starting authentication flow for agent: {}",
            self.config.agent_id
        );

        let mut retries = 0;
        while retries < self.config.max_auth_retries {
            match self.do_authenticate().await {
                Ok(token) => {
                    info!("Authentication successful");
                    return Ok(token);
                }
                Err(e) => {
                    retries += 1;
                    warn!(
                        "Authentication attempt {} failed: {}. Retries left: {}",
                        retries,
                        e,
                        self.config.max_auth_retries - retries
                    );
                    if retries >= self.config.max_auth_retries {
                        return Err(anyhow!(
                            "Authentication failed after {} retries: {}",
                            self.config.max_auth_retries,
                            e
                        ));
                    }
                    // Brief delay before retry
                    tokio::time::sleep(std::time::Duration::from_millis(
                        1000,
                    ))
                    .await;
                }
            }
        }

        Err(anyhow!("Authentication failed"))
    }

    /// Internal authentication implementation
    async fn do_authenticate(&self) -> Result<String> {
        // Step 1: Request challenge
        debug!("Step 1: Requesting challenge from verifier");
        let challenge_response = self.request_challenge().await?;

        // Step 2: Generate TPM proof
        debug!("Step 2: Generating TPM proof of possession");
        let proof = self.generate_tpm_proof(&challenge_response)?;

        // Step 3: Submit proof and get token
        debug!("Step 3: Submitting proof and requesting token");
        let auth_response =
            self.submit_proof(challenge_response.data.id, proof).await?;

        // Step 4: Store token
        debug!("Step 4: Processing authentication result");
        let token = self.process_auth_result(auth_response).await?;

        Ok(token)
    }

    /// Step 1: Request challenge from verifier
    async fn request_challenge(&self) -> Result<SessionResponse> {
        let session_request = SessionRequest {
            data: SessionRequestData {
                data_type: "session".to_string(),
                attributes: SessionRequestAttributes {
                    agent_id: self.config.agent_id.clone(),
                    auth_supported: vec![SupportedAuthMethod {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                    }],
                },
            },
        };

        let url = format!("{}/sessions", self.config.verifier_base_url);
        debug!("Requesting challenge from: {url}");

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/vnd.api+json")
            .json(&session_request)
            .send()
            .await?;

        let status = response.status();
        debug!("Challenge request response status: {status}");

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Challenge request failed with status {}: {}",
                status,
                error_text
            ));
        }

        let session_response: SessionResponse = response.json().await?;
        debug!(
            "Received challenge response with session ID: {}",
            session_response.data.id
        );

        Ok(session_response)
    }

    /// Step 2: Generate TPM proof of possession
    fn generate_tpm_proof(
        &self,
        challenge_response: &SessionResponse,
    ) -> Result<ProofOfPossession> {
        if challenge_response.data.attributes.auth_requested.is_empty() {
            return Err(anyhow!(
                "No authentication methods requested by verifier"
            ));
        }

        let auth_method =
            &challenge_response.data.attributes.auth_requested[0];
        let challenge = &auth_method.parameters.challenge;

        debug!("Generating proof for challenge: {challenge}");
        debug!(
            "Authentication method: {} / {}",
            auth_method.auth_class, auth_method.auth_type
        );

        self.tpm_ops.generate_proof(challenge)
    }

    /// Step 3: Submit proof and get authentication result
    async fn submit_proof(
        &self,
        session_id: u64,
        proof: ProofOfPossession,
    ) -> Result<SessionIdResponse> {
        // Since SessionIdRequestData has private data_type field,
        // we need to construct the JSON manually
        let session_update_json = serde_json::json!({
            "data": {
                "type": "session",
                "id": session_id,
                "attributes": {
                    "agent_id": self.config.agent_id,
                    "authentication_provided": [{
                        "authentication_class": "pop",
                        "authentication_type": "tpm_pop",
                        "data": {
                            "message": proof.message,
                            "signature": proof.signature
                        }
                    }]
                }
            }
        });

        let url = format!(
            "{}/sessions/{}",
            self.config.verifier_base_url, session_id
        );
        debug!("Submitting proof to: {url}");

        let response = self
            .http_client
            .patch(&url)
            .header("Content-Type", "application/vnd.api+json")
            .json(&session_update_json)
            .send()
            .await?;

        let status = response.status();
        debug!("Proof submission response status: {status}");

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Proof submission failed with status {}: {}",
                status,
                error_text
            ));
        }

        let auth_response: SessionIdResponse = response.json().await?;
        debug!(
            "Received authentication result: {}",
            auth_response.data.attributes.evaluation
        );

        Ok(auth_response)
    }

    /// Step 4: Process authentication result and store token
    async fn process_auth_result(
        &self,
        auth_response: SessionIdResponse,
    ) -> Result<String> {
        let attributes = &auth_response.data.attributes;

        if attributes.evaluation != "success" {
            return Err(anyhow!(
                "Authentication failed with evaluation: {}",
                attributes.evaluation
            ));
        }

        let token = attributes.token.as_ref().ok_or_else(|| {
            anyhow!("Authentication succeeded but no token provided")
        })?;

        let expires_at = attributes.token_expires_at.unwrap_or_else(|| {
            // Default to 1 hour if no expiration provided
            Utc::now() + Duration::hours(1)
        });

        let session_token = SessionToken {
            token: token.clone(),
            expires_at,
            session_id: auth_response.data.id,
        };

        debug!(
            "Storing session token (expires at: {})",
            session_token.expires_at
        );

        let mut token_guard = self.session_token.lock().await;
        *token_guard = Some(session_token);

        Ok(token.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn create_test_client(
        mock_server_url: &str,
    ) -> AuthenticationClient {
        let config = AuthConfig {
            verifier_base_url: mock_server_url.to_string(),
            agent_id: "test-agent-123".to_string(),
            avoid_tpm: true,
            timeout_ms: 1000,
            token_refresh_buffer_minutes: 5,
            max_auth_retries: 2,
        };

        AuthenticationClient::new(config).unwrap() //#[allow_ci]
    }

    #[tokio::test]
    async fn test_successful_authentication_flow() {
        let mock_server = MockServer::start().await;

        // Mock challenge request (POST /sessions)
        Mock::given(method("POST"))
            .and(path("/sessions"))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": 1,
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "authentication_requested": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "test-challenge-123"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2025-01-01T13:00:00Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

        // Mock proof submission (PATCH /sessions/1)
        Mock::given(method("PATCH"))
            .and(path("/sessions/1"))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": 1,
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "evaluation": "success",
                            "token": "test-token-456",
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
                            "challenges_expire_at": "2025-01-01T13:00:00Z",
                            "response_received_at": "2025-01-01T12:00:01Z",
                            "token_expires_at": "2030-01-01T18:00:00Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri()).await;

        // Test authentication - get token with metadata since that's our main method
        let (token, _expires_at, session_id) =
            client.get_auth_token_with_metadata().await.unwrap(); //#[allow_ci]
        assert_eq!(token, "test-token-456");
        assert_eq!(session_id, 1);

        // Verify token is valid
        let token_guard = client.session_token.lock().await;
        let session_token = token_guard.as_ref().unwrap(); //#[allow_ci]
        assert!(session_token.is_valid(5));
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let mock_server = MockServer::start().await;

        // Mock challenge request
        Mock::given(method("POST"))
            .and(path("/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": 1,
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "authentication_requested": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "test-challenge-123"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2025-01-01T13:00:00Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

        // Mock proof submission failure
        Mock::given(method("PATCH"))
            .and(path("/sessions/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": 1,
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "evaluation": "fail",
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
                            "challenges_expire_at": "2025-01-01T13:00:00Z",
                            "response_received_at": "2025-01-01T12:00:01Z"
                        }
                    }
                }),
            ))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri()).await;

        let result = client.get_auth_token_with_metadata().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err() //#[allow_ci]
            .to_string()
            .contains("Authentication failed"));
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let mock_server = MockServer::start().await;

        // Mock challenge request
        Mock::given(method("POST"))
            .and(path("/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": 1,
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "authentication_requested": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "test-challenge-123"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2025-01-01T13:00:00Z"
                        }
                    }
                }),
            ))
            .expect(1..) //#[allow_ci] // May be called multiple times
            .mount(&mock_server)
            .await;

        // Mock proof submission with short expiration
        Mock::given(method("PATCH"))
            .and(path("/sessions/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": 1,
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "evaluation": "success",
                            "token": "short-lived-token",
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
                            "challenges_expire_at": "2025-01-01T13:00:00Z",
                            "response_received_at": "2025-01-01T12:00:01Z",
                            // Token expires in 1 minute (less than 5 minute buffer)
                            "token_expires_at": "2025-01-01T12:01:00Z"
                        }
                    }
                }),
            ))
            .expect(1..) //#[allow_ci] // May be called multiple times
            .mount(&mock_server)
            .await;

        let config = AuthConfig {
            verifier_base_url: mock_server.uri(),
            agent_id: "test-agent-123".to_string(),
            avoid_tpm: true,
            timeout_ms: 1000,
            token_refresh_buffer_minutes: 5, // 5 minute buffer
            max_auth_retries: 2,
        };

        let client = AuthenticationClient::new(config).unwrap(); //#[allow_ci]

        // Since token expires in 1 minute but we have 5 minute buffer,
        // it should be considered invalid and trigger re-authentication
        let (token, _, _) =
            client.get_auth_token_with_metadata().await.unwrap(); //#[allow_ci]
        assert_eq!(token, "short-lived-token");

        // Check that token is considered invalid due to buffer
        let token_guard = client.session_token.lock().await;
        let session_token = token_guard.as_ref().unwrap(); //#[allow_ci]
        assert!(!session_token.is_valid(5));
    }

    #[tokio::test]
    async fn test_raw_client_creation() {
        let config = AuthConfig {
            verifier_base_url: "https://127.0.0.1:8881".to_string(),
            agent_id: "test-agent-raw".to_string(),
            avoid_tpm: true,
            timeout_ms: 1000,
            token_refresh_buffer_minutes: 5,
            max_auth_retries: 2,
        };

        let raw_client = AuthenticationClient::new_raw(config).unwrap(); //#[allow_ci]

        // Verify the client was created successfully
        assert_eq!(raw_client.config.agent_id, "test-agent-raw");
        assert_eq!(raw_client.config.timeout_ms, 1000);
        assert!(raw_client.config.avoid_tpm);
    }

    #[tokio::test]
    async fn test_raw_client_with_tpm_ops() {
        let config = AuthConfig {
            verifier_base_url: "https://127.0.0.1:8881".to_string(),
            agent_id: "test-agent-raw-tpm".to_string(),
            avoid_tpm: false,
            timeout_ms: 2000,
            token_refresh_buffer_minutes: 10,
            max_auth_retries: 1,
        };

        let custom_tpm_ops = Box::new(MockTpmOperations);
        let raw_client = AuthenticationClient::new_raw_with_tpm_ops(
            config,
            custom_tpm_ops,
        )
        .unwrap(); //#[allow_ci]

        // Verify the client was created successfully
        assert_eq!(raw_client.config.agent_id, "test-agent-raw-tpm");
        assert_eq!(raw_client.config.timeout_ms, 2000);
        assert!(!raw_client.config.avoid_tpm);
    }
}
