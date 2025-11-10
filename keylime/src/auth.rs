// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Authentication types and utilities
//!
//! This module provides common types and utilities for authentication
//! that are shared between different components of the Keylime system.

use crate::{
    config::{
        get_config, PushModelConfigTrait, DEFAULT_AUTH_MAX_RETRIES,
        DEFAULT_AUTH_TIMEOUT_MS,
        DEFAULT_AUTH_TOKEN_EXPIRATION_FALLBACK_MINUTES, DEFAULT_VERIFIER_URL,
    },
    context_info::{AlgorithmConfigurationString, ContextInfo},
    structures::{
        ProofOfPossession, SessionIdRequest, SessionIdRequestAuthProvided,
        SessionIdResponse, SessionRequest, SessionRequestAttributes,
        SessionRequestData, SessionResponse, SessionUpdateAttributes,
        SupportedAuthMethod,
    },
};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Default API version for Keylime push model endpoints
pub const DEFAULT_PUSH_API_VERSION: &str = "v3.0";

/// Get the API version to use for push model endpoints
/// Returns the provided version or the default if None
pub fn get_push_api_version(api_version: Option<&String>) -> String {
    if let Some(version) = api_version {
        version.clone()
    } else {
        DEFAULT_PUSH_API_VERSION.to_string()
    }
}

/// Configuration for authentication
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Base URL of the verifier (e.g., "https://verifier.example.com:8881")
    pub verifier_base_url: String,
    /// Agent identifier for authentication
    pub agent_id: String,
    /// API version to use (e.g., "v3.0"), defaults to DEFAULT_PUSH_API_VERSION if None
    pub api_version: Option<String>,
    /// Whether to avoid TPM operations (for testing)
    pub avoid_tpm: bool,
    /// HTTP client timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum number of authentication retries
    pub max_auth_retries: u32,
    /// Accept invalid TLS certificates (INSECURE - for testing only)
    pub accept_invalid_certs: bool,
    /// Accept invalid TLS hostnames (INSECURE - for testing only)
    pub accept_invalid_hostnames: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            verifier_base_url: DEFAULT_VERIFIER_URL.to_string(),
            agent_id: "test-agent".to_string(),
            api_version: None,
            avoid_tpm: true,
            timeout_ms: DEFAULT_AUTH_TIMEOUT_MS,
            max_auth_retries: DEFAULT_AUTH_MAX_RETRIES,
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
        }
    }
}

/// Session token with expiration information
#[derive(Debug, Clone)]
pub struct SessionToken {
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub session_id: String, // JSON:API requires IDs to be strings
}

impl SessionToken {
    /// Check if token has not yet expired (for testing purposes only)
    ///
    /// Returns true if the current time is before the expiration time.
    ///
    /// Note: In production, the agent does NOT check token expiry locally.
    /// Instead, it uses the token until it receives a 401 response from the verifier.
    /// The verifier extends token validity on successful attestations.
    ///
    /// This aligns with the spec: "The agent will use this token to authenticate
    /// subsequent requests to the verifier. If the token is still valid, the action
    /// will proceed. Otherwise, it will reply with a 401 status and the agent will
    /// repeat the challenge-response protocol to obtain a new session token."
    ///
    /// The validity check happens on the verifier side, not the agent side.
    #[cfg(test)]
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now < self.expires_at
    }
}

/// TPM operations abstraction for authentication proof-of-possession
///
/// This trait provides an async interface for generating TPM-based cryptographic
/// proofs during the authentication protocol. Implementations handle the details
/// of interacting with TPM hardware or providing mock proofs for testing.
///
/// ## Async Design
///
/// The trait is async (`#[async_trait]`) even though underlying TPM operations
/// are synchronous. This design allows:
///
/// 1. **Non-blocking execution**: TPM operations can run on blocking thread pools
///    via `tokio::task::spawn_blocking` without blocking the async runtime
/// 2. **Consistent API**: All authentication operations use async/await patterns
/// 3. **Future extensibility**: Support for truly async TPM drivers if available
///
/// ## Runtime Requirements
///
/// Implementations that use real TPM hardware (like `RealTpmOperations`) require:
/// - An active tokio runtime (checked via `tokio::runtime::Handle::try_current()`)
/// - Available threads in the runtime's blocking thread pool
///
/// Mock implementations (like `MockTpmOperations`) don't have these requirements
/// since they don't perform actual TPM operations.
///
/// ## Thread Safety
///
/// The `Send + Sync` bounds ensure implementations can be safely shared across
/// threads, which is necessary for use in the async `AuthenticationClient`.
#[async_trait::async_trait]
pub trait TpmOperations: Send + Sync {
    /// Generate a cryptographic proof of possession for the given challenge
    ///
    /// This method uses TPM2_Certify to prove possession of the Attestation Key (AK)
    /// by certifying it with itself and including the challenge as qualifying data.
    ///
    /// # Arguments
    ///
    /// * `challenge` - Challenge string from the verifier (typically base64-encoded)
    ///
    /// # Returns
    ///
    /// A `ProofOfPossession` containing the signed attestation message and signature
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TPM operations fail (hardware/driver issues)
    /// - Challenge encoding is invalid
    /// - Cryptographic operations fail
    /// - Runtime requirements are not met (for real TPM operations)
    async fn generate_proof(
        &self,
        challenge: &str,
    ) -> Result<crate::structures::ProofOfPossession>;
}

/// Default mock TPM implementation
#[derive(Debug, Clone)]
pub struct MockTpmOperations;

#[async_trait::async_trait]
impl TpmOperations for MockTpmOperations {
    async fn generate_proof(
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

/// Real TPM implementation using hardware TPM operations
#[derive(Debug)]
pub struct RealTpmOperations {
    context_info: ContextInfo,
}

impl RealTpmOperations {
    pub fn new(context_info: ContextInfo) -> Self {
        Self { context_info }
    }
}

#[async_trait::async_trait]
impl TpmOperations for RealTpmOperations {
    async fn generate_proof(
        &self,
        challenge: &str,
    ) -> Result<crate::structures::ProofOfPossession> {
        use crate::structures::EvidenceData;

        debug!("Generating real TPM proof for challenge: {challenge}");

        // Use TPM2_Certify to generate authentication proof-of-possession
        // This certifies the AK with itself, proving we have the private key
        let mut context_info = self.context_info.clone();

        let evidence_data =
            context_info.generate_tpm_auth_proof(challenge).await?;

        // Extract the message and signature from the evidence data
        if let EvidenceData::TpmQuote {
            message, signature, ..
        } = evidence_data
        {
            debug!("Successfully generated TPM proof");
            Ok(crate::structures::ProofOfPossession { message, signature })
        } else {
            Err(anyhow::anyhow!(
                "Expected TpmQuote evidence data, got different type"
            ))
        }
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
    /// Automatically chooses between real TPM and mock based on config.avoid_tpm
    pub fn new(config: AuthConfig) -> Result<Self> {
        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let http_client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .danger_accept_invalid_hostnames(config.accept_invalid_hostnames)
            .build()?;

        let tpm_ops: Box<dyn TpmOperations> = if config.avoid_tpm {
            debug!("Using mock TPM operations for authentication");
            Box::new(MockTpmOperations)
        } else {
            debug!("Using real TPM operations for authentication");
            // Initialize context info for real TPM operations using global config
            let global_config = get_config();
            let context_info =
                ContextInfo::new_from_str(AlgorithmConfigurationString {
                    tpm_encryption_alg: global_config
                        .tpm_encryption_alg()
                        .to_string(),
                    tpm_hash_alg: global_config.tpm_hash_alg().to_string(),
                    tpm_signing_alg: global_config
                        .tpm_signing_alg()
                        .to_string(),
                    agent_data_path: global_config
                        .agent_data_path()
                        .to_string(),
                })?;
            Box::new(RealTpmOperations::new(context_info))
        };

        Ok(Self {
            config,
            http_client,
            session_token: Arc::new(Mutex::new(None)),
            tpm_ops,
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
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .danger_accept_invalid_hostnames(config.accept_invalid_hostnames)
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
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .danger_accept_invalid_hostnames(config.accept_invalid_hostnames)
            .build()?;

        let tpm_ops: Box<dyn TpmOperations> = if config.avoid_tpm {
            debug!("Using mock TPM operations for raw authentication client");
            Box::new(MockTpmOperations)
        } else {
            debug!("Using real TPM operations for raw authentication client");
            // Initialize context info for real TPM operations using global config
            let global_config = get_config();
            let context_info =
                ContextInfo::new_from_str(AlgorithmConfigurationString {
                    tpm_encryption_alg: global_config
                        .tpm_encryption_alg()
                        .to_string(),
                    tpm_hash_alg: global_config.tpm_hash_alg().to_string(),
                    tpm_signing_alg: global_config
                        .tpm_signing_alg()
                        .to_string(),
                    agent_data_path: global_config
                        .agent_data_path()
                        .to_string(),
                })?;
            Box::new(RealTpmOperations::new(context_info))
        };

        Ok(Self {
            config,
            http_client,
            session_token: Arc::new(Mutex::new(None)),
            tpm_ops,
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
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .danger_accept_invalid_hostnames(config.accept_invalid_hostnames)
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

    /// Clear the cached session token
    /// This should be called when a 401 response is received
    pub async fn clear_session_token(&self) {
        let mut token_guard = self.session_token.lock().await;
        *token_guard = None;
        debug!("Session token cleared from authentication client");
    }

    /// Get a valid authentication token with metadata (token, created_at, expires_at, session_id)
    /// This method is used by the authentication middleware to access token details
    pub async fn get_auth_token_with_metadata(
        &self,
    ) -> Result<(String, DateTime<Utc>, DateTime<Utc>, String)> {
        let token_guard = self.session_token.lock().await;

        // Check if we have an existing token
        if let Some(ref token) = *token_guard {
            info!(
                "Reusing existing authentication token (session_id: {}, expires: {})",
                token.session_id, token.expires_at
            );
            return Ok((
                token.token.clone(),
                token.created_at,
                token.expires_at,
                token.session_id.clone(),
            ));
        }

        info!("No authentication token available, performing initial authentication");
        drop(token_guard); // Release lock before authentication

        // Perform authentication and return metadata
        let _token_string = self.authenticate().await?;

        // Get the token details from the newly stored token
        let token_guard = self.session_token.lock().await;
        if let Some(ref token) = *token_guard {
            Ok((
                token.token.clone(),
                token.created_at,
                token.expires_at,
                token.session_id.clone(),
            ))
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

        // Perform authentication with retries
        // Note: The v3.0 protocol issues challenges even for non-enrolled agents,
        // so we don't need to check enrollment first. Authentication will fail
        // gracefully at proof verification if the agent doesn't exist.
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

                    // Check for TLS-related errors and provide helpful hints
                    crate::error::log_tls_error_hints(&e);

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
        let proof = self.generate_tpm_proof(&challenge_response).await?;

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

        let api_version =
            get_push_api_version(self.config.api_version.as_ref());
        let url = format!(
            "{}/{}/sessions",
            self.config.verifier_base_url, api_version
        );
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
            let error_body = response.text().await.unwrap_or_else(|e| {
                format!("(failed to read response body: {})", e)
            });
            let error_msg = if error_body.is_empty() {
                "(empty response body)".to_string()
            } else {
                error_body
            };
            return Err(anyhow!(
                "Challenge request failed with status {}: {}",
                status,
                error_msg
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
    async fn generate_tpm_proof(
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

        self.tpm_ops.generate_proof(challenge).await
    }

    /// Step 3: Submit proof and get authentication result
    async fn submit_proof(
        &self,
        session_id: String,
        proof: ProofOfPossession,
    ) -> Result<SessionIdResponse> {
        // Construct the session update request using the proper struct
        let session_update = SessionIdRequest::new(
            session_id.clone(),
            SessionUpdateAttributes {
                agent_id: self.config.agent_id.clone(),
                auth_provided: vec![SessionIdRequestAuthProvided {
                    auth_class: "pop".to_string(),
                    auth_type: "tpm_pop".to_string(),
                    data: proof,
                }],
            },
        );

        let api_version =
            get_push_api_version(self.config.api_version.as_ref());
        let url = format!(
            "{}/{}/sessions/{}",
            self.config.verifier_base_url, api_version, session_id
        );
        debug!("Submitting proof to: {url}");

        let response = self
            .http_client
            .patch(&url)
            .header("Content-Type", "application/vnd.api+json")
            .json(&session_update)
            .send()
            .await?;

        let status = response.status();
        debug!("Proof submission response status: {status}");

        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_else(|e| {
                format!("(failed to read response body: {})", e)
            });
            let error_msg = if error_body.is_empty() {
                "(empty response body)".to_string()
            } else {
                error_body
            };
            return Err(anyhow!(
                "Proof submission failed with status {}: {}",
                status,
                error_msg
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

        if attributes.evaluation != "pass" {
            return Err(anyhow!(
                "Authentication failed with evaluation: {}",
                attributes.evaluation
            ));
        }

        let token = attributes.token.as_ref().ok_or_else(|| {
            anyhow!("Authentication succeeded but no token provided")
        })?;

        let created_at = attributes.created_at;
        let expires_at = attributes.token_expires_at.unwrap_or_else(|| {
            // Defensive fallback if verifier doesn't provide token expiration
            created_at
                + Duration::minutes(
                    DEFAULT_AUTH_TOKEN_EXPIRATION_FALLBACK_MINUTES,
                )
        });

        let session_token = SessionToken {
            token: token.clone(),
            created_at,
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
            api_version: None, // Use DEFAULT_PUSH_API_VERSION
            avoid_tpm: true,
            timeout_ms: 1000,
            max_auth_retries: 2,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        AuthenticationClient::new(config).unwrap() //#[allow_ci]
    }

    #[test]
    fn test_default_auth_config_is_secure() {
        let config = AuthConfig::default();
        assert!(
            !config.accept_invalid_certs,
            "Default config must enforce certificate validation"
        );
    }

    #[tokio::test]
    async fn test_successful_authentication_flow() {
        let mock_server = MockServer::start().await;

        // Mock challenge request (POST /sessions)
        Mock::given(method("POST"))
            .and(path(format!("/{}/sessions", DEFAULT_PUSH_API_VERSION)))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
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
            .and(path(format!("/{}/sessions/1", DEFAULT_PUSH_API_VERSION)))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "evaluation": "pass",
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
        let (token, _created_at, _expires_at, session_id) =
            client.get_auth_token_with_metadata().await.unwrap(); //#[allow_ci]
        assert_eq!(token, "test-token-456");
        assert_eq!(session_id, "1");

        // Verify token is valid
        let token_guard = client.session_token.lock().await;
        let session_token = token_guard.as_ref().unwrap(); //#[allow_ci]
        assert!(session_token.is_valid());
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let mock_server = MockServer::start().await;

        // Mock challenge request
        Mock::given(method("POST"))
            .and(path(format!("/{}/sessions", DEFAULT_PUSH_API_VERSION)))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
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
            .and(path(format!("/{}/sessions/1", DEFAULT_PUSH_API_VERSION)))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
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
            .and(path(format!("/{}/sessions", DEFAULT_PUSH_API_VERSION)))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
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
            .and(path(format!("/{}/sessions/1", DEFAULT_PUSH_API_VERSION)))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "1",
                        "attributes": {
                            "agent_id": "test-agent-123",
                            "evaluation": "pass",
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
                            // Token with 1 minute lifetime (in the past, so expired)
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
            api_version: None, // Use DEFAULT_PUSH_API_VERSION
            avoid_tpm: true,
            timeout_ms: 1000,
            max_auth_retries: 2,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        let client = AuthenticationClient::new(config).unwrap(); //#[allow_ci]

        // Token is in the past so it's already expired
        let (token, _, _, _) =
            client.get_auth_token_with_metadata().await.unwrap(); //#[allow_ci]
        assert_eq!(token, "short-lived-token");

        // Check that token is considered invalid (already expired)
        let token_guard = client.session_token.lock().await;
        let session_token = token_guard.as_ref().unwrap(); //#[allow_ci]
        assert!(!session_token.is_valid());
    }

    #[tokio::test]
    async fn test_raw_client_creation() {
        let config = AuthConfig {
            verifier_base_url: "https://127.0.0.1:8881".to_string(),
            agent_id: "test-agent-raw".to_string(),
            api_version: None, // Use DEFAULT_PUSH_API_VERSION
            avoid_tpm: true,
            timeout_ms: 1000,
            max_auth_retries: 2,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
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
            api_version: None, // Use DEFAULT_PUSH_API_VERSION
            avoid_tpm: false,
            timeout_ms: 2000,
            max_auth_retries: 1,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
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

    // Tests for TPM Operations trait implementations
    #[tokio::test]
    async fn test_mock_tpm_operations_proof_generation() {
        let mock_ops = MockTpmOperations;
        let challenge = "test-challenge-12345";

        let proof = mock_ops.generate_proof(challenge).await.unwrap(); //#[allow_ci]

        // Verify the proof structure
        assert!(!proof.message.is_empty());
        assert!(!proof.signature.is_empty());

        // Verify base64 encoding
        use base64::{engine::general_purpose, Engine as _};
        let decoded_message =
            general_purpose::STANDARD.decode(&proof.message).unwrap(); //#[allow_ci]
        let _decoded_signature =
            general_purpose::STANDARD.decode(&proof.signature).unwrap(); //#[allow_ci]

        // Verify the message contains the challenge
        let message_str = String::from_utf8(decoded_message).unwrap(); //#[allow_ci]
        assert!(message_str.contains(challenge));

        // Verify signature is deterministic for same challenge
        let proof2 = mock_ops.generate_proof(challenge).await.unwrap(); //#[allow_ci]
        assert_eq!(proof.message, proof2.message);
        assert_eq!(proof.signature, proof2.signature);
    }

    #[tokio::test]
    async fn test_mock_tpm_operations_different_challenges() {
        let mock_ops = MockTpmOperations;

        let proof1 = mock_ops.generate_proof("challenge-1").await.unwrap(); //#[allow_ci]
        let proof2 = mock_ops.generate_proof("challenge-2").await.unwrap(); //#[allow_ci]

        // Different challenges should produce different proofs
        assert_ne!(proof1.message, proof2.message);
        assert_ne!(proof1.signature, proof2.signature);
    }

    // Test helper: Custom TPM operations implementation for testing
    struct TestTpmOperations {
        should_fail: bool,
        custom_prefix: String,
    }

    #[async_trait::async_trait]
    impl TpmOperations for TestTpmOperations {
        async fn generate_proof(
            &self,
            challenge: &str,
        ) -> Result<ProofOfPossession> {
            if self.should_fail {
                return Err(anyhow::anyhow!("Test TPM failure"));
            }

            use base64::{engine::general_purpose, Engine as _};
            Ok(ProofOfPossession {
                message: general_purpose::STANDARD.encode(format!(
                    "{}-msg-{}",
                    self.custom_prefix, challenge
                )),
                signature: general_purpose::STANDARD.encode(format!(
                    "{}-sig-{}",
                    self.custom_prefix, challenge
                )),
            })
        }
    }

    #[tokio::test]
    async fn test_custom_tpm_operations_success() {
        let test_ops = TestTpmOperations {
            should_fail: false,
            custom_prefix: "test".to_string(),
        };
        let challenge = "custom-challenge";

        let proof = test_ops.generate_proof(challenge).await.unwrap(); //#[allow_ci]

        use base64::{engine::general_purpose, Engine as _};
        let decoded_msg = String::from_utf8(
            general_purpose::STANDARD.decode(&proof.message).unwrap(), //#[allow_ci]
        )
        .unwrap(); //#[allow_ci]

        assert_eq!(decoded_msg, "test-msg-custom-challenge");
    }

    #[tokio::test]
    async fn test_custom_tpm_operations_failure() {
        let test_ops = TestTpmOperations {
            should_fail: true,
            custom_prefix: "fail".to_string(),
        };
        let result = test_ops.generate_proof("any-challenge").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Test TPM failure"));
        //#[allow_ci]
    }

    // Tests for AuthenticationClient TPM selection logic
    #[tokio::test]
    async fn test_authentication_client_mock_tpm_selection() {
        let config = AuthConfig {
            verifier_base_url: "https://test.example.com".to_string(),
            agent_id: "test-agent".to_string(),
            api_version: None,
            avoid_tpm: true, // Should use MockTpmOperations
            timeout_ms: 1000,
            max_auth_retries: 1,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        // This should succeed even without real TPM hardware
        let client = AuthenticationClient::new(config).unwrap(); //#[allow_ci]
        assert!(client.config.avoid_tpm);
    }

    #[tokio::test]
    async fn test_authentication_client_with_custom_tpm_ops() {
        let config = AuthConfig {
            verifier_base_url: "https://test.example.com".to_string(),
            agent_id: "test-agent".to_string(),
            api_version: None,
            avoid_tpm: false,
            timeout_ms: 1000,
            max_auth_retries: 1,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        let custom_ops = Box::new(TestTpmOperations {
            should_fail: false,
            custom_prefix: "custom".to_string(),
        });
        let client =
            AuthenticationClient::with_tpm_ops(config, custom_ops).unwrap(); //#[allow_ci]
        assert!(!client.config.avoid_tpm);
    }

    // Integration test for authentication flow with different TPM configurations
    #[tokio::test]
    async fn test_authentication_flow_with_custom_tpm_ops() {
        let mock_server = MockServer::start().await;

        // Mock challenge request
        Mock::given(method("POST"))
            .and(path(format!("/{}/sessions", DEFAULT_PUSH_API_VERSION)))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "42",
                        "attributes": {
                            "agent_id": "test-custom-tpm",
                            "authentication_requested": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "custom-test-challenge"
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

        // Mock successful proof submission
        Mock::given(method("PATCH"))
            .and(path(format!("/{}/sessions/42", DEFAULT_PUSH_API_VERSION)))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "42",
                        "attributes": {
                            "agent_id": "test-custom-tpm",
                            "evaluation": "pass",
                            "token": "custom-tpm-token-789",
                            "authentication": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "custom-test-challenge"
                                },
                                "data": {
                                    "message": "integration-msg-custom-test-challenge",
                                    "signature": "integration-sig-custom-test-challenge"
                                }
                            }],
                            "created_at": "2025-01-01T12:00:00Z",
                            "challenges_expire_at": "2025-01-01T13:00:00Z",
                            "response_received_at": "2025-01-01T12:00:01Z",
                            "token_expires_at": "2030-01-01T18:00:00Z"
                        }
                    }
                })
            ))
            .mount(&mock_server)
            .await;

        let config = AuthConfig {
            verifier_base_url: mock_server.uri(),
            agent_id: "test-custom-tpm".to_string(),
            api_version: None,
            avoid_tpm: false,
            timeout_ms: 1000,
            max_auth_retries: 1,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        // Use custom TPM operations that will succeed
        let custom_ops = Box::new(TestTpmOperations {
            should_fail: false,
            custom_prefix: "integration".to_string(),
        });
        let client =
            AuthenticationClient::new_raw_with_tpm_ops(config, custom_ops)
                .unwrap(); //#[allow_ci]

        let (token, _created_at, _expires_at, session_id) =
            client.get_auth_token_with_metadata().await.unwrap(); //#[allow_ci]

        assert_eq!(token, "custom-tpm-token-789");
        assert_eq!(session_id, "42");
    }

    #[tokio::test]
    async fn test_authentication_flow_with_failing_tpm_ops() {
        let mock_server = MockServer::start().await;

        // Mock challenge request
        Mock::given(method("POST"))
            .and(path(format!("/{}/sessions", DEFAULT_PUSH_API_VERSION)))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({
                    "data": {
                        "type": "session",
                        "id": "99",
                        "attributes": {
                            "agent_id": "test-failing-tpm",
                            "authentication_requested": [{
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": "fail-challenge"
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

        let config = AuthConfig {
            verifier_base_url: mock_server.uri(),
            agent_id: "test-failing-tpm".to_string(),
            api_version: None,
            avoid_tpm: false,
            timeout_ms: 1000,
            max_auth_retries: 1,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        // Use custom TPM operations that will fail
        let failing_ops = Box::new(TestTpmOperations {
            should_fail: true,
            custom_prefix: "fail".to_string(),
        });
        let client =
            AuthenticationClient::new_raw_with_tpm_ops(config, failing_ops)
                .unwrap(); //#[allow_ci]

        let result = client.get_auth_token_with_metadata().await;
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string(); //#[allow_ci]
                                                         // The error message should indicate authentication failure, which could include the TPM failure
        assert!(
            error_msg.contains("Authentication failed")
                || error_msg.contains("Test TPM failure")
        );
    }

    // Test for TPM operations trait object behavior
    #[tokio::test]
    async fn test_tpm_operations_trait_object() {
        let ops: Vec<Box<dyn TpmOperations>> = vec![
            Box::new(MockTpmOperations),
            Box::new(TestTpmOperations {
                should_fail: false,
                custom_prefix: "trait".to_string(),
            }),
        ];

        for (i, op) in ops.iter().enumerate() {
            let challenge = format!("trait-test-{}", i);
            let proof = op.generate_proof(&challenge).await.unwrap(); //#[allow_ci]

            assert!(!proof.message.is_empty());
            assert!(!proof.signature.is_empty());

            // Verify base64 encoding
            use base64::{engine::general_purpose, Engine as _};
            assert!(general_purpose::STANDARD.decode(&proof.message).is_ok());
            assert!(general_purpose::STANDARD
                .decode(&proof.signature)
                .is_ok());
        }
    }

    // Test TPM configuration validation
    #[tokio::test]
    async fn test_tpm_config_validation() {
        // Test mock TPM configuration scenario
        let config = AuthConfig {
            verifier_base_url: "https://test.example.com".to_string(),
            agent_id: "config-test".to_string(),
            api_version: None,
            avoid_tpm: true, // Only test mock TPM to avoid config issues
            timeout_ms: 1000,
            max_auth_retries: 1,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        // Mock TPM should always work
        let client = AuthenticationClient::new(config).unwrap(); //#[allow_ci]
        assert!(client.config.avoid_tpm);

        // Test with custom TPM ops (this tests the real TPM code path without requiring actual config)
        let real_tpm_config = AuthConfig {
            verifier_base_url: "https://test.example.com".to_string(),
            agent_id: "real-tpm-test".to_string(),
            api_version: None,
            avoid_tpm: false,
            timeout_ms: 1000,
            max_auth_retries: 1,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        let custom_ops = Box::new(TestTpmOperations {
            should_fail: false,
            custom_prefix: "validation".to_string(),
        });
        let real_client =
            AuthenticationClient::with_tpm_ops(real_tpm_config, custom_ops)
                .unwrap(); //#[allow_ci]
        assert!(!real_client.config.avoid_tpm);
    }
}
