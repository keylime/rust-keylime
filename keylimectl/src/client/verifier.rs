// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Verifier client for communicating with the Keylime verifier

// API version detection temporarily removed - will be implemented later
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use keylime::resilient_client::ResilientClient;
use log::{debug, warn};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// Client for communicating with the Keylime verifier
#[derive(Debug)]
pub struct VerifierClient {
    client: ResilientClient,
    base_url: String,
    api_version: String,
}

impl VerifierClient {
    /// Create a new verifier client
    pub fn new(config: &Config) -> Result<Self, KeylimectlError> {
        let base_url = config.verifier_base_url();

        // Create HTTP client with TLS configuration
        let http_client = Self::create_http_client(config)?;

        // Create resilient client with retry logic
        let client = ResilientClient::new(
            Some(http_client),
            Duration::from_secs(1), // Initial delay
            config.client.max_retries,
            &[
                StatusCode::OK,
                StatusCode::CREATED,
                StatusCode::ACCEPTED,
                StatusCode::NO_CONTENT,
            ],
            Some(Duration::from_secs(60)), // Max delay
        );

        Ok(Self {
            client,
            base_url,
            api_version: "2.1".to_string(), // Default API version
        })
    }

    /// Auto-detect and set the API version
    #[allow(dead_code)]
    pub async fn detect_api_version(
        &mut self,
    ) -> Result<(), KeylimectlError> {
        // API version detection temporarily disabled
        // Will be implemented in a future version
        Ok(())
    }

    /// Add an agent to the verifier
    pub async fn add_agent(
        &self,
        agent_uuid: &str,
        data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding agent {agent_uuid} to verifier");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::POST, &url, &data, None)
            .map_err(|e| KeylimectlError::Json(e))?
            .send()
            .await
            .with_context(|| {
                "Failed to send add agent request to verifier".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Get agent information from the verifier
    pub async fn get_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting agent {agent_uuid} from verifier");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send get agent request to verifier".to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response = self.handle_response(response).await?;
                Ok(Some(json_response))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let error_response = self.handle_response(response).await;
                match error_response {
                    Ok(_) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Delete an agent from the verifier
    pub async fn delete_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting agent {agent_uuid} from verifier");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send delete agent request to verifier".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Reactivate an agent on the verifier
    pub async fn reactivate_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Reactivating agent {agent_uuid} on verifier");

        let url = format!(
            "{}/v{}/agents/{}/reactivate",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::PUT, &url)
            .body("")
            .send()
            .await
            .with_context(|| {
                "Failed to send reactivate agent request to verifier".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Stop an agent on the verifier
    #[allow(dead_code)]
    pub async fn stop_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Stopping agent {agent_uuid} on verifier");

        let url = format!(
            "{}/v{}/agents/{}/stop",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_request(Method::PUT, &url)
            .body("")
            .send()
            .await
            .with_context(|| {
                "Failed to send stop agent request to verifier".to_string()
            })?;

        self.handle_response(response).await
    }

    /// List all agents on the verifier
    pub async fn list_agents(
        &self,
        verifier_id: Option<&str>,
    ) -> Result<Value, KeylimectlError> {
        debug!("Listing agents on verifier");

        let mut url =
            format!("{}/v{}/agents/", self.base_url, self.api_version);

        if let Some(vid) = verifier_id {
            url.push_str(&format!("?verifier={vid}"));
        }

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list agents request to verifier".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Get bulk information for all agents
    pub async fn get_bulk_info(
        &self,
        verifier_id: Option<&str>,
    ) -> Result<Value, KeylimectlError> {
        debug!("Getting bulk agent info from verifier");

        let mut url = format!(
            "{}/v{}/agents/?bulk=true",
            self.base_url, self.api_version
        );

        if let Some(vid) = verifier_id {
            url.push_str(&format!("&verifier={vid}"));
        }

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send bulk info request to verifier".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Add a runtime policy
    pub async fn add_runtime_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding runtime policy {policy_name} to verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_json_request_from_struct(
                Method::POST,
                &url,
                &policy_data,
                None,
            )
            .map_err(|e| KeylimectlError::Json(e))?
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to send add runtime policy request to verifier"
                )
            })?;

        self.handle_response(response).await
    }

    /// Get a runtime policy
    pub async fn get_runtime_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting runtime policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to send get runtime policy request to verifier"
                )
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response = self.handle_response(response).await?;
                Ok(Some(json_response))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let error_response = self.handle_response(response).await;
                match error_response {
                    Ok(_) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Update a runtime policy
    pub async fn update_runtime_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating runtime policy {policy_name} on verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::PUT, &url, &policy_data, None)
            .map_err(|e| KeylimectlError::Json(e))?
            .send()
            .await
            .with_context(|| "Failed to send update runtime policy request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// Delete a runtime policy
    pub async fn delete_runtime_policy(
        &self,
        policy_name: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting runtime policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/allowlists/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| "Failed to send delete runtime policy request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// List runtime policies
    pub async fn list_runtime_policies(
        &self,
    ) -> Result<Value, KeylimectlError> {
        debug!("Listing runtime policies on verifier");

        let url =
            format!("{}/v{}/allowlists/", self.base_url, self.api_version);

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| "Failed to send list runtime policies request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// Add a measured boot policy
    pub async fn add_mb_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding measured boot policy {policy_name} to verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::POST, &url, &policy_data, None)
            .map_err(|e| KeylimectlError::Json(e))?
            .send()
            .await
            .with_context(|| "Failed to send add measured boot policy request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// Get a measured boot policy
    pub async fn get_mb_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting measured boot policy {policy_name} from verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| "Failed to send get measured boot policy request to verifier".to_string())?;

        match response.status() {
            StatusCode::OK => {
                let json_response = self.handle_response(response).await?;
                Ok(Some(json_response))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let error_response = self.handle_response(response).await;
                match error_response {
                    Ok(_) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Update a measured boot policy
    pub async fn update_mb_policy(
        &self,
        policy_name: &str,
        policy_data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating measured boot policy {policy_name} on verifier");

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::PUT, &url, &policy_data, None)
            .map_err(|e| KeylimectlError::Json(e))?
            .send()
            .await
            .with_context(|| "Failed to send update measured boot policy request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// Delete a measured boot policy
    pub async fn delete_mb_policy(
        &self,
        policy_name: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!(
            "Deleting measured boot policy {} from verifier",
            policy_name
        );

        let url = format!(
            "{}/v{}/mbpolicies/{}",
            self.base_url, self.api_version, policy_name
        );

        let response = self
            .client
            .get_request(Method::DELETE, &url)
            .send()
            .await
            .with_context(|| "Failed to send delete measured boot policy request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// List measured boot policies
    pub async fn list_mb_policies(&self) -> Result<Value, KeylimectlError> {
        debug!("Listing measured boot policies on verifier");

        let url =
            format!("{}/v{}/mbpolicies/", self.base_url, self.api_version);

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| "Failed to send list measured boot policies request to verifier".to_string())?;

        self.handle_response(response).await
    }

    /// Create HTTP client with TLS configuration
    fn create_http_client(
        config: &Config,
    ) -> Result<reqwest::Client, KeylimectlError> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.client.timeout));

        // Configure TLS
        if !config.tls.verify_server_cert {
            builder = builder.danger_accept_invalid_certs(true);
            warn!("Server certificate verification is disabled");
        }

        // Add client certificate if configured
        if let (Some(cert_path), Some(key_path)) =
            (&config.tls.client_cert, &config.tls.client_key)
        {
            let cert = std::fs::read(cert_path).with_context(|| {
                format!("Failed to read client certificate: {}", cert_path)
            })?;

            let key = std::fs::read(key_path).with_context(|| {
                format!("Failed to read client key: {}", key_path)
            })?;

            let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key)
                .with_context(|| "Failed to create client identity from certificate and key".to_string())?;

            builder = builder.identity(identity);
        }

        builder
            .build()
            .with_context(|| "Failed to create HTTP client".to_string())
    }

    /// Handle HTTP response and convert to JSON
    async fn handle_response(
        &self,
        response: reqwest::Response,
    ) -> Result<Value, KeylimectlError> {
        let status = response.status();
        let response_text = response
            .text()
            .await
            .with_context(|| "Failed to read response body".to_string())?;

        match status {
            StatusCode::OK
            | StatusCode::CREATED
            | StatusCode::ACCEPTED
            | StatusCode::NO_CONTENT => {
                if response_text.is_empty() {
                    Ok(json!({"status": "success"}))
                } else {
                    serde_json::from_str(&response_text).with_context(|| {
                        format!(
                            "Failed to parse JSON response: {}",
                            response_text
                        )
                    })
                }
            }
            _ => {
                let error_message = if response_text.is_empty() {
                    format!("HTTP {} error", status.as_u16())
                } else {
                    // Try to parse as JSON for better error message
                    match serde_json::from_str::<Value>(&response_text) {
                        Ok(json_error) => json_error
                            .get("status")
                            .or_else(|| json_error.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&response_text)
                            .to_string(),
                        Err(_) => response_text.clone(),
                    }
                };

                Err(KeylimectlError::api_error(
                    status.as_u16(),
                    error_message,
                    serde_json::from_str(&response_text).ok(),
                ))
            }
        }
    }
}
