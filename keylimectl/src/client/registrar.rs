// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Registrar client for communicating with the Keylime registrar

use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use keylime::resilient_client::ResilientClient;
use log::{debug, warn};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// Client for communicating with the Keylime registrar
#[derive(Debug)]
pub struct RegistrarClient {
    client: ResilientClient,
    base_url: String,
    api_version: String,
}

impl RegistrarClient {
    /// Create a new registrar client
    pub fn new(config: &Config) -> Result<Self, KeylimectlError> {
        let base_url = config.registrar_base_url();

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

    /// Get agent information from the registrar
    pub async fn get_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting agent {agent_uuid} from registrar");

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
                "Failed to send get agent request to registrar".to_string()
            })?;

        match response.status() {
            StatusCode::OK => {
                let json_response = self.handle_response(response).await?;

                // Extract agent data from registrar response format
                if let Some(results) = json_response.get("results") {
                    if let Some(agent_data) = results.get(agent_uuid) {
                        Ok(Some(agent_data.clone()))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(Some(json_response))
                }
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

    /// Delete an agent from the registrar
    pub async fn delete_agent(
        &self,
        agent_uuid: &str,
    ) -> Result<Value, KeylimectlError> {
        debug!("Deleting agent {agent_uuid} from registrar");

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
                "Failed to send delete agent request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// List all agents on the registrar
    pub async fn list_agents(&self) -> Result<Value, KeylimectlError> {
        debug!("Listing agents on registrar");

        let url = format!("{}/v{}/agents/", self.base_url, self.api_version);

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| {
                "Failed to send list agents request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Add an agent to the registrar
    #[allow(dead_code)]
    pub async fn add_agent(
        &self,
        agent_uuid: &str,
        data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Adding agent {agent_uuid} to registrar");

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
                "Failed to send add agent request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Update an agent on the registrar
    #[allow(dead_code)]
    pub async fn update_agent(
        &self,
        agent_uuid: &str,
        data: Value,
    ) -> Result<Value, KeylimectlError> {
        debug!("Updating agent {agent_uuid} on registrar");

        let url = format!(
            "{}/v{}/agents/{}",
            self.base_url, self.api_version, agent_uuid
        );

        let response = self
            .client
            .get_json_request_from_struct(Method::PUT, &url, &data, None)
            .map_err(|e| KeylimectlError::Json(e))?
            .send()
            .await
            .with_context(|| {
                "Failed to send update agent request to registrar".to_string()
            })?;

        self.handle_response(response).await
    }

    /// Get agent by EK hash
    #[allow(dead_code)]
    pub async fn get_agent_by_ek_hash(
        &self,
        ek_hash: &str,
    ) -> Result<Option<Value>, KeylimectlError> {
        debug!("Getting agent by EK hash {ek_hash} from registrar");

        let url = format!(
            "{}/v{}/agents/?ekhash={}",
            self.base_url, self.api_version, ek_hash
        );

        let response = self
            .client
            .get_request(Method::GET, &url)
            .send()
            .await
            .with_context(|| "Failed to send get agent by EK hash request to registrar".to_string())?;

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
                format!("Failed to read client certificate: {cert_path}")
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
