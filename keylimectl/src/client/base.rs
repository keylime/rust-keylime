// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Base client functionality shared across all Keylime service clients
//!
//! This module provides shared HTTP client creation and TLS configuration logic
//! that is used by all service-specific clients (verifier, registrar, agent).
//! This eliminates code duplication and ensures consistent behavior across clients.

use crate::client::error::{ApiResponseError, ClientError, TlsError};
use crate::config::Config;
use keylime::resilient_client::ResilientClient;
use log::{debug, warn};
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

/// Base HTTP client functionality shared across all service clients
///
/// This structure encapsulates the common HTTP client setup and TLS configuration
/// logic that is used by all Keylime service clients. It provides a consistent
/// foundation for secure communication with Keylime services.
///
/// # Features
///
/// - **TLS Configuration**: Mutual TLS with client certificates
/// - **Retry Logic**: Exponential backoff with configurable retries
/// - **Connection Pooling**: Persistent HTTP connections for performance
/// - **Security**: Proper certificate validation and verification
///
/// # Examples
///
/// ```rust
/// use keylimectl::client::base::BaseClient;
/// use keylimectl::config::Config;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
/// let base_url = "https://localhost:8881".to_string();
/// let base_client = BaseClient::new(base_url, &config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct BaseClient {
    /// The underlying resilient HTTP client
    pub client: ResilientClient,
    /// Base URL for the service
    pub base_url: String,
}

impl BaseClient {
    /// Create a new base client with the specified configuration
    ///
    /// Initializes a new HTTP client with TLS configuration, retry logic,
    /// and connection pooling based on the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL for the service (e.g., "https://localhost:8881")
    /// * `config` - Configuration containing TLS and client settings
    ///
    /// # Returns
    ///
    /// Returns a configured `BaseClient` ready for HTTP communication.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - TLS certificate files cannot be read
    /// - Certificate/key files are invalid
    /// - HTTP client initialization fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::client::base::BaseClient;
    /// use keylimectl::config::Config;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::default();
    /// let base_url = config.verifier_base_url();
    /// let client = BaseClient::new(base_url, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        base_url: String,
        config: &Config,
        agent_cert_pem: Option<&str>,
    ) -> Result<Self, ClientError> {
        debug!("Creating BaseClient for {base_url} with TLS config: verify_server_cert={}, client_cert={:?}, client_key={:?}",
               config.tls.verify_server_cert, config.tls.client_cert, config.tls.client_key);

        // Create HTTP client with TLS configuration
        let mut builder = Self::create_http_client_builder(config)?;

        // Add agent's self-signed cert as trusted CA for pull-model
        // connections.  The cert comes from the registrar database.
        if let Some(pem) = agent_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| {
                    ClientError::Tls(TlsError::configuration(format!(
                        "Failed to parse agent mTLS certificate: {e}"
                    )))
                })?;
            builder = builder.add_root_certificate(cert);
            debug!("Added agent mTLS certificate as trusted root");
        }

        let http_client = builder.build().map_err(|e| {
            ClientError::configuration(format!(
                "Failed to create HTTP client: {e}"
            ))
        })?;

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

        Ok(Self { client, base_url })
    }

    /// Build a `reqwest::ClientBuilder` with TLS settings from config.
    ///
    /// Returns the builder *before* calling `.build()` so callers can
    /// inject extra root certificates (e.g. the agent's self-signed
    /// mTLS cert) before finalizing the client.
    fn create_http_client_builder(
        config: &Config,
    ) -> Result<reqwest::ClientBuilder, ClientError> {
        debug!("Creating HTTP client with TLS config: verify_server_cert={}, client_cert={:?}, client_key={:?}, trusted_ca={:?}",
               config.tls.verify_server_cert, config.tls.client_cert, config.tls.client_key, config.tls.trusted_ca);

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.client.timeout))
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .danger_accept_invalid_hostnames(
                config.tls.accept_invalid_hostnames,
            );

        if config.tls.accept_invalid_hostnames {
            warn!(
                "TLS hostname verification is disabled. \
                 Set tls.accept_invalid_hostnames = false for stricter security."
            );
        }

        // Configure TLS
        if !config.tls.verify_server_cert {
            builder = builder.danger_accept_invalid_certs(true);
            warn!("Server certificate verification is disabled");
        }

        // Add trusted CA certificates for server verification
        debug!(
            "Attempting to load {} trusted CA certificate(s)",
            config.tls.trusted_ca.len()
        );
        let mut loaded_cas = 0;
        for ca_path in &config.tls.trusted_ca {
            debug!("Checking CA certificate: {ca_path}");
            if std::path::Path::new(ca_path).exists() {
                debug!("CA certificate file exists, attempting to load: {ca_path}");
                let ca_cert = std::fs::read(ca_path).map_err(|e| {
                    ClientError::Tls(TlsError::ca_certificate_file(
                        ca_path,
                        format!("Failed to read file: {e}"),
                    ))
                })?;

                let ca_cert = reqwest::Certificate::from_pem(&ca_cert)
                    .map_err(|e| {
                        ClientError::Tls(TlsError::ca_certificate_file(
                            ca_path,
                            format!("Failed to parse PEM: {e}"),
                        ))
                    })?;

                builder = builder.add_root_certificate(ca_cert);
                loaded_cas += 1;
                debug!("Successfully loaded CA certificate: {ca_path}");
            } else {
                warn!("Trusted CA certificate file not found: {ca_path}");
            }
        }
        debug!(
            "Loaded {loaded_cas} CA certificate(s) for server verification"
        );

        // Add client certificate if configured
        if let (Some(cert_path), Some(key_path)) =
            (&config.tls.client_cert, &config.tls.client_key)
        {
            let cert = std::fs::read(cert_path).map_err(|e| {
                ClientError::Tls(TlsError::certificate_file(
                    cert_path,
                    format!("Failed to read file: {e}"),
                ))
            })?;

            let key = std::fs::read(key_path).map_err(|e| {
                ClientError::Tls(TlsError::private_key_file(
                    key_path,
                    format!("Failed to read file: {e}"),
                ))
            })?;

            let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key)
                .map_err(|e| ClientError::Tls(TlsError::configuration(
                    format!("Failed to create client identity from cert {cert_path} and key {key_path}: {e}")
                )))?;

            debug!("Successfully created TLS identity from cert {cert_path} and key {key_path}");

            builder = builder.identity(identity);
        }

        Ok(builder)
    }

    /// Create HTTP client with TLS configuration (convenience wrapper).
    ///
    /// Equivalent to `create_http_client_builder(config)?.build()`.
    #[cfg(test)]
    pub fn create_http_client(
        config: &Config,
    ) -> Result<reqwest::Client, ClientError> {
        Self::create_http_client_builder(config)?
            .build()
            .map_err(|e| {
                ClientError::configuration(format!(
                    "Failed to create HTTP client: {e}"
                ))
            })
    }

    /// Handle HTTP response and convert to JSON
    ///
    /// Processes HTTP responses from Keylime services, handling both
    /// success and error cases. Converts successful responses to JSON
    /// and transforms HTTP errors into appropriate `ClientError` types.
    ///
    /// # Arguments
    ///
    /// * `response` - HTTP response from a Keylime service
    ///
    /// # Returns
    ///
    /// Returns parsed JSON data for successful responses.
    ///
    /// # Response Handling
    ///
    /// - **2xx responses**: Parsed as JSON or default success object
    /// - **4xx/5xx responses**: Converted to `ClientError::Api` with details
    /// - **Empty responses**: Returns `{"status": "success"}`
    /// - **Invalid JSON**: Returns parsing error with response text
    ///
    /// # Error Details
    ///
    /// For error responses, attempts to extract meaningful error messages
    /// from the JSON response body, falling back to HTTP status descriptions.
    ///
    /// # Errors
    ///
    /// This method can fail if:
    /// - Response body cannot be read
    /// - Response contains invalid JSON
    /// - Service returns an error status code
    pub async fn handle_response(
        &self,
        response: reqwest::Response,
    ) -> Result<Value, ClientError> {
        let status = response.status();
        let response_text =
            response.text().await.map_err(ClientError::Network)?;

        match status {
            StatusCode::OK
            | StatusCode::CREATED
            | StatusCode::ACCEPTED
            | StatusCode::NO_CONTENT => {
                if response_text.is_empty() {
                    Ok(serde_json::json!({"status": "success"}))
                } else {
                    serde_json::from_str(&response_text)
                        .map_err(ClientError::Json)
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

                // Try to parse the response as JSON for additional context
                let response_json = serde_json::from_str(&response_text).ok();

                Err(ClientError::Api(ApiResponseError::ServerError {
                    status: status.as_u16(),
                    message: error_message,
                    response: response_json,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientConfig, RegistrarConfig, TlsConfig, VerifierConfig,
    };

    /// Create a test configuration for base client testing
    fn create_test_config() -> Config {
        Config {
            loaded_from: None,
            cli_overrides: crate::config::CliOverrides::default(),
            verifier: VerifierConfig {
                ip: "127.0.0.1".to_string(),
                port: 8881,
                id: Some("test-verifier".to_string()),
            },
            registrar: RegistrarConfig::default(),
            tls: TlsConfig {
                client_cert: None,
                client_key: None,
                client_key_password: None,
                trusted_ca: vec![],
                verify_server_cert: false, // Disable for testing
                enable_agent_mtls: true,
                accept_invalid_hostnames: true,
            },
            client: ClientConfig {
                timeout: 30,
                retry_interval: 1.0,
                exponential_backoff: true,
                max_retries: 3,
            },
        }
    }

    #[test]
    fn test_base_client_new() {
        let config = create_test_config();
        let base_url = "https://127.0.0.1:8881".to_string();
        let result = BaseClient::new(base_url.clone(), &config, None);

        assert!(result.is_ok());
        let client = result.unwrap(); //#[allow_ci]
        assert_eq!(client.base_url, base_url);
    }

    #[test]
    fn test_create_http_client_basic() {
        let config = create_test_config();
        let result = BaseClient::create_http_client(&config);

        assert!(result.is_ok());
        // Basic validation that client was created
        let _client = result.unwrap(); //#[allow_ci]
    }

    #[test]
    fn test_create_http_client_with_timeout() {
        let mut config = create_test_config();
        config.client.timeout = 60;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_http_client_with_cert_files_nonexistent() {
        let mut config = create_test_config();
        config.tls.client_cert = Some("/nonexistent/cert.pem".to_string());
        config.tls.client_key = Some("/nonexistent/key.pem".to_string());

        let result = BaseClient::create_http_client(&config);
        // Should fail because cert files don't exist
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.to_string().contains("Certificate file error"));
    }

    #[test]
    fn test_tls_config_no_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = false;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification disabled
    }

    #[test]
    fn test_tls_config_with_verification() {
        let mut config = create_test_config();
        config.tls.verify_server_cert = true;

        let result = BaseClient::create_http_client(&config);
        assert!(result.is_ok());
        // Client should be created successfully with verification enabled
    }
}
