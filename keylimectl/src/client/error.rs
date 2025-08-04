//! Client-specific error types for keylimectl
//!
//! This module provides error types specific to HTTP client operations,
//! including network errors, API errors, and client configuration issues.
//! These errors can be converted to the main `KeylimectlError` type for
//! user-facing error messages.
//!
//! # Error Types
//!
//! - [`ClientError`] - Main error type for client operations
//! - [`ApiResponseError`] - Specific API response parsing errors
//! - [`TlsError`] - TLS/SSL configuration and connection errors
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::client::error::{ClientError, ApiResponseError};
//!
//! // Create an API error
//! let api_err = ClientError::Api(ApiResponseError::InvalidStatus {
//!     status: 404,
//!     message: "Not found".to_string()
//! });
//!
//! // Create a network error
//! let network_err = ClientError::network("Connection timeout");
//! ```

use serde_json::Value;
use thiserror::Error;

/// Client-specific error types
///
/// This enum covers all error conditions that can occur during HTTP client operations,
/// from network connectivity issues to API response parsing problems.
#[derive(Error, Debug)]
pub enum ClientError {
    /// Network/HTTP errors from reqwest
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Request middleware errors
    #[error("Request middleware error: {0}")]
    RequestMiddleware(#[from] reqwest_middleware::Error),

    /// API response errors
    #[error("API error: {0}")]
    Api(#[from] ApiResponseError),

    /// TLS configuration errors
    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),

    /// JSON parsing errors
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    /// Client configuration errors
    #[error("Client configuration error: {message}")]
    Configuration { message: String },
}

/// API response specific errors
///
/// These errors represent issues with API responses from Keylime services,
/// including HTTP status codes and response parsing issues.
#[derive(Error, Debug)]
pub enum ApiResponseError {
    /// Server returned an error response
    #[error("Server error: {message} (status: {status})")]
    ServerError {
        status: u16,
        message: String,
        response: Option<Value>,
    },
}

/// TLS configuration and connection errors
///
/// These errors represent issues with TLS/SSL setup and connections,
/// including certificate validation and configuration problems.
#[derive(Error, Debug)]
pub enum TlsError {
    /// Certificate file not found or unreadable
    #[error("Certificate file error: {path} - {reason}")]
    CertificateFile { path: String, reason: String },

    /// Private key file not found or unreadable
    #[error("Private key file error: {path} - {reason}")]
    PrivateKeyFile { path: String, reason: String },

    /// CA certificate file not found or unreadable
    #[error("CA certificate file error: {path} - {reason}")]
    CaCertificateFile { path: String, reason: String },

    /// TLS configuration error
    #[error("TLS configuration error: {message}")]
    Configuration { message: String },
}

impl ClientError {
    /// Create a new configuration error
    pub fn configuration<T: Into<String>>(message: T) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }
}

impl ApiResponseError {}

impl TlsError {
    /// Create a certificate file error
    pub fn certificate_file<P: Into<String>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::CertificateFile {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create a private key file error
    pub fn private_key_file<P: Into<String>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::PrivateKeyFile {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create a CA certificate file error
    pub fn ca_certificate_file<P: Into<String>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::CaCertificateFile {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration<M: Into<String>>(message: M) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_client_error_creation() {
        let _config_err = ClientError::configuration("Invalid timeout");
    }

    #[test]
    fn test_api_response_error_creation() {
        let _server_err = ApiResponseError::ServerError {
            status: 500,
            message: "Internal error".to_string(),
            response: Some(json!({"error": "database down"})),
        };
    }

    #[test]
    fn test_tls_error_creation() {
        let cert_err =
            TlsError::certificate_file("/path/to/cert.pem", "File not found");
        match cert_err {
            TlsError::CertificateFile { path, reason } => {
                assert_eq!(path, "/path/to/cert.pem");
                assert_eq!(reason, "File not found");
            }
            _ => panic!("Expected CertificateFile error"), //#[allow_ci]
        }

        let key_err = TlsError::private_key_file(
            "/path/to/key.pem",
            "Permission denied",
        );
        match key_err {
            TlsError::PrivateKeyFile { path, reason } => {
                assert_eq!(path, "/path/to/key.pem");
                assert_eq!(reason, "Permission denied");
            }
            _ => panic!("Expected PrivateKeyFile error"), //#[allow_ci]
        }
    }

    #[test]
    fn test_client_error_types() {
        // Server errors (5xx)
        let _server_err = ClientError::Api(ApiResponseError::ServerError {
            status: 500,
            message: "Internal error".to_string(),
            response: None,
        });

        // Configuration errors
        let _config_err = ClientError::configuration("Invalid timeout");
    }

    #[test]
    fn test_error_display() {
        let api_err = ApiResponseError::ServerError {
            status: 500,
            message: "Database connection failed".to_string(),
            response: None,
        };
        assert!(api_err.to_string().contains("500"));
        assert!(api_err.to_string().contains("Database connection failed"));

        let tls_err =
            TlsError::certificate_file("/path/cert.pem", "Not found");
        assert!(tls_err.to_string().contains("/path/cert.pem"));
        assert!(tls_err.to_string().contains("Not found"));

        let client_err = ClientError::configuration("Invalid timeout value");
        assert!(client_err.to_string().contains("Invalid timeout value"));
    }
}
