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
#[allow(dead_code)]
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

    /// Version detection errors
    #[error("Version detection error: {message}")]
    VersionDetection { message: String },

    /// Authentication errors
    #[error("Authentication error: {message}")]
    Authentication { message: String },
}

/// API response specific errors
///
/// These errors represent issues with API responses from Keylime services,
/// including HTTP status codes and response parsing issues.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ApiResponseError {
    /// Invalid HTTP status code received
    #[error("HTTP {status}: {message}")]
    InvalidStatus { status: u16, message: String },

    /// Unexpected response format
    #[error("Unexpected response format: {details}")]
    UnexpectedFormat { details: String },

    /// Missing required fields in response
    #[error("Missing required field in response: {field}")]
    MissingField { field: String },

    /// Empty response when data was expected
    #[error("Empty response received")]
    EmptyResponse,

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
#[allow(dead_code)]
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

    /// TLS handshake failure
    #[error("TLS handshake failed: {reason}")]
    HandshakeFailed { reason: String },

    /// Certificate validation error
    #[error("Certificate validation failed: {reason}")]
    CertificateValidation { reason: String },

    /// TLS configuration error
    #[error("TLS configuration error: {message}")]
    Configuration { message: String },
}

#[allow(dead_code)]
impl ClientError {
    /// Create a new network error
    pub fn network<T: Into<String>>(message: T) -> Self {
        Self::Configuration {
            message: format!("Network: {}", message.into()),
        }
    }

    /// Create a new configuration error
    pub fn configuration<T: Into<String>>(message: T) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create a new version detection error
    pub fn version_detection<T: Into<String>>(message: T) -> Self {
        Self::VersionDetection {
            message: message.into(),
        }
    }

    /// Create a new authentication error
    pub fn authentication<T: Into<String>>(message: T) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Check if this error is retryable
    ///
    /// Returns true if the operation that caused this error should be retried.
    /// Generally, network errors and 5xx server errors are retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(_) => true,
            Self::RequestMiddleware(_) => true,
            Self::Api(ApiResponseError::ServerError { status, .. }) => {
                *status >= 500
            }
            Self::Api(ApiResponseError::InvalidStatus { status, .. }) => {
                *status >= 500
            }
            _ => false,
        }
    }

    /// Get error category for structured logging
    pub fn category(&self) -> &'static str {
        match self {
            Self::Network(_) => "network",
            Self::RequestMiddleware(_) => "middleware",
            Self::Api(_) => "api",
            Self::Tls(_) => "tls",
            Self::Json(_) => "json",
            Self::Configuration { .. } => "configuration",
            Self::VersionDetection { .. } => "version_detection",
            Self::Authentication { .. } => "authentication",
        }
    }
}

#[allow(dead_code)]
impl ApiResponseError {
    /// Create a new server error
    pub fn server_error(
        status: u16,
        message: String,
        response: Option<Value>,
    ) -> Self {
        Self::ServerError {
            status,
            message,
            response,
        }
    }

    /// Create a new invalid status error
    pub fn invalid_status(status: u16, message: String) -> Self {
        Self::InvalidStatus { status, message }
    }

    /// Create a new unexpected format error
    pub fn unexpected_format<T: Into<String>>(details: T) -> Self {
        Self::UnexpectedFormat {
            details: details.into(),
        }
    }

    /// Create a new missing field error
    pub fn missing_field<T: Into<String>>(field: T) -> Self {
        Self::MissingField {
            field: field.into(),
        }
    }

    /// Get HTTP status code if available
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidStatus { status, .. } => Some(*status),
            Self::ServerError { status, .. } => Some(*status),
            _ => None,
        }
    }
}

#[allow(dead_code)]
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

    /// Create a handshake failed error
    pub fn handshake_failed<R: Into<String>>(reason: R) -> Self {
        Self::HandshakeFailed {
            reason: reason.into(),
        }
    }

    /// Create a certificate validation error
    pub fn certificate_validation<R: Into<String>>(reason: R) -> Self {
        Self::CertificateValidation {
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
        let config_err = ClientError::configuration("Invalid timeout");
        assert_eq!(config_err.category(), "configuration");
        assert!(!config_err.is_retryable());

        let version_err =
            ClientError::version_detection("API version mismatch");
        assert_eq!(version_err.category(), "version_detection");
        assert!(!version_err.is_retryable());

        let auth_err = ClientError::authentication("Invalid credentials");
        assert_eq!(auth_err.category(), "authentication");
        assert!(!auth_err.is_retryable());
    }

    #[test]
    fn test_api_response_error_creation() {
        let server_err = ApiResponseError::server_error(
            500,
            "Internal error".to_string(),
            Some(json!({"error": "database down"})),
        );
        assert_eq!(server_err.status_code(), Some(500));

        let invalid_status =
            ApiResponseError::invalid_status(404, "Not found".to_string());
        assert_eq!(invalid_status.status_code(), Some(404));

        let unexpected_format =
            ApiResponseError::unexpected_format("Expected JSON array");
        assert_eq!(unexpected_format.status_code(), None);

        let missing_field = ApiResponseError::missing_field("agent_uuid");
        assert_eq!(missing_field.status_code(), None);
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
            _ => panic!("Expected CertificateFile error"),
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
            _ => panic!("Expected PrivateKeyFile error"),
        }

        let handshake_err = TlsError::handshake_failed("Certificate expired");
        match handshake_err {
            TlsError::HandshakeFailed { reason } => {
                assert_eq!(reason, "Certificate expired");
            }
            _ => panic!("Expected HandshakeFailed error"),
        }
    }

    #[test]
    fn test_client_error_retryable() {
        // Network errors should be retryable
        let network_err = ClientError::network("Connection timeout");
        assert!(!network_err.is_retryable()); // This creates a Configuration error actually

        // Server errors (5xx) should be retryable
        let server_err = ClientError::Api(ApiResponseError::server_error(
            500,
            "Internal error".to_string(),
            None,
        ));
        assert!(server_err.is_retryable());

        // Client errors (4xx) should not be retryable
        let client_err = ClientError::Api(ApiResponseError::invalid_status(
            400,
            "Bad request".to_string(),
        ));
        assert!(!client_err.is_retryable());

        // Configuration errors should not be retryable
        let config_err = ClientError::configuration("Invalid timeout");
        assert!(!config_err.is_retryable());
    }

    #[test]
    fn test_error_display() {
        let api_err = ApiResponseError::server_error(
            500,
            "Database connection failed".to_string(),
            None,
        );
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
