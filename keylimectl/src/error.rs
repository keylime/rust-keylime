// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Error handling for keylimectl
//!
//! This module provides comprehensive error types and utilities for the keylimectl CLI tool.
//! It includes:
//!
//! - [`KeylimectlError`] - Main error enum covering all error types
//! - [`ErrorContext`] - Trait for adding context to errors
//! - JSON serialization support for structured error output
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::error::{KeylimectlError, ErrorContext};
//!
//! // Create an API error
//! let api_err = KeylimectlError::api_error(404, "Agent not found".to_string(), None);
//!
//! // Add context to an error
//! let result: Result<(), std::io::Error> = Err(std::io::Error::new(
//!     std::io::ErrorKind::NotFound,
//!     "file not found"
//! ));
//! let with_context = result.with_context(|| "Failed to read config file".to_string());
//! ```

use serde_json::Value;
use thiserror::Error;

/// Main error type for keylimectl operations
///
/// This enum covers all possible error conditions that can occur during keylimectl operations,
/// from configuration issues to network failures and API errors.
#[derive(Error, Debug)]
pub enum KeylimectlError {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    /// Network/HTTP errors
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Request middleware errors
    #[error("Request middleware error: {0}")]
    RequestMiddleware(#[from] reqwest_middleware::Error),

    /// API errors from the verifier/registrar
    #[error("API error: {message} (status: {status})")]
    Api {
        /// HTTP status code
        status: u16,
        /// Error message from the server
        message: String,
        /// Full response body if available
        response: Option<Value>,
    },

    /// Agent not found errors
    #[error("Agent {uuid} not found on {service}")]
    #[cfg(test)]
    AgentNotFound {
        /// Agent UUID
        uuid: String,
        /// Service name (verifier/registrar)
        service: String,
    },

    /// Policy not found errors
    #[error("Policy '{name}' not found")]
    #[cfg(test)]
    PolicyNotFound {
        /// Policy name
        name: String,
    },

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// File I/O errors
    #[error("File error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// UUID parsing errors
    #[error("Invalid UUID: {0}")]
    Uuid(#[from] uuid::Error),

    /// Client-specific errors
    #[error("Client error: {0}")]
    Client(#[from] crate::client::error::ClientError),

    /// Command-specific errors
    #[error("Command error: {0}")]
    Command(#[from] crate::commands::error::CommandError),

    /// Generic errors with context
    #[error("Error: {0}")]
    Generic(#[from] anyhow::Error),
}

impl KeylimectlError {
    /// Create a new API error
    ///
    /// # Arguments
    ///
    /// * `status` - HTTP status code
    /// * `message` - Error message from the server
    /// * `response` - Optional full response body
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let error = KeylimectlError::api_error(
    ///     404,
    ///     "Agent not found".to_string(),
    ///     None
    /// );
    /// ```
    pub fn api_error(
        status: u16,
        message: String,
        response: Option<Value>,
    ) -> Self {
        Self::Api {
            status,
            message,
            response,
        }
    }

    /// Create a new validation error
    ///
    /// # Arguments
    ///
    /// * `message` - Validation error message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let error = KeylimectlError::validation("Invalid UUID format");
    /// ```
    pub fn validation<T: Into<String>>(message: T) -> Self {
        Self::Validation(message.into())
    }

    /// Create a new agent not found error
    ///
    /// # Arguments
    ///
    /// * `uuid` - Agent UUID
    /// * `service` - Service name (verifier/registrar)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let error = KeylimectlError::agent_not_found("12345", "verifier");
    /// ```
    #[cfg(test)]
    pub fn agent_not_found<T: Into<String>, U: Into<String>>(
        uuid: T,
        service: U,
    ) -> Self {
        Self::AgentNotFound {
            uuid: uuid.into(),
            service: service.into(),
        }
    }

    /// Create a new policy not found error
    ///
    /// # Arguments
    ///
    /// * `name` - Policy name
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let error = KeylimectlError::policy_not_found("my_policy");
    /// ```
    #[cfg(test)]
    pub fn policy_not_found<T: Into<String>>(name: T) -> Self {
        Self::PolicyNotFound { name: name.into() }
    }

    /// Get the error code for JSON output
    ///
    /// Returns a string constant that identifies the error type for programmatic use.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let error = KeylimectlError::validation("test");
    /// assert_eq!(error.error_code(), "VALIDATION_ERROR");
    /// ```
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Config(_) => "CONFIG_ERROR",
            Self::Network(_) => "NETWORK_ERROR",
            Self::Api { .. } => "API_ERROR",
            #[cfg(test)]
            Self::AgentNotFound { .. } => "AGENT_NOT_FOUND",
            #[cfg(test)]
            Self::PolicyNotFound { .. } => "POLICY_NOT_FOUND",
            Self::Validation(_) => "VALIDATION_ERROR",
            Self::Io(_) => "IO_ERROR",
            Self::Json(_) => "JSON_ERROR",
            Self::Uuid(_) => "UUID_ERROR",
            Self::Client(_) => "CLIENT_ERROR",
            Self::Command(_) => "COMMAND_ERROR",
            Self::Generic(_) => "GENERIC_ERROR",
            Self::RequestMiddleware(_) => "REQUEST_MIDDLEWARE_ERROR",
        }
    }

    /// Check if this error is retryable
    ///
    /// Returns true if the operation that caused this error should be retried.
    /// Generally, network errors and 5xx server errors are retryable.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let network_error = KeylimectlError::Network(reqwest::Error::from(
    ///     reqwest::Error::from(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
    /// ));
    /// assert!(network_error.is_retryable());
    ///
    /// let validation_error = KeylimectlError::validation("bad input");
    /// assert!(!validation_error.is_retryable());
    /// ```
    #[cfg(test)]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(_) => true,
            Self::Api { status, .. } => *status >= 500,
            Self::Client(_) => false, // Client errors are generally not retryable
            Self::Command(_) => false, // Command errors are generally not retryable
            _ => false,
        }
    }

    /// Convert to JSON value for output
    ///
    /// Creates a structured JSON representation of the error suitable for CLI output.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::error::KeylimectlError;
    ///
    /// let error = KeylimectlError::validation("test error");
    /// let json = error.to_json();
    ///
    /// assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
    /// assert_eq!(json["error"]["message"], "Validation error: test error");
    /// ```
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "error": {
                "code": self.error_code(),
                "message": self.to_string(),
                "details": self.error_details()
            }
        })
    }

    /// Get additional error details for JSON output
    fn error_details(&self) -> Value {
        match self {
            Self::Api {
                status, response, ..
            } => serde_json::json!({
                "http_status": status,
                "response": response
            }),
            #[cfg(test)]
            Self::AgentNotFound { uuid, service } => serde_json::json!({
                "agent_uuid": uuid,
                "service": service
            }),
            #[cfg(test)]
            Self::PolicyNotFound { name } => serde_json::json!({
                "policy_name": name
            }),
            _ => Value::Null,
        }
    }
}

/// Helper trait for adding context to results
///
/// This trait provides convenient methods for adding contextual information to errors,
/// making debugging easier by providing a chain of what went wrong. It leverages
/// `anyhow` for rich error context while preserving backtrace information.
///
/// # Examples
///
/// ```rust
/// use keylimectl::error::{KeylimectlError, ErrorContext};
///
/// fn read_file() -> Result<String, std::io::Error> {
///     std::fs::read_to_string("nonexistent.txt")
/// }
///
/// let result = read_file()
///     .with_context(|| "Failed to read configuration file".to_string());
/// ```
pub trait ErrorContext<T> {
    /// Add context to an error with full backtrace preservation
    ///
    /// Uses `anyhow` to provide rich context while maintaining error chains.
    /// This is the recommended way to add context for user-facing errors.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that returns the context message
    fn with_context<F>(self, f: F) -> Result<T, KeylimectlError>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
    E: Into<KeylimectlError>,
{
    fn with_context<F>(self, f: F) -> Result<T, KeylimectlError>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let base_error = e.into();
            // Use anyhow to maintain full error chain with backtrace
            KeylimectlError::Generic(
                anyhow::Error::new(base_error).context(f()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_api_error_creation() {
        let error = KeylimectlError::api_error(
            404,
            "Not found".to_string(),
            Some(json!({"error": "agent not found"})),
        );

        match error {
            KeylimectlError::Api {
                status,
                message,
                response,
            } => {
                assert_eq!(status, 404);
                assert_eq!(message, "Not found");
                assert!(response.is_some());
            }
            _ => panic!("Expected API error"), //#[allow_ci]
        }
    }

    #[test]
    fn test_validation_error() {
        let error = KeylimectlError::validation("Invalid input");
        assert_eq!(error.error_code(), "VALIDATION_ERROR");
        assert_eq!(error.to_string(), "Validation error: Invalid input");
    }

    #[test]
    fn test_agent_not_found_error() {
        let error = KeylimectlError::agent_not_found("12345", "verifier");

        match &error {
            KeylimectlError::AgentNotFound { uuid, service } => {
                assert_eq!(uuid, "12345");
                assert_eq!(service, "verifier");
            }
            _ => panic!("Expected AgentNotFound error"), //#[allow_ci]
        }

        assert_eq!(error.error_code(), "AGENT_NOT_FOUND");
    }

    #[test]
    fn test_policy_not_found_error() {
        let error = KeylimectlError::policy_not_found("my_policy");

        match &error {
            KeylimectlError::PolicyNotFound { name } => {
                assert_eq!(name, "my_policy");
            }
            _ => panic!("Expected PolicyNotFound error"), //#[allow_ci]
        }

        assert_eq!(error.error_code(), "POLICY_NOT_FOUND");
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            KeylimectlError::validation("test").error_code(),
            "VALIDATION_ERROR"
        );
        assert_eq!(
            KeylimectlError::agent_not_found("test", "verifier").error_code(),
            "AGENT_NOT_FOUND"
        );
        assert_eq!(
            KeylimectlError::policy_not_found("test").error_code(),
            "POLICY_NOT_FOUND"
        );
    }

    #[test]
    fn test_is_retryable() {
        // Test API errors

        // 5xx errors should be retryable
        let server_error = KeylimectlError::api_error(
            500,
            "Internal error".to_string(),
            None,
        );
        assert!(server_error.is_retryable());

        let bad_gateway =
            KeylimectlError::api_error(502, "Bad gateway".to_string(), None);
        assert!(bad_gateway.is_retryable());

        // 4xx errors should not be retryable
        let client_error =
            KeylimectlError::api_error(400, "Bad request".to_string(), None);
        assert!(!client_error.is_retryable());

        let not_found =
            KeylimectlError::api_error(404, "Not found".to_string(), None);
        assert!(!not_found.is_retryable());

        // Validation errors should not be retryable
        let validation_error = KeylimectlError::validation("Invalid input");
        assert!(!validation_error.is_retryable());

        // IO errors should not be retryable
        let io_error = KeylimectlError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(!io_error.is_retryable());
    }

    #[test]
    fn test_to_json() {
        let error = KeylimectlError::validation("test error");
        let json = error.to_json();

        assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        assert_eq!(json["error"]["message"], "Validation error: test error");
        assert_eq!(json["error"]["details"], Value::Null);
    }

    #[test]
    fn test_api_error_to_json() {
        let response = json!({"error": "not found"});
        let error = KeylimectlError::api_error(
            404,
            "Not found".to_string(),
            Some(response.clone()),
        );
        let json = error.to_json();

        assert_eq!(json["error"]["code"], "API_ERROR");
        assert_eq!(json["error"]["details"]["http_status"], 404);
        assert_eq!(json["error"]["details"]["response"], response);
    }

    #[test]
    fn test_agent_not_found_to_json() {
        let error = KeylimectlError::agent_not_found("12345", "verifier");
        let json = error.to_json();

        assert_eq!(json["error"]["code"], "AGENT_NOT_FOUND");
        assert_eq!(json["error"]["details"]["agent_uuid"], "12345");
        assert_eq!(json["error"]["details"]["service"], "verifier");
    }

    #[test]
    fn test_with_context() {
        let io_error: Result<(), std::io::Error> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));

        let result = io_error
            .with_context(|| "Failed to read config file".to_string());

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.error_code(), "GENERIC_ERROR");
        assert!(error.to_string().contains("Failed to read config file"));
    }
}
