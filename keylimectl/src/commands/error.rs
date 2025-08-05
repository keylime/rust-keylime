//! Command-specific error types for keylimectl
//!
//! This module provides error types specific to CLI command operations,
//! including agent management, policy operations, and resource listing.
//! These errors provide detailed context for command execution failures.
//!
//! # Error Types
//!
//! - [`CommandError`] - Main error type for command operations
//! - [`AgentError`] - Agent management specific errors
//! - [`PolicyError`] - Policy operation specific errors
//! - [`ResourceError`] - Resource listing and management errors
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::commands::error::{CommandError, AgentError};
//!
//! // Create an agent error
//! let agent_err = CommandError::Agent(AgentError::NotFound {
//!     uuid: "12345".to_string(),
//!     service: "verifier".to_string(),
//! });
//!
//! // Create a policy error
//! let policy_err = CommandError::policy_not_found("my_policy");
//! ```

use std::path::PathBuf;
use thiserror::Error;

/// Command execution error types
///
/// This enum covers all error conditions that can occur during CLI command
/// execution, from agent management failures to policy operations and file I/O.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum CommandError {
    /// Agent management errors
    #[error("Agent error: {0}")]
    Agent(#[from] AgentError),

    /// Policy operation errors
    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),

    /// Resource listing and management errors
    #[error("Resource error: {0}")]
    Resource(#[from] ResourceError),

    /// File I/O errors
    #[error("File operation error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing/serialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// UUID parsing errors
    #[error("Invalid UUID: {0}")]
    Uuid(#[from] uuid::Error),

    /// Command parameter validation errors
    #[error("Invalid parameter: {parameter} - {reason}")]
    InvalidParameter { parameter: String, reason: String },

    /// Command execution context errors
    #[error("Command execution error: {details}")]
    Execution { details: String },

    /// Output formatting errors
    #[error("Output formatting error: {format} - {reason}")]
    OutputFormat { format: String, reason: String },
}

/// Agent management specific errors
///
/// These errors represent issues with agent lifecycle operations,
/// including creation, updates, removal, and status queries.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AgentError {
    /// Agent not found on specified service
    #[error("Agent {uuid} not found on {service}")]
    NotFound { uuid: String, service: String },

    /// Agent already exists
    #[error("Agent {uuid} already exists on {service}")]
    AlreadyExists { uuid: String, service: String },

    /// Agent operation failed
    #[error("Agent operation failed: {operation} for {uuid} - {reason}")]
    OperationFailed {
        operation: String,
        uuid: String,
        reason: String,
    },

    /// Invalid agent configuration
    #[error("Invalid agent configuration: {field} - {reason}")]
    InvalidConfiguration { field: String, reason: String },

    /// Agent state inconsistency
    #[error("Agent state inconsistency: {uuid} - {details}")]
    StateInconsistency { uuid: String, details: String },

    /// TPM quote validation failure
    #[error("TPM quote validation failed for {uuid}: {reason}")]
    TpmQuoteValidation { uuid: String, reason: String },

    /// Cryptographic operation failure
    #[error(
        "Cryptographic operation failed for {uuid}: {operation} - {reason}"
    )]
    CryptographicFailure {
        uuid: String,
        operation: String,
        reason: String,
    },

    /// Network connectivity issues with agent
    #[error("Cannot connect to agent {uuid} at {address}: {reason}")]
    ConnectivityFailure {
        uuid: String,
        address: String,
        reason: String,
    },
}

/// Policy operation specific errors
///
/// These errors represent issues with policy management operations,
/// including creation, updates, validation, and file operations.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum PolicyError {
    /// Policy not found
    #[error("Policy '{name}' not found")]
    NotFound { name: String },

    /// Policy already exists
    #[error("Policy '{name}' already exists")]
    AlreadyExists { name: String },

    /// Policy file errors
    #[error("Policy file error: {path} - {reason}")]
    FileError { path: PathBuf, reason: String },

    /// Policy validation errors
    #[error("Policy validation failed: {reason}")]
    ValidationFailed { reason: String },

    /// Policy format errors
    #[error("Invalid policy format in {path}: {reason}")]
    InvalidFormat { path: PathBuf, reason: String },

    /// Policy operation errors
    #[error("Policy operation failed: {operation} for '{name}' - {reason}")]
    OperationFailed {
        operation: String,
        name: String,
        reason: String,
    },

    /// Policy consistency errors
    #[error("Policy consistency error: {details}")]
    ConsistencyError { details: String },

    /// Policy dependency errors
    #[error("Policy dependency error: {policy} depends on {dependency} - {reason}")]
    DependencyError {
        policy: String,
        dependency: String,
        reason: String,
    },
}

/// Resource listing and management errors
///
/// These errors represent issues with resource operations,
/// including listing, filtering, and display formatting.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ResourceError {
    /// Resource not found
    #[error("Resource not found: {resource_type} - {details}")]
    NotFound {
        resource_type: String,
        details: String,
    },

    /// Resource access denied
    #[error("Access denied to resource: {resource_type} - {reason}")]
    AccessDenied {
        resource_type: String,
        reason: String,
    },

    /// Resource listing failed
    #[error("Failed to list {resource_type}: {reason}")]
    ListingFailed {
        resource_type: String,
        reason: String,
    },

    /// Resource filtering error
    #[error("Resource filtering error: {filter} - {reason}")]
    FilterError { filter: String, reason: String },

    /// Resource format error
    #[error("Resource format error: {reason}")]
    FormatError { reason: String },

    /// Empty result set
    #[error("No {resource_type} found matching criteria")]
    EmptyResult { resource_type: String },
}

#[allow(dead_code)]
impl CommandError {
    /// Create an invalid parameter error
    pub fn invalid_parameter<P: Into<String>, R: Into<String>>(
        parameter: P,
        reason: R,
    ) -> Self {
        Self::InvalidParameter {
            parameter: parameter.into(),
            reason: reason.into(),
        }
    }

    /// Create an execution error
    pub fn execution<D: Into<String>>(details: D) -> Self {
        Self::Execution {
            details: details.into(),
        }
    }

    /// Create an output format error
    pub fn output_format<F: Into<String>, R: Into<String>>(
        format: F,
        reason: R,
    ) -> Self {
        Self::OutputFormat {
            format: format.into(),
            reason: reason.into(),
        }
    }

    /// Create an agent not found error
    pub fn agent_not_found<U: Into<String>, S: Into<String>>(
        uuid: U,
        service: S,
    ) -> Self {
        Self::Agent(AgentError::NotFound {
            uuid: uuid.into(),
            service: service.into(),
        })
    }

    /// Create a policy not found error
    pub fn policy_not_found<N: Into<String>>(name: N) -> Self {
        Self::Policy(PolicyError::NotFound { name: name.into() })
    }

    /// Create a resource not found error
    pub fn resource_not_found<T: Into<String>, D: Into<String>>(
        resource_type: T,
        details: D,
    ) -> Self {
        Self::Resource(ResourceError::NotFound {
            resource_type: resource_type.into(),
            details: details.into(),
        })
    }

    /// Create a resource error
    pub fn resource_error<T: Into<String>, R: Into<String>>(
        resource_type: T,
        reason: R,
    ) -> Self {
        Self::Resource(ResourceError::ListingFailed {
            resource_type: resource_type.into(),
            reason: reason.into(),
        })
    }

    /// Create an agent operation failed error
    pub fn agent_operation_failed<
        U: Into<String>,
        O: Into<String>,
        R: Into<String>,
    >(
        uuid: U,
        operation: O,
        reason: R,
    ) -> Self {
        Self::Agent(AgentError::OperationFailed {
            uuid: uuid.into(),
            operation: operation.into(),
            reason: reason.into(),
        })
    }

    /// Create a policy file error
    pub fn policy_file_error<P: Into<String>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::Policy(PolicyError::FileError {
            path: PathBuf::from(path.into()),
            reason: reason.into(),
        })
    }

    /// Get the error category for structured logging
    pub fn category(&self) -> &'static str {
        match self {
            Self::Agent(_) => "agent",
            Self::Policy(_) => "policy",
            Self::Resource(_) => "resource",
            Self::Io(_) => "io",
            Self::Json(_) => "json",
            Self::Uuid(_) => "uuid",
            Self::InvalidParameter { .. } => "parameter",
            Self::Execution { .. } => "execution",
            Self::OutputFormat { .. } => "output_format",
        }
    }

    /// Check if this is a user error (vs system error)
    pub fn is_user_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidParameter { .. }
                | Self::Uuid(_)
                | Self::Agent(AgentError::InvalidConfiguration { .. })
                | Self::Policy(PolicyError::ValidationFailed { .. })
                | Self::Policy(PolicyError::InvalidFormat { .. })
                | Self::Resource(ResourceError::FilterError { .. })
                | Self::OutputFormat { .. }
        )
    }

    /// Check if the operation should be retried
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Agent(AgentError::ConnectivityFailure { .. }) => true,
            Self::Agent(AgentError::OperationFailed { .. }) => true,
            Self::Resource(ResourceError::ListingFailed { .. }) => true,
            Self::Io(io_err) => matches!(
                io_err.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
            ),
            _ => false,
        }
    }
}

#[allow(dead_code)]
impl AgentError {
    /// Create an agent not found error
    pub fn not_found<U: Into<String>, S: Into<String>>(
        uuid: U,
        service: S,
    ) -> Self {
        Self::NotFound {
            uuid: uuid.into(),
            service: service.into(),
        }
    }

    /// Create an agent already exists error
    pub fn already_exists<U: Into<String>, S: Into<String>>(
        uuid: U,
        service: S,
    ) -> Self {
        Self::AlreadyExists {
            uuid: uuid.into(),
            service: service.into(),
        }
    }

    /// Create an operation failed error
    pub fn operation_failed<
        O: Into<String>,
        U: Into<String>,
        R: Into<String>,
    >(
        operation: O,
        uuid: U,
        reason: R,
    ) -> Self {
        Self::OperationFailed {
            operation: operation.into(),
            uuid: uuid.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid configuration error
    pub fn invalid_configuration<F: Into<String>, R: Into<String>>(
        field: F,
        reason: R,
    ) -> Self {
        Self::InvalidConfiguration {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Create a state inconsistency error
    pub fn state_inconsistency<U: Into<String>, D: Into<String>>(
        uuid: U,
        details: D,
    ) -> Self {
        Self::StateInconsistency {
            uuid: uuid.into(),
            details: details.into(),
        }
    }

    /// Create a TPM quote validation error
    pub fn tpm_quote_validation<U: Into<String>, R: Into<String>>(
        uuid: U,
        reason: R,
    ) -> Self {
        Self::TpmQuoteValidation {
            uuid: uuid.into(),
            reason: reason.into(),
        }
    }

    /// Create a cryptographic failure error
    pub fn cryptographic_failure<
        U: Into<String>,
        O: Into<String>,
        R: Into<String>,
    >(
        uuid: U,
        operation: O,
        reason: R,
    ) -> Self {
        Self::CryptographicFailure {
            uuid: uuid.into(),
            operation: operation.into(),
            reason: reason.into(),
        }
    }

    /// Create a connectivity failure error
    pub fn connectivity_failure<
        U: Into<String>,
        A: Into<String>,
        R: Into<String>,
    >(
        uuid: U,
        address: A,
        reason: R,
    ) -> Self {
        Self::ConnectivityFailure {
            uuid: uuid.into(),
            address: address.into(),
            reason: reason.into(),
        }
    }
}

#[allow(dead_code)]
impl PolicyError {
    /// Create a policy not found error
    pub fn not_found<N: Into<String>>(name: N) -> Self {
        Self::NotFound { name: name.into() }
    }

    /// Create a policy already exists error
    pub fn already_exists<N: Into<String>>(name: N) -> Self {
        Self::AlreadyExists { name: name.into() }
    }

    /// Create a file error
    pub fn file_error<P: Into<PathBuf>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::FileError {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create a validation failed error
    pub fn validation_failed<R: Into<String>>(reason: R) -> Self {
        Self::ValidationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid format error
    pub fn invalid_format<P: Into<PathBuf>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::InvalidFormat {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create an operation failed error
    pub fn operation_failed<
        O: Into<String>,
        N: Into<String>,
        R: Into<String>,
    >(
        operation: O,
        name: N,
        reason: R,
    ) -> Self {
        Self::OperationFailed {
            operation: operation.into(),
            name: name.into(),
            reason: reason.into(),
        }
    }

    /// Create a consistency error
    pub fn consistency_error<D: Into<String>>(details: D) -> Self {
        Self::ConsistencyError {
            details: details.into(),
        }
    }

    /// Create a dependency error
    pub fn dependency_error<
        P: Into<String>,
        D: Into<String>,
        R: Into<String>,
    >(
        policy: P,
        dependency: D,
        reason: R,
    ) -> Self {
        Self::DependencyError {
            policy: policy.into(),
            dependency: dependency.into(),
            reason: reason.into(),
        }
    }
}

#[allow(dead_code)]
impl ResourceError {
    /// Create a resource not found error
    pub fn not_found<T: Into<String>, D: Into<String>>(
        resource_type: T,
        details: D,
    ) -> Self {
        Self::NotFound {
            resource_type: resource_type.into(),
            details: details.into(),
        }
    }

    /// Create an access denied error
    pub fn access_denied<T: Into<String>, R: Into<String>>(
        resource_type: T,
        reason: R,
    ) -> Self {
        Self::AccessDenied {
            resource_type: resource_type.into(),
            reason: reason.into(),
        }
    }

    /// Create a listing failed error
    pub fn listing_failed<T: Into<String>, R: Into<String>>(
        resource_type: T,
        reason: R,
    ) -> Self {
        Self::ListingFailed {
            resource_type: resource_type.into(),
            reason: reason.into(),
        }
    }

    /// Create a filter error
    pub fn filter_error<F: Into<String>, R: Into<String>>(
        filter: F,
        reason: R,
    ) -> Self {
        Self::FilterError {
            filter: filter.into(),
            reason: reason.into(),
        }
    }

    /// Create a format error
    pub fn format_error<R: Into<String>>(reason: R) -> Self {
        Self::FormatError {
            reason: reason.into(),
        }
    }

    /// Create an empty result error
    pub fn empty_result<T: Into<String>>(resource_type: T) -> Self {
        Self::EmptyResult {
            resource_type: resource_type.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_command_error_creation() {
        let param_err =
            CommandError::invalid_parameter("uuid", "Invalid format");
        assert_eq!(param_err.category(), "parameter");
        assert!(param_err.is_user_error());
        assert!(!param_err.is_retryable());

        let exec_err = CommandError::execution("Connection timeout");
        assert_eq!(exec_err.category(), "execution");
        assert!(!exec_err.is_user_error());

        let format_err =
            CommandError::output_format("table", "Invalid column width");
        assert_eq!(format_err.category(), "output_format");
        assert!(format_err.is_user_error());
    }

    #[test]
    fn test_agent_error_creation() {
        let not_found = AgentError::not_found("12345", "verifier");
        match not_found {
            AgentError::NotFound { uuid, service } => {
                assert_eq!(uuid, "12345");
                assert_eq!(service, "verifier");
            }
            _ => panic!("Expected NotFound error"),
        }

        let op_failed =
            AgentError::operation_failed("add", "12345", "Network timeout");
        match op_failed {
            AgentError::OperationFailed {
                operation,
                uuid,
                reason,
            } => {
                assert_eq!(operation, "add");
                assert_eq!(uuid, "12345");
                assert_eq!(reason, "Network timeout");
            }
            _ => panic!("Expected OperationFailed error"),
        }

        let crypto_failed = AgentError::cryptographic_failure(
            "12345",
            "RSA encryption",
            "Invalid public key",
        );
        match crypto_failed {
            AgentError::CryptographicFailure {
                uuid,
                operation,
                reason,
            } => {
                assert_eq!(uuid, "12345");
                assert_eq!(operation, "RSA encryption");
                assert_eq!(reason, "Invalid public key");
            }
            _ => panic!("Expected CryptographicFailure error"),
        }
    }

    #[test]
    fn test_policy_error_creation() {
        let not_found = PolicyError::not_found("my_policy");
        match not_found {
            PolicyError::NotFound { name } => {
                assert_eq!(name, "my_policy");
            }
            _ => panic!("Expected NotFound error"),
        }

        let file_err =
            PolicyError::file_error("/path/policy.json", "Permission denied");
        match file_err {
            PolicyError::FileError { path, reason } => {
                assert_eq!(path, PathBuf::from("/path/policy.json"));
                assert_eq!(reason, "Permission denied");
            }
            _ => panic!("Expected FileError error"),
        }

        let validation_err =
            PolicyError::validation_failed("Missing allowlist field");
        match validation_err {
            PolicyError::ValidationFailed { reason } => {
                assert_eq!(reason, "Missing allowlist field");
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[test]
    fn test_resource_error_creation() {
        let not_found =
            ResourceError::not_found("agents", "No agents registered");
        match not_found {
            ResourceError::NotFound {
                resource_type,
                details,
            } => {
                assert_eq!(resource_type, "agents");
                assert_eq!(details, "No agents registered");
            }
            _ => panic!("Expected NotFound error"),
        }

        let listing_failed =
            ResourceError::listing_failed("policies", "API unavailable");
        match listing_failed {
            ResourceError::ListingFailed {
                resource_type,
                reason,
            } => {
                assert_eq!(resource_type, "policies");
                assert_eq!(reason, "API unavailable");
            }
            _ => panic!("Expected ListingFailed error"),
        }

        let empty_result = ResourceError::empty_result("agents");
        match empty_result {
            ResourceError::EmptyResult { resource_type } => {
                assert_eq!(resource_type, "agents");
            }
            _ => panic!("Expected EmptyResult error"),
        }
    }

    #[test]
    fn test_error_display() {
        let agent_err = AgentError::not_found("12345", "verifier");
        assert!(agent_err.to_string().contains("12345"));
        assert!(agent_err.to_string().contains("verifier"));
        assert!(agent_err.to_string().contains("not found"));

        let policy_err =
            PolicyError::validation_failed("Invalid JSON syntax");
        assert!(policy_err.to_string().contains("validation failed"));
        assert!(policy_err.to_string().contains("Invalid JSON syntax"));

        let resource_err = ResourceError::empty_result("agents");
        assert!(resource_err.to_string().contains("No agents found"));
    }

    #[test]
    fn test_retryable_classification() {
        // Retryable errors
        let connectivity_err =
            CommandError::Agent(AgentError::connectivity_failure(
                "12345",
                "192.168.1.100:9002",
                "Connection refused",
            ));
        assert!(connectivity_err.is_retryable());

        let op_failed = CommandError::Agent(AgentError::operation_failed(
            "add",
            "12345",
            "Temporary failure",
        ));
        assert!(op_failed.is_retryable());

        let listing_failed = CommandError::Resource(
            ResourceError::listing_failed("agents", "Service unavailable"),
        );
        assert!(listing_failed.is_retryable());

        // Non-retryable errors
        let invalid_param =
            CommandError::invalid_parameter("uuid", "Invalid format");
        assert!(!invalid_param.is_retryable());

        let validation_err = CommandError::Policy(
            PolicyError::validation_failed("Bad syntax"),
        );
        assert!(!validation_err.is_retryable());
    }

    #[test]
    fn test_user_error_classification() {
        // User errors
        let invalid_param =
            CommandError::invalid_parameter("port", "Must be > 0");
        assert!(invalid_param.is_user_error());

        let validation_err =
            CommandError::Policy(PolicyError::validation_failed("Bad JSON"));
        assert!(validation_err.is_user_error());

        let uuid_err =
            CommandError::invalid_parameter("uuid", "Invalid format");
        assert!(uuid_err.is_user_error());

        // System errors
        let io_err = CommandError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied",
        ));
        assert!(!io_err.is_user_error());

        let agent_not_found =
            CommandError::agent_not_found("12345", "verifier");
        assert!(!agent_not_found.is_user_error());
    }
}
