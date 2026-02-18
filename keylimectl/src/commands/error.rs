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
pub enum CommandError {
    /// Agent management errors
    #[error("Agent error: {0}")]
    Agent(#[from] AgentError),

    /// Policy operation errors
    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),

    /// Policy generation errors
    #[error("Policy generation error: {0}")]
    PolicyGeneration(#[from] PolicyGenerationError),

    /// DSSE signing/verification errors
    #[error("DSSE error: {0}")]
    Dsse(#[from] DsseError),

    /// Evidence verification errors
    #[error("Evidence error: {0}")]
    Evidence(#[from] EvidenceError),

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
}

/// Agent management specific errors
///
/// These errors represent issues with agent lifecycle operations,
/// including creation, updates, removal, and status queries.
#[derive(Error, Debug)]
pub enum AgentError {
    /// Agent not found on specified service
    #[error("Agent {uuid} not found on {service}")]
    NotFound { uuid: String, service: String },

    /// Agent operation failed
    #[cfg_attr(not(feature = "api-v2"), allow(dead_code))]
    #[error("Agent operation failed: {operation} for {uuid} - {reason}")]
    OperationFailed {
        operation: String,
        uuid: String,
        reason: String,
    },
}

/// Policy operation specific errors
///
/// These errors represent issues with policy management operations,
/// including creation, updates, validation, and file operations.
#[derive(Error, Debug)]
pub enum PolicyError {
    /// Policy not found
    #[error("Policy '{name}' not found")]
    NotFound { name: String },

    /// Policy file errors
    #[error("Policy file error: {path} - {reason}")]
    FileError { path: PathBuf, reason: String },
}

/// Resource listing and management errors
///
/// These errors represent issues with resource operations,
/// including listing, filtering, and display formatting.
#[derive(Error, Debug)]
pub enum ResourceError {
    /// Resource listing failed
    #[error("Failed to list {resource_type}: {reason}")]
    ListingFailed {
        resource_type: String,
        reason: String,
    },
}

/// Policy generation errors
///
/// These errors represent issues with local policy generation,
/// including IMA log parsing, filesystem scanning, and digest calculation.
#[derive(Error, Debug)]
#[allow(dead_code)] // Variants used as features are implemented
pub enum PolicyGenerationError {
    /// IMA measurement list parse error
    #[error("Failed to parse IMA measurement list {path}: {reason}")]
    ImaParse { path: PathBuf, reason: String },

    /// Allowlist parse error
    #[error("Failed to parse allowlist {path}: {reason}")]
    AllowlistParse { path: PathBuf, reason: String },

    /// Filesystem scan error
    #[error("Filesystem scan error at {path}: {reason}")]
    FilesystemScan { path: PathBuf, reason: String },

    /// Digest calculation error
    #[error("Failed to calculate digest for {path}: {reason}")]
    Digest { path: PathBuf, reason: String },

    /// Policy merge error
    #[error("Failed to merge policies: {reason}")]
    Merge { reason: String },

    /// Unsupported hash algorithm
    #[error("Unsupported hash algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    /// Output write error
    #[error("Failed to write output to {path}: {reason}")]
    Output { path: PathBuf, reason: String },
}

/// DSSE (Dead Simple Signing Envelope) errors
///
/// These errors represent issues with policy signing and
/// signature verification using the DSSE protocol.
#[derive(Error, Debug)]
#[allow(dead_code)] // Variants used as features are implemented
pub enum DsseError {
    /// Signing operation failed
    #[error("Signing failed: {reason}")]
    SigningFailed { reason: String },

    /// Signature verification failed
    #[error("Signature verification failed: {reason}")]
    VerificationFailed { reason: String },

    /// Invalid DSSE envelope structure
    #[error("Invalid DSSE envelope: {reason}")]
    InvalidEnvelope { reason: String },

    /// Key loading or generation error
    #[error("Key error: {reason}")]
    KeyError { reason: String },
}

/// Evidence verification errors
///
/// These errors represent issues with one-shot attestation
/// evidence verification via the verifier.
#[derive(Error, Debug)]
#[allow(dead_code)] // Variants used as features are implemented
pub enum EvidenceError {
    /// Invalid or malformed evidence
    #[error("Invalid evidence: {reason}")]
    InvalidEvidence { reason: String },

    /// Verifier communication error
    #[error("Verifier error: {reason}")]
    VerifierError { reason: String },
}

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
    #[cfg_attr(not(feature = "api-v2"), allow(dead_code))]
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
}

impl AgentError {}

impl PolicyError {}

impl ResourceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_command_error_creation() {
        let _param_err =
            CommandError::invalid_parameter("uuid", "Invalid format");
    }

    #[test]
    fn test_agent_error_creation() {
        let not_found = AgentError::NotFound {
            uuid: "12345".to_string(),
            service: "verifier".to_string(),
        };
        match not_found {
            AgentError::NotFound { uuid, service } => {
                assert_eq!(uuid, "12345");
                assert_eq!(service, "verifier");
            }
            _ => panic!("Expected NotFound error"), //#[allow_ci]
        }

        let op_failed = AgentError::OperationFailed {
            operation: "add".to_string(),
            uuid: "12345".to_string(),
            reason: "Network timeout".to_string(),
        };
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
            _ => panic!("Expected OperationFailed error"), //#[allow_ci]
        }
    }

    #[test]
    fn test_policy_error_creation() {
        let not_found = PolicyError::NotFound {
            name: "my_policy".to_string(),
        };
        match not_found {
            PolicyError::NotFound { name } => {
                assert_eq!(name, "my_policy");
            }
            _ => panic!("Expected NotFound error"), //#[allow_ci]
        }

        let file_err = PolicyError::FileError {
            path: PathBuf::from("/path/policy.json"),
            reason: "Permission denied".to_string(),
        };
        match file_err {
            PolicyError::FileError { path, reason } => {
                assert_eq!(path, PathBuf::from("/path/policy.json"));
                assert_eq!(reason, "Permission denied");
            }
            _ => panic!("Expected FileError error"), //#[allow_ci]
        }
    }

    #[test]
    fn test_resource_error_creation() {
        let listing_failed = ResourceError::ListingFailed {
            resource_type: "policies".to_string(),
            reason: "API unavailable".to_string(),
        };
        match listing_failed {
            ResourceError::ListingFailed {
                resource_type,
                reason,
            } => {
                assert_eq!(resource_type, "policies");
                assert_eq!(reason, "API unavailable");
            }
        }
    }

    #[test]
    fn test_error_display() {
        let agent_err = AgentError::NotFound {
            uuid: "12345".to_string(),
            service: "verifier".to_string(),
        };
        assert!(agent_err.to_string().contains("12345"));
        assert!(agent_err.to_string().contains("verifier"));
        assert!(agent_err.to_string().contains("not found"));

        let policy_err = PolicyError::NotFound {
            name: "test_policy".to_string(),
        };
        assert!(policy_err.to_string().contains("test_policy"));
        assert!(policy_err.to_string().contains("not found"));

        let resource_err = ResourceError::ListingFailed {
            resource_type: "agents".to_string(),
            reason: "Service unavailable".to_string(),
        };
        assert!(resource_err.to_string().contains("agents"));
    }

    #[test]
    fn test_error_classification() {
        // Operation failed errors
        let _op_failed = CommandError::Agent(AgentError::OperationFailed {
            operation: "add".to_string(),
            uuid: "12345".to_string(),
            reason: "Temporary failure".to_string(),
        });

        let _listing_failed =
            CommandError::Resource(ResourceError::ListingFailed {
                resource_type: "agents".to_string(),
                reason: "Service unavailable".to_string(),
            });

        // Parameter errors
        let _invalid_param =
            CommandError::invalid_parameter("uuid", "Invalid format");
    }

    #[test]
    fn test_user_error_classification() {
        // System errors
        let _io_err = CommandError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied",
        ));
        // Note: is_user_error() method was removed as unused

        let _agent_not_found =
            CommandError::agent_not_found("12345", "verifier");
        // This verifies the constructor still works
    }
}
