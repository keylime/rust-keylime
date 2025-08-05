//! Configuration-specific error types for keylimectl
//!
//! This module provides error types specific to configuration loading,
//! validation, and processing. These errors provide detailed context
//! for configuration-related issues while maintaining good error ergonomics.
//!
//! # Error Types
//!
//! - [`ConfigError`] - Main error type for configuration operations
//! - [`ValidationError`] - Specific validation error details
//! - [`LoadError`] - Configuration file loading errors
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::config::error::{ConfigError, ValidationError};
//!
//! // Create a validation error
//! let validation_err = ConfigError::Validation(ValidationError::InvalidPort {
//!     service: "verifier".to_string(),
//!     port: 0,
//!     reason: "Port cannot be zero".to_string(),
//! });
//!
//! // Create a file loading error
//! let load_err = ConfigError::file_not_found("/path/to/config.toml");
//! ```

use std::path::PathBuf;
use thiserror::Error;

/// Configuration-specific error types
///
/// This enum covers all error conditions that can occur during configuration
/// operations, from file loading to validation and environment variable processing.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ConfigError {
    /// Configuration file loading errors
    #[error("Configuration file error: {0}")]
    Load(#[from] LoadError),

    /// Configuration validation errors
    #[error("Configuration validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Environment variable processing errors
    #[error("Environment variable error: {message}")]
    Environment { message: String },

    /// Serialization/deserialization errors
    #[error("Configuration serialization error: {message}")]
    Serialization { message: String },

    /// Configuration parsing errors from config crate
    #[error("Configuration parsing error: {0}")]
    ConfigParsing(#[from] config::ConfigError),

    /// I/O errors when reading configuration files
    #[error("I/O error reading configuration: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid configuration format
    #[error("Invalid configuration format: {details}")]
    InvalidFormat { details: String },

    /// Missing required configuration
    #[error("Missing required configuration: {field}")]
    MissingRequired { field: String },
}

/// Configuration file loading errors
///
/// These errors represent issues when loading configuration files,
/// including file system errors and format issues.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum LoadError {
    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: PathBuf },

    /// Configuration file has invalid permissions
    #[error("Configuration file permission denied: {path}")]
    PermissionDenied { path: PathBuf },

    /// Configuration file has invalid format
    #[error("Invalid configuration file format: {path} - {reason}")]
    InvalidFormat { path: PathBuf, reason: String },

    /// Multiple configuration files with conflicting settings
    #[error("Conflicting configuration files: {details}")]
    ConflictingFiles { details: String },

    /// Configuration file is empty or malformed
    #[error("Malformed configuration file: {path} - {reason}")]
    Malformed { path: PathBuf, reason: String },
}

/// Configuration validation errors
///
/// These errors represent validation failures for specific configuration
/// values, providing detailed context about what is wrong and how to fix it.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ValidationError {
    /// Invalid IP address
    #[error("Invalid IP address for {service}: {ip} - {reason}")]
    InvalidIpAddress {
        service: String,
        ip: String,
        reason: String,
    },

    /// Invalid port number
    #[error("Invalid port for {service}: {port} - {reason}")]
    InvalidPort {
        service: String,
        port: u16,
        reason: String,
    },

    /// TLS certificate file issues
    #[error("TLS certificate error: {path} - {reason}")]
    TlsCertificate { path: String, reason: String },

    /// TLS private key file issues
    #[error("TLS private key error: {path} - {reason}")]
    TlsPrivateKey { path: String, reason: String },

    /// TLS CA certificate file issues
    #[error("TLS CA certificate error: {path} - {reason}")]
    TlsCaCertificate { path: String, reason: String },

    /// Invalid timeout value
    #[error("Invalid timeout: {value} seconds - {reason}")]
    InvalidTimeout { value: u64, reason: String },

    /// Invalid retry configuration
    #[error("Invalid retry configuration: {field} = {value} - {reason}")]
    InvalidRetry {
        field: String,
        value: String,
        reason: String,
    },

    /// Cross-component validation failure
    #[error("Configuration consistency error: {details}")]
    CrossComponent { details: String },

    /// URL construction failure
    #[error("Invalid URL configuration for {service}: {reason}")]
    InvalidUrl { service: String, reason: String },

    /// Missing certificate/key pair
    #[error("TLS configuration incomplete: {reason}")]
    IncompleteTls { reason: String },
}

#[allow(dead_code)]
impl ConfigError {
    /// Create a file not found error
    pub fn file_not_found<P: Into<PathBuf>>(path: P) -> Self {
        Self::Load(LoadError::FileNotFound { path: path.into() })
    }

    /// Create a permission denied error
    pub fn permission_denied<P: Into<PathBuf>>(path: P) -> Self {
        Self::Load(LoadError::PermissionDenied { path: path.into() })
    }

    /// Create an invalid format error
    pub fn invalid_format<D: Into<String>>(details: D) -> Self {
        Self::InvalidFormat {
            details: details.into(),
        }
    }

    /// Create a missing required error
    pub fn missing_required<F: Into<String>>(field: F) -> Self {
        Self::MissingRequired {
            field: field.into(),
        }
    }

    /// Create an environment variable error
    pub fn environment<M: Into<String>>(message: M) -> Self {
        Self::Environment {
            message: message.into(),
        }
    }

    /// Create a serialization error
    pub fn serialization<M: Into<String>>(message: M) -> Self {
        Self::Serialization {
            message: message.into(),
        }
    }

    /// Get the error category for structured logging
    pub fn category(&self) -> &'static str {
        match self {
            Self::Load(_) => "load",
            Self::Validation(_) => "validation",
            Self::Environment { .. } => "environment",
            Self::Serialization { .. } => "serialization",
            Self::ConfigParsing(_) => "parsing",
            Self::Io(_) => "io",
            Self::InvalidFormat { .. } => "format",
            Self::MissingRequired { .. } => "missing_required",
        }
    }

    /// Check if this is a user configuration error (vs system error)
    pub fn is_user_error(&self) -> bool {
        matches!(
            self,
            Self::Validation(_)
                | Self::InvalidFormat { .. }
                | Self::MissingRequired { .. }
                | Self::Load(LoadError::InvalidFormat { .. })
                | Self::Load(LoadError::Malformed { .. })
                | Self::Load(LoadError::ConflictingFiles { .. })
        )
    }
}

#[allow(dead_code)]
impl ValidationError {
    /// Create an invalid IP address error
    pub fn invalid_ip_address<
        S: Into<String>,
        I: Into<String>,
        R: Into<String>,
    >(
        service: S,
        ip: I,
        reason: R,
    ) -> Self {
        Self::InvalidIpAddress {
            service: service.into(),
            ip: ip.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid port error
    pub fn invalid_port<S: Into<String>, R: Into<String>>(
        service: S,
        port: u16,
        reason: R,
    ) -> Self {
        Self::InvalidPort {
            service: service.into(),
            port,
            reason: reason.into(),
        }
    }

    /// Create a TLS certificate error
    pub fn tls_certificate<P: Into<String>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::TlsCertificate {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create a TLS private key error
    pub fn tls_private_key<P: Into<String>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::TlsPrivateKey {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create a TLS CA certificate error
    pub fn tls_ca_certificate<P: Into<String>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::TlsCaCertificate {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid timeout error
    pub fn invalid_timeout<R: Into<String>>(value: u64, reason: R) -> Self {
        Self::InvalidTimeout {
            value,
            reason: reason.into(),
        }
    }

    /// Create an invalid retry configuration error
    pub fn invalid_retry<
        F: Into<String>,
        V: Into<String>,
        R: Into<String>,
    >(
        field: F,
        value: V,
        reason: R,
    ) -> Self {
        Self::InvalidRetry {
            field: field.into(),
            value: value.into(),
            reason: reason.into(),
        }
    }

    /// Create a cross-component validation error
    pub fn cross_component<D: Into<String>>(details: D) -> Self {
        Self::CrossComponent {
            details: details.into(),
        }
    }

    /// Create an invalid URL error
    pub fn invalid_url<S: Into<String>, R: Into<String>>(
        service: S,
        reason: R,
    ) -> Self {
        Self::InvalidUrl {
            service: service.into(),
            reason: reason.into(),
        }
    }

    /// Create an incomplete TLS configuration error
    pub fn incomplete_tls<R: Into<String>>(reason: R) -> Self {
        Self::IncompleteTls {
            reason: reason.into(),
        }
    }
}

#[allow(dead_code)]
impl LoadError {
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

    /// Create a conflicting files error
    pub fn conflicting_files<D: Into<String>>(details: D) -> Self {
        Self::ConflictingFiles {
            details: details.into(),
        }
    }

    /// Create a malformed file error
    pub fn malformed<P: Into<PathBuf>, R: Into<String>>(
        path: P,
        reason: R,
    ) -> Self {
        Self::Malformed {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_config_error_creation() {
        let file_err = ConfigError::file_not_found("/path/to/config.toml");
        assert_eq!(file_err.category(), "load");
        assert!(!file_err.is_user_error());

        let format_err = ConfigError::invalid_format("Expected TOML format");
        assert_eq!(format_err.category(), "format");
        assert!(format_err.is_user_error());

        let env_err = ConfigError::environment("Invalid KEYLIME_PORT value");
        assert_eq!(env_err.category(), "environment");
        assert!(!env_err.is_user_error());

        let missing_err = ConfigError::missing_required("verifier.port");
        assert_eq!(missing_err.category(), "missing_required");
        assert!(missing_err.is_user_error());
    }

    #[test]
    fn test_validation_error_creation() {
        let ip_err = ValidationError::invalid_ip_address(
            "verifier",
            "invalid.ip",
            "Not a valid IP address",
        );
        match ip_err {
            ValidationError::InvalidIpAddress {
                service,
                ip,
                reason,
            } => {
                assert_eq!(service, "verifier");
                assert_eq!(ip, "invalid.ip");
                assert_eq!(reason, "Not a valid IP address");
            }
            _ => panic!("Expected InvalidIpAddress error"),
        }

        let port_err = ValidationError::invalid_port(
            "registrar",
            0,
            "Port cannot be zero",
        );
        match port_err {
            ValidationError::InvalidPort {
                service,
                port,
                reason,
            } => {
                assert_eq!(service, "registrar");
                assert_eq!(port, 0);
                assert_eq!(reason, "Port cannot be zero");
            }
            _ => panic!("Expected InvalidPort error"),
        }

        let tls_err = ValidationError::tls_certificate(
            "/path/cert.pem",
            "File not found",
        );
        match tls_err {
            ValidationError::TlsCertificate { path, reason } => {
                assert_eq!(path, "/path/cert.pem");
                assert_eq!(reason, "File not found");
            }
            _ => panic!("Expected TlsCertificate error"),
        }
    }

    #[test]
    fn test_load_error_creation() {
        let not_found = LoadError::FileNotFound {
            path: PathBuf::from("/config.toml"),
        };
        assert!(not_found.to_string().contains("/config.toml"));

        let invalid_format =
            LoadError::invalid_format("/config.toml", "Invalid TOML syntax");
        match invalid_format {
            LoadError::InvalidFormat { path, reason } => {
                assert_eq!(path, PathBuf::from("/config.toml"));
                assert_eq!(reason, "Invalid TOML syntax");
            }
            _ => panic!("Expected InvalidFormat error"),
        }

        let conflicting =
            LoadError::conflicting_files("Multiple port settings found");
        match conflicting {
            LoadError::ConflictingFiles { details } => {
                assert_eq!(details, "Multiple port settings found");
            }
            _ => panic!("Expected ConflictingFiles error"),
        }
    }

    #[test]
    fn test_error_display() {
        let validation_err = ValidationError::invalid_port(
            "verifier",
            0,
            "Must be greater than 0",
        );
        assert!(validation_err.to_string().contains("verifier"));
        assert!(validation_err.to_string().contains("0"));
        assert!(validation_err
            .to_string()
            .contains("Must be greater than 0"));

        let config_err = ConfigError::Validation(validation_err);
        assert!(config_err
            .to_string()
            .contains("Configuration validation error"));

        let load_err = LoadError::FileNotFound {
            path: PathBuf::from("/test.toml"),
        };
        assert!(load_err.to_string().contains("not found"));
        assert!(load_err.to_string().contains("/test.toml"));
    }

    #[test]
    fn test_user_error_classification() {
        // User errors (configuration mistakes)
        let validation_err = ConfigError::Validation(
            ValidationError::invalid_port("verifier", 0, "Invalid"),
        );
        assert!(validation_err.is_user_error());

        let format_err = ConfigError::invalid_format("Bad TOML");
        assert!(format_err.is_user_error());

        // System errors (environmental issues)
        let io_err = ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied",
        ));
        assert!(!io_err.is_user_error());

        let env_err = ConfigError::environment("Missing env var");
        assert!(!env_err.is_user_error());
    }
}
