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

    /// Configuration parsing errors from config crate
    #[error("Configuration parsing error: {0}")]
    ConfigParsing(#[from] config::ConfigError),

    /// I/O errors when reading configuration files
    #[error("I/O error reading configuration: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration file loading errors
///
/// These errors represent issues when loading configuration files,
/// including file system errors and format issues.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum LoadError {}

/// Configuration validation errors
///
/// These errors represent validation failures for specific configuration
/// values, providing detailed context about what is wrong and how to fix it.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ValidationError {}

impl ConfigError {}

impl ValidationError {}

impl LoadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error_creation() {
        // Test basic error creation and display
        let io_err = ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found",
        ));
        assert!(io_err.to_string().contains("I/O error"));
    }
}
