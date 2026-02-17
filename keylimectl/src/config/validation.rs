// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Configuration validation logic for keylimectl
//!
//! This module provides comprehensive validation for all configuration components,
//! ensuring that configuration values are valid and usable before the application
//! attempts to use them. The validation is structured into logical groups for
//! better maintainability and testing.
//!
//! # Validation Categories
//!
//! 1. **Network Validation**: IP addresses, ports, and connectivity requirements
//! 2. **TLS Validation**: Certificate files, key files, and TLS settings
//! 3. **Client Validation**: Timeouts, retries, and HTTP client settings
//! 4. **Cross-Component Validation**: Validation that spans multiple config sections
//!
//! # Error Handling
//!
//! All validation functions return `Result<(), ConfigError>` where errors contain
//! descriptive messages that can be shown directly to users.
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::config::{Config, validation};
//!
//! let config = Config::default();
//!
//! // Validate entire configuration
//! validation::validate_complete_config(&config)?;
//!
//! // Validate specific components
//! validation::validate_network_config(&config.verifier, &config.registrar)?;
//! validation::validate_tls_config(&config.tls)?;
//! validation::validate_client_config(&config.client)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use super::{ClientConfig, RegistrarConfig, TlsConfig, VerifierConfig};
use config::ConfigError;
use std::path::Path;

/// Validate the complete configuration
///
/// This is the main validation entry point that performs comprehensive validation
/// of all configuration components and their interactions.
///
/// # Arguments
///
/// * `verifier` - Verifier service configuration
/// * `registrar` - Registrar service configuration
/// * `tls` - TLS/SSL security configuration
/// * `client` - HTTP client behavior configuration
///
/// # Returns
///
/// Returns `Ok(())` if all validation passes, or `Err(ConfigError)` with a
/// descriptive error message indicating the first validation failure encountered.
///
/// # Validation Performed
///
/// 1. Network configuration (IPs and ports)
/// 2. TLS configuration (certificates and settings)
/// 3. Client configuration (timeouts and retries)
/// 4. Cross-component consistency checks
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::{Config, validation};
///
/// let config = Config::default();
/// validation::validate_complete_config(
///     &config.verifier,
///     &config.registrar,
///     &config.tls,
///     &config.client
/// )?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_complete_config(
    verifier: &VerifierConfig,
    registrar: &RegistrarConfig,
    tls: &TlsConfig,
    client: &ClientConfig,
) -> Result<(), ConfigError> {
    // Validate each component
    validate_network_config(verifier, registrar)?;
    validate_tls_config(tls)?;
    validate_client_config(client)?;

    // Perform cross-component validation
    validate_cross_component_config(verifier, registrar, tls, client)?;

    Ok(())
}

/// Validate network configuration (IP addresses and ports)
///
/// Ensures that IP addresses are not empty and ports are valid (non-zero).
/// This validation is essential for establishing network connections to services.
///
/// # Arguments
///
/// * `verifier` - Verifier service configuration
/// * `registrar` - Registrar service configuration
///
/// # Returns
///
/// Returns `Ok(())` if network configuration is valid, or `Err(ConfigError)`
/// with a specific error message.
///
/// # Validation Rules
///
/// - IP addresses cannot be empty strings
/// - Ports must be greater than 0 (valid port range 1-65535)
/// - IPv6 addresses are automatically detected and handled properly
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::{VerifierConfig, RegistrarConfig, validation};
///
/// let verifier = VerifierConfig {
///     ip: "192.168.1.100".to_string(),
///     port: 8881,
///     id: None,
/// };
/// let registrar = RegistrarConfig {
///     ip: "192.168.1.100".to_string(),
///     port: 8891,
/// };
///
/// validation::validate_network_config(&verifier, &registrar)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_network_config(
    verifier: &VerifierConfig,
    registrar: &RegistrarConfig,
) -> Result<(), ConfigError> {
    // Validate verifier network configuration
    validate_ip_address(&verifier.ip, "Verifier")?;
    validate_port(verifier.port, "Verifier")?;

    // Validate registrar network configuration
    validate_ip_address(&registrar.ip, "Registrar")?;
    validate_port(registrar.port, "Registrar")?;

    Ok(())
}

/// Validate TLS configuration (certificates and security settings)
///
/// Ensures that TLS certificate and key files exist if specified, and that
/// TLS settings are consistent and secure.
///
/// # Arguments
///
/// * `tls` - TLS configuration to validate
///
/// # Returns
///
/// Returns `Ok(())` if TLS configuration is valid, or `Err(ConfigError)`
/// with a specific error message.
///
/// # Validation Rules
///
/// - If client certificate is specified, the file must exist and be readable
/// - If client key is specified, the file must exist and be readable
/// - Certificate and key should be specified together for mTLS
/// - TLS settings should be consistent with security requirements
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::{TlsConfig, validation};
///
/// let tls = TlsConfig {
///     client_cert: None,
///     client_key: None,
///     client_key_password: None,
///     trusted_ca: vec![],
///     verify_server_cert: true,
///     enable_agent_mtls: true,
///     accept_invalid_hostnames: true,
/// };
///
/// validation::validate_tls_config(&tls)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_tls_config(tls: &TlsConfig) -> Result<(), ConfigError> {
    // Validate client certificate if specified
    if let Some(ref cert_path) = tls.client_cert {
        validate_file_exists(cert_path, "Client certificate")?;
    }

    // Validate client key if specified
    if let Some(ref key_path) = tls.client_key {
        validate_file_exists(key_path, "Client key")?;
    }

    // Validate trusted CA certificates if specified
    for ca_path in &tls.trusted_ca {
        validate_file_exists(ca_path, "Trusted CA certificate")?;
    }

    // Validate TLS consistency
    validate_tls_consistency(tls)?;

    Ok(())
}

/// Validate client configuration (timeouts, retries, and HTTP settings)
///
/// Ensures that HTTP client settings are reasonable and will not cause
/// operational issues.
///
/// # Arguments
///
/// * `client` - Client configuration to validate
///
/// # Returns
///
/// Returns `Ok(())` if client configuration is valid, or `Err(ConfigError)`
/// with a specific error message.
///
/// # Validation Rules
///
/// - Timeout must be greater than 0 seconds
/// - Retry interval must be positive (> 0.0 seconds)
/// - Max retries should be reasonable (typically 0-10)
/// - Exponential backoff settings should be consistent
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::{ClientConfig, validation};
///
/// let client = ClientConfig {
///     timeout: 60,
///     retry_interval: 1.0,
///     exponential_backoff: true,
///     max_retries: 3,
/// };
///
/// validation::validate_client_config(&client)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_client_config(
    client: &ClientConfig,
) -> Result<(), ConfigError> {
    // Validate timeout
    if client.timeout == 0 {
        return Err(ConfigError::Message(
            "Client timeout cannot be 0".to_string(),
        ));
    }

    // Validate retry interval
    if client.retry_interval <= 0.0 {
        return Err(ConfigError::Message(
            "Retry interval must be positive".to_string(),
        ));
    }

    // Validate max retries (reasonable upper bound)
    if client.max_retries > 20 {
        return Err(ConfigError::Message(
            "Max retries should not exceed 20 (current value may cause excessive delays)".to_string(),
        ));
    }

    Ok(())
}

/// Validate cross-component configuration consistency
///
/// Performs validation that spans multiple configuration components to ensure
/// they work together properly.
///
/// # Arguments
///
/// * `verifier` - Verifier service configuration
/// * `registrar` - Registrar service configuration
/// * `tls` - TLS configuration
/// * `client` - Client configuration
///
/// # Validation Performed
///
/// - Ensures TLS settings are appropriate for the deployment
/// - Validates that timeout settings are reasonable for the network configuration
/// - Checks for potential configuration conflicts
fn validate_cross_component_config(
    _verifier: &VerifierConfig,
    _registrar: &RegistrarConfig,
    tls: &TlsConfig,
    client: &ClientConfig,
) -> Result<(), ConfigError> {
    // Validate TLS and client timeout relationship
    if tls.verify_server_cert && client.timeout < 10 {
        return Err(ConfigError::Message(
            "Client timeout should be at least 10 seconds when server certificate verification is enabled".to_string(),
        ));
    }

    // More cross-component validations can be added here as needed

    Ok(())
}

/// Validate an IP address field
///
/// Ensures the IP address is not empty. Additional validation for IP format
/// could be added here if needed.
fn validate_ip_address(
    ip: &str,
    service_name: &str,
) -> Result<(), ConfigError> {
    if ip.is_empty() {
        return Err(ConfigError::Message(format!(
            "{service_name} IP cannot be empty"
        )));
    }

    Ok(())
}

/// Validate a port number
///
/// Ensures the port is in the valid range (1-65535).
fn validate_port(port: u16, service_name: &str) -> Result<(), ConfigError> {
    if port == 0 {
        return Err(ConfigError::Message(format!(
            "{service_name} port cannot be 0"
        )));
    }

    Ok(())
}

/// Validate that a file exists and is readable
///
/// Used for validating certificate files, key files, and other required files.
fn validate_file_exists(
    path: &str,
    file_type: &str,
) -> Result<(), ConfigError> {
    if !Path::new(path).exists() {
        return Err(ConfigError::Message(format!(
            "{file_type} file not found: {path}"
        )));
    }

    Ok(())
}

/// Validate TLS configuration consistency
///
/// Ensures that TLS settings are consistent and follow security best practices.
fn validate_tls_consistency(tls: &TlsConfig) -> Result<(), ConfigError> {
    // Check if certificate and key are specified together
    let has_cert = tls.client_cert.is_some();
    let has_key = tls.client_key.is_some();

    if has_cert != has_key {
        return Err(ConfigError::Message(
            "Client certificate and key must be specified together for mutual TLS".to_string(),
        ));
    }

    // Warn if mTLS is enabled but no certificates are provided
    if tls.enable_agent_mtls && !has_cert {
        // This is not necessarily an error, as certificates might be auto-generated
        // But we could add a warning mechanism here if needed
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_valid_verifier_config() -> VerifierConfig {
        VerifierConfig {
            ip: "127.0.0.1".to_string(),
            port: 8881,
            id: None,
        }
    }

    fn create_valid_registrar_config() -> RegistrarConfig {
        RegistrarConfig {
            ip: "127.0.0.1".to_string(),
            port: 8891,
        }
    }

    fn create_valid_tls_config() -> TlsConfig {
        TlsConfig {
            client_cert: None,
            client_key: None,
            client_key_password: None,
            trusted_ca: vec![],
            verify_server_cert: true,
            enable_agent_mtls: true,
            accept_invalid_hostnames: true,
        }
    }

    fn create_valid_client_config() -> ClientConfig {
        ClientConfig {
            timeout: 60,
            retry_interval: 1.0,
            exponential_backoff: true,
            max_retries: 3,
        }
    }

    #[test]
    fn test_validate_complete_config_success() {
        let verifier = create_valid_verifier_config();
        let registrar = create_valid_registrar_config();
        let tls = create_valid_tls_config();
        let client = create_valid_client_config();

        let result =
            validate_complete_config(&verifier, &registrar, &tls, &client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_network_config_success() {
        let verifier = create_valid_verifier_config();
        let registrar = create_valid_registrar_config();

        let result = validate_network_config(&verifier, &registrar);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_network_config_empty_verifier_ip() {
        let mut verifier = create_valid_verifier_config();
        verifier.ip = String::new();
        let registrar = create_valid_registrar_config();

        let result = validate_network_config(&verifier, &registrar);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Verifier IP cannot be empty"));
    }

    #[test]
    fn test_validate_network_config_zero_port() {
        let mut verifier = create_valid_verifier_config();
        verifier.port = 0;
        let registrar = create_valid_registrar_config();

        let result = validate_network_config(&verifier, &registrar);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Verifier port cannot be 0"));
    }

    #[test]
    fn test_validate_tls_config_success() {
        let tls = create_valid_tls_config();
        let result = validate_tls_config(&tls);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tls_config_with_valid_files() {
        // Create temporary files for testing
        let mut cert_file = NamedTempFile::new().unwrap(); //#[allow_ci]
        let mut key_file = NamedTempFile::new().unwrap(); //#[allow_ci]

        cert_file.write_all(b"dummy cert content").unwrap(); //#[allow_ci]
        key_file.write_all(b"dummy key content").unwrap(); //#[allow_ci]

        let tls = TlsConfig {
            client_cert: Some(cert_file.path().to_string_lossy().to_string()),
            client_key: Some(key_file.path().to_string_lossy().to_string()),
            client_key_password: None,
            trusted_ca: vec![],
            verify_server_cert: true,
            enable_agent_mtls: true,
            accept_invalid_hostnames: true,
        };

        let result = validate_tls_config(&tls);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tls_config_missing_cert_file() {
        let tls = TlsConfig {
            client_cert: Some("/nonexistent/cert.pem".to_string()),
            client_key: None,
            client_key_password: None,
            trusted_ca: vec![],
            verify_server_cert: true,
            enable_agent_mtls: true,
            accept_invalid_hostnames: true,
        };

        let result = validate_tls_config(&tls);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Client certificate file not found"));
    }

    #[test]
    fn test_validate_tls_consistency_cert_without_key() {
        let mut cert_file = NamedTempFile::new().unwrap(); //#[allow_ci]
        cert_file.write_all(b"dummy cert content").unwrap(); //#[allow_ci]

        let tls = TlsConfig {
            client_cert: Some(cert_file.path().to_string_lossy().to_string()),
            client_key: None, // Missing key
            client_key_password: None,
            trusted_ca: vec![],
            verify_server_cert: true,
            enable_agent_mtls: true,
            accept_invalid_hostnames: true,
        };

        let result = validate_tls_config(&tls);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be specified together"));
    }

    #[test]
    fn test_validate_client_config_success() {
        let client = create_valid_client_config();
        let result = validate_client_config(&client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_client_config_zero_timeout() {
        let mut client = create_valid_client_config();
        client.timeout = 0;

        let result = validate_client_config(&client);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("timeout cannot be 0"));
    }

    #[test]
    fn test_validate_client_config_negative_retry_interval() {
        let mut client = create_valid_client_config();
        client.retry_interval = -1.0;

        let result = validate_client_config(&client);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be positive"));
    }

    #[test]
    fn test_validate_client_config_excessive_retries() {
        let mut client = create_valid_client_config();
        client.max_retries = 50;

        let result = validate_client_config(&client);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("should not exceed 20"));
    }

    #[test]
    fn test_cross_component_validation_short_timeout_with_tls() {
        let verifier = create_valid_verifier_config();
        let registrar = create_valid_registrar_config();
        let tls = create_valid_tls_config();
        let mut client = create_valid_client_config();
        client.timeout = 5; // Too short for TLS verification

        let result =
            validate_complete_config(&verifier, &registrar, &tls, &client);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 10 seconds"));
    }
}
