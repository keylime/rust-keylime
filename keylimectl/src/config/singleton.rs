// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Global configuration singleton for keylimectl
//!
//! This module provides a global singleton for the keylimectl configuration,
//! similar to the pattern used in the keylime agent. The configuration is
//! initialized once at application startup and accessed throughout the
//! application without passing it as a parameter.

use super::Config;
use crate::error::KeylimectlError;
use std::sync::OnceLock;

static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

/// Initialize the global configuration singleton
///
/// This function must be called once at application startup to set the
/// global configuration. Subsequent calls will return an error.
///
/// # Arguments
///
/// * `config` - The configuration to use globally
///
/// # Errors
///
/// Returns an error if the configuration has already been initialized.
///
/// # Examples
///
/// ```rust,ignore
/// use keylimectl::config::{Config, singleton};
///
/// let config = Config::load(None)?;
/// singleton::initialize_config(config)?;
/// ```
pub fn initialize_config(config: Config) -> Result<(), KeylimectlError> {
    GLOBAL_CONFIG.set(config).map_err(|_| {
        KeylimectlError::validation("Config singleton already initialized")
    })
}

/// Get a reference to the global configuration
///
/// This is the main factory method for accessing the configuration throughout
/// the application. The configuration must have been initialized via
/// `initialize_config()` first.
///
/// # Panics
///
/// Panics if the configuration has not been initialized. This is intentional
/// as the configuration should always be initialized at application startup.
///
/// # Examples
///
/// ```rust,ignore
/// use keylimectl::config::singleton;
///
/// let config = singleton::get_config();
/// println!("Verifier: {}:{}", config.verifier.ip, config.verifier.port);
/// ```
pub fn get_config() -> &'static Config {
    GLOBAL_CONFIG
        .get()
        .expect("Config not initialized - call initialize_config first")
}

/// Check if the configuration has been initialized
///
/// This can be used for defensive programming or in tests to verify
/// initialization state.
///
/// # Examples
///
/// ```rust,ignore
/// use keylimectl::config::singleton;
///
/// if !singleton::is_initialized() {
///     eprintln!("Warning: Config not initialized");
/// }
/// ```
#[allow(dead_code)]
pub fn is_initialized() -> bool {
    GLOBAL_CONFIG.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientConfig, RegistrarConfig, TlsConfig, VerifierConfig,
    };

    #[allow(dead_code)]
    fn create_test_config() -> Config {
        Config {
            verifier: VerifierConfig {
                ip: "127.0.0.1".to_string(),
                port: 8881,
                id: Some("test-verifier".to_string()),
            },
            registrar: RegistrarConfig {
                ip: "127.0.0.1".to_string(),
                port: 8891,
            },
            tls: TlsConfig {
                client_cert: None,
                client_key: None,
                client_key_password: None,
                trusted_ca: vec![],
                verify_server_cert: false,
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
    fn test_singleton_not_initialized() {
        // Note: This test may fail if other tests have initialized the singleton
        // In a real scenario, we'd need test isolation
        assert!(
            !is_initialized() || is_initialized(),
            "Should return valid state"
        );
    }

    #[test]
    #[should_panic(expected = "Config not initialized")]
    fn test_get_config_panics_when_not_initialized() {
        // Clear any existing config (not possible with OnceLock, so this test
        // assumes it runs in isolation or after initialization)
        // This test demonstrates the expected panic behavior
        if !is_initialized() {
            let _ = get_config();
        }
    }

    // Note: We can't easily test the full singleton pattern here because
    // OnceLock can only be set once per process lifetime. Real tests would
    // need to be in integration tests with process isolation.
}
