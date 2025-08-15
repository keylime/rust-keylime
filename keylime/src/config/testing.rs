// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Testing utilities for configuration management
//!
//! This module provides utilities for creating and managing test configurations,
//! including the ability to override configuration values during test execution.

use crate::config::{base::config_translate_keywords, AgentConfig};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, OnceLock},
};

// Global storage for testing configuration override
pub(crate) static TESTING_CONFIG_OVERRIDE: OnceLock<
    Mutex<Option<AgentConfig>>,
> = OnceLock::new();

/// Create a configuration based on a temporary directory
///
/// # Arguments
///
/// * `tempdir`: Path to be used as the keylime directory in the generated configuration
/// * `overrides`: HashMap of configuration option names to values to override in the configuration
///
/// # Returns
///
/// A `AgentConfig` structure using the given path as the `keylime_dir` option and any provided overrides
pub fn get_testing_config(
    tempdir: &Path,
    overrides: Option<HashMap<String, String>>,
) -> AgentConfig {
    let mut config = AgentConfig {
        keylime_dir: tempdir.display().to_string(),
        ..AgentConfig::default()
    };

    // Apply any overrides if provided
    if let Some(overrides) = overrides {
        apply_config_overrides(&mut config, overrides);
    }

    // It is expected that the translation of keywords will not fail
    config_translate_keywords(&config).expect("failed to translate keywords")
}

/// Apply configuration overrides to an AgentConfig instance
///
/// # Arguments
///
/// * `config`: Mutable reference to the AgentConfig to modify
/// * `overrides`: HashMap of configuration option names to values to override
fn apply_config_overrides(
    config: &mut AgentConfig,
    overrides: HashMap<String, String>,
) {
    use crate::config::{
        DEFAULT_CONTACT_PORT, DEFAULT_PORT, DEFAULT_REGISTRAR_PORT,
        DEFAULT_REVOCATION_NOTIFICATION_PORT,
    };

    for (key, value) in overrides {
        match key.as_str() {
            "measuredboot_ml_path" => config.measuredboot_ml_path = value,
            "ima_ml_path" => config.ima_ml_path = value,
            "agent_data_path" => config.agent_data_path = value,
            "api_versions" => config.api_versions = value,
            "disabled_signing_algorithms" => {
                // Parse as comma-separated list
                config.disabled_signing_algorithms =
                    value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "ek_handle" => config.ek_handle = value,
            "exponential_backoff_max_delay" => {
                config.exponential_backoff_max_delay = value.parse().ok();
            }
            "exponential_backoff_max_retries" => {
                config.exponential_backoff_max_retries = value.parse().ok();
            }
            "exponential_backoff_initial_delay" => {
                config.exponential_backoff_initial_delay = value.parse().ok();
            }
            "enable_iak_idevid" => {
                config.enable_iak_idevid = value.parse().unwrap_or(false);
            }
            "iak_cert" => config.iak_cert = value,
            "iak_handle" => config.iak_handle = value,
            "iak_idevid_asymmetric_alg" => {
                config.iak_idevid_asymmetric_alg = value
            }
            "iak_idevid_name_alg" => config.iak_idevid_name_alg = value,
            "iak_idevid_template" => config.iak_idevid_template = value,
            "iak_password" => config.iak_password = value,
            "idevid_cert" => config.idevid_cert = value,
            "idevid_handle" => config.idevid_handle = value,
            "idevid_password" => config.idevid_password = value,
            "ip" => config.ip = value,
            "port" => {
                config.port = value.parse().unwrap_or(DEFAULT_PORT);
            }
            "registrar_ip" => config.registrar_ip = value,
            "registrar_port" => {
                config.registrar_port =
                    value.parse().unwrap_or(DEFAULT_REGISTRAR_PORT);
            }
            "run_as" => config.run_as = value,
            "tpm_encryption_alg" => config.tpm_encryption_alg = value,
            "tpm_hash_alg" => config.tpm_hash_alg = value,
            "tpm_ownerpassword" => config.tpm_ownerpassword = value,
            "tpm_signing_alg" => config.tpm_signing_alg = value,
            "trusted_client_ca" => config.trusted_client_ca = value,
            "uuid" => config.uuid = value,
            "version" => config.version = value,
            // Pull attestation options
            "allow_payload_revocation_actions" => {
                config.allow_payload_revocation_actions =
                    value.parse().unwrap_or(false);
            }
            "contact_ip" => config.contact_ip = value,
            "contact_port" => {
                config.contact_port =
                    value.parse().unwrap_or(DEFAULT_CONTACT_PORT);
            }
            "dec_payload_file" => config.dec_payload_file = value,
            "enable_agent_mtls" => {
                config.enable_agent_mtls = value.parse().unwrap_or(true);
            }
            "enable_insecure_payload" => {
                config.enable_insecure_payload =
                    value.parse().unwrap_or(false);
            }
            "enable_revocation_notifications" => {
                config.enable_revocation_notifications =
                    value.parse().unwrap_or(false);
            }
            "enc_keyname" => config.enc_keyname = value,
            "extract_payload_zip" => {
                config.extract_payload_zip = value.parse().unwrap_or(true);
            }
            "payload_script" => config.payload_script = value,
            "revocation_actions" => config.revocation_actions = value,
            "revocation_actions_dir" => config.revocation_actions_dir = value,
            "revocation_cert" => config.revocation_cert = value,
            "revocation_notification_ip" => {
                config.revocation_notification_ip = value
            }
            "revocation_notification_port" => {
                config.revocation_notification_port = value
                    .parse()
                    .unwrap_or(DEFAULT_REVOCATION_NOTIFICATION_PORT);
            }
            "secure_size" => config.secure_size = value,
            "server_cert" => config.server_cert = value,
            "server_key" => config.server_key = value,
            "server_key_password" => config.server_key_password = value,
            // Push attestation options
            "certification_keys_server_identifier" => {
                config.certification_keys_server_identifier = value
            }
            "ima_ml_count_file" => config.ima_ml_count_file = value,
            "registrar_api_versions" => config.registrar_api_versions = value,
            "uefi_logs_evidence_version" => {
                config.uefi_logs_evidence_version = value
            }
            "verifier_url" => config.verifier_url = value,
            _ => {
                log::warn!("Unknown configuration override key: {key}");
            }
        }
    }
}

/// Set a testing configuration override that will be returned by AgentConfig::new()
/// during test execution. This allows tests to override specific configuration values
/// without affecting the actual configuration files.
///
/// # Arguments
///
/// * `config`: The configuration to use as override during testing
pub fn set_testing_config_override(config: AgentConfig) {
    let mutex = TESTING_CONFIG_OVERRIDE.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = mutex.lock() {
        *guard = Some(config);
    }
}

/// Clear the testing configuration override, restoring normal configuration loading behavior
pub fn clear_testing_config_override() {
    let mutex = TESTING_CONFIG_OVERRIDE.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = mutex.lock() {
        *guard = None;
    }
}

/// Check if there is a testing configuration override and return it if available
///
/// This function is called from AgentConfig::new() to check if there's a testing
/// configuration that should be used instead of loading from files.
///
/// # Returns
///
/// * `Some(AgentConfig)` if a testing override is set
/// * `None` if no testing override is active
pub fn get_testing_config_override() -> Option<AgentConfig> {
    let mutex = TESTING_CONFIG_OVERRIDE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = mutex.lock() {
        guard.clone()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_get_testing_config() {
        let dir = tempfile::tempdir()
            .expect("failed to create temporary directory");

        // Get the config and check that the value is correct
        let config = get_testing_config(dir.path(), None);
        assert_eq!(config.keylime_dir, dir.path().display().to_string());
    }

    #[test]
    fn test_get_testing_config_with_overrides() {
        let dir = tempfile::tempdir()
            .expect("failed to create temporary directory");

        let mut overrides = HashMap::new();
        overrides.insert("ip".to_string(), "192.168.1.100".to_string());
        overrides.insert("port".to_string(), "9999".to_string());
        overrides
            .insert("ima_ml_path".to_string(), "/custom/path".to_string());

        let config = get_testing_config(dir.path(), Some(overrides));

        assert_eq!(config.keylime_dir, dir.path().display().to_string());
        assert_eq!(config.ip, "192.168.1.100");
        assert_eq!(config.port, 9999);
        assert_eq!(config.ima_ml_path, "/custom/path");
    }

    #[test]
    fn test_testing_config_override() {
        // Clear any existing override
        clear_testing_config_override();

        // Verify no override is set
        assert!(get_testing_config_override().is_none());

        // Set an override
        let test_config = AgentConfig {
            ip: "test.example.com".to_string(),
            port: 12345,
            ..AgentConfig::default()
        };
        set_testing_config_override(test_config.clone());

        // Verify override is returned
        let retrieved = get_testing_config_override();
        assert!(retrieved.is_some());
        let retrieved_config = retrieved.expect("failed to retrieve config");
        assert_eq!(retrieved_config.ip, "test.example.com");
        assert_eq!(retrieved_config.port, 12345);

        // Clear override
        clear_testing_config_override();
        assert!(get_testing_config_override().is_none());
    }

    #[test]
    fn test_apply_config_overrides() {
        let mut config = AgentConfig::default();
        let mut overrides = HashMap::new();

        overrides.insert("ip".to_string(), "192.168.1.1".to_string());
        overrides.insert("enable_iak_idevid".to_string(), "true".to_string());
        overrides.insert(
            "disabled_signing_algorithms".to_string(),
            "rsa,ecdsa".to_string(),
        );

        apply_config_overrides(&mut config, overrides);

        assert_eq!(config.ip, "192.168.1.1");
        assert!(config.enable_iak_idevid);
        assert_eq!(config.disabled_signing_algorithms, vec!["rsa", "ecdsa"]);
    }
}
