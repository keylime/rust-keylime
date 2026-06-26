// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Local diagnostic information (no network calls).
//!
//! Shows effective configuration, version, features, config file
//! search results, and per-field source annotations.

use serde_json::{json, Value};

use crate::config;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;

/// Execute the `info` command (no subcommand).
pub fn execute(_output: &OutputHandler) -> Result<Value, KeylimectlError> {
    let config = config::singleton::get_config();

    let version_info = build_version_info();
    let config_files = build_config_file_info(config);
    let effective_config = build_effective_config(config);
    let env_vars = scan_keylime_env_vars();

    Ok(json!({
        "keylimectl": version_info,
        "config_files": config_files,
        "effective_config": effective_config,
        "environment_variables": env_vars,
    }))
}

/// Build version and feature information.
fn build_version_info() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "features": {
            "api-v2": cfg!(feature = "api-v2"),
            "api-v3": cfg!(feature = "api-v3"),
            "wizard": cfg!(feature = "wizard"),
            "tpm-quote-validation": cfg!(feature = "tpm-quote-validation"),
        },
    })
}

/// Build config file search information.
fn build_config_file_info(config: &config::Config) -> Value {
    let search_paths = config::Config::config_search_paths();
    let searched: Vec<Value> = search_paths
        .iter()
        .map(|p| {
            json!({
                "path": p.display().to_string(),
                "exists": p.exists(),
            })
        })
        .collect();

    json!({
        "loaded_from": config.loaded_from.as_ref()
            .map(|p| p.display().to_string()),
        "searched": searched,
    })
}

/// Build the effective configuration with per-field source annotations.
fn build_effective_config(config: &config::Config) -> Value {
    let defaults = config::Config::default();
    let overrides = &config.cli_overrides;

    json!({
        "verifier": {
            "ip": {
                "value": config.verifier.ip,
                "source": determine_source_str(
                    &config.verifier.ip,
                    &defaults.verifier.ip,
                    overrides.verifier_ip,
                    "KEYLIME_VERIFIER__IP",
                ),
            },
            "port": {
                "value": config.verifier.port,
                "source": determine_source_u16(
                    config.verifier.port,
                    defaults.verifier.port,
                    overrides.verifier_port,
                    "KEYLIME_VERIFIER__PORT",
                ),
            },
            "id": config.verifier.id,
        },
        "registrar": {
            "ip": {
                "value": config.registrar.ip,
                "source": determine_source_str(
                    &config.registrar.ip,
                    &defaults.registrar.ip,
                    overrides.registrar_ip,
                    "KEYLIME_REGISTRAR__IP",
                ),
            },
            "port": {
                "value": config.registrar.port,
                "source": determine_source_u16(
                    config.registrar.port,
                    defaults.registrar.port,
                    overrides.registrar_port,
                    "KEYLIME_REGISTRAR__PORT",
                ),
            },
        },
        "tls": {
            "verify_server_cert": config.tls.verify_server_cert,
            "enable_agent_mtls": config.tls.enable_agent_mtls,
            "client_cert": config.tls.client_cert,
            "client_key": config.tls.client_key,
            "trusted_ca": config.tls.trusted_ca,
        },
        "client": {
            "timeout": {
                "value": config.client.timeout,
                "source": determine_source_u64(
                    config.client.timeout,
                    defaults.client.timeout,
                    overrides.timeout,
                    "KEYLIME_CLIENT__TIMEOUT",
                ),
            },
            "retry_interval": config.client.retry_interval,
            "max_retries": config.client.max_retries,
            "exponential_backoff": config.client.exponential_backoff,
        },
    })
}

/// Determine the source of a string config field.
///
/// Priority: CLI > env var > config file / default.
fn determine_source_str(
    current: &str,
    default: &str,
    cli_override: bool,
    env_var_name: &str,
) -> &'static str {
    if cli_override {
        return "cli";
    }
    if std::env::var(env_var_name).is_ok() {
        return "env_var";
    }
    if current != default {
        return "config_file";
    }
    "default"
}

/// Determine the source of a u16 config field.
fn determine_source_u16(
    current: u16,
    default: u16,
    cli_override: bool,
    env_var_name: &str,
) -> &'static str {
    if cli_override {
        return "cli";
    }
    if std::env::var(env_var_name).is_ok() {
        return "env_var";
    }
    if current != default {
        return "config_file";
    }
    "default"
}

/// Determine the source of a u64 config field.
fn determine_source_u64(
    current: u64,
    default: u64,
    cli_override: bool,
    env_var_name: &str,
) -> &'static str {
    if cli_override {
        return "cli";
    }
    if std::env::var(env_var_name).is_ok() {
        return "env_var";
    }
    if current != default {
        return "config_file";
    }
    "default"
}

/// Scan for KEYLIME_ environment variables.
fn scan_keylime_env_vars() -> Value {
    let mut vars = serde_json::Map::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("KEYLIME_") {
            let _ = vars.insert(key, Value::String(value));
        }
    }
    Value::Object(vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliOverrides;

    #[test]
    fn test_build_version_info() {
        let info = build_version_info();
        assert!(info["version"].is_string());
        assert!(info["features"]["api-v2"].is_boolean());
        assert!(info["features"]["api-v3"].is_boolean());
        assert!(info["features"]["wizard"].is_boolean());
        assert!(info["features"]["tpm-quote-validation"].is_boolean());
    }

    #[test]
    fn test_build_config_file_info_defaults() {
        let config = config::Config::default();
        let info = build_config_file_info(&config);
        assert!(info["loaded_from"].is_null());
        assert!(info["searched"].is_array());
        let searched = info["searched"].as_array().unwrap(); //#[allow_ci]
        assert!(!searched.is_empty());
        // Each entry should have path and exists
        for entry in searched {
            assert!(entry["path"].is_string());
            assert!(entry["exists"].is_boolean());
        }
    }

    #[test]
    fn test_determine_source_cli() {
        assert_eq!(
            determine_source_str(
                "10.0.0.1",
                "127.0.0.1",
                true,
                "KEYLIME_VERIFIER__IP"
            ),
            "cli"
        );
    }

    #[test]
    fn test_determine_source_default() {
        assert_eq!(
            determine_source_str(
                "127.0.0.1",
                "127.0.0.1",
                false,
                // Use an unlikely-to-exist env var name
                "KEYLIME_TEST_NONEXISTENT_VAR_12345"
            ),
            "default"
        );
    }

    #[test]
    fn test_determine_source_config_file() {
        assert_eq!(
            determine_source_str(
                "10.0.0.1",
                "127.0.0.1",
                false,
                "KEYLIME_TEST_NONEXISTENT_VAR_12345"
            ),
            "config_file"
        );
    }

    #[test]
    fn test_determine_source_u16_cli() {
        assert_eq!(
            determine_source_u16(
                9001,
                8881,
                true,
                "KEYLIME_TEST_NONEXISTENT_VAR_12345"
            ),
            "cli"
        );
    }

    #[test]
    fn test_determine_source_u16_default() {
        assert_eq!(
            determine_source_u16(
                8881,
                8881,
                false,
                "KEYLIME_TEST_NONEXISTENT_VAR_12345"
            ),
            "default"
        );
    }

    #[test]
    fn test_determine_source_u64_config_file() {
        assert_eq!(
            determine_source_u64(
                120,
                60,
                false,
                "KEYLIME_TEST_NONEXISTENT_VAR_12345"
            ),
            "config_file"
        );
    }

    #[test]
    fn test_scan_keylime_env_vars() {
        let vars = scan_keylime_env_vars();
        assert!(vars.is_object());
        // All keys should start with KEYLIME_
        if let Value::Object(map) = vars {
            for key in map.keys() {
                assert!(key.starts_with("KEYLIME_"));
            }
        }
    }

    #[test]
    fn test_build_effective_config() {
        let config = config::Config {
            cli_overrides: CliOverrides {
                verifier_ip: true,
                ..CliOverrides::default()
            },
            ..config::Config::default()
        };
        let effective = build_effective_config(&config);

        // verifier_ip should report "cli" source since we set the override
        assert_eq!(effective["verifier"]["ip"]["source"], "cli");
        // verifier_port should be "default" (no override, default value)
        assert_eq!(effective["verifier"]["port"]["source"], "default");
    }
}
