// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Configuration wizard for keylimectl
//!
//! Provides both interactive and non-interactive modes for creating
//! or updating keylimectl configuration files.

use log::{debug, info};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{CliOverrides, Config, RegistrarConfig, VerifierConfig};
#[cfg(feature = "wizard")]
use crate::config::{ClientConfig, TlsConfig};
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::ConfigScope;

/// Parameters for the configure command, extracted from CLI args.
#[derive(Debug)]
pub struct ConfigureParams<'a> {
    /// Run without interactive prompts
    pub non_interactive: bool,
    /// Configuration scope
    pub scope: &'a ConfigScope,
    /// Verifier IP for non-interactive mode
    pub verifier_ip: Option<&'a str>,
    /// Verifier port for non-interactive mode
    pub verifier_port: Option<u16>,
    /// Registrar IP for non-interactive mode
    pub registrar_ip: Option<&'a str>,
    /// Registrar port for non-interactive mode
    pub registrar_port: Option<u16>,
    /// Test connectivity after configuration
    pub test_connectivity: bool,
}

/// Execute the configure command.
pub async fn execute(
    params: &ConfigureParams<'_>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let config_path = resolve_config_path(params.scope)?;

    let config = if params.non_interactive {
        build_non_interactive_config(
            params.verifier_ip,
            params.verifier_port,
            params.registrar_ip,
            params.registrar_port,
        )
    } else {
        #[cfg(feature = "wizard")]
        {
            run_interactive_wizard(
                params.scope,
                &config_path,
                params.verifier_ip,
                params.verifier_port,
                params.registrar_ip,
                params.registrar_port,
            )?
        }
        #[cfg(not(feature = "wizard"))]
        {
            output.info(
                "Interactive mode requires the 'wizard' feature. \
                 Use --non-interactive or rebuild with --features wizard.",
            );
            return Err(KeylimectlError::Validation(
                "Interactive mode requires the 'wizard' feature".into(),
            ));
        }
    };

    if params.test_connectivity {
        info!("Connectivity testing is not yet implemented");
    }

    write_config_file(&config_path, &config)?;

    let result = json!({
        "status": "success",
        "config_path": config_path.display().to_string(),
        "verifier": {
            "ip": config.verifier.ip,
            "port": config.verifier.port,
        },
        "registrar": {
            "ip": config.registrar.ip,
            "port": config.registrar.port,
        },
    });

    output.info(format!(
        "Configuration written to {}",
        config_path.display()
    ));

    Ok(result)
}

/// Build a configuration from CLI-provided values, using defaults for
/// anything not specified.
fn build_non_interactive_config(
    verifier_ip: Option<&str>,
    verifier_port: Option<u16>,
    registrar_ip: Option<&str>,
    registrar_port: Option<u16>,
) -> Config {
    let defaults = Config::default();

    Config {
        loaded_from: None,
        cli_overrides: CliOverrides::default(),
        verifier: VerifierConfig {
            ip: verifier_ip.unwrap_or(&defaults.verifier.ip).to_string(),
            port: verifier_port.unwrap_or(defaults.verifier.port),
            id: defaults.verifier.id,
        },
        registrar: RegistrarConfig {
            ip: registrar_ip.unwrap_or(&defaults.registrar.ip).to_string(),
            port: registrar_port.unwrap_or(defaults.registrar.port),
        },
        tls: defaults.tls,
        client: defaults.client,
    }
}

/// Resolve the configuration file path based on the scope.
fn resolve_config_path(
    scope: &ConfigScope,
) -> Result<PathBuf, KeylimectlError> {
    match scope {
        ConfigScope::Local => Ok(PathBuf::from(".keylimectl/config.toml")),
        ConfigScope::User => {
            let home = dirs_path_home()?;
            Ok(home.join(".config").join("keylimectl").join("config.toml"))
        }
        ConfigScope::System => {
            Ok(PathBuf::from("/etc/keylime/keylimectl.conf"))
        }
    }
}

/// Get the user's home directory.
fn dirs_path_home() -> Result<PathBuf, KeylimectlError> {
    std::env::var("HOME").map(PathBuf::from).map_err(|_| {
        KeylimectlError::Validation(
            "Could not determine home directory".into(),
        )
    })
}

/// Write a configuration to a TOML file, creating parent directories
/// as needed.
fn write_config_file(
    path: &Path,
    config: &Config,
) -> Result<(), KeylimectlError> {
    // Create parent directories
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                KeylimectlError::Validation(format!(
                    "Failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }

    let toml_str = toml::to_string_pretty(config).map_err(|e| {
        KeylimectlError::Validation(format!(
            "Failed to serialize configuration: {e}"
        ))
    })?;

    debug!("Writing configuration to {}", path.display());
    fs::write(path, toml_str).map_err(|e| {
        KeylimectlError::Validation(format!(
            "Failed to write configuration to {}: {e}",
            path.display()
        ))
    })?;

    Ok(())
}

/// Run the interactive configuration wizard (requires `wizard` feature).
#[cfg(feature = "wizard")]
fn run_interactive_wizard(
    scope: &ConfigScope,
    config_path: &Path,
    default_verifier_ip: Option<&str>,
    default_verifier_port: Option<u16>,
    default_registrar_ip: Option<&str>,
    default_registrar_port: Option<u16>,
) -> Result<Config, KeylimectlError> {
    use dialoguer::{Confirm, Input};

    eprintln!("keylimectl Configuration Wizard");
    eprintln!("===============================");
    eprintln!();

    // Show where config will be written
    eprintln!("Scope:  {:?} ({})", scope, config_path.display());
    eprintln!();

    // Check for existing file
    if config_path.exists() {
        eprintln!(
            "A configuration file already exists at {}",
            config_path.display()
        );
        let overwrite = Confirm::new()
            .with_prompt("Overwrite existing configuration?")
            .default(false)
            .interact()
            .map_err(|e| {
                KeylimectlError::Validation(format!(
                    "Failed to read user input: {e}"
                ))
            })?;

        if !overwrite {
            return Err(KeylimectlError::Validation(
                "Configuration cancelled by user".into(),
            ));
        }
        eprintln!();
    }

    let defaults = Config::default();

    // Step 1: Verifier configuration
    eprintln!("Step 1: Verifier Configuration");
    eprintln!("------------------------------");

    let verifier_ip: String = Input::new()
        .with_prompt("Verifier IP address")
        .default(
            default_verifier_ip
                .unwrap_or(&defaults.verifier.ip)
                .to_string(),
        )
        .interact_text()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    let verifier_port: u16 = Input::new()
        .with_prompt("Verifier port")
        .default(default_verifier_port.unwrap_or(defaults.verifier.port))
        .interact_text()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    eprintln!();

    // Step 2: Registrar configuration
    eprintln!("Step 2: Registrar Configuration");
    eprintln!("-------------------------------");

    let registrar_ip: String = Input::new()
        .with_prompt("Registrar IP address")
        .default(
            default_registrar_ip
                .unwrap_or(&defaults.registrar.ip)
                .to_string(),
        )
        .interact_text()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    let registrar_port: u16 = Input::new()
        .with_prompt("Registrar port")
        .default(default_registrar_port.unwrap_or(defaults.registrar.port))
        .interact_text()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    eprintln!();

    // Step 3: TLS configuration
    eprintln!("Step 3: TLS Configuration");
    eprintln!("-------------------------");

    let verify_server_cert = Confirm::new()
        .with_prompt("Verify server certificates?")
        .default(defaults.tls.verify_server_cert)
        .interact()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    let enable_mtls = Confirm::new()
        .with_prompt("Enable mutual TLS (mTLS)?")
        .default(defaults.tls.client_cert.is_some())
        .interact()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    let (client_cert, client_key) = if enable_mtls {
        let cert: String = Input::new()
            .with_prompt("Client certificate path")
            .default(defaults.tls.client_cert.unwrap_or_default())
            .interact_text()
            .map_err(|e| {
                KeylimectlError::Validation(format!(
                    "Failed to read user input: {e}"
                ))
            })?;

        let key: String = Input::new()
            .with_prompt("Client key path")
            .default(defaults.tls.client_key.unwrap_or_default())
            .interact_text()
            .map_err(|e| {
                KeylimectlError::Validation(format!(
                    "Failed to read user input: {e}"
                ))
            })?;

        (Some(cert), Some(key))
    } else {
        (None, None)
    };

    eprintln!();

    // Step 4: Client settings
    eprintln!("Step 4: Client Settings");
    eprintln!("-----------------------");

    let timeout: u64 = Input::new()
        .with_prompt("Request timeout (seconds)")
        .default(defaults.client.timeout)
        .interact_text()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    eprintln!();

    let config = Config {
        loaded_from: None,
        cli_overrides: CliOverrides::default(),
        verifier: VerifierConfig {
            ip: verifier_ip,
            port: verifier_port,
            id: None,
        },
        registrar: RegistrarConfig {
            ip: registrar_ip,
            port: registrar_port,
        },
        tls: TlsConfig {
            client_cert,
            client_key,
            verify_server_cert,
            ..defaults.tls
        },
        client: ClientConfig {
            timeout,
            ..defaults.client
        },
    };

    // Show summary
    eprintln!("Configuration Summary");
    eprintln!("=====================");
    eprintln!("Verifier:  {}:{}", config.verifier.ip, config.verifier.port);
    eprintln!(
        "Registrar: {}:{}",
        config.registrar.ip, config.registrar.port
    );
    eprintln!(
        "TLS:       verify_server_cert={}, mTLS={}",
        config.tls.verify_server_cert,
        config.tls.client_cert.is_some()
    );
    eprintln!("Timeout:   {}s", config.client.timeout);
    eprintln!();

    let confirm = Confirm::new()
        .with_prompt("Write this configuration?")
        .default(true)
        .interact()
        .map_err(|e| {
            KeylimectlError::Validation(format!(
                "Failed to read user input: {e}"
            ))
        })?;

    if !confirm {
        return Err(KeylimectlError::Validation(
            "Configuration cancelled by user".into(),
        ));
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_non_interactive_config_defaults() {
        let config = build_non_interactive_config(None, None, None, None);

        assert_eq!(config.verifier.ip, "127.0.0.1");
        assert_eq!(config.verifier.port, 8881);
        assert_eq!(config.registrar.ip, "127.0.0.1");
        assert_eq!(config.registrar.port, 8891);
        assert_eq!(config.client.timeout, 60);
    }

    #[test]
    fn test_build_non_interactive_config_with_overrides() {
        let config = build_non_interactive_config(
            Some("10.0.0.1"),
            Some(9001),
            Some("10.0.0.2"),
            Some(9002),
        );

        assert_eq!(config.verifier.ip, "10.0.0.1");
        assert_eq!(config.verifier.port, 9001);
        assert_eq!(config.registrar.ip, "10.0.0.2");
        assert_eq!(config.registrar.port, 9002);
    }

    #[test]
    fn test_build_non_interactive_config_partial_overrides() {
        let config = build_non_interactive_config(
            Some("192.168.1.1"),
            None,
            None,
            Some(9999),
        );

        assert_eq!(config.verifier.ip, "192.168.1.1");
        assert_eq!(config.verifier.port, 8881); // default
        assert_eq!(config.registrar.ip, "127.0.0.1"); // default
        assert_eq!(config.registrar.port, 9999);
    }

    #[test]
    fn test_resolve_config_path_local() {
        let path = resolve_config_path(&ConfigScope::Local).unwrap(); //#[allow_ci]
        assert_eq!(path, PathBuf::from(".keylimectl/config.toml"));
    }

    #[test]
    fn test_resolve_config_path_user() {
        let path = resolve_config_path(&ConfigScope::User).unwrap(); //#[allow_ci]
        let expected = PathBuf::from(std::env::var("HOME").unwrap()) //#[allow_ci]
            .join(".config")
            .join("keylimectl")
            .join("config.toml");
        assert_eq!(path, expected);
    }

    #[test]
    fn test_resolve_config_path_system() {
        let path = resolve_config_path(&ConfigScope::System).unwrap(); //#[allow_ci]
        assert_eq!(path, PathBuf::from("/etc/keylime/keylimectl.conf"));
    }

    #[test]
    fn test_write_config_file_creates_dirs_and_file() {
        let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let config_path = tmpdir
            .path()
            .join("subdir")
            .join("nested")
            .join("config.toml");

        let config = Config::default();
        write_config_file(&config_path, &config).unwrap(); //#[allow_ci]

        assert!(config_path.exists());

        // Verify the written TOML is valid and round-trips
        let contents = fs::read_to_string(&config_path).unwrap(); //#[allow_ci]
        let parsed: Config = toml::from_str(&contents).unwrap(); //#[allow_ci]
        assert_eq!(parsed.verifier.ip, config.verifier.ip);
        assert_eq!(parsed.verifier.port, config.verifier.port);
        assert_eq!(parsed.registrar.ip, config.registrar.ip);
        assert_eq!(parsed.registrar.port, config.registrar.port);
        assert_eq!(parsed.client.timeout, config.client.timeout);
    }

    #[test]
    fn test_write_config_file_overwrites_existing() {
        let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let config_path = tmpdir.path().join("config.toml");

        // Write first config
        let config1 = Config::default();
        write_config_file(&config_path, &config1).unwrap(); //#[allow_ci]

        // Write second config with different values
        let config2 = build_non_interactive_config(
            Some("10.0.0.1"),
            Some(9001),
            None,
            None,
        );
        write_config_file(&config_path, &config2).unwrap(); //#[allow_ci]

        // Verify the second config was written
        let contents = fs::read_to_string(&config_path).unwrap(); //#[allow_ci]
        let parsed: Config = toml::from_str(&contents).unwrap(); //#[allow_ci]
        assert_eq!(parsed.verifier.ip, "10.0.0.1");
        assert_eq!(parsed.verifier.port, 9001);
    }

    #[test]
    fn test_generated_toml_roundtrips() {
        let config = build_non_interactive_config(
            Some("::1"),
            Some(8881),
            Some("192.168.1.100"),
            Some(8891),
        );

        let toml_str = toml::to_string_pretty(&config).unwrap(); //#[allow_ci]
        let parsed: Config = toml::from_str(&toml_str).unwrap(); //#[allow_ci]

        assert_eq!(parsed.verifier.ip, "::1");
        assert_eq!(parsed.verifier.port, 8881);
        assert_eq!(parsed.registrar.ip, "192.168.1.100");
        assert_eq!(parsed.registrar.port, 8891);
    }
}
