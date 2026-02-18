// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Configuration management for keylimectl
//!
//! This module provides comprehensive configuration management for the keylimectl CLI tool.
//! It supports multiple configuration sources with a clear precedence order:
//!
//! 1. Command-line arguments (highest priority)
//! 2. Environment variables (prefixed with `KEYLIME_`)
//! 3. Configuration files (TOML format)
//! 4. Default values (lowest priority)
//!
//! # Configuration Sources
//!
//! ## Configuration Files (Optional)
//! Configuration files are completely optional. The system searches for TOML files in the following order:
//! - Explicit path provided via CLI argument `--config` (required to exist if specified)
//! - `.keylimectl/config.toml` (project-local)
//! - `keylimectl.toml` (current directory)
//! - `keylimectl.conf` (current directory)
//! - `~/.config/keylimectl/config.toml` (user, canonical)
//! - `$XDG_CONFIG_HOME/keylimectl/config.toml` (XDG override)
//! - `/etc/keylime/keylimectl.conf` (system-wide)
//! - `/usr/etc/keylime/keylimectl.conf` (alternative system-wide)
//! - Legacy paths: `~/.config/keylime/keylimectl.conf`, `~/.keylimectl.toml`
//!
//! If no configuration files are found, keylimectl will work perfectly with defaults and environment variables.
//!
//! ## Environment Variables
//! Environment variables use the prefix `KEYLIME_` with double underscores as separators:
//! - `KEYLIME_VERIFIER__IP=192.168.1.100`
//! - `KEYLIME_VERIFIER__PORT=8881`
//! - `KEYLIME_TLS__VERIFY_SERVER_CERT=false`
//!
//! ## Example Configuration File
//!
//! ```toml
//! [verifier]
//! ip = "127.0.0.1"
//! port = 8881
//! id = "verifier-1"
//!
//! [registrar]
//! ip = "127.0.0.1"
//! port = 8891
//!
//! [tls]
//! client_cert = "/path/to/client.crt"
//! client_key = "/path/to/client.key"
//! verify_server_cert = true
//! enable_agent_mtls = true
//!
//! [client]
//! timeout = 60
//! max_retries = 3
//! exponential_backoff = true
//! ```
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::config::Config;
//! use keylimectl::Cli;
//!
//! // Load default configuration
//! let config = Config::default();
//!
//! // Load from files and environment
//! let config = Config::load(None).expect("Failed to load config");
//!
//! // Apply CLI overrides
//! let cli = Cli::default();
//! let config = config.with_cli_overrides(&cli);
//!
//! // Validate configuration
//! config.validate().expect("Invalid configuration");
//!
//! // Get service URLs
//! let verifier_url = config.verifier_base_url();
//! let registrar_url = config.registrar_base_url();
//! ```

use crate::Cli;
use config::{ConfigError, Environment, File, FileFormat};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Records which configuration fields were overridden by CLI arguments.
///
/// This is used by the `info` command to annotate each config field with
/// its source (CLI, env var, config file, or default).
#[derive(Default, Debug, Clone)]
pub struct CliOverrides {
    /// Whether `--verifier-ip` was provided
    pub verifier_ip: bool,
    /// Whether `--verifier-port` was provided
    pub verifier_port: bool,
    /// Whether `--registrar-ip` was provided
    pub registrar_ip: bool,
    /// Whether `--registrar-port` was provided
    pub registrar_port: bool,
    /// Whether `--timeout` was provided
    pub timeout: bool,
}

/// Main configuration structure for keylimectl
///
/// This structure contains all configuration settings needed for keylimectl operations,
/// including service endpoints, TLS settings, and client behavior configuration.
///
/// # Fields
///
/// - `verifier`: Configuration for connecting to the Keylime verifier service
/// - `registrar`: Configuration for connecting to the Keylime registrar service
/// - `tls`: TLS/SSL security configuration
/// - `client`: HTTP client behavior and retry configuration
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path of the configuration file that was loaded, if any
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,
    /// Records which fields were overridden by CLI arguments
    #[serde(skip)]
    pub cli_overrides: CliOverrides,
    /// Verifier configuration
    pub verifier: VerifierConfig,
    /// Registrar configuration
    pub registrar: RegistrarConfig,
    /// TLS configuration
    pub tls: TlsConfig,
    /// Client configuration
    pub client: ClientConfig,
}

/// Configuration for the Keylime verifier service
///
/// The verifier continuously monitors agent integrity and manages attestation policies.
/// This configuration specifies how to connect to the verifier service.
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::VerifierConfig;
///
/// let config = VerifierConfig {
///     ip: "192.168.1.100".to_string(),
///     port: 8881,
///     id: Some("verifier-1".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    /// Verifier IP address
    pub ip: String,
    /// Verifier port
    pub port: u16,
    /// Verifier ID (optional)
    pub id: Option<String>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            ip: "127.0.0.1".to_string(),
            port: 8881,
            id: None,
        }
    }
}

/// Configuration for the Keylime registrar service
///
/// The registrar maintains a database of registered agents and their TPM public keys.
/// This configuration specifies how to connect to the registrar service.
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::RegistrarConfig;
///
/// let config = RegistrarConfig {
///     ip: "127.0.0.1".to_string(),
///     port: 8891,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrarConfig {
    /// Registrar IP address
    pub ip: String,
    /// Registrar port
    pub port: u16,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            ip: "127.0.0.1".to_string(),
            port: 8891,
        }
    }
}

/// TLS/SSL security configuration
///
/// This configuration controls how keylimectl establishes secure connections
/// to Keylime services, including client certificates and server verification.
///
/// # Security Notes
///
/// - `verify_server_cert` should only be disabled for testing
/// - Client certificates are required for mutual TLS authentication
/// - Trusted CA certificates ensure server identity verification
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::TlsConfig;
///
/// let config = TlsConfig {
///     client_cert: Some("/path/to/client.crt".to_string()),
///     client_key: Some("/path/to/client.key".to_string()),
///     client_key_password: None,
///     trusted_ca: vec!["/path/to/ca.crt".to_string()],
///     verify_server_cert: true,
///     enable_agent_mtls: true,
///     accept_invalid_hostnames: true,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Client certificate file path
    pub client_cert: Option<String>,
    /// Client private key file path
    pub client_key: Option<String>,
    /// Client key password
    pub client_key_password: Option<String>,
    /// Trusted CA certificates
    #[serde(default)]
    pub trusted_ca: Vec<String>,
    /// Verify server certificates
    pub verify_server_cert: bool,
    /// Enable agent mTLS
    pub enable_agent_mtls: bool,
    /// Accept invalid hostnames in server certificates
    ///
    /// Keylime auto-generated certificates may not include the correct
    /// hostname/IP in the SAN extension. Set to `true` to skip hostname
    /// verification (default). Set to `false` for stricter security when
    /// using properly issued certificates.
    #[serde(default = "default_accept_invalid_hostnames")]
    pub accept_invalid_hostnames: bool,
}

fn default_accept_invalid_hostnames() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            client_cert: Some(
                "/var/lib/keylime/cv_ca/client-cert.crt".to_string(),
            ),
            client_key: Some(
                "/var/lib/keylime/cv_ca/client-private.pem".to_string(),
            ),
            client_key_password: None,
            trusted_ca: vec!["/var/lib/keylime/cv_ca/cacert.crt".to_string()],
            verify_server_cert: true,
            enable_agent_mtls: true,
            accept_invalid_hostnames: true,
        }
    }
}

/// HTTP client behavior and retry configuration
///
/// This configuration controls how the HTTP client behaves when making requests
/// to Keylime services, including timeouts, retries, and backoff strategies.
///
/// # Examples
///
/// ```rust
/// use keylimectl::config::ClientConfig;
///
/// let config = ClientConfig {
///     timeout: 30,
///     retry_interval: 1.0,
///     exponential_backoff: true,
///     max_retries: 5,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Request timeout in seconds
    pub timeout: u64,
    /// Retry interval in seconds
    pub retry_interval: f64,
    /// Use exponential backoff for retries
    pub exponential_backoff: bool,
    /// Maximum number of retries
    pub max_retries: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: 60,
            retry_interval: 1.0,
            exponential_backoff: true,
            max_retries: 3,
        }
    }
}

impl Config {
    /// Check if a configuration file was loaded
    #[must_use]
    pub fn has_config_file(&self) -> bool {
        self.loaded_from.is_some()
    }

    /// Return the list of configuration file search paths.
    ///
    /// Used by the `info` command to show which paths were searched.
    #[must_use]
    pub fn config_search_paths() -> Vec<PathBuf> {
        Self::get_config_paths(None)
    }

    /// Load configuration from multiple sources
    ///
    /// Loads configuration with the following precedence (highest to lowest):
    /// 1. Environment variables (KEYLIME_*)
    /// 2. Configuration files (TOML format) - **OPTIONAL**
    /// 3. Default values
    ///
    /// Configuration files are completely optional. If no configuration files are found,
    /// the system will use default values combined with any environment variables.
    /// This allows keylimectl to work out-of-the-box without requiring any configuration.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Optional explicit path to configuration file.
    ///   If None, searches standard locations. If Some() but file doesn't exist, returns error.
    ///
    /// # Returns
    ///
    /// Returns the merged configuration. Will not fail if no config files are found when
    /// using automatic discovery (config_path = None).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::config::Config;
    ///
    /// // Works with no config files - uses defaults + env vars
    /// let config = Config::load(None)?;
    ///
    /// // Load from specific file (errors if file doesn't exist)
    /// let config = Config::load(Some("/path/to/config.toml"))?;
    /// # Ok::<(), config::ConfigError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns ConfigError if:
    /// - Explicit configuration file path provided but file doesn't exist
    /// - Configuration file has invalid syntax
    /// - Environment variables have invalid values
    pub fn load(config_path: Option<&str>) -> Result<Self, ConfigError> {
        let mut builder = config::Config::builder()
            .add_source(config::Config::try_from(&Config::default())?);

        // Add configuration file sources
        let config_paths = Self::get_config_paths(config_path);
        let mut config_file_found = false;
        let mut loaded_path: Option<PathBuf> = None;

        for path in config_paths {
            if path.exists() {
                config_file_found = true;
                if loaded_path.is_none() {
                    loaded_path = Some(path.clone());
                }
                log::debug!("Loading config from: {}", path.display());
                builder = builder.add_source(
                    File::from(path).format(FileFormat::Toml).required(false),
                );
            }
        }

        // If an explicit config path was provided but the file doesn't exist, that's an error
        if let Some(explicit_path) = config_path {
            if !PathBuf::from(explicit_path).exists() {
                return Err(ConfigError::Message(format!(
                    "Specified configuration file not found: {explicit_path}"
                )));
            }
        }

        // Add environment variables
        builder = builder.add_source(
            Environment::with_prefix("KEYLIME")
                .prefix_separator("_")
                .separator("__")
                .try_parsing(true),
        );

        let mut config: Config = builder.build()?.try_deserialize()?;
        config.loaded_from = loaded_path;

        // Log information about configuration sources used
        if config_file_found {
            log::debug!(
                "Configuration loaded successfully with config files"
            );
        } else {
            log::info!("No configuration files found, using defaults and environment variables");
        }

        Ok(config)
    }

    /// Apply command-line argument overrides
    ///
    /// CLI arguments have the highest precedence and will override any values
    /// loaded from configuration files or environment variables.
    ///
    /// # Arguments
    ///
    /// * `cli` - Command-line arguments parsed by clap
    ///
    /// # Returns
    ///
    /// Returns the configuration with CLI overrides applied.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::config::Config;
    /// use keylimectl::Cli;
    ///
    /// let config = Config::load(None)?
    ///     .with_cli_overrides(&cli);
    /// # Ok::<(), config::ConfigError>(())
    /// ```
    pub fn with_cli_overrides(mut self, cli: &Cli) -> Self {
        if let Some(ref ip) = cli.verifier_ip {
            self.verifier.ip = ip.clone();
            self.cli_overrides.verifier_ip = true;
        }

        if let Some(port) = cli.verifier_port {
            self.verifier.port = port;
            self.cli_overrides.verifier_port = true;
        }

        if let Some(ref ip) = cli.registrar_ip {
            self.registrar.ip = ip.clone();
            self.cli_overrides.registrar_ip = true;
        }

        if let Some(port) = cli.registrar_port {
            self.registrar.port = port;
            self.cli_overrides.registrar_port = true;
        }

        if let Some(timeout) = cli.timeout {
            self.client.timeout = timeout;
            self.cli_overrides.timeout = true;
        }

        self
    }

    /// Get configuration file search paths
    ///
    /// Returns paths in order of precedence (highest priority first):
    /// 1. `.keylimectl/config.toml` (project-local)
    /// 2. `keylimectl.toml` (current directory)
    /// 3. `keylimectl.conf` (current directory)
    /// 4. `~/.config/keylimectl/config.toml` (user, canonical)
    /// 5. `$XDG_CONFIG_HOME/keylimectl/config.toml` (XDG override)
    /// 6. `/etc/keylime/keylimectl.conf` (system-wide)
    /// 7. `/usr/etc/keylime/keylimectl.conf` (alternative system-wide)
    ///
    /// Legacy paths (8-10) are included for backward compatibility.
    fn get_config_paths(config_path: Option<&str>) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // If explicit path provided, use only that
        if let Some(path) = config_path {
            paths.push(PathBuf::from(path));
            return paths;
        }

        // 1. Project-local directory
        paths.push(PathBuf::from(".keylimectl/config.toml"));

        // 2-3. Current directory
        paths.push(PathBuf::from("keylimectl.toml"));
        paths.push(PathBuf::from("keylimectl.conf"));

        // 4. User config (canonical path)
        if let Some(home) = std::env::var_os("HOME") {
            let home_path = PathBuf::from(&home);
            paths.push(home_path.join(".config/keylimectl/config.toml"));
        }

        // 5. XDG config directory
        if let Some(xdg_config) = std::env::var_os("XDG_CONFIG_HOME") {
            paths.push(
                PathBuf::from(xdg_config).join("keylimectl/config.toml"),
            );
        }

        // 6-7. System-wide
        paths.push(PathBuf::from("/etc/keylime/keylimectl.conf"));
        paths.push(PathBuf::from("/usr/etc/keylime/keylimectl.conf"));

        // 8-10. Legacy paths for backward compatibility
        if let Some(home) = std::env::var_os("HOME") {
            let home_path = PathBuf::from(&home);
            paths.push(home_path.join(".config/keylime/keylimectl.conf"));
            paths.push(home_path.join(".keylimectl.toml"));
        }
        if let Some(xdg_config) = std::env::var_os("XDG_CONFIG_HOME") {
            paths.push(
                PathBuf::from(xdg_config).join("keylime/keylimectl.conf"),
            );
        }

        paths
    }

    /// Get the verifier service base URL
    ///
    /// Constructs the complete HTTPS URL for the verifier service,
    /// properly handling both IPv4 and IPv6 addresses.
    ///
    /// # Returns
    ///
    /// Returns the verifier base URL in the format `https://ip:port`
    /// or `https://[ipv6]:port` for IPv6 addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::config::Config;
    ///
    /// let config = Config::default();
    /// assert_eq!(config.verifier_base_url(), "https://127.0.0.1:8881");
    /// ```
    pub fn verifier_base_url(&self) -> String {
        // Handle IPv6 addresses
        if self.verifier.ip.contains(':')
            && !self.verifier.ip.starts_with('[')
        {
            format!("https://[{}]:{}", self.verifier.ip, self.verifier.port)
        } else {
            format!("https://{}:{}", self.verifier.ip, self.verifier.port)
        }
    }

    /// Get the registrar service base URL
    ///
    /// Constructs the complete HTTPS URL for the registrar service,
    /// properly handling both IPv4 and IPv6 addresses.
    ///
    /// # Returns
    ///
    /// Returns the registrar base URL in the format `https://ip:port`
    /// or `https://[ipv6]:port` for IPv6 addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::config::Config;
    ///
    /// let config = Config::default();
    /// assert_eq!(config.registrar_base_url(), "https://127.0.0.1:8891");
    /// ```
    pub fn registrar_base_url(&self) -> String {
        // Handle IPv6 addresses
        if self.registrar.ip.contains(':')
            && !self.registrar.ip.starts_with('[')
        {
            format!("https://[{}]:{}", self.registrar.ip, self.registrar.port)
        } else {
            format!("https://{}:{}", self.registrar.ip, self.registrar.port)
        }
    }

    /// Validate the configuration for correctness
    ///
    /// Performs comprehensive validation of all configuration values,
    /// checking for required fields, valid ranges, and file existence.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if configuration is valid, or `ConfigError`
    /// describing the first validation failure encountered.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keylimectl::config::Config;
    ///
    /// let config = Config::default();
    /// config.validate().expect("Default config should be valid");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns ConfigError if:
    /// - IP addresses are empty
    /// - Ports are zero
    /// - Certificate/key files don't exist
    /// - Timeout is zero
    /// - Retry interval is not positive
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Use the extracted validation logic from the validation module
        crate::config::validation::validate_complete_config(
            &self.verifier,
            &self.registrar,
            &self.tls,
            &self.client,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper function to create a test CLI instance
    fn create_test_cli(
        verifier_ip: Option<String>,
        verifier_port: Option<u16>,
        registrar_ip: Option<String>,
        registrar_port: Option<u16>,
    ) -> Cli {
        Cli {
            config: None,
            verifier_ip,
            verifier_port,
            registrar_ip,
            registrar_port,
            timeout: None,
            verbose: 0,
            quiet: false,
            format: crate::OutputFormat::Json,
            command: Some(crate::Commands::Agent {
                action: crate::AgentAction::List {
                    detailed: false,
                    registrar_only: false,
                },
            }),
        }
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();

        assert_eq!(config.verifier.ip, "127.0.0.1");
        assert_eq!(config.verifier.port, 8881);
        assert!(config.verifier.id.is_none());

        assert_eq!(config.registrar.ip, "127.0.0.1");
        assert_eq!(config.registrar.port, 8891);

        assert_eq!(
            config.tls.client_cert,
            Some("/var/lib/keylime/cv_ca/client-cert.crt".to_string())
        );
        assert_eq!(
            config.tls.client_key,
            Some("/var/lib/keylime/cv_ca/client-private.pem".to_string())
        );
        assert!(config.tls.verify_server_cert);
        assert!(config.tls.enable_agent_mtls);

        assert_eq!(config.client.timeout, 60);
        assert_eq!(config.client.max_retries, 3);
        assert!(config.client.exponential_backoff);
    }

    #[test]
    fn test_verifier_base_url_ipv4() {
        let config = Config {
            verifier: VerifierConfig {
                ip: "192.168.1.100".to_string(),
                port: 8881,
                id: None,
            },
            ..Config::default()
        };

        assert_eq!(config.verifier_base_url(), "https://192.168.1.100:8881");
    }

    #[test]
    fn test_verifier_base_url_ipv6() {
        let config = Config {
            verifier: VerifierConfig {
                ip: "2001:db8::1".to_string(),
                port: 8881,
                id: None,
            },
            ..Config::default()
        };

        assert_eq!(config.verifier_base_url(), "https://[2001:db8::1]:8881");
    }

    #[test]
    fn test_verifier_base_url_ipv6_bracketed() {
        let config = Config {
            verifier: VerifierConfig {
                ip: "[2001:db8::1]".to_string(),
                port: 8881,
                id: None,
            },
            ..Config::default()
        };

        assert_eq!(config.verifier_base_url(), "https://[2001:db8::1]:8881");
    }

    #[test]
    fn test_registrar_base_url_ipv4() {
        let config = Config {
            registrar: RegistrarConfig {
                ip: "10.0.0.1".to_string(),
                port: 9000,
            },
            ..Config::default()
        };

        assert_eq!(config.registrar_base_url(), "https://10.0.0.1:9000");
    }

    #[test]
    fn test_registrar_base_url_ipv6() {
        let config = Config {
            registrar: RegistrarConfig {
                ip: "::1".to_string(),
                port: 8891,
            },
            ..Config::default()
        };

        assert_eq!(config.registrar_base_url(), "https://[::1]:8891");
    }

    #[test]
    fn test_cli_overrides() {
        let mut config = Config::default();

        let cli = create_test_cli(
            Some("10.0.0.1".to_string()),
            Some(9001),
            Some("10.0.0.2".to_string()),
            Some(9002),
        );

        config = config.with_cli_overrides(&cli);

        assert_eq!(config.verifier.ip, "10.0.0.1");
        assert_eq!(config.verifier.port, 9001);
        assert_eq!(config.registrar.ip, "10.0.0.2");
        assert_eq!(config.registrar.port, 9002);
    }

    #[test]
    fn test_cli_partial_overrides() {
        let mut config = Config::default();

        let cli = create_test_cli(
            Some("192.168.1.1".to_string()),
            None,
            None,
            None,
        );

        config = config.with_cli_overrides(&cli);

        assert_eq!(config.verifier.ip, "192.168.1.1");
        assert_eq!(config.verifier.port, 8881); // Should remain default
        assert_eq!(config.registrar.ip, "127.0.0.1"); // Should remain default
    }

    #[test]
    fn test_cli_timeout_override() {
        let config = Config::default();
        assert_eq!(config.client.timeout, 60); // Default

        let mut cli = create_test_cli(None, None, None, None);
        cli.timeout = Some(120);
        let config = config.with_cli_overrides(&cli);
        assert_eq!(config.client.timeout, 120);
    }

    #[test]
    fn test_cli_timeout_no_override() {
        let config = Config::default();
        let cli = create_test_cli(None, None, None, None);
        let config = config.with_cli_overrides(&cli);
        assert_eq!(config.client.timeout, 60); // Should remain default
    }

    #[test]
    fn test_validate_config_missing_certs() {
        // Default config points to /var/lib/keylime/cv_ca/ which may or
        // may not exist depending on the environment.  Use paths that are
        // guaranteed absent to verify that validation catches missing files.
        let config = Config {
            tls: TlsConfig {
                client_cert: Some(
                    "/nonexistent/keylimectl-test/cert.crt".to_string(),
                ),
                client_key: Some(
                    "/nonexistent/keylimectl-test/key.pem".to_string(),
                ),
                trusted_ca: vec![
                    "/nonexistent/keylimectl-test/ca.crt".to_string()
                ],
                ..TlsConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_verifier_ip() {
        let config = Config {
            verifier: VerifierConfig {
                ip: "".to_string(),
                port: 8881,
                id: None,
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Verifier IP cannot be empty"));
    }

    #[test]
    fn test_validate_empty_registrar_ip() {
        let config = Config {
            registrar: RegistrarConfig {
                ip: "".to_string(),
                port: 8891,
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Registrar IP cannot be empty"));
    }

    #[test]
    fn test_validate_zero_verifier_port() {
        let config = Config {
            verifier: VerifierConfig {
                ip: "127.0.0.1".to_string(),
                port: 0,
                id: None,
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Verifier port cannot be 0"));
    }

    #[test]
    fn test_validate_zero_registrar_port() {
        let config = Config {
            registrar: RegistrarConfig {
                ip: "127.0.0.1".to_string(),
                port: 0,
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Registrar port cannot be 0"));
    }

    #[test]
    fn test_validate_nonexistent_cert_file() {
        let config = Config {
            tls: TlsConfig {
                client_cert: Some("/nonexistent/cert.pem".to_string()),
                ..TlsConfig::default()
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Client certificate file not found"));
    }

    #[test]
    fn test_validate_nonexistent_key_file() {
        let config = Config {
            tls: TlsConfig {
                client_cert: None,
                client_key: Some("/nonexistent/key.pem".to_string()),
                trusted_ca: vec![],
                ..TlsConfig::default()
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Client key file not found"));
    }

    #[test]
    fn test_validate_zero_timeout() {
        let config = Config {
            tls: TlsConfig {
                client_cert: None,
                client_key: None,
                trusted_ca: vec![],
                ..TlsConfig::default()
            },
            client: ClientConfig {
                timeout: 0,
                retry_interval: 1.0,
                exponential_backoff: true,
                max_retries: 3,
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Client timeout cannot be 0"));
    }

    #[test]
    fn test_validate_negative_retry_interval() {
        let config = Config {
            tls: TlsConfig {
                client_cert: None,
                client_key: None,
                trusted_ca: vec![],
                ..TlsConfig::default()
            },
            client: ClientConfig {
                timeout: 60,
                retry_interval: -1.0,
                exponential_backoff: true,
                max_retries: 3,
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Retry interval must be positive"));
    }

    #[test]
    fn test_validate_zero_retry_interval() {
        let config = Config {
            tls: TlsConfig {
                client_cert: None,
                client_key: None,
                trusted_ca: vec![],
                ..TlsConfig::default()
            },
            client: ClientConfig {
                timeout: 60,
                retry_interval: 0.0,
                exponential_backoff: true,
                max_retries: 3,
            },
            ..Config::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Retry interval must be positive"));
    }

    #[test]
    fn test_validate_with_existing_cert_files() {
        // Create temporary certificate and key files
        let cert_file = NamedTempFile::new().unwrap(); //#[allow_ci]
        let key_file = NamedTempFile::new().unwrap(); //#[allow_ci]

        let config = Config {
            tls: TlsConfig {
                client_cert: Some(
                    cert_file.path().to_string_lossy().to_string(),
                ),
                client_key: Some(
                    key_file.path().to_string_lossy().to_string(),
                ),
                client_key_password: None,
                trusted_ca: vec![], // Empty trusted CA to avoid non-existent file validation
                verify_server_cert: true,
                enable_agent_mtls: true,
                accept_invalid_hostnames: true,
            },
            ..Config::default()
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_config_from_toml_string() {
        let toml_content = r#"
[verifier]
ip = "10.0.0.1"
port = 9001
id = "test-verifier"

[registrar]
ip = "10.0.0.2"
port = 9002

[tls]
verify_server_cert = false
enable_agent_mtls = false
trusted_ca = []

[client]
timeout = 30
max_retries = 5
exponential_backoff = false
retry_interval = 2.0
"#;

        // Create a temporary file with the TOML content
        let mut temp_file = NamedTempFile::new().unwrap(); //#[allow_ci]
        temp_file.write_all(toml_content.as_bytes()).unwrap(); //#[allow_ci]
        temp_file.flush().unwrap(); //#[allow_ci]

        let config =
            Config::load(Some(temp_file.path().to_str().unwrap())).unwrap(); //#[allow_ci]

        assert_eq!(config.verifier.ip, "10.0.0.1");
        assert_eq!(config.verifier.port, 9001);
        assert_eq!(config.verifier.id, Some("test-verifier".to_string()));

        assert_eq!(config.registrar.ip, "10.0.0.2");
        assert_eq!(config.registrar.port, 9002);

        assert!(!config.tls.verify_server_cert);
        assert!(!config.tls.enable_agent_mtls);

        assert_eq!(config.client.timeout, 30);
        assert_eq!(config.client.max_retries, 5);
        assert!(!config.client.exponential_backoff);
        assert_eq!(config.client.retry_interval, 2.0);
    }

    #[test]
    fn test_load_config_no_files() {
        // Test loading config when no config files exist
        // This should always succeed with defaults since config files are optional
        let result = Config::load(None);

        // Should always succeed now that config files are optional
        match result {
            Ok(config) => {
                assert_eq!(config.verifier.ip, "127.0.0.1"); // Default value
                assert_eq!(config.verifier.port, 8881); // Default value
                assert_eq!(config.registrar.ip, "127.0.0.1"); // Default value
                assert_eq!(config.registrar.port, 8891); // Default value
            }
            Err(e) => {
                panic!("Config load with no files should succeed: {e:?}"); //#[allow_ci]
            }
        }
    }

    #[test]
    fn test_load_config_explicit_file_not_found() {
        // Test that explicit config file paths are still required to exist
        let result = Config::load(Some("/nonexistent/path/config.toml"));

        assert!(
            result.is_err(),
            "Should error when explicit config file doesn't exist"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Specified configuration file not found"));
        assert!(error_msg.contains("/nonexistent/path/config.toml"));
    }

    #[test]
    fn test_get_config_paths_explicit() {
        let paths = Config::get_config_paths(Some("/custom/path.toml"));
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from("/custom/path.toml"));
    }

    #[test]
    fn test_get_config_paths_standard() {
        let paths = Config::get_config_paths(None);

        // Project-local should be first
        assert_eq!(paths[0], PathBuf::from(".keylimectl/config.toml"));

        // Should include standard paths
        assert!(paths.contains(&PathBuf::from("keylimectl.toml")));
        assert!(paths.contains(&PathBuf::from("keylimectl.conf")));
        assert!(
            paths.contains(&PathBuf::from("/etc/keylime/keylimectl.conf"))
        );
        assert!(paths
            .contains(&PathBuf::from("/usr/etc/keylime/keylimectl.conf")));
    }

    #[test]
    fn test_loaded_from_with_explicit_file() {
        let mut temp_file = NamedTempFile::new().unwrap(); //#[allow_ci]
        temp_file //#[allow_ci]
            .write_all(b"[verifier]\nip = \"10.0.0.1\"\n")
            .unwrap(); //#[allow_ci]
        temp_file.flush().unwrap(); //#[allow_ci]

        let config = Config::load(Some(
            temp_file.path().to_str().unwrap(), //#[allow_ci]
        ))
        .unwrap(); //#[allow_ci]
        assert!(config.has_config_file());
        assert_eq!(
            config.loaded_from.unwrap(), //#[allow_ci]
            temp_file.path()
        );
    }

    #[test]
    fn test_loaded_from_default_is_none() {
        let config = Config::default();
        assert!(!config.has_config_file());
        assert!(config.loaded_from.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();

        // Test that config can be serialized to and from TOML
        let toml_str = toml::to_string(&config).unwrap(); //#[allow_ci]
        let deserialized: Config = toml::from_str(&toml_str).unwrap(); //#[allow_ci]

        assert_eq!(config.verifier.ip, deserialized.verifier.ip);
        assert_eq!(config.verifier.port, deserialized.verifier.port);
        assert_eq!(config.registrar.ip, deserialized.registrar.ip);
        assert_eq!(config.registrar.port, deserialized.registrar.port);
    }

    #[test]
    fn test_tls_config_defaults() {
        let tls_config = TlsConfig::default();

        assert_eq!(
            tls_config.client_cert,
            Some("/var/lib/keylime/cv_ca/client-cert.crt".to_string())
        );
        assert_eq!(
            tls_config.client_key,
            Some("/var/lib/keylime/cv_ca/client-private.pem".to_string())
        );
        assert!(tls_config.client_key_password.is_none());
        assert_eq!(
            tls_config.trusted_ca,
            vec!["/var/lib/keylime/cv_ca/cacert.crt".to_string()]
        );
        assert!(tls_config.verify_server_cert);
        assert!(tls_config.enable_agent_mtls);
    }

    #[test]
    fn test_client_config_defaults() {
        let client_config = ClientConfig::default();

        assert_eq!(client_config.timeout, 60);
        assert_eq!(client_config.retry_interval, 1.0);
        assert!(client_config.exponential_backoff);
        assert_eq!(client_config.max_retries, 3);
    }
}
