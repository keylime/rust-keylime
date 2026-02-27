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
//! # Module Structure
//!
//! - [`validation`]: Configuration validation logic extracted for better organization
//! - Main configuration types and loading logic in this module
//!
//! # Configuration Sources
//!
//! ## Configuration Files (Optional)
//! Configuration files are completely optional. The system searches for TOML files in the following order:
//! - Explicit path provided via CLI argument (required to exist if specified)
//! - `keylimectl.toml` (current directory)
//! - `keylimectl.conf` (current directory)
//! - `/etc/keylime/keylimectl.conf` (system-wide)
//! - `/usr/etc/keylime/keylimectl.conf` (alternative system-wide)
//! - `~/.config/keylime/keylimectl.conf` (user-specific)
//! - `~/.keylimectl.toml` (user-specific)
//! - `$XDG_CONFIG_HOME/keylime/keylimectl.conf` (XDG standard)
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
//! use keylimectl::config::{Config, validation};
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
//! // Validate configuration using extracted validation logic
//! validation::validate_complete_config(
//!     &config.verifier,
//!     &config.registrar,
//!     &config.tls,
//!     &config.client
//! ).expect("Invalid configuration");
//!
//! // Get service URLs
//! let verifier_url = config.verifier_base_url();
//! let registrar_url = config.registrar_base_url();
//! ```

pub mod error;
pub mod singleton;
pub mod validation;

// Re-export main config types for backwards compatibility
pub use self::main_config::*;

// Import the main configuration from the original file
#[path = "../config_main.rs"]
mod main_config;
