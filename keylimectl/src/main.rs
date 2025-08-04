// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! # keylimectl
//!
//! A modern, user-friendly command-line tool for Keylime remote attestation.
//! This tool replaces the Python keylime_tenant with improved usability while
//! maintaining full API compatibility.

#![deny(
    nonstandard_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    unconditional_recursion,
    unused,
    while_true,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

mod client;
mod commands;
mod config;
mod error;
mod output;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{debug, error};
use serde_json::Value;
use std::process;

use crate::config::Config;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;

/// Modern command-line tool for Keylime remote attestation
#[derive(Parser)]
#[command(
    name = "keylimectl",
    version,
    about = "A modern command-line tool for Keylime remote attestation",
    long_about = "keylimectl provides an intuitive interface for managing Keylime agents, \
                  policies, and attestation. It replaces keylime_tenant with improved \
                  usability while maintaining full API compatibility."
)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Verifier IP address
    #[arg(long, value_name = "IP")]
    verifier_ip: Option<String>,

    /// Verifier port
    #[arg(long, value_name = "PORT")]
    verifier_port: Option<u16>,

    /// Registrar IP address
    #[arg(long, value_name = "IP")]
    registrar_ip: Option<String>,

    /// Registrar port
    #[arg(long, value_name = "PORT")]
    registrar_port: Option<u16>,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress all output except JSON results
    #[arg(short, long)]
    quiet: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

/// Available output formats
#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    /// JSON output (default)
    Json,
    /// Human-readable table format
    Table,
    /// YAML output
    Yaml,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Manage agents
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Manage runtime policies
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Manage measured boot policies
    #[command(alias = "mb")]
    MeasuredBoot {
        #[command(subcommand)]
        action: MeasuredBootAction,
    },
}

/// Agent management actions
#[derive(Subcommand)]
enum AgentAction {
    /// Add an agent to the verifier
    Add {
        /// Agent identifier (can be any string, not necessarily a UUID)
        #[arg(value_name = "AGENT_ID")]
        uuid: String,

        /// Agent IP address (if not using push model)
        #[arg(long, value_name = "IP")]
        ip: Option<String>,

        /// Agent port (if not using push model)
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,

        /// Verifier IP for the agent to connect to
        #[arg(long, value_name = "IP")]
        verifier_ip: Option<String>,

        /// Runtime policy to apply
        #[arg(long, value_name = "POLICY")]
        runtime_policy: Option<String>,

        /// Measured boot policy to apply
        #[arg(long, value_name = "POLICY")]
        mb_policy: Option<String>,

        /// Payload file to deliver securely
        #[arg(long, value_name = "FILE")]
        payload: Option<String>,

        /// Certificate directory for secure delivery
        #[arg(long, value_name = "DIR")]
        cert_dir: Option<String>,

        /// Verify cryptographic key derivation
        #[arg(long)]
        verify: bool,

        /// Use push model (agent connects to verifier)
        #[arg(long)]
        push_model: bool,

        /// TPM policy in JSON format
        #[arg(long, value_name = "POLICY")]
        tpm_policy: Option<String>,
    },

    /// Remove an agent from the verifier
    Remove {
        /// Agent identifier
        #[arg(value_name = "AGENT_ID")]
        uuid: String,

        /// Also remove from registrar
        #[arg(long)]
        from_registrar: bool,

        /// Skip verifier checks (force removal)
        #[arg(long)]
        force: bool,
    },

    /// Update an existing agent
    Update {
        /// Agent identifier
        #[arg(value_name = "AGENT_ID")]
        uuid: String,

        /// New runtime policy
        #[arg(long, value_name = "POLICY")]
        runtime_policy: Option<String>,

        /// New measured boot policy
        #[arg(long, value_name = "POLICY")]
        mb_policy: Option<String>,
    },

    /// Show agent status
    Status {
        /// Agent identifier
        #[arg(value_name = "AGENT_ID")]
        uuid: String,

        /// Check verifier only
        #[arg(long)]
        verifier_only: bool,

        /// Check registrar only
        #[arg(long)]
        registrar_only: bool,
    },

    /// Reactivate a failed agent
    Reactivate {
        /// Agent identifier
        #[arg(value_name = "AGENT_ID")]
        uuid: String,
    },

    /// List all agents
    List {
        /// Show detailed information
        #[arg(long)]
        detailed: bool,

        /// List agents from registrar only
        #[arg(long)]
        registrar_only: bool,
    },
}

/// Policy management actions
#[derive(Subcommand)]
enum PolicyAction {
    /// Push a runtime policy to the verifier
    Push {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,

        /// Policy file path
        #[arg(long, value_name = "FILE")]
        file: String,
    },

    /// Show a runtime policy
    Show {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// Update an existing runtime policy
    Update {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,

        /// Policy file path
        #[arg(long, value_name = "FILE")]
        file: String,
    },

    /// Delete a runtime policy
    Delete {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// List all runtime policies
    List,
}

/// Measured boot policy actions
#[derive(Subcommand)]
enum MeasuredBootAction {
    /// List all measured boot policies
    List,

    /// Push a measured boot policy to the verifier
    Push {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,

        /// Policy file path
        #[arg(long, value_name = "FILE")]
        file: String,
    },

    /// Show a measured boot policy
    Show {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// Update an existing measured boot policy
    Update {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,

        /// Policy file path
        #[arg(long, value_name = "FILE")]
        file: String,
    },

    /// Delete a measured boot policy
    Delete {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    init_logging(cli.verbose, cli.quiet);

    // Load configuration
    let config = match Config::load(cli.config.as_deref()) {
        Ok(config) => {
            debug!("Loaded configuration with TLS settings: client_cert={:?}, client_key={:?}, trusted_ca={:?}",
                   config.tls.client_cert, config.tls.client_key, config.tls.trusted_ca);
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {e}");
            process::exit(1);
        }
    };

    // Override config with CLI arguments
    let config = config.with_cli_overrides(&cli);
    debug!("Final configuration after CLI overrides: client_cert={:?}, client_key={:?}, trusted_ca={:?}",
           config.tls.client_cert, config.tls.client_key, config.tls.trusted_ca);

    // Validate the final configuration
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {e}");
        process::exit(1);
    }
    debug!("Configuration validation passed");

    // Initialize config singleton
    if let Err(e) = config::singleton::initialize_config(config) {
        error!("Failed to initialize config singleton: {e}");
        process::exit(1);
    }

    // Initialize output handler
    let output = OutputHandler::new(cli.format, cli.quiet);

    // Execute command (no longer pass config)
    let result = execute_command(&cli.command, &output).await;

    match result {
        Ok(response) => {
            output.success(response);
        }
        Err(e) => {
            error!("Command failed: {e}");
            output.error(e);
            process::exit(1);
        }
    }
}

/// Initialize logging based on verbosity level
fn init_logging(verbose: u8, quiet: bool) {
    if quiet {
        return;
    }

    let log_level = match verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    pretty_env_logger::formatted_builder()
        .filter_level(log_level)
        .target(pretty_env_logger::env_logger::Target::Stderr)
        .init();
}

/// Execute the given command
async fn execute_command(
    command: &Commands,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match command {
        Commands::Agent { action } => {
            commands::agent::execute(action, output).await
        }
        Commands::Policy { action } => {
            commands::policy::execute(action, output).await
        }
        Commands::MeasuredBoot { action } => {
            commands::measured_boot::execute(action, output).await
        }
    }
}
