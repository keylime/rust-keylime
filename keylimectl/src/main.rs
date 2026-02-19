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

// Ensure at least one API version feature is enabled
#[cfg(not(any(feature = "api-v2", feature = "api-v3")))]
compile_error!(
    "At least one of the 'api-v2' or 'api-v3' features must be enabled. \
     Use '--features api-v2' or '--features api-v3' or both."
);

mod api_versions;
mod client;
mod commands;
mod config;
mod error;
mod output;
mod policy_tools;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use log::{debug, error, warn};
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
                  usability while maintaining full API compatibility.",
    after_long_help = "CONFIGURATION SOURCES (highest to lowest priority):\n  \
        1. Command-line arguments (--verifier-ip, --timeout, etc.)\n  \
        2. Environment variables (KEYLIME_VERIFIER__IP, KEYLIME_CLIENT__TIMEOUT, etc.)\n  \
        3. Configuration files (keylimectl.toml, ~/.config/keylimectl/config.toml, etc.)\n  \
        4. Built-in defaults\n\n\
        Run `keylimectl configure` to create a configuration file interactively."
)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Verifier IP address [default: 127.0.0.1]
    #[arg(long, value_name = "IP")]
    verifier_ip: Option<String>,

    /// Verifier port [default: 8881]
    #[arg(long, value_name = "PORT")]
    verifier_port: Option<u16>,

    /// Registrar IP address [default: 127.0.0.1]
    #[arg(long, value_name = "IP")]
    registrar_ip: Option<String>,

    /// Registrar port [default: 8891]
    #[arg(long, value_name = "PORT")]
    registrar_port: Option<u16>,

    /// Request timeout in seconds [default: 60]
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,

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
    command: Option<Commands>,
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
    /// Show diagnostic information
    #[command(alias = "diag")]
    Info {
        #[command(subcommand)]
        subcommand: Option<InfoSubcommand>,
    },
    /// Verify attestation evidence against a verifier
    Verify {
        #[command(subcommand)]
        action: VerifyAction,
    },
    /// Create or update a configuration file
    Configure {
        /// Run without interactive prompts
        #[arg(long)]
        non_interactive: bool,

        /// Configuration scope
        #[arg(long, value_enum, default_value = "user")]
        scope: ConfigScope,

        /// Verifier IP for non-interactive mode
        #[arg(long, value_name = "IP")]
        verifier_ip: Option<String>,

        /// Verifier port for non-interactive mode
        #[arg(long, value_name = "PORT")]
        verifier_port: Option<u16>,

        /// Registrar IP for non-interactive mode
        #[arg(long, value_name = "IP")]
        registrar_ip: Option<String>,

        /// Registrar port for non-interactive mode
        #[arg(long, value_name = "PORT")]
        registrar_port: Option<u16>,

        /// Test connectivity after configuration
        #[arg(long)]
        test_connectivity: bool,
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
        #[arg(long, conflicts_with = "pull_model")]
        push_model: bool,

        /// Force pull model (legacy API 2.x behavior, overrides auto-detection)
        #[arg(long, conflicts_with = "push_model")]
        pull_model: bool,

        /// TPM policy in JSON format
        #[arg(long, value_name = "POLICY")]
        tpm_policy: Option<String>,

        /// Wait for first attestation to complete after enrollment
        #[arg(long)]
        wait_for_attestation: bool,

        /// Timeout in seconds for --wait-for-attestation (default: 60)
        #[arg(long, value_name = "SECONDS", default_value_t = 60)]
        attestation_timeout: u64,
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

    /// Show a runtime policy from the verifier
    Show {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// Update an existing runtime policy on the verifier
    Update {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,

        /// Policy file path
        #[arg(long, value_name = "FILE")]
        file: String,
    },

    /// Delete a runtime policy from the verifier
    Delete {
        /// Policy name
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// List all runtime policies
    List,

    /// Generate a policy locally from input sources
    Generate {
        #[command(subcommand)]
        subcommand: GenerateSubcommand,
    },

    /// Sign a policy file using DSSE
    Sign {
        /// Policy file to sign
        #[arg(value_name = "FILE")]
        file: String,

        /// Private key file to sign with (generates new key if omitted)
        #[arg(short, long, value_name = "FILE")]
        keyfile: Option<String>,

        /// Path to save generated private key
        #[arg(short = 'p', long, value_name = "PATH")]
        keypath: Option<String>,

        /// Signing backend
        #[arg(short, long, value_enum, default_value = "ecdsa")]
        backend: SigningBackend,

        /// Output file for signed policy
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,

        /// Output file for X.509 certificate (x509 backend only)
        #[arg(short = 'c', long, value_name = "FILE")]
        cert_outfile: Option<String>,
    },

    /// Verify the DSSE signature on a signed policy
    VerifySignature {
        /// Signed policy file to verify
        #[arg(value_name = "FILE")]
        file: String,

        /// Public key or certificate file to verify against
        #[arg(short, long, value_name = "FILE")]
        key: String,
    },

    /// Validate a policy file structure and content
    Validate {
        /// Policy file to validate
        #[arg(value_name = "FILE")]
        file: String,

        /// Policy type (auto-detected if omitted)
        #[arg(
            short = 't',
            long,
            value_name = "TYPE",
            value_parser = ["runtime", "measured-boot", "tpm"]
        )]
        policy_type: Option<String>,

        /// Also verify DSSE signature using this key
        #[arg(short = 's', long, value_name = "FILE")]
        signature_key: Option<String>,
    },

    /// Convert a legacy allowlist to the current policy format
    Convert {
        /// Input allowlist or policy file
        #[arg(value_name = "FILE")]
        file: String,

        /// Output file (required)
        #[arg(short, long, value_name = "FILE")]
        output: String,

        /// Exclude list file to merge
        #[arg(short, long, value_name = "FILE")]
        excludelist: Option<String>,

        /// Verification key files to add
        #[arg(short = 'v', long, value_name = "FILES")]
        verification_keys: Option<String>,
    },
}

impl PolicyAction {
    /// Returns true if this action operates entirely locally
    /// (no network connectivity required).
    fn is_local_only(&self) -> bool {
        matches!(
            self,
            PolicyAction::Generate { .. }
                | PolicyAction::Sign { .. }
                | PolicyAction::VerifySignature { .. }
                | PolicyAction::Validate { .. }
                | PolicyAction::Convert { .. }
        )
    }
}

/// Policy generation subcommands
#[derive(Subcommand)]
enum GenerateSubcommand {
    /// Generate a runtime policy from IMA logs, allowlists, or filesystem
    Runtime {
        /// IMA measurement list path. If -m is given without a value, uses the
        /// default: /sys/kernel/security/ima/ascii_runtime_measurements
        #[arg(
            short = 'm',
            long,
            value_name = "FILE",
            num_args = 0..=1,
            default_missing_value = "/sys/kernel/security/ima/ascii_runtime_measurements",
        )]
        ima_measurement_list: Option<String>,

        /// Plain-text allowlist file
        #[arg(short, long, value_name = "FILE")]
        allowlist: Option<String>,

        /// Root filesystem path to scan
        #[arg(long, value_name = "PATH")]
        rootfs: Option<String>,

        /// Paths to skip during filesystem scan (repeatable)
        #[arg(long, value_name = "PATH")]
        skip_path: Vec<String>,

        /// Base policy to merge into
        #[arg(short = 'B', long, value_name = "FILE")]
        base_policy: Option<String>,

        /// IMA exclude list file
        #[arg(short, long, value_name = "FILE")]
        excludelist: Option<String>,

        /// Output file (stdout if omitted)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,

        /// Include keyrings entries
        #[arg(short, long)]
        keyrings: bool,

        /// Include ima-buf entries
        #[arg(long)]
        ima_buf: bool,

        /// Keyrings to ignore (repeatable)
        #[arg(short, long, value_name = "KEYRING")]
        ignored_keyrings: Vec<String>,

        /// Add IMA signature verification key (repeatable)
        #[arg(short = 'A', long, value_name = "FILE")]
        add_ima_signature_verification_key: Vec<String>,

        /// Hash algorithm (auto-detected if omitted)
        #[arg(long, value_name = "ALG")]
        hash_alg: Option<String>,

        /// Directory containing initramfs files (e.g., /boot)
        #[arg(long, value_name = "DIR")]
        ramdisk_dir: Option<String>,
    },

    /// Generate a measured boot policy from a UEFI event log
    MeasuredBoot {
        /// UEFI event log file
        #[arg(
            long,
            value_name = "FILE",
            default_value = "/sys/kernel/security/tpm0/binary_bios_measurements"
        )]
        eventlog_file: String,

        /// Generate policy without Secure Boot variables
        #[arg(long)]
        without_secureboot: bool,

        /// Output file (stdout if omitted)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Generate a TPM policy from PCR values
    Tpm {
        /// Read PCR values from file (one per line)
        #[arg(long, value_name = "FILE", group = "pcr_source")]
        pcr_file: Option<String>,

        /// Read PCR values from local TPM (requires tpm-local feature)
        #[arg(long, group = "pcr_source")]
        from_tpm: bool,

        /// PCR indices to include (comma-separated, e.g., "0,1,2,7")
        #[arg(
            long,
            value_name = "INDICES",
            default_value = "0,1,2,3,4,5,6,7"
        )]
        pcrs: String,

        /// PCR mask (overrides --pcrs, e.g., "0x408000")
        #[arg(long, value_name = "MASK")]
        mask: Option<String>,

        /// Hash algorithm
        #[arg(long, value_name = "ALG", default_value = "sha256")]
        hash_alg: String,

        /// Output file (stdout if omitted)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },
}

/// Signing backend for policy signing
#[derive(Clone, Debug, clap::ValueEnum)]
enum SigningBackend {
    /// ECDSA P-256 signing (default)
    Ecdsa,
    /// X.509 certificate-based signing
    X509,
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

/// Configuration scope for the `configure` command
#[derive(Clone, Debug, clap::ValueEnum)]
enum ConfigScope {
    /// Local directory: ./.keylimectl/config.toml
    Local,
    /// User home: ~/.config/keylimectl/config.toml
    User,
    /// System-wide: /etc/keylime/keylimectl.conf
    System,
}

/// Info subcommands for diagnostic inspection
#[derive(Subcommand)]
enum InfoSubcommand {
    /// Show verifier status and API version
    Verifier,
    /// Show registrar status and API version
    Registrar,
    /// Show detailed information for a specific agent
    Agent {
        /// Agent identifier
        #[arg(value_name = "AGENT_ID")]
        agent_id: String,
    },
    /// Validate TLS certificates and test connectivity
    Tls,
}

/// Evidence verification actions
#[derive(Subcommand)]
enum VerifyAction {
    /// Verify TPM or TEE attestation evidence
    Evidence {
        /// Nonce used for the quote
        #[arg(long, value_name = "NONCE")]
        nonce: String,

        /// TPM quote file
        #[arg(long, value_name = "FILE")]
        quote: String,

        /// Hash algorithm
        #[arg(long, value_name = "ALG", default_value = "sha256")]
        hash_alg: String,

        /// TPM Attestation Key (AK) file
        #[arg(long, value_name = "FILE")]
        tpm_ak: String,

        /// TPM Endorsement Key (EK) file
        #[arg(long, value_name = "FILE")]
        tpm_ek: String,

        /// Runtime policy file
        #[arg(long, value_name = "FILE")]
        runtime_policy: Option<String>,

        /// IMA measurement list file
        #[arg(long, value_name = "FILE")]
        ima_measurement_list: Option<String>,

        /// Measured boot policy file
        #[arg(long, value_name = "FILE")]
        mb_policy: Option<String>,

        /// Measured boot log file
        #[arg(long, value_name = "FILE")]
        mb_log: Option<String>,

        /// TPM policy file
        #[arg(long, value_name = "FILE")]
        tpm_policy: Option<String>,

        /// Evidence type
        #[arg(
            long,
            value_name = "TYPE",
            default_value = "tpm",
            value_parser = ["tpm", "tee"]
        )]
        evidence_type: String,
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

    match cli.command {
        Some(ref command @ Commands::Configure { .. }) => {
            // Configure command does not require config validation
            // or the singleton — it creates/updates configuration.
            let output = OutputHandler::new(cli.format, cli.quiet);

            let result = execute_command(command, &output).await;

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
        Some(
            ref command @ Commands::Policy {
                action:
                    ref action @ PolicyAction::Generate { .. }
                    | ref action @ PolicyAction::Sign { .. }
                    | ref action @ PolicyAction::VerifySignature { .. }
                    | ref action @ PolicyAction::Validate { .. }
                    | ref action @ PolicyAction::Convert { .. },
            },
        ) if action.is_local_only() => {
            // Local-only policy commands do not require network
            // connectivity or valid TLS configuration.
            if let Err(e) = config.validate() {
                warn!("Configuration validation: {e}");
            }

            if let Err(e) = config::singleton::initialize_config(config) {
                error!("Failed to initialize config singleton: {e}");
                process::exit(1);
            }

            let output = OutputHandler::new(cli.format, cli.quiet);

            let result = execute_command(command, &output).await;

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
        Some(ref command @ Commands::Info { .. }) => {
            // Info commands should work even with incomplete config.
            // Warn on validation failures instead of exiting.
            if let Err(e) = config.validate() {
                warn!("Configuration validation: {e}");
            }

            // Always initialize singleton so info subcommands can
            // use get_config() uniformly.
            if let Err(e) = config::singleton::initialize_config(config) {
                error!("Failed to initialize config singleton: {e}");
                process::exit(1);
            }

            let output = OutputHandler::new(cli.format, cli.quiet);

            let result = execute_command(command, &output).await;

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
        Some(ref command) => {
            // Validate the final configuration strictly for commands
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

            // Execute command
            let result = execute_command(command, &output).await;

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
        None => {
            // Warn about validation issues but don't exit
            if let Err(e) = config.validate() {
                warn!("Configuration validation: {e}");
            }

            handle_no_command(&config);
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

/// Handle the case when no subcommand is provided.
///
/// Shows a configuration summary followed by clap's auto-generated help text.
fn handle_no_command(config: &Config) {
    use std::io::IsTerminal;

    print_config_summary(config);

    if !config.has_config_file() {
        eprintln!("No configuration file found.");
        if std::io::stdin().is_terminal() {
            eprintln!("  Tip: Run `keylimectl configure` to create one.");
        }
        eprintln!();
    }

    // Print clap's auto-generated help (subcommands, options, etc.)
    // This stays in sync automatically as commands are added/removed.
    let mut cmd = Cli::command();
    let _ = cmd.print_help();
}

/// Print a summary of the current configuration to stderr.
fn print_config_summary(config: &Config) {
    if let Some(ref path) = config.loaded_from {
        eprintln!("Configuration: {}", path.display());
    } else {
        eprintln!("Configuration: (defaults)");
    }
    eprintln!(
        "Verifier:      {}:{}",
        config.verifier.ip, config.verifier.port
    );
    eprintln!(
        "Registrar:     {}:{}",
        config.registrar.ip, config.registrar.port
    );
    eprintln!("TLS:           {}", tls_summary(&config.tls));
    eprintln!();
}

/// Generate a short summary of the TLS configuration.
fn tls_summary(tls: &config::TlsConfig) -> &'static str {
    if tls.client_cert.is_some() && tls.verify_server_cert {
        "mTLS enabled, server verification on"
    } else if tls.client_cert.is_some() {
        "mTLS enabled, server verification off"
    } else if tls.verify_server_cert {
        "server verification on"
    } else {
        "disabled"
    }
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
        Commands::Info { subcommand } => {
            commands::info::execute(subcommand, output).await
        }
        Commands::Verify { action } => {
            commands::verify::execute(action, output).await
        }
        Commands::Configure {
            non_interactive,
            scope,
            verifier_ip,
            verifier_port,
            registrar_ip,
            registrar_port,
            test_connectivity,
        } => {
            let params = commands::configure::ConfigureParams {
                non_interactive: *non_interactive,
                scope,
                verifier_ip: verifier_ip.as_deref(),
                verifier_port: *verifier_port,
                registrar_ip: registrar_ip.as_deref(),
                registrar_port: *registrar_port,
                test_connectivity: *test_connectivity,
            };
            commands::configure::execute(&params, output).await
        }
    }
}
