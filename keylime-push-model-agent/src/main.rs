// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use anyhow::Result;
use clap::Parser;
use keylime::config::PushModelConfigTrait;
use log::{debug, error, info, warn};
mod attestation;
mod context_info_handler;
mod header_validation;
mod privileged_resources;
mod registration;
mod response_handler;
mod state_machine;
mod struct_filler;
mod url_selector;

use keylime::config::DEFAULT_REGISTRAR_URL;

const DEFAULT_TIMEOUT_MILLIS: &str = "5000"; // Keep as string for clap default_value
const DEFAULT_METHOD: &str = "POST";
const DEFAULT_MESSAGE_TYPE_STR: &str = "Attestation";
const DEFAULT_ATTESTATION_INTERVAL_SECONDS: u64 = 60;

pub enum MessageType {
    Attestation,
    EvidenceHandling,
    Session,
}

pub struct ResponseInformation {
    pub status_code: reqwest::StatusCode,
    pub body: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, ignore_errors = true)]
struct Args {
    /// identifier
    /// Default: 12345678
    #[arg(long, default_missing_value = "12345678")]
    agent_identifier: Option<String>,
    /// API version
    /// Default: "v3.0"
    #[arg(long, default_value = url_selector::DEFAULT_API_VERSION)]
    api_version: Option<String>,
    /// CA certificate file
    #[arg(long, default_value = "/var/lib/keylime/cv_ca/cacert.crt")]
    ca_certificate: String,
    /// Client certificate file
    #[arg(
        short,
        long,
        default_value = "/var/lib/keylime/cv_ca/client-cert.crt"
    )]
    certificate: String,
    /// Client private key file
    #[arg(
        short,
        long,
        default_value = "/var/lib/keylime/cv_ca/client-private.pem"
    )]
    key: String,
    /// json file
    #[arg(short, long, default_missing_value = "")]
    json_file: Option<String>,
    /// index
    /// Default: 1
    #[arg(long, default_value = "1")]
    attestation_index: Option<String>,
    /// insecure
    #[arg(long, action, default_missing_value = "true")]
    insecure: Option<bool>,
    /// Type of message
    /// Default: "Attestation"
    #[arg(long, default_value = DEFAULT_MESSAGE_TYPE_STR)]
    message_type: Option<String>,
    /// Method
    /// Default: "POST"
    #[arg(long, default_missing_value = DEFAULT_METHOD)]
    method: Option<String>,
    /// Registrar URL
    /// Default: "http://127.0.0.1:8888"
    #[arg(long, default_value = DEFAULT_REGISTRAR_URL)]
    registrar_url: String,
    /// Session ID
    /// Default: 1
    #[arg(long, default_missing_value = "1", default_value = "1")]
    session_index: Option<String>,
    /// Timeout in milliseconds
    /// Default: 5000
    #[arg(long, default_value = DEFAULT_TIMEOUT_MILLIS)]
    timeout: u64,
    /// Verifier URL
    #[arg(short, long)]
    verifier_url: Option<String>,
    /// avoid tpm
    /// Default: false
    #[arg(long, action, default_missing_value = "false")]
    avoid_tpm: Option<bool>,
    /// Interval in seconds between the attestations happening after the first successful attestation
    /// Default: 60
    #[arg(long, default_value_t = DEFAULT_ATTESTATION_INTERVAL_SECONDS)]
    attestation_interval_seconds: u64,
}

fn get_avoid_tpm_from_args(args: &Args) -> bool {
    args.avoid_tpm.unwrap_or(false)
}

fn create_registrar_tls_config<T: PushModelConfigTrait>(
    config: &T,
    timeout: u64,
) -> Option<registration::RegistrarTlsConfig> {
    if !config.registrar_tls_enabled() {
        info!("Registrar TLS enabled: false - using plain HTTP");
        return None;
    }

    let ca_cert = config.registrar_tls_ca_cert();
    let client_cert = config.registrar_tls_client_cert();
    let client_key = config.registrar_tls_client_key();

    info!("Registrar TLS enabled: true");
    debug!("Registrar CA certificate: {}", ca_cert);
    debug!("Registrar client certificate: {}", client_cert);
    debug!("Registrar client key: {}", client_key);

    // Only use TLS if all certificate paths are provided
    if !ca_cert.is_empty()
        && !client_cert.is_empty()
        && !client_key.is_empty()
    {
        info!("Registrar TLS configuration complete - using HTTPS");
        return Some(registration::RegistrarTlsConfig {
            ca_cert: Some(ca_cert.to_string()),
            client_cert: Some(client_cert.to_string()),
            client_key: Some(client_key.to_string()),
            insecure: None,
            timeout: Some(timeout),
        });
    }

    // Check for partial configuration
    let provided_count = [
        !ca_cert.is_empty(),
        !client_cert.is_empty(),
        !client_key.is_empty(),
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    if provided_count > 0 {
        warn!(
            "Registrar TLS is enabled but only {} out of 3 certificate paths are configured.",
            provided_count
        );
        warn!("This may indicate a configuration mistake.");
        warn!(
            "Missing paths: {}{}{}",
            if ca_cert.is_empty() {
                "registrar_tls_ca_cert "
            } else {
                ""
            },
            if client_cert.is_empty() {
                "registrar_tls_client_cert "
            } else {
                ""
            },
            if client_key.is_empty() {
                "registrar_tls_client_key "
            } else {
                ""
            }
        );
    } else {
        warn!("Registrar TLS is enabled but no certificate paths are configured.");
    }
    warn!("Falling back to plain HTTP for Registrar communication.");
    None
}

async fn run(
    args: &Args,
    _privileged_resources: privileged_resources::PrivilegedResources,
) -> Result<()> {
    let config = keylime::config::get_config();

    // Warn if insecure TLS settings are enabled
    if config.tls_accept_invalid_certs {
        warn!("INSECURE: TLS certificate validation is DISABLED!");
        warn!("INSECURE: The agent will accept invalid or self-signed certificates.");
        warn!("INSECURE: Only use this setting for testing or debugging purposes.");
    }

    if config.tls_accept_invalid_hostnames {
        warn!("INSECURE: TLS hostname verification is DISABLED!");
        warn!(
            "INSECURE: The agent will accept certificates for ANY hostname."
        );
        warn!("INSECURE: Only use this setting for testing or debugging purposes.");
    }

    let avoid_tpm = get_avoid_tpm_from_args(args);
    context_info_handler::init_context_info(avoid_tpm)?;
    debug!("Avoid TPM: {avoid_tpm}");
    let ctx_info = match context_info_handler::get_context_info(avoid_tpm) {
        Ok(Some(context_info)) => Some(context_info),
        Ok(None) => {
            error!("No context");
            None
        }
        Err(e) => {
            error!("Error obtaining context information: {e:?}");
            return Err(e);
        }
    };
    let agent_identifier = match &args.agent_identifier {
        Some(id) => id.clone(),
        None => config.uuid().to_string(),
    };
    let verifier_url = match args.verifier_url {
        Some(ref url) => url.clone(),
        _ => config.verifier_url().to_string(),
    };
    let negotiations_request_url =
        url_selector::get_negotiations_request_url(&url_selector::UrlArgs {
            verifier_url: verifier_url.clone(),
            api_version: args.api_version.clone(),
            agent_identifier: Some(agent_identifier.clone()),
            location: None,
        });
    if negotiations_request_url.starts_with("ERROR:") {
        return Err(anyhow::anyhow!(negotiations_request_url));
    }
    debug!("Negotiations request URL: {negotiations_request_url}");
    let neg_config = attestation::NegotiationConfig {
        avoid_tpm,
        ca_certificate: &args.ca_certificate,
        client_certificate: &args.certificate,
        enable_authentication: config.enable_authentication(),
        agent_id: &agent_identifier,
        ima_log_path: Some(config.ima_ml_path.as_str()),
        initial_delay_ms: config
            .exponential_backoff_initial_delay
            .unwrap_or(1000),
        insecure: args.insecure,
        key: &args.key,
        max_delay_ms: config.exponential_backoff_max_delay,
        max_retries: config.exponential_backoff_max_retries.unwrap_or(5),
        timeout: args.timeout,
        uefi_log_path: Some(config.measuredboot_ml_path.as_str()),
        url: &negotiations_request_url,
        verifier_url: verifier_url.as_str(),
        tls_accept_invalid_certs: config.tls_accept_invalid_certs,
        tls_accept_invalid_hostnames: config.tls_accept_invalid_hostnames,
    };
    let attestation_client =
        attestation::AttestationClient::new(&neg_config)?;

    // Create Registrar TLS config from configuration
    let registrar_tls_config =
        create_registrar_tls_config(config, args.timeout);

    let mut state_machine = state_machine::StateMachine::new(
        attestation_client,
        neg_config,
        ctx_info,
        config.attestation_interval_seconds(),
        registrar_tls_config,
    );
    state_machine.run().await;
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    // Load config
    let config = keylime::config::get_config();

    // === EARLY SECURITY VALIDATION (before opening privileged resources) ===
    // Validate run_as setting before doing any privileged operations
    let run_as = if keylime::permissions::get_euid() == 0 {
        if config.run_as.is_empty() {
            error!("CRITICAL SECURITY WARNING: Running as root without 'run_as' configured!");
            error!("This is a significant security risk and should be avoided in production.");
            error!("Set 'run_as = \"keylime:keylime\"' in the config file to drop privileges.");
            error!("The agent will continue running as root, but this is NOT recommended.");
            None
        } else {
            // Early validation: Verify user/group exist before opening privileged resources
            if let Err(e) = keylime::permissions::UserIds::try_from(
                config.run_as.as_str(),
            ) {
                error!(
                    "Failed to validate run_as setting '{}': {}",
                    config.run_as, e
                );
                error!("This must be fixed before starting the agent to ensure secure privilege dropping.");
                return Err(anyhow::anyhow!(
                    "Failed to validate run_as setting: {}",
                    e
                ));
            }
            Some(&config.run_as)
        }
    } else {
        if !config.run_as.is_empty() {
            warn!("Ignoring 'run_as' option because Keylime agent has not been started as root.");
        }
        None
    };

    // === PRIVILEGED INITIALIZATION (as root) ===
    // Open resources that require root privileges (IMA/measured boot logs)
    // This happens after validating security settings to prevent exploitation
    let privileged_resources =
        privileged_resources::PrivilegedResources::new(config)?;

    if let Some(user_group) = run_as {
        if let Err(e) = keylime::permissions::run_as(user_group) {
            error!("Failed to drop privileges to {}: {}", user_group, e);
            error!("Troubleshooting steps:");

            // Provide error-specific guidance based on the error type
            let error_str = e.to_string();
            if error_str.contains("GetPWNam") {
                error!(
                    "  ERROR: User '{}' not found",
                    user_group.split(':').next().unwrap_or("unknown")
                );
                error!("    Solution: Create user with: useradd -r -s /bin/false keylime");
            } else if error_str.contains("GetGrNam") {
                error!(
                    "  ERROR: Group '{}' not found",
                    user_group.split(':').nth(1).unwrap_or("unknown")
                );
                error!("    Solution: Create group with: groupadd keylime");
            } else if error_str.contains("SetGroups") {
                error!("  ERROR: Failed to set supplementary groups");
                error!("    This may indicate insufficient privileges or a system issue");
            } else if error_str.contains("SetGID") {
                error!("  ERROR: Failed to set GID");
                error!("    This may indicate the group doesn't exist or insufficient privileges");
            } else if error_str.contains("SetUID") {
                error!("  ERROR: Failed to set UID");
                error!("    This may indicate the user doesn't exist or insufficient privileges");
            }

            error!("  General troubleshooting:");
            error!("    1. Verify user and group exist: getent passwd keylime && getent group keylime");
            error!("    2. Verify user is in tss group: groups keylime | grep tss");
            error!("    3. If missing, run: usermod -a -G tss keylime");
            error!("    4. Ensure proper permissions on /sys/kernel/security (root access required at startup)");
            return Err(anyhow::anyhow!(
                "Privilege dropping failed. See error messages above for troubleshooting."
            ));
        }
        info!("Running the service as {}...", user_group);
    }

    // === CONTINUE AS UNPRIVILEGED USER ===
    // All subsequent operations run as unprivileged user
    // TPM access is provided via group membership (typically 'tss' group)
    run(&Args::parse(), privileged_resources).await
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;

    // Mock config for testing
    struct MockConfig {
        tls_enabled: bool,
        ca_cert: String,
        client_cert: String,
        client_key: String,
        backoff_max_delay: Option<u64>,
        backoff_max_retries: Option<u32>,
        backoff_initial_delay: Option<u64>,
    }

    impl PushModelConfigTrait for MockConfig {
        fn registrar_tls_enabled(&self) -> bool {
            self.tls_enabled
        }

        fn registrar_tls_ca_cert(&self) -> &str {
            &self.ca_cert
        }

        fn registrar_tls_client_cert(&self) -> &str {
            &self.client_cert
        }

        fn registrar_tls_client_key(&self) -> &str {
            &self.client_key
        }

        // Dummy implementations for other required trait methods
        fn agent_data_path(&self) -> &str {
            ""
        }
        fn api_versions(
            &self,
        ) -> Result<Vec<&str>, keylime::config::OverrideError> {
            Ok(vec![])
        }
        fn attestation_interval_seconds(&self) -> u64 {
            60
        }
        fn certification_keys_server_identifier(&self) -> &str {
            ""
        }
        fn contact_ip(&self) -> &str {
            ""
        }
        fn contact_port(&self) -> u32 {
            0
        }
        fn enable_authentication(&self) -> bool {
            false
        }
        fn exponential_backoff_max_delay(&self) -> &Option<u64> {
            &self.backoff_max_delay
        }
        fn exponential_backoff_max_retries(&self) -> &Option<u32> {
            &self.backoff_max_retries
        }
        fn exponential_backoff_initial_delay(&self) -> &Option<u64> {
            &self.backoff_initial_delay
        }
        fn enable_iak_idevid(&self) -> bool {
            false
        }
        fn ek_handle(
            &self,
        ) -> Result<String, keylime::config::OverrideError> {
            Ok(String::new())
        }
        fn ima_ml_count_file(&self) -> &str {
            ""
        }
        fn measuredboot_ml_path(&self) -> &str {
            ""
        }
        fn registrar_api_versions(
            &self,
        ) -> Result<Vec<&str>, keylime::list_parser::ListParsingError>
        {
            Ok(vec![])
        }
        fn registrar_ip(&self) -> &str {
            ""
        }
        fn registrar_port(&self) -> u32 {
            0
        }
        fn server_cert(&self) -> &str {
            ""
        }
        fn server_key(&self) -> &str {
            ""
        }
        fn server_key_password(&self) -> &str {
            ""
        }
        fn tpm_encryption_alg(&self) -> &str {
            ""
        }
        fn tpm_hash_alg(&self) -> &str {
            ""
        }
        fn tpm_signing_alg(&self) -> &str {
            ""
        }
        fn uefi_logs_evidence_version(&self) -> &str {
            ""
        }
        fn uuid(&self) -> &str {
            ""
        }
        fn verifier_url(&self) -> &str {
            ""
        }
    }

    #[test]
    fn test_create_registrar_tls_config_disabled() {
        // Test when TLS is disabled
        let config = MockConfig {
            tls_enabled: false,
            ca_cert: "".to_string(),
            client_cert: "".to_string(),
            client_key: "".to_string(),
            backoff_max_delay: None,
            backoff_max_retries: None,
            backoff_initial_delay: None,
        };

        let result = create_registrar_tls_config(&config, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_registrar_tls_config_enabled_complete() {
        // Test when TLS is enabled with all certificate paths
        let config = MockConfig {
            tls_enabled: true,
            ca_cert: "/path/to/ca.crt".to_string(),
            client_cert: "/path/to/client.crt".to_string(),
            client_key: "/path/to/client.key".to_string(),
            backoff_max_delay: None,
            backoff_max_retries: None,
            backoff_initial_delay: None,
        };

        let result = create_registrar_tls_config(&config, 5000);
        assert!(result.is_some());

        let tls_config = result.unwrap();
        assert_eq!(tls_config.ca_cert, Some("/path/to/ca.crt".to_string()));
        assert_eq!(
            tls_config.client_cert,
            Some("/path/to/client.crt".to_string())
        );
        assert_eq!(
            tls_config.client_key,
            Some("/path/to/client.key".to_string())
        );
        assert_eq!(tls_config.timeout, Some(5000));
        assert_eq!(tls_config.insecure, None);
    }

    #[test]
    fn test_create_registrar_tls_config_enabled_no_certs() {
        // Test when TLS is enabled but no certificate paths are provided
        let config = MockConfig {
            tls_enabled: true,
            ca_cert: "".to_string(),
            client_cert: "".to_string(),
            client_key: "".to_string(),
            backoff_max_delay: None,
            backoff_max_retries: None,
            backoff_initial_delay: None,
        };

        let result = create_registrar_tls_config(&config, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_registrar_tls_config_partial_one_cert() {
        // Test when TLS is enabled with only 1 certificate path (partial config)
        let config = MockConfig {
            tls_enabled: true,
            ca_cert: "/path/to/ca.crt".to_string(),
            client_cert: "".to_string(),
            client_key: "".to_string(),
            backoff_max_delay: None,
            backoff_max_retries: None,
            backoff_initial_delay: None,
        };

        let result = create_registrar_tls_config(&config, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_registrar_tls_config_partial_two_certs() {
        // Test when TLS is enabled with only 2 certificate paths (partial config)
        let config = MockConfig {
            tls_enabled: true,
            ca_cert: "/path/to/ca.crt".to_string(),
            client_cert: "/path/to/client.crt".to_string(),
            client_key: "".to_string(),
            backoff_max_delay: None,
            backoff_max_retries: None,
            backoff_initial_delay: None,
        };

        let result = create_registrar_tls_config(&config, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_registrar_tls_config_partial_different_combo() {
        // Test another partial config combination (ca_cert and client_key only)
        let config = MockConfig {
            tls_enabled: true,
            ca_cert: "/path/to/ca.crt".to_string(),
            client_cert: "".to_string(),
            client_key: "/path/to/client.key".to_string(),
            backoff_max_delay: None,
            backoff_max_retries: None,
            backoff_initial_delay: None,
        };

        let result = create_registrar_tls_config(&config, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_registrar_tls_config_custom_timeout() {
        // Test that custom timeout is properly set
        let config = MockConfig {
            tls_enabled: true,
            ca_cert: "/path/to/ca.crt".to_string(),
            client_cert: "/path/to/client.crt".to_string(),
            client_key: "/path/to/client.key".to_string(),
            backoff_max_delay: None,
            backoff_max_retries: None,
            backoff_initial_delay: None,
        };

        let result = create_registrar_tls_config(&config, 10000);
        assert!(result.is_some());

        let tls_config = result.unwrap();
        assert_eq!(tls_config.timeout, Some(10000));
    }

    #[actix_rt::test]
    async fn run_test() {
        // Set arguments to avoid TPM
        let args = Args {
            api_version: None,
            avoid_tpm: Some(true),
            registrar_url: "".to_string(),
            verifier_url: Some("".to_string()),
            timeout: 0,
            ca_certificate: "".to_string(),
            certificate: "".to_string(),
            key: "".to_string(),
            insecure: None,
            agent_identifier: None,
            json_file: None,
            message_type: None,
            method: None,
            attestation_index: None,
            session_index: None,
            attestation_interval_seconds:
                DEFAULT_ATTESTATION_INTERVAL_SECONDS,
        };

        // Create mock privileged resources with missing files (None for both handles)
        let config = keylime::config::get_config();
        let privileged_resources =
            privileged_resources::PrivilegedResources::new(config)
                .expect("Failed to create privileged resources");

        let res = run(&args, privileged_resources);
        assert!(res.await.is_err());
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn avoid_tpm_test() {
        // Set arguments to avoid TPM
        let args = Args {
            api_version: None,
            avoid_tpm: Some(true),
            registrar_url: "".to_string(),
            verifier_url: Some("".to_string()),
            timeout: 0,
            ca_certificate: "".to_string(),
            certificate: "".to_string(),
            key: "".to_string(),
            insecure: None,
            agent_identifier: None,
            json_file: None,
            message_type: None,
            method: None,
            attestation_index: None,
            session_index: None,
            attestation_interval_seconds:
                DEFAULT_ATTESTATION_INTERVAL_SECONDS,
        };
        let avoid_tpm = get_avoid_tpm_from_args(&args);
        assert!(avoid_tpm);
    }
}
