use crate::{
    config::*,
    list_parser::{parse_list, ListParsingError},
};
use keylime_macros::define_view_trait;
use log::*;
use thiserror::Error;

//TODO Temporary
#[derive(Debug, Error)]
pub enum OverrideError {
    /// List parsing error
    #[error("List parsing error")]
    ListParsing(#[from] ListParsingError),
}

//TODO Temporary
fn override_default_api_versions(
    _input: &str,
) -> Result<Vec<&str>, OverrideError> {
    warn!("Overriding default API versions for push model");
    Ok(DEFAULT_PUSH_API_VERSIONS.into())
}

//TODO Temporary
fn override_default_ek_handle(_input: &str) -> Result<String, OverrideError> {
    warn!("Overriding default EK handle for push model");
    Ok(DEFAULT_PUSH_EK_HANDLE.into())
}

#[define_view_trait(for_struct = "AgentConfig")]
pub struct PushModelConfig {
    agent_data_path: String,
    #[transform(using = override_default_api_versions, error = OverrideError)]
    api_versions: Vec<&str>,
    attestation_interval_seconds: u64,
    certification_keys_server_identifier: String,
    contact_ip: String,
    contact_port: u32,
    enable_authentication: bool,
    exponential_backoff_max_delay: Option<u64>,
    exponential_backoff_max_retries: Option<u32>,
    exponential_backoff_initial_delay: Option<u64>,
    enable_iak_idevid: bool,
    #[transform(using = override_default_ek_handle, error = OverrideError)]
    ek_handle: String,
    ima_ml_count_file: String,
    measuredboot_ml_path: String,
    #[transform(using = parse_list, error = ListParsingError)]
    registrar_api_versions: Vec<&str>,
    registrar_ip: String,
    registrar_port: u32,
    registrar_tls_enabled: bool,
    registrar_tls_ca_cert: String,
    registrar_tls_client_cert: String,
    registrar_tls_client_key: String,
    server_cert: String,
    server_key: String,
    server_key_password: String,
    tpm_encryption_alg: String,
    tpm_hash_alg: String,
    tpm_signing_alg: String,
    uefi_logs_evidence_version: String,
    uuid: String,
    verifier_url: String,
    verifier_tls_ca_cert: String,
    verifier_tls_client_cert: String,
    verifier_tls_client_key: String,
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::get_testing_config;

    #[test]
    fn test_push_model_trait() {
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = get_testing_config(tmpdir.path(), None);
        assert_eq!(
            config.certification_keys_server_identifier(),
            DEFAULT_CERTIFICATION_KEYS_SERVER_IDENTIFIER
        );
        assert_eq!(
            config.agent_data_path(),
            tmpdir
                .path()
                .join(DEFAULT_AGENT_DATA_PATH)
                .display()
                .to_string()
        );
        assert_eq!(config.contact_ip(), DEFAULT_CONTACT_IP);
        assert_eq!(config.contact_port(), DEFAULT_CONTACT_PORT);
        assert_eq!(
            config.ek_handle().expect("Failed to get ek_handle()"),
            DEFAULT_PUSH_EK_HANDLE
        );
        assert_eq!(config.enable_iak_idevid(), DEFAULT_ENABLE_IAK_IDEVID);
        assert_eq!(config.ima_ml_count_file(), DEFAULT_IMA_ML_COUNT_FILE);
        assert_eq!(config.registrar_ip(), DEFAULT_REGISTRAR_IP);
        assert_eq!(config.registrar_port(), DEFAULT_REGISTRAR_PORT);
        assert_eq!(
            config.server_cert(),
            tmpdir
                .path()
                .join(DEFAULT_SERVER_CERT)
                .display()
                .to_string()
        );
        assert_eq!(
            config.server_key(),
            tmpdir.path().join(DEFAULT_SERVER_KEY).display().to_string()
        );
        assert_eq!(config.server_key_password(), DEFAULT_SERVER_KEY_PASSWORD);
        assert_eq!(
            config.uefi_logs_evidence_version(),
            DEFAULT_UEFI_LOGS_EVIDENCE_VERSION
        );
        assert_eq!(config.tpm_encryption_alg(), DEFAULT_TPM_ENCRYPTION_ALG);
        assert_eq!(config.tpm_hash_alg(), DEFAULT_TPM_HASH_ALG);
        assert_eq!(config.tpm_signing_alg(), DEFAULT_TPM_SIGNING_ALG);
        assert_eq!(
            config
                .api_versions()
                .expect("failed to parse api_versions")
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>(),
            DEFAULT_PUSH_API_VERSIONS
        );
        assert_eq!(
            config
                .registrar_api_versions()
                .expect("failed to parse registrar_api_versions")
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>(),
            DEFAULT_REGISTRAR_API_VERSIONS
        );
        assert_eq!(config.uuid(), DEFAULT_UUID);
        assert_eq!(config.verifier_url(), DEFAULT_VERIFIER_URL);
        assert_eq!(
            config.attestation_interval_seconds(),
            DEFAULT_ATTESTATION_INTERVAL_SECONDS
        );
    } // create_default_config_test

    #[test]
    fn test_attestation_interval_seconds_custom() {
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);

        // Modify to use a custom attestation interval
        config.attestation_interval_seconds = 5;

        assert_eq!(config.attestation_interval_seconds(), 5);

        // Verify it's different from default
        assert_ne!(
            config.attestation_interval_seconds(),
            DEFAULT_ATTESTATION_INTERVAL_SECONDS
        );
    }

    #[test]
    fn test_enable_authentication_default() {
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = get_testing_config(tmpdir.path(), None);

        // Verify default is false (disabled)
        assert_eq!(
            config.enable_authentication(),
            DEFAULT_ENABLE_AUTHENTICATION
        );
        assert!(!config.enable_authentication());
    }

    #[test]
    fn test_enable_authentication_custom() {
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);

        // Enable authentication
        config.enable_authentication = true;

        assert!(config.enable_authentication());

        // Verify it's different from default
        assert_ne!(
            config.enable_authentication(),
            DEFAULT_ENABLE_AUTHENTICATION
        );
    }

    #[test]
    fn test_verifier_tls_cert_paths_default() {
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = get_testing_config(tmpdir.path(), None);

        // Verify default paths are resolved correctly relative to keylime_dir
        assert_eq!(
            config.verifier_tls_ca_cert(),
            tmpdir
                .path()
                .join(DEFAULT_VERIFIER_TLS_CA_CERT)
                .display()
                .to_string()
        );
        assert_eq!(
            config.verifier_tls_client_cert(),
            tmpdir
                .path()
                .join(DEFAULT_VERIFIER_TLS_CLIENT_CERT)
                .display()
                .to_string()
        );
        assert_eq!(
            config.verifier_tls_client_key(),
            tmpdir
                .path()
                .join(DEFAULT_VERIFIER_TLS_CLIENT_KEY)
                .display()
                .to_string()
        );
    }
}
