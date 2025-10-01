use keylime::{
    agent_registration::{
        AgentRegistration, AgentRegistrationConfig, RetryConfig,
    },
    cert,
    config::PushModelConfigTrait,
    context_info,
    error::Result,
};

pub struct RegistrarTlsConfig {
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub insecure: Option<bool>,
    pub timeout: Option<u64>,
}

pub async fn check_registration(
    context_info: Option<context_info::ContextInfo>,
    tls_config: Option<RegistrarTlsConfig>,
) -> Result<()> {
    if context_info.is_some() {
        crate::registration::register_agent(
            &mut context_info.unwrap(),
            tls_config,
        )
        .await?;
    }
    Ok(())
}

fn get_retry_config() -> Option<RetryConfig> {
    let config = keylime::config::get_config();

    if config.exponential_backoff_max_retries().is_none()
        && config.exponential_backoff_initial_delay().is_none()
        && config.exponential_backoff_max_delay().is_none()
    {
        None
    } else {
        Some(RetryConfig {
            max_retries: config
                .exponential_backoff_max_retries()
                .unwrap_or(0),
            initial_delay_ms: config
                .exponential_backoff_initial_delay()
                .unwrap_or(0),
            max_delay_ms: *config.exponential_backoff_max_delay(),
        })
    }
}

pub async fn register_agent(
    context_info: &mut context_info::ContextInfo,
    tls_config: Option<RegistrarTlsConfig>,
) -> Result<()> {
    let config = keylime::config::get_config();

    let (ca_cert, client_cert, client_key, insecure, timeout) =
        if let Some(tls) = tls_config {
            (
                tls.ca_cert,
                tls.client_cert,
                tls.client_key,
                tls.insecure,
                tls.timeout,
            )
        } else {
            (None, None, None, None, None)
        };

    let ac = AgentRegistrationConfig {
        contact_ip: config.contact_ip().to_string(),
        contact_port: config.contact_port(),
        registrar_ip: config.registrar_ip().to_string(),
        registrar_port: config.registrar_port(),
        enable_iak_idevid: config.enable_iak_idevid(),
        // TODO: make it to not panic on failure
        ek_handle: config
            .ek_handle()
            .expect("failed to get ek_handle")
            .to_string(),
        registrar_ca_cert: ca_cert,
        registrar_client_cert: client_cert,
        registrar_client_key: client_key,
        registrar_insecure: insecure,
        registrar_timeout: timeout,
    };

    let cert_config = cert::CertificateConfig {
        agent_uuid: config.uuid().to_string(),
        contact_ip: config.contact_ip().to_string(),
        contact_port: config.contact_port(),
        server_cert: config.server_cert().to_string(),
        server_key: config.server_key().to_string(),
        server_key_password: config.server_key_password().to_string(),
    };

    let server_cert_key = cert::cert_from_server_key(&cert_config)?;

    let retry_config = get_retry_config();

    let aa = AgentRegistration {
        ak: context_info.ak.clone(),
        ek_result: context_info.ek_result.clone(),
        api_versions: config
            .registrar_api_versions()?
            .iter()
            .map(|e| e.to_string())
            .collect(),
        agent_registration_config: ac,
        agent_uuid: config.uuid().to_string(),
        mtls_cert: Some(server_cert_key.0),
        device_id: None, // TODO: Check how to proceed with device ID
        attest: None, // TODO: Check how to proceed with attestation, normally, no device ID means no attest
        signature: None, // TODO: Normally, no device ID means no signature
        ak_handle: context_info.ak_handle,
        retry_config,
    };
    let ctx = context_info.get_mutable_tpm_context();
    match keylime::agent_registration::register_agent(aa, ctx).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
} // register_agent

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;

    use keylime::{
        config::get_testing_config,
        context_info::{AlgorithmConfigurationString, ContextInfo},
        tpm::testing,
    };

    #[actix_rt::test]
    async fn test_avoid_registration() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
        let _config = get_testing_config(tmpdir.path(), None);
        let result = check_registration(None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_agent() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };
        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;
        // Use an invalid registrar address to guarantee failure
        config.registrar_ip = "127.0.0.1".to_string();
        config.registrar_port = 1; // Invalid port to ensure connection fails

        // Create guard that will automatically clear override when dropped
        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");
        let result = register_agent(&mut context_info, None).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }

    #[actix_rt::test]
    async fn test_registrar_tls_config_creation() {
        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: Some(false),
            timeout: Some(5000),
        };

        assert_eq!(tls_config.ca_cert, Some("/path/to/ca.pem".to_string()));
        assert_eq!(
            tls_config.client_cert,
            Some("/path/to/cert.pem".to_string())
        );
        assert_eq!(
            tls_config.client_key,
            Some("/path/to/key.pem".to_string())
        );
        assert_eq!(tls_config.insecure, Some(false));
        assert_eq!(tls_config.timeout, Some(5000));
    }

    #[actix_rt::test]
    async fn test_registrar_tls_config_all_none() {
        let tls_config = RegistrarTlsConfig {
            ca_cert: None,
            client_cert: None,
            client_key: None,
            insecure: None,
            timeout: None,
        };

        assert_eq!(tls_config.ca_cert, None);
        assert_eq!(tls_config.client_cert, None);
        assert_eq!(tls_config.client_key, None);
        assert_eq!(tls_config.insecure, None);
        assert_eq!(tls_config.timeout, None);
    }

    #[actix_rt::test]
    async fn test_registrar_tls_config_partial() {
        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: None,
            client_key: None,
            insecure: Some(true),
            timeout: Some(10000),
        };

        assert_eq!(tls_config.ca_cert, Some("/path/to/ca.pem".to_string()));
        assert_eq!(tls_config.client_cert, None);
        assert_eq!(tls_config.client_key, None);
        assert_eq!(tls_config.insecure, Some(true));
        assert_eq!(tls_config.timeout, Some(10000));
    }

    #[actix_rt::test]
    async fn test_registrar_tls_config_empty_strings() {
        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("".to_string()),
            client_cert: Some("".to_string()),
            client_key: Some("".to_string()),
            insecure: Some(false),
            timeout: Some(0),
        };

        assert_eq!(tls_config.ca_cert, Some("".to_string()));
        assert_eq!(tls_config.client_cert, Some("".to_string()));
        assert_eq!(tls_config.client_key, Some("".to_string()));
        assert_eq!(tls_config.insecure, Some(false));
        assert_eq!(tls_config.timeout, Some(0));
    }

    #[actix_rt::test]
    async fn test_check_registration_with_none_context() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
        let _config = get_testing_config(tmpdir.path(), None);

        // Test with None context_info and None tls_config
        let result = check_registration(None, None).await;
        assert!(result.is_ok());
    }

    #[actix_rt::test]
    async fn test_check_registration_with_tls_config_none_context() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
        let _config = get_testing_config(tmpdir.path(), None);

        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: Some(false),
            timeout: Some(5000),
        };

        // Test with None context_info but Some tls_config (should not register)
        let result = check_registration(None, Some(tls_config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_agent_with_tls_config() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;
        config.registrar_ip = "127.0.0.1".to_string();
        config.registrar_port = 1; // Invalid port to ensure connection fails

        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");

        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: Some(false),
            timeout: Some(5000),
        };

        let result =
            register_agent(&mut context_info, Some(tls_config)).await;
        assert!(result.is_err()); // Should fail due to invalid port
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_register_agent_with_partial_tls_config() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;
        config.registrar_ip = "127.0.0.1".to_string();
        config.registrar_port = 1;

        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");

        // Test with only CA cert
        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: None,
            client_key: None,
            insecure: None,
            timeout: Some(5000),
        };

        let result =
            register_agent(&mut context_info, Some(tls_config)).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_register_agent_with_insecure_tls() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;
        config.registrar_ip = "127.0.0.1".to_string();
        config.registrar_port = 1;

        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");

        // Test with insecure=true
        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: Some(true),
            timeout: Some(5000),
        };

        let result =
            register_agent(&mut context_info, Some(tls_config)).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }

    #[actix_rt::test]
    async fn test_get_retry_config_all_none() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;

        let _guard = keylime::config::TestConfigGuard::new(config);

        let retry_config = get_retry_config();
        assert!(retry_config.is_none());
    }

    #[actix_rt::test]
    async fn test_get_retry_config_with_values() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        config.exponential_backoff_initial_delay = Some(100);
        config.exponential_backoff_max_retries = Some(5);
        config.exponential_backoff_max_delay = Some(2000);

        let _guard = keylime::config::TestConfigGuard::new(config);

        let retry_config = get_retry_config();
        assert!(retry_config.is_some());
        let retry = retry_config.unwrap(); //#[allow_ci]
        assert_eq!(retry.initial_delay_ms, 100);
        assert_eq!(retry.max_retries, 5);
        assert_eq!(retry.max_delay_ms, Some(2000));
    }

    #[actix_rt::test]
    async fn test_get_retry_config_partial() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tempdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        config.exponential_backoff_initial_delay = Some(200);
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;

        let _guard = keylime::config::TestConfigGuard::new(config);

        let retry_config = get_retry_config();
        assert!(retry_config.is_some());
        let retry = retry_config.unwrap(); //#[allow_ci]
        assert_eq!(retry.initial_delay_ms, 200);
        assert_eq!(retry.max_retries, 0);
        assert_eq!(retry.max_delay_ms, None);
    }

    #[actix_rt::test]
    async fn test_registrar_tls_config_with_different_timeout_values() {
        // Test with zero timeout
        let tls_config_zero = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: None,
            timeout: Some(0),
        };
        assert_eq!(tls_config_zero.timeout, Some(0));

        // Test with large timeout
        let tls_config_large = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: None,
            timeout: Some(300000),
        };
        assert_eq!(tls_config_large.timeout, Some(300000));

        // Test with None timeout
        let tls_config_none = RegistrarTlsConfig {
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: None,
            timeout: None,
        };
        assert_eq!(tls_config_none.timeout, None);
    }

    #[actix_rt::test]
    async fn test_tls_config_extraction_some() {
        let tls_config = Some(RegistrarTlsConfig {
            ca_cert: Some("/ca.pem".to_string()),
            client_cert: Some("/cert.pem".to_string()),
            client_key: Some("/key.pem".to_string()),
            insecure: Some(false),
            timeout: Some(5000),
        });

        let (ca_cert, client_cert, client_key, insecure, timeout) =
            if let Some(tls) = tls_config {
                (
                    tls.ca_cert,
                    tls.client_cert,
                    tls.client_key,
                    tls.insecure,
                    tls.timeout,
                )
            } else {
                (None, None, None, None, None)
            };

        assert_eq!(ca_cert, Some("/ca.pem".to_string()));
        assert_eq!(client_cert, Some("/cert.pem".to_string()));
        assert_eq!(client_key, Some("/key.pem".to_string()));
        assert_eq!(insecure, Some(false));
        assert_eq!(timeout, Some(5000));
    }

    #[actix_rt::test]
    async fn test_tls_config_extraction_none() {
        let tls_config: Option<RegistrarTlsConfig> = None;

        let (ca_cert, client_cert, client_key, insecure, timeout) =
            if let Some(tls) = tls_config {
                (
                    tls.ca_cert,
                    tls.client_cert,
                    tls.client_key,
                    tls.insecure,
                    tls.timeout,
                )
            } else {
                (None, None, None, None, None)
            };

        assert_eq!(ca_cert, None);
        assert_eq!(client_cert, None);
        assert_eq!(client_key, None);
        assert_eq!(insecure, None);
        assert_eq!(timeout, None);
    }

    // Helper function to generate test certificates
    #[cfg(test)]
    fn generate_test_tls_certificates(
        temp_dir: &std::path::Path,
    ) -> (String, String, String) {
        use keylime::crypto;
        use std::fs::File;
        use std::io::Write;

        let ca_path = temp_dir.join("ca.pem");
        let cert_path = temp_dir.join("cert.pem");
        let key_path = temp_dir.join("key.pem");

        // Generate CA certificate
        let ca_key = crypto::testing::rsa_generate(2048)
            .expect("Failed to generate CA key");
        let ca_cert = crypto::x509::CertificateBuilder::new()
            .private_key(&ca_key)
            .common_name("Test Registrar CA")
            .build()
            .expect("Failed to build CA cert");

        // Generate client certificate
        let client_key = crypto::testing::rsa_generate(2048)
            .expect("Failed to generate client key");
        let client_cert = crypto::x509::CertificateBuilder::new()
            .private_key(&client_key)
            .common_name("test-agent")
            .build()
            .expect("Failed to build client cert");

        // Write certificates to files
        let mut ca_file =
            File::create(&ca_path).expect("Failed to create CA file");
        ca_file
            .write_all(
                &ca_cert.to_pem().expect("Failed to convert CA to PEM"),
            )
            .expect("Failed to write CA cert");

        let mut cert_file =
            File::create(&cert_path).expect("Failed to create cert file");
        cert_file
            .write_all(
                &client_cert.to_pem().expect("Failed to convert cert to PEM"),
            )
            .expect("Failed to write cert");

        let mut key_file =
            File::create(&key_path).expect("Failed to create key file");
        key_file
            .write_all(
                &client_key
                    .private_key_to_pem_pkcs8()
                    .expect("Failed to convert key to PEM"),
            )
            .expect("Failed to write key");

        (
            ca_path.to_string_lossy().to_string(),
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
    }

    #[tokio::test]
    async fn test_register_agent_with_real_tls_certs() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let (ca_path, cert_path, key_path) =
            generate_test_tls_certificates(tmpdir.path());

        // Verify files were created
        assert!(std::path::Path::new(&ca_path).exists());
        assert!(std::path::Path::new(&cert_path).exists());
        assert!(std::path::Path::new(&key_path).exists());

        let mut config = get_testing_config(tmpdir.path(), None);
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;
        config.registrar_ip = "127.0.0.1".to_string();
        config.registrar_port = 1; // Invalid port to ensure connection fails

        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");

        let tls_config = RegistrarTlsConfig {
            ca_cert: Some(ca_path),
            client_cert: Some(cert_path),
            client_key: Some(key_path),
            insecure: Some(false),
            timeout: Some(5000),
        };

        // Should fail due to invalid port, but TLS config should be processed
        let result =
            register_agent(&mut context_info, Some(tls_config)).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_register_agent_with_nonexistent_tls_certs() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;
        config.registrar_ip = "127.0.0.1".to_string();
        config.registrar_port = 8891;

        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");

        // Use paths to non-existent certificate files
        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("/nonexistent/ca.pem".to_string()),
            client_cert: Some("/nonexistent/cert.pem".to_string()),
            client_key: Some("/nonexistent/key.pem".to_string()),
            insecure: Some(false),
            timeout: Some(5000),
        };

        // Should fail due to missing certificate files
        let result =
            register_agent(&mut context_info, Some(tls_config)).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }

    #[actix_rt::test]
    async fn test_tls_config_all_fields_set() {
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let (ca_path, cert_path, key_path) =
            generate_test_tls_certificates(tmpdir.path());

        let tls_config = RegistrarTlsConfig {
            ca_cert: Some(ca_path.clone()),
            client_cert: Some(cert_path.clone()),
            client_key: Some(key_path.clone()),
            insecure: Some(false),
            timeout: Some(10000),
        };

        // Verify all fields are set correctly
        assert_eq!(tls_config.ca_cert, Some(ca_path));
        assert_eq!(tls_config.client_cert, Some(cert_path));
        assert_eq!(tls_config.client_key, Some(key_path));
        assert_eq!(tls_config.insecure, Some(false));
        assert_eq!(tls_config.timeout, Some(10000));
    }

    #[tokio::test]
    async fn test_register_agent_tls_with_empty_cert_paths() {
        let _mutex = testing::lock_tests().await;

        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let mut config = get_testing_config(tmpdir.path(), None);
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;
        config.registrar_ip = "127.0.0.1".to_string();
        config.registrar_port = 1;

        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");

        // Empty paths should result in HTTP fallback
        let tls_config = RegistrarTlsConfig {
            ca_cert: Some("".to_string()),
            client_cert: Some("".to_string()),
            client_key: Some("".to_string()),
            insecure: Some(false),
            timeout: Some(5000),
        };

        let result =
            register_agent(&mut context_info, Some(tls_config)).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }
}
