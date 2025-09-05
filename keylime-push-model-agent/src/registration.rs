use keylime::{
    agent_registration::{
        AgentRegistration, AgentRegistrationConfig, RetryConfig,
    },
    cert,
    config::PushModelConfigTrait,
    context_info,
    error::Result,
};

pub async fn check_registration(
    context_info: Option<context_info::ContextInfo>,
) -> Result<()> {
    if context_info.is_some() {
        crate::registration::register_agent(&mut context_info.unwrap()) //#[allow_ci]
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
) -> Result<()> {
    let config = keylime::config::get_config();

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
        let result = check_registration(None).await;
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
            disabled_signing_algorithms: vec![],
        };
        config.exponential_backoff_initial_delay = None;
        config.exponential_backoff_max_retries = None;
        config.exponential_backoff_max_delay = None;

        // Create guard that will automatically clear override when dropped
        let _guard = keylime::config::TestConfigGuard::new(config);

        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");
        let result = register_agent(&mut context_info).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }
}
