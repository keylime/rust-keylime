use keylime::{
    agent_registration::{AgentRegistration, AgentRegistrationConfig},
    cert,
    config::PushModelConfigTrait,
    context_info,
    error::Result,
};

pub async fn check_registration(
    context_info: Option<context_info::ContextInfo>,
) -> Result<()> {
    let reg_config = keylime::config::PushModelConfig::default();
    if context_info.is_some() {
        crate::registration::register_agent(
            &reg_config,
            &mut context_info.unwrap(),
        )
        .await?;
    }
    Ok(())
}

pub async fn register_agent<T: PushModelConfigTrait>(
    config: &T,
    context_info: &mut context_info::ContextInfo,
) -> Result<()> {
    let ac = AgentRegistrationConfig {
        contact_ip: config.get_contact_ip(),
        contact_port: config.get_contact_port(),
        registrar_ip: config.get_registrar_ip(),
        registrar_port: config.get_registrar_port(),
        enable_iak_idevid: config.get_enable_iak_idevid(),
        ek_handle: config.get_ek_handle(),
    };

    let cert_config = cert::CertificateConfig {
        agent_uuid: config.get_uuid(),
        contact_ip: config.get_contact_ip(),
        contact_port: config.get_contact_port(),
        server_cert: config.get_server_cert(),
        server_key: config.get_server_key(),
        server_key_password: config.get_server_key_password(),
    };

    let server_cert_key = cert::cert_from_server_key(&cert_config)?;

    let aa = AgentRegistration {
        ak: context_info.ak.clone(),
        ek_result: context_info.ek_result.clone(),
        api_versions: config.get_registrar_api_versions(),
        agent_registration_config: ac,
        agent_uuid: config.get_uuid(),
        mtls_cert: Some(server_cert_key.0),
        device_id: None, // TODO: Check how to proceed with device ID
        attest: None, // TODO: Check how to proceed with attestation, normally, no device ID means no attest
        signature: None, // TODO: Normally, no device ID means no signature
        ak_handle: context_info.ak_handle,
    };
    let ctx = context_info.get_mutable_tpm_context();
    match keylime::agent_registration::register_agent(aa, ctx).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
} // register_agent

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "testing")]
    use keylime::context_info::{AlgorithmConfigurationString, ContextInfo};

    #[actix_rt::test]
    async fn test_avoid_registration() {
        let result = check_registration(None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_register_agent() {
        use keylime::tpm::testing;
        let _mutex = testing::lock_tests().await;
        let config = keylime::config::PushModelConfig::default();
        let alg_config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };
        let mut context_info = ContextInfo::new_from_str(alg_config)
            .expect("Failed to create context info from string");
        let result = register_agent(&config, &mut context_info).await;
        assert!(result.is_err());
        assert!(context_info.flush_context().is_ok());
    }
}
