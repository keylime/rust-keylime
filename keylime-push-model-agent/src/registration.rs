use keylime::agent_data::AgentData;
use keylime::agent_registration::{
    AgentRegistration, AgentRegistrationConfig,
};
use keylime::cert;
use keylime::config::PushModelConfigTrait;
use keylime::hash_ek;
use keylime::keylime_error::Result;
use keylime::tpm;
use log::debug;

pub async fn check_registration(avoid_registration: &bool) -> Result<()> {
    if !*avoid_registration {
        let reg_config = keylime::config::PushModelConfig::default();
        debug!("Registering agent with config: {}", reg_config.display());
        crate::registration::register_agent(&reg_config).await?;
    }
    Ok(())
}

pub async fn register_agent<T: PushModelConfigTrait>(
    config: &T,
) -> Result<()> {
    let tpm_encryption_alg =
        keylime::algorithms::EncryptionAlgorithm::try_from(
            config.get_tpm_encryption_alg().as_ref(),
        )?;
    let tpm_hash_alg = keylime::algorithms::HashAlgorithm::try_from(
        config.get_tpm_hash_alg().as_ref(),
    )?;
    let tpm_signing_alg = keylime::algorithms::SignAlgorithm::try_from(
        config.get_tpm_signing_alg().as_ref(),
    )?;
    let mut ctx = tpm::Context::new()?;
    let ek_result = ctx.create_ek(tpm_encryption_alg, None)?;
    let ek_hash = hash_ek::hash_ek_pubkey(ek_result.public.clone())?;
    let ak =
        ctx.create_ak(ek_result.key_handle, tpm_hash_alg, tpm_signing_alg)?;
    let ak_handle = ctx.load_ak(ek_result.key_handle, &ak)?;

    AgentData::create(
        tpm_hash_alg,
        tpm_signing_alg,
        &ak,
        ek_hash.as_bytes(),
    )?;

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
        ak,
        ek_result,
        api_versions: config.get_registrar_api_versions(),
        agent_registration_config: ac,
        agent_uuid: config.get_uuid(),
        mtls_cert: Some(server_cert_key.0),
        device_id: None, // TODO: Check how to proceed with device ID
        attest: None, // TODO: Check how to proceed with attestation, normally, no device ID means no attest
        signature: None, // TODO: Normally, no device ID means no signature
        ak_handle,
    };
    match keylime::agent_registration::register_agent(aa, &mut ctx).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
} // register_agent

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_avoid_registration() {
        let avoid_registration = true;
        let result = check_registration(&avoid_registration).await;
        assert!(result.is_ok());
    }
}
