// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use crate::{
    agent_identity::AgentIdentityBuilder,
    crypto::{self},
    device_id,
    error::{Error, Result},
    registrar_client::RegistrarClientBuilder,
    tpm::{self},
};
use base64::{engine::general_purpose, Engine as _};
use log::{error, info};
use openssl::x509::X509;
use tss_esapi::{
    handles::KeyHandle, structures::PublicBuffer, traits::Marshall,
};

#[derive(Debug)]
pub struct AgentRegistrationConfig {
    pub contact_ip: String,
    pub contact_port: u32,
    pub ek_handle: String,
    pub enable_iak_idevid: bool,
    pub registrar_ip: String,
    pub registrar_port: u32,
    pub registrar_ca_cert: Option<String>,
    pub registrar_client_cert: Option<String>,
    pub registrar_client_key: Option<String>,
    pub registrar_insecure: Option<bool>,
    pub registrar_timeout: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: Option<u64>,
}

#[derive(Debug)]
pub struct AgentRegistration {
    pub ak: tpm::AKResult,
    pub ek_result: tpm::EKResult,
    pub api_versions: Vec<String>,
    pub agent_registration_config: AgentRegistrationConfig,
    pub agent_uuid: String,
    pub mtls_cert: Option<X509>,
    pub device_id: Option<device_id::DeviceID>,
    pub attest: Option<tss_esapi::structures::Attest>,
    pub signature: Option<tss_esapi::structures::Signature>,
    pub ak_handle: KeyHandle,
    pub retry_config: Option<RetryConfig>,
}

pub async fn register_agent(
    aa: AgentRegistration,
    ctx: &mut tpm::Context<'_>,
) -> Result<()> {
    let iak_pub;
    let idevid_pub;
    let ak_pub = &PublicBuffer::try_from(aa.ak.public)?.marshall()?;
    let ek_pub =
        &PublicBuffer::try_from(aa.ek_result.public.clone())?.marshall()?;

    let mut ai_builder = AgentIdentityBuilder::new()
        .ak_pub(ak_pub)
        .ek_pub(ek_pub)
        .enabled_api_versions(
            aa.api_versions.iter().map(|ver| ver.as_ref()).collect(),
        )
        .uuid(&aa.agent_uuid)
        .ip(aa.agent_registration_config.contact_ip.clone())
        .port(aa.agent_registration_config.contact_port);

    if let Some(mtls_cert) = aa.mtls_cert {
        ai_builder = ai_builder.mtls_cert(mtls_cert);
    }

    // If the certificate is not None add it to the builder
    if let Some(ekchain) = aa.ek_result.to_pem() {
        ai_builder = ai_builder.ek_cert(ekchain);
    }

    // Set the IAK/IDevID related fields, if enabled
    if aa.agent_registration_config.enable_iak_idevid {
        let (Some(dev_id), Some(attest), Some(signature)) =
            (&aa.device_id, aa.attest, aa.signature)
        else {
            error!("IDevID and IAK are enabled but could not be generated");
            return Err(Error::ConfigurationGenericError(
                "IDevID and IAK are enabled but could not be generated"
                    .to_string(),
            ));
        };

        iak_pub =
            PublicBuffer::try_from(dev_id.iak_pubkey.clone())?.marshall()?;
        idevid_pub = PublicBuffer::try_from(dev_id.idevid_pubkey.clone())?
            .marshall()?;
        ai_builder = ai_builder
            .iak_attest(attest.marshall()?)
            .iak_sign(signature.marshall()?)
            .iak_pub(&iak_pub)
            .idevid_pub(&idevid_pub);

        // If the IAK certificate was provided, set it
        if let Some(iak_cert) = dev_id.iak_cert.clone() {
            ai_builder = ai_builder.iak_cert(iak_cert);
        }

        // If the IDevID certificate was provided, set it
        if let Some(idevid_cert) = dev_id.idevid_cert.clone() {
            ai_builder = ai_builder.idevid_cert(idevid_cert);
        }
    }

    // Build the Agent Identity
    let ai = ai_builder.build().await?;

    let ac = &aa.agent_registration_config;

    // Build the registrar client
    // Create a RegistrarClientBuilder and set the parameters
    let mut builder = RegistrarClientBuilder::new()
        .registrar_address(ac.registrar_ip.clone())
        .registrar_port(ac.registrar_port)
        .retry_config(aa.retry_config.clone());

    // Add TLS configuration if provided
    if let Some(ca_cert) = &ac.registrar_ca_cert {
        builder = builder.ca_certificate(ca_cert.clone());
    }
    if let Some(client_cert) = &ac.registrar_client_cert {
        builder = builder.certificate(client_cert.clone());
    }
    if let Some(client_key) = &ac.registrar_client_key {
        builder = builder.key(client_key.clone());
    }
    if let Some(insecure) = ac.registrar_insecure {
        builder = builder.insecure(insecure);
    }
    if let Some(timeout) = ac.registrar_timeout {
        builder = builder.timeout(timeout);
    }

    let mut registrar_client = builder.build().await?;

    // Request keyblob material
    let keyblob = registrar_client.register_agent(&ai).await?;

    info!("SUCCESS: Agent {} registered", &aa.agent_uuid);

    let key = ctx.activate_credential(
        keyblob,
        aa.ak_handle,
        aa.ek_result.key_handle,
    )?;

    // Flush EK if we created it
    if aa.agent_registration_config.ek_handle.is_empty() {
        ctx.flush_context(aa.ek_result.key_handle.into())?;
    }

    let mackey = general_purpose::STANDARD.encode(key.value());
    let auth_tag =
        crypto::compute_hmac(mackey.as_bytes(), aa.agent_uuid.as_bytes())?;
    let auth_tag = hex::encode(&auth_tag);

    registrar_client.activate_agent(&ai, &auth_tag).await?;

    info!("SUCCESS: Agent {} activated", &aa.agent_uuid);
    Ok(())
}
