// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use crate::config;
use crate::error::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use keylime::{
    crypto::{self, x509::CertificateBuilder},
    registrar_client::RegistrarClientBuilder,
    tpm::{self, IAKResult, IDevIDResult},
};
use log::{error, info};
use openssl::x509::X509;
use tss_esapi::handles::KeyHandle;
use tss_esapi::structures::PublicBuffer;
use tss_esapi::traits::Marshall;

#[derive(Debug)]
pub struct AgentRegistration {
    pub ak: tpm::AKResult,
    pub ek_result: tpm::EKResult,
    pub api_versions: Vec<String>,
    pub agent: config::AgentConfig,
    pub agent_uuid: String,
    pub mtls_cert: Option<X509>,
    pub device_id: Option<keylime::device_id::DeviceID>,
    pub attest: Option<tss_esapi::structures::Attest>,
    pub signature: Option<tss_esapi::structures::Signature>,
    pub ak_handle: KeyHandle,
}

pub async fn register_agent(
    mut aa: AgentRegistration,
    mut ctx: &mut tpm::Context<'_>,
) -> Result<()> {
    let iak_pub;
    let idevid_pub;
    let ak_pub = &PublicBuffer::try_from(aa.ak.public)?.marshall()?;
    let ek_pub =
        &PublicBuffer::try_from(aa.ek_result.public.clone())?.marshall()?;

    // Create a RegistrarClientBuilder and set the parameters
    let mut builder = RegistrarClientBuilder::new()
        .ak_pub(ak_pub)
        .ek_pub(ek_pub)
        .enabled_api_versions(
            aa.api_versions.iter().map(|ver| ver.as_ref()).collect(),
        )
        .registrar_ip(aa.agent.registrar_ip.clone())
        .registrar_port(aa.agent.registrar_port)
        .uuid(&aa.agent_uuid)
        .ip(aa.agent.contact_ip.clone())
        .port(aa.agent.contact_port);

    if let Some(mtls_cert) = aa.mtls_cert {
        builder = builder.mtls_cert(mtls_cert);
    }

    // If the certificate is not None add it to the builder
    if let Some(ekchain) = aa.ek_result.to_pem() {
        builder = builder.ek_cert(ekchain);
    }

    // Set the IAK/IDevID related fields, if enabled
    if aa.agent.enable_iak_idevid {
        let (Some(dev_id), Some(attest), Some(signature)) =
            (&aa.device_id, aa.attest, aa.signature)
        else {
            error!("IDevID and IAK are enabled but could not be generated");
            return Err(Error::Configuration(
                config::KeylimeConfigError::Generic(
                    "IDevID and IAK are enabled but could not be generated"
                        .to_string(),
                ),
            ));
        };

        iak_pub =
            PublicBuffer::try_from(dev_id.iak_pubkey.clone())?.marshall()?;
        idevid_pub = PublicBuffer::try_from(dev_id.idevid_pubkey.clone())?
            .marshall()?;
        builder = builder
            .iak_attest(attest.marshall()?)
            .iak_sign(signature.marshall()?)
            .iak_pub(&iak_pub)
            .idevid_pub(&idevid_pub);

        // If the IAK certificate was provided, set it
        if let Some(iak_cert) = dev_id.iak_cert.clone() {
            builder = builder.iak_cert(iak_cert);
        }

        // If the IDevID certificate was provided, set it
        if let Some(idevid_cert) = dev_id.idevid_cert.clone() {
            builder = builder.idevid_cert(idevid_cert);
        }
    }

    // Build the registrar client
    let mut registrar_client = builder.build().await?;

    // Request keyblob material
    let keyblob = registrar_client.register_agent().await?;

    info!("SUCCESS: Agent {} registered", &aa.agent_uuid);

    let key = ctx.activate_credential(
        keyblob,
        aa.ak_handle,
        aa.ek_result.key_handle,
    )?;

    // Flush EK if we created it
    if aa.agent.ek_handle.is_empty() {
        ctx.flush_context(aa.ek_result.key_handle.into())?;
    }

    let mackey = general_purpose::STANDARD.encode(key.value());
    let auth_tag =
        crypto::compute_hmac(mackey.as_bytes(), aa.agent_uuid.as_bytes())?;
    let auth_tag = hex::encode(&auth_tag);

    registrar_client.activate_agent(&auth_tag).await?;

    info!("SUCCESS: Agent {} activated", &aa.agent_uuid);
    Ok(())
}
