use log::*;
use openssl::x509::X509;
use thiserror::Error;

use crate::crypto::{x509_to_der, x509_to_pem, CryptoError};

#[derive(Error, Debug)]
pub enum AgentIdentityBuilderError {
    /// Agent public AK not set
    #[error("Agent public AK not set")]
    AKPubNotSet,

    /// Agent contact IP or hostname not set
    #[error("Agent contact IP or hostname not set")]
    AgentContactIPNotSet,

    /// Agent port not set
    #[error("Agent port not set")]
    AgentPortNotSet,

    /// Agent UUID not set
    #[error("Agent UUID not set")]
    AgentUUIDNotSet,

    /// Failed to convert certificate type
    #[error("Failed to convert certificate type")]
    CertConvert(#[source] CryptoError),

    /// Agent public EK not set
    #[error("Agent public EK not set")]
    EKPubNotSet,

    /// Accepted API versions not set
    #[error("List of enabled API versions not set")]
    EnabledAPIVersionsNotSet,
}

#[derive(Debug, Default)]
pub struct AgentIdentityBuilder<'a> {
    ak_pub: Option<&'a [u8]>,
    ek_cert: Option<String>,
    ek_pub: Option<&'a [u8]>,
    enabled_api_versions: Option<Vec<&'a str>>,
    iak_attest: Option<Vec<u8>>,
    iak_cert: Option<X509>,
    iak_pub: Option<&'a [u8]>,
    iak_sign: Option<Vec<u8>>,
    idevid_cert: Option<X509>,
    idevid_pub: Option<&'a [u8]>,
    ip: Option<String>,
    mtls_cert: Option<X509>,
    port: Option<u32>,
    uuid: Option<&'a str>,
}

impl<'a> AgentIdentityBuilder<'a> {
    /// Create a new AgentIdentityBuilder object
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the public Attestation Key (AK)
    ///
    /// # Arguments:
    ///
    /// * ak_pub (&'a [u8]): The buffer containing the marshalled public AK
    pub fn ak_pub(mut self, ak_pub: &'a [u8]) -> Self {
        self.ak_pub = Some(ak_pub);
        self
    }

    /// Set the API versions that are enabled
    ///
    /// # Arguments:
    ///
    /// * api_versions (Vec<&'a str>): The enabled API versions
    pub fn enabled_api_versions(
        mut self,
        api_versions: Vec<&'a str>,
    ) -> Self {
        self.enabled_api_versions = Some(api_versions);
        self
    }

    /// Set the public Endorsement Key (EK)
    ///
    /// # Arguments:
    ///
    /// * ek_pub (&'a [u8]): The buffer containing the marshalled public EK
    pub fn ek_pub(mut self, ek_pub: &'a [u8]) -> Self {
        self.ek_pub = Some(ek_pub);
        self
    }

    /// Set the Endorsement Key (EK) certificate
    ///
    /// # Arguments:
    ///
    /// * ek_cert (String): A string containing the EK certificate in PEM format
    pub fn ek_cert(mut self, ek_cert: String) -> Self {
        self.ek_cert = Some(ek_cert);
        self
    }

    /// Set the IAK attestation evidence
    ///
    /// This is obtained by certifying the IAK with the AK
    ///
    /// # Arguments:
    ///
    /// * iak_attest (Vec<u8>): A vector containing the IAK attestation
    pub fn iak_attest(mut self, iak_attest: Vec<u8>) -> Self {
        self.iak_attest = Some(iak_attest);
        self
    }

    /// Set the IAK certificate
    ///
    /// # Arguments:
    ///
    /// * iak_cert (X509): The IAK certificate
    pub fn iak_cert(mut self, iak_cert: X509) -> Self {
        self.iak_cert = Some(iak_cert);
        self
    }

    /// Set the IAK attestation signature
    ///
    /// # Arguments:
    ///
    /// * iak_sign (Vec<u8>): A vector containing the IAK attestation signature
    pub fn iak_sign(mut self, iak_sign: Vec<u8>) -> Self {
        self.iak_sign = Some(iak_sign);
        self
    }

    /// Set the public IAK
    ///
    /// # Arguments:
    ///
    /// * iak_pub <&'a [u8]>: The buffer containing the marshalled public IAK
    pub fn iak_pub(mut self, iak_pub: &'a [u8]) -> Self {
        self.iak_pub = Some(iak_pub);
        self
    }

    /// Set the IDevID certificate
    ///
    /// # Arguments:
    ///
    /// * idevid_cert (X509): The IDevID certificate
    pub fn idevid_cert(mut self, idevid_cert: X509) -> Self {
        self.idevid_cert = Some(idevid_cert);
        self
    }

    /// Set the IDevID public key
    ///
    /// # Arguments:
    ///
    /// * idevid_pub: The IDevID public key
    pub fn idevid_pub(mut self, idevid_pub: &'a [u8]) -> Self {
        self.idevid_pub = Some(idevid_pub);
        self
    }

    /// Set the Agent contact IP
    ///
    /// This is the Agent IP or hostname to be contacted when making requests
    ///
    /// # Arguments:
    ///
    /// * ip (String): The Agent contact IP
    pub fn ip(mut self, ip: String) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Set the Agent mTLS certificate
    ///
    /// This is the certificate used when creating TLS connections to contact the Agent
    ///
    /// # Arguments:
    ///
    /// * mtls_cert (X509): The Agent mTLS certificate
    pub fn mtls_cert(mut self, mtls_cert: X509) -> Self {
        self.mtls_cert = Some(mtls_cert);
        self
    }

    /// Set the Agent port
    ///
    /// # Arguments:
    ///
    /// * port (u32): The port the Agent will listen to receive requests
    pub fn port(mut self, port: u32) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the agent UUID
    ///
    /// # Arguments:
    ///
    /// * uuid (&'a str): The agent UUID
    pub fn uuid(mut self, uuid: &'a str) -> Self {
        self.uuid = Some(uuid);
        self
    }

    /// Generate the AgentIdentity object using the previously set options
    pub async fn build(
        mut self,
    ) -> Result<AgentIdentity<'a>, AgentIdentityBuilderError> {
        // Check that required fields were set and take from the builder
        let Some(ak_pub) = self.ak_pub else {
            return Err(AgentIdentityBuilderError::AKPubNotSet);
        };

        let Some(ip) = self.ip.take() else {
            return Err(AgentIdentityBuilderError::AgentContactIPNotSet);
        };

        let Some(port) = self.port else {
            return Err(AgentIdentityBuilderError::AgentPortNotSet);
        };

        let Some(uuid) = self.uuid.take() else {
            return Err(AgentIdentityBuilderError::AgentUUIDNotSet);
        };

        let Some(ek_pub) = self.ek_pub else {
            return Err(AgentIdentityBuilderError::EKPubNotSet);
        };

        let mtls_cert = match self.mtls_cert.take() {
            Some(cert) => Some(
                x509_to_pem(&cert)
                    .map_err(AgentIdentityBuilderError::CertConvert)?,
            ),
            None => Some("disabled".to_string()),
        };

        let idevid_cert = match self.idevid_cert.take() {
            Some(cert) => Some(
                x509_to_der(&cert)
                    .map_err(AgentIdentityBuilderError::CertConvert)?,
            ),
            None => None,
        };

        let iak_cert = match self.iak_cert.take() {
            Some(cert) => Some(
                x509_to_der(&cert)
                    .map_err(AgentIdentityBuilderError::CertConvert)?,
            ),
            None => None,
        };

        // Take the enabled_api_versions
        let Some(enabled_api_versions) = self.enabled_api_versions.take()
        else {
            return Err(AgentIdentityBuilderError::EnabledAPIVersionsNotSet);
        };

        Ok(AgentIdentity {
            ak_pub,
            ek_cert: self.ek_cert,
            ek_pub,
            enabled_api_versions,
            iak_attest: self.iak_attest.take(),
            iak_cert,
            iak_pub: self.iak_pub,
            iak_sign: self.iak_sign.take(),
            idevid_cert,
            idevid_pub: self.idevid_pub,
            ip,
            mtls_cert,
            port,
            uuid,
        })
    }
}

#[derive(Default, Debug)]
pub struct AgentIdentity<'a> {
    pub ak_pub: &'a [u8],
    pub ek_cert: Option<String>,
    pub ek_pub: &'a [u8],
    pub enabled_api_versions: Vec<&'a str>,
    pub iak_attest: Option<Vec<u8>>,
    pub iak_cert: Option<Vec<u8>>,
    pub iak_pub: Option<&'a [u8]>,
    pub iak_sign: Option<Vec<u8>>,
    pub idevid_cert: Option<Vec<u8>>,
    pub idevid_pub: Option<&'a [u8]>,
    pub ip: String,
    pub mtls_cert: Option<String>,
    pub port: u32,
    pub uuid: &'a str,
}

#[cfg(test)]
mod test {
    use super::*;

    #[actix_rt::test]
    async fn test_build_missing_required() {
        let mock_data = [0u8; 1];
        let required = [
            "ak_pub",
            "ek_pub",
            "enabled_api_versions",
            "ip",
            "port",
            "uuid",
        ];

        for to_skip in required.iter() {
            // Add all required fields but the one to skip
            let to_add: Vec<&str> =
                required.iter().filter(|&x| x != to_skip).copied().collect();
            let mut builder = AgentIdentityBuilder::new();

            if to_add.contains(&"ak_pub") {
                builder = builder.ak_pub(&mock_data);
            }

            if to_add.contains(&"ek_pub") {
                builder = builder.ek_pub(&mock_data);
            }

            if to_add.contains(&"enabled_api_versions") {
                builder = builder.enabled_api_versions(vec!["1.2"]);
            }

            if to_add.contains(&"ip") {
                builder = builder.ip("1.2.3.4".to_string());
            }

            if to_add.contains(&"port") {
                builder = builder.port(0);
            }

            if to_add.contains(&"uuid") {
                builder = builder.uuid("uuid");
            }

            let result = builder.build().await;
            assert!(result.is_err());
        }
    }
}
