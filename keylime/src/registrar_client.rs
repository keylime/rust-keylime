use crate::serialization::*;
use log::*;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::Number;
use std::net::IpAddr;
use thiserror::Error;

use crate::{
    crypto::{x509_to_der, x509_to_pem, CryptoError},
    version::KeylimeRegistrarVersion,
};

pub const UNKNOWN_API_VERSION: &str = "unknown";

fn is_empty(buf: &[u8]) -> bool {
    buf.is_empty()
}

#[derive(Error, Debug)]
pub enum RegistrarClientBuilderError {
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

    /// Incompatible configured API versions
    #[error("Registrar and agent API versions are incompatible: agent enabled APIs '{agent_enabled}', registrar supported APIs '{registrar_supported}'")]
    IncompatibleAPI {
        agent_enabled: String,
        registrar_supported: String,
    },

    /// Registrar IP or hostname not set
    #[error("Registrar IP or hostname not set")]
    RegistrarIPNotSet,

    /// The registrar does not support the '/version' endpoint
    #[error("Registrar does not support the /version endpoint")]
    RegistrarNoVersion,

    /// Registrar port not set
    #[error("Registrar port not set")]
    RegistrarPortNotSet,

    /// Reqwest error
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

#[derive(Debug, Default)]
pub struct RegistrarClientBuilder<'a> {
    ak_pub: Option<&'a [u8]>,
    ek_pub: Option<&'a [u8]>,
    ek_cert: Option<Vec<u8>>,
    enabled_api_versions: Option<Vec<&'a str>>,
    iak_attest: Option<Vec<u8>>,
    iak_cert: Option<X509>,
    iak_sign: Option<Vec<u8>>,
    iak_pub: Option<&'a [u8]>,
    idevid_cert: Option<X509>,
    idevid_pub: Option<&'a [u8]>,
    ip: Option<String>,
    mtls_cert: Option<X509>,
    parsed_registrar_ip: Option<String>,
    port: Option<u32>,
    registrar_ip: Option<String>,
    registrar_port: Option<u32>,
    uuid: Option<&'a str>,
}

impl<'a> RegistrarClientBuilder<'a> {
    /// Create a new RegistrarClientBuilder object
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the public Attestation Key (AK) to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * ak_pub (&'a [u8]): The buffer containing the marshalled public AK
    pub fn ak_pub(mut self, ak_pub: &'a [u8]) -> Self {
        self.ak_pub = Some(ak_pub);
        self
    }

    /// Set the registrar API versions that are enabled
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

    /// Set the public Endorsement Key (EK) to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * ek_pub (&'a [u8]): The buffer containing the marshalled public EK
    pub fn ek_pub(mut self, ek_pub: &'a [u8]) -> Self {
        self.ek_pub = Some(ek_pub);
        self
    }

    /// Set the Endorsement Key (EK) certificate to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * ek_cert (Vec<u8>): A vector containing the EK certificate in DER format
    pub fn ek_cert(mut self, ek_cert: Vec<u8>) -> Self {
        self.ek_cert = Some(ek_cert);
        self
    }

    /// Set the IAK attestation to include in the registration request
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

    /// Set the IAK certificate to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * iak_cert (X509): The IAK certificate
    pub fn iak_cert(mut self, iak_cert: X509) -> Self {
        self.iak_cert = Some(iak_cert);
        self
    }

    /// Set the IAK attestation signature to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * iak_sign (Vec<u8>): A vector containing the IAK attestation signature
    pub fn iak_sign(mut self, iak_sign: Vec<u8>) -> Self {
        self.iak_sign = Some(iak_sign);
        self
    }

    /// Set the public IAK to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * iak_pub <&'a [u8]>: The buffer containing the marshalled public IAK
    pub fn iak_pub(mut self, iak_pub: &'a [u8]) -> Self {
        self.iak_pub = Some(iak_pub);
        self
    }

    /// Set the IDevID certificate to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * idevid_cert (X509): The IDevID certificate
    pub fn idevid_cert(mut self, idevid_cert: X509) -> Self {
        self.idevid_cert = Some(idevid_cert);
        self
    }

    /// Set the IDevID public key to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * idevid_pub: The IDevID public key
    pub fn idevid_pub(mut self, idevid_pub: &'a [u8]) -> Self {
        self.idevid_pub = Some(idevid_pub);
        self
    }

    /// Set the Agent contact IP to include in the registration request
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

    /// Set the Agent mTLS certificate to include in the registration request
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

    /// Set the Agent port to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * port (u32): The port the Agent will listen to receive requests
    pub fn port(mut self, port: u32) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the registrar IP address or hostname to contact when registering the agent
    ///
    /// # Arguments:
    ///
    /// * ip (String): The registrar IP or hostname
    pub fn registrar_ip(mut self, ip: String) -> Self {
        self.registrar_ip = Some(ip);
        self
    }

    /// Set the registrar port to contact when registering the agent
    ///
    /// # Arguments:
    ///
    /// * port (u32): The port to contact when registering the agent
    pub fn registrar_port(mut self, port: u32) -> Self {
        self.registrar_port = Some(port);
        self
    }

    /// Set the agent UUID to include in the registration request
    ///
    /// # Arguments:
    ///
    /// * uuid (&'a str): The agent UUID
    pub fn uuid(mut self, uuid: &'a str) -> Self {
        self.uuid = Some(uuid);
        self
    }

    /// Parse self.registrar_ip and store the result in self.parsed_registrar_ip
    pub fn parse_registrar_ip(
        &mut self,
    ) -> Result<String, RegistrarClientBuilderError> {
        if let Some(ref parsed_registrar_ip) = self.parsed_registrar_ip {
            return Ok(parsed_registrar_ip.clone());
        }

        let Some(ref registrar_ip) = self.registrar_ip else {
            return Err(RegistrarClientBuilderError::RegistrarIPNotSet);
        };

        // Parse the registrar IP or hostname
        let remote_ip = match registrar_ip.parse::<IpAddr>() {
            Ok(addr) => {
                // Add brackets if the address is IPv6
                if addr.is_ipv6() {
                    format!("[{registrar_ip}]")
                } else {
                    registrar_ip.to_string()
                }
            }
            Err(_) => {
                // The registrar_ip option can also be a hostname.
                // If it is the case, the hostname was already validated during configuration
                registrar_ip.to_string()
            }
        };

        // Store the parsed IP or hostname
        self.parsed_registrar_ip = Some(remote_ip.clone());
        Ok(remote_ip)
    }

    /// Get the registrar API version from the '/version' endpoint
    pub async fn get_registrar_api_version(
        &mut self,
    ) -> Result<String, RegistrarClientBuilderError> {
        let registrar_ip = self.parse_registrar_ip()?;

        let Some(registrar_port) = self.registrar_port else {
            return Err(RegistrarClientBuilderError::RegistrarPortNotSet);
        };

        let Some(enabled_apis) = &self.enabled_api_versions else {
            return Err(
                RegistrarClientBuilderError::EnabledAPIVersionsNotSet,
            );
        };

        // Try to reach the registrar
        let addr = format!("http://{registrar_ip}:{registrar_port}/version");

        info!("Requesting registrar API version to {}", addr);

        let resp = reqwest::Client::new()
            .get(&addr)
            .send()
            .await
            .map_err(RegistrarClientBuilderError::Reqwest)?;

        if !resp.status().is_success() {
            info!("Registrar at '{addr}' does not support the '/version' endpoint");
            return Err(RegistrarClientBuilderError::RegistrarNoVersion);
        }

        let resp: Response<KeylimeRegistrarVersion> = resp.json().await?;

        let registrar_api_version = &resp.results.current_version;

        if enabled_apis.contains(&registrar_api_version.as_str()) {
            Ok(registrar_api_version.to_string())
        } else {
            // Check if one of the API versions that the registrar supports is enabled
            // from the latest to the oldest
            for reg_supported_version in
                resp.results.supported_versions.iter().rev()
            {
                if enabled_apis.contains(&reg_supported_version.as_str()) {
                    return Ok(reg_supported_version.to_string());
                }
            }

            warn!("Registrar at '{addr}' does not support any API version: agent enabled versions = '[{}]', registrar supported versions = '[{}]'", enabled_apis.join(", "), resp.results.supported_versions.join(", "));
            Err(RegistrarClientBuilderError::IncompatibleAPI {
                agent_enabled: enabled_apis.join(", "),
                registrar_supported: resp
                    .results
                    .supported_versions
                    .join(", "),
            })
        }
    }

    /// Generate the RegistrarClient object using the previously set options
    pub async fn build(
        mut self,
    ) -> Result<RegistrarClient<'a>, RegistrarClientBuilderError> {
        let registrar_ip = self.parse_registrar_ip()?;

        // Check that required fields were set and take from the builder
        let Some(ak_pub) = self.ak_pub else {
            return Err(RegistrarClientBuilderError::AKPubNotSet);
        };

        let Some(ip) = self.ip.take() else {
            return Err(RegistrarClientBuilderError::AgentContactIPNotSet);
        };

        let Some(port) = self.port else {
            return Err(RegistrarClientBuilderError::AgentPortNotSet);
        };

        let Some(uuid) = self.uuid.take() else {
            return Err(RegistrarClientBuilderError::AgentUUIDNotSet);
        };

        let Some(ek_pub) = self.ek_pub else {
            return Err(RegistrarClientBuilderError::EKPubNotSet);
        };

        let Some(registrar_port) = self.registrar_port else {
            return Err(RegistrarClientBuilderError::RegistrarPortNotSet);
        };

        let mtls_cert = match self.mtls_cert.take() {
            Some(cert) => Some(
                x509_to_pem(&cert)
                    .map_err(RegistrarClientBuilderError::CertConvert)?,
            ),
            None => Some("disabled".to_string()),
        };

        let idevid_cert = match self.idevid_cert.take() {
            Some(cert) => Some(
                x509_to_der(&cert)
                    .map_err(RegistrarClientBuilderError::CertConvert)?,
            ),
            None => None,
        };

        let iak_cert = match self.iak_cert.take() {
            Some(cert) => Some(
                x509_to_der(&cert)
                    .map_err(RegistrarClientBuilderError::CertConvert)?,
            ),
            None => None,
        };

        // Get the registrar API version. If it was caused by an error in the request, set the
        // version as UNKNOWN_API_VERSION, otherwise abort the build process
        let registrar_api_version =
            match self.get_registrar_api_version().await {
                Ok(version) => version,
                Err(e) => match e {
                    RegistrarClientBuilderError::RegistrarNoVersion => {
                        UNKNOWN_API_VERSION.to_string()
                    }
                    _ => {
                        return Err(e);
                    }
                },
            };

        // Take the enabled_api_versions after calling get_registrar_api_version which uses it
        let Some(enabled_api_versions) = self.enabled_api_versions.take()
        else {
            // This should never be reachable as get_registrar_api_version() checks that this is
            // set
            unreachable!();
        };

        Ok(RegistrarClient {
            enabled_api_versions,
            ak_pub,
            api_version: registrar_api_version,
            ek_pub,
            ek_cert: self.ek_cert.take(),
            iak_attest: self.iak_attest.take(),
            iak_cert,
            iak_sign: self.iak_sign.take(),
            iak_pub: self.iak_pub,
            idevid_cert,
            idevid_pub: self.idevid_pub,
            ip,
            mtls_cert,
            port,
            registrar_ip,
            registrar_port,
            uuid,
        })
    }
}

#[derive(Error, Debug)]
pub enum RegistrarClientError {
    /// Activation failure
    #[error("Failed to activate agent: received {code} from {addr}")]
    Activation { addr: String, code: u16 },

    /// All tried API versions were rejected
    #[error("None of the tried API versions were enabled: tried '{0}'")]
    AllAPIVersionsRejected(String),

    /// Error has no code
    #[error("cannot get error code for type {0}")]
    NoCode(String),

    /// Registration failure
    #[error("Failed to register agent: received {code} from {addr}")]
    Registration { addr: String, code: u16 },

    /// Reqwest error
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

#[derive(Default, Debug)]
pub struct RegistrarClient<'a> {
    ak_pub: &'a [u8],
    api_version: String,
    ek_cert: Option<Vec<u8>>,
    ek_pub: &'a [u8],
    enabled_api_versions: Vec<&'a str>,
    iak_attest: Option<Vec<u8>>,
    iak_cert: Option<Vec<u8>>,
    iak_pub: Option<&'a [u8]>,
    iak_sign: Option<Vec<u8>>,
    idevid_cert: Option<Vec<u8>>,
    idevid_pub: Option<&'a [u8]>,
    ip: String,
    mtls_cert: Option<String>,
    port: u32,
    registrar_ip: String,
    registrar_port: u32,
    uuid: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterResponseResults {
    #[serde(deserialize_with = "deserialize_maybe_base64")]
    blob: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Activate<'a> {
    auth_tag: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActivateResponseResults {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response<T> {
    code: Number,
    status: String,
    results: T,
}

#[derive(Debug, Serialize, Deserialize)]
struct Register<'a> {
    #[serde(serialize_with = "serialize_as_base64")]
    aik_tpm: &'a [u8],
    #[serde(
        serialize_with = "serialize_as_base64",
        skip_serializing_if = "is_empty"
    )]
    ek_tpm: &'a [u8],
    #[serde(serialize_with = "serialize_maybe_base64")]
    ekcert: Option<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_maybe_base64",
        skip_serializing_if = "Option::is_none"
    )]
    iak_attest: Option<Vec<u8>>,
    #[serde(serialize_with = "serialize_maybe_base64")]
    iak_cert: Option<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_maybe_base64",
        skip_serializing_if = "Option::is_none"
    )]
    iak_sign: Option<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_option_base64",
        skip_serializing_if = "Option::is_none"
    )]
    iak_tpm: Option<&'a [u8]>,
    #[serde(serialize_with = "serialize_maybe_base64")]
    idevid_cert: Option<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_option_base64",
        skip_serializing_if = "Option::is_none"
    )]
    idevid_tpm: Option<&'a [u8]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtls_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u32>,
}

impl RegistrarClient<'_> {
    async fn try_register_agent(
        &self,
        api_version: &str,
    ) -> Result<Vec<u8>, RegistrarClientError> {
        let data = Register {
            aik_tpm: self.ak_pub,
            ek_tpm: self.ek_pub,
            ekcert: self.ek_cert.clone(),
            iak_attest: self.iak_attest.clone(),
            iak_cert: self.iak_cert.clone(),
            iak_sign: self.iak_sign.clone(),
            iak_tpm: self.iak_pub,
            idevid_cert: self.idevid_cert.clone(),
            idevid_tpm: self.idevid_pub,
            ip: Some(self.ip.clone()),
            mtls_cert: self.mtls_cert.clone(),
            port: Some(self.port),
        };

        let addr = format!(
            "http://{}:{}/v{}/agents/{}",
            &self.registrar_ip, &self.registrar_port, api_version, &self.uuid
        );

        info!(
            "Requesting agent registration from {} for {}",
            &addr, &self.uuid
        );

        let resp = reqwest::Client::new()
            .post(&addr)
            .json(&data)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(RegistrarClientError::Registration {
                addr,
                code: resp.status().as_u16(),
            });
        }

        let resp: Response<RegisterResponseResults> = resp.json().await?;

        Ok(resp.results.blob.unwrap_or_default())
    }

    /// Register the agent using the previously set of parameters and receive the encrypted
    /// challenge as a binary blob.
    ///
    /// The encrypted challenge is generated by the registrar using the tpm2_makecredential
    /// operation, which:
    ///
    /// * Generates a random nonce (challenge)
    /// * Encrypts the random nonce with the public EK provided by the agent
    /// * Encodes the AK name together with the encrypted challenge using base64
    pub async fn register_agent(
        &mut self,
    ) -> Result<Vec<u8>, RegistrarClientError> {
        // In case the registrar does not support the '/version' endpoint, try the enabled API
        // versions
        if self.api_version == UNKNOWN_API_VERSION {
            for api_version in &self.enabled_api_versions {
                info!("Trying to register agent using API version {api_version}");
                let r = self.try_register_agent(api_version).await;

                // If the registration was successful, register the API version to use for
                // following requests
                if r.is_ok() {
                    self.api_version = api_version.to_string();
                    return r;
                }
            }
        } else {
            return self.try_register_agent(&self.api_version).await;
        }

        // All enabled API versions were tried
        Err(RegistrarClientError::AllAPIVersionsRejected(
            self.enabled_api_versions.join(", "),
        ))
    }

    async fn try_activate_agent(
        &self,
        auth_tag: &str,
        api_version: &str,
    ) -> Result<(), RegistrarClientError> {
        let data = Activate { auth_tag };

        let addr = format!(
            "http://{}:{}/v{}/agents/{}",
            &self.registrar_ip, &self.registrar_port, api_version, &self.uuid
        );

        info!(
            "Requesting agent activation from {} for {}",
            &addr, &self.uuid
        );

        let resp =
            reqwest::Client::new().put(&addr).json(&data).send().await?;

        if !resp.status().is_success() {
            return Err(RegistrarClientError::Activation {
                addr,
                code: resp.status().as_u16(),
            });
        }

        let _resp: Response<ActivateResponseResults> = resp.json().await?;

        Ok(())
    }

    /// Activate the agent using the authentication tag
    ///
    /// To generate the authentication tag, it is necessary to decrypt the challenge obtained
    /// during registration using the tpm2_activatecredential operation.
    ///
    /// The tpm2_activatecredential will:
    ///
    /// * Verify that the AK is in the same TPM as the EK
    /// * Decrypt the blob using the private EK
    ///
    /// The authentication tag is the base64-encoded HMAC using SHA-384 as the underlying hash
    /// algorithm, the decrypted challenge as key, and the agent UUID as the input
    ///
    /// # Arguments:
    ///
    /// * auth_tag (&str): The authentication tag
    pub async fn activate_agent(
        &mut self,
        auth_tag: &str,
    ) -> Result<(), RegistrarClientError> {
        // In case the registrar does not support the '/version' endpoint, try the enabled API
        // versions
        if self.api_version == UNKNOWN_API_VERSION {
            for api_version in &self.enabled_api_versions {
                info!("Trying to register agent using API version {api_version}");
                let r = self.try_activate_agent(auth_tag, api_version).await;

                // If the registration was successful, register the API version to use for
                // following requests
                if r.is_ok() {
                    self.api_version = api_version.to_string();
                    return r;
                }
            }
        } else {
            return self
                .try_activate_agent(auth_tag, &self.api_version)
                .await;
        }

        // All enabled API versions were tried
        Err(RegistrarClientError::AllAPIVersionsRejected(
            self.enabled_api_versions.join(", "),
        ))
    }
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[actix_rt::test]
    async fn test_register_agent_ok() {
        // Setup mock server with the registration and api version responses
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        let api_response: Response<KeylimeRegistrarVersion> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: KeylimeRegistrarVersion {
                current_version: "1.2".to_string(),
                supported_versions: vec!["1.2".to_string()],
            },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("POST"))
            .and(path("/v1.2/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let mock = Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(api_response),
            );
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        let response = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_data.to_vec())
            .enabled_api_versions(vec!["1.2"])
            .iak_attest(vec![0])
            .iak_cert(cert.clone())
            .iak_sign(vec![0])
            .iak_pub(&mock_data)
            .idevid_cert(cert.clone())
            .idevid_pub(&mock_data)
            .ip("1.2.3.4".to_string())
            .mtls_cert(cert.clone())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid")
            .build()
            .await;
        assert!(response.is_ok(), "error: {:?}", response);
        let mut registrar_client = response.unwrap(); //#[allow_ci]
        let response = registrar_client.register_agent().await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn test_register_agent_with_old_registrar() {
        // Setup mock server with only the registration endpoint
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("POST"))
            .and(path("/v1.2/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_data.to_vec())
            .enabled_api_versions(vec!["1.2", "3.4"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent().await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn test_register_agent_different_api() {
        // Setup mock server with the registration and api version responses
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        // Mock a registrar with a different API version
        let api_response: Response<KeylimeRegistrarVersion> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: KeylimeRegistrarVersion {
                current_version: "3.4".to_string(),
                supported_versions: vec!["3.4".to_string()],
            },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let mock = Mock::given(method("GET")).respond_with(
            ResponseTemplate::new(200).set_body_json(api_response),
        );
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_data.to_vec())
            .enabled_api_versions(vec!["1.2", "3.4"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent().await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn test_register_agent_ok_without_ekcert() {
        // Setup mock server with the registration and api version responses
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        let api_response: Response<KeylimeRegistrarVersion> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: KeylimeRegistrarVersion {
                current_version: "1.2".to_string(),
                supported_versions: vec!["1.2".to_string()],
            },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("POST"))
            .and(path("/v1.2/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let mock = Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(api_response),
            );
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4", "1.2.3.5"])
            .build()
            .unwrap(); //#[allow_ci]

        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent().await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn test_register_agent_err() {
        // Setup mock server without any response configured
        let mock_server = MockServer::start().await;
        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .build()
            .unwrap(); //#[allow_ci]

        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent().await;
        assert!(response.is_err());
    }

    #[actix_rt::test]
    async fn test_register_agent_unsupported_api() {
        // Setup mock server with the registration and api version responses
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        // Mock a registrar with a different API version
        let api_response: Response<KeylimeRegistrarVersion> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: KeylimeRegistrarVersion {
                current_version: "3.4".to_string(),
                supported_versions: vec!["3.4".to_string()],
            },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("POST"))
            .and(path("/v3.4/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let mock = Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(api_response),
            );
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        // Try to register with an unsupported API version
        let response = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_data.to_vec())
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid")
            .build()
            .await;

        // The build process should fail as there is no compatible API version
        assert!(response.is_err());
    }

    #[actix_rt::test]
    async fn test_activate_agent_ok() {
        // Setup mock server with the activation and api version responses
        let response: Response<ActivateResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: ActivateResponseResults {},
        };

        let api_response: Response<KeylimeRegistrarVersion> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: KeylimeRegistrarVersion {
                current_version: "1.2".to_string(),
                supported_versions: vec!["3.4".to_string()],
            },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("PUT"))
            .and(path("/v1.2/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let mock = Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(api_response),
            );
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];

        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.activate_agent("tag").await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn test_activate_agent_old_registrar() {
        // Setup mock server with only the activation endpoint
        let response: Response<ActivateResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: ActivateResponseResults {},
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("PUT"))
            .and(path("/v1.2/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];

        // Enable only a newer API version in the client
        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2", "3.4"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.activate_agent("tag").await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn test_activate_agent_different_api() {
        // Setup mock server with the activation and api version responses
        let response: Response<ActivateResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: ActivateResponseResults {},
        };

        // Mock a registrar with a different API version
        let api_response: Response<KeylimeRegistrarVersion> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: KeylimeRegistrarVersion {
                current_version: "1.2".to_string(),
                supported_versions: vec!["1.2".to_string()],
            },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("PUT"))
            .and(path("/v1.2/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let mock = Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(api_response),
            );
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];

        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2", "3.4"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.activate_agent("tag").await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn test_activate_agent_unsupported_api() {
        // Setup mock server with the activation and api version responses
        let response: Response<ActivateResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: ActivateResponseResults {},
        };

        // Mock a registrar with a different API version
        let api_response: Response<KeylimeRegistrarVersion> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: KeylimeRegistrarVersion {
                current_version: "3.4".to_string(),
                supported_versions: vec!["3.4".to_string()],
            },
        };

        let mock_server = MockServer::start().await;

        let mock = Mock::given(method("PUT"))
            .and(path("/v3.4/agents/uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let mock = Mock::given(method("GET"))
            .and(path("/version"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(api_response),
            );
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];

        // Try to activate with an unsupported API version
        let response = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid")
            .build()
            .await;

        // The build process should fail as there is no compatible API version
        assert!(response.is_err());
    }

    #[actix_rt::test]
    async fn test_activate_agent_err() {
        // Setup mock server without any response configured
        let mock_server = MockServer::start().await;
        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];

        let builder = RegistrarClientBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .registrar_ip(ip.to_string())
            .registrar_port(port)
            .uuid("uuid");

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.activate_agent("tag").await;
        assert!(response.is_err());
    }

    #[actix_rt::test]
    async fn test_build_missing_required() {
        let mock_data = [0u8; 1];
        let required = [
            "ak_pub",
            "ek_pub",
            "enabled_api_versions",
            "ip",
            "port",
            "registrar_ip",
            "registrar_port",
            "uuid",
        ];

        for to_skip in required.iter() {
            // Add all required fields but the one to skip
            let to_add: Vec<&str> =
                required.iter().filter(|&x| x != to_skip).copied().collect();
            let mut builder = RegistrarClientBuilder::new();

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

            if to_add.contains(&"registrar_ip") {
                builder = builder.registrar_ip("1.2.3.5".to_string());
            }

            if to_add.contains(&"registrar_port") {
                builder = builder.registrar_port(8891);
            }

            if to_add.contains(&"uuid") {
                builder = builder.uuid("uuid");
            }

            let result = builder.build().await;
            assert!(result.is_err());
        }
    }
}
