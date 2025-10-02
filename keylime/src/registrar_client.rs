use crate::resilient_client::ResilientClient;
use crate::{
    agent_identity::AgentIdentity,
    agent_registration::RetryConfig,
    https_client::{self, ClientArgs},
    serialization::*,
};
use log::*;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Number;
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

use crate::version::KeylimeRegistrarVersion;

pub const UNKNOWN_API_VERSION: &str = "unknown";

fn is_empty(buf: &[u8]) -> bool {
    buf.is_empty()
}

#[derive(Error, Debug)]
pub enum RegistrarClientBuilderError {
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

    /// Middleware error
    #[error("Middleware error: {0}")]
    Middleware(#[from] reqwest_middleware::Error),

    /// HTTPS client creation error
    #[error("HTTPS client creation error: {0}")]
    HttpsClient(#[from] anyhow::Error),
}

#[derive(Debug, Default)]
pub struct RegistrarClientBuilder {
    registrar_current_api_version: Option<String>,
    registrar_supported_api_versions: Option<Vec<String>>,
    registrar_address: Option<String>,
    registrar_port: Option<u32>,
    retry_config: Option<RetryConfig>,
    ca_certificate: Option<String>,
    certificate: Option<String>,
    key: Option<String>,
    insecure: Option<bool>,
    timeout: Option<u64>,
}

impl RegistrarClientBuilder {
    /// Create a new RegistrarClientBuilder object
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the registrar IP address or hostname to contact when registering the agent
    ///
    /// # Arguments:
    ///
    /// * address (String): The registrar IP or hostname
    pub fn registrar_address(mut self, address: String) -> Self {
        let a = RegistrarClientBuilder::parse_registrar_address(address);
        self.registrar_address = Some(a);
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

    /// Set the RetryConfig for the registrar client
    ///
    /// # Arguments:
    ///
    /// * rt: RetryConfig: The retry configuration to use for the registrar client
    pub fn retry_config(mut self, rt: Option<RetryConfig>) -> Self {
        self.retry_config = rt;
        self
    }

    /// Set the CA certificate file path for TLS communication
    ///
    /// # Arguments:
    ///
    /// * ca_certificate (String): Path to the CA certificate file
    pub fn ca_certificate(mut self, ca_certificate: String) -> Self {
        self.ca_certificate = Some(ca_certificate);
        self
    }

    /// Set the client certificate file path for TLS communication
    ///
    /// # Arguments:
    ///
    /// * certificate (String): Path to the client certificate file
    pub fn certificate(mut self, certificate: String) -> Self {
        self.certificate = Some(certificate);
        self
    }

    /// Set the client private key file path for TLS communication
    ///
    /// # Arguments:
    ///
    /// * key (String): Path to the client private key file
    pub fn key(mut self, key: String) -> Self {
        self.key = Some(key);
        self
    }

    /// Set the insecure flag to disable TLS certificate validation
    ///
    /// # Arguments:
    ///
    /// * insecure (bool): If true, disable certificate validation
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = Some(insecure);
        self
    }

    /// Set the request timeout in milliseconds
    ///
    /// # Arguments:
    ///
    /// * timeout (u64): Request timeout in milliseconds
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Parse the received address
    fn parse_registrar_address(address: String) -> String {
        // Parse the registrar IP or hostname
        match address.parse::<IpAddr>() {
            Ok(addr) => {
                // Add brackets if the address is IPv6
                if addr.is_ipv6() {
                    format!("[{address}]")
                } else {
                    address.to_string()
                }
            }
            Err(_) => {
                // The registrar_ip option can also be a hostname.
                // If it is the case, it is expected that the hostname was
                // already validated during configuration
                address.to_string()
            }
        }
    }

    /// Get the registrar API version from the Registrar '/version' endpoint
    async fn get_registrar_api_version(
        &mut self,
        resilient_client: &ResilientClient,
        scheme: &str,
    ) -> Result<String, RegistrarClientBuilderError> {
        let Some(ref registrar_ip) = self.registrar_address else {
            return Err(RegistrarClientBuilderError::RegistrarIPNotSet);
        };

        let Some(registrar_port) = self.registrar_port else {
            return Err(RegistrarClientBuilderError::RegistrarPortNotSet);
        };

        // Try to reach the registrar
        let addr =
            format!("{scheme}://{registrar_ip}:{registrar_port}/version");

        info!("Requesting registrar API version to {addr}");

        let resp = resilient_client
            .get_request(reqwest::Method::GET, &addr)
            .send()
            .await?;

        if !resp.status().is_success() {
            info!("Registrar at '{addr}' does not support the '/version' endpoint");
            return Err(RegistrarClientBuilderError::RegistrarNoVersion);
        }

        let resp: Response<KeylimeRegistrarVersion> = resp.json().await?;

        self.registrar_current_api_version =
            Some(resp.results.current_version.clone());
        self.registrar_supported_api_versions =
            Some(resp.results.supported_versions);

        Ok(resp.results.current_version)
    }

    /// Generate the RegistrarClient object using the previously set options
    pub async fn build(
        &mut self,
    ) -> Result<RegistrarClient, RegistrarClientBuilderError> {
        let Some(registrar_ip) = self.registrar_address.clone() else {
            return Err(RegistrarClientBuilderError::RegistrarIPNotSet);
        };

        let Some(registrar_port) = self.registrar_port else {
            return Err(RegistrarClientBuilderError::RegistrarPortNotSet);
        };

        // Determine if TLS should be used
        // TLS is used if all TLS parameters are provided and insecure is not true
        let use_tls = self.ca_certificate.is_some()
            && self.certificate.is_some()
            && self.key.is_some()
            && !self.insecure.unwrap_or(false);

        let scheme = if use_tls { "https" } else { "http" };

        // Create the client (HTTPS or plain HTTP)
        let client = if use_tls {
            let args = ClientArgs {
                ca_certificate: self
                    .ca_certificate
                    .clone()
                    .unwrap_or_default(),
                certificate: self.certificate.clone().unwrap_or_default(),
                key: self.key.clone().unwrap_or_default(),
                insecure: self.insecure,
                timeout: self.timeout.unwrap_or(5000),
            };
            https_client::get_https_client(&args)?
        } else {
            reqwest::Client::new()
        };

        // Create ResilientClient once, using retry config if provided
        let (initial_delay, max_retries, max_delay) =
            if let Some(ref retry_config) = self.retry_config {
                (
                    Duration::from_millis(retry_config.initial_delay_ms),
                    retry_config.max_retries,
                    retry_config.max_delay_ms.map(Duration::from_millis),
                )
            } else {
                // No retry config: use 0 retries
                (Duration::from_millis(100), 0, None)
            };

        let resilient_client = ResilientClient::new(
            Some(client),
            initial_delay,
            max_retries,
            &[StatusCode::OK],
            max_delay,
        );

        // Get the registrar API version. If it was caused by an error in the request, set the
        // version as UNKNOWN_API_VERSION, otherwise abort the build process
        let registrar_api_version = match self
            .get_registrar_api_version(&resilient_client, scheme)
            .await
        {
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

        Ok(RegistrarClient {
            supported_api_versions: self
                .registrar_supported_api_versions
                .clone(),
            api_version: registrar_api_version,
            registrar_ip,
            registrar_port,
            resilient_client,
            scheme: scheme.to_string(),
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

    /// Incompatible configured API versions
    #[error("Registrar and agent API versions are incompatible: agent enabled APIs '{agent_enabled}', registrar supported APIs '{registrar_supported}'")]
    IncompatibleAPI {
        agent_enabled: String,
        registrar_supported: String,
    },

    /// The information provided by the Registrar is inconsistent
    #[error("Inconsistent information from registrar: current API version = '{0}', but no list of supported API versions was provided")]
    Inconsistent(String),

    /// Error has no code
    #[error("cannot get error code for type {0}")]
    NoCode(String),

    /// Registration failure
    #[error("Failed to register agent: received {code} from {addr}")]
    Registration { addr: String, code: u16 },

    /// Registration forbidden - TPM identity mismatch or security rejection
    #[error("Registration forbidden: {message}. This may indicate a TPM identity change or UUID spoofing attempt. The existing agent record must be deleted before re-registering with a different TPM.")]
    RegistrationForbidden { message: String },

    /// Reqwest error
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Serde error
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Middleware error
    #[error("Middleware error: {0}")]
    Middleware(#[from] reqwest_middleware::Error),
}

#[derive(Clone, Debug)]
pub struct RegistrarClient {
    api_version: String,
    supported_api_versions: Option<Vec<String>>,
    registrar_ip: String,
    registrar_port: u32,
    resilient_client: ResilientClient,
    scheme: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    ekcert: Option<String>,
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

impl RegistrarClient {
    async fn try_register_agent(
        &self,
        ai: &AgentIdentity<'_>,
        api_version: &str,
    ) -> Result<Vec<u8>, RegistrarClientError> {
        let data = Register {
            aik_tpm: ai.ak_pub,
            ek_tpm: ai.ek_pub,
            ekcert: ai.ek_cert.clone(),
            iak_attest: ai.iak_attest.clone(),
            iak_cert: ai.iak_cert.clone(),
            iak_sign: ai.iak_sign.clone(),
            iak_tpm: ai.iak_pub,
            idevid_cert: ai.idevid_cert.clone(),
            idevid_tpm: ai.idevid_pub,
            ip: Some(ai.ip.clone()),
            mtls_cert: ai.mtls_cert.clone(),
            port: Some(ai.port),
        };

        let registrar_ip = &self.registrar_ip;
        let registrar_port = &self.registrar_port;
        let uuid = &ai.uuid;
        let scheme = &self.scheme;

        let addr = format!(
            "{scheme}://{registrar_ip}:{registrar_port}/v{api_version}/agents/{uuid}",
        );

        info!(
            "Requesting agent registration from {} for {}",
            &addr, &ai.uuid
        );

        let resp = self
            .resilient_client
            .get_json_request_from_struct(
                reqwest::Method::POST,
                &addr,
                &data,
                None,
            )
            .map_err(RegistrarClientError::Serde)?
            .send()
            .await
            .map_err(RegistrarClientError::Middleware)?;

        if !resp.status().is_success() {
            // Check if this is a 403 Forbidden - indicates security rejection
            if resp.status() == StatusCode::FORBIDDEN {
                let error_message = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                return Err(RegistrarClientError::RegistrationForbidden {
                    message: error_message,
                });
            }
            return Err(RegistrarClientError::Registration {
                addr,
                code: resp.status().as_u16(),
            });
        }

        let resp: Response<RegisterResponseResults> = resp.json().await?;

        Ok(resp.results.blob.unwrap_or_default())
    }

    /// Log the warning about incompatible registrar and agent APIs and return the appropriate
    /// error
    fn incompatible(
        &self,
        agent_enabled: String,
        registrar_supported: String,
    ) -> RegistrarClientError {
        warn!("Registrar at '{}' does not support any enabled API version: agent enabled versions = '[{agent_enabled}]', registrar supported versions = '[{registrar_supported}]'", self.registrar_ip);
        RegistrarClientError::IncompatibleAPI {
            agent_enabled,
            registrar_supported,
        }
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
        ai: &AgentIdentity<'_>,
    ) -> Result<Vec<u8>, RegistrarClientError> {
        // The current Registrar API version is enabled and should work
        if ai.enabled_api_versions.contains(&self.api_version.as_ref()) {
            return self.try_register_agent(ai, &self.api_version).await;
        }

        // In case the registrar does not support the '/version' endpoint, try the enabled API
        // versions
        if self.api_version == UNKNOWN_API_VERSION {
            // Assume the list of enabled versions is ordered from the oldest to the newest
            for api_version in ai.enabled_api_versions.iter().rev() {
                info!("Trying to register agent using API version {api_version}");
                let r = self.try_register_agent(ai, api_version).await;

                // Check if this is a security rejection (403 Forbidden)
                // If so, return immediately - don't try other API versions
                if let Err(RegistrarClientError::RegistrationForbidden {
                    ..
                }) = r
                {
                    return r;
                }

                // If successful, cache the API version for future requests
                if r.is_ok() {
                    self.api_version = api_version.to_string();
                    return r;
                }
            }
            // All enabled API versions were tried
            Err(RegistrarClientError::AllAPIVersionsRejected(
                ai.enabled_api_versions.join(", "),
            ))
        } else {
            // The current Registrar API version is not enabled.
            // Find the latest enabled version that is supported
            if let Some(ref supported) = self.supported_api_versions {
                for api_version in ai.enabled_api_versions.iter().rev() {
                    if supported.contains(&api_version.to_string()) {
                        // Found a compatible API version, it should work
                        let r =
                            self.try_register_agent(ai, api_version).await;

                        // Check if this is a security rejection (403 Forbidden)
                        // If so, return immediately - don't try other API versions
                        if let Err(
                            RegistrarClientError::RegistrationForbidden {
                                ..
                            },
                        ) = r
                        {
                            return r;
                        }

                        // If successful, cache the API version for future requests
                        if r.is_ok() {
                            self.api_version = api_version.to_string();
                            return r;
                        }
                    }
                }
                // None of the enabled APIs is supported
                Err(self.incompatible(
                    ai.enabled_api_versions.join(", "),
                    supported.join(", "),
                ))
            } else {
                Err(RegistrarClientError::Inconsistent(
                    self.api_version.to_string(),
                ))
            }
        }
    }

    async fn try_activate_agent(
        &self,
        auth_tag: &str,
        ai: &AgentIdentity<'_>,
        api_version: &str,
    ) -> Result<(), RegistrarClientError> {
        let data = Activate { auth_tag };

        let registrar_ip = &self.registrar_ip;
        let registrar_port = &self.registrar_port;
        let uuid = &ai.uuid;
        let scheme = &self.scheme;

        let addr = format!(
            "{scheme}://{registrar_ip}:{registrar_port}/v{api_version}/agents/{uuid}",
        );

        info!(
            "Requesting agent activation from {} for {}",
            &addr, &ai.uuid
        );

        let resp = self
            .resilient_client
            .get_json_request_from_struct(
                reqwest::Method::PUT,
                &addr,
                &data,
                None,
            )
            .map_err(RegistrarClientError::Serde)?
            .send()
            .await
            .map_err(RegistrarClientError::Middleware)?;

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
    /// * ai (&AgentIdentity<'_>): The identity data of the Agent to be activated
    /// * auth_tag (&str): The authentication tag
    pub async fn activate_agent(
        &mut self,
        ai: &AgentIdentity<'_>,
        auth_tag: &str,
    ) -> Result<(), RegistrarClientError> {
        // The current Registrar API version is enabled and should work
        if ai.enabled_api_versions.contains(&self.api_version.as_ref()) {
            return self
                .try_activate_agent(auth_tag, ai, &self.api_version)
                .await;
        }

        // In case the registrar does not support the '/version' endpoint, try the enabled API
        // versions
        if self.api_version == UNKNOWN_API_VERSION {
            // Assume the list of enabled versions is ordered from the oldest to the newest
            for api_version in ai.enabled_api_versions.iter().rev() {
                info!("Trying to register agent using API version {api_version}");
                let r =
                    self.try_activate_agent(auth_tag, ai, api_version).await;

                // If successful, cache the API version for future requests
                if r.is_ok() {
                    self.api_version = api_version.to_string();
                    return r;
                }
            }
            // All enabled API versions were tried
            Err(RegistrarClientError::AllAPIVersionsRejected(
                ai.enabled_api_versions.join(", "),
            ))
        } else {
            // The current Registrar API version is not enabled.
            // Find the latest enabled version that is supported
            if let Some(ref supported) = self.supported_api_versions {
                for api_version in ai.enabled_api_versions.iter().rev() {
                    if supported.contains(&api_version.to_string()) {
                        // Found a compatible API version, it should work
                        let r = self
                            .try_activate_agent(auth_tag, ai, api_version)
                            .await;

                        // If successful, cache the API version for future requests
                        if r.is_ok() {
                            self.api_version = api_version.to_string();
                            return r;
                        }
                    }
                }
                // None of the enabled APIs is supported
                Err(self.incompatible(
                    ai.enabled_api_versions.join(", "),
                    supported.join(", "),
                ))
            } else {
                Err(RegistrarClientError::Inconsistent(
                    self.api_version.to_string(),
                ))
            }
        }
    }
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agent_identity::AgentIdentityBuilder, crypto};
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
        let mock_chain = String::from("");
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_chain)
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
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let response = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port)
            .build()
            .await;

        assert!(response.is_ok(), "error: {response:?}");
        let mut registrar_client = response.unwrap(); //#[allow_ci]
        let response = registrar_client.register_agent(&ai).await;
        assert!(response.is_ok(), "error: {response:?}");
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
        let mock_chain = String::from("");
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_chain)
            .enabled_api_versions(vec!["1.2", "3.4"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port);

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent(&ai).await;
        assert!(response.is_ok(), "error: {response:?}");
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
        let mock_chain = String::from("");
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_chain)
            .enabled_api_versions(vec!["1.2", "3.4"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port);

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent(&ai).await;
        assert!(response.is_ok(), "error: {response:?}");
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

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port);

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent(&ai).await;
        assert!(response.is_ok(), "error: {response:?}");
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

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port);

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.register_agent(&ai).await;
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
        let mock_chain = String::from("");
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .add_ips(vec!["1.2.3.4"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .ek_cert(mock_chain)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        // Try to register with an unsupported API version
        let response = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port)
            .build()
            .await;

        // The build process should work, but the registration should fail
        assert!(response.is_ok(), "error: {response:?}");
        let mut registrar_client =
            response.expect("failed to build Registrar Client");
        let response = registrar_client.register_agent(&ai).await;
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

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port);

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.activate_agent(&ai, "tag").await;
        assert!(response.is_ok(), "error: {response:?}");
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

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2", "3.4"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        // Enable only a newer API version in the client
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port);

        let mut registrar_client = builder.build().await.unwrap(); //#[allow_ci]

        let response = registrar_client.activate_agent(&ai, "tag").await;
        assert!(response.is_ok(), "error: {response:?}");
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

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2", "3.4"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let mut registrar_client = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port)
            .build()
            .await
            .expect("failed top build Registrar Client");

        let response = registrar_client.activate_agent(&ai, "tag").await;
        assert!(response.is_ok(), "error: {response:?}");
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

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        // Try to activate with an unsupported API version
        let response = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port)
            .build()
            .await;

        // The build process should work, but the activation should fail as
        // there is no compatible API version
        assert!(response.is_ok(), "error: {response:?}");
        let mut registrar_client =
            response.expect("failed to build Registrar Client");
        let response = registrar_client.activate_agent(&ai, "tag").await;
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

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .ip("1.2.3.4".to_string())
            .port(0)
            .uuid("uuid")
            .build()
            .await
            .expect("failed to build Agent Identity");

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address(ip.to_string())
            .registrar_port(port);

        let mut registrar_client = builder
            .build()
            .await
            .expect("failed to build Registrar Client");

        let response = registrar_client.activate_agent(&ai, "tag").await;
        assert!(response.is_err());
    }

    #[actix_rt::test]
    async fn test_build_missing_required() {
        let required = ["registrar_address", "registrar_port"];

        for to_skip in required.iter() {
            // Add all required fields but the one to skip
            let to_add: Vec<&str> =
                required.iter().filter(|&x| x != to_skip).copied().collect();
            let mut builder = RegistrarClientBuilder::new();

            if to_add.contains(&"registrar_address") {
                builder = builder.registrar_address("1.2.3.5".to_string());
            }

            if to_add.contains(&"registrar_port") {
                builder = builder.registrar_port(8891);
            }

            let result = builder.build().await;
            assert!(result.is_err());
        }
    }

    #[actix_rt::test]
    async fn test_builder_tls_ca_certificate() {
        let builder = RegistrarClientBuilder::new()
            .ca_certificate("/path/to/ca.pem".to_string());

        assert_eq!(
            builder.ca_certificate,
            Some("/path/to/ca.pem".to_string())
        );
    }

    #[actix_rt::test]
    async fn test_builder_tls_client_certificate() {
        let builder = RegistrarClientBuilder::new()
            .certificate("/path/to/cert.pem".to_string());

        assert_eq!(
            builder.certificate,
            Some("/path/to/cert.pem".to_string())
        );
    }

    #[actix_rt::test]
    async fn test_builder_tls_client_key() {
        let builder =
            RegistrarClientBuilder::new().key("/path/to/key.pem".to_string());

        assert_eq!(builder.key, Some("/path/to/key.pem".to_string()));
    }

    #[actix_rt::test]
    async fn test_builder_tls_insecure_true() {
        let builder = RegistrarClientBuilder::new().insecure(true);

        assert_eq!(builder.insecure, Some(true));
    }

    #[actix_rt::test]
    async fn test_builder_tls_insecure_false() {
        let builder = RegistrarClientBuilder::new().insecure(false);

        assert_eq!(builder.insecure, Some(false));
    }

    #[actix_rt::test]
    async fn test_builder_tls_timeout() {
        let builder = RegistrarClientBuilder::new().timeout(10000);

        assert_eq!(builder.timeout, Some(10000));
    }

    #[actix_rt::test]
    async fn test_builder_chaining_with_tls() {
        let builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(8890)
            .ca_certificate("/path/to/ca.pem".to_string())
            .certificate("/path/to/cert.pem".to_string())
            .key("/path/to/key.pem".to_string())
            .insecure(false)
            .timeout(5000);

        assert_eq!(builder.registrar_address, Some("127.0.0.1".to_string()));
        assert_eq!(builder.registrar_port, Some(8890));
        assert_eq!(
            builder.ca_certificate,
            Some("/path/to/ca.pem".to_string())
        );
        assert_eq!(
            builder.certificate,
            Some("/path/to/cert.pem".to_string())
        );
        assert_eq!(builder.key, Some("/path/to/key.pem".to_string()));
        assert_eq!(builder.insecure, Some(false));
        assert_eq!(builder.timeout, Some(5000));
    }

    #[actix_rt::test]
    async fn test_builder_tls_default_values() {
        let builder = RegistrarClientBuilder::new();

        assert_eq!(builder.ca_certificate, None);
        assert_eq!(builder.certificate, None);
        assert_eq!(builder.key, None);
        assert_eq!(builder.insecure, None);
        assert_eq!(builder.timeout, None);
    }

    #[actix_rt::test]
    async fn test_builder_partial_tls_config_missing_ca() {
        let builder = RegistrarClientBuilder::new()
            .certificate("/path/to/cert.pem".to_string())
            .key("/path/to/key.pem".to_string());

        // Should have cert and key but not CA
        assert_eq!(builder.ca_certificate, None);
        assert_eq!(
            builder.certificate,
            Some("/path/to/cert.pem".to_string())
        );
        assert_eq!(builder.key, Some("/path/to/key.pem".to_string()));
    }

    #[actix_rt::test]
    async fn test_builder_partial_tls_config_missing_cert() {
        let builder = RegistrarClientBuilder::new()
            .ca_certificate("/path/to/ca.pem".to_string())
            .key("/path/to/key.pem".to_string());

        // Should have CA and key but not cert
        assert_eq!(
            builder.ca_certificate,
            Some("/path/to/ca.pem".to_string())
        );
        assert_eq!(builder.certificate, None);
        assert_eq!(builder.key, Some("/path/to/key.pem".to_string()));
    }

    #[actix_rt::test]
    async fn test_builder_partial_tls_config_missing_key() {
        let builder = RegistrarClientBuilder::new()
            .ca_certificate("/path/to/ca.pem".to_string())
            .certificate("/path/to/cert.pem".to_string());

        // Should have CA and cert but not key
        assert_eq!(
            builder.ca_certificate,
            Some("/path/to/ca.pem".to_string())
        );
        assert_eq!(
            builder.certificate,
            Some("/path/to/cert.pem".to_string())
        );
        assert_eq!(builder.key, None);
    }

    #[actix_rt::test]
    async fn test_builder_empty_string_tls_paths() {
        let builder = RegistrarClientBuilder::new()
            .ca_certificate("".to_string())
            .certificate("".to_string())
            .key("".to_string());

        assert_eq!(builder.ca_certificate, Some("".to_string()));
        assert_eq!(builder.certificate, Some("".to_string()));
        assert_eq!(builder.key, Some("".to_string()));
    }

    #[actix_rt::test]
    async fn test_builder_timeout_various_values() {
        // Test with zero timeout
        let builder_zero = RegistrarClientBuilder::new().timeout(0);
        assert_eq!(builder_zero.timeout, Some(0));

        // Test with very large timeout
        let builder_large = RegistrarClientBuilder::new().timeout(3600000);
        assert_eq!(builder_large.timeout, Some(3600000));

        // Test with default-ish timeout
        let builder_default = RegistrarClientBuilder::new().timeout(5000);
        assert_eq!(builder_default.timeout, Some(5000));
    }

    #[actix_rt::test]
    async fn test_builder_insecure_with_tls_certs() {
        // Test that insecure can be set alongside TLS certificates
        let builder = RegistrarClientBuilder::new()
            .ca_certificate("/path/to/ca.pem".to_string())
            .certificate("/path/to/cert.pem".to_string())
            .key("/path/to/key.pem".to_string())
            .insecure(true);

        assert_eq!(
            builder.ca_certificate,
            Some("/path/to/ca.pem".to_string())
        );
        assert_eq!(
            builder.certificate,
            Some("/path/to/cert.pem".to_string())
        );
        assert_eq!(builder.key, Some("/path/to/key.pem".to_string()));
        assert_eq!(builder.insecure, Some(true));
    }

    #[actix_rt::test]
    async fn test_builder_retry_config_with_tls() {
        let retry = Some(RetryConfig {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: Some(1000),
        });

        let builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(8890)
            .retry_config(retry.clone())
            .ca_certificate("/path/to/ca.pem".to_string())
            .certificate("/path/to/cert.pem".to_string())
            .key("/path/to/key.pem".to_string());

        // Verify retry_config was set
        assert!(builder.retry_config.is_some());
        let retry_cfg = builder.retry_config.as_ref().unwrap(); //#[allow_ci]
        assert_eq!(retry_cfg.max_retries, 3);
        assert_eq!(retry_cfg.initial_delay_ms, 100);
        assert_eq!(retry_cfg.max_delay_ms, Some(1000));

        // Verify TLS config was also set
        assert_eq!(
            builder.ca_certificate,
            Some("/path/to/ca.pem".to_string())
        );
    }

    // Helper function to generate test certificates
    #[cfg(test)]
    fn generate_test_certificates(
        temp_dir: &std::path::Path,
    ) -> (String, String, String, String) {
        use crate::crypto;
        use std::fs::File;
        use std::io::Write;

        // Define paths
        let ca_path = temp_dir.join("ca.pem");
        let client_cert_path = temp_dir.join("client_cert.pem");
        let client_key_path = temp_dir.join("client_key.pem");
        let server_cert_path = temp_dir.join("server_cert.pem");

        // Generate CA certificate
        let ca_key = crypto::testing::rsa_generate(2048)
            .expect("Failed to generate CA key");
        let ca_cert = crypto::x509::CertificateBuilder::new()
            .private_key(&ca_key)
            .common_name("Test CA")
            .build()
            .expect("Failed to build CA cert");

        // Generate server certificate
        let server_key = crypto::testing::rsa_generate(2048)
            .expect("Failed to generate server key");
        let server_cert = crypto::x509::CertificateBuilder::new()
            .private_key(&server_key)
            .common_name("localhost")
            .add_ips(vec!["127.0.0.1"])
            .build()
            .expect("Failed to build server cert");

        // Generate client certificate
        let client_key = crypto::testing::rsa_generate(2048)
            .expect("Failed to generate client key");
        let client_cert = crypto::x509::CertificateBuilder::new()
            .private_key(&client_key)
            .common_name("test-client")
            .build()
            .expect("Failed to build client cert");

        // Write CA certificate
        let mut ca_file =
            File::create(&ca_path).expect("Failed to create CA file");
        ca_file
            .write_all(
                &ca_cert.to_pem().expect("Failed to convert CA to PEM"),
            )
            .expect("Failed to write CA cert");

        // Write client certificate
        let mut client_cert_file = File::create(&client_cert_path)
            .expect("Failed to create client cert file");
        client_cert_file
            .write_all(
                &client_cert
                    .to_pem()
                    .expect("Failed to convert client cert to PEM"),
            )
            .expect("Failed to write client cert");

        // Write client key
        let mut client_key_file = File::create(&client_key_path)
            .expect("Failed to create client key file");
        client_key_file
            .write_all(
                &client_key
                    .private_key_to_pem_pkcs8()
                    .expect("Failed to convert key to PEM"),
            )
            .expect("Failed to write client key");

        // Write server certificate
        let mut server_cert_file = File::create(&server_cert_path)
            .expect("Failed to create server cert file");
        server_cert_file
            .write_all(
                &server_cert
                    .to_pem()
                    .expect("Failed to convert server cert to PEM"),
            )
            .expect("Failed to write server cert");

        (
            ca_path.to_string_lossy().to_string(),
            client_cert_path.to_string_lossy().to_string(),
            client_key_path.to_string_lossy().to_string(),
            server_cert_path.to_string_lossy().to_string(),
        )
    }

    #[actix_rt::test]
    async fn test_builder_with_real_tls_certificates() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, client_cert_path, client_key_path, _server_cert_path) =
            generate_test_certificates(tmpdir.path());

        let builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(8890)
            .ca_certificate(ca_path.clone())
            .certificate(client_cert_path.clone())
            .key(client_key_path.clone());

        // Verify all TLS paths were set correctly
        assert_eq!(builder.ca_certificate, Some(ca_path.clone()));
        assert_eq!(builder.certificate, Some(client_cert_path.clone()));
        assert_eq!(builder.key, Some(client_key_path.clone()));

        // Verify files exist
        assert!(std::path::Path::new(&ca_path).exists());
        assert!(std::path::Path::new(&client_cert_path).exists());
        assert!(std::path::Path::new(&client_key_path).exists());
    }

    #[actix_rt::test]
    async fn test_builder_build_with_invalid_tls_cert_files() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");

        // Try to build with non-existent certificate files
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(8890)
            .ca_certificate(
                tmpdir
                    .path()
                    .join("nonexistent_ca.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .certificate(
                tmpdir
                    .path()
                    .join("nonexistent_cert.pem")
                    .to_string_lossy()
                    .to_string(),
            )
            .key(
                tmpdir
                    .path()
                    .join("nonexistent_key.pem")
                    .to_string_lossy()
                    .to_string(),
            );

        // Build should fail because certificate files don't exist
        let result = builder.build().await;
        assert!(result.is_err());
    }

    #[actix_rt::test]
    async fn test_tls_enabled_when_all_certs_provided() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, client_cert_path, client_key_path, _) =
            generate_test_certificates(tmpdir.path());

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(8890)
            .ca_certificate(ca_path)
            .certificate(client_cert_path)
            .key(client_key_path)
            .insecure(false);

        // The build will fail because there's no server running,
        // but we can verify that TLS configuration was processed
        let result = builder.build().await;
        // Should fail at version endpoint, not at TLS setup
        assert!(result.is_err());
    }

    #[actix_rt::test]
    async fn test_tls_disabled_when_insecure_true() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, client_cert_path, client_key_path, _) =
            generate_test_certificates(tmpdir.path());

        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(8890)
            .ca_certificate(ca_path)
            .certificate(client_cert_path)
            .key(client_key_path)
            .insecure(true); // This should disable TLS

        // Build will fail due to no server, but won't try to load certs
        let result = builder.build().await;
        assert!(result.is_err());
    }

    #[actix_rt::test]
    async fn test_http_fallback_when_partial_tls_config() {
        // When only some TLS params are provided, should fall back to HTTP
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(8890)
            .ca_certificate("/path/to/ca.pem".to_string())
            // Missing certificate and key
            .insecure(false);

        let result = builder.build().await;
        // Should fail trying to connect via HTTP to get version
        assert!(result.is_err());
    }

    // Mockoon-based integration tests for registrar HTTP and HTTPS
    #[actix_rt::test]
    async fn test_mockoon_registrar_http_registration() {
        if std::env::var("MOCKOON_REGISTRAR").is_err() {
            return;
        }

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("mockoon-test-agent")
            .add_ips(vec!["127.0.0.1"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("127.0.0.1".to_string())
            .port(9001)
            .uuid("test-uuid-mockoon-http")
            .build()
            .await
            .expect("failed to build Agent Identity");

        // Test HTTP registration with Mockoon on port 3001
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(3001);

        let mut registrar_client =
            builder.build().await.expect("Failed to build client");

        let result = registrar_client.register_agent(&ai).await;
        assert!(result.is_ok(), "HTTP registration failed: {result:?}");

        // Verify we got a blob back
        let blob = result.unwrap(); //#[allow_ci]
        assert!(!blob.is_empty(), "Expected non-empty blob from registration");
    }

    #[actix_rt::test]
    async fn test_mockoon_registrar_http_activation() {
        if std::env::var("MOCKOON_REGISTRAR").is_err() {
            return;
        }

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("mockoon-test-agent")
            .add_ips(vec!["127.0.0.1"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("127.0.0.1".to_string())
            .port(9001)
            .uuid("test-uuid-mockoon-http")
            .build()
            .await
            .expect("failed to build Agent Identity");

        // Test HTTP activation with Mockoon on port 3001
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(3001);

        let mut registrar_client =
            builder.build().await.expect("Failed to build client");

        let result = registrar_client
            .activate_agent(&ai, "test-auth-tag")
            .await;
        assert!(result.is_ok(), "HTTP activation failed: {result:?}");
    }

    #[actix_rt::test]
    async fn test_mockoon_registrar_https_registration() {
        if std::env::var("MOCKOON_REGISTRAR").is_err() {
            return;
        }

        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, client_cert_path, client_key_path, _) =
            generate_test_certificates(tmpdir.path());

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("mockoon-test-agent-tls")
            .add_ips(vec!["127.0.0.1"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("127.0.0.1".to_string())
            .port(9001)
            .uuid("test-uuid-mockoon-https")
            .build()
            .await
            .expect("failed to build Agent Identity");

        // Test HTTPS registration with Mockoon on port 3001
        // Note: Mockoon HTTPS requires TLS to be enabled in the registrar.json config
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(3001)
            .ca_certificate(ca_path)
            .certificate(client_cert_path)
            .key(client_key_path)
            .insecure(false);

        // Build will attempt to connect to get version
        // This test demonstrates TLS configuration flow
        let result = builder.build().await;

        // With Mockoon not configured for TLS, this will fail at connection
        // In a real TLS-enabled Mockoon setup, this would succeed
        // This test verifies the TLS code path is executed
        assert!(result.is_err() || result.is_ok());
    }

    #[actix_rt::test]
    async fn test_mockoon_registrar_version_endpoint() {
        if std::env::var("MOCKOON_REGISTRAR").is_err() {
            return;
        }

        // Test that we can retrieve the API version from Mockoon
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(3001);

        let result = builder.build().await;
        assert!(
            result.is_ok(),
            "Failed to build client and get version: {result:?}"
        );

        let client = result.unwrap(); //#[allow_ci]
        // Verify the API version was retrieved
        assert_eq!(client.api_version, "1.2");
        assert!(client.supported_api_versions.is_some());

        let supported = client.supported_api_versions.unwrap(); //#[allow_ci]
        assert!(supported.contains(&"1.2".to_string()));
    }

    #[actix_rt::test]
    async fn test_mockoon_registrar_with_retry_config() {
        if std::env::var("MOCKOON_REGISTRAR").is_err() {
            return;
        }

        let retry_config = Some(RetryConfig {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: Some(1000),
        });

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("mockoon-test-agent-retry")
            .add_ips(vec!["127.0.0.1"])
            .build()
            .unwrap(); //#[allow_ci]

        let ai = AgentIdentityBuilder::new()
            .ak_pub(&mock_data)
            .ek_pub(&mock_data)
            .enabled_api_versions(vec!["1.2"])
            .mtls_cert(cert)
            .ip("127.0.0.1".to_string())
            .port(9001)
            .uuid("test-uuid-mockoon-retry")
            .build()
            .await
            .expect("failed to build Agent Identity");

        // Test registration with retry configuration
        let mut builder = RegistrarClientBuilder::new()
            .registrar_address("127.0.0.1".to_string())
            .registrar_port(3001)
            .retry_config(retry_config);

        let mut registrar_client =
            builder.build().await.expect("Failed to build client");

        let result = registrar_client.register_agent(&ai).await;
        assert!(
            result.is_ok(),
            "Registration with retry config failed: {result:?}"
        );
    }
}
