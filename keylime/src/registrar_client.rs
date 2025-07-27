use crate::resilient_client::ResilientClient;
use crate::{
    agent_identity::AgentIdentity, agent_registration::RetryConfig,
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
}

#[derive(Debug, Default)]
pub struct RegistrarClientBuilder {
    registrar_current_api_version: Option<String>,
    registrar_supported_api_versions: Option<Vec<String>>,
    registrar_address: Option<String>,
    registrar_port: Option<u32>,
    retry_config: Option<RetryConfig>,
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
    ) -> Result<String, RegistrarClientBuilderError> {
        let Some(ref registrar_ip) = self.registrar_address else {
            return Err(RegistrarClientBuilderError::RegistrarIPNotSet);
        };

        let Some(registrar_port) = self.registrar_port else {
            return Err(RegistrarClientBuilderError::RegistrarPortNotSet);
        };

        // Try to reach the registrar
        let addr = format!("http://{registrar_ip}:{registrar_port}/version");

        info!("Requesting registrar API version to {addr}");

        let resp = if let Some(retry_config) = &self.retry_config {
            debug!(
                "Using ResilientClient for version check with {} retries.",
                retry_config.max_retries
            );
            let client = ResilientClient::new(
                None,
                Duration::from_millis(retry_config.initial_delay_ms),
                retry_config.max_retries,
                &[StatusCode::OK],
                retry_config.max_delay_ms.map(Duration::from_millis),
            );

            client
                .get_request(reqwest::Method::GET, &addr)
                .send()
                .await?
        } else {
            reqwest::Client::new()
                .get(&addr)
                .send()
                .await
                .map_err(RegistrarClientBuilderError::Reqwest)?
        };

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

        let resilient_client =
            self.retry_config.as_ref().map(|retry_config| {
                ResilientClient::new(
                    None,
                    Duration::from_millis(retry_config.initial_delay_ms),
                    retry_config.max_retries,
                    &[StatusCode::OK],
                    retry_config.max_delay_ms.map(Duration::from_millis),
                )
            });

        Ok(RegistrarClient {
            supported_api_versions: self
                .registrar_supported_api_versions
                .clone(),
            api_version: registrar_api_version,
            registrar_ip,
            registrar_port,
            resilient_client,
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

#[derive(Clone, Default, Debug)]
pub struct RegistrarClient {
    api_version: String,
    supported_api_versions: Option<Vec<String>>,
    registrar_ip: String,
    registrar_port: u32,
    resilient_client: Option<ResilientClient>,
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

        let addr = format!(
            "http://{registrar_ip}:{registrar_port}/v{api_version}/agents/{uuid}",
        );

        info!(
            "Requesting agent registration from {} for {}",
            &addr, &ai.uuid
        );

        let resp = match self.resilient_client {
            Some(ref client) => client
                .get_json_request_from_struct(
                    reqwest::Method::POST,
                    &addr,
                    &data,
                    None,
                )
                .map_err(RegistrarClientError::Serde)?
                .send()
                .await
                .map_err(RegistrarClientError::Middleware)?,
            None => {
                reqwest::Client::new()
                    .post(&addr)
                    .json(&data)
                    .send()
                    .await?
            }
        };

        if !resp.status().is_success() {
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

        let addr = format!(
            "http://{registrar_ip}:{registrar_port}/v{api_version}/agents/{uuid}",
        );

        info!(
            "Requesting agent activation from {} for {}",
            &addr, &ai.uuid
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
}
