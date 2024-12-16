use crate::error::Error;

use crate::common::API_VERSION;
use keylime::serialization::*;
use log::*;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::Number;
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize)]
struct Register<'a> {
    #[serde(serialize_with = "serialize_maybe_base64")]
    ekcert: Option<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_as_base64",
        skip_serializing_if = "is_empty"
    )]
    ek_tpm: &'a [u8],
    #[serde(serialize_with = "serialize_as_base64")]
    aik_tpm: &'a [u8],
    #[serde(
        serialize_with = "serialize_option_base64",
        skip_serializing_if = "Option::is_none"
    )]
    iak_tpm: Option<&'a [u8]>,
    #[serde(
        serialize_with = "serialize_option_base64",
        skip_serializing_if = "Option::is_none"
    )]
    idevid_tpm: Option<&'a [u8]>,
    #[serde(serialize_with = "serialize_maybe_base64")]
    idevid_cert: Option<Vec<u8>>,
    #[serde(serialize_with = "serialize_maybe_base64")]
    iak_cert: Option<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_maybe_base64",
        skip_serializing_if = "Option::is_none"
    )]
    iak_attest: Option<Vec<u8>>,
    #[serde(
        serialize_with = "serialize_maybe_base64",
        skip_serializing_if = "Option::is_none"
    )]
    iak_sign: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtls_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u32>,
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

pub(crate) async fn do_activate_agent(
    registrar_ip: &str,
    registrar_port: u32,
    agent_uuid: &str,
    auth_tag: &str,
) -> crate::error::Result<()> {
    let data = Activate { auth_tag };

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
            // The registrar_ip option can also be a hostname. If it is the case, the hostname was
            // already validated during configuration
            registrar_ip.to_string()
        }
    };

    #[cfg(test)]
    let addr = format!("http://{remote_ip}:{registrar_port}");

    #[cfg(not(test))]
    let addr = format!(
        "http://{remote_ip}:{registrar_port}/{API_VERSION}/agents/{agent_uuid}"
    );

    info!(
        "Requesting agent activation from {} for {}",
        addr, agent_uuid
    );

    let resp = reqwest::Client::new().put(&addr).json(&data).send().await?;

    if !resp.status().is_success() {
        return Err(Error::Registrar {
            addr,
            code: resp.status().as_u16(),
        });
    }

    let resp: Response<ActivateResponseResults> = resp.json().await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_register_agent(
    registrar_ip: &str,
    registrar_port: u32,
    agent_uuid: &str,
    ek_tpm: &[u8],
    ekcert: Option<Vec<u8>>,
    aik_tpm: &[u8],
    iak_tpm: Option<&[u8]>,
    idevid_tpm: Option<&[u8]>,
    idevid_cert_x509: Option<X509>,
    iak_cert_x509: Option<X509>,
    iak_attest: Option<Vec<u8>>,
    iak_sign: Option<Vec<u8>>,
    mtls_cert_x509: Option<&X509>,
    ip: &str,
    port: u32,
) -> crate::error::Result<Vec<u8>> {
    let mtls_cert = match mtls_cert_x509 {
        Some(cert) => Some(crate::crypto::x509_to_pem(cert)?),
        None => Some("disabled".to_string()),
    };

    let idevid_cert = match idevid_cert_x509 {
        Some(cert) => Some(crate::crypto::x509_to_der(&cert)?),
        None => None,
    };

    let iak_cert = match iak_cert_x509 {
        Some(cert) => Some(crate::crypto::x509_to_der(&cert)?),
        None => None,
    };

    let ip = if ip.is_empty() {
        None
    } else {
        Some(ip.to_string())
    };

    let data = Register {
        ekcert,
        ek_tpm,
        aik_tpm,
        iak_tpm,
        idevid_tpm,
        idevid_cert,
        iak_cert,
        iak_attest,
        iak_sign,
        mtls_cert,
        ip,
        port: Some(port),
    };

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
            // The registrar_ip option can also be a hostname. If it is the case, the hostname was
            // already validated during configuration
            registrar_ip.to_string()
        }
    };

    #[cfg(test)]
    let addr = format!("http://{remote_ip}:{registrar_port}");

    #[cfg(not(test))]
    let addr = format!(
        "http://{remote_ip}:{registrar_port}/{API_VERSION}/agents/{agent_uuid}"
    );

    info!(
        "Requesting agent registration from {} for {}",
        addr, agent_uuid
    );

    let resp = reqwest::Client::new()
        .post(&addr)
        .json(&data)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(Error::Registrar {
            addr,
            code: resp.status().as_u16(),
        });
    }

    let resp: Response<RegisterResponseResults> = resp.json().await?;

    if resp.results.blob.is_some() {
        Ok(resp.results.blob.unwrap()) //#[allow_ci]
    } else {
        Ok(Vec::new())
    }
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use keylime::crypto;
    use wiremock::matchers::{any, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[actix_rt::test]
    async fn mock_register_agent_ok() {
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let addr = format!("http://{}:{}", uri[0], uri[1]);

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
        let response = do_register_agent(
            ip,
            port,
            "uuid",
            &mock_data,
            Some(mock_data.to_vec()),
            &mock_data,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            "1.2.3.4",
            0,
        )
        .await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn mock_register_agent_ok_without_ekcert() {
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let addr = format!("http://{}:{}", uri[0], uri[1]);

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
        let response = do_register_agent(
            ip,
            port,
            "uuid",
            &mock_data,
            None,
            &mock_data,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            "",
            0,
        )
        .await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn mock_register_agent_err() {
        let response: Response<RegisterResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: RegisterResponseResults { blob: None },
        };

        let mock_server = MockServer::start().await;
        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let addr = format!("http://{}:{}", uri[0], uri[1]);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let mock_data = [0u8; 1];
        let priv_key = crypto::testing::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::x509::CertificateBuilder::new()
            .private_key(&priv_key)
            .common_name("uuid")
            .build()
            .unwrap(); //#[allow_ci]
        let response = do_register_agent(
            ip,
            port,
            "uuid",
            &mock_data,
            Some(mock_data.to_vec()),
            &mock_data,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            "",
            0,
        )
        .await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap().http_code().unwrap(), 404); //#[allow_ci]
    }

    #[actix_rt::test]
    async fn mock_activate_agent_ok() {
        let response: Response<ActivateResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: ActivateResponseResults {},
        };

        let mock_server = MockServer::start().await;
        let mock = Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response));
        mock_server.register(mock).await;

        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let addr = format!("http://{}:{}", uri[0], uri[1]);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let response = do_activate_agent(ip, port, "uuid", "tag").await;
        assert!(response.is_ok());
    }

    #[actix_rt::test]
    async fn mock_activate_agent_err() {
        let response: Response<ActivateResponseResults> = Response {
            code: 200.into(),
            status: "OK".to_string(),
            results: ActivateResponseResults {},
        };

        let mock_server = MockServer::start().await;
        let uri = mock_server.uri();
        let uri = uri.split("//").collect::<Vec<&str>>()[1]
            .split(':')
            .collect::<Vec<&str>>();
        assert_eq!(uri.len(), 2);

        let addr = format!("http://{}:{}", uri[0], uri[1]);

        let ip = uri[0];
        let port = uri[1].parse().unwrap(); //#[allow_ci]

        let response = do_activate_agent(ip, port, "uuid", "tag").await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap().http_code().unwrap(), 404); //#[allow_ci]
    }
}
