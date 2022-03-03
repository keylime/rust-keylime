use crate::error::Error;

use crate::common::PYTHON_API_VERSION;
use crate::serialization::*;
use log::*;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::Number;

fn is_empty(buf: &[u8]) -> bool {
    buf.is_empty()
}

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
    mtls_cert: String,
    ip: Option<String>,
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
    registrar_port: &str,
    agent_uuid: &str,
    auth_tag: &str,
) -> crate::error::Result<()> {
    let data = Activate { auth_tag };

    #[cfg(test)]
    let addr = format!("http://{}:{}", registrar_ip, registrar_port);

    #[cfg(not(test))]
    let addr = format!(
        "http://{}:{}/{}/agents/{}",
        registrar_ip, registrar_port, PYTHON_API_VERSION, agent_uuid
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
    registrar_port: &str,
    agent_uuid: &str,
    ek_tpm: &[u8],
    ekcert: Option<Vec<u8>>,
    aik_tpm: &[u8],
    mtls_cert_x509: &X509,
    ip: Option<String>,
    port: Option<u32>,
) -> crate::error::Result<Vec<u8>> {
    let mtls_cert = String::from_utf8(mtls_cert_x509.to_pem()?)?;

    let data = Register {
        ekcert,
        ek_tpm,
        aik_tpm,
        mtls_cert,
        ip,
        port,
    };

    #[cfg(test)]
    let addr = format!("http://{}:{}", registrar_ip, registrar_port);

    #[cfg(not(test))]
    let addr = format!(
        "http://{}:{}/{}/agents/{}",
        registrar_ip, registrar_port, PYTHON_API_VERSION, agent_uuid
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use wiremock::matchers::{any, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
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

        let mock_data = [0u8; 1];
        let priv_key = crypto::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::generate_x509(&priv_key, "uuid").unwrap(); //#[allow_ci]
        let response = do_register_agent(
            uri[0],
            uri[1],
            "uuid",
            &mock_data,
            Some((&mock_data).to_vec()),
            &mock_data,
            &cert,
            None,
            None,
        )
        .await;
        assert!(response.is_ok());
    }

    #[tokio::test]
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

        let mock_data = [0u8; 1];
        let priv_key = crypto::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::generate_x509(&priv_key, "uuid").unwrap(); //#[allow_ci]
        let response = do_register_agent(
            uri[0], uri[1], "uuid", &mock_data, None, &mock_data, &cert,
            None, None,
        )
        .await;
        assert!(response.is_ok());
    }

    #[tokio::test]
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

        let mock_data = [0u8; 1];
        let priv_key = crypto::rsa_generate(2048).unwrap(); //#[allow_ci]
        let cert = crypto::generate_x509(&priv_key, "uuid").unwrap(); //#[allow_ci]
        let response = do_register_agent(
            uri[0],
            uri[1],
            "uuid",
            &mock_data,
            Some((&mock_data).to_vec()),
            &mock_data,
            &cert,
            None,
            None,
        )
        .await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap().http_code().unwrap(), 404); //#[allow_ci]
    }

    #[tokio::test]
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

        let response = do_activate_agent(uri[0], uri[1], "uuid", "tag").await;
        assert!(response.is_ok());
    }

    #[tokio::test]
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

        let response = do_activate_agent(uri[0], uri[1], "uuid", "tag").await;
        assert!(response.is_err());
        assert_eq!(response.err().unwrap().http_code().unwrap(), 404); //#[allow_ci]
    }
}
