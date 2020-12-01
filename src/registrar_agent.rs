use crate::error::Error;
use reqwest::header::*;
use serde::{Deserialize, Serialize};
use serde_json::Number;

fn serialize_as_base64<S>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

fn deserialize_as_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        base64::decode(&string).map_err(serde::de::Error::custom)
    })
}

pub fn deserialize_maybe_base64<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<WrappedBase64Encoded>::deserialize(deserializer)
        .map(|wrapped| wrapped.map(|wrapped| wrapped.0))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Register<'a> {
    ek: &'a str,
    #[serde(serialize_with = "serialize_as_base64")]
    ekcert: &'a [u8],
    #[serde(serialize_with = "serialize_as_base64")]
    ek_tpm: &'a [u8],
    aik: &'a str,
    aik_name: &'a str,
    tpm_version: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponseResults {
    #[serde(deserialize_with = "deserialize_maybe_base64")]
    blob: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    code: Number,
    status: String,
    results: RegisterResponseResults,
}

#[derive(Debug, Deserialize)]
struct WrappedBase64Encoded(
    #[serde(deserialize_with = "deserialize_as_base64")] Vec<u8>,
);

pub(crate) async fn do_register_agent (
    registrar_ip: &str,
    registrar_port: &str,
    agent_uuid: &str,
    ek: &str,
    ekcert: &[u8],
    aik: &str,
    ek_tpm: &[u8],
    aik_name: &str,
) -> Result<RegisterResponse, Error> {
    let data = Register {
        ek: ek,
        ekcert: ekcert,
        ek_tpm: ek_tpm,
        aik: aik,
        aik_name: aik_name,
        tpm_version: 2,
    };
    reqwest::Client::new()
        .post("http://127.0.0.1:8890/agents/D432FBB3-D2F1-4A97-9EF7-75BD81C00000")
        .json(&data)
        .send()
        .await?
        .json()
        .await
        .map_err(|e|e.into())
}

