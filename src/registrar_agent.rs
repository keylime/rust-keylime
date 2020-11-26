// use reqwest::header::*;
// use serde::{Deserialize, Serialize};
// // https://docs.rs/reqwest/0.9.2/reqwest/

// /* calling
// ek:  <class 'bytes'>
// ekcert:  <class 'str'>
// ek_tpm:  <class 'bytes'>
// aik:  <class 'bytes'>
// aik_name:  <class 'str'>

// # register it and get back a blob
// keyblob = registrar_client.doRegisterAgent(
//     registrar_ip, registrar_port, agent_uuid, tpm_version, ek, ekcert, aik, ek_tpm, aik_name)
// */

// #[derive(Debug, Serialize, Deserialize)]
// struct Register {
//     ek: Vec<u8>,
//     ekcert: String,
//     ek_tpm: Vec<u8>,
//     aik: Vec<u8>,
//     aik_name: String,
// }

// pub async fn payload_bearer_request(
//     path: &str,
//     payload: serde_json::Value,
//     token: &str,
// ) -> Result<reqwest::Response, reqwest::Error> {
//     let client = reqwest::Client::new();
//     client
//         .post(path)
//         .bearer_auth(token.to_string())
//         .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
//         .json(&payload)
//         .send()
//         .await?.error_for_status()
// }


// pub async fn doRegisterAgent(
//     registrar_ip: &str,
//     registrar_port: &str,
//     agent_uuid: &str,
// ) -> Result<(keyblob: Vec<u8>), reqwest::Error> {
// }

// /*
// retval = registrar_client.doActivateAgent(
//             registrar_ip, registrar_port, agent_uuid, key)
// */
// // async fn doActivateAgent() -> Result<()> {
// //     // revoker.await?;
// //     Ok(())
// // }
