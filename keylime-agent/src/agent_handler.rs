// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Keylime Authors

use crate::common::JsonWrapper;
use crate::{tpm, Error as KeylimeError, QuoteData};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use log::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AgentInfo {
    pub agent_uuid: String,
    pub tpm_hash_alg: String,
    pub tpm_enc_alg: String,
    pub tpm_sign_alg: String,
    pub ak_handle: u32,
}

// This is an Info request which gets some information about this keylime agent
// It should return a AgentInfo object as JSON
pub async fn info(
    req: HttpRequest,
    data: web::Data<QuoteData>,
) -> impl Responder {
    debug!("Returning agent information");

    let mut info = AgentInfo {
        agent_uuid: data.agent_uuid.clone(),
        tpm_hash_alg: data.hash_alg.to_string(),
        tpm_enc_alg: data.enc_alg.to_string(),
        tpm_sign_alg: data.sign_alg.to_string(),
        ak_handle: data.ak_handle.value(),
    };

    let response = JsonWrapper::success(info);
    info!("GET info returning 200 response");
    HttpResponse::Ok().json(response)
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {
    use super::*;
    use crate::common::API_VERSION;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_agent_info() {
        let mut quotedata = QuoteData::fixture().unwrap(); //#[allow_ci]
        quotedata.hash_alg = keylime::algorithms::HashAlgorithm::Sha256;
        quotedata.enc_alg = keylime::algorithms::EncryptionAlgorithm::Rsa;
        quotedata.sign_alg = keylime::algorithms::SignAlgorithm::RsaSsa;
        quotedata.agent_uuid = "DEADBEEF".to_string();
        let data = web::Data::new(quotedata);
        let mut app =
            test::init_service(App::new().app_data(data.clone()).route(
                &format!("/{API_VERSION}/agent/info"),
                web::get().to(info),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!("/{API_VERSION}/agent/info"))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<AgentInfo> = test::read_body_json(resp).await;
        assert_eq!(result.results.agent_uuid.as_str(), "DEADBEEF");
        assert_eq!(result.results.tpm_hash_alg.as_str(), "sha256");
        assert_eq!(result.results.tpm_enc_alg.as_str(), "rsa");
        assert_eq!(result.results.tpm_sign_alg.as_str(), "rsassa");
    }
}
