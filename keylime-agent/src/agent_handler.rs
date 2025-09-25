// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Keylime Authors

use crate::{tpm, Error as KeylimeError, QuoteData};
use actix_web::{http, web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use keylime::json_wrapper::JsonWrapper;
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
async fn info(
    req: HttpRequest,
    data: web::Data<QuoteData<'_>>,
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

/// Configure the endpoints for the /agent scope
async fn agent_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = "URI not supported, only /info is supported for GET in /agent interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported in /agent interface";
            response = HttpResponse::MethodNotAllowed()
                .insert_header(http::header::Allow(vec![http::Method::GET]))
                .json(JsonWrapper::error(error, message));
        }
    };

    warn!(
        "{} returning {} response. {}",
        req.head().method,
        error,
        message
    );

    response
}

/// Configure the endpoints for the /agents scope
pub(crate) fn configure_agent_endpoints(cfg: &mut web::ServiceConfig) {
    _ = cfg
        .service(web::resource("/info").route(web::get().to(info)))
        .default_service(web::to(agent_default));
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use serde_json::{json, Value};

    #[actix_rt::test]
    async fn test_agent_info() {
        let (mut quotedata, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]
        quotedata.hash_alg = keylime::algorithms::HashAlgorithm::Sha256;
        quotedata.enc_alg = keylime::algorithms::EncryptionAlgorithm::Rsa2048;
        quotedata.sign_alg = keylime::algorithms::SignAlgorithm::RsaSsa;
        quotedata.agent_uuid = "DEADBEEF".to_string();
        let data = web::Data::new(quotedata);
        let mut app = test::init_service(
            App::new()
                .app_data(data.clone())
                .route("/vX.Y/agent/info", web::get().to(info)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/vX.Y/agent/info")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<AgentInfo> = test::read_body_json(resp).await;
        assert_eq!(result.results.agent_uuid.as_str(), "DEADBEEF");
        assert_eq!(result.results.tpm_hash_alg.as_str(), "sha256");
        assert_eq!(result.results.tpm_enc_alg.as_str(), "rsa2048");
        assert_eq!(result.results.tpm_sign_alg.as_str(), "rsassa");

        // Explicitly drop QuoteData to cleanup keys
        drop(data);
    }

    #[actix_rt::test]
    async fn test_agents_default() {
        let mut app = test::init_service(
            App::new().service(web::resource("/").to(agent_default)),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);

        let req = test::TestRequest::delete().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let headers = resp.headers();

        assert!(headers.contains_key("allow"));
        assert_eq!(headers.get("allow").unwrap().to_str().unwrap(), "GET"); //#[allow_ci]

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 405);
    }
}
