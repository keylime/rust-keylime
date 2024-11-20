// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{
    common::JsonWrapper,
    revocation::{Revocation, RevocationMessage},
    Error, QuoteData, Result,
};
use actix_web::{http, web, HttpRequest, HttpResponse, Responder};
use log::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// This is Revocation request from the cloud verifier via REST API
async fn revocation(
    body: web::Json<Revocation>,
    req: HttpRequest,
    data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    info!("Received revocation");

    match data
        .revocation_tx
        .send(RevocationMessage::Revocation(body.into_inner()))
        .await
    {
        Err(e) => {
            HttpResponse::InternalServerError().json(JsonWrapper::error(
                500,
                "Fail to send Revocation message to revocation worker"
                    .to_string(),
            ))
        }
        Ok(_) => HttpResponse::Ok().json(JsonWrapper::success(())),
    }
}

async fn notifications_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::POST => {
            error = 400;
            message = "URI not supported, only /revocation is supported for POST in /notifications/ interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported in /notifications/ interface";
            response = HttpResponse::MethodNotAllowed()
                .insert_header(http::header::Allow(vec![http::Method::POST]))
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

/// Configure the endpoints for the /notifications scope
pub(crate) fn configure_notifications_endpoints(
    cfg: &mut web::ServiceConfig,
) {
    _ = cfg
        .service(
            web::resource("/revocation").route(web::post().to(revocation)),
        )
        .default_service(web::to(notifications_default));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::API_VERSION;
    use actix_rt::Arbiter;
    use actix_web::{test, web, App};
    use serde_json::{json, Value};
    use std::{fs, path::Path};
    use tokio::sync::mpsc;

    #[actix_rt::test]
    async fn test_notifications_default() {
        let mut app = test::init_service(
            App::new().service(web::resource("/").to(notifications_default)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/")
            .data("some data")
            .to_request();

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
        assert_eq!(
            headers.get("allow").unwrap().to_str().unwrap(), //#[allow_ci]
            "POST"
        );

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 405);
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn test_revocation() {
        let revocation_cert = Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("test-data/test-cert.pem"),
        );

        let revocation_actions_dir = Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/actions"),
        );

        let (mut fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]

        // Replace the channels on the fixture with some local ones
        let (mut revocation_tx, mut revocation_rx) =
            mpsc::channel::<RevocationMessage>(1);
        fixture.revocation_tx = revocation_tx;

        let quotedata = web::Data::new(fixture);

        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{API_VERSION}/notifications/revocation"),
                web::post().to(revocation),
            ))
            .await;

        let sig_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data/revocation.sig");
        let signature = fs::read_to_string(sig_path).unwrap(); //#[allow_ci]

        let message_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data/test_ok.json");
        let message = fs::read_to_string(message_path).unwrap(); //#[allow_ci]

        let arbiter = Arbiter::new();

        // Create the message body with the payload and signature
        let revocation = Revocation {
            msg: message.clone(),
            signature: signature.clone(),
        };

        // Run fake revocation worker
        assert!(arbiter.spawn(Box::pin(async move {
            let m = revocation_rx.recv().await;
            assert!(
                m == Some(RevocationMessage::Revocation(Revocation {
                    msg: message,
                    signature,
                }))
            )
        })));

        let req = test::TestRequest::post()
            .uri(&format!("/{API_VERSION}/notifications/revocation",))
            .set_json(&revocation)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Explicitly drop QuoteData to cleanup keys
        drop(quotedata);
    }
}
