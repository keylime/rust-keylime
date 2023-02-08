// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{common::JsonWrapper, revocation, Error, QuoteData, Result};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use log::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug)]
struct KeylimeRevocation {
    msg: String,
    signature: String,
}

// This is Revocation request from the cloud verifier via REST API
pub async fn revocation(
    body: web::Bytes,
    req: HttpRequest,
    data: web::Data<QuoteData>,
) -> impl Responder {
    info!("Received revocation");

    let json_body = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(e) => {
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("JSON parsing error: {e}"),
            ));
        }
    };

    let revocation_cert = match &data.revocation_cert {
        Some(cert) => cert,
        None => {
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(501, "Revocation certificate not set."),
            );
        }
    };

    let secure_size = &data.secure_size;
    let revocation_actions = match &data.revocation_actions {
        Some(actions) => actions,
        None => "",
    };

    let actions_dir = match &data.revocation_actions_dir {
        Some(dir) => dir,
        None => {
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    501,
                    "Revocation actions directory not set",
                ),
            );
        }
    };

    let payload_actions_allowed = data.allow_payload_revocation_actions;
    let work_dir = &data.work_dir;
    let mount = &data.secure_mount;

    match revocation::process_revocation(
        json_body,
        revocation_cert,
        secure_size,
        revocation_actions,
        actions_dir,
        payload_actions_allowed,
        work_dir,
        mount,
    ) {
        Ok(_) => HttpResponse::Ok().json(JsonWrapper::success(())),
        Err(e) => HttpResponse::InternalServerError().json(
            JsonWrapper::error(501, "Revocation actions directory not set"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::API_VERSION;
    use actix_web::{test, web, App};
    use serde_json::json;
    use std::{fs, path::Path};

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

        let quotedata = web::Data::new(QuoteData {
            revocation_cert,
            revocation_actions_dir,
            ..QuoteData::fixture().unwrap() //#[allow_ci]
        });

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

        // Create the message body with the payload and signature
        let revocation = KeylimeRevocation {
            msg: message,
            signature,
        };

        let req = test::TestRequest::post()
            .uri(&format!("/{API_VERSION}/notifications/revocation",))
            .set_json(&revocation)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
