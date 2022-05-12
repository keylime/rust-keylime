// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Keylime Authors

use crate::common::{JsonWrapper, API_VERSION};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use log::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct KeylimeVersion {
    supported_version: String,
}

// This is the handler for the GET request for the API version
#[allow(clippy::unwrap_used)]
pub async fn version(req: HttpRequest) -> impl Responder {
    info!(
        "GET invoked from {:?} with uri {}",
        req.connection_info().peer_addr().unwrap(),
        req.uri()
    );

    let response = JsonWrapper::success(KeylimeVersion {
        supported_version: API_VERSION[1..].to_string(),
    });

    HttpResponse::Ok().json(response)
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_version() {
        let mut app = test::init_service(
            App::new().route("/version", web::get().to(version)),
        )
        .await;

        let req = test::TestRequest::get().uri("/version").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: JsonWrapper<KeylimeVersion> =
            test::read_body_json(resp).await;
        assert_eq!(body.results.supported_version, API_VERSION[1..]);
    }
}
