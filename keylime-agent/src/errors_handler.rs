// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::QuoteData;
use actix_web::{
    body, dev,
    error::{InternalError, JsonPayloadError, PathError, QueryPayloadError},
    http,
    middleware::{ErrorHandlerResponse, ErrorHandlers},
    web, Error, HttpRequest, HttpResponse, Responder, Result,
};
use keylime::{json_wrapper::JsonWrapper, version::Version};
use log::*;

pub(crate) async fn app_default(
    req: HttpRequest,
    quote_data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    let error;
    let response;
    let message;

    let api_versions = quote_data
        .api_versions
        .iter()
        .map(|v| format!("/{v}"))
        .collect::<Vec<_>>()
        .join(", ");

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = format!(
                "Not Implemented: Use {api_versions} or /version interfaces"
            );
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, &message));
        }
        http::Method::POST => {
            error = 400;
            message = format!(
                "Not Implemented: Use {api_versions} or /version interfaces"
            );
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, &message));
        }
        _ => {
            error = 405;
            message = "Method is not supported".to_string();
            response = HttpResponse::MethodNotAllowed()
                .insert_header(http::header::Allow(vec![
                    http::Method::GET,
                    http::Method::POST,
                ]))
                .json(JsonWrapper::error(error, &message));
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

pub(crate) async fn version_not_supported(
    req: HttpRequest,
    version: web::Path<Version>,
) -> impl Responder {
    let message = format!("API version not supported: v{version}");

    warn!("{} returning 400 response. {}", req.head().method, message);

    HttpResponse::BadRequest().json(JsonWrapper::error(400, message))
}

pub(crate) fn json_parser_error(
    err: JsonPayloadError,
    req: &HttpRequest,
) -> Error {
    warn!("{} returning 400 response. {}", req.head().method, err);

    let resp = HttpResponse::BadRequest().json(JsonWrapper::error(400, &err));
    InternalError::from_response(err, resp).into()
}

pub(crate) fn query_parser_error(
    err: QueryPayloadError,
    req: &HttpRequest,
) -> Error {
    warn!("{} returning 400 response. {}", req.head().method, err);

    let resp = HttpResponse::BadRequest().json(JsonWrapper::error(400, &err));
    InternalError::from_response(err, resp).into()
}

pub(crate) fn path_parser_error(err: PathError, req: &HttpRequest) -> Error {
    warn!("{} returning 400 response. {}", req.head().method, err);

    let resp = HttpResponse::BadRequest().json(JsonWrapper::error(400, &err));
    InternalError::from_response(err, resp).into()
}

// This handler is ugly as there is no easy way to capture default errors emitted by the server and
// wrap using the JSON structure.
// see: https://github.com/actix/actix-web/issues/1604
pub(crate) fn wrap_404<B>(
    res: dev::ServiceResponse<B>,
) -> Result<ErrorHandlerResponse<body::BoxBody>> {
    let status = res.status();

    warn!(
        "{} returning 404 response. {}",
        res.request().head().method,
        status.canonical_reason().unwrap_or("Not Found")
    );

    let response =
        HttpResponse::build(res.status()).json(JsonWrapper::error(
            status.as_u16(),
            status.canonical_reason().unwrap_or("Not Found"),
        ));

    Ok(ErrorHandlerResponse::Response(dev::ServiceResponse::new(
        res.into_parts().0,
        response.map_into_left_body(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App, Resource};
    use core::future::Future;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};

    #[cfg(feature = "testing")]
    async fn test_default(resource: Resource, allow: &str) {
        let (fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]
        let quotedata = web::Data::new(fixture);
        let mut app = test::init_service(
            App::new().app_data(quotedata).service(resource),
        )
        .await;

        if allow.contains("GET") {
            let req = test::TestRequest::get().uri("/").to_request();

            let resp = test::call_service(&app, req).await;
            assert!(resp.status().is_client_error());

            let result: JsonWrapper<Value> = test::read_body_json(resp).await;

            assert_eq!(result.results, json!({}));
            assert_eq!(result.code, 400);
        }

        if allow.contains("POST") {
            let req = test::TestRequest::post()
                .uri("/")
                .data("some data")
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert!(resp.status().is_client_error());

            let result: JsonWrapper<Value> = test::read_body_json(resp).await;

            assert_eq!(result.results, json!({}));
            assert_eq!(result.code, 400);
        }

        let req = test::TestRequest::delete().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let headers = resp.headers();

        assert!(headers.contains_key("allow"));
        assert_eq!(headers.get("allow").unwrap().to_str().unwrap(), allow); //#[allow_ci]

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 405);
    }

    #[actix_rt::test]
    #[cfg(feature = "testing")]
    async fn test_app_default() {
        test_default(web::resource("/").to(app_default), "GET, POST").await
    }

    #[derive(Serialize, Deserialize)]
    struct DummyQuery {
        param: String,
    }

    #[derive(Serialize, Deserialize)]
    struct DummyPayload {
        field: u32,
    }

    #[derive(Serialize, Deserialize)]
    struct DummyPathParam {
        number: u32,
        string: String,
    }

    async fn dummy(
        req: HttpRequest,
        body: web::Json<DummyPayload>,
        query: web::Query<DummyQuery>,
    ) -> impl Responder {
        HttpResponse::Ok().await
    }

    async fn dummy_with_path(
        req: HttpRequest,
        path: web::Path<DummyPathParam>,
    ) -> impl Responder {
        HttpResponse::Ok().await
    }

    #[actix_rt::test]
    async fn test_parsing_error() {
        let mut app = test::init_service(
            App::new()
                .wrap(
                    ErrorHandlers::new()
                        .handler(http::StatusCode::NOT_FOUND, wrap_404),
                )
                .app_data(
                    web::JsonConfig::default()
                        .error_handler(json_parser_error),
                )
                .app_data(
                    web::QueryConfig::default()
                        .error_handler(query_parser_error),
                )
                .app_data(
                    web::PathConfig::default()
                        .error_handler(path_parser_error),
                )
                .service(
                    web::resource("/v2.2/ok").route(web::get().to(dummy)),
                )
                .service(
                    web::resource("/v2.2/ok/{number}/{string}")
                        .route(web::get().to(dummy_with_path)),
                )
                .service(
                    web::resource(r"/v{major:\d+}.{minor:\d+}{tail}*")
                        .to(version_not_supported),
                ),
        )
        .await;

        // Sanity well formed request
        let req = test::TestRequest::get()
            .uri("/v2.2/ok?param=Test")
            .set_json(&DummyPayload { field: 42 })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        // Test unsupported version
        let req = test::TestRequest::get()
            .uri("/v500.440/some/tail")
            .set_json(&DummyPayload { field: 42 })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert_eq!(result.status, "API version not supported: v500.440");

        // Test JSON parsing error
        let req = test::TestRequest::get()
            .uri("/v2.2/ok?param=Test")
            .insert_header(http::header::ContentType::json())
            .set_payload("Not JSON")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert!(result.status.contains("Json deserialize error"));

        // Test Query parsing error
        let req = test::TestRequest::get()
            .uri("/v2.2/ok?test=query")
            .set_json(&DummyPayload { field: 42 })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert!(result.status.contains("Query deserialize error"));

        // Test Path parsing error
        let req = test::TestRequest::get()
            .uri("/v2.2/ok/something/42?test=query")
            .set_json(&DummyPayload { field: 42 })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert!(result.status.contains("Path deserialize error"));

        // Test not found
        let req = test::TestRequest::get().uri("/notfound").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 404);
        assert!(result.status.contains("Not Found"));
    }
}
