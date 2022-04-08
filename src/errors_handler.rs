// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::common::{APIVersion, JsonWrapper, API_VERSION};
use actix_web::{
    error::{JsonPayloadError, PathError, QueryPayloadError},
    http, web, Error, HttpRequest, HttpResponse, Responder,
};
use log::*;

pub(crate) async fn app_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = format!(
                "Not Implemented: Use /version or /{}/ interfaces",
                API_VERSION
            );
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, &message));
        }
        http::Method::POST => {
            error = 400;
            message =
                format!("Not Implemented: Use /{}/ interface", API_VERSION);
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, &message));
        }
        _ => {
            error = 405;
            message = "Method is not supported".to_string();
            response = HttpResponse::MethodNotAllowed()
                .set(http::header::Allow(vec![
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

    response.await
}

pub(crate) async fn api_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = "Not Implemented: Use /keys/ or /quotes/ interfaces";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        http::Method::POST => {
            error = 400;
            message =
                "Not Implemented: Use /keys/ or /notifications/ interfaces";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported";
            response = HttpResponse::MethodNotAllowed()
                .set(http::header::Allow(vec![
                    http::Method::GET,
                    http::Method::POST,
                ]))
                .json(JsonWrapper::error(error, message));
        }
    };

    warn!(
        "{} returning {} response. {}",
        req.head().method,
        error,
        message
    );

    response.await
}

pub(crate) async fn keys_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = "URI not supported, only /pubkey and /verify are supported for GET in /keys/ interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        http::Method::POST => {
            error = 400;
            message = "URI not supported, only /ukey and /vkey are supported for POST in /keys/ interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported in /keys/ interface";
            response = HttpResponse::MethodNotAllowed()
                .set(http::header::Allow(vec![
                    http::Method::GET,
                    http::Method::POST,
                ]))
                .json(JsonWrapper::error(error, message));
        }
    };

    warn!(
        "{} returning {} response. {}",
        req.head().method,
        error,
        message
    );

    response.await
}

pub(crate) async fn quotes_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = "URI not supported, only /identity and /integrity are supported for GET in /quotes/ interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported in /quotes/ interface";
            response = HttpResponse::MethodNotAllowed()
                .set(http::header::Allow(vec![http::Method::GET]))
                .json(JsonWrapper::error(error, message));
        }
    };

    warn!(
        "{} returning {} response. {}",
        req.head().method,
        error,
        message
    );

    response.await
}

pub(crate) async fn notifications_default(
    req: HttpRequest,
) -> impl Responder {
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
                .set(http::header::Allow(vec![http::Method::POST]))
                .json(JsonWrapper::error(error, message));
        }
    };

    warn!(
        "{} returning {} response. {}",
        req.head().method,
        error,
        message
    );

    response.await
}

pub(crate) async fn version_not_supported(
    req: HttpRequest,
    version: web::Path<APIVersion>,
) -> impl Responder {
    let message = format!("API version not supported: {}", version);

    warn!("{} returning 400 response. {}", req.head().method, message);

    HttpResponse::BadRequest()
        .json(JsonWrapper::error(400, message))
        .await
}

pub(crate) fn json_parser_error(
    err: JsonPayloadError,
    req: &HttpRequest,
) -> Error {
    warn!("{} returning 400 response. {}", req.head().method, err);

    HttpResponse::BadRequest()
        .json(JsonWrapper::error(400, err))
        .into()
}

pub(crate) fn query_parser_error(
    err: QueryPayloadError,
    req: &HttpRequest,
) -> Error {
    warn!("{} returning 400 response. {}", req.head().method, err);

    HttpResponse::BadRequest()
        .json(JsonWrapper::error(400, err))
        .into()
}

pub(crate) fn path_parser_error(err: PathError, req: &HttpRequest) -> Error {
    warn!("{} returning 400 response. {}", req.head().method, err);

    HttpResponse::BadRequest()
        .json(JsonWrapper::error(400, err))
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App, Resource};
    use core::future::Future;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};

    async fn test_default(resource: Resource, allow: &str) {
        let mut app = test::init_service(App::new().service(resource)).await;

        if allow.contains("GET") {
            let req = test::TestRequest::get().uri("/").to_request();

            let resp = test::call_service(&mut app, req).await;
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

            let resp = test::call_service(&mut app, req).await;
            assert!(resp.status().is_client_error());

            let result: JsonWrapper<Value> = test::read_body_json(resp).await;

            assert_eq!(result.results, json!({}));
            assert_eq!(result.code, 400);
        }

        let req = test::TestRequest::delete().uri("/").to_request();

        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_client_error());

        let headers = resp.headers();

        assert!(headers.contains_key("allow"));
        assert_eq!(headers.get("allow").unwrap().to_str().unwrap(), allow); //#[allow_ci]

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 405);
    }

    #[actix_rt::test]
    async fn test_app_default() {
        test_default(web::resource("/").to(app_default), "GET, POST").await
    }

    #[actix_rt::test]
    async fn test_api_default() {
        test_default(web::resource("/").to(api_default), "GET, POST").await
    }

    #[actix_rt::test]
    async fn test_keys_default() {
        test_default(web::resource("/").to(keys_default), "GET, POST").await
    }

    #[actix_rt::test]
    async fn test_quotes_default() {
        test_default(web::resource("/").to(quotes_default), "GET").await
    }

    #[actix_rt::test]
    async fn test_notifications_default() {
        test_default(web::resource("/").to(notifications_default), "POST")
            .await
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
                    web::resource("/v2.0/ok").route(web::get().to(dummy)),
                )
                .service(
                    web::resource("/v2.0/ok/{number}/{string}")
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
            .uri("/v2.0/ok?param=Test")
            .set_json(&DummyPayload { field: 42 })
            .to_request();

        let resp = test::call_service(&mut app, req).await;

        assert!(resp.status().is_success());

        // Test unsupported version
        let req = test::TestRequest::get()
            .uri("/v500.440/some/tail")
            .set_json(&DummyPayload { field: 42 })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert_eq!(result.status, "API version not supported: v500.440");

        // Test JSON parsing error
        let req = test::TestRequest::get()
            .uri("/v2.0/ok?param=Test")
            .header(http::header::CONTENT_TYPE, "application/json")
            .set_payload("Not JSON")
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert!(result.status.contains("Json deserialize error"));

        // Test Query parsing error
        let req = test::TestRequest::get()
            .uri("/v2.0/ok?test=query")
            .set_json(&DummyPayload { field: 42 })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert!(result.status.contains("Query deserialize error"));

        // Test Path parsing error
        let req = test::TestRequest::get()
            .uri("/v2.0/ok/something/42?test=query")
            .set_json(&DummyPayload { field: 42 })
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_client_error());
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);
        assert!(result.status.contains("Path deserialize error"));
    }
}
