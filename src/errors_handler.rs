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
