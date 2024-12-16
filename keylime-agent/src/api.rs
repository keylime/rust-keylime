use crate::{
    agent_handler, common::JsonWrapper, config, errors_handler, keys_handler,
    notifications_handler, quotes_handler, QuoteData,
};
use actix_web::{http, web, HttpRequest, HttpResponse, Responder, Scope};
use keylime::{list_parser::parse_list, version::KeylimeVersion};
use log::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub static SUPPORTED_API_VERSIONS: &[&str] = &["2.1", "2.2"];

#[derive(Error, Debug, PartialEq)]
pub enum APIError {
    #[error("API version \"{0}\" not supported")]
    UnsupportedVersion(String),
}

/// This is the handler for the GET request for the API version
pub async fn version(
    req: HttpRequest,
    quote_data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    info!(
        "GET invoked from {:?} with uri {}",
        req.connection_info().peer_addr().unwrap(), //#[allow_ci]
        req.uri()
    );

    // The response reports the latest supported version or error
    match quote_data.api_versions.last() {
        Some(version) => {
            HttpResponse::Ok().json(JsonWrapper::success(KeylimeVersion {
                supported_version: version.clone(),
            }))
        }
        None => HttpResponse::InternalServerError()
            .json(JsonWrapper::error(500, "Misconfigured API version")),
    }
}

/// Handles the default case for the API version scope
async fn api_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message =
                "Not Implemented: Use /agent, /keys, or /quotes interfaces";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        http::Method::POST => {
            error = 400;
            message =
                "Not Implemented: Use /keys or /notifications interfaces";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported";
            response = HttpResponse::MethodNotAllowed()
                .insert_header(http::header::Allow(vec![
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

    response
}

/// Configure the endpoints supported by API version 2.1
///
/// Version 2.1 is the base API version
fn configure_api_v2_1(cfg: &mut web::ServiceConfig) {
    _ = cfg
        .service(
            web::scope("/keys")
                .configure(keys_handler::configure_keys_endpoints),
        )
        .service(web::scope("/notifications").configure(
            notifications_handler::configure_notifications_endpoints,
        ))
        .service(
            web::scope("/quotes")
                .configure(quotes_handler::configure_quotes_endpoints),
        )
        .default_service(web::to(api_default))
}

/// Configure the endpoints supported by API version 2.2
///
/// The version 2.2 added the /agent/info endpoint
fn configure_api_v2_2(cfg: &mut web::ServiceConfig) {
    // Configure the endpoints shared with version 2.1
    configure_api_v2_1(cfg);

    // Configure added endpoints
    _ = cfg.service(
        web::scope("/agent")
            .configure(agent_handler::configure_agent_endpoints),
    )
}

/// Get a scope configured for the given API version
pub(crate) fn get_api_scope(version: &str) -> Result<Scope, APIError> {
    match version {
        "2.1" => Ok(web::scope(format!("v{version}").as_ref())
            .configure(configure_api_v2_1)),
        "2.2" => Ok(web::scope(format!("v{version}").as_ref())
            .configure(configure_api_v2_2)),
        _ => Err(APIError::UnsupportedVersion(version.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use serde_json::{json, Value};

    #[actix_rt::test]
    async fn test_configure_api() {
        // Test that invalid version results in error
        let result = get_api_scope("invalid");
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, APIError::UnsupportedVersion("invalid".into()));
        }

        // Test that a valid version is successful
        let version = SUPPORTED_API_VERSIONS.last().unwrap(); //#[allow_ci]
        let result = get_api_scope(version);
        assert!(
            result.is_ok(),
            "Failed to get scope for version \"{version}\""
        );
        let scope = result.unwrap(); //#[allow_ci]
    }

    #[actix_rt::test]
    async fn test_api_default() {
        let mut app = test::init_service(
            App::new().service(web::resource("/").to(api_default)),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);

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
            "GET, POST"
        );

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 405);
    }

    #[actix_rt::test]
    #[cfg(feature = "testing")]
    async fn test_default_version() {
        let (fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]
        let quotedata = web::Data::new(fixture);
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata)
                .route("/version", web::get().to(version)),
        )
        .await;

        let req = test::TestRequest::get().uri("/version").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: JsonWrapper<KeylimeVersion> =
            test::read_body_json(resp).await;
        assert_eq!(
            Some(body.results.supported_version),
            SUPPORTED_API_VERSIONS.last().map(|x| x.to_string())
        );
    }

    #[actix_rt::test]
    #[cfg(feature = "testing")]
    async fn test_custom_version() {
        // Get the first supported API version
        let first = SUPPORTED_API_VERSIONS[0].to_string();

        let (mut fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]

        // Set the API version with only the first supported version
        fixture.api_versions = vec![first];
        let quotedata = web::Data::new(fixture);

        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("/version", web::get().to(version)),
        )
        .await;

        let req = test::TestRequest::get().uri("/version").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Check that the returned version is the version from the configuration
        let body: JsonWrapper<KeylimeVersion> =
            test::read_body_json(resp).await;
        assert_eq!(
            body.results.supported_version,
            SUPPORTED_API_VERSIONS[0].to_string(),
        );
    }

    #[actix_rt::test]
    #[cfg(feature = "testing")]
    async fn test_misconfigured_version() {
        let (mut fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]

        // Set the API version with empty Vec
        fixture.api_versions = vec![];
        let quotedata = web::Data::new(fixture);

        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("/version", web::get().to(version)),
        )
        .await;

        let req = test::TestRequest::get().uri("/version").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_server_error());

        // Check that the returned version is the version from the configuration
        let result: JsonWrapper<Value> = test::read_body_json(resp).await;
        assert_eq!(result.code, 500);
    }
}
