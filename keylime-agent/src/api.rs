use crate::{
    agent_handler, config, errors_handler, keys_handler,
    notifications_handler, quotes_handler, QuoteData,
};
use actix_web::{http, web, HttpRequest, HttpResponse, Responder, Scope};
use keylime::{
    config::SUPPORTED_API_VERSIONS,
    json_wrapper::JsonWrapper,
    list_parser::parse_list,
    version::{KeylimeVersion, Version},
};
use log::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum APIError {
    #[error("API version \"{0}\" not supported")]
    UnsupportedVersion(String),
}

/// Extract the API version from the request's app_data
///
/// Returns an error response if the API version is not configured.
/// This should never happen in production if routes are correctly configured.
pub(crate) fn get_api_version(
    req: &HttpRequest,
) -> Result<Version, HttpResponse> {
    req.app_data::<web::Data<Version>>()
        .map(|v| v.as_ref().clone())
        .ok_or_else(|| {
            error!("API version not configured for endpoint: {}", req.uri());
            HttpResponse::InternalServerError().json(JsonWrapper::error(
                500,
                "Internal server error: API version not configured",
            ))
        })
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

/// Configure the base endpoints shared by all API versions
///
/// This includes /keys, /quotes, and /notifications endpoints
fn configure_base_endpoints(cfg: &mut web::ServiceConfig) {
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

/// Configure the endpoints supported by API version 2.1
///
/// Version 2.1 is the base API version
fn configure_api_v2_1(cfg: &mut web::ServiceConfig) {
    let version = Version::from_str("2.1").expect("Invalid API version");
    _ = cfg.app_data(web::Data::new(version));
    configure_base_endpoints(cfg);
}

/// Configure the endpoints supported by API version 2.2
///
/// The version 2.2 added the /agent/info endpoint
fn configure_api_v2_2(cfg: &mut web::ServiceConfig) {
    let version = Version::from_str("2.2").expect("Invalid API version");
    _ = cfg.app_data(web::Data::new(version));
    configure_base_endpoints(cfg);

    // Configure added endpoints
    _ = cfg.service(
        web::scope("/agent")
            .configure(agent_handler::configure_agent_endpoints),
    )
}

/// Configure the endpoints supported by API version 2.3
///
/// Version 2.3 has the same agent-side endpoints as 2.2 (server-side only changes)
fn configure_api_v2_3(cfg: &mut web::ServiceConfig) {
    let version = Version::from_str("2.3").expect("Invalid API version");
    _ = cfg.app_data(web::Data::new(version));
    configure_base_endpoints(cfg);
    _ = cfg.service(
        web::scope("/agent")
            .configure(agent_handler::configure_agent_endpoints),
    )
}

/// Configure the endpoints supported by API version 2.4
///
/// Version 2.4 has the same agent-side endpoints as 2.2 (server-side only changes)
fn configure_api_v2_4(cfg: &mut web::ServiceConfig) {
    let version = Version::from_str("2.4").expect("Invalid API version");
    _ = cfg.app_data(web::Data::new(version));
    configure_base_endpoints(cfg);
    _ = cfg.service(
        web::scope("/agent")
            .configure(agent_handler::configure_agent_endpoints),
    )
}

/// Configure the endpoints supported by API version 2.5
///
/// Version 2.5 has the same agent-side endpoints as 2.2, but uses updated
/// algorithm reporting format (e.g., "rsa2048" instead of "rsa")
fn configure_api_v2_5(cfg: &mut web::ServiceConfig) {
    let version = Version::from_str("2.5").expect("Invalid API version");
    _ = cfg.app_data(web::Data::new(version));
    configure_base_endpoints(cfg);
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
        "2.3" => Ok(web::scope(format!("v{version}").as_ref())
            .configure(configure_api_v2_3)),
        "2.4" => Ok(web::scope(format!("v{version}").as_ref())
            .configure(configure_api_v2_4)),
        "2.5" => Ok(web::scope(format!("v{version}").as_ref())
            .configure(configure_api_v2_5)),
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
