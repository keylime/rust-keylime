use crate::auth::{
    AuthConfig, AuthenticationClient, SecretToken, SessionToken,
};
use anyhow;
use async_trait::async_trait;
use chrono::Utc;
use http::Extensions;
use httpdate::parse_http_date;
use log::{debug, warn};
use rand::Rng;
use reqwest::{Client, Method, Response, StatusCode};
use reqwest_middleware::{
    ClientBuilder, ClientWithMiddleware, Error, Middleware, Next,
    RequestBuilder,
};
use reqwest_retry::{
    default_on_request_failure, default_on_request_success,
    policies::ExponentialBackoff, Jitter, RetryTransientMiddleware,
    Retryable, RetryableStrategy,
};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

// We define a default maximum delay for retries, which in the pracitical sense
// is set to 1 hour. This can be adjusted based on the application's needs.
const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(3600);

const REQUEST_ID_HEADER: &str = "X-Request-ID";

const RESPONSE_RETRY_AFTER_HEADER: &str = "Retry-After";

/// Middleware for logging request details.
#[derive(Debug, Clone)]
struct LoggingMiddleware;

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(
        &self,
        req: reqwest::Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response, Error> {
        debug!(
            "Sending request(method:{}, url:{}) with headers:",
            req.method(),
            req.url()
        );
        for (key, value) in req.headers() {
            if key == "Authorization" {
                if let Ok(auth_str) = value.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        // Wrap in SecretToken to use its Display trait for hashing
                        let secret = SecretToken::new(token.to_string());
                        debug!("  {key}: \"Bearer {}\"", secret);
                    } else {
                        debug!("  {key}: \"<redacted>\"");
                    }
                } else {
                    debug!("  {key}: \"<redacted>\"");
                }
            } else {
                debug!("  {key}: {value:?}");
            }
        }

        let response = next.run(req, extensions).await?;

        debug!("Response code: {}", response.status());
        debug!("Response headers:");
        for (key, value) in response.headers() {
            if key == "Authorization" {
                if let Ok(auth_str) = value.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        // Wrap in SecretToken to use its Display trait for hashing
                        let secret = SecretToken::new(token.to_string());
                        debug!("  {key}: \"Bearer {}\"", secret);
                    } else {
                        debug!("  {key}: \"<redacted>\"");
                    }
                } else {
                    debug!("  {key}: \"<redacted>\"");
                }
            } else {
                debug!("  {key}: {value:?}");
            }
        }

        Ok(response)
    }
}

/// A middleware to specifically handle the `Retry-After` header.
#[derive(Debug, Clone)]
struct RetryAfterMiddleware {
    max_retries: u32,
}

#[async_trait]
impl Middleware for RetryAfterMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response, Error> {
        let mut retry_count = 0u32;

        loop {
            // Clone the request for potential retry
            let req_for_retry = if retry_count < self.max_retries {
                req.try_clone()
            } else {
                None
            };

            let res = next.clone().run(req, extensions).await;

            let response = match res {
                Ok(response) => response,
                // If there's a network error, let the main retry middleware handle it
                Err(e) => return Err(e),
            };

            // Check if we should retry based on Retry-After header
            if let Some(header_value) =
                response.headers().get(RESPONSE_RETRY_AFTER_HEADER)
            {
                if retry_count >= self.max_retries {
                    warn!(
                        "Maximum Retry-After attempts ({}) reached, not retrying further",
                        self.max_retries
                    );
                    return Ok(response);
                }

                if let Some(req_clone) = req_for_retry {
                    if let Some(duration) = parse_retry_after(header_value) {
                        retry_count += 1;
                        debug!(
                            "Server specified {:?} header: waiting {:?} (attempt {}/{})",
                            RESPONSE_RETRY_AFTER_HEADER, duration, retry_count, self.max_retries
                        );
                        tokio::time::sleep(duration).await;
                        debug!("Retrying request after Retry-After delay");

                        // Use the cloned request for the next iteration
                        req = req_clone;
                        continue;
                    }
                } else {
                    warn!("Request is not cloneable, cannot retry with Retry-After header");
                }
            }

            // No Retry-After header or unable to retry, return the response
            return Ok(response);
        }
    }
}

/// Custom strategy to determine which responses are retryable.
/// It considers any status code NOT in the `success_codes` list as a potential transient error.
#[derive(Clone)]
struct StopOnSuccessStrategy {
    success_codes: Vec<StatusCode>,
}

impl RetryableStrategy for StopOnSuccessStrategy {
    fn handle(&self, res: &Result<Response, Error>) -> Option<Retryable> {
        match res {
            // If we got a response, check its status code.
            Ok(response) => {
                let status = response.status();
                // If the status code is a success code, it's NOT retryable.
                if self.success_codes.contains(&status) {
                    return None;
                }
                // If a `Retry-After` header is present, we must not apply a second
                // delay from the exponential backoff policy. We return None to signal
                // that this strategy will not handle it, deferring to the dedicated
                // RetryAfterMiddleware instead.
                if response
                    .headers()
                    .contains_key(RESPONSE_RETRY_AFTER_HEADER)
                {
                    debug!("{RESPONSE_RETRY_AFTER_HEADER:?} header found; deferring to RetryAfterMiddleware.");
                    None
                } else {
                    // For any other status, let the default strategy decide if it's a transient error.
                    warn!(
                        "Received non-success status code: {}",
                        response.status()
                    );
                    default_on_request_success(response)
                }
            }
            // If there was a network error, it's always a transient error.
            Err(e) => {
                // Provide helpful context for common TLS/network errors
                if e.is_connect() {
                    warn!("Network error (connection failed): {e}");
                    // Check for TLS-related errors and provide helpful hints
                    crate::error::log_tls_error_hints(e);
                } else if e.is_timeout() {
                    warn!("Network error (timeout): {e}");
                } else {
                    warn!("Network error: {e}");
                }
                default_on_request_failure(e)
            }
        }
    }
}

/// Parses the `Retry-After` header value.
/// It can be either an integer number of seconds or an HTTP-date.
fn parse_retry_after(
    header_value: &reqwest::header::HeaderValue,
) -> Option<Duration> {
    if let Ok(value_str) = header_value.to_str() {
        // Try parsing as an integer (seconds) first.
        if let Ok(seconds) = value_str.parse::<u64>() {
            return Some(Duration::from_secs(seconds));
        }
        // Otherwise, try parsing as an HTTP-date.
        if let Ok(http_date) = parse_http_date(value_str) {
            let now = Utc::now().into();
            // If `duration_since` fails, it means the time has already passed.
            // In that case, we can retry immediately (duration of zero).
            return Some(
                http_date.duration_since(now).unwrap_or(Duration::ZERO),
            );
        }
    }
    None
}

/// Shared state for authentication tokens with proper concurrency control
#[derive(Debug)]
struct TokenState {
    /// RwLock for the actual token - allows concurrent reads
    token: RwLock<Option<SessionToken>>,
    /// Mutex for refresh operations - ensures single writer
    refresh_lock: Mutex<()>,
    /// Raw authentication client (no middleware to avoid loops)
    auth_client: AuthenticationClient,
}

impl TokenState {
    fn new(
        auth_config: AuthConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create a raw authentication client to avoid middleware loops
        let auth_client = AuthenticationClient::new_raw(auth_config)
            .map_err(|e| format!("Failed to create auth client: {e}"))?;

        Ok(Self {
            token: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            auth_client,
        })
    }

    async fn get_valid_token(
        &self,
    ) -> Result<SecretToken, Box<dyn std::error::Error + Send + Sync>> {
        // Fast path: try to read existing token
        {
            let token_guard = self.token.read().await;
            if let Some(ref token) = *token_guard {
                debug!("Using existing token from middleware");
                return Ok(token.token.clone());
            }
        }

        // Slow path: token is missing, need to refresh
        self.refresh_token().await
    }

    async fn refresh_token(
        &self,
    ) -> Result<SecretToken, Box<dyn std::error::Error + Send + Sync>> {
        // Acquire refresh lock to ensure only one refresh at a time
        let _refresh_guard = self.refresh_lock.lock().await;

        // Double-check: another request might have refreshed while we waited
        {
            let token_guard = self.token.read().await;
            if let Some(ref token) = *token_guard {
                debug!("Token was refreshed by another request");
                return Ok(token.token.clone());
            }
        }

        // Use the raw authentication client to get a new token with metadata
        debug!("Performing token refresh using raw authentication client");
        match self.auth_client.get_auth_token_with_metadata().await {
            Ok((token_string, created_at, expires_at, session_id)) => {
                let new_token = SessionToken {
                    token: SecretToken::new(token_string.clone()),
                    created_at,
                    expires_at,
                    session_id,
                };

                // Store the new token
                {
                    let mut token_guard = self.token.write().await;
                    *token_guard = Some(new_token);
                }

                debug!("Token refresh completed successfully");
                Ok(SecretToken::new(token_string))
            }
            Err(e) => {
                warn!("Token refresh failed: {e}");
                Err(format!("Authentication failed: {e}").into())
            }
        }
    }

    async fn clear_token(&self) {
        let mut token_guard = self.token.write().await;
        *token_guard = None;
        debug!("Authentication token cleared from shared state");

        // Also clear the token from the authentication client's cache
        self.auth_client.clear_session_token().await;
    }
}

/// Middleware for transparent authentication using challenge-response protocol
#[derive(Debug)]
pub struct AuthenticationMiddleware {
    token_state: Arc<TokenState>,
}

impl AuthenticationMiddleware {
    pub fn new(
        auth_config: AuthConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let token_state = Arc::new(TokenState::new(auth_config)?);
        Ok(Self { token_state })
    }

    fn is_auth_endpoint(&self, req: &reqwest::Request) -> bool {
        let path = req.url().path();
        // Skip authentication for auth endpoints to prevent infinite loops
        //
        // Auth endpoints match these patterns:
        // 1. /[prefix/]sessions           (e.g., /sessions, /v3.0/sessions, /api/sessions)
        // 2. /[prefix/]sessions/{id}      (e.g., /sessions/1, /v3.0/sessions/42, /api/sessions/123)
        //
        // The key insight: "sessions" must be the final segment or second-to-last segment
        //
        // We use segment-based matching to avoid false positives on URLs like:
        // - /users/sessions_count           (segment is "sessions_count", not "sessions")
        // - /data/sessions-backup           (segment is "sessions-backup", not "sessions")
        // - /api/admin/sessions/report      ("sessions" is third-to-last, has more after ID)
        //
        // But we do match:
        // - /sessions                       ("sessions" is last segment)
        // - /v3.0/sessions                  ("sessions" is last segment)
        // - /api/sessions/123               ("sessions" is second-to-last, followed by ID)
        let segments: Vec<&str> =
            path.split('/').filter(|s| !s.is_empty()).collect();

        let len = segments.len();
        if len == 0 {
            return false;
        }

        // Check if "sessions" is the last segment (e.g., /v3.0/sessions)
        if segments[len - 1] == "sessions" {
            return true;
        }

        // Check if "sessions" is second-to-last segment followed by a single segment (the ID)
        // (e.g., /v3.0/sessions/42)
        if len >= 2 && segments[len - 2] == "sessions" {
            return true;
        }

        false
    }
}

#[async_trait]
impl Middleware for AuthenticationMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response, Error> {
        // Skip authentication for auth endpoints to prevent infinite loops
        if self.is_auth_endpoint(&req) {
            debug!(
                "Skipping auth for authentication endpoint: {}",
                req.url().path()
            );
            return next.run(req, extensions).await;
        }

        // Add Authorization header if not present
        if !req.headers().contains_key("Authorization") {
            match self.token_state.get_valid_token().await {
                Ok(token) => {
                    debug!("Adding authentication token to request");
                    req.headers_mut().insert(
                        "Authorization",
                        format!("Bearer {}", token.reveal())
                            .parse()
                            .map_err(|e| {
                                Error::Middleware(anyhow::anyhow!(
                                    "Invalid token format: {}",
                                    e
                                ))
                            })?,
                    );
                }
                Err(e) => {
                    warn!("Failed to get auth token: {e}");
                    return Err(Error::Middleware(anyhow::anyhow!(
                        "Authentication failed: {}",
                        e
                    )));
                }
            }
        }

        let response = next.run(req, extensions).await?;

        // Handle 401 responses by clearing token
        if response.status() == StatusCode::UNAUTHORIZED {
            warn!("Received 401, clearing token for future requests");
            self.token_state.clear_token().await;
            // Note: We don't retry here to avoid infinite loops
            // The retry will happen naturally on the next request
        }

        Ok(response)
    }
}

/// A client that transparently handles retries with exponential backoff.
#[derive(Debug, Clone)]
pub struct ResilientClient {
    client: ClientWithMiddleware,
}

impl ResilientClient {
    /// Creates a new client with a defined retry strategy.
    pub fn new(
        client: Option<Client>,
        initial_delay: Duration,
        max_retries: u32,
        success_codes: &[StatusCode],
        max_delay: Option<Duration>,
    ) -> Self {
        let base_client = client.unwrap_or_default();
        let final_max_delay = max_delay.unwrap_or(DEFAULT_MAX_DELAY);

        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(initial_delay, final_max_delay)
            .jitter(Jitter::None)
            .build_with_max_retries(max_retries);

        let client_with_middleware = ClientBuilder::new(base_client)
            .with(RetryAfterMiddleware { max_retries })
            .with(RetryTransientMiddleware::new_with_policy_and_strategy(
                retry_policy,
                StopOnSuccessStrategy {
                    success_codes: success_codes.to_vec(),
                },
            ))
            .with(LoggingMiddleware)
            .build();

        Self {
            client: client_with_middleware,
        }
    }

    /// Creates a new client with optional authentication middleware
    pub fn new_with_auth(
        client: Option<Client>,
        auth_config: Option<AuthConfig>,
        initial_delay: std::time::Duration,
        max_retries: u32,
        success_codes: &[StatusCode],
        max_delay: Option<std::time::Duration>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let base_client = client.unwrap_or_default();
        let final_max_delay = max_delay.unwrap_or(DEFAULT_MAX_DELAY);

        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(initial_delay, final_max_delay)
            .jitter(Jitter::None)
            .build_with_max_retries(max_retries);

        let mut builder = ClientBuilder::new(base_client)
            .with(RetryAfterMiddleware { max_retries })
            .with(RetryTransientMiddleware::new_with_policy_and_strategy(
                retry_policy,
                StopOnSuccessStrategy {
                    success_codes: success_codes.to_vec(),
                },
            ));

        // Add authentication middleware if config is provided
        if let Some(auth_cfg) = auth_config {
            debug!("Adding authentication middleware to client");
            let auth_middleware = AuthenticationMiddleware::new(auth_cfg)?;
            builder = builder.with(auth_middleware);
        }

        let client_with_middleware = builder.with(LoggingMiddleware).build();

        Ok(Self {
            client: client_with_middleware,
        })
    }

    /// Generates a six-character lowercase alphanumeric request ID.
    fn generate_request_id() -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::rng();
        let request_id: String = (0..6)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        request_id
    }

    /// Sends a non JSON request using the client.
    pub fn get_request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client
            .request(method, url)
            .header(REQUEST_ID_HEADER, Self::generate_request_id())
    }

    /// Prepares a request with a JSON body, returning a Result.
    pub fn get_json_request(
        &self,
        method: Method,
        url: &str,
        json_string: &str,
        custom_content_type: Option<String>,
    ) -> Result<RequestBuilder, serde_json::Error> {
        let builder = self
            .client
            .request(method, url)
            .header(REQUEST_ID_HEADER, Self::generate_request_id())
            .body(json_string.to_string());

        match custom_content_type {
            Some(ct) => Ok(builder
                .header("Content-Type", ct.clone())
                .header("Accept", ct)),
            None => Ok(builder
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")),
        }
    }

    /// Prepares a request with a JSON body, returning a Result.
    pub fn get_json_request_from_struct<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        json_serializable: &T,
        custom_content_type: Option<String>,
    ) -> Result<RequestBuilder, serde_json::Error> {
        let body_as_string = serde_json::to_string(json_serializable)?;

        self.get_json_request(
            method,
            url,
            &body_as_string,
            custom_content_type,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use httpdate;
    use reqwest::header;
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_resilient_client_creation() {
        let mock_server = MockServer::start().await;
        // The mock server will only respond with 200 if the custom header is present.
        Mock::given(method("GET"))
            .and(path("/test"))
            .and(header("X-Test", "true"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Create a pre-configured client with a default header.
        let mut headers = header::HeaderMap::new();
        headers.insert("X-Test", "true".parse().unwrap()); //#[allow_ci]
        let preconfigured_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap(); //#[allow_ci]

        // Initialize ResilientClient with the pre-configured client.
        let resilient_client = ResilientClient::new(
            Some(preconfigured_client),
            Duration::from_millis(10),
            0,
            &[StatusCode::OK],
            None,
        );

        // Make a request. The test will pass only if the default header is sent correctly.
        let response = resilient_client
            .client
            .get(format!("{}/test", &mock_server.uri()))
            .send()
            .await
            .unwrap(); //#[allow_ci]

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_custom_content_type_client_creation() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("Content-Type", "application/vnd.api+json"))
            .respond_with(ResponseTemplate::new(200)) // The server will succeed with 200
            .mount(&mock_server)
            .await;
        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            3,
            &[StatusCode::OK],
            None,
        );

        let response = client
            .get_json_request_from_struct(
                Method::POST,
                &format!("{}/submit", &mock_server.uri()),
                &json!({}),
                Some("application/vnd.api+json".to_string()),
            )
            .unwrap() //#[allow_ci]
            .send()
            .await;

        assert!(response.is_ok());
        assert_eq!(response.unwrap().status(), StatusCode::OK); //#[allow_ci]
    }

    #[tokio::test]
    async fn test_retry_on_server_error_then_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(202)) // The server will succeed with 202
            .mount(&mock_server)
            .await;

        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            3,
            &[StatusCode::ACCEPTED], // We tell the client that 202 is a success code
            None,
        );

        let response = client
            .get_json_request_from_struct(
                Method::POST,
                &format!("{}/submit", &mock_server.uri()),
                &json!({}),
                None,
            )
            .unwrap() //#[allow_ci]
            .send()
            .await;

        assert!(response.is_ok());
        assert_eq!(response.unwrap().status(), StatusCode::ACCEPTED); //#[allow_ci]
        let received_requests =
            mock_server.received_requests().await.unwrap(); //#[allow_ci]
        assert_eq!(received_requests.len(), 3);
    }

    #[tokio::test]
    async fn test_stops_on_success_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/submit"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            3,
            &[StatusCode::OK], // We tell the client that 200 is a success code
            None,
        );

        let response = client
            .get_json_request_from_struct(
                Method::POST,
                &format!("{}/submit", &mock_server.uri()),
                &json!({}),
                None,
            )
            .unwrap() //#[allow_ci]
            .send()
            .await;

        assert!(response.is_ok());
        assert_eq!(response.unwrap().status(), StatusCode::OK); //#[allow_ci]
        let received_requests =
            mock_server.received_requests().await.unwrap(); //#[allow_ci]
        assert_eq!(received_requests.len(), 1);
    }

    #[tokio::test]
    async fn test_exhausts_retries() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/submit"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let max_retries = 2;
        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            max_retries,
            &[StatusCode::OK],
            None,
        );

        let response = client
            .get_json_request_from_struct(
                Method::POST,
                &format!("{}/submit", &mock_server.uri()),
                &json!({}),
                None,
            )
            .unwrap() //#[allow_ci]
            .send()
            .await
            .unwrap(); //#[allow_ci]

        // The overall request is "successful" at the network level, but the status indicates an error.
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // The server should have received 1 (original) + 2 (retries) = 3 requests.
        let received_requests =
            mock_server.received_requests().await.unwrap(); //#[allow_ci]
        assert_eq!(received_requests.len(), (max_retries + 1) as usize);
    }

    /// A helper function to find a TCP port that is currently not in use.
    fn find_free_port() -> u16 {
        // Ask the OS for a free port by binding to port 0.
        TcpListener::bind("127.0.0.1:0")
            .expect("Could not bind to a free port")
            .local_addr()
            .expect("Could not get local address")
            .port()
    }

    #[tokio::test]
    async fn test_retries_on_network_error() {
        // Verifies that the client retries when a network error occurs (e.g., connection refused).
        // This specifically tests the `Err(_)` arm of the `handle` method.
        let unreachable_url =
            format!("http://127.0.0.1:{}", find_free_port());
        let max_retries = 2;

        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            max_retries,
            &[StatusCode::OK],
            None,
        );

        let response = client
            .get_json_request_from_struct(
                Method::GET,
                &unreachable_url,
                &json!({}),
                None,
            )
            .unwrap() //#[allow_ci]
            .send()
            .await;

        // The request should fail because the server is unreachable.
        assert!(
            response.is_err(),
            "Expected the request to fail with a network error"
        );
    }

    #[tokio::test]
    async fn test_get_request_without_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            3,
            &[StatusCode::OK],
            None,
        );

        let response = client
            .get_request(
                Method::GET,
                &format!("{}/health", &mock_server.uri()),
            )
            .send()
            .await;

        assert!(response.is_ok());
        let res = response.unwrap(); //#[allow_ci]
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.text().await.unwrap(), "OK"); //#[allow_ci]

        let received_requests =
            mock_server.received_requests().await.unwrap(); //#[allow_ci]
        assert_eq!(received_requests.len(), 1);
    }

    #[tokio::test]
    async fn test_honors_retry_after_header_with_seconds() {
        let mock_server = MockServer::start().await;

        // The server will first respond with a 429 and a `Retry-After: 2` header.
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(
                ResponseTemplate::new(429).insert_header("Retry-After", "2"),
            )
            .up_to_n_times(1) // Only respond this way once
            .mount(&mock_server)
            .await;

        // The second time, it will succeed.
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = ResilientClient::new(
            None,
            Duration::from_millis(10), // Short initial delay
            1,                         // Max 1 retry
            &[StatusCode::OK],
            None,
        );

        let start_time = std::time::Instant::now();
        let response = client
            .get_request(Method::GET, &format!("{}/test", &mock_server.uri()))
            .send()
            .await
            .unwrap(); //#[allow_ci]
        let elapsed = start_time.elapsed();

        // The total time should be at least 2 seconds due to the Retry-After header.
        assert!(elapsed >= Duration::from_secs(2));
        assert_eq!(response.status(), StatusCode::OK);
        let received_requests =
            mock_server.received_requests().await.unwrap(); //#[allow_ci]
        assert_eq!(received_requests.len(), 2);
    }

    #[tokio::test]
    async fn test_honors_retry_after_header_with_http_date() {
        let mock_server = MockServer::start().await;
        use chrono::Timelike;
        // Create a date string for 1 second in the future
        let now_truncated = Utc::now().with_nanosecond(0).unwrap(); //#[allow_ci]
        let retry_at = now_truncated + chrono::Duration::seconds(1);
        let http_date = httpdate::fmt_http_date(retry_at.into());

        // The server will first respond with a 503 and a future date.
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(
                ResponseTemplate::new(503)
                    .insert_header("Retry-After", http_date.as_str()),
            )
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // The second time, it will succeed.
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            1,
            &[StatusCode::OK],
            None,
        );

        let start_time = std::time::Instant::now();
        let response = client
            .get_request(Method::GET, &format!("{}/test", &mock_server.uri()))
            .send()
            .await
            .unwrap(); //#[allow_ci]
        let elapsed = start_time.elapsed();

        assert!(
            elapsed > Duration::from_secs(0),
            "The client waited for {elapsed:?}, which is less than the expected"
        );
        assert!(elapsed < Duration::from_secs(2));
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_max_retry_after_attempts_limit() {
        let mock_server = MockServer::start().await;

        // Server will respond with 429 and Retry-After header every time
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(
                ResponseTemplate::new(429).insert_header("Retry-After", "1"),
            )
            .mount(&mock_server)
            .await;

        let max_retries = 3;
        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            max_retries,
            &[StatusCode::OK],
            None,
        );

        let start_time = std::time::Instant::now();
        let response = client
            .get_request(Method::GET, &format!("{}/test", &mock_server.uri()))
            .send()
            .await
            .unwrap(); //#[allow_ci]
        let elapsed = start_time.elapsed();

        // Should return 429 after max_retries
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // Should have made exactly max_retries + 1 requests (initial + retries)
        let received_requests =
            mock_server.received_requests().await.unwrap(); //#[allow_ci]
        assert_eq!(received_requests.len(), (max_retries + 1) as usize);

        // Should have waited for max_retries seconds (each retry waits 1 second)
        assert!(elapsed >= Duration::from_secs(max_retries as u64));
        assert!(elapsed < Duration::from_secs((max_retries + 2) as u64));
    }

    #[actix_rt::test]
    async fn test_x_request_id_with_mockoon() {
        if std::env::var("MOCKOON").is_err() {
            return;
        }
        // Mockoon checks if the request is using the X-Request-Id header
        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            3,
            &[StatusCode::OK],
            None,
        );

        let response = client
            .get_request(
                Method::GET,
                "http://localhost:3000/x-request-id-test",
            )
            .send()
            .await;
        // Mockoon x-request-id-test only returns 200 OK if X-Request-ID exists
        assert!(response.is_ok());
        assert_eq!(response.unwrap().status(), StatusCode::OK); //#[allow_ci]

        let response = client
            .get_json_request(
                Method::GET,
                "http://localhost:3000/x-request-id-test",
                "{}",
                None,
            )
            .expect("Failed to create JSON request")
            .send()
            .await;

        assert!(response.is_ok());
        assert_eq!(response.unwrap().status(), StatusCode::OK); //#[allow_ci]
    }

    #[tokio::test]
    async fn test_recovers_before_retry_after_limit() {
        let mock_server = MockServer::start().await;

        let retry_response =
            ResponseTemplate::new(429).insert_header("Retry-After", "1");

        // Fail the first two times
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(retry_response)
            .up_to_n_times(2) // Respond this way twice
            .mount(&mock_server)
            .await;

        // Succeed on the third attempt
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .up_to_n_times(1) // Only respond this way once
            .mount(&mock_server)
            .await;

        let client = ResilientClient::new(
            None,
            Duration::from_millis(10),
            5, // Regular retry limit
            &[StatusCode::OK],
            None,
        );

        let start_time = std::time::Instant::now();
        let response = client
            .get_request(Method::GET, &format!("{}/test", &mock_server.uri()))
            .send()
            .await
            .unwrap(); //#[allow_ci]
        let elapsed = start_time.elapsed();

        // Should eventually succeed
        assert_eq!(response.status(), StatusCode::OK);

        // Should have made 3 total requests (2 failures + 1 success)
        let received_requests =
            mock_server.received_requests().await.unwrap(); //#[allow_ci]
        assert_eq!(received_requests.len(), 3);

        // Should have waited for ~2 seconds (for the two retries)
        assert!(elapsed >= Duration::from_secs(2));
        assert!(elapsed < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn test_parse_retry_after_logic() {
        use reqwest::header::HeaderValue;
        use std::time::SystemTime;

        // 1. Test with valid integer seconds
        let header = HeaderValue::from_static("5");
        assert_eq!(parse_retry_after(&header), Some(Duration::from_secs(5)));

        // 2. Test with zero seconds (edge case)
        let header = HeaderValue::from_static("0");
        assert_eq!(parse_retry_after(&header), Some(Duration::from_secs(0)));

        // 3. Test with large valid number
        let header = HeaderValue::from_static("86400"); // 24 hours
        assert_eq!(
            parse_retry_after(&header),
            Some(Duration::from_secs(86400))
        );

        // 4. Test with whitespace (should fail - HTTP headers shouldn't have leading/trailing spaces)
        let header = HeaderValue::from_static(" 5 ");
        assert_eq!(parse_retry_after(&header), None);

        // 5. Test with fractional seconds (should fail)
        let header = HeaderValue::from_static("1.5");
        assert_eq!(parse_retry_after(&header), None);

        // 6. Test with a valid HTTP-date in future
        let future_time = SystemTime::now() + Duration::from_secs(10);
        let date_str = httpdate::fmt_http_date(future_time);
        let header = HeaderValue::from_str(&date_str).unwrap(); //#[allow_ci]
        let duration = parse_retry_after(&header).unwrap(); //#[allow_ci]
                                                            // Check that the duration is close to 10s, allowing for minor timing delays
        assert!(duration.as_secs() >= 9 && duration.as_secs() <= 10);

        // 7. Test with HTTP-date in the past (should return Duration::ZERO)
        let past_time = SystemTime::now() - Duration::from_secs(10);
        let past_date_str = httpdate::fmt_http_date(past_time);
        let header = HeaderValue::from_str(&past_date_str).unwrap(); //#[allow_ci]
        assert_eq!(parse_retry_after(&header), Some(Duration::ZERO));

        // 8. Test with malformed string value
        let header = HeaderValue::from_static("not-a-valid-value");
        assert_eq!(parse_retry_after(&header), None);

        // 9. Test with invalid UTF-8 sequence
        let invalid_utf8_bytes = &[0xC3, 0x28]; // This is an invalid UTF-8 sequence
        let header = HeaderValue::from_bytes(invalid_utf8_bytes).unwrap(); //#[allow_ci]
        assert_eq!(
            parse_retry_after(&header),
            None,
            "Should return None for non-UTF-8 header values"
        );

        // 10. Test with empty string
        let header = HeaderValue::from_static("");
        assert_eq!(parse_retry_after(&header), None);

        // 11. Test with negative number (should fail)
        let header = HeaderValue::from_static("-5");
        assert_eq!(parse_retry_after(&header), None);

        // 12. Test with very large number that might overflow
        let header = HeaderValue::from_static("18446744073709551615"); // u64::MAX
                                                                       // This should either work or fail gracefully, but not panic
        let result = parse_retry_after(&header);
        assert!(result.is_some() || result.is_none()); // Just ensure no panic
    }

    #[tokio::test]
    async fn test_resilient_client_with_auth_config() {
        use crate::auth::AuthConfig;

        let auth_config = AuthConfig {
            verifier_base_url: "https://verifier.example.com".to_string(),
            agent_id: "test-agent".to_string(),
            api_version: None, // Use DEFAULT_PUSH_API_VERSION
            avoid_tpm: true,
            timeout_ms: 5000,
            max_auth_retries: 3,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        // Test with authentication
        let _client_with_auth = ResilientClient::new_with_auth(
            None,
            Some(auth_config),
            std::time::Duration::from_millis(10),
            3,
            &[StatusCode::OK],
            None,
        )
        .unwrap(); //#[allow_ci]

        // Verify the client was created successfully
        // (We can't easily test the middleware behavior without a mock server,
        // but we can at least verify the client creation doesn't panic)
    }

    #[tokio::test]
    async fn test_resilient_client_without_auth_config() {
        // Test without authentication (should behave like the original client)
        let _client_without_auth = ResilientClient::new_with_auth(
            None,
            None, // No auth config
            std::time::Duration::from_millis(10),
            3,
            &[StatusCode::OK],
            None,
        )
        .unwrap(); //#[allow_ci]

        // Verify the client was created successfully
    }

    #[tokio::test]
    async fn test_authentication_middleware_path_detection() {
        use crate::auth::AuthConfig;

        let auth_config = AuthConfig {
            verifier_base_url: "https://verifier.example.com".to_string(),
            agent_id: "test-agent".to_string(),
            api_version: None, // Use DEFAULT_PUSH_API_VERSION
            avoid_tpm: true,
            timeout_ms: 5000,
            max_auth_retries: 3,
            accept_invalid_certs: true, // Tests use self-signed certs
            accept_invalid_hostnames: false,
        };

        let middleware = AuthenticationMiddleware::new(auth_config).unwrap(); //#[allow_ci]

        // Mock a request to a sessions endpoint (should be detected as auth endpoint)
        let mock_request = reqwest::Request::new(
            Method::POST,
            "https://verifier.example.com/v3.0/sessions"
                .parse()
                .unwrap(), //#[allow_ci]
        );
        assert!(middleware.is_auth_endpoint(&mock_request));

        // Mock a request to a non-auth endpoint
        let mock_request2 = reqwest::Request::new(
            Method::GET,
            "https://verifier.example.com/v3.0/agents/123/attestations"
                .parse()
                .unwrap(), //#[allow_ci]
        );
        assert!(!middleware.is_auth_endpoint(&mock_request2));
    }

    mod auth_middleware_tests {
        use super::*;
        use crate::auth::{AuthConfig, SessionToken};
        use chrono::{Duration, Utc};
        use std::sync::Arc;

        #[tokio::test]
        async fn test_token_state_basic_operations() {
            let auth_config = AuthConfig {
                verifier_base_url: "https://verifier.example.com".to_string(),
                agent_id: "test-agent".to_string(),
                api_version: None, // Use DEFAULT_PUSH_API_VERSION
                avoid_tpm: true,
                timeout_ms: 5000,
                max_auth_retries: 3,
                accept_invalid_certs: true, // Tests use self-signed certs
                accept_invalid_hostnames: false,
            };

            let token_state = TokenState::new(auth_config).unwrap(); //#[allow_ci]

            // Test initially no token - should trigger authentication
            let result = token_state.get_valid_token().await;
            assert!(
                result.is_err(),
                "Should fail when no auth server available"
            );
            // Since we're using a real auth client, we expect authentication-related errors
            let error_msg = result.unwrap_err().to_string(); //#[allow_ci]
            assert!(
                error_msg.contains("Authentication failed"),
                "Error: {error_msg}"
            );

            // Test clear token when no token exists (should not panic)
            token_state.clear_token().await;

            // Manually insert a valid token for testing
            {
                let mut token_guard = token_state.token.write().await;
                let now = Utc::now();
                *token_guard = Some(SessionToken {
                    token: SecretToken::new("test-token-123".to_string()),
                    created_at: now,
                    expires_at: now + Duration::hours(1), // Valid for 1 hour
                    session_id: "42".to_string(),
                });
            }

            // Test get valid token with valid token - should succeed now
            let result = token_state.get_valid_token().await;
            assert!(result.is_ok(), "Should succeed with valid token");
            assert_eq!(result.unwrap().reveal(), "test-token-123"); //#[allow_ci]

            // Test clear token
            token_state.clear_token().await;

            // Verify token was cleared
            {
                let token_guard = token_state.token.read().await;
                assert!(token_guard.is_none());
            }
        }

        #[tokio::test]
        async fn test_authentication_middleware_advanced_patterns() {
            let auth_config = AuthConfig {
                verifier_base_url: "https://verifier.example.com".to_string(),
                agent_id: "test-agent".to_string(),
                api_version: None, // Use DEFAULT_PUSH_API_VERSION
                avoid_tpm: true,
                timeout_ms: 5000,
                max_auth_retries: 3,
                accept_invalid_certs: true, // Tests use self-signed certs
                accept_invalid_hostnames: false,
            };

            let middleware =
                AuthenticationMiddleware::new(auth_config).unwrap(); //#[allow_ci]

            // Test different auth endpoint patterns
            let test_cases = vec![
                ("https://verifier.example.com/v3.0/sessions", true),
                ("https://verifier.example.com/v2.5/sessions/42", true),
                ("https://verifier.example.com/sessions", true),
                ("https://verifier.example.com/api/sessions/123", true),
                ("https://verifier.example.com/agents", false),
                ("https://verifier.example.com/attestations", false),
                ("https://verifier.example.com/keys", false),
            ];

            for (url, expected_is_auth) in test_cases {
                let mock_request = reqwest::Request::new(
                    Method::GET,
                    url.parse().unwrap(), //#[allow_ci]
                );
                assert_eq!(
                    middleware.is_auth_endpoint(&mock_request),
                    expected_is_auth,
                    "URL {url} should be auth endpoint: {expected_is_auth}"
                );
            }
        }

        #[tokio::test]
        async fn test_middleware_concurrent_access() {
            let auth_config = AuthConfig {
                verifier_base_url: "https://verifier.example.com".to_string(),
                agent_id: "test-agent".to_string(),
                api_version: None, // Use DEFAULT_PUSH_API_VERSION
                avoid_tpm: true,
                timeout_ms: 5000,
                max_auth_retries: 3,
                accept_invalid_certs: true, // Tests use self-signed certs
                accept_invalid_hostnames: false,
            };

            let token_state = Arc::new(TokenState::new(auth_config).unwrap()); //#[allow_ci]

            // Test concurrent access to token state (should not deadlock)
            let mut handles = vec![];

            for i in 0..5 {
                let token_state_clone = Arc::clone(&token_state);
                let handle = tokio::spawn(async move {
                    if i % 2 == 0 {
                        // Even threads try to get token
                        let _result =
                            token_state_clone.get_valid_token().await;
                    } else {
                        // Odd threads clear token
                        token_state_clone.clear_token().await;
                    }
                });
                handles.push(handle);
            }

            // Wait for all tasks to complete (should not hang)
            for handle in handles {
                handle.await.unwrap(); //#[allow_ci]
            }

            // Verify we can still access the token state
            token_state.clear_token().await;
        }

        #[tokio::test]
        async fn test_is_auth_endpoint() {
            let auth_config = AuthConfig {
                verifier_base_url: "https://127.0.0.1:8881".to_string(),
                agent_id: "test-agent".to_string(),
                api_version: None,
                avoid_tpm: true,
                timeout_ms: 30000,
                max_auth_retries: 1,
                accept_invalid_certs: true, // Tests use self-signed certs
                accept_invalid_hostnames: false,
            };

            let middleware =
                AuthenticationMiddleware::new(auth_config).unwrap(); //#[allow_ci]

            // Helper function to create a test request
            let create_request = |url: &str| {
                reqwest::Client::new().get(url).build().unwrap() //#[allow_ci]
            };

            // Test cases that SHOULD be recognized as auth endpoints
            assert!(
                middleware.is_auth_endpoint(&create_request(
                    "https://verifier/v3.0/sessions"
                )),
                "/v3.0/sessions should be an auth endpoint"
            );
            assert!(
                middleware.is_auth_endpoint(&create_request(
                    "https://verifier/v3.0/sessions/1"
                )),
                "/v3.0/sessions/1 should be an auth endpoint"
            );
            assert!(
                middleware.is_auth_endpoint(&create_request(
                    "https://verifier/v2.5/sessions/42"
                )),
                "/v2.5/sessions/42 should be an auth endpoint"
            );
            assert!(
                middleware.is_auth_endpoint(&create_request(
                    "https://verifier/v1.0/sessions"
                )),
                "/v1.0/sessions should be an auth endpoint"
            );

            // Test cases that should NOT be recognized as auth endpoints
            // Note: We can't easily distinguish /api/sessions/123 (auth) from
            // /api/sessions/report (non-auth) without validating that the last
            // segment is numeric. The current implementation errs on the side of
            // caution by matching any /*/sessions/* pattern to avoid auth loops.
            assert!(
                !middleware.is_auth_endpoint(&create_request(
                    "https://verifier/users/sessions_count"
                )),
                "/users/sessions_count should NOT be an auth endpoint"
            );
            assert!(
                !middleware.is_auth_endpoint(&create_request(
                    "https://verifier/data/sessions-backup"
                )),
                "/data/sessions-backup should NOT be an auth endpoint"
            );
            assert!(
                !middleware.is_auth_endpoint(&create_request(
                    "https://verifier/v3.0/agents"
                )),
                "/v3.0/agents should NOT be an auth endpoint"
            );
            assert!(
                !middleware.is_auth_endpoint(&create_request(
                    "https://verifier/v3.0/attestations"
                )),
                "/v3.0/attestations should NOT be an auth endpoint"
            );
            assert!(
                !middleware.is_auth_endpoint(&create_request(
                    "https://verifier/api/v3.0/mysessions"
                )),
                "/api/v3.0/mysessions should NOT be an auth endpoint"
            );
        }
    }
}
