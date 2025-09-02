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
use std::time::Duration;

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
            debug!("  {key}: {value:?}");
        }
        next.run(req, extensions).await
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
                    debug!("{:?} header found; deferring to RetryAfterMiddleware.", RESPONSE_RETRY_AFTER_HEADER);
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
                warn!("Network error: {e}");
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
            .unwrap();
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
        let now_truncated = Utc::now().with_nanosecond(0).unwrap();
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
            .unwrap();
        let elapsed = start_time.elapsed();

        assert!(
            elapsed > Duration::from_secs(0),
            "The client waited for {:?}, which is less than the expected",
            elapsed
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
            .unwrap();
        let elapsed = start_time.elapsed();

        // Should return 429 after max_retries
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // Should have made exactly max_retries + 1 requests (initial + retries)
        let received_requests =
            mock_server.received_requests().await.unwrap();
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
            .unwrap();
        let elapsed = start_time.elapsed();

        // Should eventually succeed
        assert_eq!(response.status(), StatusCode::OK);

        // Should have made 3 total requests (2 failures + 1 success)
        let received_requests =
            mock_server.received_requests().await.unwrap();
        assert_eq!(received_requests.len(), 3);

        // Should have waited for ~2 seconds (for the two retries)
        assert!(elapsed >= Duration::from_secs(2));
        assert!(elapsed < Duration::from_secs(3));
    }
}
