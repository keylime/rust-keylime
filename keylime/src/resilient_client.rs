use reqwest::{Client, Method, Response, StatusCode};
use reqwest_middleware::{
    ClientBuilder, ClientWithMiddleware, Error, RequestBuilder,
};
use reqwest_retry::{
    policies::ExponentialBackoff, RetryTransientMiddleware, Retryable,
    RetryableStrategy,
};
use serde::Serialize;
use std::time::Duration;

const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(60);

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
                // If the status code is one of our defined success codes, it's NOT retryable.
                if self.success_codes.contains(&response.status()) {
                    None
                } else {
                    // For any other status, let the default strategy decide if it's a transient error.
                    Some(Retryable::Transient)
                }
            }
            // If there was a network error, it's always a transient error.
            Err(_) => Some(Retryable::Transient),
        }
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
            .build_with_max_retries(max_retries);

        let client_with_middleware = ClientBuilder::new(base_client)
            .with(RetryTransientMiddleware::new_with_policy_and_strategy(
                retry_policy,
                StopOnSuccessStrategy {
                    success_codes: success_codes.to_vec(),
                },
            ))
            .build();

        Self {
            client: client_with_middleware,
        }
    }

    /// Prepares a request with a JSON body, returning a Result.
    pub fn send_json<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        json_serializable: &T,
    ) -> Result<RequestBuilder, serde_json::Error> {
        // Use the `?` operator to propagate a serialization error instead of panicking.
        let body_as_string = serde_json::to_string(json_serializable)?;

        let builder = self
            .client
            .request(method, url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body_as_string);

        // Wrap the successful result in Ok().
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .send_json(
                Method::POST,
                &format!("{}/submit", &mock_server.uri()),
                &json!({}),
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
            .send_json(
                Method::POST,
                &format!("{}/submit", &mock_server.uri()),
                &json!({}),
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
            .send_json(
                Method::POST,
                &format!("{}/submit", &mock_server.uri()),
                &json!({}),
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
            .send_json(Method::GET, &unreachable_url, &json!({}))
            .unwrap() //#[allow_ci]
            .send()
            .await;

        // The request should fail because the server is unreachable.
        assert!(
            response.is_err(),
            "Expected the request to fail with a network error"
        );
    }
}
