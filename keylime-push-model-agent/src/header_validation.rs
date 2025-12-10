// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Header validation for Push Model agent using RFC compliance
//!
//! This module provides header validation functionality according to:
//! - RFC 9110 Section 10.2.2: 201 Created response handling

use crate::url_selector::resolve_url;
use log::debug;
use reqwest::header::{HeaderMap, LOCATION};

/// Simple RFC compliance error for header validation
#[derive(Debug)]
pub enum HeaderValidationError {
    MissingLocationHeader,
    InvalidLocationHeader(String),
    InvalidBaseUrl(String),
}

impl std::fmt::Display for HeaderValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderValidationError::MissingLocationHeader => {
                write!(f, "Missing Location header in 201 Created response")
            }
            HeaderValidationError::InvalidLocationHeader(msg) => {
                write!(f, "Invalid Location header value: {msg}")
            }
            HeaderValidationError::InvalidBaseUrl(msg) => {
                write!(f, "Invalid base URL: {msg}")
            }
        }
    }
}

impl std::error::Error for HeaderValidationError {}

/// Validates response headers according to RFC 9110 and RFC 3986
pub struct HeaderValidator;

impl HeaderValidator {
    /// Validate Location header in 201 Created responses according to RFC 9110 Section 10.2.2
    pub fn validate_location_header(
        headers: &HeaderMap,
        expected_base_url: Option<&str>,
    ) -> Result<String, HeaderValidationError> {
        let location = headers
            .get(LOCATION)
            .ok_or(HeaderValidationError::MissingLocationHeader)?;

        let location_str = location.to_str().map_err(|_| {
            HeaderValidationError::InvalidLocationHeader(
                "Invalid UTF-8 encoding".to_string(),
            )
        })?;

        debug!("Validating Location header: {location_str}");

        // Use the existing resolve_url function for all URL validation and resolution
        if let Some(base_url) = expected_base_url {
            // Resolve against the provided base URL
            resolve_url(base_url, location_str).map_err(|e| {
                if e.to_string().contains("Invalid base URL") {
                    HeaderValidationError::InvalidBaseUrl(e.to_string())
                } else {
                    HeaderValidationError::InvalidLocationHeader(
                        e.to_string(),
                    )
                }
            })
        } else {
            // No base URL provided, validate using a dummy base to check if it's a valid URI reference
            let dummy_base = "http://example.com";
            match resolve_url(dummy_base, location_str) {
                Ok(_) => Ok(location_str.to_string()), // Return original if valid
                Err(_) => Err(HeaderValidationError::InvalidLocationHeader(
                    "Invalid URI reference".to_string(),
                )),
            }
        }
    }

    /// Validate 201 Created response headers for RFC 9110 Section 10.2.2 compliance
    pub fn validate_201_created_response(
        headers: &HeaderMap,
        expected_base_url: Option<&str>,
    ) -> Result<(), HeaderValidationError> {
        // RFC 9110 Section 10.2.2: 201 Created responses MUST include a Location header
        Self::validate_location_header(headers, expected_base_url)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn create_test_headers_with_location(location: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(header_value) = HeaderValue::from_str(location) {
            headers.insert(LOCATION, header_value);
        }
        headers
    }

    #[test]
    fn test_validate_location_header_absolute_url() {
        let headers = create_test_headers_with_location(
            "https://example.com/v3.0/agents/123/attestations/1",
        );
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(), //#[allow_ci]
            "https://example.com/v3.0/agents/123/attestations/1"
        );
    }

    #[test]
    fn test_validate_location_header_relative_url() {
        let headers = create_test_headers_with_location(
            "/v3.0/agents/123/attestations/1",
        );
        let base_url = "https://example.com";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(), //#[allow_ci]
            "https://example.com/v3.0/agents/123/attestations/1"
        );
    }

    #[test]
    fn test_validate_location_header_missing() {
        let headers = HeaderMap::new();
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(), //#[allow_ci]
            HeaderValidationError::MissingLocationHeader
        ));
    }

    #[test]
    fn test_validate_location_header_invalid_uri() {
        let headers = create_test_headers_with_location("http://");
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_201_created_response() {
        let mut headers = HeaderMap::new();
        if let Ok(location_value) =
            HeaderValue::from_str("https://example.com/resource/123")
        {
            headers.insert(LOCATION, location_value);
        }

        let result =
            HeaderValidator::validate_201_created_response(&headers, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_201_created_response_missing_location() {
        let headers = HeaderMap::new();
        let result =
            HeaderValidator::validate_201_created_response(&headers, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_location_header_non_utf8() {
        let mut headers = HeaderMap::new();
        // Use unsafe bytes to create a non-UTF8 header value
        let invalid_utf8_bytes = vec![0x80, 0x81, 0x82];
        if let Ok(header_value) = HeaderValue::from_bytes(&invalid_utf8_bytes)
        {
            headers.insert(LOCATION, header_value);
            let result =
                HeaderValidator::validate_location_header(&headers, None);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(), //#[allow_ci]
                HeaderValidationError::InvalidLocationHeader(_)
            ));
        }
    }

    #[test]
    fn test_validate_location_header_relative_without_base() {
        let headers = create_test_headers_with_location("/relative/path");
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/relative/path"); //#[allow_ci]
    }

    #[test]
    fn test_validate_location_header_relative_with_base() {
        let headers = create_test_headers_with_location("relative/path");
        let base_url = "https://api.example.com/v1/";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(), //#[allow_ci]
            "https://api.example.com/v1/relative/path"
        );
    }

    #[test]
    fn test_validate_location_header_absolute_with_base() {
        let headers =
            create_test_headers_with_location("https://other.com/resource");
        let base_url = "https://api.example.com/v1/";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://other.com/resource"); //#[allow_ci]
    }

    #[test]
    fn test_validate_location_header_query_and_fragment() {
        let headers = create_test_headers_with_location(
            "https://example.com/resource?id=123#section",
        );
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(), //#[allow_ci]
            "https://example.com/resource?id=123#section"
        );
    }

    #[test]
    fn test_validate_location_header_relative_query_fragment() {
        let headers = create_test_headers_with_location(
            "/resource?id=123&type=test#section",
        );
        let base_url = "https://api.example.com";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(), //#[allow_ci]
            "https://api.example.com/resource?id=123&type=test#section"
        );
    }

    #[test]
    fn test_validate_location_header_empty_string() {
        let headers = create_test_headers_with_location("");
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ""); //#[allow_ci]
    }

    #[test]
    fn test_validate_location_header_port_in_url() {
        let headers = create_test_headers_with_location(
            "https://example.com:8443/api/v1/resource",
        );
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(), //#[allow_ci]
            "https://example.com:8443/api/v1/resource"
        );
    }

    #[test]
    fn test_validate_location_header_invalid_base_url() {
        let headers = create_test_headers_with_location("/relative/path");
        let invalid_base = "not a valid url";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(invalid_base),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_201_created_response_with_base_url() {
        let headers = create_test_headers_with_location("/api/v1/agents/123");
        let base_url = "https://keylime.example.com";
        let result = HeaderValidator::validate_201_created_response(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_201_created_response_invalid_location_header() {
        let headers = create_test_headers_with_location("http://");
        let result =
            HeaderValidator::validate_201_created_response(&headers, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_location_header_path_traversal() {
        let headers =
            create_test_headers_with_location("../../../etc/passwd");
        let base_url = "https://api.example.com/v1/agents/";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
        // The url crate should handle path normalization
        let resolved = result.unwrap(); //#[allow_ci]
        assert!(resolved.starts_with("https://api.example.com/"));
    }

    #[test]
    fn test_validate_location_header_special_characters() {
        let headers = create_test_headers_with_location(
            "https://example.com/resource%20with%20spaces",
        );
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(), //#[allow_ci]
            "https://example.com/resource%20with%20spaces"
        );
    }

    #[test]
    fn test_validate_location_header_international_domain() {
        let headers = create_test_headers_with_location(
            "https://xn--e1afmkfd.xn--p1ai/resource",
        );
        let r = HeaderValidator::validate_location_header(&headers, None);
        assert!(r.is_ok());
        assert_eq!(r.unwrap(), "https://xn--e1afmkfd.xn--p1ai/resource"); //#[allow_ci]
    }

    #[test]
    fn test_validate_location_header_root_path() {
        let headers = create_test_headers_with_location("/");
        let base_url = "https://api.example.com";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://api.example.com/"); //#[allow_ci]
    }

    #[test]
    fn test_validate_location_header_dot_segments() {
        let headers =
            create_test_headers_with_location("./current/../resource");
        let base_url = "https://api.example.com/v1/";
        let result = HeaderValidator::validate_location_header(
            &headers,
            Some(base_url),
        );
        assert!(result.is_ok());
        // The url crate should normalize dot segments
        let resolved = result.unwrap(); //#[allow_ci]
        assert!(resolved.contains("resource"));
    }
}
