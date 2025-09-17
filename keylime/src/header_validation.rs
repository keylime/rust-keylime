// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Header validation for Push Model agent using RFC compliance
//!
//! This module provides header validation functionality according to:
//! - RFC 9110 Section 10.2.2: 201 Created response handling

use crate::rfc3986_compliance::{RfcComplianceError, UriReference};
use log::debug;
use reqwest::header::{HeaderMap, LOCATION};

/// Validates response headers according to RFC 9110 and RFC 3986
pub struct HeaderValidator;

impl HeaderValidator {
    /// Validate Location header in 201 Created responses according to RFC 9110 Section 10.2.2
    pub fn validate_location_header(
        headers: &HeaderMap,
        expected_base_url: Option<&str>,
    ) -> Result<String, RfcComplianceError> {
        let location = headers
            .get(LOCATION)
            .ok_or(RfcComplianceError::MissingLocationHeader)?;

        let location_str = location.to_str().map_err(|_| {
            RfcComplianceError::InvalidLocationHeader(
                "Invalid UTF-8 encoding".to_string(),
            )
        })?;

        // Validate the location header according to RFC 3986
        let uri_ref = UriReference::parse(location_str)?;

        debug!("Validated Location header: {}", location_str);

        // If we have a base URL, resolve relative references
        if let Some(base_url) = expected_base_url {
            if uri_ref.is_relative() {
                let base = UriReference::parse(base_url)?;
                let resolved = uri_ref.resolve_against(&base)?;
                return Ok(resolved.to_string());
            }
        }

        Ok(location_str.to_string())
    }

    /// Validate 201 Created response headers for RFC 9110 Section 10.2.2 compliance
    pub fn validate_201_created_response(
        headers: &HeaderMap,
        expected_base_url: Option<&str>,
    ) -> Result<(), RfcComplianceError> {
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
            result.unwrap(),
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
            result.unwrap(),
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
            result.unwrap_err(),
            RfcComplianceError::MissingLocationHeader
        ));
    }

    #[test]
    fn test_validate_location_header_invalid_uri() {
        let headers = create_test_headers_with_location("invalid\x00uri");
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
                result.unwrap_err(),
                RfcComplianceError::InvalidLocationHeader(_)
            ));
        }
    }

    #[test]
    fn test_validate_location_header_relative_without_base() {
        let headers = create_test_headers_with_location("/relative/path");
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/relative/path");
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
            result.unwrap(),
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
        assert_eq!(result.unwrap(), "https://other.com/resource");
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
            result.unwrap(),
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
            result.unwrap(),
            "https://api.example.com/resource?id=123&type=test#section"
        );
    }

    #[test]
    fn test_validate_location_header_empty_string() {
        let headers = create_test_headers_with_location("");
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
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
            result.unwrap(),
            "https://example.com:8443/api/v1/resource"
        );
    }

    #[test]
    fn test_validate_location_header_invalid_base_url() {
        let headers = create_test_headers_with_location("/relative/path");
        let invalid_base = "not\x00a\x01valid\x02url";
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
        let headers = create_test_headers_with_location("invalid\x00uri");
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
        // The RFC implementation should handle path normalization
        let resolved = result.unwrap();
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
            result.unwrap(),
            "https://example.com/resource%20with%20spaces"
        );
    }

    #[test]
    fn test_validate_location_header_international_domain() {
        let headers = create_test_headers_with_location(
            "https://xn--e1afmkfd.xn--p1ai/resource",
        );
        let result =
            HeaderValidator::validate_location_header(&headers, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://xn--e1afmkfd.xn--p1ai/resource");
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
        assert_eq!(result.unwrap(), "https://api.example.com/");
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
        // The RFC implementation should normalize dot segments
        let resolved = result.unwrap();
        assert!(resolved.contains("resource"));
    }
}
