// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Header validation for Push Model agent using RFC compliance
//!
//! This module provides header validation functionality according to:
//! - RFC 9110 Section 10.2.2: 201 Created response handling

use keylime::rfc3986_compliance::{RfcComplianceError, UriReference};
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
}
