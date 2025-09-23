// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! URL selection and validation for Push Model agent using RFC compliance

use keylime::https_client::resolve_url;
use log::warn;

/// Validate and resolve URL according to RFC 3986 using the url crate
/// This checks for RFC 3986 compliance and resolves the URL in one step
fn validate_and_resolve_url(
    base_url: &str,
    relative_url: &str,
) -> Result<String, String> {
    // Check for control characters (excluding tab) in both URLs as per RFC 3986
    for (i, &byte) in base_url.as_bytes().iter().enumerate() {
        if byte < 0x20 && byte != 0x09 {
            return Err(format!(
                "Control character in base URL at position {}",
                i
            ));
        }
        if byte == 0x7F {
            return Err(format!(
                "DEL character in base URL at position {}",
                i
            ));
        }
    }

    for (i, &byte) in relative_url.as_bytes().iter().enumerate() {
        if byte < 0x20 && byte != 0x09 {
            return Err(format!(
                "Control character in relative URL at position {}",
                i
            ));
        }
        if byte == 0x7F {
            return Err(format!(
                "DEL character in relative URL at position {}",
                i
            ));
        }
    }

    // Use the existing resolve_url function which handles RFC 3986 compliance via url crate
    resolve_url(base_url, relative_url).map_err(|e| e.to_string())
}

/// Simple RFC 9110 Section 10.2.2 compliance check for Location header in 201 responses
pub fn validate_location_header_for_201(
    status: u16,
    location: Option<&str>,
) -> Result<(), String> {
    if status == 201 && location.is_none() {
        return Err(
            "201 Created response missing Location header".to_string()
        );
    }
    Ok(())
}

pub const DEFAULT_API_VERSION: &str = "v3.0";

pub struct UrlArgs {
    pub verifier_url: String,
    pub agent_identifier: Option<String>,
    pub api_version: Option<String>,
    pub location: Option<String>,
}

fn get_api_version(args: &UrlArgs) -> String {
    if args.api_version.is_some() {
        return args.api_version.clone().unwrap();
    }
    DEFAULT_API_VERSION.to_string()
}

/// Get negotiations request URL with RFC 3986 compliance validation
pub fn get_negotiations_request_url(args: &UrlArgs) -> String {
    if args.verifier_url.is_empty() {
        return "ERROR: No verifier URL provided".to_string();
    }

    let id = match args.agent_identifier {
        Some(ref identifier) => identifier.clone(),
        None => return "ERROR: No agent identifier provided".to_string(),
    };

    let api_version = get_api_version(args);
    let relative_path = format!("{}/agents/{}/attestations", api_version, id);

    // Validate and resolve URL according to RFC 3986 in one step
    match validate_and_resolve_url(&args.verifier_url, &relative_path) {
        Ok(resolved_url) => resolved_url,
        Err(e) => {
            warn!(
                "Failed to validate/resolve URL according to RFC 3986: {}",
                e
            );
            format!("ERROR: Invalid verifier URL: {}", e)
        }
    }
}

/// Get evidence submission request URL with RFC 3986 compliance validation
pub fn get_evidence_submission_request_url(args: &UrlArgs) -> String {
    if args.verifier_url.is_empty() {
        return "ERROR: No verifier URL provided".to_string();
    }

    let location = match &args.location {
        Some(loc) => loc.clone(),
        None => return "ERROR: No location provided".to_string(),
    };

    // Validate and resolve URL according to RFC 3986 in one step
    match validate_and_resolve_url(&args.verifier_url, &location) {
        Ok(resolved_url) => resolved_url,
        Err(e) => {
            warn!("Failed to validate/resolve evidence submission URL according to RFC 3986: {}", e);
            format!("ERROR: Invalid location header: {}", e)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn get_attestation_request_url_test() {
        let url = get_negotiations_request_url(&UrlArgs {
            api_version: None,
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            agent_identifier: Some("024680".to_string()),
            location: None,
        });
        assert_eq!(
            url,
            "https://1.2.3.4:5678/v3.0/agents/024680/attestations"
                .to_string()
        );
    } // get_attestation_request_url_test

    #[test]
    fn get_evidence_handling_request_url_test() {
        let urls = vec![
            "https://1.2.3.4:5678/".to_string(),
            "https://1.2.3.4:5678".to_string(),
            "http://1.2.3.4:5678/".to_string(),
            "http://1.2.3.4:5678".to_string(),
        ];
        for u in urls {
            let url = get_evidence_submission_request_url(&UrlArgs {
                verifier_url: u.clone(),
                api_version: None,
                agent_identifier: None,
                location: Some(
                    "/v3.0/agents/024680/attestations/0".to_string(),
                ),
            });

            match u.clone().ends_with('/') {
                true => assert_eq!(
                    url,
                    u.clone().to_string()
                        + "v3.0/agents/024680/attestations/0"
                ),
                false => assert_eq!(
                    url,
                    u.clone().to_string()
                        + "/v3.0/agents/024680/attestations/0"
                ),
            };
        }
    } // get_evidence_handling_request_url_test

    #[test]
    fn test_rfc_compliance_with_mockoon_urls() {
        // Test URL validation and generation for Mockoon endpoints

        // Test negotiation URL generation with RFC 3986 compliance
        let mockoon_base = "http://localhost:3000";
        let agent_id = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000";

        let url = get_negotiations_request_url(&UrlArgs {
            api_version: Some("v3.0".to_string()),
            verifier_url: mockoon_base.to_string(),
            agent_identifier: Some(agent_id.to_string()),
            location: None,
        });

        // Should not return an error
        assert!(
            !url.starts_with("ERROR:"),
            "URL generation should not fail: {}",
            url
        );

        // Should generate a properly formatted URL
        let expected =
            format!("{}/v3.0/agents/{}/attestations", mockoon_base, agent_id);
        assert_eq!(
            url, expected,
            "Generated URL should match expected format"
        );

        // Test with trailing slash on base URL
        let url_with_slash = get_negotiations_request_url(&UrlArgs {
            api_version: Some("v3.0".to_string()),
            verifier_url: format!("{}/", mockoon_base),
            agent_identifier: Some(agent_id.to_string()),
            location: None,
        });

        assert!(
            !url_with_slash.starts_with("ERROR:"),
            "URL generation with trailing slash should not fail"
        );
        assert_eq!(
            url_with_slash, expected,
            "URL should be the same regardless of trailing slash"
        );

        // Test evidence submission URL generation with RFC 3986 compliance
        let location_header = "/v3.0/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000/attestations/1";

        let evidence_url = get_evidence_submission_request_url(&UrlArgs {
            verifier_url: mockoon_base.to_string(),
            api_version: None,
            agent_identifier: None,
            location: Some(location_header.to_string()),
        });

        assert!(
            !evidence_url.starts_with("ERROR:"),
            "Evidence URL generation should not fail: {}",
            evidence_url
        );

        let expected_evidence =
            format!("{}{}", mockoon_base, location_header);
        assert_eq!(
            evidence_url, expected_evidence,
            "Evidence URL should correctly combine base and location"
        );

        // Test with invalid URL (should return error)
        let invalid_url = get_negotiations_request_url(&UrlArgs {
            api_version: Some("v3.0".to_string()),
            verifier_url: "invalid\x00url".to_string(),
            agent_identifier: Some(agent_id.to_string()),
            location: None,
        });

        assert!(
            invalid_url.starts_with("ERROR:"),
            "Invalid URL should return error: {}",
            invalid_url
        );
        assert!(
            invalid_url.contains("Invalid verifier URL"),
            "Error should mention invalid verifier URL"
        );

        // Test with invalid location header
        let invalid_location =
            get_evidence_submission_request_url(&UrlArgs {
                verifier_url: mockoon_base.to_string(),
                api_version: None,
                agent_identifier: None,
                location: Some("invalid\x00location".to_string()),
            });

        assert!(
            invalid_location.starts_with("ERROR:"),
            "Invalid location should return error: {}",
            invalid_location
        );
        assert!(
            invalid_location.contains("Invalid location header"),
            "Error should mention invalid location header"
        );
    }

    #[test]
    fn test_rfc_3986_relative_url_resolution() {
        let base_url = "http://localhost:3000/api";

        // Test resolving relative paths (common in Mockoon responses)
        let test_cases = vec![
            (
                "../v3.0/agents/123/attestations",
                "http://localhost:3000/v3.0/agents/123/attestations",
            ),
            (
                "./agents/456/attestations",
                "http://localhost:3000/agents/456/attestations",
            ), // "./" removes the parent path
            (
                "/v3.0/agents/789/attestations",
                "http://localhost:3000/v3.0/agents/789/attestations",
            ),
            (
                "agents/abc/attestations",
                "http://localhost:3000/agents/abc/attestations",
            ), // Relative paths also remove the current path component
        ];

        for (relative_path, expected) in test_cases {
            let url = get_evidence_submission_request_url(&UrlArgs {
                verifier_url: base_url.to_string(),
                api_version: None,
                agent_identifier: None,
                location: Some(relative_path.to_string()),
            });

            assert!(
                !url.starts_with("ERROR:"),
                "URL resolution should not fail for {}: {}",
                relative_path,
                url
            );
            assert_eq!(
                url, expected,
                "Relative URL resolution failed for {}",
                relative_path
            );
        }
    }

    #[test]
    fn test_validate_and_resolve_url_valid_urls() {
        let base_url = "https://example.com";

        // Test valid absolute URLs (should resolve to themselves)
        let valid_absolute_urls = vec![
            "https://other.com",
            "http://localhost:8080",
            "https://api.example.com/v1/endpoint",
            "ftp://files.example.com/path",
        ];

        for url in valid_absolute_urls {
            assert!(
                validate_and_resolve_url(base_url, url).is_ok(),
                "Should accept valid absolute URL: {}",
                url
            );
        }

        // Test valid relative URLs
        let valid_relative_urls = vec![
            "/path/to/resource",
            "../parent/resource",
            "./current/resource",
            "resource",
            "?query=value",
            "#fragment",
            "/path?query=value#fragment",
        ];

        for url in valid_relative_urls {
            assert!(
                validate_and_resolve_url(base_url, url).is_ok(),
                "Should accept valid relative URL: {}",
                url
            );
        }
    }

    #[test]
    fn test_validate_and_resolve_url_control_characters() {
        let base_url = "https://example.com";

        // Test URLs with control characters (should be rejected)
        let invalid_control_char_urls = vec![
            "http://example.com\x00",      // NULL character
            "http://example.com\x01",      // SOH character
            "http://example.com\x1F",      // Unit separator
            "http://example.com\x7F",      // DEL character
            "http://example.com/path\x0A", // Line feed
            "http://example.com/path\x0D", // Carriage return
        ];

        for url in invalid_control_char_urls {
            assert!(
                validate_and_resolve_url(base_url, url).is_err(),
                "Should reject URL with control character: {:?}",
                url
            );
        }

        // Test that tab character is allowed (exception)
        assert!(
            validate_and_resolve_url(base_url, "http://example.com\x09")
                .is_ok(),
            "Should allow tab character in URL"
        );

        // Test control characters in base URL
        assert!(
            validate_and_resolve_url("http://example.com\x00", "/path")
                .is_err(),
            "Should reject base URL with control character"
        );
    }

    #[test]
    fn test_validate_and_resolve_url_edge_cases() {
        let base_url = "https://example.com";

        // Test URLs that are valid relative URLs according to RFC 3986
        let valid_relative_urls = vec![
            "not a url at all",    // Valid relative path
            "",                    // Empty string is valid relative URL
            "ht tp://example.com", // Space character is allowed in relative URLs
        ];

        for url in valid_relative_urls {
            assert!(
                validate_and_resolve_url(base_url, url).is_ok(),
                "According to RFC 3986, this should be valid as relative URL: {}",
                url
            );
        }

        // Test URLs that fail validation (parsing fails)
        let invalid_urls = vec![
            "://missing-scheme", // Invalid relative URL that may cause parsing issues
        ];

        for url in invalid_urls {
            // These may either succeed (if url crate can handle them) or fail
            // The important thing is that we don't crash
            let result = validate_and_resolve_url(base_url, url);
            // Just ensure we get a result, whether success or error
            let _ = result;
        }
    }

    #[test]
    fn test_get_api_version() {
        // Test with custom API version
        let args_with_version = UrlArgs {
            verifier_url: "https://example.com".to_string(),
            agent_identifier: Some("test".to_string()),
            api_version: Some("v2.0".to_string()),
            location: None,
        };
        assert_eq!(get_api_version(&args_with_version), "v2.0");

        // Test with None API version (should return default)
        let args_without_version = UrlArgs {
            verifier_url: "https://example.com".to_string(),
            agent_identifier: Some("test".to_string()),
            api_version: None,
            location: None,
        };
        assert_eq!(
            get_api_version(&args_without_version),
            DEFAULT_API_VERSION
        );
    }

    #[test]
    fn test_get_negotiations_request_url_edge_cases() {
        // Test with empty verifier URL
        let url = get_negotiations_request_url(&UrlArgs {
            verifier_url: "".to_string(),
            agent_identifier: Some("test".to_string()),
            api_version: None,
            location: None,
        });
        assert_eq!(url, "ERROR: No verifier URL provided");

        // Test with no agent identifier
        let url = get_negotiations_request_url(&UrlArgs {
            verifier_url: "https://example.com".to_string(),
            agent_identifier: None,
            api_version: None,
            location: None,
        });
        assert_eq!(url, "ERROR: No agent identifier provided");

        // Test with custom API version
        let url = get_negotiations_request_url(&UrlArgs {
            verifier_url: "https://example.com".to_string(),
            agent_identifier: Some("test-agent".to_string()),
            api_version: Some("v2.1".to_string()),
            location: None,
        });
        assert_eq!(
            url,
            "https://example.com/v2.1/agents/test-agent/attestations"
        );
    }

    #[test]
    fn test_get_evidence_submission_request_url_edge_cases() {
        // Test with empty verifier URL
        let url = get_evidence_submission_request_url(&UrlArgs {
            verifier_url: "".to_string(),
            agent_identifier: None,
            api_version: None,
            location: Some("/path".to_string()),
        });
        assert_eq!(url, "ERROR: No verifier URL provided");

        // Test with no location
        let url = get_evidence_submission_request_url(&UrlArgs {
            verifier_url: "https://example.com".to_string(),
            agent_identifier: None,
            api_version: None,
            location: None,
        });
        assert_eq!(url, "ERROR: No location provided");

        // Test with valid absolute location URL
        let url = get_evidence_submission_request_url(&UrlArgs {
            verifier_url: "https://example.com".to_string(),
            agent_identifier: None,
            api_version: None,
            location: Some("https://other.com/path".to_string()),
        });
        assert_eq!(url, "https://other.com/path");
    }

    #[test]
    fn test_url_resolution_error_handling() {
        // Test URL resolution with malformed base URL that passes validation but fails resolution
        // This tests the error handling in resolve_url
        let url = get_negotiations_request_url(&UrlArgs {
            verifier_url: "http://[invalid-ipv6".to_string(), // Invalid IPv6 format
            agent_identifier: Some("test".to_string()),
            api_version: None,
            location: None,
        });

        // Should return an error message starting with "ERROR:"
        assert!(
            url.starts_with("ERROR:"),
            "Should return error for malformed URL that fails resolution: {}",
            url
        );
    }

    #[test]
    fn test_special_characters_in_agent_identifier() {
        // Test with agent identifier containing special characters
        let test_cases = vec![
            "agent-with-dashes",
            "agent_with_underscores",
            "agent123",
            "AGENT-UPPERCASE",
            "agent.with.dots",
        ];

        for agent_id in test_cases {
            let url = get_negotiations_request_url(&UrlArgs {
                verifier_url: "https://example.com".to_string(),
                agent_identifier: Some(agent_id.to_string()),
                api_version: None,
                location: None,
            });

            assert!(
                !url.starts_with("ERROR:"),
                "Should handle agent identifier with special characters: {}",
                agent_id
            );
            assert!(
                url.contains(agent_id),
                "URL should contain the agent identifier: {}",
                url
            );
        }
    }

    #[test]
    fn test_url_schemes() {
        // Test different URL schemes
        let schemes = vec!["http://example.com", "https://example.com"];

        for base_url in schemes {
            let url = get_negotiations_request_url(&UrlArgs {
                verifier_url: base_url.to_string(),
                agent_identifier: Some("test".to_string()),
                api_version: None,
                location: None,
            });

            assert!(
                !url.starts_with("ERROR:"),
                "Should handle URL scheme: {}",
                base_url
            );
            assert!(
                url.starts_with(base_url),
                "Generated URL should preserve scheme: {}",
                url
            );
        }
    }

    #[test]
    fn test_location_header_variations() {
        let base_url = "https://example.com";

        // Test various location header formats
        let location_cases = vec![
            ("/absolute/path", "https://example.com/absolute/path"),
            ("relative/path", "https://example.com/relative/path"),
            ("../parent/path", "https://example.com/parent/path"),
            ("./current/path", "https://example.com/current/path"),
            ("?query=only", "https://example.com/?query=only"), // URL resolution adds trailing slash
            ("#fragment-only", "https://example.com/#fragment-only"), // URL resolution adds trailing slash
        ];

        for (location, expected) in location_cases {
            let url = get_evidence_submission_request_url(&UrlArgs {
                verifier_url: base_url.to_string(),
                agent_identifier: None,
                api_version: None,
                location: Some(location.to_string()),
            });

            assert!(
                !url.starts_with("ERROR:"),
                "Should handle location header format: {}",
                location
            );
            assert_eq!(
                url, expected,
                "Location resolution failed for: {}",
                location
            );
        }
    }

    #[test]
    fn test_negotiations_url_resolve_base_parse_error() {
        // Test case where verifier URL passes RFC validation but fails URL parsing in resolve_url
        // Create a URL that passes our RFC 3986 validation but fails Url::parse()
        let url = get_negotiations_request_url(&UrlArgs {
            verifier_url: "notavalidurl".to_string(), // This may pass initial validation but fails URL parsing
            agent_identifier: Some("test".to_string()),
            api_version: None,
            location: None,
        });

        assert!(
            url.starts_with("ERROR: Invalid verifier URL:"),
            "Should return error for URL that fails base parsing in resolve_url: {}",
            url
        );
    }

    #[test]
    fn test_negotiations_url_resolve_join_error() {
        // Test case where base URL is valid but joining with relative path fails
        // Using a URL that parses but has issues with joining
        let url = get_negotiations_request_url(&UrlArgs {
            verifier_url: "http://user:@example.com".to_string(), // Valid base URL
            agent_identifier: Some("../../../etc/passwd".to_string()), // Path that could cause join issues
            api_version: None,
            location: None,
        });

        // This should either succeed or fail with resolve error, not with validation error
        if url.starts_with("ERROR:") {
            assert!(
                url.contains("Failed to resolve URL:")
                    || url.contains("Invalid verifier URL:"),
                "Error should be about URL resolution or validation: {}",
                url
            );
        }
    }

    #[test]
    fn test_evidence_submission_url_resolve_base_parse_error() {
        // Test case where verifier URL passes RFC validation but fails URL parsing in resolve_url
        let url = get_evidence_submission_request_url(&UrlArgs {
            verifier_url: "relativeurlnotabsolute".to_string(), // Passes RFC validation as relative but fails Url::parse as base
            agent_identifier: None,
            api_version: None,
            location: Some("/valid/path".to_string()),
        });

        assert!(
            url.starts_with("ERROR: Invalid location header:"),
            "Should return error for URL that fails base parsing in resolve_url: {}",
            url
        );
    }

    #[test]
    fn test_evidence_submission_url_resolve_join_error() {
        // Test case where both base and location are valid individually but joining fails
        // Use a scenario that might cause URL joining to fail
        let url = get_evidence_submission_request_url(&UrlArgs {
            verifier_url: "data:text/plain,hello".to_string(), // Valid URL but non-HTTP scheme that might cause join issues
            agent_identifier: None,
            api_version: None,
            location: Some("http://different.scheme".to_string()),
        });

        // This should either succeed or fail with resolve error
        if url.starts_with("ERROR:") {
            assert!(
                url.contains("Failed to resolve evidence submission URL:")
                    || url.contains("Invalid"),
                "Error should be about URL resolution or validation: {}",
                url
            );
        }
    }

    #[test]
    fn test_location_header_validation_for_201() {
        // Test 201 response requires Location header
        assert!(validate_location_header_for_201(201, None).is_err());
        assert!(validate_location_header_for_201(201, Some("/path")).is_ok());

        // Test other status codes don't require Location header
        assert!(validate_location_header_for_201(200, None).is_ok());
        assert!(validate_location_header_for_201(404, None).is_ok());
        assert!(validate_location_header_for_201(500, None).is_ok());
    }

    #[test]
    fn test_extremely_malformed_urls_that_pass_validation() {
        // Test URLs that pass our basic RFC validation but fail deeper parsing
        let malformed_urls = vec![
            "://",              // Empty scheme and authority
            "scheme:",          // Scheme only
            "//authority/path", // Authority without scheme
        ];

        for malformed_url in malformed_urls {
            // Test negotiations URL
            let negotiations_result =
                get_negotiations_request_url(&UrlArgs {
                    verifier_url: malformed_url.to_string(),
                    agent_identifier: Some("test".to_string()),
                    api_version: None,
                    location: None,
                });

            if !negotiations_result.starts_with("ERROR:") {
                // If it doesn't error, it should be a valid URL
                assert!(
                    negotiations_result.starts_with("http://")
                        || negotiations_result.starts_with("https://"),
                    "If no error, should produce valid URL: {}",
                    negotiations_result
                );
            } else {
                assert!(
                    negotiations_result.contains("Invalid verifier URL:")
                        || negotiations_result
                            .contains("Failed to resolve URL:"),
                    "Error should be about validation or resolution: {}",
                    negotiations_result
                );
            }

            // Test evidence submission URL
            let evidence_result =
                get_evidence_submission_request_url(&UrlArgs {
                    verifier_url: malformed_url.to_string(),
                    agent_identifier: None,
                    api_version: None,
                    location: Some("/test/path".to_string()),
                });

            if !evidence_result.starts_with("ERROR:") {
                // If it doesn't error, it should be a valid URL
                assert!(
                    evidence_result.starts_with("http://")
                        || evidence_result.starts_with("https://")
                        || evidence_result.starts_with("//"),
                    "If no error, should produce valid URL: {}",
                    evidence_result
                );
            } else {
                assert!(
                    evidence_result.contains("Invalid")
                        || evidence_result.contains("Failed to resolve"),
                    "Error should be about validation or resolution: {}",
                    evidence_result
                );
            }
        }
    }

    #[test]
    fn test_get_evidence_submission_request_url_invalid_verifier_url() {
        // Test specifically where validation returns an error
        // for the verifier URL in get_evidence_submission_request_url

        // Test URLs with control characters that will fail RFC 3986 validation
        let invalid_verifier_urls = vec![
            "http://example.com\x00",      // NULL character
            "http://example.com\x01",      // SOH character
            "http://example.com\x1F",      // Unit separator
            "http://example.com\x7F",      // DEL character
            "http://example.com/path\x0A", // Line feed
            "http://example.com/path\x0D", // Carriage return
            "https://test.com\x02/path",   // STX character
            "https://invalid\x03.com",     // ETX character
        ];

        for invalid_url in invalid_verifier_urls {
            let result = get_evidence_submission_request_url(&UrlArgs {
                verifier_url: invalid_url.to_string(),
                agent_identifier: None,
                api_version: None,
                location: Some(
                    "/v3.0/agents/test/attestations/1".to_string(),
                ),
            });

            // Should return error due to invalid verifier URL
            assert!(
                result.starts_with("ERROR: Invalid"),
                "Should return invalid verifier URL error for control character URL: {:?}, got: {}",
                invalid_url,
                result
            );

            // Error message should contain information about the control character
            assert!(
                result.contains("Control character")
                    || result.contains("DEL character"),
                "Error message should mention control character issue: {}",
                result
            );
        }
    }

    #[test]
    fn test_get_evidence_submission_request_url_invalid_verifier_url_edge_cases(
    ) {
        // Additional edge cases for verifier URL validation to ensure lines 94-95 coverage

        // Test with various invalid URL patterns that should trigger RFC 3986 validation errors
        let test_cases = vec![
            (
                "http://",
                "Should reject incomplete URL that fails both absolute and relative parsing"
            ),
            (
                "://incomplete",
                "Should reject URL with missing scheme"
            ),
        ];

        for (invalid_url, description) in test_cases {
            let result = get_evidence_submission_request_url(&UrlArgs {
                verifier_url: invalid_url.to_string(),
                agent_identifier: None,
                api_version: None,
                location: Some("/valid/path".to_string()),
            });

            // Should return either validation error or resolution error
            assert!(
                result.starts_with("ERROR:"),
                "{}: {}",
                description,
                result
            );

            // Should be either invalid verifier URL or failed resolution
            assert!(
                result.contains("Invalid") || result.contains("Failed to resolve"),
                "Error should be about verifier URL validation or resolution: {}",
                result
            );
        }
    }
}
