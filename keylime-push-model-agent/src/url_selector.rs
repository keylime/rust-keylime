// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! URL selection and validation for Push Model agent using RFC compliance

use keylime::https_client::resolve_url;
use log::warn;
use url::Url;

/// Validate URL according to RFC 3986 - can be absolute or relative
fn validate_url_rfc3986(url_str: &str) -> Result<(), String> {
    // Check for control characters (excluding tab) as per RFC 3986
    for (i, &byte) in url_str.as_bytes().iter().enumerate() {
        if byte < 0x20 && byte != 0x09 {
            // Allow tab (0x09) but reject other control chars
            return Err(format!("Control character at position {}", i));
        }
        if byte == 0x7F {
            // DEL character
            return Err(format!("DEL character at position {}", i));
        }
    }

    // First try to parse as absolute URL
    if Url::parse(url_str).is_ok() {
        return Ok(());
    }

    // If that fails, check if it's a valid relative URL by trying to resolve it against a dummy base
    let dummy_base = "http://example.com";
    if let Ok(base) = Url::parse(dummy_base) {
        if base.join(url_str).is_ok() {
            return Ok(());
        }
    }

    Err("Invalid URL according to RFC 3986".to_string())
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

    // Validate the base verifier URL according to RFC 3986
    if let Err(e) = validate_url_rfc3986(&args.verifier_url) {
        warn!("Invalid verifier URL according to RFC 3986: {}", e);
        return format!("ERROR: Invalid verifier URL: {}", e);
    }

    let id = match args.agent_identifier {
        Some(ref identifier) => identifier.clone(),
        None => return "ERROR: No agent identifier provided".to_string(),
    };

    let api_version = get_api_version(args);
    let relative_path = format!("{}/agents/{}/attestations", api_version, id);

    // Use RFC 3986 compliant URL resolution
    match resolve_url(&args.verifier_url, &relative_path) {
        Ok(resolved_url) => resolved_url,
        Err(e) => {
            warn!("Failed to resolve URL according to RFC 3986: {}", e);
            format!("ERROR: Failed to resolve URL: {}", e)
        }
    }
}

/// Get evidence submission request URL with RFC 3986 compliance validation
pub fn get_evidence_submission_request_url(args: &UrlArgs) -> String {
    if args.verifier_url.is_empty() {
        return "ERROR: No verifier URL provided".to_string();
    }

    // Validate the base verifier URL according to RFC 3986
    if let Err(e) = validate_url_rfc3986(&args.verifier_url) {
        warn!("Invalid verifier URL according to RFC 3986: {}", e);
        return format!("ERROR: Invalid verifier URL: {}", e);
    }

    let location = match &args.location {
        Some(loc) => {
            // Validate the location header according to RFC 3986
            if let Err(e) = validate_url_rfc3986(loc) {
                warn!("Invalid location header according to RFC 3986: {}", e);
                return format!("ERROR: Invalid location header: {}", e);
            }
            loc.clone()
        }
        None => return "ERROR: No location provided".to_string(),
    };

    // Use RFC 3986 compliant URL resolution
    match resolve_url(&args.verifier_url, &location) {
        Ok(resolved_url) => resolved_url,
        Err(e) => {
            warn!("Failed to resolve evidence submission URL according to RFC 3986: {}", e);
            format!("ERROR: Failed to resolve evidence submission URL: {}", e)
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
    fn test_validate_url_rfc3986_valid_urls() {
        // Test valid absolute URLs
        let valid_absolute_urls = vec![
            "https://example.com",
            "http://localhost:8080",
            "https://api.example.com/v1/endpoint",
            "ftp://files.example.com/path",
            "https://user:pass@example.com:443/path?query=value#fragment",
        ];

        for url in valid_absolute_urls {
            assert!(
                validate_url_rfc3986(url).is_ok(),
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
                validate_url_rfc3986(url).is_ok(),
                "Should accept valid relative URL: {}",
                url
            );
        }
    }

    #[test]
    fn test_validate_url_rfc3986_control_characters() {
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
                validate_url_rfc3986(url).is_err(),
                "Should reject URL with control character: {:?}",
                url
            );
        }

        // Test that tab character is allowed (exception)
        assert!(
            validate_url_rfc3986("http://example.com\x09").is_ok(),
            "Should allow tab character in URL"
        );
    }

    #[test]
    fn test_validate_url_rfc3986_edge_cases() {
        // Test URLs that are valid relative URLs according to RFC 3986
        let valid_relative_urls = vec![
            "not a url at all",    // Valid relative path
            "",                    // Empty string is valid relative URL
            "://missing-scheme", // Valid relative URL (authority with empty scheme)
            "ht tp://example.com", // Space character is allowed in relative URLs
        ];

        for url in valid_relative_urls {
            assert!(
                validate_url_rfc3986(url).is_ok(),
                "According to RFC 3986, this should be valid as relative URL: {}",
                url
            );
        }

        // Test URLs that fail validation (both absolute and relative parsing fail)
        let invalid_urls = vec![
            "http://", // Incomplete URL that fails both absolute and relative parsing
        ];

        for url in invalid_urls {
            assert!(
                validate_url_rfc3986(url).is_err(),
                "This URL should be invalid: {}",
                url
            );
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
}
