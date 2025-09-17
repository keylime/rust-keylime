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
}
