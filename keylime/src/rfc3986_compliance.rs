// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! RFC compliance implementations for URI handling
//!
//! This module implements compliance with:
//! - RFC 3986 Section 4.1: URI reference syntax
//! - RFC 3986 Section 4.2: Relative reference handling

use std::fmt;
use thiserror::Error;

/// Errors related to RFC compliance
#[derive(Error, Debug)]
pub enum RfcComplianceError {
    #[error("Invalid URI reference syntax: {0}")]
    InvalidUriReference(String),
    #[error("Invalid relative reference: {0}")]
    InvalidRelativeReference(String),
    #[error("Missing Location header in 201 Created response")]
    MissingLocationHeader,
    #[error("Invalid Location header value: {0}")]
    InvalidLocationHeader(String),
}

/// RFC 3986 Section 4.1: URI reference
///
/// URI-reference = URI / relative-ref
/// URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
/// relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
#[derive(Debug, Clone, PartialEq)]
pub struct UriReference {
    /// The scheme component (e.g., "https")
    pub scheme: Option<String>,
    /// The authority component (e.g., "example.com:8080")
    pub authority: Option<String>,
    /// The path component
    pub path: String,
    /// The query component
    pub query: Option<String>,
    /// The fragment component
    pub fragment: Option<String>,
}

impl UriReference {
    /// Parse a URI reference according to RFC 3986 Section 4.1
    pub fn parse(uri_ref: &str) -> Result<Self, RfcComplianceError> {
        // First check for invalid characters according to RFC 3986
        for ch in uri_ref.chars() {
            if ch.is_control() && ch != '\t' {
                return Err(RfcComplianceError::InvalidUriReference(
                    format!(
                        "URI contains invalid control character: {:?}",
                        ch
                    ),
                ));
            }
        }

        // RFC 3986 grammar parsing
        let _chars = uri_ref.chars().peekable();
        let authority = None;
        let query = None;
        let fragment = None;

        // Check for scheme
        let scheme_end = uri_ref.find(':');
        if let Some(pos) = scheme_end {
            let potential_scheme = &uri_ref[..pos];
            if Self::is_valid_scheme(potential_scheme) {
                let scheme = Some(potential_scheme.to_string());
                let remainder = &uri_ref[pos + 1..];
                return Self::parse_hier_part_and_rest(
                    remainder, scheme, authority, query, fragment,
                );
            }
        }

        // No scheme found, this is a relative reference (RFC 3986 Section 4.2)
        Self::parse_relative_ref(uri_ref)
    }

    /// Check if a string is a valid URI scheme according to RFC 3986
    fn is_valid_scheme(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }

        let mut chars = s.chars();
        // First character must be a letter
        if let Some(first) = chars.next() {
            if !first.is_ascii_alphabetic() {
                return false;
            }
        } else {
            return false;
        }

        // Subsequent characters must be letters, digits, '+', '-', or '.'
        for c in chars {
            if !c.is_ascii_alphanumeric() && c != '+' && c != '-' && c != '.'
            {
                return false;
            }
        }

        true
    }

    /// Parse hier-part and remaining components
    fn parse_hier_part_and_rest(
        remainder: &str,
        scheme: Option<String>,
        mut authority: Option<String>,
        mut query: Option<String>,
        mut fragment: Option<String>,
    ) -> Result<UriReference, RfcComplianceError> {
        let mut working_str = remainder;
        let path;

        // Check for authority (starts with "//")
        if working_str.starts_with("//") {
            working_str = &working_str[2..];
            if let Some(auth_end) = working_str.find(['/', '?', '#']) {
                authority = Some(working_str[..auth_end].to_string());
                working_str = &working_str[auth_end..];
            } else {
                authority = Some(working_str.to_string());
                working_str = "";
            }
        }

        // Parse path
        if let Some(query_start) = working_str.find('?') {
            path = working_str[..query_start].to_string();
            working_str = &working_str[query_start + 1..];

            if let Some(fragment_start) = working_str.find('#') {
                query = Some(working_str[..fragment_start].to_string());
                fragment =
                    Some(working_str[fragment_start + 1..].to_string());
            } else {
                query = Some(working_str.to_string());
            }
        } else if let Some(fragment_start) = working_str.find('#') {
            path = working_str[..fragment_start].to_string();
            fragment = Some(working_str[fragment_start + 1..].to_string());
        } else {
            path = working_str.to_string();
        }

        Ok(UriReference {
            scheme,
            authority,
            path,
            query,
            fragment,
        })
    }

    /// Parse relative reference according to RFC 3986 Section 4.2
    fn parse_relative_ref(
        relative_ref: &str,
    ) -> Result<UriReference, RfcComplianceError> {
        let mut authority = None;
        let path;
        let mut query = None;
        let mut fragment = None;
        let mut working_str = relative_ref;

        // Check for authority (starts with "//")
        if working_str.starts_with("//") {
            working_str = &working_str[2..];
            if let Some(auth_end) = working_str.find(['/', '?', '#']) {
                authority = Some(working_str[..auth_end].to_string());
                working_str = &working_str[auth_end..];
            } else {
                authority = Some(working_str.to_string());
                working_str = "";
            }
        }

        // Parse path, query, and fragment
        if let Some(query_start) = working_str.find('?') {
            path = working_str[..query_start].to_string();
            working_str = &working_str[query_start + 1..];

            if let Some(fragment_start) = working_str.find('#') {
                query = Some(working_str[..fragment_start].to_string());
                fragment =
                    Some(working_str[fragment_start + 1..].to_string());
            } else {
                query = Some(working_str.to_string());
            }
        } else if let Some(fragment_start) = working_str.find('#') {
            path = working_str[..fragment_start].to_string();
            fragment = Some(working_str[fragment_start + 1..].to_string());
        } else {
            path = working_str.to_string();
        }

        Ok(UriReference {
            scheme: None,
            authority,
            path,
            query,
            fragment,
        })
    }

    /// Check if this is a relative reference (RFC 3986 Section 4.2)
    pub fn is_relative(&self) -> bool {
        self.scheme.is_none()
    }

    /// Resolve a relative reference against a base URI (RFC 3986 Section 5.2.2)
    pub fn resolve_against(
        &self,
        base: &UriReference,
    ) -> Result<UriReference, RfcComplianceError> {
        if !self.is_relative() {
            // If this URI has a scheme, it's absolute
            return Ok(self.clone());
        }

        let mut target = UriReference {
            scheme: base.scheme.clone(),
            authority: None,
            path: String::new(),
            query: None,
            fragment: self.fragment.clone(),
        };

        if self.authority.is_some() {
            target.authority = self.authority.clone();
            target.path = self.path.clone();
            target.query = self.query.clone();
        } else {
            target.authority = base.authority.clone();

            if self.path.is_empty() {
                target.path = base.path.clone();
                target.query =
                    self.query.as_ref().or(base.query.as_ref()).cloned();
            } else {
                if self.path.starts_with('/') {
                    target.path = self.path.clone();
                } else {
                    target.path = Self::merge_paths(&base.path, &self.path);
                }
                target.query = self.query.clone();
            }
        }

        // Remove dot segments (RFC 3986 Section 5.2.4)
        target.path = Self::remove_dot_segments(&target.path);

        // Special case: if we have an authority but the path is just ".",
        // it should be empty instead (for authority-only URIs like "//g")
        if target.authority.is_some() && target.path == "." {
            target.path = String::new();
        }

        // Special handling for dot-only relative references - should point to directories
        // This includes ".", "..", "../..", etc. but not paths like "../g"
        let is_dots_only = self.path.chars().all(|c| c == '.' || c == '/');
        if is_dots_only
            && !self.path.is_empty()
            && !target.path.ends_with('/')
            && !target.path.is_empty()
        {
            target.path.push('/');
        }

        Ok(target)
    }

    /// Merge paths according to RFC 3986 Section 5.2.3
    fn merge_paths(base_path: &str, relative_path: &str) -> String {
        if base_path.is_empty() {
            format!("/{}", relative_path)
        } else {
            let last_slash = base_path.rfind('/');
            match last_slash {
                Some(pos) => {
                    // Include the slash in the result
                    format!("{}{}", &base_path[..=pos], relative_path)
                }
                None => relative_path.to_string(),
            }
        }
    }

    /// Remove dot segments according to RFC 3986 Section 5.2.4
    fn remove_dot_segments(path: &str) -> String {
        let segments: Vec<&str> = path.split('/').collect();
        let mut result: Vec<&str> = Vec::new();
        let starts_with_slash = path.starts_with('/');
        let ends_with_slash = path.ends_with('/') && !path.is_empty();

        for segment in segments.iter() {
            match *segment {
                "." => {
                    // Skip current directory segments, but this preserves trailing slash behavior
                    continue;
                }
                "" => {
                    // Skip empty segments except they indicate leading/trailing slashes
                    continue;
                }
                ".." => {
                    // Go up one directory
                    if !result.is_empty() && result.last() != Some(&"..") {
                        result.pop();
                    } else if !starts_with_slash {
                        // Only keep .. segments for relative paths
                        result.push("..");
                    }
                }
                _ => {
                    result.push(segment);
                }
            }
        }

        // Rebuild the path
        let mut output = String::new();

        if starts_with_slash {
            output.push('/');
        }

        for (i, segment) in result.iter().enumerate() {
            if i > 0 {
                output.push('/');
            }
            output.push_str(segment);
        }

        // Preserve trailing slash if original had one
        if ends_with_slash {
            output.push('/');
        }

        // Handle edge cases per RFC 3986 Section 5.2.4
        if output.is_empty() {
            if starts_with_slash {
                output = "/".to_string();
            } else {
                // For relative paths that become empty, use "."
                // But this will be overridden later for authority-only URIs
                output = ".".to_string();
            }
        } else if output == "//" {
            // Handle the edge case where we get "//" - this should be "/"
            output = "/".to_string();
        } else if output == "/" && !starts_with_slash {
            // This shouldn't happen in normal cases
            output = ".".to_string();
        }

        output
    }
}

impl fmt::Display for UriReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref scheme) = self.scheme {
            write!(f, "{}:", scheme)?;
        }

        if let Some(ref authority) = self.authority {
            write!(f, "//{}", authority)?;
        }

        write!(f, "{}", self.path)?;

        if let Some(ref query) = self.query {
            write!(f, "?{}", query)?;
        }

        if let Some(ref fragment) = self.fragment {
            write!(f, "#{}", fragment)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_reference_parsing() {
        // Test absolute URI
        let uri = UriReference::parse(
            "https://example.com:8080/path?query=value#fragment",
        )
        .unwrap(); //#[allow_ci]
        assert_eq!(uri.scheme, Some("https".to_string()));
        assert_eq!(uri.authority, Some("example.com:8080".to_string()));
        assert_eq!(uri.path, "/path");
        assert_eq!(uri.query, Some("query=value".to_string()));
        assert_eq!(uri.fragment, Some("fragment".to_string()));
        assert!(!uri.is_relative());

        // Test relative reference
        let rel = UriReference::parse("/path?query=value").unwrap(); //#[allow_ci]
        assert_eq!(rel.scheme, None);
        assert_eq!(rel.path, "/path");
        assert_eq!(rel.query, Some("query=value".to_string()));
        assert!(rel.is_relative());
    }

    #[test]
    fn test_scheme_validation() {
        assert!(UriReference::is_valid_scheme("http"));
        assert!(UriReference::is_valid_scheme("https"));
        assert!(UriReference::is_valid_scheme("ftp"));
        assert!(UriReference::is_valid_scheme("custom+scheme"));
        assert!(!UriReference::is_valid_scheme("123invalid"));
        assert!(!UriReference::is_valid_scheme(""));
    }

    #[test]
    fn test_relative_resolution() {
        let base =
            UriReference::parse("https://example.com/path/to/resource")
                .unwrap(); //#[allow_ci]
        let relative = UriReference::parse("../other").unwrap(); //#[allow_ci]
        let resolved = relative.resolve_against(&base).unwrap(); //#[allow_ci]
        assert_eq!(resolved.to_string(), "https://example.com/path/other");
    }

    #[test]
    fn test_dot_segment_removal() {
        assert_eq!(
            UriReference::remove_dot_segments("/a/b/c/./../../g"),
            "/a/g"
        );
        assert_eq!(UriReference::remove_dot_segments("/../a/b"), "/a/b");
        assert_eq!(UriReference::remove_dot_segments("/a/./b"), "/a/b");
    }

    #[test]
    fn test_invalid_control_characters() {
        // Test various control characters (except tab which is allowed)
        assert!(UriReference::parse("http://example.com\x00").is_err());
        assert!(UriReference::parse("http://example.com\x01").is_err());
        assert!(UriReference::parse("http://example.com\x1f").is_err());
        assert!(UriReference::parse("http://example.com\x7f").is_err());

        // Tab should be allowed
        assert!(UriReference::parse("http://example.com\t").is_ok());
    }

    #[test]
    fn test_scheme_edge_cases() {
        // Valid schemes
        assert!(UriReference::is_valid_scheme("a"));
        assert!(UriReference::is_valid_scheme("A"));
        assert!(UriReference::is_valid_scheme("http"));
        assert!(UriReference::is_valid_scheme("HTTPS"));
        assert!(UriReference::is_valid_scheme("ftp"));
        assert!(UriReference::is_valid_scheme("custom-scheme"));
        assert!(UriReference::is_valid_scheme("custom.scheme"));
        assert!(UriReference::is_valid_scheme("custom+scheme"));
        assert!(UriReference::is_valid_scheme("a1b2c3"));

        // Invalid schemes
        assert!(!UriReference::is_valid_scheme(""));
        assert!(!UriReference::is_valid_scheme("1http"));
        assert!(!UriReference::is_valid_scheme("-http"));
        assert!(!UriReference::is_valid_scheme(".http"));
        assert!(!UriReference::is_valid_scheme("+http"));
        assert!(!UriReference::is_valid_scheme("ht_tp"));
        assert!(!UriReference::is_valid_scheme("ht@tp"));
        assert!(!UriReference::is_valid_scheme("ht:tp"));
    }

    #[test]
    fn test_authority_parsing() {
        // URI with authority
        let uri =
            UriReference::parse("https://user:pass@example.com:8080/path")
                .unwrap(); //#[allow_ci]
        assert_eq!(uri.scheme, Some("https".to_string()));
        assert_eq!(
            uri.authority,
            Some("user:pass@example.com:8080".to_string())
        );
        assert_eq!(uri.path, "/path");

        // Relative reference with authority
        let rel = UriReference::parse("//example.com/path").unwrap(); //#[allow_ci]
        assert_eq!(rel.scheme, None);
        assert_eq!(rel.authority, Some("example.com".to_string()));
        assert_eq!(rel.path, "/path");

        // Authority without path
        let auth_only = UriReference::parse("//example.com").unwrap(); //#[allow_ci]
        assert_eq!(auth_only.authority, Some("example.com".to_string()));
        assert_eq!(auth_only.path, "");
    }

    #[test]
    fn test_query_and_fragment_parsing() {
        // Query only
        let query_uri =
            UriReference::parse("http://example.com?query=value&other=data")
                .unwrap(); //#[allow_ci]
        assert_eq!(
            query_uri.query,
            Some("query=value&other=data".to_string())
        );
        assert_eq!(query_uri.fragment, None);

        // Fragment only
        let frag_uri =
            UriReference::parse("http://example.com#section1").unwrap(); //#[allow_ci]
        assert_eq!(frag_uri.query, None);
        assert_eq!(frag_uri.fragment, Some("section1".to_string()));

        // Both query and fragment
        let both_uri =
            UriReference::parse("http://example.com/path?q=v#frag").unwrap(); //#[allow_ci]
        assert_eq!(both_uri.query, Some("q=v".to_string()));
        assert_eq!(both_uri.fragment, Some("frag".to_string()));

        // Empty query and fragment
        let empty_uri = UriReference::parse("http://example.com?#").unwrap(); //#[allow_ci]
        assert_eq!(empty_uri.query, Some("".to_string()));
        assert_eq!(empty_uri.fragment, Some("".to_string()));
    }

    #[test]
    fn test_path_variations() {
        // Absolute path
        let abs_path = UriReference::parse("/absolute/path").unwrap(); //#[allow_ci]
        assert_eq!(abs_path.path, "/absolute/path");
        assert!(abs_path.is_relative());

        // Relative path
        let rel_path = UriReference::parse("relative/path").unwrap(); //#[allow_ci]
        assert_eq!(rel_path.path, "relative/path");
        assert!(rel_path.is_relative());

        // Empty path
        let empty_path = UriReference::parse("").unwrap(); //#[allow_ci]
        assert_eq!(empty_path.path, "");
        assert!(empty_path.is_relative());

        // Root path
        let root_path = UriReference::parse("/").unwrap(); //#[allow_ci]
        assert_eq!(root_path.path, "/");

        // Path with encoded characters
        let encoded_path =
            UriReference::parse("/path%20with%20spaces").unwrap(); //#[allow_ci]
        assert_eq!(encoded_path.path, "/path%20with%20spaces");
    }

    #[test]
    fn test_complex_relative_resolution() {
        let base =
            UriReference::parse("https://example.com/a/b/c/d").unwrap(); //#[allow_ci]

        // Test various relative references from RFC 3986 Section 5.4.1
        let test_cases = vec![
            ("g", "https://example.com/a/b/c/g"),
            ("./g", "https://example.com/a/b/c/g"),
            ("g/", "https://example.com/a/b/c/g/"),
            ("/g", "https://example.com/g"),
            ("//g", "https://g"),
            ("?y", "https://example.com/a/b/c/d?y"),
            ("g?y", "https://example.com/a/b/c/g?y"),
            ("#s", "https://example.com/a/b/c/d#s"),
            ("g#s", "https://example.com/a/b/c/g#s"),
            ("g?y#s", "https://example.com/a/b/c/g?y#s"),
            (";x", "https://example.com/a/b/c/;x"),
            ("g;x", "https://example.com/a/b/c/g;x"),
            ("g;x?y#s", "https://example.com/a/b/c/g;x?y#s"),
            ("", "https://example.com/a/b/c/d"),
            (".", "https://example.com/a/b/c/"),
            ("./", "https://example.com/a/b/c/"),
            ("..", "https://example.com/a/b/"),
            ("../", "https://example.com/a/b/"),
            ("../g", "https://example.com/a/b/g"),
            ("../..", "https://example.com/a/"),
            ("../../", "https://example.com/a/"),
            ("../../g", "https://example.com/a/g"),
        ];

        for (relative, expected) in test_cases {
            let rel_ref = UriReference::parse(relative).unwrap(); //#[allow_ci]
            let resolved = rel_ref.resolve_against(&base).unwrap(); //#[allow_ci]
            assert_eq!(
                resolved.to_string(),
                expected,
                "Failed for relative reference: {}",
                relative
            );
        }
    }

    #[test]
    fn test_absolute_uri_resolution() {
        let base = UriReference::parse("https://example.com/path").unwrap(); //#[allow_ci]
        let absolute = UriReference::parse("http://other.com/other").unwrap(); //#[allow_ci]

        // Absolute URI should not be affected by base
        let resolved = absolute.resolve_against(&base).unwrap(); //#[allow_ci]
        assert_eq!(resolved.to_string(), "http://other.com/other");
    }

    #[test]
    fn test_edge_case_dot_segments() {
        // Additional dot segment removal tests
        assert_eq!(UriReference::remove_dot_segments(""), ".");
        assert_eq!(UriReference::remove_dot_segments("."), ".");
        assert_eq!(UriReference::remove_dot_segments(".."), "..");
        assert_eq!(UriReference::remove_dot_segments("./"), ".");
        assert_eq!(UriReference::remove_dot_segments("../"), "../");
        assert_eq!(UriReference::remove_dot_segments("/"), "/");
        assert_eq!(UriReference::remove_dot_segments("/."), "/");
        assert_eq!(UriReference::remove_dot_segments("/.."), "/");
        assert_eq!(UriReference::remove_dot_segments("/./"), "/");
        assert_eq!(UriReference::remove_dot_segments("/../"), "/");
        assert_eq!(UriReference::remove_dot_segments("a/b/../c"), "a/c");
        assert_eq!(UriReference::remove_dot_segments("a/b/../../c"), "c");
        assert_eq!(
            UriReference::remove_dot_segments("a/b/../../../c"),
            "../c"
        );
        assert_eq!(UriReference::remove_dot_segments("./a/b/c"), "a/b/c");
        assert_eq!(UriReference::remove_dot_segments("../a/b/c"), "../a/b/c");
    }

    #[test]
    fn test_path_merging() {
        // Test path merging scenarios
        assert_eq!(UriReference::merge_paths("", "relative"), "/relative");
        assert_eq!(UriReference::merge_paths("/", "relative"), "/relative");
        assert_eq!(UriReference::merge_paths("/a", "relative"), "/relative");
        assert_eq!(
            UriReference::merge_paths("/a/", "relative"),
            "/a/relative"
        );
        assert_eq!(
            UriReference::merge_paths("/a/b", "relative"),
            "/a/relative"
        );
        assert_eq!(
            UriReference::merge_paths("/a/b/", "relative"),
            "/a/b/relative"
        );
        assert_eq!(
            UriReference::merge_paths("no-slash", "relative"),
            "relative"
        );
    }

    #[test]
    fn test_uri_display() {
        // Test string representation
        let uri = UriReference {
            scheme: Some("https".to_string()),
            authority: Some("example.com:8080".to_string()),
            path: "/path/to/resource".to_string(),
            query: Some("key=value&other=data".to_string()),
            fragment: Some("section".to_string()),
        };
        assert_eq!(uri.to_string(), "https://example.com:8080/path/to/resource?key=value&other=data#section");

        // Test minimal URI
        let minimal = UriReference {
            scheme: None,
            authority: None,
            path: "path".to_string(),
            query: None,
            fragment: None,
        };
        assert_eq!(minimal.to_string(), "path");

        // Test scheme only
        let scheme_only = UriReference {
            scheme: Some("https".to_string()),
            authority: None,
            path: "".to_string(),
            query: None,
            fragment: None,
        };
        assert_eq!(scheme_only.to_string(), "https:");
    }

    #[test]
    fn test_special_characters_in_components() {
        // Test special characters in different components
        let uri = UriReference::parse("https://user%40domain:pass@example.com:8080/path%20with%20spaces?key=%20value%20&other=data#section%20name").unwrap(); //#[allow_ci]
        assert_eq!(uri.scheme, Some("https".to_string()));
        assert_eq!(
            uri.authority,
            Some("user%40domain:pass@example.com:8080".to_string())
        );
        assert_eq!(uri.path, "/path%20with%20spaces");
        assert_eq!(uri.query, Some("key=%20value%20&other=data".to_string()));
        assert_eq!(uri.fragment, Some("section%20name".to_string()));
    }

    #[test]
    fn test_rfc_compliance_error_display() {
        let error =
            RfcComplianceError::InvalidUriReference("test".to_string());
        assert_eq!(
            format!("{}", error),
            "Invalid URI reference syntax: test"
        );

        let error =
            RfcComplianceError::InvalidRelativeReference("test".to_string());
        assert_eq!(format!("{}", error), "Invalid relative reference: test");

        let error = RfcComplianceError::MissingLocationHeader;
        assert_eq!(
            format!("{}", error),
            "Missing Location header in 201 Created response"
        );

        let error =
            RfcComplianceError::InvalidLocationHeader("test".to_string());
        assert_eq!(
            format!("{}", error),
            "Invalid Location header value: test"
        );
    }

    #[test]
    fn test_uri_reference_clone_and_partial_eq() {
        let uri1 = UriReference::parse("https://example.com/path").unwrap(); //#[allow_ci]
        let uri2 = uri1.clone();
        assert_eq!(uri1, uri2);

        let uri3 = UriReference::parse("https://example.com/other").unwrap(); //#[allow_ci]
        assert_ne!(uri1, uri3);
    }

    #[test]
    fn test_relative_resolution_with_empty_base_path() {
        let base = UriReference::parse("https://example.com").unwrap(); //#[allow_ci]
        let relative = UriReference::parse("path").unwrap(); //#[allow_ci]
        let resolved = relative.resolve_against(&base).unwrap(); //#[allow_ci]
        assert_eq!(resolved.to_string(), "https://example.com/path");
    }

    #[test]
    fn test_relative_resolution_query_inheritance() {
        let base = UriReference::parse("https://example.com/path?base=query")
            .unwrap(); //#[allow_ci]

        // Empty relative reference should inherit base query
        let empty_rel = UriReference::parse("").unwrap(); //#[allow_ci]
        let resolved = empty_rel.resolve_against(&base).unwrap(); //#[allow_ci]
        assert_eq!(
            resolved.to_string(),
            "https://example.com/path?base=query"
        );

        // Relative with query should override base query
        let query_rel = UriReference::parse("?new=query").unwrap(); //#[allow_ci]
        let resolved = query_rel.resolve_against(&base).unwrap(); //#[allow_ci]
        assert_eq!(
            resolved.to_string(),
            "https://example.com/path?new=query"
        );
    }
}
