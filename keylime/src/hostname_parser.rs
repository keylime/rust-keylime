// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Keylime Authors

use pest::Parser;
use pest_derive::Parser;
use thiserror::Error;

#[derive(Parser)]
#[grammar = "hostname.pest"]
pub struct HostnameParser;

#[derive(Error, Debug)]
pub enum HostnameParsingError {
    #[error("Invalid input {0}")]
    InvalidInput(String),

    #[error("failed to parse the input {input}")]
    ParseError {
        input: String,
        source: Box<pest::error::Error<Rule>>,
    },
}

/// Parses a hostname from a string slice following RFC-1123
///
/// Valid hostnames are formed by labels separated by dots ('.').
///
/// The labels can only contain alphanumeric characters ('a'..'z' | 'A'..'Z' | '0'..'9') and the
/// hyphen ('-'). The labels cannot begin or end with an hyphen.
///
/// # Arguments
///
/// * `hostname` the string to be parsed
///
/// # Returns
///
/// The obtained hostname as a &str if it is a valid hostname
///
/// # Examples
///
/// Valid hostnames:
///
/// * `hostname`
/// * `host-name`
/// * `a.b.c`
/// * `a-b.c-d.e-f`
///
/// Invalid hostnames:
///
/// * `a_b.c`
/// * `a.b-.c`
/// * `a.-b.c`
pub fn parse_hostname(hostname: &str) -> Result<&str, HostnameParsingError> {
    let Some(pair) = HostnameParser::parse(Rule::hostname, hostname)
        .map_err(|e| HostnameParsingError::ParseError {
            input: hostname.to_string(),
            source: Box::new(e),
        })?
        .next()
    else {
        return Err(HostnameParsingError::InvalidInput(hostname.to_string()));
    };
    return Ok(pair.as_str());
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hostname() {
        // Sanity: most common case
        assert_eq!(parse_hostname("hostname").unwrap(), "hostname"); //#[allow_ci]
        assert_eq!(parse_hostname("ab.cd.ef").unwrap(), "ab.cd.ef"); //#[allow_ci]
        assert_eq!(parse_hostname("ab-cd-ef").unwrap(), "ab-cd-ef"); //#[allow_ci]

        // More advanced cases
        assert_eq!(
            parse_hostname("hostname-123.test").unwrap(), //#[allow_ci]
            "hostname-123.test"
        );
        assert_eq!(parse_hostname("123-456.789").unwrap(), "123-456.789"); //#[allow_ci]
        assert_eq!(parse_hostname("1----9").unwrap(), "1----9"); //#[allow_ci]

        // Invalid input
        assert!(parse_hostname("-host-na.me").is_err());
        assert!(parse_hostname("host-na.me-").is_err());
        assert!(parse_hostname(".host-na.me").is_err());
        assert!(parse_hostname("host-na.me.").is_err());
        assert!(parse_hostname("host_name").is_err());
        assert!(parse_hostname("host..name").is_err());
    }
}
