// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Keylime Authors

use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Parser)]
#[grammar = "ip.pest"]
pub struct IpParser;

#[derive(Error, Debug)]
pub enum IpParsingError {
    #[error("Invalid input {0}")]
    InvalidInput(String),

    #[error("Invalid IP")]
    InvalidIP(#[from] AddrParseError),

    #[error("failed to parse the input {input}")]
    ParseError {
        input: String,
        source: Box<pest::error::Error<Rule>>,
    },

    #[error("Unexpected end of input")]
    UnexpectedEOI,
}

fn get_inner_ip(pair: Pair<Rule>) -> Result<&str, IpParsingError> {
    let Some(item) = pair.into_inner().next() else {
        unreachable!()
    };

    match item.as_rule() {
        Rule::ip | Rule::bracketed | Rule::unbracketed => get_inner_ip(item),
        Rule::ipv4 => {
            // Validate the IP using the standard parser
            let _parsed_ipv4 = item.as_str().parse::<Ipv4Addr>()?;
            Ok(item.as_str())
        }
        Rule::ipv6 => {
            // Validate the IP using the standard parser
            let _parsed_ipv6 = item.as_str().parse::<Ipv6Addr>()?;
            Ok(item.as_str())
        }
        Rule::EOI => Err(IpParsingError::UnexpectedEOI),
        _ => {
            unreachable!()
        }
    }
}

/// Parses an ip address from a string slice removing eventual brackets.
/// This is mostly to remove brackets when using IPv6
///
/// Both IPv4 and IPv6 are supported:
///
/// * The IPv4 and IPv6 can be inside square brackets ("[]") or not
///
/// # Arguments
///
/// * `ip` the string to be parsed
///
/// # Returns
///
/// The obtained ip as a &str without brackets, if they were present
///
/// # Examples
///
/// Valid input lists, and respective result:
///
/// * `127.0.0.1` => `127.0.0.1`
/// * `::1` => `::1`
/// * `[127.0.0.1]` => `127.0.0.1
/// * `[::1]` => `::1`
pub fn parse_ip(ip: &str) -> Result<&str, IpParsingError> {
    let Some(pair) = IpParser::parse(Rule::ip, ip)
        .map_err(|e| IpParsingError::ParseError {
            input: ip.to_string(),
            source: Box::new(e),
        })?
        .next()
    else {
        return Err(IpParsingError::InvalidInput(ip.to_string()));
    };
    return get_inner_ip(pair);
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip() {
        // Sanity: most common case
        assert_eq!(parse_ip("127.0.0.1").unwrap(), "127.0.0.1"); //#[allow_ci]
        assert_eq!(parse_ip("[127.0.0.1]").unwrap(), "127.0.0.1"); //#[allow_ci]
        assert_eq!(parse_ip("::1").unwrap(), "::1"); //#[allow_ci]
        assert_eq!(parse_ip("[::1]").unwrap(), "::1"); //#[allow_ci]

        // More advanced cases
        assert_eq!(parse_ip("::").unwrap(), "::"); //#[allow_ci]
        assert_eq!(parse_ip("::1").unwrap(), "::1"); //#[allow_ci]
        assert_eq!(parse_ip("1::").unwrap(), "1::"); //#[allow_ci]
        assert_eq!(parse_ip("1::1").unwrap(), "1::1"); //#[allow_ci]
        assert_eq!(parse_ip("[1::1]").unwrap(), "1::1"); //#[allow_ci]
        assert_eq!(parse_ip("1::2:3:4").unwrap(), "1::2:3:4"); //#[allow_ci]
        assert_eq!(parse_ip("1:2::3:4").unwrap(), "1:2::3:4"); //#[allow_ci]
        assert_eq!(parse_ip("1:2:3::4").unwrap(), "1:2:3::4"); //#[allow_ci]
        assert_eq!(parse_ip("1:2:3:4:5:6:7:8").unwrap(), "1:2:3:4:5:6:7:8"); //#[allow_ci]

        // Invalid input
        assert!(parse_ip("1").is_err());
        assert!(parse_ip("1.2").is_err());
        assert!(parse_ip("1.2.3.4.5").is_err());
        assert!(parse_ip("1:2:3").is_err());
        assert!(parse_ip("1::2::3").is_err());
        assert!(parse_ip("1:2::3:4::5:6").is_err());
    }
}
