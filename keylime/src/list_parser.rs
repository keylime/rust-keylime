// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Keylime Authors

use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use thiserror::Error;

#[derive(Parser)]
#[grammar = "list.pest"]
pub struct ListParser;

#[derive(Error, Debug)]
pub enum ListParsingError {
    #[error("failed to parse list")]
    ParseError(#[source] Box<pest::error::Error<Rule>>),
}

fn get_inner_str(pair: Pair<Rule>) -> Vec<&str> {
    let mut l = Vec::new();
    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::list
            | Rule::bracketed
            | Rule::unbracketed
            | Rule::name
            | Rule::bracketed_name => {
                l.extend(get_inner_str(item));
            }
            Rule::single | Rule::double => {
                let s = item.as_str();
                let c = get_inner_str(item);
                if !c.is_empty() {
                    l.push(s);
                }
            }
            Rule::single_content
            | Rule::double_content
            | Rule::unquoted
            | Rule::bracketed_unquoted => {
                let i = item.as_str();
                if !i.is_empty() {
                    l.push(i);
                }
            }
            Rule::EOI => {
                break;
            }
            _ => {
                unreachable!()
            }
        }
    }
    l
}

/// Parses a list from a string slice and return a Vec<&str>
///
/// The list in the input string:
///
/// * can contain single-quoted, double-quoted, or unquoted strings
/// * can be inside square brackets ("[]") or not
/// * can have string separated by commas, white spaces, or newlines
///
/// If the string is single-quoted or double-quoted, the quotes are kept in the
/// output Vec<&str>.
///
/// # Arguments
///
/// * `list` the string to be parsed
///
/// # Returns
///
/// The obtained list as a Vec<&str>
///
/// # Examples
///
/// Valid input lists, and respective result:
///
/// * `a b c` => `["a", "b", "c"]`
/// * `'a' "b" c` => `["'a'", "\"b\"", "c"]`
/// * `[a b c]` => `["a", "b", "c"]`
/// * `['a', "b", c]` => `["'a'", "\"b\"", "c"]`
///
pub fn parse_list(list: &str) -> Result<Vec<&str>, ListParsingError> {
    if let Some(pair) = ListParser::parse(Rule::list, list)
        .map_err(|e| ListParsingError::ParseError(Box::new(e)))?
        .next()
    {
        return Ok(get_inner_str(pair));
    }
    Ok(Vec::new())
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_list() {
        // Sanity: most common case
        assert_eq!(
            parse_list("[\"aa\", \"bb\", \"cc\"]").unwrap(), //#[allow_ci]
            ["\"aa\"", "\"bb\"", "\"cc\""]
        );

        // Unquoted
        assert_eq!(parse_list("default").unwrap(), ["default"]); //#[allow_ci]

        // Double-quoted
        assert_eq!(parse_list("\"[default]\"").unwrap(), ["\"[default]\""]); //#[allow_ci]

        // Single-quoted
        assert_eq!(parse_list("'[default]'").unwrap(), ["'[default]'"]); //#[allow_ci]

        // Brackets, no quotes
        assert_eq!(parse_list("[default]").unwrap(), ["default"]); //#[allow_ci]
        assert_eq!(parse_list("[aa, bb]").unwrap(), ["aa", "bb"]); //#[allow_ci]

        // Brackets, double-quotes
        assert_eq!(parse_list("[\"default\"]").unwrap(), ["\"default\""]); //#[allow_ci]
        assert_eq!(
            parse_list("[\"aa\", \"bb\"]").unwrap(), //#[allow_ci]
            ["\"aa\"", "\"bb\""]
        );

        // Brackets, single-quotes
        assert_eq!(parse_list("['default']").unwrap(), ["'default'"]); //#[allow_ci]
        assert_eq!(parse_list("['aa', 'bb']").unwrap(), ["'aa'", "'bb'"]); //#[allow_ci]

        // Comma-separated
        assert_eq!(parse_list("aa,bb,cc").unwrap(), ["aa", "bb", "cc"]); //#[allow_ci]
        assert_eq!(
            parse_list("'aa','bb','cc'").unwrap(), //#[allow_ci]
            ["'aa'", "'bb'", "'cc'"]
        );
        assert_eq!(
            parse_list("'aa',\"bb\",'cc'").unwrap(), //#[allow_ci]
            ["'aa'", "\"bb\"", "'cc'"]
        );

        // Spaces-separated
        assert_eq!(parse_list("aa bb cc").unwrap(), ["aa", "bb", "cc"]); //#[allow_ci]
        assert_eq!(
            parse_list("'aa' 'bb' 'cc'").unwrap(), //#[allow_ci]
            ["'aa'", "'bb'", "'cc'"]
        );
        assert_eq!(
            parse_list("\"aa\" \"bb\" \"cc\"").unwrap(), //#[allow_ci]
            ["\"aa\"", "\"bb\"", "\"cc\""]
        );
        assert_eq!(
            parse_list("aa 'bb' \"cc\"").unwrap(), //#[allow_ci]
            ["aa", "'bb'", "\"cc\""]
        );

        // New-line-separated
        assert_eq!(parse_list("aa\nbb\ncc").unwrap(), ["aa", "bb", "cc"]); //#[allow_ci]

        // Tab-separated
        assert_eq!(parse_list("aa\tbb\tcc").unwrap(), ["aa", "bb", "cc"]); //#[allow_ci]

        // Carriage-return-separated
        assert_eq!(parse_list("aa\rbb\rcc").unwrap(), ["aa", "bb", "cc"]); //#[allow_ci]

        // Corner cases

        // Entry named "["
        assert_eq!(parse_list("\"[\"").unwrap(), ["\"[\""]); //#[allow_ci]
        assert_eq!(parse_list("'['").unwrap(), ["'['"]); //#[allow_ci]

        // Entry named "]"
        assert_eq!(parse_list("\"]\"").unwrap(), ["\"]\""]); //#[allow_ci]
        assert_eq!(parse_list("']'").unwrap(), ["']'"]); //#[allow_ci]
        assert_eq!(parse_list("]").unwrap(), ["]"]); //#[allow_ci]

        // Entry named "\'"
        assert_eq!(parse_list("\"'\"").unwrap(), ["\"'\""]); //#[allow_ci]
        assert_eq!(parse_list("[']").unwrap(), ["'"]); //#[allow_ci]

        // Entry named "\""
        assert_eq!(parse_list("'\"'").unwrap(), ["'\"'"]); //#[allow_ci]
        assert_eq!(parse_list("[\"]").unwrap(), ["\""]); //#[allow_ci]

        // Entry named ","
        assert_eq!(parse_list("','").unwrap(), ["','"]); //#[allow_ci]
        assert_eq!(parse_list("\",\"").unwrap(), ["\",\""]); //#[allow_ci]

        // Entry named " "
        assert_eq!(parse_list("' '").unwrap(), ["' '"]); //#[allow_ci]
        assert_eq!(parse_list("\" \"").unwrap(), ["\" \""]); //#[allow_ci]

        // Empty lists
        assert_eq!(parse_list("[]").unwrap(), [] as [&str; 0]); //#[allow_ci]
        assert_eq!(parse_list("").unwrap(), [] as [&str; 0]); //#[allow_ci]
        assert_eq!(parse_list("\"\"").unwrap(), [] as [&str; 0]); //#[allow_ci]
        assert_eq!(parse_list("'', ''").unwrap(), [] as [&str; 0]); //#[allow_ci]
        assert_eq!(parse_list(" \n \t \r").unwrap(), [] as [&str; 0]); //#[allow_ci]
        assert_eq!(parse_list("[ \n \t \r]").unwrap(), [] as [&str; 0]); //#[allow_ci]

        // Uncommon cases
        assert_eq!(parse_list("[a,").unwrap(), ["[a"]); //#[allow_ci]
        assert_eq!(parse_list("[a b").unwrap(), ["[a", "b"]); //#[allow_ci]
        assert_eq!(parse_list("'[  ]").unwrap(), ["'[", "]"]); //#[allow_ci]

        // Error cases
        assert!(parse_list(",,").is_err());
    }
}
