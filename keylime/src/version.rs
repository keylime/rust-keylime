use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeVersion {
    pub supported_version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeRegistrarVersion {
    pub current_version: String,
    pub supported_versions: Vec<String>,
}

pub trait GetErrorInput {
    fn input(&self) -> String;
}

#[derive(Error, Debug)]
pub enum VersionParsingError {
    /// The version input was malformed
    #[error("input '{input}' malformed as a version")]
    MalformedVersion { input: String },

    /// The parts of the version were not numbers
    #[error("parts of version '{input}' were not numbers")]
    ParseError {
        input: String,
        source: std::num::ParseIntError,
    },
}

impl GetErrorInput for VersionParsingError {
    fn input(&self) -> String {
        match self {
            VersionParsingError::MalformedVersion { input } => input.into(),
            VersionParsingError::ParseError { input, source: _ } => {
                input.into()
            }
        }
    }
}

// Implement the trait for all the references
impl<T: GetErrorInput> GetErrorInput for &T
where
    T: GetErrorInput,
{
    fn input(&self) -> String {
        (**self).input()
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize,
)]
pub struct Version {
    major: u32,
    minor: u32,
}

impl Version {
    /// Create a new Version with the given major and minor version numbers.
    pub const fn new(major: u32, minor: u32) -> Self {
        Version { major, minor }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for Version {
    type Err = VersionParsingError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut parts = input.split('.');
        match (parts.next(), parts.next()) {
            (Some(major), Some(minor)) => Ok(Version {
                major: major.parse().map_err(|e| {
                    VersionParsingError::ParseError {
                        input: input.to_string(),
                        source: e,
                    }
                })?,
                minor: minor.parse().map_err(|e| {
                    VersionParsingError::ParseError {
                        input: input.to_string(),
                        source: e,
                    }
                })?,
            }),
            _ => Err(VersionParsingError::MalformedVersion {
                input: input.to_string(),
            }),
        }
    }
}

impl TryFrom<&str> for Version {
    type Error = VersionParsingError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Version::from_str(input)
    }
}

impl TryFrom<String> for Version {
    type Error = VersionParsingError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        Version::from_str(input.as_str())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_str() {
        let v = Version::from_str("1.2").unwrap(); //#[allow_ci]
        assert_eq!(v, Version { major: 1, minor: 2 });
        let v2: Version = "3.4".try_into().unwrap(); //#[allow_ci]
        assert_eq!(v2, Version { major: 3, minor: 4 });
        let v3: Version = "5.6".to_string().try_into().unwrap(); //#[allow_ci]
        assert_eq!(v3, Version { major: 5, minor: 6 });
    }

    #[test]
    fn test_display() {
        let s = format!("{}", Version { major: 1, minor: 2 });
        assert_eq!(s, "1.2".to_string());
    }

    #[test]
    fn test_ord() {
        let v11: Version = "1.1".try_into().unwrap(); //#[allow_ci]
        let v12: Version = "1.2".try_into().unwrap(); //#[allow_ci]
        let v21: Version = "2.1".try_into().unwrap(); //#[allow_ci]
        let v110: Version = "1.10".try_into().unwrap(); //#[allow_ci]
        assert!(v11 < v12);
        assert!(v12 < v110);
        assert!(v110 < v21);

        let mut v = vec![v12.clone(), v110.clone(), v11.clone()];
        v.sort();
        let expected = vec![v11, v12, v110];
        assert_eq!(v, expected);
    }

    #[test]
    fn test_invalid() {
        let result = Version::from_str("a.b");
        assert!(result.is_err());
        let result = Version::from_str("1.b");
        assert!(result.is_err());
        let result = Version::from_str("a.2");
        assert!(result.is_err());
        let result = Version::from_str("22");
        assert!(result.is_err());
        let result = Version::from_str(".12");
        assert!(result.is_err());
    }
}
