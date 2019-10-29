use super::*;
use std::error::Error;
use std::fmt;

/*
 * Custom Error type for tpm execution error. It contains both error from the
 * TPM command execution result or error cause by rust function. Potential
 * rust error are map to this error by implemented From<> trait.
 */
#[derive(Debug)]
pub enum KeylimeTpmError {
    TpmRustError { details: String },
    TpmError { code: i32, details: String },
}

impl KeylimeTpmError {
    pub fn new_tpm_error(err_code: i32, err_msg: &str) -> KeylimeTpmError {
        KeylimeTpmError::TpmError {
            code: err_code,
            details: err_msg.to_string(),
        }
    }

    pub fn new_tpm_rust_error(err_msg: &str) -> KeylimeTpmError {
        KeylimeTpmError::TpmRustError {
            details: err_msg.to_string(),
        }
    }
}

impl Error for KeylimeTpmError {
    fn description(&self) -> &str {
        match &self {
            KeylimeTpmError::TpmError {
                ref details,
                ref code,
            } => details,
            KeylimeTpmError::TpmRustError { ref details } => details,
        }
    }
}

impl fmt::Display for KeylimeTpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeylimeTpmError::TpmError {
                ref code,
                ref details,
            } => write!(
                f,
                "Execute TPM command failed with Error Code: [{}] and 
                Error Message [{}].",
                code, details,
            ),
            KeylimeTpmError::TpmRustError { ref details } => write!(
                f,
                "Error occur in TPM rust interface with message [{}].",
                details,
            ),
        }
    }
}

impl From<std::io::Error> for KeylimeTpmError {
    fn from(e: std::io::Error) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<std::time::SystemTimeError> for KeylimeTpmError {
    fn from(e: std::time::SystemTimeError) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<std::string::FromUtf8Error> for KeylimeTpmError {
    fn from(e: std::string::FromUtf8Error) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<serde_json::error::Error> for KeylimeTpmError {
    fn from(e: serde_json::error::Error) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}

impl From<std::num::ParseIntError> for KeylimeTpmError {
    fn from(e: std::num::ParseIntError) -> KeylimeTpmError {
        KeylimeTpmError::new_tpm_rust_error(e.description())
    }
}
