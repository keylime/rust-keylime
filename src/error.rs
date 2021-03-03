// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("HttpServer error: {0}")]
    ActixWeb(actix_web::Error),
    #[error("TPM Error: {0}")]
    TPM(tss_esapi::Error),
    #[error("Invalid request")]
    #[allow(unused)]
    InvalidRequest,
    #[error("Configuration loading error: {0}")]
    Ini(ini::ini::Error),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Serialization/deserialization error: {0}")]
    Serde(serde_json::Error),
    #[error("Permission error")]
    Permission,
    #[error("IO error: {0}")]
    IO(std::io::Error),
    #[error("Text decoding error: {0}")]
    Utf8(std::string::FromUtf8Error),
    #[error("Secure Mount error")]
    #[allow(unused)]
    SecureMount,
    #[error("TPM in use")]
    TPMInUse,
    #[error("Execution error: {0:?}, {1}")]
    Execution(Option<i32>, String),
    #[error("Error executing script {0}: {1:?}, {2}")]
    Script(String, Option<i32>, String),
    #[error("Number parsing error: {0}")]
    NumParse(std::num::ParseIntError),
    #[error("Crypto error: {0}")]
    OpenSSL(openssl::error::ErrorStack),
    #[error("ZMQ error: {0}")]
    ZMQ(zmq::Error),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub(crate) fn code(&self) -> Result<Option<i32>> {
        match self {
            Error::Execution(code, _) => Ok(code.to_owned()),
            other => Err(Error::Other(format!(
                "cannot get code for Error type {}",
                other
            ))),
        }
    }

    pub(crate) fn stderr(&self) -> Result<String> {
        match self {
            Error::Execution(_, stderr) => Ok(stderr.to_owned()),
            other => Err(Error::Other(format!(
                "cannot get stderr for Error type {}",
                other
            ))),
        }
    }
}

impl std::convert::TryFrom<std::process::Output> for Error {
    type Error = Error;
    fn try_from(output: std::process::Output) -> Result<Self> {
        let code = output.status.code();
        let stderr = String::from_utf8(output.stderr)?;
        Ok(Error::Execution(code, stderr))
    }
}

impl From<tss_esapi::Error> for Error {
    fn from(err: tss_esapi::Error) -> Self {
        Error::TPM(err)
    }
}

impl From<actix_web::Error> for Error {
    fn from(err: actix_web::Error) -> Self {
        Error::ActixWeb(err)
    }
}

impl From<ini::ini::Error> for Error {
    fn from(err: ini::ini::Error) -> Self {
        Error::Ini(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serde(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Utf8(err)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::NumParse(err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Error::OpenSSL(err)
    }
}

impl From<zmq::Error> for Error {
    fn from(err: zmq::Error) -> Self {
        Error::ZMQ(err)
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
