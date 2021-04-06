// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use thiserror::Error;
use tss_esapi::{
    constants::response_code::Tss2ResponseCodeKind,
    Error::{Tss2Error, WrapperError},
};

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("HttpServer error: {0}")]
    ActixWeb(actix_web::Error),
    #[error("TPM Error: {err:?}, kind: {kind:?}, {message}")]
    Tpm {
        err: tss_esapi::Error,
        kind: Option<Tss2ResponseCodeKind>,
        message: String,
    },
    #[error("Invalid request")]
    #[allow(unused)]
    InvalidRequest,
    #[error("Configuration loading error: {0}")]
    Ini(ini::ini::Error),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Reqwest error: {0}")]
    Reqwest(reqwest::Error),
    #[error("Registrar error: received {code} from {addr}")]
    Registrar { addr: String, code: u16 },
    #[error("Serialization/deserialization error: {0}")]
    Serde(serde_json::Error),
    #[error("Permission error")]
    Permission,
    #[error("IO error: {0}")]
    Io(std::io::Error),
    #[error("Text decoding error: {0}")]
    Utf8(std::string::FromUtf8Error),
    #[error("Secure Mount error: {0})")]
    #[allow(unused)]
    SecureMount(String),
    #[error("TPM in use")]
    TpmInUse,
    #[error("UUID error")]
    Uuid(uuid::Error),
    #[error("Execution error: {0:?}, {1}")]
    Execution(Option<i32>, String),
    #[error("Error executing script {0}: {1:?}, {2}")]
    Script(String, Option<i32>, String),
    #[error("Number parsing error: {0}")]
    NumParse(std::num::ParseIntError),
    #[error("Crypto error: {0}")]
    Crypto(openssl::error::ErrorStack),
    #[error("ZMQ error: {0}")]
    Zmq(zmq::Error),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub(crate) fn http_code(&self) -> Result<u16> {
        match self {
            Error::Registrar { addr, code } => Ok(*code),
            other => Err(Error::Other(format!(
                "cannot get http code for Error type {}",
                other
            ))),
        }
    }

    pub(crate) fn exe_code(&self) -> Result<Option<i32>> {
        match self {
            Error::Execution(code, _) => Ok(code.to_owned()),
            other => Err(Error::Other(format!(
                "cannot get execution status code for Error type {}",
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
        let kind = if let Tss2Error(tss2_rc) = err {
            tss2_rc.kind()
        } else {
            None
        };
        let message = format!("{}", err);

        Error::Tpm { err, kind, message }
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
        Error::Io(err)
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
        Error::Crypto(err)
    }
}

impl From<zmq::Error> for Error {
    fn from(err: zmq::Error) -> Self {
        Error::ZMQ(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Reqwest(err)
    }
}

impl From<uuid::Error> for Error {
    fn from(err: uuid::Error) -> Self {
        Error::Uuid(err)
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
