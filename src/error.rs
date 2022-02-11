// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::algorithms;
use thiserror::Error;
use tss_esapi::{
    constants::response_code::Tss2ResponseCodeKind, Error::Tss2Error,
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
    Ini(#[from] ini::Error),
    #[error("Infallible: {0}")]
    Infallible(#[from] std::convert::Infallible),
    #[error("Compress tools error: {0}")]
    CompressTools(#[from] compress_tools::Error),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Registrar error: received {code} from {addr}")]
    Registrar { addr: String, code: u16 },
    #[error("Serialization/deserialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Permission error")]
    Permission,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Text decoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Secure Mount error: {0})")]
    #[allow(unused)]
    SecureMount(String),
    #[error("TPM in use")]
    TpmInUse,
    #[error("UUID error")]
    Uuid(#[from] uuid::Error),
    #[error("Execution error: {0:?}, {1}")]
    Execution(Option<i32>, String),
    #[error("Error executing script {0}: {1:?}, {2}")]
    Script(String, Option<i32>, String),
    #[error("Number parsing error: {0}")]
    NumParse(#[from] std::num::ParseIntError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[cfg(feature = "with-zmq")]
    #[error("ZMQ error: {0}")]
    Zmq(#[from] zmq::Error),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("parse bool error: {0}")]
    ParseBool(#[from] std::str::ParseBoolError),
    #[error("from hex error: {0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("Keylime algorithm error: {0}")]
    Algorithm(#[from] algorithms::AlgorithmError),
    #[error("Error converting number: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error("C string is not NUL-terminated: {0}")]
    Nul(#[from] std::ffi::NulError),
    #[error("Error persisting file path: {0}")]
    PathPersist(#[from] tempfile::PathPersistError),
    #[error("Error persisting file: {0}")]
    Persist(#[from] tempfile::PersistError),
    #[error("{0}")]
    Other(String),
}

impl actix_web::ResponseError for Error {}

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

pub(crate) type Result<T> = std::result::Result<T, Error>;
