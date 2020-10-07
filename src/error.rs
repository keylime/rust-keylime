use std::fmt;

#[derive(Debug)]
pub(crate) enum Error {
    TPM(tss_esapi::Error),
    Hyper(hyper::Error),
    InvalidRequest,
    Ini(ini::ini::Error),
    Configuration(String),
    Serde(serde_json::Error),
    Permission,
    IO(std::io::Error),
    Utf8(std::string::FromUtf8Error),
    SecureMount,
    TPMInUse,
    Execution(Option<i32>, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO
        write!(f, "todo: {:?}", self)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        "Keylime Error"
    }
}

impl From<tss_esapi::Error> for Error {
    fn from(err: tss_esapi::Error) -> Self {
        Error::TPM(err)
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Error::Hyper(err)
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

pub(crate) type Result<T> = std::result::Result<T, Error>;
