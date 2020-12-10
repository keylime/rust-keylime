use std::fmt;

#[derive(Debug)]
pub(crate) enum Error {
    ActixWeb(actix_web::Error),
    TPM(tss_esapi::Error),
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
    NumParse(std::num::ParseIntError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Ini(err) => {
                write!(f, "Error loading configuration: {}", err)
            }
            Error::TPM(err) => write!(f, "TPM Error encountered: {}", err),
            Error::ActixWeb(err) => write!(f, "HttpServer({})", err),
            anything => write!(f, "Another error: {:?}", anything),
        }
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

pub(crate) type Result<T> = std::result::Result<T, Error>;
