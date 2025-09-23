// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors
use glob;

use thiserror::Error;
use tss_esapi::{
    constants::response_code::Tss2ResponseCodeKind, Error::Tss2Error,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("HttpServer error: {0}")]
    ActixWeb(#[from] actix_web::Error),
    #[error("Failed to build Agent Identity")]
    AgentIdentityBuilder(
        #[from] crate::agent_identity::AgentIdentityBuilderError,
    ),
    #[error("TSS2 Error: {err:?}, kind: {kind:?}, {message}")]
    Tss2 {
        err: tss_esapi::Error,
        kind: Option<Tss2ResponseCodeKind>,
        message: String,
    },
    #[error("Keylime TPM error: {0}")]
    Tpm(#[from] crate::tpm::TpmError),
    #[error("Invalid request")]
    #[allow(unused)]
    InvalidRequest,
    #[error("Infallible: {0}")]
    Infallible(#[from] std::convert::Infallible),
    #[error("Conversion error: {0}")]
    Conversion(String),
    #[error("Configuration error")]
    Configuration(#[from] crate::config::KeylimeConfigError),
    #[error("Configuration builder error")]
    ConfigurationGenericError(String),
    #[error("Device ID error")]
    DeviceID(#[from] crate::device_id::DeviceIDError),
    #[error("Device ID builder error")]
    DeviceIDBuilder(#[from] crate::device_id::DeviceIDBuilderError),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("RegistrarClient error")]
    RegistrarClient(#[from] crate::registrar_client::RegistrarClientError),
    #[error("RegistrarClientBuilder error")]
    RegistrarClientBuilder(
        #[from] crate::registrar_client::RegistrarClientBuilderError,
    ),
    #[error("Serialization/deserialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Permission error")]
    Permission(#[from] crate::permissions::PermissionError),
    #[error("Glob error")]
    Glob(#[from] glob::GlobError),
    #[error("Glob pattern error")]
    GlobPattern(#[from] glob::PatternError),
    #[error("Invalid IP: {0}")]
    InvalidIP(#[from] std::net::AddrParseError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse IP")]
    IpParser(#[from] crate::ip_parser::IpParsingError),
    #[error("Failed to parse hostname")]
    HostnameParser(#[from] crate::hostname_parser::HostnameParsingError),
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
    Crypto(#[from] crate::crypto::CryptoError),
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
    Algorithm(#[from] crate::algorithms::AlgorithmError),
    #[error("Error converting number: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error("C string is not NUL-terminated: {0}")]
    Nul(#[from] std::ffi::NulError),
    #[error("Error persisting file path: {0}")]
    PathPersist(#[from] tempfile::PathPersistError),
    #[error("Error persisting file: {0}")]
    Persist(#[from] tempfile::PersistError),
    #[error("Error joining threads: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Error sending internal message: {0}")]
    Sender(String),
    #[error("Error receiving internal message: {0}")]
    Receiver(String),
    #[error("List parser error")]
    ListParser(#[from] crate::list_parser::ListParsingError),
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("Certificate generation error")]
    CertificateGeneration(
        #[from] crate::crypto::x509::CertificateBuilderError,
    ),
    #[error("UEFI Log parser error: {0}")]
    UEFILog(String),
    #[error("{0}")]
    Other(String),
}

impl actix_web::ResponseError for Error {}

impl Error {
    pub fn exe_code(&self) -> Result<Option<i32>> {
        match self {
            Error::Execution(code, _) => Ok(code.to_owned()),
            other => Err(Error::Other(format!(
                "cannot get execution status code for Error type {other}"
            ))),
        }
    }

    pub fn stderr(&self) -> Result<String> {
        match self {
            Error::Execution(_, stderr) => Ok(stderr.to_owned()),
            other => Err(Error::Other(format!(
                "cannot get stderr for Error type {other}"
            ))),
        }
    }
}

impl TryFrom<std::process::Output> for Error {
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
        let message = format!("{err}");

        Error::Tss2 { err, kind, message }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {

    use super::*;
    use crate::tpm::TpmError;

    #[test]
    fn test_error_display() {
        let err = Error::Tpm(TpmError::PublicKeyCertificateMismatch(
            "TestKey".to_string(),
        ));
        assert_eq!(
            format!("{err}"),
            "Keylime TPM error: TestKey key does not match with certificate. Check template in configuration."
        );
    }

    #[test]
    fn test_error_conversion() {
        let err = Error::Conversion("Test conversion error".to_string());
        assert_eq!(
            format!("{err}"),
            "Conversion error: Test conversion error"
        );
    }

    #[test]
    fn test_error_execution() {
        let err = Error::Execution(Some(1), "Test error".to_string());
        assert_eq!(format!("{err}"), "Execution error: Some(1), Test error");
    }

    #[test]
    fn test_error_script() {
        let err = Error::Script(
            "TestScript".to_string(),
            Some(1),
            "Test error".to_string(),
        );
        assert_eq!(
            format!("{err}"),
            "Error executing script TestScript: Some(1), Test error"
        );
    }

    #[test]
    fn test_error_from_output() {
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: vec![],
            stderr: b"Test error".to_vec(),
        };
        let err = Error::try_from(output).unwrap(); //#[allow_ci]
        assert_eq!(format!("{err}"), "Execution error: None, Test error");
    }

    #[test]
    fn test_tss2_error_conversion() {
        use tss_esapi::constants::response_code::Tss2ResponseCode;
        use tss_esapi::Error;
        let err = Error::Tss2Error(Tss2ResponseCode::Success);
        assert_eq!(format!("{err}"), "success");
    }

    #[test]
    fn test_from_tss_esapi_tss2error() {
        use tss_esapi::constants::response_code::Tss2ResponseCode;
        use tss_esapi::tss2_esys::TSS2_RC;
        use tss_esapi::Error as TssEsapiError;

        let raw_rc = TSS2_RC::from(0x0000000Bu32);
        let tss2_esys_error = Tss2ResponseCode::from(raw_rc);

        let original_tss_error = TssEsapiError::Tss2Error(tss2_esys_error);

        let converted_error: Error = original_tss_error.into();

        if let Error::Tss2 { err, kind, message } = converted_error {
            assert_eq!(format!("{err:?}"), format!("{original_tss_error:?}"));
            assert_eq!(message, format!("{original_tss_error}"));
            assert!(kind.is_some());
        } else {
            panic!("Expected Tss2Error, got {converted_error:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_output_success() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::Output;
        let successful_output = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"This is standard output".to_vec(),
            stderr: b"".to_vec(),
        };
        let result: std::result::Result<Error, Error> =
            Error::try_from(successful_output);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_tss_esapi_other_error() {
        use tss_esapi::WrapperErrorKind;
        let original_tss_error =
            tss_esapi::Error::WrapperError(WrapperErrorKind::WrongParamSize);
        let converted_error: Error = original_tss_error.into();
        if let Error::Tss2 { err, kind, message } = converted_error {
            assert_eq!(format!("{err:?}"), format!("{original_tss_error:?}"));
            assert_eq!(kind, None);
            assert_eq!(message, format!("{original_tss_error}"));
        }
    }

    #[test]
    fn test_exe_code_other_error() {
        let non_execution_error = Error::InvalidRequest;
        let result = non_execution_error.exe_code();
        assert!(result.is_err());

        let unwrapped_err = result.unwrap_err();
        if let Error::Other(msg) = unwrapped_err {
            let expected_msg = format!(
                "cannot get execution status code for Error type {non_execution_error}"
            );
            assert_eq!(msg, expected_msg);
        }
    }

    #[test]
    fn test_stderr_other_error() {
        let non_execution_error = Error::InvalidRequest;
        let result = non_execution_error.stderr();
        assert!(result.is_err());
        let unwrapped_err = result.unwrap_err();
        if let Error::Other(msg) = unwrapped_err {
            let expected_msg = format!(
                "cannot get stderr for Error type {non_execution_error}"
            );
            assert_eq!(msg, expected_msg);
        }
    }

    #[test]
    fn test_display_permission() {
        let err: Error =
            crate::permissions::PermissionError::NotRoot("file".to_string())
                .into();
        assert_eq!(format!("{err}"), "Permission error");
    }

    #[test]
    fn test_display_secure_mount() {
        let err = Error::SecureMount("mount failed".to_string());
        assert_eq!(format!("{err}"), "Secure Mount error: mount failed)");
    }

    #[test]
    fn test_display_tpm_in_use() {
        let err = Error::TpmInUse;
        assert_eq!(format!("{err}"), "TPM in use");
    }

    #[test]
    fn test_display_sender() {
        let err = Error::Sender("channel closed".to_string());
        assert_eq!(
            format!("{err}"),
            "Error sending internal message: channel closed"
        );
    }

    #[test]
    fn test_display_receiver() {
        let err = Error::Receiver("channel disconnected".to_string());
        assert_eq!(
            format!("{err}"),
            "Error receiving internal message: channel disconnected"
        );
    }

    #[test]
    fn test_from_io_error() {
        use std::io::{Error as IoError, ErrorKind as IoErrorKind};
        let io_err = IoError::new(IoErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        if let Error::Io(e) = err {
            assert_eq!(e.kind(), IoErrorKind::NotFound);
            assert_eq!(format!("{e}"), "file not found");
        } else {
            panic!("Expected Error::Io, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_addr_parse_error() {
        let parse_err = "invalid-ip".parse::<std::net::IpAddr>().unwrap_err();
        let err: Error = parse_err.into();
        if let Error::InvalidIP(e) = err {
            assert_eq!(format!("{e}"), "invalid IP address syntax");
        } else {
            panic!("Expected Error::InvalidIP, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_parse_int_error() {
        let parse_err = "".parse::<i32>().unwrap_err();
        let err: Error = parse_err.into();
        if let Error::NumParse(e) = err {
            assert_eq!(
                format!("{e}"),
                "cannot parse integer from empty string"
            );
        } else {
            panic!("Expected Error::NumParse, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_parse_bool_error() {
        let parse_err = "truee".parse::<bool>().unwrap_err();
        let err: Error = parse_err.into();
        if let Error::ParseBool(e) = err {
            assert_eq!(
                format!("{e}"),
                "provided string was not `true` or `false`"
            );
        } else {
            panic!("Expected Error::ParseBool, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_hex_error() {
        let hex_err = hex::decode("0Z").unwrap_err();
        let err: Error = hex_err.into();
        if let Error::FromHex(e) = err {
            let msg = format!("{e}");
            assert_eq!(msg, "Invalid character 'Z' at position 1");
            assert!(msg.contains("Invalid character"));
        } else {
            panic!("Expected Error::FromHex, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_nul_error() {
        use std::ffi::CString;
        let nul_err = CString::new("a\0b").unwrap_err();
        let err: Error = nul_err.into();
        if let Error::Nul(e) = err {
            let msg = format!("{e}");
            assert!(msg
                .contains("nul byte found in provided data at position: 1"));
        } else {
            panic!("Expected Error::Nul, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_zip_error() {
        use zip::result::ZipError as ZipErrorSource;
        let zip_err = ZipErrorSource::InvalidArchive("Invalid zip data");
        let err: Error = zip_err.into();
        if let Error::Zip(e) = err {
            if let ZipErrorSource::InvalidArchive(msg) = e {
                assert_eq!(msg, "Invalid zip data");
            } else {
                panic!("Expected ZipError::InvalidArchive, got {e:?}"); //#[allow_ci]
            }
        } else {
            panic!("Expected Error::Zip, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_try_from_output_invalid_utf8() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;
        use std::process::Output;
        let invalid_output = Output {
            status: ExitStatus::from_raw(1),
            stdout: vec![],
            stderr: vec![0xff, 0xff, 0xff],
        };

        let result: std::result::Result<Error, Error> =
            Error::try_from(invalid_output);
        assert!(result.is_err());

        let err = result.unwrap_err();
        if let Error::Utf8(e) = err {
            let msg = format!("{e}");
            assert!(msg.contains("invalid utf-8 sequence"));
        } else {
            panic!("Invalid stderr: {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_stderr_execution_error() -> Result<()> {
        let execution_err =
            Error::Execution(Some(1), "Process stderr output".to_string());
        let stderr_output = execution_err.stderr()?;
        assert_eq!(stderr_output, "Process stderr output");

        let execution_err_none =
            Error::Execution(None, "Process stderr output 2".to_string());
        let stderr_output_none = execution_err_none.stderr()?;
        assert_eq!(stderr_output_none, "Process stderr output 2");

        Ok(())
    }

    #[test]
    fn test_display_configuration_error() {
        use crate::config::KeylimeConfigError;
        let cfg_err =
            KeylimeConfigError::Generic("Generic config test".to_string());
        let err = Error::Configuration(cfg_err);
        assert_eq!(format!("{err}"), "Configuration error");
    }

    #[test]
    fn test_display_ip_parser_error() {
        use crate::ip_parser::IpParsingError;
        let ip_err = IpParsingError::InvalidInput("Invalid".to_string());
        let err = Error::IpParser(ip_err);
        assert_eq!(format!("{err}"), "Failed to parse IP");
    }

    #[test]
    fn test_display_hostname_parser_error() {
        use crate::hostname_parser::HostnameParsingError;
        let hn_err =
            HostnameParsingError::InvalidInput(("-Invalid").to_string());
        let err = Error::HostnameParser(hn_err);
        assert_eq!(format!("{err}"), "Failed to parse hostname");
    }

    #[test]
    fn test_display_crypto_error() {
        use crate::crypto::CryptoError;
        let crypto_source = CryptoError::Base64DecodeError(
            base64::DecodeError::InvalidByte(0, 0),
        );
        let err = Error::Crypto(crypto_source);
        // El Display envuelve
        assert_eq!(format!("{err}"), "Crypto error: failed to decode base64");
    }

    #[test]
    fn test_from_configuration_error() {
        use crate::config;
        let cfg_err = config::KeylimeConfigError::Generic(
            "Another config test".to_string(),
        );
        let err: Error = cfg_err.into();
        if let Error::Configuration(e) = err {
            assert_eq!(
                format!("{e}"),
                "Configuration error: Another config test"
            );
        } else {
            panic!("Expected Error::Configuration, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_from_ip_parser_error() {
        use crate::ip_parser::IpParsingError;
        let ip_err = IpParsingError::InvalidInput("Invalid".to_string());
        let err: Error = ip_err.into();
        if let Error::IpParser(e) = err {
            assert_eq!(format!("{e}"), "Invalid input Invalid");
        } else {
            panic!("Expected Error::IpParser, got {err:?}"); //#[allow_ci]
        }
    }

    #[test]
    fn test_display_other_error() {
        let err = Error::Other("Some other error".to_string());
        assert_eq!(format!("{err}"), "Some other error");
    }

    #[test]
    fn test_display_tpm_error() {
        let err = Error::Tpm(TpmError::PublicKeyCertificateMismatch(
            "TestKey".to_string(),
        ));
        assert_eq!(
            format!("{err}"),
            "Keylime TPM error: TestKey key does not match with certificate. Check template in configuration."
        );
    }

    #[test]
    fn test_actix_web_error() {
        let actix_err =
            actix_web::Error::from(std::io::Error::other("Actix web error"));
        let err: Error = actix_err.into();
        assert_eq!(format!("{err}"), "HttpServer error: Actix web error");
    }

    #[test]
    fn test_tss2_error() {
        use tss_esapi::constants::response_code::Tss2ResponseCode;
        let tss2_err = Tss2Error(Tss2ResponseCode::Success);
        let err: Error = tss2_err.into();
        assert_eq!(
            format!("{err}"),
            "TSS2 Error: Tss2Error(Success), kind: Some(Success), success"
        );
    }

    #[test]
    fn test_invalid_request_error() {
        let err = Error::InvalidRequest;
        assert_eq!(format!("{err}"), "Invalid request");
    }

    #[test]
    fn test_device_id_builder_error() {
        use crate::device_id::DeviceIDBuilderError;
        let device_id_err = DeviceIDBuilderError::IAKHandleNotSet;
        let err: Error = device_id_err.into();
        assert_eq!(format!("{err}"), "Device ID builder error");
    }

    #[test]
    fn test_registrar_client_error() {
        use crate::registrar_client::RegistrarClientError;
        let registrar_err = RegistrarClientError::Registration {
            addr: "1.2.3.4".to_string(),
            code: 404,
        };
        let err: Error = registrar_err.into();
        assert_eq!(format!("{err}"), "RegistrarClient error");
    }

    #[test]
    fn test_invalid_ip_error() {
        let parse_err =
            "111.222.333.444".parse::<std::net::IpAddr>().unwrap_err();
        let err: Error = parse_err.into();
        if let Error::InvalidIP(e) = err {
            assert_eq!(format!("{e}"), "invalid IP address syntax");
        }
    }

    #[test]
    fn test_display_uuid_error() {
        let uuid_source_err =
            uuid::Uuid::parse_str("not-a-uuid").unwrap_err();
        let err = Error::Uuid(uuid_source_err);
        let expected_prefix = "UUID error";
        let formatted_err = format!("{err}");
        assert!(
            formatted_err.starts_with(expected_prefix),
            "Expected error to start with '{expected_prefix}', but got: {formatted_err}"
        );
    }

    #[test]
    fn test_from_uuid_error() {
        let uuid_source_err =
            uuid::Uuid::parse_str("Z-invalid-uuid").unwrap_err();
        let err: Error = uuid_source_err.into();

        if let Error::Uuid(e) = err {
            let inner_msg = format!("{e}");
            assert!(inner_msg.contains("invalid character"));
        } else {
            panic!("Expected Error::Uuid, got {err:?}"); //#[allow_ci]
        }
    }

    #[tokio::test]
    async fn test_from_join_error() {
        let handle = tokio::task::spawn_blocking(|| {
            panic!("Simulated task panic for JoinError test"); //#[allow_ci]
        });
        let join_error = handle.await.unwrap_err();
        let converted_error: Error = join_error.into();

        if let Error::Join(e) = converted_error {
            let msg = format!("{e}");
            assert!(msg.contains("panicked"),);
            assert!(msg.contains("Simulated task panic"),);
            assert!(e.is_panic());
        } else {
            panic!("Expected Error::Join, got {converted_error:?}"); //#[allow_ci]
        }
    }
}
