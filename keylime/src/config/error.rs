use crate::{
    hostname_parser::HostnameParsingError, ip_parser::IpParsingError,
    list_parser::ListParsingError,
};
use config::ConfigError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeylimeConfigError {
    // Error from config crate
    #[error("Error from the config crate")]
    Config(#[from] ConfigError),

    // Generic configuration error
    #[error("Configuration error: {0}")]
    Generic(String),

    // Glob error
    #[error("Glob pattern error")]
    GlobPattern(#[from] glob::PatternError),

    // Host name parsing error
    #[error("Host name parsing error")]
    HostnameParsing(#[from] HostnameParsingError),

    // Incompatible options error
    #[error("Incompatible configuration options '{option_a}' set as '{value_a}', but '{option_b}' is set as '{value_b}'")]
    IncompatibleOptions {
        option_a: String,
        value_a: String,
        option_b: String,
        value_b: String,
    },

    // Infallible
    #[error("Infallible")]
    Infallible(#[from] std::convert::Infallible),

    // IP parsing error
    #[error("IP parsing error")]
    IpParsing(#[from] IpParsingError),

    // Unsupported type in configuration
    #[error(
        "Unsupported type conversion from serde_json::Value to config::Value"
    )]
    JsonConversion,

    // List parsing error
    #[error("List parsing error")]
    ListParsing(#[from] ListParsingError),

    // Missing directory set in keylime_dir configuration option
    #[error(
        "Missing directory {path} set in 'revocation_actions_dir' configuration option"
    )]
    MissingActionsDir {
        path: String,
        source: std::io::Error,
    },

    // Missing configuration file set in KEYLIME_AGENT_CONFIG
    #[error("Missing file {file} set in 'KEYLIME_AGENT_CONFIG' environment variable")]
    MissingEnvConfigFile { file: String },

    // Missing directory set in keylime_dir configuration option
    #[error(
        "Missing directory {path} set in 'keylime_dir' configuration option"
    )]
    MissingKeylimeDir {
        path: String,
        source: std::io::Error,
    },

    #[error("Required option {0} not set in configuration")]
    RequiredOption(String),

    // Error from serde crate
    #[error("Serde error")]
    Serde(#[from] serde_json::Error),

    // Configuration singleton already initialized
    #[error("Configuration singleton already initialized")]
    SingletonAlreadyInitialized,
}
