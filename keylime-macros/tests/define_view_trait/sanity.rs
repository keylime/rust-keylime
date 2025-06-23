use keylime_macros::define_view_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParsingError {
    #[error("Configuration value cannot be an empty string")]
    Empty,
}

fn parse_string_list(raw: &str) -> Result<Vec<String>, ParsingError> {
    if raw.is_empty() {
        return Err(ParsingError::Empty);
    }
    Ok(raw.split(',').map(|s| s.trim().to_string()).collect())
}

struct AppConfig {
    port: u16,
    host: String,
    api_versions: String,
}

#[define_view_trait(for_struct = "AppConfig")]
struct AppView {
    port: u16,
    host: String,
    #[transform(using = parse_string_list, error = ParsingError)]
    api_versions: Vec<String>,
}

fn main() {}

#[test]
fn test_sanity(obj: &impl AppViewTrait) {

    let config = AppConfig{
        port: 8080,
        host: "localhost",
        api_versions: "1.0, 2.0".to_string(),
    };

    assert_eq!(config.port(), &8080);
    assert_eq!(config.host(), "localhost");
    assert_eq!(config.api_versions(), vec!["1.0", "2.0"]);
}

#[test]
fn test_parser_error(obj: &impl AppViewTrait) {

    let config = AppConfig{
        port: 8080,
        host: "localhost",
        api_versions: "".to_string(), // This is empty to cause error
    };

    assert_eq!(config.port(), &8080);
    assert_eq!(config.host(), "localhost");

    let r = config.api_versions();
    assert!(r.is_err());
}
