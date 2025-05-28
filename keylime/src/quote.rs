use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Integ {
    pub nonce: String,
    pub mask: String,
    pub partial: String,
    pub ima_ml_entry: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeylimeQuote {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_measurement_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_measurement_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_measurement_list_entry: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keylime_quote_serialization() {
        let quote = KeylimeQuote {
            quote: "example_quote".to_string(),
            hash_alg: "SHA256".to_string(),
            enc_alg: "AES".to_string(),
            sign_alg: "RSASSA-PSS".to_string(),
            pubkey: Some("example_pubkey".to_string()),
            ima_measurement_list: Some("example_ima_ml".to_string()),
            mb_measurement_list: None,
            ima_measurement_list_entry: Some(12345),
        };

        let serialized = serde_json::to_string(&quote).unwrap(); //#[allow_ci]
        assert!(serialized.contains("example_quote"));
        assert!(serialized.contains("SHA256"));
        assert!(serialized.contains("AES"));
        assert!(serialized.contains("RSASSA-PSS"));
        assert!(serialized.contains("example_pubkey"));
        assert!(serialized.contains("example_ima_ml"));
        assert!(serialized.contains("12345"));

        let pretty_serialized = serde_json::to_string_pretty(&quote).unwrap(); //#[allow_ci]
        assert_eq!(
            pretty_serialized,
            r#"{
  "quote": "example_quote",
  "hash_alg": "SHA256",
  "enc_alg": "AES",
  "sign_alg": "RSASSA-PSS",
  "pubkey": "example_pubkey",
  "ima_measurement_list": "example_ima_ml",
  "ima_measurement_list_entry": 12345
}"#
        );
    }
}
