use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// Meta section for the HashList V1
#[derive(Serialize, Deserialize, Debug)]
struct MetaV1 {
    version: String,
    generator: String,
    timestamp: String,
}

/// KeyLime HashList version 1 implementation
#[derive(Serialize, Deserialize, Debug)]
struct HashListV1 {
    meta: MetaV1,
    release: String,
    hashes: HashMap<String, Vec<HashMap<String, String>>>,
}

/// Shortcut for deserializing a String to a HashList
fn deserialize(data: String) -> Result<HashListV1, serde_json::Error> {
    serde_json::from_str(&data)
}

/// Shortcut for serializing a HashList to a String
fn serialize(hash_list: HashListV1) -> Result<String, serde_json::Error> {
    serde_json::to_string(&hash_list)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const data: &str = r#"{
        "meta": {
                "version": "1.2.3",
                "generator": "test",
                "timestamp": "2020-10-20"
        },
        "release": "10000",
        "hashes": {
            "/filesystem/path": [
                {"sha256": "HASH"}
            ]
        }
    }"#;

    // Ensure deserializing works as expected
    #[test]
    fn test_deserialze() {
        let deserialized = deserialize(String::from(data)).unwrap();
        assert_eq!(deserialized.meta.version, "1.2.3");
        assert_eq!(deserialized.meta.generator, "test");
        assert_eq!(deserialized.meta.timestamp, "2020-10-20");
        assert_eq!(deserialized.release, "10000");
        assert_eq!(deserialized.hashes["/filesystem/path"].len(), 1);
        assert_eq!(deserialized.hashes["/filesystem/path"][0]["sha256"], "HASH");
    }

    // Ensure serializing works as expected
    #[test]
    fn test_serialze() {
        let deserialized = deserialize(String::from(data)).unwrap();
        let serialized = serialize(deserialized);
    }
}