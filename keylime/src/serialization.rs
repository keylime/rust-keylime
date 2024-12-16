use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct WrappedBase64Encoded(
    #[serde(deserialize_with = "deserialize_as_base64")] Vec<u8>,
);

pub fn is_empty(buf: &[u8]) -> bool {
    buf.is_empty()
}

pub fn serialize_as_base64<S>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&general_purpose::STANDARD.encode(bytes))
}

pub fn deserialize_as_base64<'de, D>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        general_purpose::STANDARD
            .decode(string)
            .map_err(serde::de::Error::custom)
    })
}

pub fn serialize_maybe_base64<S>(
    value: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match *value {
        Some(ref value) => {
            serializer.serialize_str(&general_purpose::STANDARD.encode(value))
        }
        None => serializer.serialize_none(),
    }
}

pub fn serialize_option_base64<S>(
    value: &Option<&[u8]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match *value {
        Some(value) => {
            serializer.serialize_str(&general_purpose::STANDARD.encode(value))
        }
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_maybe_base64<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<WrappedBase64Encoded>::deserialize(deserializer)
        .map(|wrapped| wrapped.map(|wrapped| wrapped.0))
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestStruct<'a> {
        #[serde(
            serialize_with = "serialize_maybe_base64",
            deserialize_with = "deserialize_maybe_base64"
        )]
        maybe_base64: Option<Vec<u8>>,
        #[serde(
            serialize_with = "serialize_as_base64",
            skip_serializing_if = "is_empty"
        )]
        as_base64: &'a [u8],
        #[serde(
            serialize_with = "serialize_option_base64",
            skip_serializing_if = "Option::is_none"
        )]
        option_base64: Option<&'a [u8]>,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestResponse {
        #[serde(deserialize_with = "deserialize_maybe_base64", default)]
        maybe_base64: Option<Vec<u8>>,
        #[serde(deserialize_with = "deserialize_maybe_base64", default)]
        as_base64: Option<Vec<u8>>,
        #[serde(deserialize_with = "deserialize_maybe_base64", default)]
        option_base64: Option<Vec<u8>>,
    }

    #[test]
    fn test_serialization() {
        let maybe_base64: Option<Vec<u8>> = Some("test".as_bytes().to_vec());
        let as_base64: &[u8] = "test".as_bytes();

        let complete = TestStruct {
            maybe_base64,
            as_base64,
            option_base64: Some(as_base64),
        };

        let serialized = serde_json::to_string(&complete).unwrap(); //#[allow_ci]

        assert_eq!(serialized, "{\"maybe_base64\":\"dGVzdA==\",\"as_base64\":\"dGVzdA==\",\"option_base64\":\"dGVzdA==\"}");

        let deserialized: TestResponse =
            serde_json::from_str(&serialized).unwrap(); //#[allow_ci]

        assert_eq!(
            deserialized.maybe_base64,
            Some("test".as_bytes().to_vec())
        );
        assert_eq!(deserialized.as_base64, Some("test".as_bytes().to_vec()));
        assert_eq!(
            deserialized.option_base64,
            Some("test".as_bytes().to_vec())
        );

        let maybe_base64: Option<Vec<u8>> = Some("test".as_bytes().to_vec());
        let options_missing = TestStruct {
            maybe_base64,
            as_base64: &[],
            option_base64: None,
        };

        let serialized = serde_json::to_string(&options_missing).unwrap(); //#[allow_ci]

        // Expect the None and empty fields to be skipped
        assert_eq!(serialized, "{\"maybe_base64\":\"dGVzdA==\"}");

        let deserialized: TestResponse =
            serde_json::from_str(&serialized).unwrap(); //#[allow_ci]

        assert_eq!(
            deserialized.maybe_base64,
            Some("test".as_bytes().to_vec())
        );
        assert_eq!(deserialized.as_base64, None);
        assert_eq!(deserialized.option_base64, None);
    }
}
