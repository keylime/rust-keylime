use super::capabilities_negotiation::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::to_value;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::convert::From;
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingRequest {
    pub data: EvidenceHandlingRequestData,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingRequestData {
    #[serde(rename = "type")]
    pub data_type: String,
    pub attributes: EvidenceHandlingRequestAttributes,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingRequestAttributes {
    pub evidence_collected: Vec<EvidenceCollected>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceCollected {
    pub evidence_class: String,
    pub evidence_type: String,
    pub data: EvidenceData,
}

#[derive(Debug, Clone)]
pub enum EvidenceRequest {
    TpmQuote {
        challenge: String,
        signature_scheme: String,
        hash_algorithm: String,
        selected_subjects: HashMap<String, Vec<u32>>,
    },
    ImaLog {
        starting_offset: Option<usize>,
        entry_count: Option<usize>,
        format: Option<String>,
        log_path: Option<String>,
    },
    UefiLog {
        format: Option<String>,
        log_path: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(try_from = "JsonValue", into = "JsonValue")]
#[serde(untagged)]
pub enum EvidenceData {
    TpmQuote {
        subject_data: String,
        message: String,
        signature: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<JsonValue>,
    },
    UefiLog {
        entries: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<JsonValue>,
    },
    ImaLog {
        entry_count: usize,
        entries: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        meta: Option<JsonValue>,
    },
}

// For ImaLog/UefiLog differentiation, entry_count must be checked
impl TryFrom<JsonValue> for EvidenceData {
    type Error = String;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        if let Some(subject_data) = value.get("subject_data") {
            if subject_data.is_string() {
                let subject_data =
                    subject_data.as_str().ok_or("Incorrect Subject Data")?;
                let message = value
                    .get("message")
                    .ok_or_else(|| "Missing message field".to_string())?
                    .as_str()
                    .ok_or_else(|| "Invalid message field".to_string())?
                    .to_string();
                let signature = value
                    .get("signature")
                    .ok_or_else(|| "Missing signature field".to_string())?
                    .as_str()
                    .ok_or_else(|| "Invalid signature field".to_string())?
                    .to_string();
                let meta = value.get("meta").cloned();
                return Ok(EvidenceData::TpmQuote {
                    subject_data: subject_data.to_string(),
                    message,
                    signature,
                    meta,
                });
            } else {
                return Err("Invalid subject_data field".to_string());
            }
        } else if let Some(entry_count) = value.get("entry_count") {
            if entry_count.is_number() {
                let entry_count = entry_count
                    .as_u64()
                    .ok_or_else(|| "Invalid entry_count field".to_string())?
                    as usize;
                let entries = value
                    .get("entries")
                    .ok_or_else(|| "Missing entries field".to_string())?
                    .as_str()
                    .ok_or_else(|| "Invalid entries field".to_string())?
                    .to_string();
                let meta = value.get("meta").cloned();
                return Ok(EvidenceData::ImaLog {
                    entry_count,
                    entries,
                    meta,
                });
            } else {
                return Err("Invalid entry_count field".to_string());
            }
        } else if let Some(entries) = value.get("entries") {
            if entries.is_string() {
                let entries = value
                    .get("entries")
                    .unwrap() //#[allow_ci]
                    .as_str()
                    .unwrap() //#[allow_ci]
                    .to_string();
                let meta = value.get("meta").cloned();
                return Ok(EvidenceData::UefiLog { entries, meta });
            } else {
                return Err("Invalid entries field".to_string());
            }
        };
        Err("Failed to deserialize EvidenceData".to_string())
    }
}

impl From<EvidenceData> for JsonValue {
    fn from(data: EvidenceData) -> Self {
        match data {
            EvidenceData::TpmQuote {
                subject_data,
                message,
                signature,
                meta,
            } => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "subject_data".to_string(),
                    to_value(subject_data).unwrap(), //#[allow_ci]
                );
                map.insert("message".to_string(), to_value(message).unwrap()); //#[allow_ci]
                map.insert(
                    "signature".to_string(),
                    to_value(signature).unwrap(), //#[allow_ci]
                );
                if let Some(meta_value) = meta {
                    map.insert("meta".to_string(), meta_value);
                }
                JsonValue::Object(map)
            }
            EvidenceData::UefiLog { entries, meta } => {
                let mut map = serde_json::Map::new();
                map.insert("entries".to_string(), to_value(entries).unwrap()); //#[allow_ci]
                if let Some(meta_value) = meta {
                    map.insert("meta".to_string(), meta_value);
                }
                JsonValue::Object(map)
            }
            EvidenceData::ImaLog {
                entry_count,
                entries,
                meta,
            } => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "entry_count".to_string(),
                    to_value(entry_count).unwrap(), //#[allow_ci]
                );
                map.insert("entries".to_string(), to_value(entries).unwrap()); //#[allow_ci]
                if let Some(meta_value) = meta {
                    map.insert("meta".to_string(), meta_value);
                }
                JsonValue::Object(map)
            }
        }
    }
}

impl From<EvidenceData> for EvidenceCollected {
    fn from(evidence_data: EvidenceData) -> Self {
        match evidence_data {
            EvidenceData::TpmQuote {
                subject_data,
                message,
                signature,
                meta,
            } => EvidenceCollected {
                evidence_class: "certification".to_string(),
                evidence_type: "tpm_quote".to_string(),
                data: EvidenceData::TpmQuote {
                    subject_data,
                    message,
                    signature,
                    meta,
                },
            },
            EvidenceData::ImaLog { entries, meta, .. } => {
                // Count the number of entries (lines)
                let entry_count = entries.lines().count();
                EvidenceCollected {
                    evidence_class: "log".to_string(),
                    evidence_type: "ima_log".to_string(),
                    data: EvidenceData::ImaLog {
                        entry_count,
                        entries,
                        meta,
                    },
                }
            }
            EvidenceData::UefiLog { entries, meta } => EvidenceCollected {
                evidence_class: "log".to_string(),
                evidence_type: "uefi_log".to_string(),
                data: EvidenceData::UefiLog { entries, meta },
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonApiInfo {
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingResponse {
    pub data: EvidenceHandlingResponseData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<EvidenceHandlingResponseMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsonapi: Option<JsonApiInfo>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingResponseData {
    #[serde(rename = "type")]
    pub data_type: String,
    pub attributes: EvidenceHandlingResponseAttributes,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingResponseMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds_to_next_attestation: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingResponseAttributes {
    pub stage: String,
    pub evidence: Vec<EvidenceHandlingResponseAttributesEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_info: Option<SystemInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities_received_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenges_expire_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_received_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum EvidenceCapabilities {
    Certification(Capabilities),
    Log(LogCapabilities),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingResponseAttributesEvidence {
    pub evidence_class: String,
    pub evidence_type: String,
    pub capabilities: EvidenceCapabilities,
    pub chosen_parameters: Option<ChosenParameters>,
    pub data: EvidenceData,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_evidence_data_to_evidence_collected_conversion() {
        // Test TpmQuoteData conversion
        let tpm_evidence = EvidenceData::TpmQuote {
            subject_data: "test_subject".to_string(),
            message: "test_message".to_string(),
            signature: "test_signature".to_string(),
            meta: None,
        };
        let tpm_collected: EvidenceCollected = tpm_evidence.into();
        assert_eq!(tpm_collected.evidence_class, "certification");
        assert_eq!(tpm_collected.evidence_type, "tpm_quote");
        if let EvidenceData::TpmQuote {
            subject_data,
            message,
            signature,
            ..
        } = tpm_collected.data
        {
            assert_eq!(subject_data, "test_subject");
            assert_eq!(message, "test_message");
            assert_eq!(signature, "test_signature");
        } else {
            panic!("Expected TpmQuote"); //#[allow_ci]
        }

        // Test ImaLog conversion
        let ima_evidence = EvidenceData::ImaLog {
            entry_count: 0, // This should be recalculated
            entries: "line1\nline2\nline3".to_string(),
            meta: None,
        };
        let ima_collected: EvidenceCollected = ima_evidence.into();
        assert_eq!(ima_collected.evidence_class, "log");
        assert_eq!(ima_collected.evidence_type, "ima_log");
        if let EvidenceData::ImaLog {
            entry_count,
            entries,
            ..
        } = ima_collected.data
        {
            assert_eq!(entry_count, 3); // Should be recalculated from lines
            assert_eq!(entries, "line1\nline2\nline3");
        } else {
            panic!("Expected ImaLog"); //#[allow_ci]
        }

        // Test UefiLog conversion
        let uefi_evidence = EvidenceData::UefiLog {
            entries: "uefi_entries".to_string(),
            meta: None,
        };
        let uefi_collected: EvidenceCollected = uefi_evidence.into();
        assert_eq!(uefi_collected.evidence_class, "log");
        assert_eq!(uefi_collected.evidence_type, "uefi_log");
        if let EvidenceData::UefiLog { entries, .. } = uefi_collected.data {
            assert_eq!(entries, "uefi_entries");
        } else {
            panic!("Expected UefiLog"); //#[allow_ci]
        }
    }

    #[test]
    fn serialize_evidence_handling_request() {
        let tpm_evidence_data = EvidenceData::TpmQuote {
            subject_data: "subject_data".to_string(),
            message: "message".to_string(),
            signature: "signature".to_string(),
            meta: None,
        };

        let tpm_evidence_collected = EvidenceCollected {
            evidence_class: "certification".to_string(),
            evidence_type: "tpm_quote".to_string(),
            data: tpm_evidence_data,
        };

        let uefi_evidence_data = EvidenceData::UefiLog {
            entries: "uefi_log_entries".to_string(),
            meta: None,
        };
        let uefi_evidence_collected = EvidenceCollected {
            evidence_class: "log".to_string(),
            evidence_type: "uefi_log".to_string(),
            data: uefi_evidence_data,
        };

        let ima_evidence_data = EvidenceData::ImaLog {
            entry_count: 95,
            entries: "ima_log_entries".to_string(),
            meta: None,
        };
        let ima_evidence_collected = EvidenceCollected {
            evidence_class: "log".to_string(),
            evidence_type: "ima_log".to_string(),
            data: ima_evidence_data,
        };

        let attributes = EvidenceHandlingRequestAttributes {
            evidence_collected: vec![
                tpm_evidence_collected,
                uefi_evidence_collected,
                ima_evidence_collected,
            ],
        };

        let data = EvidenceHandlingRequestData {
            data_type: "attestation".to_string(),
            attributes,
        };

        let request = EvidenceHandlingRequest { data };

        let serialized = serde_json::to_string_pretty(&request).unwrap(); //#[allow_ci]
        assert_eq!(
            serialized,
            r#"{
  "data": {
    "type": "attestation",
    "attributes": {
      "evidence_collected": [
        {
          "evidence_class": "certification",
          "evidence_type": "tpm_quote",
          "data": {
            "message": "message",
            "signature": "signature",
            "subject_data": "subject_data"
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "uefi_log",
          "data": {
            "entries": "uefi_log_entries"
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "ima_log",
          "data": {
            "entries": "ima_log_entries",
            "entry_count": 95
          }
        }
      ]
    }
  }
}"#
        );
    } // serialize_evidence_handling_request/

    #[test]
    fn deserialize_evidence_handling_request() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "data": {
                        "subject_data": "subject_data_deserialized",
                        "message": "message_deserialized",
                        "signature": "signature_deserialized"
                    }
                },
                {
                    "evidence_class": "log",
                    "evidence_type": "uefi_log",
                    "data": {
                        "entries": "uefi_log_entries_deserialized"
                    }
                },
                {
                    "evidence_class": "log",
                    "evidence_type": "ima_log",
                    "data": {
                        "entries": "ima_log_entries_deserialized",
                        "entry_count": 96
                    }
                }
            ]
        }
    }
}"#;
        let deserialized: EvidenceHandlingRequest =
            serde_json::from_str(json).unwrap(); //#[allow_ci]

        assert_eq!(deserialized.data.data_type, "attestation");
        assert_eq!(deserialized.data.attributes.evidence_collected.len(), 3);
        assert_eq!(
            deserialized.data.attributes.evidence_collected[0].evidence_class,
            "certification"
        );
        assert_eq!(
            deserialized.data.attributes.evidence_collected[0].evidence_type,
            "tpm_quote"
        );
        if let EvidenceData::TpmQuote {
            subject_data,
            message,
            signature,
            ..
        } = &deserialized.data.attributes.evidence_collected[0].data
        {
            assert_eq!(subject_data, "subject_data_deserialized");
            assert_eq!(message, "message_deserialized");
            assert_eq!(signature, "signature_deserialized");
        } else {
            panic!("Expected TpmQuoteData"); //#[allow_ci]
        }
        assert_eq!(
            deserialized.data.attributes.evidence_collected[1].evidence_class,
            "log"
        );
        assert_eq!(
            deserialized.data.attributes.evidence_collected[1].evidence_type,
            "uefi_log"
        );
        if let EvidenceData::UefiLog { entries, .. } =
            &deserialized.data.attributes.evidence_collected[1].data
        {
            assert_eq!(entries, "uefi_log_entries_deserialized");
        } else {
            panic!("Expected UefiLog"); //#[allow_ci]
        }
        assert_eq!(
            deserialized.data.attributes.evidence_collected[2].evidence_class,
            "log"
        );
        assert_eq!(
            deserialized.data.attributes.evidence_collected[2].evidence_type,
            "ima_log"
        );
        if let EvidenceData::ImaLog {
            entry_count,
            entries,
            ..
        } = &deserialized.data.attributes.evidence_collected[2].data
        {
            assert_eq!(*entry_count, 96);
            assert_eq!(entries, "ima_log_entries_deserialized");
        } else {
            panic!("Expected ImaLog"); //#[allow_ci]
        }
    } // deserialize_evidence_handling_request

    #[test]
    fn deserialize_evidence_handling_request_wrong_evidence_data() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "data": {
                        "unexpected_field": "unexepcted_field"
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                assert!(e
                    .to_string()
                    .contains("Failed to deserialize EvidenceData")); //#[allow_ci]
            }
        } //#[allow_ci]
    } // deserialize_evidence_handling_request_wrong_evidence_data
    #[test]
    fn deserialize_evidence_handling_request_no_message() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "data": {
                        "subject_data": "subject_data_deserialized",
                        "signature": "signature_deserialized"
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                assert!(e.to_string().contains("Missing message field")); //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_request_no_message

    #[test]
    fn deserialize_evidence_handling_request_no_signature() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "data": {
                        "subject_data": "subject_data_deserialized",
                        "message": "message_deserialized"
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                assert!(e.to_string().contains("Missing signature field")); //#[allow_ci]
            }
        } //#[allow_ci]
    } // deserialize_evidence_handling_request_no_signature

    #[test]
    fn deserialize_evidence_handling_request_invalid_signature_field() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "data": {
                        "subject_data": "subject_data_deserialized",
                        "signature": 12300000,
                        "message": "message_deserialized"
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                assert!(e.to_string().contains("Invalid signature field")); //#[allow_ci]
            }
        } //#[allow_ci]
    } // deserialize_evidence_handling_request_invalid_signature_field

    #[test]
    fn deserialize_evidence_handling_request_invalid_subject_data() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "data": {
                        "subject_data": 123456,
                        "signature": 12345678,
                        "message": "message_deserialized"
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                assert!(e.to_string().contains("Invalid subject_data field"));
                //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_request_invalid_subject_data

    #[test]
    fn deserialize_evidence_handling_request_wrong_message() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "data": {
                        "subject_data": "subject_data_deserialized",
                        "signature": "signature_deserialized",
                        "message": 12345
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                assert!(e.to_string().contains("Invalid message field")); //#[allow_ci]
            }
        } //#[allow_ci]
    } // deserialize_evidence_handling_request_wrong_message

    #[test]
    fn deserialize_evidence_handling_request_invalid_entries() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "log",
                    "evidence_type": "uefi_log",
                    "data": {
                        "entries": 12345
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                print!("Error: {e:?}"); //#[allow_ci]
                assert!(e.to_string().contains("Invalid entries field")); //#[allow_ci]
            }
        } //#[allow_ci]
    } // deserialize_evidence_handling_request_invalid_entries

    #[test]
    fn deserialize_evidence_handling_request_invalid_entry_count() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "log",
                    "evidence_type": "ima_log",
                    "data": {
                        "entry_count": "invalid_entry_count",
                        "entries": "valid_entries"
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                print!("Error: {e:?}"); //#[allow_ci]
                assert!(e.to_string().contains("Invalid entry_count field")); //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_request_invalid_entry_count

    #[test]
    fn deserialize_evidence_handling_request_invalid_entry_count_format() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "log",
                    "evidence_type": "ima_log",
                    "data": {
                        "entry_count": -1,
                        "entries": "valid_entries"
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                print!("Error: {e:?}"); //#[allow_ci]
                assert!(e.to_string().contains("Invalid entry_count field")); //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_request_invalid_entry_count_format

    #[test]
    fn deserialize_evidence_handling_missing_entries_field() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "log",
                    "evidence_type": "ima_log",
                    "data": {
                        "entry_count": 125
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                print!("Error: {e:?}"); //#[allow_ci]
                assert!(e.to_string().contains("Missing entries field")); //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_missing_entries_field

    #[test]
    fn deserialize_evidence_handling_invalid_entries_field() {
        let json = r#"{
    "data": {
        "type": "attestation",
        "attributes": {
            "evidence_collected": [
                {
                    "evidence_class": "log",
                    "evidence_type": "uefi_log",
                    "data": {
                        "entry_count": 125,
                        "entries": 12345
                    }
                }
            ]
        }
    }
}"#;
        match serde_json::from_str::<EvidenceHandlingRequest>(json) {
            Ok(_) => panic!("Expected error"), //#[allow_ci]
            Err(e) => {
                print!("Error: {e:?}"); //#[allow_ci]
                assert!(e.to_string().contains("Invalid entries field")); //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_invalid_entries_field

    #[test]
    fn serialize_evidence_handling_response() {
        // Create a sample EvidenceHandlingResponse and serialize it to JSON
        let response = EvidenceHandlingResponse {
            data: EvidenceHandlingResponseData {
                data_type: "attestation".to_string(),
                attributes: EvidenceHandlingResponseAttributes {
                    stage: "evaluating_evidence".to_string(),
                    evidence: vec![
                        EvidenceHandlingResponseAttributesEvidence {
                            evidence_class: "certification".to_string(),
                            evidence_type: "tpm_quote".to_string(),
                            capabilities: EvidenceCapabilities::Certification(
                                Capabilities {
                                    component_version: "2.0".to_string(),
                                    hash_algorithms: vec!["sha3_512".to_string()],
                                    signature_schemes: vec!["rsassa".to_string()],
                                    available_subjects: PcrBanks {
                                        sha1: Some(vec![0x01, 0x02, 0x03]),
                                        sha256: Some(vec![0x04, 0x05, 0x06]),
                                        sha384: None,
                                        sha512: None,
                                        sm3_256: None,
                                    },
                                    certification_keys: vec![],
                                },
                            ),
                            chosen_parameters: Some(
                                ChosenParameters::Parameters(Box::new(
                                    CertificationParameters {
                                        challenge: Some("challenge".to_string()),
                                        selected_subjects: Some(PcrBanks {
                                            sha1: Some(vec![0x01, 0x02, 0x03]),
                                            sha256: Some(vec![0x04, 0x05, 0x06]),
                                            sha384: None,
                                            sha512: None,
                                            sm3_256: None,
                                        }),
                                        hash_algorithm: Some(
                                            "sha384".to_string(),
                                        ),
                                        signature_scheme: Some(
                                            "rsassa".to_string(),
                                        ),
                                        certification_key: Some(CertificationKey {
                                            key_class: "asymmetric".to_string(),
                                            key_size: 2048,
                                            server_identifier: "ak".to_string(),
                                            local_identifier: "att_local_identifier".to_string(),
                                            key_algorithm: "rsa".to_string(),
                                            public: "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth".to_string(),
                                            allowable_hash_algorithms: None,
                                            allowable_signature_schemes: None,
                                        }),
                                    },
                                )),
                            ),
                            data: EvidenceData::TpmQuote {
                                subject_data: "subject_data".to_string(),
                                message: "message".to_string(),
                                signature: "signature".to_string(),
                                meta: None,
                            },
                        },
                        EvidenceHandlingResponseAttributesEvidence {
                            evidence_class: "log".to_string(),
                            evidence_type: "uefi_log".to_string(),
                            capabilities: EvidenceCapabilities::Log(
                                LogCapabilities {
                                    evidence_version: Some("1.0".to_string()),
                                    entry_count: 50,
                                    supports_partial_access: false,
                                    appendable: false,
                                    formats: vec![
                                        "application/octet-stream".to_string()
                                    ],
                                },
                            ),
                            chosen_parameters: Some(
                                ChosenParameters::Parameters(Box::new(
                                    CertificationParameters {
                                        challenge: Some("challenge".to_string()),
                                        selected_subjects: Some(PcrBanks {
                                            sha1: Some(vec![0x01, 0x02, 0x03]),
                                            sha256: Some(vec![0x04, 0x05, 0x06]),
                                            sha384: None,
                                            sha512: None,
                                            sm3_256: None,
                                        }),
                                        hash_algorithm: Some(
                                            "sha384".to_string(),
                                        ),
                                        signature_scheme: Some(
                                            "rsassa".to_string(),
                                        ),
                                        certification_key: Some(CertificationKey {
                                            key_class: "asymmetric".to_string(),
                                            key_size: 2048,
                                            server_identifier: "ak".to_string(),
                                            local_identifier: "att_local_identifier".to_string(),
                                            key_algorithm: "rsa".to_string(),
                                            public: "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth".to_string(),
                                            allowable_hash_algorithms: None,
                                            allowable_signature_schemes: None,
                                        }),
                                    },
                                )),
                            ),
                            data: EvidenceData::UefiLog {
                                entries: "uefi_log_entries".to_string(),
                                meta: None,
                            },
                        },
                        EvidenceHandlingResponseAttributesEvidence {
                            evidence_class: "log".to_string(),
                            evidence_type: "ima_log".to_string(),
                            capabilities: EvidenceCapabilities::Log(
                                LogCapabilities {
                                    evidence_version: None,
                                    entry_count: 150,
                                    supports_partial_access: true,
                                    appendable: true,
                                    formats: vec!["text/plain".to_string()],
                                },
                            ),
                            chosen_parameters: Some(ChosenParameters::Offset(
                                LogParameters {
                                    format: "application/octet-stream".to_string(),
                                    starting_offset: None,
                                    entry_count: None,
                                },
                            )),
                            data: EvidenceData::ImaLog {
                                entry_count: 96,
                                entries: "ima_log_entries".to_string(),
                                meta: None,
                            },
                        },
                    ],
                    system_info: Some(SystemInfo {
                        boot_time: "2025-08-27T11:00:17Z".parse().unwrap(), //#[allow_ci]
                    }),
                    capabilities_received_at: Some(
                        "2025-08-27T11:01:17Z".parse().unwrap(), //#[allow_ci]
                    ),
                    challenges_expire_at: Some(
                        "2025-08-27T11:01:17Z".parse().unwrap(), //#[allow_ci]
                    ),
                    evidence_received_at: Some(
                        "2025-08-27T11:01:17Z".parse().unwrap(), //#[allow_ci]
                    ),
                },
            },
            meta: Some(EvidenceHandlingResponseMeta {
                seconds_to_next_attestation: Some(120),
            }),
            jsonapi: Some(JsonApiInfo {
                version: "1.1".to_string(),
            }),
        };
        // Serialize the response to JSON and check it is correctly generated
        let serialized = serde_json::to_string_pretty(&response).unwrap(); //#[allow_ci]
        assert_eq!(
            serialized,
            r#"{
  "data": {
    "type": "attestation",
    "attributes": {
      "stage": "evaluating_evidence",
      "evidence": [
        {
          "evidence_class": "certification",
          "evidence_type": "tpm_quote",
          "capabilities": {
            "component_version": "2.0",
            "hash_algorithms": [
              "sha3_512"
            ],
            "signature_schemes": [
              "rsassa"
            ],
            "available_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "certification_keys": []
          },
          "chosen_parameters": {
            "certification_key": {
              "key_algorithm": "rsa",
              "key_class": "asymmetric",
              "key_size": 2048,
              "local_identifier": "att_local_identifier",
              "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth",
              "server_identifier": "ak"
            },
            "challenge": "challenge",
            "hash_algorithm": "sha384",
            "selected_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "signature_scheme": "rsassa"
          },
          "data": {
            "message": "message",
            "signature": "signature",
            "subject_data": "subject_data"
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "uefi_log",
          "capabilities": {
            "evidence_version": "1.0",
            "entry_count": 50,
            "supports_partial_access": false,
            "appendable": false,
            "formats": [
              "application/octet-stream"
            ]
          },
          "chosen_parameters": {
            "certification_key": {
              "key_algorithm": "rsa",
              "key_class": "asymmetric",
              "key_size": 2048,
              "local_identifier": "att_local_identifier",
              "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth",
              "server_identifier": "ak"
            },
            "challenge": "challenge",
            "hash_algorithm": "sha384",
            "selected_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "signature_scheme": "rsassa"
          },
          "data": {
            "entries": "uefi_log_entries"
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "ima_log",
          "capabilities": {
            "entry_count": 150,
            "supports_partial_access": true,
            "appendable": true,
            "formats": [
              "text/plain"
            ]
          },
          "chosen_parameters": {
            "format": "application/octet-stream"
          },
          "data": {
            "entries": "ima_log_entries",
            "entry_count": 96
          }
        }
      ],
      "system_info": {
        "boot_time": "2025-08-27T11:00:17Z"
      },
      "capabilities_received_at": "2025-08-27T11:01:17Z",
      "challenges_expire_at": "2025-08-27T11:01:17Z",
      "evidence_received_at": "2025-08-27T11:01:17Z"
    }
  },
  "meta": {
    "seconds_to_next_attestation": 120
  },
  "jsonapi": {
    "version": "1.1"
  }
}"#
        );
    } // serialize_evidence_handling_response

    #[test]
    fn deserialize_evidence_handling_response() {
        let json = r#"{
"data": {
    "type": "attestation",
    "attributes": {
      "stage": "evaluating_evidence",
      "evidence": [
        {
          "evidence_class": "certification",
          "evidence_type": "tpm_quote",
          "capabilities": {
            "component_version": "2.0",
            "hash_algorithms": [
              "sha3_512"
            ],
            "signature_schemes": [
              "rsassa"
            ],
            "available_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "certification_keys": [
              {
                "key_algorithm": "rsa",
                "key_class": "asymmetric",
                "key_size": 2048,
                "server_identifier": "ak",
                "local_identifier": "att_local_identifier",
                "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth"
              }
            ]
          },
          "chosen_parameters": {
            "certification_key": {
              "key_algorithm": "rsa",
              "key_class": "asymmetric",
              "key_size": 2048,
              "local_identifier": "att_local_identifier",
              "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth",
              "server_identifier": "ak"
            },
            "challenge": "challenge",
            "hash_algorithm": "sha384",
            "selected_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "signature_scheme": "rsassa"
          },
          "data": {
            "message": "message",
            "signature": "signature",
            "subject_data": "subject_data"
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "uefi_log",
          "capabilities": {
            "component_version": "2.0",
            "hash_algorithms": [
              "sha3_512"
            ],
            "signature_schemes": [
              "rsassa"
            ],
            "available_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "certification_keys": [
              {
                "key_algorithm": "rsa",
                "key_class": "asymmetric",
                "key_size": 2048,
                "server_identifier": "ak",
                "local_identifier": "att_local_identifier",
                "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth"
              }
            ]
          },
          "chosen_parameters": {
            "certification_key": {
              "key_algorithm": "rsa",
              "key_class": "asymmetric",
              "key_size": 2048,
              "local_identifier": "att_local_identifier",
              "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth",
              "server_identifier": "ak"
            },
            "challenge": "challenge",
            "hash_algorithm": "sha384",
            "selected_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "signature_scheme": "rsassa"
          },
          "data": {
            "entries": "uefi_log_entries"
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "ima_log",
          "capabilities": {
            "component_version": "2.0",
            "hash_algorithms": [
              "sha3_512"
            ],
            "signature_schemes": [
              "rsassa"
            ],
            "available_subjects": {
              "sha1": [
                1,
                2,
                3
              ],
              "sha256": [
                4,
                5,
                6
              ]
            },
            "certification_keys": [
              {
                "key_algorithm": "rsa",
                "key_class": "asymmetric",
                "key_size": 2048,
                "server_identifier": "ak",
                "local_identifier": "att_local_identifier",
                "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth"
              }
            ]
          },
          "chosen_parameters": {
            "format": "application/octet-stream"
          },
          "data": {
            "entries": "ima_log_entries",
            "entry_count": 96
          }
        }
      ],
      "evidence_received_at": "2025-08-07T12:05:17.228706Z",
      "capabilities_received_at": "2025-08-07T11:52:17.228706Z",
      "challenges_expire_at": "2025-08-07T12:22:17.228706Z"
    }
  }
}"#;
        let deserialized: EvidenceHandlingResponse =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(deserialized.data.data_type, "attestation");
        assert_eq!(deserialized.data.attributes.evidence.len(), 3);
        assert_eq!(
            deserialized.data.attributes.evidence[0].evidence_class,
            "certification"
        );
        assert_eq!(
            deserialized.data.attributes.evidence[0].evidence_type,
            "tpm_quote"
        );
        if let EvidenceData::TpmQuote {
            subject_data,
            message,
            signature,
            ..
        } = &deserialized.data.attributes.evidence[0].data
        {
            assert_eq!(subject_data, "subject_data");
            assert_eq!(message, "message");
            assert_eq!(signature, "signature");
        } else {
            panic!("Expected TpmQuoteData"); //#[allow_ci]
        }
        assert!(matches!(
            deserialized.data.attributes.evidence[0].capabilities,
            EvidenceCapabilities::Certification(_)
        ));
        if let EvidenceCapabilities::Certification(capabilities) =
            &deserialized.data.attributes.evidence[0].capabilities
        {
            assert_eq!(capabilities.component_version, "2.0");
            assert_eq!(capabilities.hash_algorithms, vec!["sha3_512"]);
            assert_eq!(capabilities.signature_schemes, vec!["rsassa"]);
            assert_eq!(
                capabilities.available_subjects.sha1,
                Some(vec![0x01, 0x02, 0x03])
            );
            assert_eq!(
                capabilities.available_subjects.sha256,
                Some(vec![0x04, 0x05, 0x06])
            );
            let some_certification_keys =
                capabilities.certification_keys.first();
            assert!(some_certification_keys.is_some());
            let certification_key = some_certification_keys.unwrap(); //#[allow_ci]
            assert_eq!(certification_key.key_class, "asymmetric");
            assert_eq!(
                certification_key.local_identifier,
                "att_local_identifier"
            );
            assert_eq!(certification_key.key_algorithm, "rsa");
            assert_eq!(certification_key.key_size, 2048);
            assert_eq!(certification_key.server_identifier, "ak");
            assert_eq!(certification_key.public, "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth");
        }

        let some_chosen_parameters = deserialized.data.attributes.evidence[0]
            .chosen_parameters
            .as_ref();
        assert!(some_chosen_parameters.is_some());
        let chosen_parameters = some_chosen_parameters.unwrap(); //#[allow_ci]
        match chosen_parameters {
            ChosenParameters::Parameters(params) => {
                assert_eq!(params.challenge, Some("challenge".to_string()));
                assert_eq!(
                    params.selected_subjects.clone().unwrap().sha1, //#[allow_ci]
                    Some(vec![0x01, 0x02, 0x03])
                );
                assert_eq!(
                    params.selected_subjects.clone().unwrap().sha256, //#[allow_ci]
                    Some(vec![0x04, 0x05, 0x06])
                );
                assert_eq!(params.hash_algorithm, Some("sha384".to_string()));
                assert_eq!(
                    params.signature_scheme,
                    Some("rsassa".to_string())
                );
                let certification_key =
                    params.certification_key.as_ref().unwrap(); //#[allow_ci]
                assert_eq!(certification_key.key_class, "asymmetric");
                assert_eq!(
                    certification_key.local_identifier,
                    "att_local_identifier"
                );
                assert_eq!(certification_key.key_algorithm, "rsa");
                assert_eq!(certification_key
                        .public,
                    "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth"
                );
            }
            _ => panic!("Expected Parameters"), //#[allow_ci]
        }
        assert_eq!(
            deserialized.data.attributes.evidence[1].evidence_class,
            "log"
        );
        assert_eq!(
            deserialized.data.attributes.evidence[1].evidence_type,
            "uefi_log"
        );
        if let EvidenceData::UefiLog { entries, .. } =
            &deserialized.data.attributes.evidence[1].data
        {
            assert_eq!(entries, "uefi_log_entries");
        } else {
            panic!("Expected UefiLog"); //#[allow_ci]
        }
        assert!(deserialized.data.attributes.system_info.is_none());
        let evidence_received_at =
            deserialized.data.attributes.evidence_received_at;
        assert!(evidence_received_at.is_some());
        let evidence_received_at_utc = evidence_received_at.unwrap(); //#[allow_ci]
        assert_eq!(
            evidence_received_at_utc.to_string(),
            "2025-08-07 12:05:17.228706 UTC"
        );
        let capabilities_received_at =
            deserialized.data.attributes.capabilities_received_at;
        assert!(capabilities_received_at.is_some());
        let capabilities_received_at_utc = deserialized
            .data
            .attributes
            .capabilities_received_at
            .unwrap(); //#[allow_ci]
        assert_eq!(
            capabilities_received_at_utc.to_string(),
            "2025-08-07 11:52:17.228706 UTC"
        );
        let challenges_expire_at =
            deserialized.data.attributes.challenges_expire_at;
        assert!(challenges_expire_at.is_some());
        let challenges_expire_at_utc = challenges_expire_at.unwrap(); //#[allow_ci]
        assert_eq!(
            challenges_expire_at_utc.to_string(),
            "2025-08-07 12:22:17.228706 UTC"
        );
    } //serialize_evidence_handling_response
}
