use super::capabilities_negotiation::SystemInfo;
use serde::{Deserialize, Serialize};
use serde_json::to_value;
use serde_json::Value as JsonValue;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(try_from = "JsonValue", into = "JsonValue")]
#[serde(untagged)]
pub enum EvidenceData {
    TpmQuoteData {
        subject_data: String,
        message: String,
        signature: String,
    },
    UefiLog {
        entries: String,
    },
    ImaLog {
        entry_count: u64,
        entries: String,
    },
}

// For ImaLog/UefiLog differentiation, entry_count must be checked
impl TryFrom<JsonValue> for EvidenceData {
    type Error = String;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        if let Some(subject_data) = value.get("subject_data") {
            if subject_data.is_string() {
                let subject_data = subject_data.as_str().unwrap().to_string(); //#[allow_ci]
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
                return Ok(EvidenceData::TpmQuoteData {
                    subject_data,
                    message,
                    signature,
                });
            } else {
                return Err("Invalid subject_data field".to_string());
            }
        } else if let Some(entry_count) = value.get("entry_count") {
            if entry_count.is_number() {
                let entry_count = entry_count.as_u64().unwrap(); //#[allow_ci]
                let entries = value
                    .get("entries")
                    .ok_or_else(|| "Missing entries field".to_string())?
                    .as_str()
                    .ok_or_else(|| "Invalid entries field".to_string())?
                    .to_string();
                return Ok(EvidenceData::ImaLog {
                    entry_count,
                    entries,
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
                return Ok(EvidenceData::UefiLog { entries });
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
            EvidenceData::TpmQuoteData {
                subject_data,
                message,
                signature,
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
                JsonValue::Object(map)
            }
            EvidenceData::UefiLog { entries } => {
                let mut map = serde_json::Map::new();
                map.insert("entries".to_string(), to_value(entries).unwrap()); //#[allow_ci]
                JsonValue::Object(map)
            }
            EvidenceData::ImaLog {
                entry_count,
                entries,
            } => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "entry_count".to_string(),
                    to_value(entry_count).unwrap(), //#[allow_ci]
                );
                map.insert("entries".to_string(), to_value(entries).unwrap()); //#[allow_ci]
                JsonValue::Object(map)
            }
        }
    }
}

// EvidenceHandlingResponse:
// {
//    "data": {
//        "type": "attestation",
//        "attributes": {
//            "stage": "evaluating_evidence",            // New
//            "evidence": [
//                {
//                    "evidence_class": "certification",
//                    "evidence_type": "tpm_quote",
//                    "capabilities": {
//                        // contains the data submitted during capabilities negotiation
//                    },
//                    "chosen_parameters": {
//                        // contains the values chosen during capabilities negotiation
//                    },
//                    "data": {
//                        // contains the data submitted in the request, plus:
//                        "certification_info": {        // New: quote info rendered by the server
//                            "pcrs": {
//                                "sha256": {
//                                    "0": "...",
//                                    "1": "...",
//                                    "2": "...",
//                                    "3": "...",
//                                    "4": "...",
//                                    "5": "...",
//                                    "6": "..."
//                                }
//                            }
//                        }
//                    }
//                },
//                {
//                    "evidence_class": "log",
//                    "evidence_type": "uefi_log",
//                    "capabilities": {
//                        // contains the data submitted during capabilities negotiation
//                    },
//                    "chosen_parameters": {
//                        // contains the values chosen during capabilities negotiation
//                    },
//                    "data": {
//                        // contains the data submitted in the request
//                    }
//                },
//                {
//                    "evidence_class": "log",
//                    "evidence_type": "ima_log",
//                    "capabilities": {
//                        // contains the data submitted during capabilities negotiation
//                    },
//                    "chosen_parameters": {
//                        // contains the values chosen during capabilities negotiation
//                    },
//                    "data": {
//                        // contains the data submitted in the request
//                    }
//                }
//            ],
//            "system_info": {
//                "boot_time": "2024-11-12T16:21:17Z"        // as submitted during capabilities negotiation
//            }
//        }
//    }
//}
pub struct EvidenceHandlingResponse {
    pub data: EvidenceHandlingResponseData,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingResponseData {
    #[serde(rename = "type")]
    pub data_type: String,
    pub attributes: EvidenceHandlingResponseAttributes,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceHandlingResponseAttributes {
    pub stage: String,
    pub evidence: Vec<Evidence>,
    pub system_info: SystemInfo,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub evidence_class: String,
    pub evidence_type: String,
    pub capabilities: String,
    pub chosen_parameters: String,
    pub data: EvidenceData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CertificationInfo {
    pub pcrs: PCRs,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PCRs {
    pub sha256: PCRValues,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PCRValues {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub pcr3: String,
    pub pcr4: String,
    pub pcr5: String,
    pub pcr6: String,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn serialize_evidence_handling_request() {
        let tpm_evidence_data = EvidenceData::TpmQuoteData {
            subject_data: "subject_data".to_string(),
            message: "message".to_string(),
            signature: "signature".to_string(),
        };

        let tpm_evidence_collected = EvidenceCollected {
            evidence_class: "certification".to_string(),
            evidence_type: "tpm_quote".to_string(),
            data: tpm_evidence_data,
        };

        let uefi_evidence_data = EvidenceData::UefiLog {
            entries: "uefi_log_entries".to_string(),
        };
        let uefi_evidence_collected = EvidenceCollected {
            evidence_class: "log".to_string(),
            evidence_type: "uefi_log".to_string(),
            data: uefi_evidence_data,
        };

        let ima_evidence_data = EvidenceData::ImaLog {
            entry_count: 95,
            entries: "ima_log_entries".to_string(),
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
        if let EvidenceData::TpmQuoteData {
            subject_data,
            message,
            signature,
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
        if let EvidenceData::UefiLog { entries } =
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
                print!("Error: {}", e); //#[allow_ci]
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
                print!("Error: {}", e); //#[allow_ci]
                assert!(e.to_string().contains("Invalid entry_count field")); //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_request_invalid_entry_count
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
                print!("Error: {}", e); //#[allow_ci]
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
                print!("Error: {}", e); //#[allow_ci]
                assert!(e.to_string().contains("Invalid entries field")); //#[allow_ci]
            }
        }
    } // deserialize_evidence_handling_invalid_entries_field
}
