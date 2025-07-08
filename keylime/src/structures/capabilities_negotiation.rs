use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{from_value, to_value, Value as JsonValue};
use std::convert::TryFrom;

// Define the structure for the AttestationRequest:
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationRequest {
    #[serde(rename(serialize = "data", deserialize = "data"))]
    pub data: RequestData,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct RequestData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
    pub attributes: Attributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Attributes {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence_supported: Vec<EvidenceSupported>,
    pub system_info: SystemInfo,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "evidence_class", rename_all = "snake_case")]
pub enum EvidenceSupported {
    Certification {
        evidence_type: String,
        capabilities: Capabilities,
    },
    #[serde(rename = "log", rename_all = "snake_case")]
    EvidenceLog {
        evidence_type: String,
        capabilities: LogCapabilities,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_version: Option<String>,
    pub entry_count: usize,
    pub supports_partial_access: bool,
    pub appendable: bool,
    pub formats: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImaEntries {
    pub evidence_class: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Capabilities {
    pub component_version: String,
    pub hash_algorithms: Vec<String>,
    pub signature_schemes: Vec<String>,
    pub available_subjects: ShaValues,
    pub certification_keys: Vec<CertificationKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
// Do not serialize the struct name, only the fields
pub struct ShaValues {
    pub sha1: Vec<u32>,
    pub sha256: Vec<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificationKey {
    pub key_algorithm: String,
    pub key_class: String,
    pub key_size: usize,
    pub server_identifier: String,
    pub local_identifier: String,
    pub public: String,
}

// Define the structure for the AttestationResponse:
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationResponse {
    #[serde(rename(serialize = "data", deserialize = "data"))]
    pub data: ResponseData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
    pub attributes: ResponseAttributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseAttributes {
    pub stage: String,
    pub evidence_requested: Vec<EvidenceRequested>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemInfo {
    pub boot_time: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceRequested {
    pub evidence_class: String,
    pub evidence_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chosen_parameters: Option<ChosenParameters>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificationParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_subjects: Option<ShaValues>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certification_key: Option<CertificationKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogParameters {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starting_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(try_from = "JsonValue", into = "JsonValue")]
pub enum ChosenParameters {
    Parameters(Box<CertificationParameters>),
    Offset(LogParameters),
}

impl TryFrom<JsonValue> for ChosenParameters {
    type Error = String;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        if let Ok(offset) = from_value::<LogParameters>(value.clone()) {
            return Ok(ChosenParameters::Offset(offset));
        }
        if let Ok(params) = from_value::<CertificationParameters>(value) {
            if params.certification_key.is_some()
                || params.hash_algorithm.is_some()
                || params.challenge.is_some()
                || params.selected_subjects.is_some()
                || params.signature_scheme.is_some()
            {
                return Ok(ChosenParameters::Parameters(Box::new(params)));
            }
        }
        Err("Failed to deserialize ChosenParameters".to_string())
    }
}

impl From<ChosenParameters> for JsonValue {
    fn from(params: ChosenParameters) -> Self {
        match params {
            ChosenParameters::Parameters(params) => to_value(params).unwrap(), //#[allow_ci]
            ChosenParameters::Offset(offset) => to_value(offset).unwrap(), //#[allow_ci]
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn serialize_request() {
        // Create a new AttestationRequest object and serialize it to JSON
        let request = AttestationRequest {
            data: RequestData {
                type_: "attestation".to_string(),
                attributes: Attributes {
                    evidence_supported: vec![
                        EvidenceSupported::Certification {
                            evidence_type: "tpm_quote".to_string(),
                            capabilities: Capabilities {
                                component_version: "2.0".to_string(),
                                hash_algorithms: vec!["sha3_512".to_string()],
                                signature_schemes: vec!["rsassa".to_string()],
                                available_subjects: ShaValues {
                                    sha1: vec![0x01, 0x02, 0x03],
                                    sha256: vec![0x04, 0x05, 0x06],
                                },
                                certification_keys: vec![
                                    CertificationKey {
                                        key_class: "asymmetric".to_string(),
                                        local_identifier: "att_local_identifier".to_string(),
                                        key_algorithm: "rsa".to_string(),
                                        key_size: 2048,
                                        server_identifier: "ak".to_string(),
                                        public: "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth".to_string(),
                                    },
                                ],
                            },
                        },
                    ],
                    system_info: SystemInfo {
                        boot_time: "2025-05-29T11:39:02Z"
                        .parse()
                        .unwrap() //#[allow_ci]
                    },
                },
            },
        };
        let json = serde_json::to_string_pretty(&request).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{
  "data": {
    "type": "attestation",
    "attributes": {
      "evidence_supported": [
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
          }
        }
      ],
      "system_info": {
        "boot_time": "2025-05-29T11:39:02Z"
      }
    }
  }
}"#,
        );
        let request = AttestationRequest {
            data: RequestData {
                type_: "attestation".to_string(),
                attributes: Attributes {
                    evidence_supported: vec![
                        EvidenceSupported::EvidenceLog {
                            evidence_type: "uefi_log".to_string(),
                            capabilities: LogCapabilities {
                                evidence_version: Some("2.1".to_string()),
                                entry_count: 20,
                                supports_partial_access: false,
                                appendable: false,
                                formats: vec![
                                    "application/octet-stream".to_string()
                                ],
                            },
                        },
                        EvidenceSupported::EvidenceLog {
                            evidence_type: "ima_log".to_string(),
                            capabilities: LogCapabilities {
                                evidence_version: None,
                                entry_count: 20,
                                supports_partial_access: true,
                                appendable: false,
                                formats: vec!["text/plain".to_string()],
                            },
                        },
                    ],
                    system_info: SystemInfo {
                        boot_time: "2025-05-08T15:39:01Z".parse().unwrap(), //#[allow_ci]
                    },
                },
            },
        };
        let json = serde_json::to_string_pretty(&request).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{
  "data": {
    "type": "attestation",
    "attributes": {
      "evidence_supported": [
        {
          "evidence_class": "log",
          "evidence_type": "uefi_log",
          "capabilities": {
            "evidence_version": "2.1",
            "entry_count": 20,
            "supports_partial_access": false,
            "appendable": false,
            "formats": [
              "application/octet-stream"
            ]
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "ima_log",
          "capabilities": {
            "entry_count": 20,
            "supports_partial_access": true,
            "appendable": false,
            "formats": [
              "text/plain"
            ]
          }
        }
      ],
      "system_info": {
        "boot_time": "2025-05-08T15:39:01Z"
      }
    }
  }
}"#
        );
        let request = AttestationRequest {
            data: RequestData {
                type_: "attestation".to_string(),
                attributes: Attributes {
                    evidence_supported: vec![
                        EvidenceSupported::Certification {
                            evidence_type: "tpm_quote".to_string(),
                            capabilities: Capabilities {
                                component_version: "2.0".to_string(),
                                hash_algorithms: vec!["sha3_512".to_string()],
                                signature_schemes: vec!["rsassa".to_string()],
                                available_subjects: ShaValues {
                                    sha1: vec![0x01, 0x02, 0x03],
                                    sha256: vec![0x04, 0x05, 0x06],
                                },
                                certification_keys: vec![
                                    CertificationKey {
                                        key_class: "asymmetric".to_string(),
                                        key_size: 2048,
                                        server_identifier: "ak".to_string(),
                                        local_identifier: "att_local_identifier".to_string(),
                                        key_algorithm: "rsa".to_string(),
                                        public: "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth".to_string(),
                                    },
                                ],
                            },
                        },
                        EvidenceSupported::EvidenceLog {
                            evidence_type: "uefi_log".to_string(),
                            capabilities: LogCapabilities {
                                evidence_version: Some("2.1".to_string()),
                                entry_count: 20,
                                supports_partial_access: false,
                                appendable: false,
                                formats: vec!["application/octet-stream".to_string()],
                            },
                        },
                        EvidenceSupported::EvidenceLog {
                            evidence_type: "ima_log".to_string(),
                            capabilities: LogCapabilities {
                                evidence_version: None,
                                entry_count: 20,
                                supports_partial_access: true,
                                appendable: true,
                                formats: vec!["text/plain".to_string()],
                            },
                        },
                    ],
                    system_info: SystemInfo {
                        boot_time: "2025-05-30T11:39:01Z".parse().unwrap(), //#[allow_ci]
                    },
                },
            },
        };
        let json = serde_json::to_string_pretty(&request).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{
  "data": {
    "type": "attestation",
    "attributes": {
      "evidence_supported": [
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
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "uefi_log",
          "capabilities": {
            "evidence_version": "2.1",
            "entry_count": 20,
            "supports_partial_access": false,
            "appendable": false,
            "formats": [
              "application/octet-stream"
            ]
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "ima_log",
          "capabilities": {
            "entry_count": 20,
            "supports_partial_access": true,
            "appendable": true,
            "formats": [
              "text/plain"
            ]
          }
        }
      ],
      "system_info": {
        "boot_time": "2025-05-30T11:39:01Z"
      }
    }
  }
}"#
        );
    }

    #[test]
    fn deserialize_request() {
        // Create a JSON string and deserialize it to an AttestationRequest object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "evidence_supported":[{"evidence_class":"certification",
                                            "evidence_type":"tpm_quote",
                                            "capabilities":{"component_version":"2.0",
                                            "hash_algorithms":["sha3_512"],
                                            "signature_schemes":["rsassa"],
                                            "available_subjects":{"sha1":[1,2,3],
                                                                 "sha256":[4,5,6]},
                                            "certification_keys":[{"key_class":"asymmetric",
                                                                   "local_identifier":"att_local_identifier",
                                                                   "key_algorithm":"rsa",
                                                                   "key_size":2048,
                                                                   "server_identifier":"ak",
                                                                   "public":"OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth"}]}},
                                          {"evidence_class":"log",
                                           "evidence_type":"uefi_log",
                                           "capabilities":{"evidence_version":"2.1",
                                                           "entry_count":20,
                                                           "supports_partial_access":false,
                                                           "appendable":false,
                                                           "formats":["application/octet-stream"]}},
                                          {"evidence_class": "log",
                                           "evidence_type": "ima_log",
                                           "capabilities": {"entry_count": 20,
                                                            "supports_partial_access": true,
                                                            "appendable": true,
                                                            "formats": ["text/plain"]}
                                           }],
                    "system_info":{"boot_time":"2025-05-30 11:39:01 UTC"}
                }
            }
        }"#;
        let request: AttestationRequest = serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(request.data.type_, "attestation");
        let attestation_data = &request.data.attributes; //#[allow_ci]
        let some_evidence_supported =
            attestation_data.evidence_supported.first();
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            EvidenceSupported::Certification {
                evidence_type,
                capabilities,
            } => {
                assert_eq!(evidence_type, "tpm_quote");
                assert_eq!(capabilities.component_version, "2.0");
                assert_eq!(capabilities.hash_algorithms[0], "sha3_512");
                assert_eq!(capabilities.signature_schemes[0], "rsassa");
                assert!(
                    capabilities.available_subjects.sha1
                        == vec![0x01, 0x02, 0x03]
                );
                assert!(
                    capabilities.available_subjects.sha256
                        == vec![0x04, 0x05, 0x06]
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
            _ => panic!("Expected Certification"), //#[allow_ci]
        }
        let some_evidence_supported =
            attestation_data.evidence_supported.get(1);
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            EvidenceSupported::EvidenceLog {
                evidence_type,
                capabilities,
            } => {
                assert_eq!(evidence_type, "uefi_log");
                assert!(capabilities.evidence_version.is_some());
                assert_eq!(
                    capabilities.evidence_version.clone().unwrap(), //#[allow_ci]
                    "2.1"
                );
                assert_eq!(capabilities.entry_count, 20);
                assert!(!capabilities.supports_partial_access);
                assert!(!capabilities.appendable);
                assert_eq!(
                    capabilities.formats[0],
                    "application/octet-stream"
                );
            }
            _ => panic!("Expected Log"), //#[allow_ci]
        }
        let some_evidence_supported =
            attestation_data.evidence_supported.get(2);
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            EvidenceSupported::EvidenceLog {
                evidence_type,
                capabilities,
            } => {
                assert_eq!(evidence_type, "ima_log");
                assert!(capabilities.evidence_version.is_none());
                assert_eq!(capabilities.entry_count, 20);
                assert!(capabilities.supports_partial_access);
                assert!(capabilities.appendable);
                assert_eq!(capabilities.formats[0], "text/plain");
            }
            _ => panic!("Expected Log"), //#[allow_ci]
        }
        assert_eq!(
            request.data.attributes.system_info.boot_time.to_string(),
            "2025-05-30 11:39:01 UTC".to_string()
        );
    }

    #[test]
    fn deserialize_empty_request() {
        // Create a JSON string and deserialize it to an AttestationRequest object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "evidence_supported":[],
                    "system_info":{"boot_time":"2024-11-12 16:21:17 UTC"}
                }
            }
        }"#;
        let request: AttestationRequest = serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(request.data.type_, "attestation");
        let attestation_data = &request.data.attributes; //#[allow_ci]
        let some_evidence_supported =
            attestation_data.evidence_supported.first();
        assert!(some_evidence_supported.is_none());
        assert_eq!(
            request.data.attributes.system_info.boot_time.to_string(),
            "2024-11-12 16:21:17 UTC".to_string()
        );
    }

    #[test]
    fn deserialize_error_request() {
        // Create a JSON string and deserialize it to an AttestationRequest object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "unexpected_evidence_supported":[],
                    "system_info"{"boot_time":"2024-11-12 16:21:17 UTC"}
                }
            }
        }"#;
        // Deserialize the JSON string to an AttestationRequest object and check there is an error
        match serde_json::from_str::<AttestationRequest>(json) {
            Ok(_) => panic!("Expected an error"), //#[allow_ci]
            Err(e) => {
                assert_ne!(e.to_string().len(), 0);
            }
        }
    }

    #[test]
    fn serialize_response() {
        // Create a new AttestationResponse object and serialize it to JSON
        let response = AttestationResponse {
            data: ResponseData {
                type_: "attestation".to_string(),
                attributes: ResponseAttributes {
                    stage : "awaiting_evidence".to_string(),
                    evidence_requested: vec![
                        EvidenceRequested {
                            evidence_class: "certification".to_string(),
                            evidence_type: "tpm_quote".to_string(),
                            chosen_parameters: Some(ChosenParameters::Parameters(Box::new(CertificationParameters {
                                challenge: Some("challenge".to_string()),
                                selected_subjects: Some(ShaValues {
                                    sha1: vec![0x01, 0x02, 0x03],
                                    sha256: vec![0x04, 0x05, 0x06],
                                }),
                                hash_algorithm: Some("sha384".to_string()),
                                signature_scheme: Some("rsassa".to_string()),
                                certification_key: Some(CertificationKey {
                                    key_class: "asymmetric".to_string(),
                                    key_size: 2048,
                                    server_identifier: "ak".to_string(),
                                    local_identifier: "att_local_identifier".to_string(),
                                    key_algorithm: "rsa".to_string(),
                                    public: "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth".to_string(),
                                }),
                            }))),
                        },
                    ],
                },
            },
        };
        let json = serde_json::to_string_pretty(&response).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{
  "data": {
    "type": "attestation",
    "attributes": {
      "stage": "awaiting_evidence",
      "evidence_requested": [
        {
          "evidence_class": "certification",
          "evidence_type": "tpm_quote",
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
          }
        }
      ]
    }
  }
}"#
        );

        let response = AttestationResponse {
            data: ResponseData {
                type_: "attestation".to_string(),
                attributes: ResponseAttributes {
                    stage : "awaiting_evidence".to_string(),
                    evidence_requested: vec![
                        EvidenceRequested {
                            evidence_class: "certification".to_string(),
                            evidence_type: "tpm_quote".to_string(),
                            chosen_parameters: Some(ChosenParameters::Parameters(Box::new(CertificationParameters {
                                challenge: Some("challenge".to_string()),
                                selected_subjects: Some(ShaValues {
                                    sha1: vec![0x01, 0x02, 0x03],
                                    sha256: vec![0x04, 0x05, 0x06],
                                }),
                                hash_algorithm: Some("sha384".to_string()),
                                signature_scheme: Some("rsassa".to_string()),
                                certification_key: Some(CertificationKey {
                                    key_class: "asymmetric".to_string(),
                                    key_size: 2048,
                                    server_identifier: "ak".to_string(),
                                    local_identifier: "att_local_identifier".to_string(),
                                    key_algorithm: "rsa".to_string(),
                                    public: "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth".to_string(),
                                }),
                            }))),
                        },
                        EvidenceRequested {
                            evidence_class: "log".to_string(),
                            evidence_type: "uefi_log".to_string(),
                            chosen_parameters: Some(ChosenParameters::Offset(LogParameters {
                                format: "application/octet-stream".to_string(),
                                starting_offset: None,
                                entry_count: None,
                            })),
                        },
                        EvidenceRequested {
                            evidence_class: "log".to_string(),
                            evidence_type: "ima_log".to_string(),
                            chosen_parameters: Some(ChosenParameters::Offset(LogParameters {
                                entry_count: Some(100),
                                format: "text/plain".to_string(),
                                starting_offset: Some(25),
                            })),
                        },
                    ],
                },
            },
        };
        let json = serde_json::to_string_pretty(&response).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{
  "data": {
    "type": "attestation",
    "attributes": {
      "stage": "awaiting_evidence",
      "evidence_requested": [
        {
          "evidence_class": "certification",
          "evidence_type": "tpm_quote",
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
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "uefi_log",
          "chosen_parameters": {
            "format": "application/octet-stream"
          }
        },
        {
          "evidence_class": "log",
          "evidence_type": "ima_log",
          "chosen_parameters": {
            "entry_count": 100,
            "format": "text/plain",
            "starting_offset": 25
          }
        }
      ]
    }
  }
}"#
        );
    }

    #[test]
    fn deserialize_response() {
        // Create a JSON string and deserialize it to an AttestationResponse object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "stage": "awaiting_evidence",
                "attributes": {
                    "stage": "awaiting_evidence",
                    "evidence_requested":[{"evidence_class":"certification",
                                           "evidence_type":"tpm_quote",
                                           "chosen_parameters": {
                                                "challenge": "challenge",
                                                "hash_algorithm": "sha384",
                                                "signature_scheme": "rsassa",
                                                "selected_subjects": {
                                                    "sha1": [1, 2, 3],
                                                    "sha256": [4, 5, 6]
                                                },
                                                "certification_key": {
                                                    "key_class": "asymmetric",
                                                    "key_algorithm": "rsa",
                                                    "key_size": 2048,
                                                    "server_identifier": "ak",
                                                    "local_identifier": "local_id",
                                                    "public": "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth"
                                                }
                                           }
                                          },
                                          {"evidence_class":"log",
                                           "evidence_type":"uefi_log",
                                           "chosen_parameters": {
                                                "format": "application/octet-stream"
                                           }
                                          },
                                          {"evidence_class":"log",
                                           "evidence_type":"ima_log",
                                           "chosen_parameters": {
                                                "starting_offset": 25,
                                                "entry_count": 100,
                                                "format": "text/plain"
                                           }
                                          }],
                    "system_info":{"boot_time":"2024-11-12T16:21:17Z"}
                }
            }
        }"#;
        let response: AttestationResponse =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(response.data.type_, "attestation");
        assert_eq!(response.data.attributes.stage, "awaiting_evidence");
        assert_eq!(
            response.data.attributes.evidence_requested[0].evidence_class,
            "certification"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[0].evidence_type,
            "tpm_quote"
        );
        let some_chosen_parameters =
            response.data.attributes.evidence_requested[0]
                .chosen_parameters
                .as_ref();
        assert!(some_chosen_parameters.is_some());
        let chosen_parameters = some_chosen_parameters.unwrap(); //#[allow_ci]
        match chosen_parameters {
            ChosenParameters::Parameters(params) => {
                assert_eq!(params.challenge, Some("challenge".to_string()));
                assert_eq!(
                    params.selected_subjects.clone().unwrap().sha1, //#[allow_ci]
                    vec![0x01, 0x02, 0x03]
                );
                assert_eq!(
                    params.selected_subjects.clone().unwrap().sha256, //#[allow_ci]
                    vec![0x04, 0x05, 0x06]
                );
                assert_eq!(params.hash_algorithm, Some("sha384".to_string()));
                assert_eq!(
                    params.signature_scheme,
                    Some("rsassa".to_string())
                );
                let certification_key =
                    params.certification_key.as_ref().unwrap(); //#[allow_ci]
                assert_eq!(certification_key.key_class, "asymmetric");
                assert_eq!(certification_key.local_identifier, "local_id");
                assert_eq!(certification_key.key_algorithm, "rsa");
                assert_eq!(certification_key
                        .public,
                    "OTgtMjkzODQ1LTg5MjMtNDk1OGlrYXNkamZnO2Frc2pka2ZqYXM7a2RqZjtramJrY3hqejk4MS0zMjQ5MDhpLWpmZDth"
                );
            }
            _ => panic!("Expected Parameters"), //#[allow_ci]
        }
        assert_eq!(
            response.data.attributes.evidence_requested[1].evidence_class,
            "log"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[1].evidence_type,
            "uefi_log"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[2].evidence_class,
            "log"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[2].evidence_type,
            "ima_log"
        );
        let some_chosen_parameters =
            response.data.attributes.evidence_requested[2]
                .chosen_parameters
                .as_ref();
        assert!(some_chosen_parameters.is_some());
        let chosen_parameters = some_chosen_parameters.unwrap(); //#[allow_ci]
        match chosen_parameters {
            ChosenParameters::Offset(offset) => {
                assert_eq!(offset.starting_offset, Some(25));
            }
            ChosenParameters::Parameters(_) => {
                panic!("Unexpected Parameters"); //#[allow_ci]
            }
        }
    }

    #[test]
    fn deserialize_error_response() {
        // Create a JSON string and deserialize it to an AttestationResponse object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "stage": "awaiting_evidence",
                    "evidence_requested":[{"evidence_class":"certification",
                                           "evidence_type":"tpm_quote",
                                           "unexpected_chosen_parameters":{"challenge":"challenge"}}],
                    "system_info":{"boot_time":"2024-11-12T16:21:17Z"}
                }
            }
        }"#;
        let response: AttestationResponse =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(response.data.type_, "attestation");
        assert_eq!(response.data.attributes.stage, "awaiting_evidence");
        assert_eq!(
            response.data.attributes.evidence_requested[0].evidence_class,
            "certification"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[0].evidence_type,
            "tpm_quote"
        );
        let some_chosen_parameters =
            response.data.attributes.evidence_requested[0]
                .chosen_parameters
                .as_ref();
        assert!(some_chosen_parameters.is_none());

        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "stage": "awaiting_evidence",
                    "evidence_requested":[{"evidence_class":"certification",
                                           "evidence_type":"tpm_quote",
                                           "chosen_parameters":{"unexpected":"unexpected"}}],
                    "system_info":{"boot_time":"2024-11-12T16:21:17Z"}
                }
            }
        }"#;
        match serde_json::from_str::<AttestationResponse>(json) {
            Ok(_) => panic!("Expected an error"), //#[allow_ci]
            Err(e) => {
                assert_ne!(e.to_string().len(), 0);
            }
        }
    }
}
