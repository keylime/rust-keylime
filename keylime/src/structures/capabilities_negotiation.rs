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
    pub evidence_supported: Vec<EvidenceSupported>,
    pub boot_time: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "evidence_class", rename_all = "snake_case")]
pub enum EvidenceSupported {
    Certification {
        evidence_type: String,
        agent_capabilities: AgentCapabilities,
    },
    FullLog {
        evidence_type: String,
        version: String,
    },
    PartialLog {
        evidence_type: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MbLog {
    evidence_class: String,
    version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImaEntries {
    evidence_class: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AgentCapabilities {
    spec_version: String,
    hash_algorithms: Vec<String>,
    signing_schemes: Vec<String>,
    attestation_keys: Vec<AttestationKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationKey {
    key_class: String,
    key_identifier: String,
    key_algorithm: String,
    public_hash: String,
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
    pub evidence_requested: Vec<EvidenceRequested>,
    pub boot_time: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvidenceRequested {
    pub evidence_class: String,
    pub evidence_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chosen_parameters: Option<ChosenParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpmParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_selection: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_key: Option<AttestationKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StartingOffset {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starting_offset: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(try_from = "JsonValue", into = "JsonValue")]
pub enum ChosenParameters {
    Parameters(TpmParameters),
    Offset(StartingOffset),
}

impl TryFrom<JsonValue> for ChosenParameters {
    type Error = String;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        if let Ok(offset) = from_value::<StartingOffset>(value.clone()) {
            if offset.starting_offset.is_some() {
                return Ok(ChosenParameters::Offset(offset));
            }
        }
        if let Ok(params) = from_value::<TpmParameters>(value) {
            if params.attestation_key.is_some()
                || params.hash_algorithm.is_some()
                || params.nonce.is_some()
                || params.pcr_selection.is_some()
                || params.signing_scheme.is_some()
            {
                return Ok(ChosenParameters::Parameters(params));
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
                            agent_capabilities: AgentCapabilities {
                                spec_version: "2.0".to_string(),
                                hash_algorithms: vec!["sha3_512".to_string()],
                                signing_schemes: vec!["rsassa".to_string()],
                                attestation_keys: vec![
                                    AttestationKey {
                                        key_class: "private_key".to_string(),
                                        key_identifier: "att_key_identifier".to_string(),
                                        key_algorithm: "rsa".to_string(),
                                        public_hash: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411".to_string(),
                                    },
                                ],
                            },
                        },
                    ],
                    boot_time: "2024-11-12T16:21:17Z".to_string(),
                },
            },
        };
        let json = serde_json::to_string(&request).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{"data":{"type":"attestation","attributes":{"evidence_supported":[{"evidence_class":"certification","evidence_type":"tpm_quote","agent_capabilities":{"spec_version":"2.0","hash_algorithms":["sha3_512"],"signing_schemes":["rsassa"],"attestation_keys":[{"key_class":"private_key","key_identifier":"att_key_identifier","key_algorithm":"rsa","public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"}]}}],"boot_time":"2024-11-12T16:21:17Z"}}}"#
        );
        let request = AttestationRequest {
            data: RequestData {
                type_: "attestation".to_string(),
                attributes: Attributes {
                    evidence_supported: vec![
                        EvidenceSupported::FullLog {
                            evidence_type: "mb_log".to_string(),
                            version: "2.1".to_string(),
                        },
                        EvidenceSupported::PartialLog {
                            evidence_type: "ima_entries".to_string(),
                        },
                    ],
                    boot_time: "2024-11-12T16:21:17Z".to_string(),
                },
            },
        };
        let json = serde_json::to_string(&request).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{"data":{"type":"attestation","attributes":{"evidence_supported":[{"evidence_class":"full_log","evidence_type":"mb_log","version":"2.1"},{"evidence_class":"partial_log","evidence_type":"ima_entries"}],"boot_time":"2024-11-12T16:21:17Z"}}}"#
        );
        let request = AttestationRequest {
            data: RequestData {
                type_: "attestation".to_string(),
                attributes: Attributes {
                    evidence_supported: vec![
                        EvidenceSupported::Certification {
                            evidence_type: "tpm_quote".to_string(),
                            agent_capabilities: AgentCapabilities {
                                spec_version: "2.0".to_string(),
                                hash_algorithms: vec!["sha3_512".to_string()],
                                signing_schemes: vec!["rsassa".to_string()],
                                attestation_keys: vec![
                                    AttestationKey {
                                        key_class: "private_key".to_string(),
                                        key_identifier: "att_key_identifier".to_string(),
                                        key_algorithm: "rsa".to_string(),
                                        public_hash: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411".to_string(),
                                    },
                                ],
                            },
                        },
                        EvidenceSupported::FullLog {
                            evidence_type: "mb_log".to_string(),
                            version: "2.1".to_string(),
                        },
                        EvidenceSupported::PartialLog {
                            evidence_type: "ima_entries".to_string(),
                        },
                    ],
                    boot_time: "2025-02-26T:12:32:41".to_string(),
                },
            },
        };
        let json = serde_json::to_string(&request).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{"data":{"type":"attestation","attributes":{"evidence_supported":[{"evidence_class":"certification","evidence_type":"tpm_quote","agent_capabilities":{"spec_version":"2.0","hash_algorithms":["sha3_512"],"signing_schemes":["rsassa"],"attestation_keys":[{"key_class":"private_key","key_identifier":"att_key_identifier","key_algorithm":"rsa","public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"}]}},{"evidence_class":"full_log","evidence_type":"mb_log","version":"2.1"},{"evidence_class":"partial_log","evidence_type":"ima_entries"}],"boot_time":"2025-02-26T:12:32:41"}}}"#
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
                                            "agent_capabilities":{"spec_version":"2.0",
                                            "hash_algorithms":["sha3_512"],
                                            "signing_schemes":["rsassa"],
                                            "attestation_keys":[{"key_class":"private_key","key_identifier":"att_key_identifier",
                                                                "key_algorithm":"rsa",
                                                                "public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"}]}},
                                          {"evidence_class":"full_log",
                                           "evidence_type":"mb_log",
                                           "version":"2.1"},
                                          {"evidence_class": "partial_log",
                                           "evidence_type": "ima_entries"}],
                    "boot_time":"2024-11-12T16:21:17Z"
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
                agent_capabilities,
            } => {
                assert_eq!(evidence_type, "tpm_quote");
                assert_eq!(agent_capabilities.spec_version, "2.0");
                assert_eq!(agent_capabilities.hash_algorithms[0], "sha3_512");
                assert_eq!(agent_capabilities.signing_schemes[0], "rsassa");
                let some_attestation_keys =
                    agent_capabilities.attestation_keys.first();
                assert!(some_attestation_keys.is_some());
                let attestation_key = some_attestation_keys.unwrap(); //#[allow_ci]
                assert_eq!(attestation_key.key_class, "private_key");
                assert_eq!(
                    attestation_key.key_identifier,
                    "att_key_identifier"
                );
                assert_eq!(attestation_key.key_algorithm, "rsa");
                assert_eq!(attestation_key.public_hash, "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411");
            }
            _ => panic!("Expected Certification"), //#[allow_ci]
        }
        let some_evidence_supported =
            attestation_data.evidence_supported.get(1);
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            EvidenceSupported::FullLog {
                evidence_type,
                version,
            } => {
                assert_eq!(evidence_type, "mb_log");
                assert_eq!(version, "2.1");
            }
            _ => panic!("Expected FullLog"), //#[allow_ci]
        }
        let some_evidence_supported =
            attestation_data.evidence_supported.get(2);
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            EvidenceSupported::PartialLog { evidence_type } => {
                assert_eq!(evidence_type, "ima_entries");
            }
            _ => panic!("Expected PartialLog"), //#[allow_ci]
        }
        assert_eq!(request.data.attributes.boot_time, "2024-11-12T16:21:17Z");
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
                    "boot_time":"2024-11-12T16:21:17Z"
                }
            }
        }"#;
        let request: AttestationRequest = serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(request.data.type_, "attestation");
        let attestation_data = &request.data.attributes; //#[allow_ci]
        let some_evidence_supported =
            attestation_data.evidence_supported.first();
        assert!(some_evidence_supported.is_none());
        assert_eq!(request.data.attributes.boot_time, "2024-11-12T16:21:17Z");
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
                    "boot_time":"2024-11-12T16:21:17Z"
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
                    evidence_requested: vec![
                        EvidenceRequested {
                            evidence_class: "certification".to_string(),
                            evidence_type: "tpm_quote".to_string(),
                            chosen_parameters: Some(ChosenParameters::Parameters(TpmParameters {
                                nonce: Some("nonce".to_string()),
                                pcr_selection: Some(vec![0]),
                                hash_algorithm: Some("sha384".to_string()),
                                signing_scheme: Some("rsassa".to_string()),
                                attestation_key: Some(AttestationKey {
                                    key_class: "private_key".to_string(),
                                    key_identifier: "att_key_identifier".to_string(),
                                    key_algorithm: "rsa".to_string(),
                                    public_hash: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411".to_string(),
                                }),
                            })),
                            version: None,
                        },
                    ],
                    boot_time: "2024-11-12T16:21:17Z".to_string(),
                },
            },
        };
        let json = serde_json::to_string(&response).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{"data":{"type":"attestation","attributes":{"evidence_requested":[{"evidence_class":"certification","evidence_type":"tpm_quote","chosen_parameters":{"attestation_key":{"key_algorithm":"rsa","key_class":"private_key","key_identifier":"att_key_identifier","public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"},"hash_algorithm":"sha384","nonce":"nonce","pcr_selection":[0],"signing_scheme":"rsassa"}}],"boot_time":"2024-11-12T16:21:17Z"}}}"#
        );

        let response = AttestationResponse {
            data: ResponseData {
                type_: "attestation".to_string(),
                attributes: ResponseAttributes {
                    evidence_requested: vec![
                        EvidenceRequested {
                            evidence_class: "certification".to_string(),
                            evidence_type: "tpm_quote".to_string(),
                            chosen_parameters: Some(ChosenParameters::Parameters(TpmParameters {
                                nonce: Some("nonce".to_string()),
                                pcr_selection: Some(vec![0]),
                                hash_algorithm: Some("sha384".to_string()),
                                signing_scheme: Some("rsassa".to_string()),
                                attestation_key: Some(AttestationKey {
                                    key_class: "private_key".to_string(),
                                    key_identifier: "att_key_identifier".to_string(),
                                    key_algorithm: "rsa".to_string(),
                                    public_hash: "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411".to_string(),
                                }),
                            })),
                            version: None,
                        },
                        EvidenceRequested {
                            evidence_class: "full_log".to_string(),
                            evidence_type: "mb_log".to_string(),
                            chosen_parameters: None,
                            version: Some("2.1".to_string()),
                        },
                        EvidenceRequested {
                            evidence_class: "partial_log".to_string(),
                            evidence_type: "ima_entries".to_string(),
                            chosen_parameters: Some(ChosenParameters::Offset(StartingOffset {
                                starting_offset: Some(25),
                            })),
                            version: None,
                        },
                    ],
                    boot_time: "2024-11-12T16:21:17Z".to_string(),
                },
            },
        };
        let json = serde_json::to_string(&response).unwrap(); //#[allow_ci]
        assert_eq!(
            json,
            r#"{"data":{"type":"attestation","attributes":{"evidence_requested":[{"evidence_class":"certification","evidence_type":"tpm_quote","chosen_parameters":{"attestation_key":{"key_algorithm":"rsa","key_class":"private_key","key_identifier":"att_key_identifier","public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"},"hash_algorithm":"sha384","nonce":"nonce","pcr_selection":[0],"signing_scheme":"rsassa"}},{"evidence_class":"full_log","evidence_type":"mb_log","version":"2.1"},{"evidence_class":"partial_log","evidence_type":"ima_entries","chosen_parameters":{"starting_offset":25}}],"boot_time":"2024-11-12T16:21:17Z"}}}"#
        );
    }

    #[test]
    fn deserialize_response() {
        // Create a JSON string and deserialize it to an AttestationResponse object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "evidence_requested":[{"evidence_class":"certification",
                                           "evidence_type":"tpm_quote",
                                           "chosen_parameters":{"nonce":"nonce",
                                                                "pcr_selection":[0],
                                                                "hash_algorithm":"sha384",
                                                                "signing_scheme":"rsassa",
                                                                "attestation_key":{"key_class":"private_key",
                                                                                    "key_identifier":"att_key_identifier",
                                                                                    "key_algorithm":"rsa",
                                                                                    "public_hash":"cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"}}},
                                          {"evidence_class": "full_log",
                                           "evidence_type": "mb_log",
                                           "version": "2.1"},
                                          {"evidence_class": "partial_log",
                                           "evidence_type": "ima_entries",
                                           "chosen_parameters": {"starting_offset": 25}}],
                     "boot_time":"2024-11-12T16:21:17Z"
                }
            }
        }"#;
        let response: AttestationResponse =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(response.data.type_, "attestation");
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
                assert_eq!(params.nonce, Some("nonce".to_string()));
                assert_eq!(params.pcr_selection.as_ref().unwrap()[0], 0); //#[allow_ci]
                assert_eq!(params.hash_algorithm, Some("sha384".to_string()));
                assert_eq!(params.signing_scheme, Some("rsassa".to_string()));
                let attestation_key =
                    params.attestation_key.as_ref().unwrap(); //#[allow_ci]
                assert_eq!(attestation_key.key_class, "private_key");
                assert_eq!(
                    attestation_key.key_identifier,
                    "att_key_identifier"
                );
                assert_eq!(attestation_key.key_algorithm, "rsa");
                assert_eq!(attestation_key
                        .public_hash,
                    "cd293be6cea034bd45a0352775a219ef5dc7825ce55d1f7dae9762d80ce64411"
                );
            }
            _ => panic!("Expected Parameters"), //#[allow_ci]
        }
        assert_eq!(
            response.data.attributes.evidence_requested[1].evidence_class,
            "full_log"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[1].evidence_type,
            "mb_log"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[1].version,
            Some("2.1".to_string())
        );
        assert_eq!(
            response.data.attributes.evidence_requested[2].evidence_class,
            "partial_log"
        );
        assert_eq!(
            response.data.attributes.evidence_requested[2].evidence_type,
            "ima_entries"
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
        assert_eq!(
            response.data.attributes.boot_time,
            "2024-11-12T16:21:17Z"
        );
    }

    #[test]
    fn deserialize_error_response() {
        // Create a JSON string and deserialize it to an AttestationResponse object
        let json = r#"
        {
            "data": {
                "type":"attestation",
                "attributes": {
                    "evidence_requested":[{"evidence_class":"certification",
                                           "evidence_type":"tpm_quote",
                                           "unexpected_chosen_parameters":{"nonce":"nonce"}}],
                     "boot_time":"2024-11-12T16:21:17Z"
                }
            }
        }"#;
        let response: AttestationResponse =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(response.data.type_, "attestation");
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
                    "evidence_requested":[{"evidence_class":"certification",
                                           "evidence_type":"tpm_quote",
                                           "chosen_parameters":{"unexpected":"unexpected"}}],
                    "boot_time":"2025-02-26T13:01:17Z"
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
