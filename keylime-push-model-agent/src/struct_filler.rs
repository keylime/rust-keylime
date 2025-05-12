// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use keylime::structures;

// Implement a structure filler for the attestation request
// by using polimorphism and traits, with next options:
// 1. Use a trait to define the structure filler interface
// 2. Implement the trait for the attestation request structure
// 3. Use the trait to fill the structure with data from code
// 4. Use the trait to fill the structure with data from a file
// 5. Use the trait to fill the structure with data from real TPM quote
pub trait StructureFiller {
    fn get_attestation_request(&self) -> structures::AttestationRequest;
    fn get_session_request(&self) -> structures::SessionRequest;
    fn get_evidence_handling_request(
        &self,
    ) -> structures::EvidenceHandlingRequest;
}

pub struct FillerFromCode;
impl StructureFiller for FillerFromCode {
    fn get_attestation_request(&self) -> structures::AttestationRequest {
        get_attestation_request_from_code()
    }
    fn get_session_request(&self) -> structures::SessionRequest {
        get_session_request_from_code()
    }
    fn get_evidence_handling_request(
        &self,
    ) -> structures::EvidenceHandlingRequest {
        get_evidence_handling_request_from_code()
    }
}

pub struct FillerFromFile {
    pub file_path: String,
}

impl StructureFiller for FillerFromFile {
    fn get_attestation_request(&self) -> structures::AttestationRequest {
        get_attestation_request_from_file(self.file_path.clone())
    }
    fn get_session_request(&self) -> structures::SessionRequest {
        get_session_request_from_file(self.file_path.clone())
    }
    fn get_evidence_handling_request(
        &self,
    ) -> structures::EvidenceHandlingRequest {
        get_evidence_handling_request_from_file(self.file_path.clone())
    }
}

fn get_attestation_request_from_file(
    json_file: String,
) -> structures::AttestationRequest {
    let reader =
        std::io::BufReader::new(std::fs::File::open(json_file).unwrap());
    serde_json::from_reader(reader).unwrap()
}

fn get_session_request_from_file(
    json_file: String,
) -> structures::SessionRequest {
    let reader =
        std::io::BufReader::new(std::fs::File::open(json_file).unwrap());
    serde_json::from_reader(reader).unwrap()
}

fn get_evidence_handling_request_from_file(
    json_file: String,
) -> structures::EvidenceHandlingRequest {
    let reader =
        std::io::BufReader::new(std::fs::File::open(json_file).unwrap());
    serde_json::from_reader(reader).unwrap()
}

fn get_attestation_request_from_code() -> structures::AttestationRequest {
    structures::AttestationRequest {
        data: structures::RequestData {
            type_: "attestation".to_string(),
            attributes: structures::Attributes {
                evidence_supported: vec![
                    structures::EvidenceSupported::Certification {
                        evidence_type: "tpm_quote".to_string(),
                        capabilities: structures::Capabilities {
                            component_version: "2.0".to_string(),
                            hash_algorithms: vec!["sha3_512".to_string()],
                            signature_schemes: vec!["rsassa".to_string()],
                            available_subjects: structures::ShaValues {
                                sha1: vec![0x04, 0x05, 0x06],
                                sha256: vec![0x01, 0x02, 0x03],
                            },
                            certification_keys: vec![
                                structures::CertificationKey {
                                    local_identifier: "localid".to_string(),
                                    key_algorithm: "rsa".to_string(),
                                    key_class: "asymmetric".to_string(),
                                    key_size: 2048,
                                    server_identifier: "ak".to_string(),
                                    public: "VGhpcyBpcyBhIHRlc3QgZm9yIGEgYmFzZTY0IGVuY29kZWQgZm9ybWF0IHN0cmluZw==".to_string(),
                                },
                            ],
                        },
                    },
                ],
                system_info: structures::SystemInfo {
                    boot_time: "2024-11-12T16:21:17Z".to_string(),
                },
            },
        },
    }
}

fn get_session_request_from_code() -> structures::SessionRequest {
    structures::SessionRequest {
        data: structures::SessionRequestData {
            data_type: "session".to_string(),
            attributes: structures::SessionRequestAttributes {
                agent_id: "example-agent".to_string(),
                auth_supported: vec![
                    structures::SessionRequestAuthSupported {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                    },
                ],
            },
        },
    }
}

fn get_evidence_handling_request_from_code(
) -> structures::EvidenceHandlingRequest {
    let tpm_evidence_data = structures::EvidenceData::TpmQuoteData {
        subject_data: "subject_data".to_string(),
        message: "message".to_string(),
        signature: "signature".to_string(),
    };

    let tpm_evidence_collected = structures::EvidenceCollected {
        evidence_class: "certification".to_string(),
        evidence_type: "tpm_quote".to_string(),
        data: tpm_evidence_data,
    };
    let uefi_evidence_data = structures::EvidenceData::UefiLog {
        entries: "uefi_log_entries".to_string(),
    };
    let uefi_evidence_collected = structures::EvidenceCollected {
        evidence_class: "log".to_string(),
        evidence_type: "uefi_log".to_string(),
        data: uefi_evidence_data,
    };
    let ima_evidence_data = structures::EvidenceData::ImaLog {
        entry_count: 95,
        entries: "ima_log_entries".to_string(),
    };
    let ima_evidence_collected = structures::EvidenceCollected {
        evidence_class: "log".to_string(),
        evidence_type: "ima_log".to_string(),
        data: ima_evidence_data,
    };
    let attributes = structures::EvidenceHandlingRequestAttributes {
        evidence_collected: vec![
            tpm_evidence_collected,
            uefi_evidence_collected,
            ima_evidence_collected,
        ],
    };
    let data = structures::EvidenceHandlingRequestData {
        data_type: "attestation".to_string(),
        attributes,
    };
    structures::EvidenceHandlingRequest { data }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn get_attestation_request_test() {
        let req = get_attestation_request_from_code();
        assert_eq!(req.data.type_, "attestation");
        assert_eq!(req.data.attributes.evidence_supported.len(), 1);
        let some_evidence_supported =
            req.data.attributes.evidence_supported.first();
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            structures::EvidenceSupported::Certification {
                evidence_type,
                capabilities,
            } => {
                assert_eq!(evidence_type, "tpm_quote");
                assert_eq!(capabilities.component_version, "2.0");
                assert_eq!(capabilities.hash_algorithms[0], "sha3_512");
                assert_eq!(capabilities.signature_schemes[0], "rsassa");
                assert!(
                    capabilities.available_subjects.sha1
                        == vec![0x04, 0x05, 0x06]
                );
                assert!(
                    capabilities.available_subjects.sha256
                        == vec![0x01, 0x02, 0x03]
                );
                let some_certification_keys =
                    capabilities.certification_keys.first();
                assert!(some_certification_keys.is_some());
                let certification_key = some_certification_keys.unwrap(); //#[allow_ci]
                assert_eq!(certification_key.local_identifier, "localid");
                assert_eq!(certification_key.key_algorithm, "rsa");
                assert_eq!(certification_key.key_size, 2048);
                assert_eq!(certification_key.server_identifier, "ak");
                assert_eq!(certification_key.public, "VGhpcyBpcyBhIHRlc3QgZm9yIGEgYmFzZTY0IGVuY29kZWQgZm9ybWF0IHN0cmluZw==");
            }
            _ => panic!("Expected Certification"), //#[allow_ci]
        }
    }

    #[test]
    fn get_attestation_request_filler_from_code_test() {
        let req = FillerFromCode.get_attestation_request();
        assert_eq!(req.data.type_, "attestation");
        assert_eq!(req.data.attributes.evidence_supported.len(), 1);
        let some_evidence_supported =
            req.data.attributes.evidence_supported.first();
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            structures::EvidenceSupported::Certification {
                evidence_type,
                capabilities,
            } => {
                assert_eq!(evidence_type, "tpm_quote");
                assert_eq!(capabilities.component_version, "2.0");
                assert_eq!(capabilities.hash_algorithms[0], "sha3_512");
                assert_eq!(capabilities.signature_schemes[0], "rsassa");
                assert!(
                    capabilities.available_subjects.sha1
                        == vec![0x04, 0x05, 0x06]
                );
                assert!(
                    capabilities.available_subjects.sha256
                        == vec![0x01, 0x02, 0x03]
                );
                let some_certification_keys =
                    capabilities.certification_keys.first();
                assert!(some_certification_keys.is_some());
                let certification_key = some_certification_keys.unwrap(); //#[allow_ci]
                assert_eq!(certification_key.local_identifier, "localid");
                assert_eq!(certification_key.key_algorithm, "rsa");
                assert_eq!(certification_key.key_size, 2048);
                assert_eq!(certification_key.server_identifier, "ak");
                assert_eq!(certification_key.public, "VGhpcyBpcyBhIHRlc3QgZm9yIGEgYmFzZTY0IGVuY29kZWQgZm9ybWF0IHN0cmluZw==");
            }
            _ => panic!("Expected Certification"), //#[allow_ci]
        }
    }

    #[test]
    fn get_attestation_request_from_file_test() {
        let req = FillerFromFile {
            file_path:
                "test-data/evidence_supported_attestation_request.json"
                    .to_string(),
        }
        .get_attestation_request();

        assert_eq!(req.data.type_, "attestation");
        assert_eq!(req.data.attributes.evidence_supported.len(), 3);
        let some_evidence_supported =
            req.data.attributes.evidence_supported.first();
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            structures::EvidenceSupported::Certification {
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
                assert_eq!(
                    certification_key.local_identifier,
                    "att_local_identifier"
                );
                assert_eq!(certification_key.key_algorithm, "rsa");
                assert_eq!(certification_key.key_size, 2048);
                assert_eq!(certification_key.server_identifier, "ak");
                assert_eq!(certification_key.public, "VGhpcyBpcyBhIHRlc3QgZm9yIGEgYmFzZTY0IGVuY29kZWQgZm9ybWF0IHN0cmluZw==");
            }
            _ => panic!("Expected Certification"), //#[allow_ci]
        }

        let some_evidence_supported =
            req.data.attributes.evidence_supported.get(1);
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            structures::EvidenceSupported::EvidenceLog {
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
            req.data.attributes.evidence_supported.get(2);
        assert!(some_evidence_supported.is_some());
        let evidence_supported = some_evidence_supported.unwrap(); //#[allow_ci]
        match evidence_supported {
            structures::EvidenceSupported::EvidenceLog {
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
            req.data.attributes.system_info.boot_time,
            "2025-04-02T12:12:51Z"
        );
    }

    #[test]
    fn get_evidence_handling_request_from_file_test() {
        let deserialized = FillerFromFile {
            file_path: "test-data/evidence_handling_request.json".to_string(),
        }
        .get_evidence_handling_request();

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
        if let structures::EvidenceData::TpmQuoteData {
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
        if let structures::EvidenceData::UefiLog { entries } =
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
        if let structures::EvidenceData::ImaLog {
            entry_count,
            entries,
        } = &deserialized.data.attributes.evidence_collected[2].data
        {
            assert_eq!(*entry_count, 96);
            assert_eq!(entries, "ima_log_entries_deserialized");
        } else {
            panic!("Expected ImaLog"); //#[allow_ci]
        }
    }

    #[test]
    fn get_authentication_request_from_file_test() {
        let deserialized = FillerFromFile {
            file_path: "test-data/session_request.json".to_string(),
        }
        .get_session_request();
        assert_eq!(deserialized.data.data_type, "session");
        assert_eq!(deserialized.data.attributes.agent_id, "example-agent");
        assert_eq!(deserialized.data.attributes.auth_supported.len(), 1);
        assert_eq!(
            deserialized.data.attributes.auth_supported[0].auth_class,
            "pop"
        );
        assert_eq!(
            deserialized.data.attributes.auth_supported[0].auth_type,
            "tpm_pop"
        );
    } // get_authentication_request_from_file_test
}
