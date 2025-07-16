// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use async_trait::async_trait;
use keylime::algorithms::HashAlgorithm;
use keylime::config::{AgentConfig, PushModelConfigTrait};
use keylime::context_info::{AttestationRequiredParams, ContextInfo};
use keylime::ima::ImaLog;
use keylime::structures;
use keylime::uefi::uefi_log_handler;
use log::{debug, error};

#[async_trait]
pub trait StructureFiller {
    fn get_attestation_request(&mut self) -> structures::AttestationRequest;
    #[allow(dead_code)]
    fn get_session_request(&mut self) -> structures::SessionRequest;
    async fn get_evidence_handling_request(
        &mut self,
        params: &AttestationRequiredParams,
    ) -> structures::EvidenceHandlingRequest;
}

pub fn get_filler_request<'a>(
    json_file: Option<String>,
    tpm_context_info: Option<&'a mut ContextInfo>,
) -> Box<dyn StructureFiller + 'a> {
    if json_file.is_none() {
        if tpm_context_info.is_none() {
            return Box::new(FillerFromCode);
        }
        return Box::new(FillerFromHardware::new(tpm_context_info.unwrap()));
    }
    Box::new(FillerFromFile {
        file_path: json_file.clone().unwrap(),
    })
}

#[async_trait]
impl StructureFiller for FillerFromHardware<'_> {
    fn get_attestation_request(&mut self) -> structures::AttestationRequest {
        self.get_attestation_request_final()
    }
    fn get_session_request(&mut self) -> structures::SessionRequest {
        self.get_session_request_final()
    }
    async fn get_evidence_handling_request(
        &mut self,
        params: &AttestationRequiredParams,
    ) -> structures::EvidenceHandlingRequest {
        self.get_evidence_handling_request_final(params).await
    }
}

pub struct FillerFromHardware<'a> {
    pub tpm_context_info: &'a mut ContextInfo,
    pub uefi_log_handler: Option<uefi_log_handler::UefiLogHandler>,
}

impl<'a> FillerFromHardware<'a> {
    pub fn new(tpm_context_info: &'a mut ContextInfo) -> Self {
        // TODO: Change this to avoid loading the configuration multiple times
        // TODO: Modify here to avoid panic on failure
        let config =
            AgentConfig::new().expect("failed to load configuration");
        let ml_path = config.measuredboot_ml_path();
        let uefi_log_handler = uefi_log_handler::UefiLogHandler::new(ml_path);
        match uefi_log_handler {
            Ok(handler) => FillerFromHardware {
                tpm_context_info,
                uefi_log_handler: Some(handler),
            },
            Err(e) => {
                error!("Failed to create UEFI log handler: {e:?}");
                FillerFromHardware {
                    tpm_context_info,
                    uefi_log_handler: None,
                }
            }
        }
    }
    // TODO: Change this function to use the attestation request appropriately
    // Add self to the function signature to use the tpm_context
    fn get_attestation_request_final(
        &mut self,
    ) -> structures::AttestationRequest {
        // TODO: Change this to avoid loading the configuration multiple times
        // TODO Modify this to not panic on failure
        let config =
            AgentConfig::new().expect("failed to load configuration");

        // Get all supported hash algorithms from the TPM
        let supported_algorithms = self
            .tpm_context_info
            .get_supported_hash_algorithms()
            .unwrap_or_else(|_| {
                error!("Failed to get supported hash algorithms");
                vec![]
            });

        let tpmc_ref = self.tpm_context_info.get_mutable_tpm_context();

        // Build PCR banks for all supported algorithms
        let mut pcr_banks_builder = structures::PcrBanks::builder();

        for algorithm_str in supported_algorithms {
            // Convert string to HashAlgorithm enum
            if let Ok(algorithm) =
                HashAlgorithm::try_from(algorithm_str.as_str())
            {
                let banks =
                    tpmc_ref.pcr_banks(algorithm).unwrap_or_else(|_| {
                        error!("Failed to get PCR banks for {algorithm:?}");
                        vec![]
                    });

                pcr_banks_builder = match algorithm {
                    HashAlgorithm::Sha1 => pcr_banks_builder.sha1(banks),
                    HashAlgorithm::Sha256 => pcr_banks_builder.sha256(banks),
                    HashAlgorithm::Sha384 => pcr_banks_builder.sha384(banks),
                    HashAlgorithm::Sha512 => pcr_banks_builder.sha512(banks),
                    HashAlgorithm::Sm3_256 => {
                        pcr_banks_builder.sm3_256(banks)
                    }
                };
            } else {
                error!("Unsupported hash algorithm: {algorithm_str}");
            }
        }

        let ima_log_parser = ImaLog::new(config.ima_ml_path.as_str());
        let ima_log_count = match ima_log_parser {
            Ok(ima_log) => ima_log.entry_count(),
            Err(e) => {
                error!("Failed to read IMA log: {e:?}");
                0
            }
        };
        let uefi_count = self
            .uefi_log_handler
            .as_ref()
            .map_or(0, |handler| handler.get_entry_count());
        structures::AttestationRequest {
            data: structures::RequestData {
                type_: "attestation".to_string(),
                attributes: structures::Attributes {
                    evidence_supported: vec![
                        structures::EvidenceSupported::Certification {
                            evidence_type: "tpm_quote".to_string(),
                            capabilities: structures::Capabilities {
                                component_version: "2.0".to_string(),
                                hash_algorithms: self.tpm_context_info.get_supported_hash_algorithms().expect(
                                    "Failed to get supported hash algorithms"
                                ),
                                signature_schemes: self.tpm_context_info.get_supported_signing_schemes().expect(
                                    "Failed to get supported signing schemes"
                                ),
                                available_subjects: pcr_banks_builder.build(),
                                certification_keys: vec![
                                    self.tpm_context_info.get_ak_certification_data().expect(
                                        "Failed to get AK certification data"
                                    ),
                                ],
                            },
                        },
                        structures::EvidenceSupported::EvidenceLog {
                            evidence_type: "uefi_log".to_string(),
                            capabilities: structures::LogCapabilities {
                                evidence_version: Some(config.uefi_logs_evidence_version().to_string()),
                                entry_count: uefi_count,
                                supports_partial_access: config.uefi_logs_supports_partial_access(),
                                appendable: config.uefi_logs_appendable(),
                                // TODO: make this to not panic on failure
                                formats: config.uefi_logs_formats().expect("failed to get uefi_logs_formats").iter().map(|e| e.to_string()).collect(),
                            },
                        },
                        structures::EvidenceSupported::EvidenceLog {
                            evidence_type: "ima_log".to_string(),
                            capabilities: structures::LogCapabilities {
                                evidence_version: None,
                                entry_count: ima_log_count,
                                supports_partial_access: config.ima_logs_supports_partial_access(),
                                appendable: config.ima_logs_appendable(),
                                // TODO: make this to not panic on failure
                                formats: config.ima_logs_formats().expect("failed to get ima_log_formats").iter().map(|e| e.to_string()).collect(),
                            },
                        },
                    ],
                    system_info: structures::SystemInfo {
                        boot_time: chrono::Utc::now(),
                    },
                },
            },
        }
    }

    // TODO: Change this function to use the session request appropriately
    pub fn get_session_request_final(
        &mut self,
    ) -> structures::SessionRequest {
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

    pub async fn get_evidence_handling_request_final(
        &mut self,
        params: &AttestationRequiredParams,
    ) -> structures::EvidenceHandlingRequest {
        let evidence =
            match self.tpm_context_info.perform_attestation(params).await {
                Ok(evidence) => evidence,
                Err(e) => {
                    error!("Failed to perform attestation: {e}");
                    return structures::EvidenceHandlingRequest {
                    data: structures::EvidenceHandlingRequestData {
                        data_type: "error".to_string(),
                        attributes:
                            structures::EvidenceHandlingRequestAttributes {
                                evidence_collected: vec![],
                            },
                    },
                };
                }
            };

        let tpm_evidence_data = structures::EvidenceData::TpmQuoteData {
            subject_data: evidence.pcr_values,
            message: evidence.quote_message,
            signature: evidence.quote_signature,
        };

        let tpm_evidence_collected = structures::EvidenceCollected {
            evidence_class: "certification".to_string(),
            evidence_type: "tpm_quote".to_string(),
            data: tpm_evidence_data,
        };

        let uefi_evidence_data = structures::EvidenceData::UefiLog {
            entries: evidence.uefi_log,
        };
        let uefi_evidence_collected = structures::EvidenceCollected {
            evidence_class: "log".to_string(),
            evidence_type: "uefi_log".to_string(),
            data: uefi_evidence_data,
        };

        let ima_entry_count = match params.ima_entry_count {
            Some(count) => count,
            None => {
                debug!("IMA entry count is not provided");
                0
            }
        };
        debug!(
            "IMA information: path:{}, entry_count:{}",
            params
                .ima_log_path
                .clone()
                .unwrap_or("PATH_NOT_SET".to_string()),
            ima_entry_count
        );
        debug!("IMA log entries: {}", evidence.ima_log_entries);
        let ima_evidence_data = structures::EvidenceData::ImaLog {
            entry_count: ima_entry_count,
            entries: evidence.ima_log_entries,
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
}

pub struct FillerFromCode;
#[async_trait]
impl StructureFiller for FillerFromCode {
    fn get_attestation_request(&mut self) -> structures::AttestationRequest {
        get_attestation_request_from_code()
    }
    fn get_session_request(&mut self) -> structures::SessionRequest {
        get_session_request_from_code()
    }
    #[allow(unused_variables)]
    async fn get_evidence_handling_request(
        &mut self,
        params: &AttestationRequiredParams,
    ) -> structures::EvidenceHandlingRequest {
        get_evidence_handling_request_from_code()
    }
}

pub struct FillerFromFile {
    pub file_path: String,
}

#[async_trait]
impl StructureFiller for FillerFromFile {
    fn get_attestation_request(&mut self) -> structures::AttestationRequest {
        get_attestation_request_from_file(self.file_path.clone())
    }
    fn get_session_request(&mut self) -> structures::SessionRequest {
        get_session_request_from_file(self.file_path.clone())
    }
    #[allow(unused_variables)]
    async fn get_evidence_handling_request(
        &mut self,
        params: &AttestationRequiredParams,
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
                            available_subjects: structures::PcrBanks::builder()
                                .sha1(vec![0x04, 0x05, 0x06])
                                .sha256(vec![0x01, 0x02, 0x03])
                                .build(),
                            certification_keys: vec![
                                structures::CertificationKey {
                                    local_identifier: "localid".to_string(),
                                    key_algorithm: "rsa".to_string(),
                                    key_class: "asymmetric".to_string(),
                                    key_size: 2048,
                                    server_identifier: "ak".to_string(),
                                    public: "VGhpcyBpcyBhIHRlc3QgZm9yIGEgYmFzZTY0IGVuY29kZWQgZm9ybWF0IHN0cmluZw==".to_string(),
                                    allowable_hash_algorithms: None,
                                    allowable_signature_schemes: None,
                                },
                            ],
                        },
                    },
                ],
                system_info: structures::SystemInfo {
                    boot_time: "2024-11-12T16:21:17Z".parse().unwrap(),
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

    #[cfg(feature = "testing")]
    use keylime::{context_info, tpm::testing};

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
                        == Some(vec![0x04, 0x05, 0x06])
                );
                assert!(
                    capabilities.available_subjects.sha256
                        == Some(vec![0x01, 0x02, 0x03])
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
                        == Some(vec![0x04, 0x05, 0x06])
                );
                assert!(
                    capabilities.available_subjects.sha256
                        == Some(vec![0x01, 0x02, 0x03])
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
                        == Some(vec![0x01, 0x02, 0x03])
                );
                assert!(
                    capabilities.available_subjects.sha256
                        == Some(vec![0x04, 0x05, 0x06])
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
            req.data.attributes.system_info.boot_time.to_string(),
            "2025-04-02 12:12:51 UTC"
        );
    }

    #[actix_rt::test]
    async fn get_evidence_handling_request_from_file_test() {
        let deserialized = FillerFromFile {
            file_path: "test-data/evidence_handling_request.json".to_string(),
        }
        .get_evidence_handling_request(&AttestationRequiredParams {
            challenge: "".to_string(),
            signature_scheme: "".to_string(),
            hash_algorithm: "".to_string(),
            selected_subjects: std::collections::HashMap::new(),
            ima_offset: 0,
            ima_entry_count: Some(0),
            ima_log_path: None,
            uefi_log_path: None,
        })
        .await;

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

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_attestation_request_final() {
        let _mutex = testing::lock_tests().await;
        let mut context_info = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
                disabled_signing_algorithms: vec![],
            },
        )
        .expect("Failed to create context info from string");
        let mut filler = FillerFromHardware::new(&mut context_info);
        let attestation_request = filler.get_attestation_request_final();
        assert_eq!(attestation_request.data.type_, "attestation");
        let serialized = serde_json::to_string(&attestation_request).unwrap();
        assert!(!serialized.is_empty());
        assert!(context_info.flush_context().is_ok());
    } // test_attestation_request

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_session_request() {
        use keylime::context_info;
        let _mutex = testing::lock_tests().await;
        let mut context_info = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
                disabled_signing_algorithms: vec![],
            },
        )
        .expect("Failed to create context info from string");
        let mut filler = FillerFromHardware::new(&mut context_info);
        let session_request = filler.get_session_request();
        assert_eq!(session_request.data.data_type, "session");
        let serialized = serde_json::to_string(&session_request).unwrap();
        assert!(!serialized.is_empty());
        assert!(context_info.flush_context().is_ok());
    } // test_session_request

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_evidence_handling_request() {
        use keylime::context_info;
        use std::collections::HashMap;
        let _mutex = testing::lock_tests().await;
        let mut context_info = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
                disabled_signing_algorithms: vec![],
            },
        )
        .expect("Failed to create context info from string");
        let mut filler = FillerFromHardware::new(&mut context_info);
        let mut subjects = HashMap::new();
        subjects.insert("sha256".to_string(), vec![10]);
        let params = AttestationRequiredParams {
            challenge: "test_challenge".to_string(),
            signature_scheme: "rsassa".to_string(),
            hash_algorithm: "sha256".to_string(),
            selected_subjects: subjects,
            ima_log_path: Some("test-data/ima_log.txt".to_string()),
            ima_offset: 0,
            ima_entry_count: Some(1),
            uefi_log_path: Some("test-data/uefi_log.bin".to_string()),
        };
        let evidence_handling_request =
            filler.get_evidence_handling_request(&params).await;
        assert_eq!(evidence_handling_request.data.data_type, "attestation");
        let serialized =
            serde_json::to_string(&evidence_handling_request).unwrap();
        assert!(!serialized.is_empty());
        assert!(context_info.flush_context().is_ok());
    } // test_evidence_handling_request

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_failing_evidence_handling_request() {
        use std::collections::HashMap;
        let _mutex = testing::lock_tests().await;
        let mut context_info = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
                disabled_signing_algorithms: vec![],
            },
        )
        .expect("Failed to create context info from string");
        let mut filler = FillerFromHardware::new(&mut context_info);
        let mut subjects = HashMap::new();
        subjects.insert("sha256".to_string(), vec![10]);
        let params = AttestationRequiredParams {
            challenge: "test_challenge".to_string(),
            signature_scheme: "invalid-sign-scheme".to_string(),
            hash_algorithm: "sha256".to_string(),
            selected_subjects: subjects,
            ima_log_path: Some("test-data/ima_log.txt".to_string()),
            ima_offset: 0,
            ima_entry_count: Some(1),
            uefi_log_path: Some("test-data/uefi_log.bin".to_string()),
        };
        let _ = filler.get_evidence_handling_request(&params).await;
        assert!(context_info.flush_context().is_ok());
    }
}
