// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! # Structure Filler Module
//!
//! This module handles concurrent access to privileged resources (IMA logs, UEFI logs)
//! that were opened with root privileges before the agent dropped privileges.
//!
//! ## Threading Model and Mutex Usage
//!
//! - **Privileged Resources**: Opened as root, accessed after privilege drop via mutexes
//! - **Concurrency**: Multiple attestation requests may access resources simultaneously
//! - **Mutex Poisoning**: If a thread panics while holding a mutex, the mutex becomes "poisoned"
//!   and all future lock attempts will fail. This is a permanent failure requiring restart.
//!
//! ## Error Recovery Strategy
//!
//! - **Mutex poisoning is NOT recoverable** - the agent must be restarted
//! - Monitoring systems should alert on mutex poisoning events
//! - The error messages provide clear guidance for operators
//!
//! ## Security Considerations
//!
//! - File handles remain valid after privilege drop due to descriptor inheritance
//! - Mutexes ensure thread-safe access to shared file descriptors
//! - MeasurementList state is preserved across multiple reads for incremental updates

use async_trait::async_trait;
use keylime::algorithms::HashAlgorithm;
use keylime::config::PushModelConfigTrait;
use keylime::context_info::ContextInfo;
use keylime::structures;
use keylime::uefi::uefi_log_handler;
use log::{error, warn};
use std::fs::File;
use std::sync::Mutex;

use crate::privileged_resources::PrivilegedResources;

/// Standard error messages for mutex poisoning recovery
const MUTEX_POISONED_RECOVERY_MESSAGES: &[&str] = &[
    "This typically occurs when a thread panicked while holding the mutex.",
    "RECOVERY: The Keylime agent must be restarted to restore functionality.",
    "MONITORING: This event should trigger an alert for immediate attention.",
];

/// Helper function to log mutex poisoning recovery messages
fn log_mutex_poisoning_recovery() {
    for msg in MUTEX_POISONED_RECOVERY_MESSAGES {
        error!("{}", msg);
    }
}

#[async_trait]
pub trait StructureFiller {
    fn get_attestation_request(&mut self) -> structures::AttestationRequest;
    #[allow(dead_code)]
    fn get_session_request(&mut self) -> structures::SessionRequest;
    async fn get_evidence_handling_request(
        &mut self,
        response_info: &crate::attestation::ResponseInformation,
        config: &crate::attestation::NegotiationConfig<'_>,
    ) -> structures::EvidenceHandlingRequest;
}

pub fn get_filler_request<'a>(
    tpm_context_info: Option<&'a mut ContextInfo>,
    privileged_resources: &'a PrivilegedResources,
) -> Box<dyn StructureFiller + 'a> {
    match tpm_context_info {
        Some(info) => {
            Box::new(FillerFromHardware::new(info, privileged_resources))
        }
        None => Box::new(TestingFiller::new()),
    }
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
        response_info: &crate::attestation::ResponseInformation,
        config: &crate::attestation::NegotiationConfig<'_>,
    ) -> structures::EvidenceHandlingRequest {
        self.get_evidence_handling_request_final(response_info, config)
            .await
    }
}

fn boot_time() -> chrono::DateTime<chrono::Utc> {
    match keylime::boot_time::get_boot_time() {
        Ok(time) => time,
        Err(e) => {
            warn!("Failed to get boot time: {e}, falling back to UNIX_EPOCH time");
            chrono::DateTime::UNIX_EPOCH
        }
    }
}

pub struct FillerFromHardware<'a> {
    pub tpm_context_info: &'a mut ContextInfo,
    pub uefi_log_handler: Option<uefi_log_handler::UefiLogHandler>,
    pub privileged_resources: &'a PrivilegedResources,
}

impl<'a> FillerFromHardware<'a> {
    pub fn new(
        tpm_context_info: &'a mut ContextInfo,
        privileged_resources: &'a PrivilegedResources,
    ) -> Self {
        // Try to create UEFI log handler from privileged file handle
        let uefi_log_handler = match &privileged_resources
            .measuredboot_ml_file
        {
            Some(file) => {
                match uefi_log_handler::UefiLogHandler::from_file(file) {
                    Ok(handler) => Some(handler),
                    Err(e) => {
                        error!("Failed to create UEFI log handler from file handle: {e:?}");
                        None
                    }
                }
            }
            None => {
                warn!("No measured boot log file available");
                None
            }
        };

        FillerFromHardware {
            tpm_context_info,
            uefi_log_handler,
            privileged_resources,
        }
    }

    /// Read IMA log count from privileged file handle
    ///
    /// Returns the number of entries in the IMA log, or an error if reading fails.
    /// This method properly handles mutex locking without panicking.
    fn read_ima_log_count(
        &self,
        file_mutex: &Mutex<File>,
    ) -> Result<usize, String> {
        let mut ima_ml = self
            .privileged_resources
            .ima_ml
            .lock()
            .map_err(|e| {
                error!("CRITICAL: IMA MeasurementList mutex poisoned - this indicates a serious bug");
                log_mutex_poisoning_recovery();
                format!("IMA MeasurementList mutex poisoned: {e:?}")
            })?;

        let mut file = file_mutex.lock().map_err(|e| {
            error!("CRITICAL: IMA file mutex poisoned - this indicates a serious bug");
            log_mutex_poisoning_recovery();
            format!("IMA file mutex poisoned: {e:?}")
        })?;

        let (_, _, num_entries) = ima_ml
            .read(&mut file, 0)
            .map_err(|e| format!("Failed to read IMA log: {e:?}"))?;

        Ok(num_entries as usize)
    }

    fn get_attestation_request_final(
        &mut self,
    ) -> structures::AttestationRequest {
        let config = keylime::config::get_config();

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

        // Read IMA log using MeasurementList for stateful, incremental reading
        // This approach maintains state between reads and only processes new entries
        let ima_log_count = match &self.privileged_resources.ima_ml_file {
            Some(file_mutex) => match self.read_ima_log_count(file_mutex) {
                Ok(count) => count,
                Err(e) => {
                    error!("Failed to read IMA log count: {e}");
                    0
                }
            },
            None => {
                warn!("No IMA log file available");
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
                                supports_partial_access: false,
                                appendable: false,
                                formats: vec!["application/octet-stream".to_string()]
                            },
                        },
                        structures::EvidenceSupported::EvidenceLog {
                            evidence_type: "ima_log".to_string(),
                            capabilities: structures::LogCapabilities {
                                evidence_version: None,
                                entry_count: ima_log_count,
                                supports_partial_access: true,
                                appendable: true,
                                formats: vec!["text/plain".to_string()],
                            },
                        },
                    ],
                    system_info: structures::SystemInfo {
                        boot_time: boot_time(),
                    },
                },
            },
        }
    }

    // TODO: Change this function to use the session request appropriately
    // TODO: This is expected to be used once the PoP authentication is implemented
    #[allow(dead_code)]
    pub fn get_session_request_final(
        &mut self,
    ) -> structures::SessionRequest {
        structures::SessionRequest {
            data: structures::SessionRequestData {
                data_type: "session".to_string(),
                attributes: structures::SessionRequestAttributes {
                    agent_id: "example-agent".to_string(),
                    auth_supported: vec![structures::SupportedAuthMethod {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                    }],
                },
            },
        }
    }

    pub async fn get_evidence_handling_request_final(
        &mut self,
        response_info: &crate::attestation::ResponseInformation,
        config: &crate::attestation::NegotiationConfig<'_>,
    ) -> structures::EvidenceHandlingRequest {
        // Parse the negotiation response and prepare evidence requests
        let evidence_requests = match crate::response_handler::prepare_evidence_requests_from_response(
            &response_info.body,
            config.ima_log_path.map(|path| path.to_string()),
            config.uefi_log_path.map(|path| path.to_string()),
        ) {
            Ok(requests) => requests,
            Err(e) => {
                error!("Failed to parse evidence requests from response: {e}");
                return structures::EvidenceHandlingRequest {
                    data: structures::EvidenceHandlingRequestData {
                        data_type: "error".to_string(),
                        attributes: structures::EvidenceHandlingRequestAttributes {
                            evidence_collected: vec![],
                        },
                    },
                };
            }
        };

        let evidence_results = match self
            .tpm_context_info
            .collect_evidences(
                &evidence_requests,
                Some(&self.privileged_resources.ima_ml),
                self.privileged_resources.ima_ml_file.as_ref(),
            )
            .await
        {
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

        // Convert evidence results to the expected format
        let evidence_collected: Vec<structures::EvidenceCollected> =
            evidence_results
                .into_iter()
                .map(|evidence| evidence.into())
                .collect();

        structures::EvidenceHandlingRequest {
            data: structures::EvidenceHandlingRequestData {
                data_type: "attestation".to_string(),
                attributes: structures::EvidenceHandlingRequestAttributes {
                    evidence_collected,
                },
            },
        }
    }
}

// define an empty filler that implements StructureFiller for testing purposes
pub struct TestingFiller;
impl TestingFiller {
    pub fn new() -> Self {
        TestingFiller
    }
}

#[async_trait]
impl StructureFiller for TestingFiller {
    fn get_attestation_request(&mut self) -> structures::AttestationRequest {
        structures::AttestationRequest {
            data: structures::RequestData {
                type_: "attestation".to_string(),
                attributes: structures::Attributes {
                    evidence_supported: vec![],
                    system_info: structures::SystemInfo {
                        boot_time: boot_time(),
                    },
                },
            },
        }
    }
    fn get_session_request(&mut self) -> structures::SessionRequest {
        structures::SessionRequest {
            data: structures::SessionRequestData {
                data_type: "session".to_string(),
                attributes: structures::SessionRequestAttributes {
                    agent_id: "example-agent".to_string(),
                    auth_supported: vec![],
                },
            },
        }
    }
    async fn get_evidence_handling_request(
        &mut self,
        _response_info: &crate::attestation::ResponseInformation,
        _config: &crate::attestation::NegotiationConfig<'_>,
    ) -> structures::EvidenceHandlingRequest {
        structures::EvidenceHandlingRequest {
            data: structures::EvidenceHandlingRequestData {
                data_type: "error".to_string(),
                attributes: structures::EvidenceHandlingRequestAttributes {
                    evidence_collected: vec![],
                },
            },
        }
    }
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {

    use super::*;

    use keylime::{context_info, tpm::testing};

    /// Helper function to create empty PrivilegedResources for testing
    fn create_test_privileged_resources() -> PrivilegedResources {
        use keylime::ima::MeasurementList;
        use std::sync::Mutex;

        PrivilegedResources {
            ima_ml_file: None,
            ima_ml: Mutex::new(MeasurementList::new()),
            measuredboot_ml_file: None,
        }
    }

    #[tokio::test]
    async fn test_attestation_request_final() {
        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        // Skip test if TPM access is not available
        let mut context_info = match context_info_result {
            Ok(ctx) => ctx,
            Err(_) => {
                println!("Skipping test_attestation_request_final: TPM not available");
                return;
            }
        };

        let privileged_resources = create_test_privileged_resources();
        let mut filler =
            FillerFromHardware::new(&mut context_info, &privileged_resources);
        let attestation_request = filler.get_attestation_request_final();
        assert_eq!(attestation_request.data.type_, "attestation");
        let serialized = serde_json::to_string(&attestation_request).unwrap();
        assert!(!serialized.is_empty());
        assert!(context_info.flush_context().is_ok());
    } // test_attestation_request

    #[tokio::test]
    async fn test_filler_from_hardware_get_attestation_request() {
        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        let mut context_info = match context_info_result {
            Ok(ctx) => ctx,
            Err(e) => {
                println!("Skipping test_filler_from_hardware_get_attestation_request: TPM not available or failed to init: {e:?}");
                return;
            }
        };

        let privileged_resources = create_test_privileged_resources();
        let mut filler =
            FillerFromHardware::new(&mut context_info, &privileged_resources);

        let request = filler.get_attestation_request();

        assert_eq!(request.data.type_, "attestation");
        let attributes = request.data.attributes;
        assert_eq!(
            attributes.evidence_supported.len(),
            3,
            "Should contain tpm_quote, uefi_log, and ima_log evidence"
        );

        let tpm_quote_evidence = attributes.evidence_supported.iter().find(|e| {
            matches!(e, structures::EvidenceSupported::Certification { evidence_type, .. } if evidence_type == "tpm_quote")
        }).expect("tpm_quote evidence not found");

        if let structures::EvidenceSupported::Certification {
            capabilities,
            ..
        } = tpm_quote_evidence
        {
            assert!(
                !capabilities.hash_algorithms.is_empty(),
                "Hash algorithms should be populated from TPM"
            );
            assert!(
                !capabilities.signature_schemes.is_empty(),
                "Signature schemes should be populated from TPM"
            );
            assert!(
                capabilities.available_subjects.sha256.is_some(),
                "SHA256 PCR banks should be populated"
            );
            assert!(
                !capabilities.certification_keys.is_empty(),
                "AK certification key should be present"
            );
        } else {
            panic!("Expected Certification evidence for tpm_quote"); //#[allow_ci]
        }

        let _ = attributes.evidence_supported.iter().find(|e| {
            matches!(e, structures::EvidenceSupported::EvidenceLog { evidence_type, .. } if evidence_type == "ima_log")
        }).expect("ima_log evidence not found");

        let _ = attributes.evidence_supported.iter().find(|e| {
            matches!(e, structures::EvidenceSupported::EvidenceLog { evidence_type, .. } if evidence_type == "uefi_log")
        }).expect("uefi_log evidence not found");
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_session_request() {
        use keylime::context_info;
        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        // Skip test if TPM access is not available
        let mut context_info = match context_info_result {
            Ok(ctx) => ctx,
            Err(_) => {
                println!("Skipping test_session_request: TPM not available");
                return;
            }
        };

        let privileged_resources = create_test_privileged_resources();
        let mut filler =
            FillerFromHardware::new(&mut context_info, &privileged_resources);
        let session_request = filler.get_session_request_final();
        assert_eq!(session_request.data.data_type, "session");
        let serialized = serde_json::to_string(&session_request).unwrap();
        assert!(!serialized.is_empty());
        assert!(context_info.flush_context().is_ok());
    } // test_session_request

    #[tokio::test]
    async fn test_failing_evidence_handling_request() {
        use std::collections::HashMap;
        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        // Skip test if TPM access is not available
        let mut context_info = match context_info_result {
            Ok(ctx) => ctx,
            Err(_) => {
                println!("Skipping test_failing_evidence_handling_request: TPM not available");
                return;
            }
        };

        let privileged_resources = create_test_privileged_resources();
        let mut filler =
            FillerFromHardware::new(&mut context_info, &privileged_resources);
        let mut subjects = HashMap::new();
        subjects.insert("sha256".to_string(), vec![10]);

        // Create a response body for the failing case
        let response_body = serde_json::json!({
            "data": {
                "type": "attestation",
                "attributes": {
                    "stage": "evidence_requested",
                    "evidence_requested": [
                        {
                            "evidence_class": "certification",
                            "evidence_type": "tpm_quote",
                            "chosen_parameters": {
                                "challenge": "test_challenge",
                                "signature_scheme": "invalid-sign-scheme",
                                "hash_algorithm": "sha256",
                                "selected_subjects": {
                                    "sha256": [10]
                                }
                            }
                        },
                        {
                            "evidence_class": "log",
                            "evidence_type": "ima_log",
                            "chosen_parameters": {
                                "starting_offset": 0,
                                "entry_count": 1
                            }
                        },
                        {
                            "evidence_class": "log",
                            "evidence_type": "uefi_log"
                        }
                    ]
                }
            }
        })
        .to_string();

        let _ = filler
            .get_evidence_handling_request(
                &crate::attestation::ResponseInformation {
                    status_code: reqwest::StatusCode::CREATED,
                    headers: reqwest::header::HeaderMap::new(),
                    body: response_body,
                },
                &crate::attestation::NegotiationConfig {
                    avoid_tpm: false,
                    ca_certificate: "",
                    client_certificate: "",
                    enable_authentication: false,
                    agent_id: "test-agent-id",
                    ima_log_path: Some("test-data/ima_log.txt"),
                    initial_delay_ms: 1000,
                    insecure: Some(false),
                    key: "",
                    max_delay_ms: Some(30000),
                    max_retries: 3,
                    timeout: 30,
                    uefi_log_path: Some("test-data/uefi_log.bin"),
                    url: "http://localhost",
                    verifier_url: "http://localhost",
                    tls_accept_invalid_certs: false,
                    tls_accept_invalid_hostnames: false,
                },
            )
            .await;
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_get_filler_request_with_tpm() {
        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        if let Ok(mut ctx) = context_info_result {
            {
                let privileged_resources = create_test_privileged_resources();
                let mut filler =
                    get_filler_request(Some(&mut ctx), &privileged_resources);
                // To check the type, we can't directly compare types of Box<dyn Trait>.
                // A simple way is to check the output of a method.
                let req = filler.get_session_request();
                // FillerFromHardware returns a specific agent_id
                assert_eq!(req.data.attributes.agent_id, "example-agent");
            }
            assert!(ctx.clone().flush_context().is_ok());
        }
    }

    #[tokio::test]
    async fn test_get_filler_request_without_tpm() {
        let privileged_resources = create_test_privileged_resources();
        let mut filler = get_filler_request(None, &privileged_resources);
        // TestingFiller returns an empty auth_supported vector
        let req = filler.get_session_request();
        assert!(req.data.attributes.auth_supported.is_empty());
    }

    #[tokio::test]
    async fn test_testing_filler_methods() {
        let mut filler = TestingFiller::new();

        // Test get_attestation_request
        let attestation_req = filler.get_attestation_request();
        assert_eq!(attestation_req.data.type_, "attestation");
        assert!(attestation_req
            .data
            .attributes
            .evidence_supported
            .is_empty());

        // Test get_session_request
        let session_req = filler.get_session_request();
        assert_eq!(session_req.data.data_type, "session");
        assert!(session_req.data.attributes.auth_supported.is_empty());

        // Test get_evidence_handling_request
        let dummy_response = crate::attestation::ResponseInformation {
            status_code: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            body: "{}".to_string(),
        };
        let dummy_config = crate::attestation::NegotiationConfig {
            avoid_tpm: true,
            url: "",
            timeout: 0,
            ca_certificate: "",
            client_certificate: "",
            enable_authentication: false,
            agent_id: "test-agent-id",
            key: "",
            insecure: None,
            ima_log_path: None,
            uefi_log_path: None,
            max_retries: 0,
            initial_delay_ms: 0,
            max_delay_ms: None,
            verifier_url: "",
            tls_accept_invalid_certs: false,
            tls_accept_invalid_hostnames: false,
        };
        let evidence_req = filler
            .get_evidence_handling_request(&dummy_response, &dummy_config)
            .await;
        assert_eq!(evidence_req.data.data_type, "error");
        assert!(evidence_req.data.attributes.evidence_collected.is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_filler_from_hardware_new_with_uefi_error() {
        use keylime::config::{get_testing_config, TestConfigGuard};

        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        if let Ok(mut ctx) = context_info_result {
            // Create a temporary directory for testing
            let temp_dir = tempfile::tempdir().unwrap();

            // Create testing configuration with non-existent measuredboot_ml_path
            let mut overrides = std::collections::HashMap::new();
            overrides.insert(
                "measuredboot_ml_path".to_string(),
                "/path/to/non/existent/log".to_string(),
            );
            let test_config =
                get_testing_config(temp_dir.path(), Some(overrides));

            // Create guard that will automatically clear override when dropped
            let _guard = TestConfigGuard::new(test_config);

            let privileged_resources = create_test_privileged_resources();
            let filler =
                FillerFromHardware::new(&mut ctx, &privileged_resources);
            assert!(filler.uefi_log_handler.is_none());

            assert!(ctx.flush_context().is_ok());
        }
    }

    #[tokio::test]
    async fn test_get_evidence_handling_request_final_with_parsing_error() {
        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        if let Ok(mut ctx) = context_info_result {
            let privileged_resources = create_test_privileged_resources();
            let mut filler =
                FillerFromHardware::new(&mut ctx, &privileged_resources);
            let malformed_response =
                crate::attestation::ResponseInformation {
                    status_code: reqwest::StatusCode::CREATED,
                    headers: reqwest::header::HeaderMap::new(),
                    body: "this is not valid json".to_string(),
                };
            let dummy_config = crate::attestation::NegotiationConfig {
                avoid_tpm: true,
                url: "",
                timeout: 0,
                ca_certificate: "",
                client_certificate: "",
                enable_authentication: false,
                agent_id: "test-agent-id",
                key: "",
                insecure: None,
                ima_log_path: None,
                uefi_log_path: None,
                max_retries: 0,
                initial_delay_ms: 0,
                max_delay_ms: None,
                verifier_url: "",
                tls_accept_invalid_certs: false,
                tls_accept_invalid_hostnames: false,
            };

            let result = filler
                .get_evidence_handling_request_final(
                    &malformed_response,
                    &dummy_config,
                )
                .await;

            assert_eq!(result.data.data_type, "error");
            assert!(result.data.attributes.evidence_collected.is_empty());
            assert!(ctx.flush_context().is_ok());
        }
    }

    #[tokio::test]
    async fn test_uefi_log_capabilities_flags() {
        let _mutex = testing::lock_tests().await;
        let context_info_result = context_info::ContextInfo::new_from_str(
            context_info::AlgorithmConfigurationString {
                tpm_encryption_alg: "rsa".to_string(),
                tpm_hash_alg: "sha256".to_string(),
                tpm_signing_alg: "rsassa".to_string(),
                agent_data_path: "".to_string(),
            },
        );

        let mut context_info = match context_info_result {
            Ok(ctx) => ctx,
            Err(_) => {
                println!("Skipping test_uefi_log_capabilities_flags: TPM not available");
                return;
            }
        };

        let privileged_resources = create_test_privileged_resources();
        let mut filler =
            FillerFromHardware::new(&mut context_info, &privileged_resources);
        let request = filler.get_attestation_request();

        let uefi_log_evidence = request.data.attributes.evidence_supported.iter().find(|e| {
            matches!(e, structures::EvidenceSupported::EvidenceLog { evidence_type, .. } if evidence_type == "uefi_log")
        }).expect("uefi_log evidence not found");

        if let structures::EvidenceSupported::EvidenceLog {
            capabilities,
            ..
        } = uefi_log_evidence
        {
            assert!(
                !capabilities.supports_partial_access,
                "UEFI log supports_partial_access should be false"
            );
            assert!(
                !capabilities.appendable,
                "UEFI log appendable should be false"
            );
        } else {
            panic!("Expected EvidenceLog for uefi_log"); //#[allow_ci]
        }

        assert!(context_info.flush_context().is_ok());
    }
}
