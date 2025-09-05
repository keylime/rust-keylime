use anyhow::{anyhow, Result};
use keylime::structures::{
    AttestationResponse, ChosenParameters, EvidenceRequest,
};
use log::warn;
use std::collections::HashMap;

pub fn process_negotiation_response(
    response_body: &str,
) -> Result<Vec<EvidenceRequest>> {
    let verifier_response: AttestationResponse =
        serde_json::from_str(response_body)?;

    let evidence_requests =
        &verifier_response.data.attributes.evidence_requested;

    let mut result_requests = Vec::new();

    for evidence_request in evidence_requests {
        match evidence_request.evidence_type.as_str() {
            "tpm_quote" => {
                if let Some(ChosenParameters::Parameters(params_box)) =
                    &evidence_request.chosen_parameters
                {
                    result_requests.push(EvidenceRequest::TpmQuote {
                        challenge: params_box
                            .challenge
                            .clone()
                            .unwrap_or_default(),
                        signature_scheme: params_box
                            .signature_scheme
                            .clone()
                            .unwrap_or_default(),
                        hash_algorithm: params_box
                            .hash_algorithm
                            .clone()
                            .unwrap_or_default(),
                        selected_subjects: params_box
                            .selected_subjects
                            .as_ref()
                            .map_or(HashMap::default(), |s| s.to_map()),
                    });
                } else {
                    return Err(anyhow!(
                        "Chosen parameters for tpm_quote not found or invalid"
                    ));
                }
            }
            "ima_log" => {
                let (starting_offset, entry_count) =
                    match &evidence_request.chosen_parameters {
                        Some(ChosenParameters::Offset(offset)) => {
                            (offset.starting_offset, offset.entry_count)
                        }
                        _ => (None, None),
                    };

                result_requests.push(EvidenceRequest::ImaLog {
                    starting_offset,
                    entry_count,
                    format: None, // TODO: Extract format from chosen_parameters if available
                    log_path: None, // Will be set later by the caller
                });
            }
            "uefi_log" => {
                result_requests.push(EvidenceRequest::UefiLog {
                    format: None, // TODO: Extract format from chosen_parameters if available
                    log_path: None, // Will be set later by the caller
                });
            }
            t => {
                // Skip unknown evidence types
                warn!("Unknown evidence type: {t}");
                continue;
            }
        }
    }

    if result_requests.is_empty() {
        return Err(anyhow!("No valid evidence requests found"));
    }

    Ok(result_requests)
}

pub fn prepare_evidence_requests_from_response(
    response_body: &str,
    ima_log_path: Option<String>,
    uefi_log_path: Option<String>,
) -> Result<Vec<EvidenceRequest>, anyhow::Error> {
    // Parse the negotiation response
    let mut evidence_requests = process_negotiation_response(response_body)?;

    // Set log paths
    set_evidence_log_paths(
        &mut evidence_requests,
        ima_log_path,
        uefi_log_path,
    );

    Ok(evidence_requests)
}

pub fn set_evidence_log_paths(
    evidence_requests: &mut [EvidenceRequest],
    ima_log_path: Option<String>,
    uefi_log_path: Option<String>,
) {
    for request in evidence_requests {
        match request {
            EvidenceRequest::ImaLog { log_path, .. } => {
                *log_path = ima_log_path.clone();
            }
            EvidenceRequest::UefiLog { log_path, .. } => {
                *log_path = uefi_log_path.clone();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RESPONSE_BODY: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "certification",
                        "evidence_type": "tpm_quote",
                        "chosen_parameters": {
                            "challenge": "test-challenge-12345",
                            "hash_algorithm": "sha384",
                            "signature_scheme": "rsassa",
                            "selected_subjects": {
                                "sha1": [],
                                "sha256": [0, 1, 2, 3, 4, 5, 6]
                            },
                            "certification_key": {
                                "key_class": "asymmetric",
                                "key_algorithm": "rsa",
                                "key_size": 2048,
                                "server_identifier": "ak",
                                "local_identifier": "some_local_id",
                                "public": "..."
                            }
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
                            "starting_offset": 3925,
                            "entry_count": 100,
                            "format": "text/plain"
                        }
                    }
                ]
            }
        }
    }"#;

    const RESPONSE_ONLY_TPM_QUOTE: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "certification",
                        "evidence_type": "tpm_quote",
                        "chosen_parameters": {
                            "challenge": "test-challenge-12345",
                            "hash_algorithm": "sha384",
                            "signature_scheme": "rsassa",
                            "selected_subjects": {
                                "sha1": [],
                                "sha256": [0, 1, 2, 3, 4, 5, 6]
                            },
                            "certification_key": {
                                "key_class": "asymmetric",
                                "key_algorithm": "rsa",
                                "key_size": 2048,
                                "server_identifier": "ak",
                                "local_identifier": "some_local_id",
                                "public": "..."
                            }
                        }
                    }
                ]
            }
        }
    }"#;

    const RESPONSE_ONLY_IMA_LOG: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "log",
                        "evidence_type": "ima_log",
                        "chosen_parameters": {
                            "starting_offset": 3925,
                            "entry_count": 100,
                            "format": "text/plain"
                        }
                    }
                ]
            }
        }
    }"#;

    const RESPONSE_ONLY_UEFI_LOG: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "log",
                        "evidence_type": "uefi_log",
                        "chosen_parameters": {
                            "format": "application/octet-stream"
                        }
                    }
                ]
            }
        }
    }"#;

    const INVALID_RESPONSE_NO_EVIDENCE: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": []
            }
        }
    }"#;

    const INVALID_RESPONSE_UNKNOWN_EVIDENCE_ONLY: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "unknown",
                        "evidence_type": "unknown_type",
                        "chosen_parameters": {}
                    }
                ]
            }
        }
    }"#;

    const INVALID_RESPONSE_INVALID_TPM_QUOTE_PARAMETERS: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "certification",
                        "evidence_type": "tpm_quote",
                        "invalid_parameters": {}
                    }
                ]
            }
        }
    }"#;

    #[test]
    fn test_process_negotiation_response_with_all_evidence_types() {
        let result = process_negotiation_response(VALID_RESPONSE_BODY);
        assert!(result.is_ok(), "Parsing a valid response should succeed");
        let evidence_requests = result.unwrap(); //#[allow_ci]

        assert_eq!(evidence_requests.len(), 3);

        // Check TpmQuote request
        if let EvidenceRequest::TpmQuote {
            challenge,
            signature_scheme,
            hash_algorithm,
            selected_subjects,
        } = &evidence_requests[0]
        {
            assert_eq!(challenge, "test-challenge-12345");
            assert_eq!(signature_scheme, "rsassa");
            assert_eq!(hash_algorithm, "sha384");
            let empty_sha1: Vec<u32> = vec![];
            assert_eq!(selected_subjects.get("sha1").unwrap(), &empty_sha1); //#[allow_ci]
            assert_eq!(
                selected_subjects.get("sha256").unwrap(), //#[allow_ci]
                &vec![0, 1, 2, 3, 4, 5, 6]
            );
        } else {
            panic!("Expected TpmQuote request"); //#[allow_ci]
        }

        // Check UefiLog request
        if let EvidenceRequest::UefiLog { .. } = &evidence_requests[1] {
            // UefiLog request found
        } else {
            panic!("Expected UefiLog request"); //#[allow_ci]
        }

        // Check ImaLog request
        if let EvidenceRequest::ImaLog {
            starting_offset,
            entry_count,
            ..
        } = &evidence_requests[2]
        {
            assert_eq!(*starting_offset, Some(3925));
            assert_eq!(*entry_count, Some(100));
        } else {
            panic!("Expected ImaLog request"); //#[allow_ci]
        }
    }

    #[test]
    fn test_process_negotiation_response_single_evidence_types() {
        // Test with only TPM quote - should succeed
        let result = process_negotiation_response(RESPONSE_ONLY_TPM_QUOTE);
        assert!(result.is_ok());
        let evidence_requests = result.unwrap(); //#[allow_ci]
        assert_eq!(evidence_requests.len(), 1);
        assert!(matches!(
            evidence_requests[0],
            EvidenceRequest::TpmQuote { .. }
        ));

        // Test with only IMA log - should succeed
        let result = process_negotiation_response(RESPONSE_ONLY_IMA_LOG);
        assert!(result.is_ok());
        let evidence_requests = result.unwrap(); //#[allow_ci]
        assert_eq!(evidence_requests.len(), 1);
        assert!(matches!(
            evidence_requests[0],
            EvidenceRequest::ImaLog { .. }
        ));

        // Test with only UEFI log - should succeed
        let result = process_negotiation_response(RESPONSE_ONLY_UEFI_LOG);
        assert!(result.is_ok());
        let evidence_requests = result.unwrap(); //#[allow_ci]
        assert_eq!(evidence_requests.len(), 1);
        assert!(matches!(
            evidence_requests[0],
            EvidenceRequest::UefiLog { .. }
        ));
    }

    #[test]
    fn test_process_negotiation_response_invalid_cases() {
        // No evidence requests at all should fail
        let result =
            process_negotiation_response(INVALID_RESPONSE_NO_EVIDENCE);
        assert!(result.is_err());

        // Only unknown evidence types should fail
        let result = process_negotiation_response(
            INVALID_RESPONSE_UNKNOWN_EVIDENCE_ONLY,
        );
        assert!(result.is_err());

        // Invalid TPM quote parameters should fail
        let result = process_negotiation_response(
            INVALID_RESPONSE_INVALID_TPM_QUOTE_PARAMETERS,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_set_evidence_log_paths() {
        let result = process_negotiation_response(VALID_RESPONSE_BODY);
        assert!(result.is_ok());
        let mut evidence_requests = result.unwrap(); //#[allow_ci]

        // Initially, log paths should be None
        for request in &evidence_requests {
            match request {
                EvidenceRequest::ImaLog { log_path, .. } => {
                    assert!(log_path.is_none());
                }
                EvidenceRequest::UefiLog { log_path, .. } => {
                    assert!(log_path.is_none());
                }
                _ => {}
            }
        }

        // Set the log paths
        set_evidence_log_paths(
            &mut evidence_requests,
            Some("/path/to/ima.log".to_string()),
            Some("/path/to/uefi.log".to_string()),
        );

        // Check that log paths are now set
        for request in &evidence_requests {
            match request {
                EvidenceRequest::ImaLog { log_path, .. } => {
                    assert_eq!(
                        log_path.as_ref().unwrap(), //#[allow_ci]
                        "/path/to/ima.log"
                    );
                }
                EvidenceRequest::UefiLog { log_path, .. } => {
                    assert_eq!(
                        log_path.as_ref().unwrap(), //#[allow_ci]
                        "/path/to/uefi.log"
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_prepare_evidence_requests_from_response() {
        let evidence_requests = prepare_evidence_requests_from_response(
            VALID_RESPONSE_BODY,
            Some("/path/to/ima.log".to_string()),
            Some("/path/to/uefi.log".to_string()),
        );

        assert!(evidence_requests.is_ok());
        let requests = evidence_requests.unwrap(); //#[allow_ci]
        assert_eq!(requests.len(), 3);

        // Verify the TPM quote request
        if let EvidenceRequest::TpmQuote {
            challenge,
            signature_scheme,
            hash_algorithm,
            ..
        } = &requests[0]
        {
            assert_eq!(challenge, "test-challenge-12345");
            assert_eq!(signature_scheme, "rsassa");
            assert_eq!(hash_algorithm, "sha384");
        } else {
            panic!("Expected first request to be TPM quote"); //#[allow_ci]
        }

        // Verify the UEFI log request has the path set
        if let EvidenceRequest::UefiLog { log_path, .. } = &requests[1] {
            assert_eq!(log_path.as_ref().unwrap(), "/path/to/uefi.log"); //#[allow_ci]
        } else {
            panic!("Expected second request to be UEFI log"); //#[allow_ci]
        }

        // Verify the IMA log request has the path set
        if let EvidenceRequest::ImaLog {
            log_path,
            starting_offset,
            ..
        } = &requests[2]
        {
            assert_eq!(log_path.as_ref().unwrap(), "/path/to/ima.log"); //#[allow_ci]
            assert_eq!(*starting_offset, Some(3925));
        } else {
            panic!("Expected third request to be IMA log"); //#[allow_ci]
        }
    }
}
