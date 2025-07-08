use anyhow::{anyhow, Result};
use keylime::context_info::AttestationRequiredParams;
use keylime::structures::{AttestationResponse, ChosenParameters};

pub fn process_negotiation_response(
    response_body: &str,
) -> Result<AttestationRequiredParams> {
    let verifier_response: AttestationResponse =
        serde_json::from_str(response_body)?;

    let evidence_requests =
        &verifier_response.data.attributes.evidence_requested;
    let tpm_quote_request = evidence_requests
        .iter()
        .find(|req| req.evidence_type == "tpm_quote")
        .ok_or_else(|| {
            anyhow!("Verifier response did not request a tpm_quote")
        })?;

    let ima_log_request = evidence_requests
        .iter()
        .find(|req| req.evidence_type == "ima_log")
        .ok_or_else(|| {
            anyhow!("Verifier response did not request an ima_log")
        })?;

    let _ = evidence_requests
        .iter()
        .find(|req| req.evidence_type == "uefi_log")
        .ok_or_else(|| {
            anyhow!("Verifier response did not request a uefi_log")
        })?;

    let (ima_offset, ima_entry_count) =
        match &ima_log_request.chosen_parameters {
            Some(ChosenParameters::Offset(offset)) => {
                (offset.starting_offset.unwrap_or(0), offset.entry_count)
            }
            _ => {
                return Err(anyhow!(
                "Verifier response did not provide valid ima_log parameters"
            ));
            }
        };
    if let Some(ChosenParameters::Parameters(params_box)) =
        &tpm_quote_request.chosen_parameters
    {
        let params = AttestationRequiredParams {
            challenge: params_box.challenge.clone().unwrap_or_default(),
            signature_scheme: params_box
                .signature_scheme
                .clone()
                .unwrap_or_default(),
            hash_algorithm: params_box
                .hash_algorithm
                .clone()
                .unwrap_or_default(),
            selected_subjects: params_box.selected_subjects.as_ref().map_or(
                Default::default(),
                |s| {
                    let mut map = std::collections::HashMap::new();
                    map.insert("sha1".to_string(), s.sha1.clone());
                    map.insert("sha256".to_string(), s.sha256.clone());
                    map
                },
            ),
            ima_log_path: None,
            ima_offset,
            ima_entry_count,
            uefi_log_path: None,
        };
        Ok(params)
    } else {
        Err(anyhow!(
            "Chosen parameters for tpm_quote not found or invalid"
        ))
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

    const INVALID_RESPONSE_BODY_NO_IMA_LOG: &str = r#"{
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
                        "evidence_type": "other_invalid_log",
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

    const INVALID_RESPONSE_BODY_NO_UEFI_LOG: &str = r#"{
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
                        "evidence_type": "invalid_log",
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

    const INVALID_RESPONSE_BODY_NO_TPM_QUOTE: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "certification",
                        "evidence_type": "invalid_evidence_type",
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

    const INVALID_RESPONSE_BODY_INVALID_IMA_LOG_PARAMETERS: &str = r#"{
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
                        "invalid_parameters": {
                            "no_offset": 3925,
                            "no_entry_count": 100,
                            "format": "text/plain"
                        }
                    }
                ]
            }
        }
    }"#;

    const INVALID_RESPONSE_BODY_INVALID_TPM_QUOTE_PARAMETERS: &str = r#"{
        "data": {
            "type": "attestation",
            "attributes": {
                "stage": "awaiting_evidence",
                "evidence_requested": [
                    {
                        "evidence_class": "certification",
                        "evidence_type": "tpm_quote",
                        "invalid_parameters": {}
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
                            "offset": 3925,
                            "entry_count": 100,
                            "format": "text/plain"
                        }
                    }
                ]
            }
        }
    }"#;

    #[test]
    fn test_process_negotiation_response_success() {
        let result = process_negotiation_response(VALID_RESPONSE_BODY);
        assert!(result.is_ok(), "Parsing a valid response should succeed");
        let params = result.unwrap();

        assert_eq!(params.challenge, "test-challenge-12345");
        assert_eq!(params.signature_scheme, "rsassa");
        assert_eq!(params.hash_algorithm, "sha384");
        assert_eq!(params.ima_offset, 3925);
        assert_eq!(params.ima_entry_count, Some(100));
        let empty_sha1: Vec<u32> = vec![];
        assert_eq!(
            params.selected_subjects.get("sha1").unwrap(),
            &empty_sha1
        );
        assert_eq!(
            params.selected_subjects.get("sha256").unwrap(),
            &vec![0, 1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn test_invalid_evidences() {
        // define an array with the different invalid response bodies
        let invalid_response_bodies = [
            INVALID_RESPONSE_BODY_NO_IMA_LOG,
            INVALID_RESPONSE_BODY_NO_UEFI_LOG,
            INVALID_RESPONSE_BODY_NO_TPM_QUOTE,
            INVALID_RESPONSE_BODY_INVALID_IMA_LOG_PARAMETERS,
            INVALID_RESPONSE_BODY_INVALID_TPM_QUOTE_PARAMETERS,
        ];
        for &response_body in &invalid_response_bodies {
            let result = process_negotiation_response(response_body);
            assert!(
                result.is_err(),
                "Parsing an invalid response should not succeed"
            );
        }
    }

    #[test]
    fn test_process_negotiation_missing_tpm_quote() {
        let response_body = r#"{
            "data": { "attributes": { "evidence_requested": [
                { "evidence_type": "ima_log", "chosen_parameters": { "starting_offset": 0 } }
            ] } }
        }"#;
        let result = process_negotiation_response(response_body);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_negotiation_missing_ima_log() {
        let response_body = r#"{
            "data": { "attributes": { "evidence_requested": [
                { "evidence_type": "tpm_quote", "chosen_parameters": { "challenge": "c" } }
            ] } }
        }"#;
        let result = process_negotiation_response(response_body);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_negotiation_invalid_ima_params() {
        let response_body = r#"{
            "data": { "attributes": { "evidence_requested": [
                { "evidence_type": "tpm_quote", "chosen_parameters": { "challenge": "c" } },
                { "evidence_type": "ima_log", "chosen_parameters": { "challenge": "c" } }
            ] } }
        }"#;
        let result = process_negotiation_response(response_body);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_negotiation_missing_tpm_params() {
        let response_body = r#"{
            "data": { "attributes": { "evidence_requested": [
                { "evidence_type": "tpm_quote" },
                { "evidence_type": "ima_log", "chosen_parameters": { "starting_offset": 0 } }
            ] } }
        }"#;
        let result = process_negotiation_response(response_body);
        assert!(result.is_err());
    }
}
