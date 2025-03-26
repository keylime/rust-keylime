use keylime::structures;

pub fn get_attestation_request() -> structures::AttestationRequest {
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn get_attestation_request_test() {
        let req = get_attestation_request();
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
}
