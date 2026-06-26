// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Types and validation helpers for agent commands

use crate::commands::error::CommandError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Parameters for adding an agent to the verifier
///
/// This struct groups all the parameters needed for agent addition to improve
/// function signature readability and maintainability.
///
/// # Fields
///
/// * `agent_id` - Agent identifier (can be any string, not necessarily a UUID)
/// * `ip` - Optional agent IP address (overrides registrar data)
/// * `port` - Optional agent port (overrides registrar data)
/// * `verifier_ip` - Optional verifier IP for agent communication
/// * `runtime_policy` - Optional path to runtime policy file
/// * `mb_policy` - Optional path to measured boot policy file
/// * `payload` - Optional path to payload file for agent
/// * `cert_dir` - Optional path to certificate directory
/// * `verify` - Whether to perform key derivation verification
/// * `push_model` - Whether to use push model (agent connects to verifier)
pub(super) struct AddAgentParams<'a> {
    /// Agent identifier - can be any string
    pub agent_id: &'a str,
    /// Optional agent IP address (overrides registrar data)
    pub ip: Option<&'a str>,
    /// Optional agent port (overrides registrar data)
    pub port: Option<u16>,
    /// Optional verifier IP for agent communication
    #[cfg_attr(not(feature = "api-v2"), allow(dead_code))]
    pub verifier_ip: Option<&'a str>,
    /// Optional path to runtime policy file
    pub runtime_policy: Option<&'a str>,
    /// Optional path to measured boot policy file
    pub mb_policy: Option<&'a str>,
    /// Optional path to payload file for agent
    pub payload: Option<&'a str>,
    /// Optional path to certificate directory
    pub cert_dir: Option<&'a str>,
    /// Whether to perform key derivation verification (pull model only)
    #[cfg_attr(not(feature = "api-v2"), allow(dead_code))]
    pub verify: bool,
    /// Whether to use push model (agent connects to verifier)
    pub push_model: bool,
    /// Whether to force pull model (legacy, overrides auto-detection)
    pub pull_model: bool,
    /// Optional TPM policy in JSON format
    pub tpm_policy: Option<&'a str>,
    /// Whether to wait for attestation after enrollment
    pub wait_for_attestation: bool,
    /// Timeout for waiting for attestation (seconds)
    pub attestation_timeout: u64,
}

/// Request structure for adding an agent to the verifier
///
/// This struct represents the complete request payload sent to the verifier
/// when adding an agent for attestation monitoring. It uses serde for
/// automatic JSON serialization and ensures type safety.
///
/// # Core Required Fields
///
/// * `cloudagent_ip` - IP address where the agent can be reached
/// * `cloudagent_port` - Port where the agent is listening
/// * `verifier_ip` - IP address of the verifier
/// * `verifier_port` - Port of the verifier
/// * `ak_tpm` - Agent's attestation key from TPM
/// * `mtls_cert` - Mutual TLS certificate for agent communication
/// * `tpm_policy` - TPM policy in JSON format
///
/// # Legacy Compatibility Fields
///
/// * `v` - Optional V key from attestation (for API < 3.0)
///
/// # Policy Fields
///
/// * `runtime_policy` - Runtime policy content
/// * `runtime_policy_name` - Name of the runtime policy
/// * `runtime_policy_key` - Runtime policy signature key
/// * `mb_policy` - Measured boot policy content
/// * `mb_policy_name` - Name of the measured boot policy
///
/// # Security & Verification Fields
///
/// * `ima_sign_verification_keys` - IMA signature verification keys
/// * `revocation_key` - Revocation key for certificates
/// * `accept_tpm_hash_algs` - Accepted TPM hash algorithms
/// * `accept_tpm_encryption_algs` - Accepted TPM encryption algorithms
/// * `accept_tpm_signing_algs` - Accepted TPM signing algorithms
///
/// # Additional Fields
///
/// * `metadata` - Metadata in JSON format
/// * `payload` - Optional payload content
/// * `cert_dir` - Optional certificate directory path
/// * `supported_version` - API version supported by the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddAgentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudagent_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudagent_port: Option<u16>,
    pub verifier_ip: String,
    pub verifier_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ak_tpm: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_cert: Option<Value>,
    pub tpm_policy: String,

    // Legacy compatibility (API < 3.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<Value>,

    // Runtime policy fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_policy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_policy_key: Option<Value>,

    // Measured boot policy fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_policy_name: Option<String>,

    // IMA and verification keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_sign_verification_keys: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_key: Option<String>,

    // TPM algorithm support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_tpm_hash_algs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_tpm_encryption_algs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_tpm_signing_algs: Option<Vec<String>>,

    // Metadata and additional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_version: Option<String>,
}

#[cfg_attr(not(feature = "api-v2"), allow(dead_code))]
impl AddAgentRequest {
    /// Create a new agent request with the required fields
    #[must_use]
    pub fn new(
        cloudagent_ip: Option<String>,
        cloudagent_port: Option<u16>,
        verifier_ip: String,
        verifier_port: u16,
        tpm_policy: String,
    ) -> Self {
        Self {
            cloudagent_ip,
            cloudagent_port,
            verifier_ip,
            verifier_port,
            ak_tpm: None,
            mtls_cert: None,
            tpm_policy,
            v: None,
            runtime_policy: None,
            runtime_policy_name: None,
            runtime_policy_key: None,
            mb_policy: None,
            mb_policy_name: None,
            ima_sign_verification_keys: None,
            revocation_key: None,
            accept_tpm_hash_algs: None,
            accept_tpm_encryption_algs: None,
            accept_tpm_signing_algs: None,
            metadata: None,
            payload: None,
            cert_dir: None,
            supported_version: None,
        }
    }

    /// Set the TPM attestation key
    #[must_use]
    pub fn with_ak_tpm(mut self, ak_tpm: Option<Value>) -> Self {
        self.ak_tpm = ak_tpm;
        self
    }

    /// Set the mutual TLS certificate
    #[must_use]
    pub fn with_mtls_cert(mut self, mtls_cert: Option<Value>) -> Self {
        self.mtls_cert = mtls_cert;
        self
    }

    /// Set the V key from attestation
    #[must_use]
    pub fn with_v_key(mut self, v_key: Option<Value>) -> Self {
        self.v = v_key;
        self
    }

    /// Set the runtime policy
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_runtime_policy(mut self, policy: Option<String>) -> Self {
        self.runtime_policy = policy;
        self
    }

    /// Set the measured boot policy
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_mb_policy(mut self, policy: Option<String>) -> Self {
        self.mb_policy = policy;
        self
    }

    /// Set the payload
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_payload(mut self, payload: Option<String>) -> Self {
        self.payload = payload;
        self
    }

    /// Set the certificate directory
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_cert_dir(mut self, cert_dir: Option<String>) -> Self {
        self.cert_dir = cert_dir;
        self
    }

    /// Set the runtime policy name
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_runtime_policy_name(
        mut self,
        policy_name: Option<String>,
    ) -> Self {
        self.runtime_policy_name = policy_name;
        self
    }

    /// Set the runtime policy signature key
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_runtime_policy_key(
        mut self,
        policy_key: Option<Value>,
    ) -> Self {
        self.runtime_policy_key = policy_key;
        self
    }

    /// Set the measured boot policy name
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_mb_policy_name(
        mut self,
        policy_name: Option<String>,
    ) -> Self {
        self.mb_policy_name = policy_name;
        self
    }

    /// Set the IMA signature verification keys
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_ima_sign_verification_keys(
        mut self,
        keys: Option<String>,
    ) -> Self {
        self.ima_sign_verification_keys = keys;
        self
    }

    /// Set the revocation key
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_revocation_key(mut self, key: Option<String>) -> Self {
        self.revocation_key = key;
        self
    }

    /// Set the accepted TPM hash algorithms
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_accept_tpm_hash_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_hash_algs = algs;
        self
    }

    /// Set the accepted TPM encryption algorithms
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_accept_tpm_encryption_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_encryption_algs = algs;
        self
    }

    /// Set the accepted TPM signing algorithms
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_accept_tpm_signing_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_signing_algs = algs;
        self
    }

    /// Set the metadata
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_metadata(mut self, metadata: Option<String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the supported API version
    #[must_use]
    #[allow(dead_code)] // Will be used when CLI args are implemented
    pub fn with_supported_version(mut self, version: Option<String>) -> Self {
        self.supported_version = version;
        self
    }

    /// Validate the request before sending
    #[allow(dead_code)] // Will be used when validation is enabled
    pub fn validate(&self) -> Result<(), CommandError> {
        if let Some(ref ip) = self.cloudagent_ip {
            if ip.is_empty() {
                return Err(CommandError::invalid_parameter(
                    "cloudagent_ip",
                    "Agent IP cannot be empty".to_string(),
                ));
            }
        }

        if let Some(port) = self.cloudagent_port {
            if port == 0 {
                return Err(CommandError::invalid_parameter(
                    "cloudagent_port",
                    "Agent port cannot be zero".to_string(),
                ));
            }
        }

        if self.verifier_ip.is_empty() {
            return Err(CommandError::invalid_parameter(
                "verifier_ip",
                "Verifier IP cannot be empty".to_string(),
            ));
        }

        if self.verifier_port == 0 {
            return Err(CommandError::invalid_parameter(
                "verifier_port",
                "Verifier port cannot be zero".to_string(),
            ));
        }

        // Validate TPM policy is valid JSON
        if let Err(e) = serde_json::from_str::<Value>(&self.tpm_policy) {
            return Err(CommandError::invalid_parameter(
                "tpm_policy",
                format!("Invalid JSON in TPM policy: {e}"),
            ));
        }

        // Validate metadata is valid JSON if provided
        if let Some(metadata) = &self.metadata {
            if let Err(e) = serde_json::from_str::<Value>(metadata) {
                return Err(CommandError::invalid_parameter(
                    "metadata",
                    format!("Invalid JSON in metadata: {e}"),
                ));
            }
        }

        // Validate algorithm lists contain only known algorithms
        if let Some(hash_algs) = &self.accept_tpm_hash_algs {
            for alg in hash_algs {
                if !is_valid_tpm_hash_algorithm(alg) {
                    return Err(CommandError::invalid_parameter(
                        "accept_tpm_hash_algs",
                        format!("Unknown TPM hash algorithm: {alg}"),
                    ));
                }
            }
        }

        if let Some(enc_algs) = &self.accept_tpm_encryption_algs {
            for alg in enc_algs {
                if !is_valid_tpm_encryption_algorithm(alg) {
                    return Err(CommandError::invalid_parameter(
                        "accept_tpm_encryption_algs",
                        format!("Unknown TPM encryption algorithm: {alg}"),
                    ));
                }
            }
        }

        if let Some(sign_algs) = &self.accept_tpm_signing_algs {
            for alg in sign_algs {
                if !is_valid_tpm_signing_algorithm(alg) {
                    return Err(CommandError::invalid_parameter(
                        "accept_tpm_signing_algs",
                        format!("Unknown TPM signing algorithm: {alg}"),
                    ));
                }
            }
        }

        // Validate supported version format if provided
        if let Some(version) = &self.supported_version {
            if !is_valid_api_version(version) {
                return Err(CommandError::invalid_parameter(
                    "supported_version",
                    format!("Invalid API version format: {version}"),
                ));
            }
        }

        Ok(())
    }
}

/// Validate TPM hash algorithm names
///
/// Checks if the provided algorithm name is a known and supported TPM hash algorithm.
/// Based on the TPM 2.0 specification and common implementations.
#[must_use]
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_tpm_hash_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm.to_lowercase().as_str(),
        "sha1"
            | "sha256"
            | "sha384"
            | "sha512"
            | "sha3-256"
            | "sha3-384"
            | "sha3-512"
            | "sm3-256"
    )
}

/// Validate TPM encryption algorithm names
///
/// Checks if the provided algorithm name is a known and supported TPM encryption algorithm.
/// Based on the TPM 2.0 specification and common implementations.
#[must_use]
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_tpm_encryption_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm.to_lowercase().as_str(),
        "rsa"
            | "ecc"
            | "aes"
            | "camellia"
            | "sm4"
            | "rsassa"
            | "rsaes"
            | "rsapss"
            | "oaep"
            | "ecdsa"
            | "ecdh"
            | "ecdaa"
            | "sm2"
            | "ecschnorr"
    )
}

/// Validate TPM signing algorithm names
///
/// Checks if the provided algorithm name is a known and supported TPM signing algorithm.
/// Based on the TPM 2.0 specification and common implementations.
#[must_use]
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_tpm_signing_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm.to_lowercase().as_str(),
        "rsa"
            | "ecc"
            | "rsassa"
            | "rsapss"
            | "ecdsa"
            | "ecdaa"
            | "sm2"
            | "ecschnorr"
            | "hmac"
    )
}

/// Validate API version format
///
/// Checks if the provided version string follows a valid API version format (e.g., "2.1", "3.0").
#[must_use]
#[allow(dead_code)] // Will be used when validation is enabled
fn is_valid_api_version(version: &str) -> bool {
    // Basic format check: should be major.minor (e.g., "2.1", "3.0")
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 2 {
        return false;
    }

    // Check that both parts are valid numbers
    parts[0].parse::<u32>().is_ok() && parts[1].parse::<u32>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_agent_params_creation() {
        let params = AddAgentParams {
            agent_id: "550e8400-e29b-41d4-a716-446655440000",
            ip: Some("192.168.1.100"),
            port: Some(9002),
            verifier_ip: None,
            runtime_policy: None,
            mb_policy: None,
            payload: None,
            cert_dir: None,
            verify: true,
            push_model: false,
            pull_model: false,
            tpm_policy: None,
            wait_for_attestation: false,
            attestation_timeout: 60,
        };

        assert_eq!(params.agent_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(params.ip, Some("192.168.1.100"));
        assert_eq!(params.port, Some(9002));
        assert!(params.verify);
        assert!(!params.push_model);
    }

    #[test]
    fn test_add_agent_params_with_policies() {
        let params = AddAgentParams {
            agent_id: "550e8400-e29b-41d4-a716-446655440000",
            ip: None,
            port: None,
            verifier_ip: Some("10.0.0.1"),
            runtime_policy: Some("/path/to/runtime.json"),
            mb_policy: Some("/path/to/measured_boot.json"),
            payload: Some("/path/to/payload.txt"),
            cert_dir: Some("/path/to/certs"),
            verify: false,
            push_model: true,
            pull_model: false,
            tpm_policy: Some("{\"test\": \"policy\"}"),
            wait_for_attestation: false,
            attestation_timeout: 60,
        };

        assert_eq!(params.runtime_policy, Some("/path/to/runtime.json"));
        assert_eq!(params.mb_policy, Some("/path/to/measured_boot.json"));
        assert_eq!(params.payload, Some("/path/to/payload.txt"));
        assert_eq!(params.cert_dir, Some("/path/to/certs"));
        assert!(!params.verify);
        assert!(params.push_model);
    }

    // Test various agent parameter combinations
    mod parameter_combinations {
        use super::*;

        #[test]
        fn test_minimal_add_params() {
            let params = AddAgentParams {
                agent_id: "550e8400-e29b-41d4-a716-446655440000",
                ip: None,
                port: None,
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: false,
                pull_model: false,
                tpm_policy: None,
                wait_for_attestation: false,
                attestation_timeout: 60,
            };

            assert_eq!(
                params.agent_id,
                "550e8400-e29b-41d4-a716-446655440000"
            );
            assert!(params.ip.is_none());
            assert!(params.port.is_none());
            assert!(!params.verify);
            assert!(!params.push_model);
        }

        #[test]
        fn test_maximal_add_params() {
            let params = AddAgentParams {
                agent_id: "550e8400-e29b-41d4-a716-446655440000",
                ip: Some("192.168.1.100"),
                port: Some(9002),
                verifier_ip: Some("10.0.0.1"),
                runtime_policy: Some("/etc/keylime/runtime.json"),
                mb_policy: Some("/etc/keylime/measured_boot.json"),
                payload: Some("/etc/keylime/payload.txt"),
                cert_dir: Some("/etc/keylime/certs"),
                verify: true,
                push_model: true,
                pull_model: false,
                tpm_policy: Some("{\"pcr\": [\"15\"]}"),
                wait_for_attestation: false,
                attestation_timeout: 60,
            };

            assert!(params.ip.is_some());
            assert!(params.port.is_some());
            assert!(params.verifier_ip.is_some());
            assert!(params.runtime_policy.is_some());
            assert!(params.mb_policy.is_some());
            assert!(params.payload.is_some());
            assert!(params.cert_dir.is_some());
            assert!(params.verify);
            assert!(params.push_model);
        }

        #[test]
        fn test_push_model_params() {
            let params = AddAgentParams {
                agent_id: "550e8400-e29b-41d4-a716-446655440000",
                ip: None,   // IP not needed in push model
                port: None, // Port not needed in push model
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false, // Verification different in push model
                push_model: true,
                pull_model: false,
                tpm_policy: None,
                wait_for_attestation: false,
                attestation_timeout: 60,
            };

            assert!(params.push_model);
            assert!(!params.verify);
            assert!(params.ip.is_none());
            assert!(params.port.is_none());
        }
    }

    // Test comprehensive field support and validation
    mod comprehensive_field_tests {
        use super::*;
        use serde_json::json;

        #[test]
        fn test_add_agent_request_with_all_fields() {
            // Create a request with all possible fields
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_ak_tpm(Some(json!({"aik": "test_key"})))
            .with_mtls_cert(Some(json!({"cert": "test_cert"})))
            .with_v_key(Some(json!({"v": "test_v_key"})))
            .with_runtime_policy(Some("runtime policy content".to_string()))
            .with_runtime_policy_name(Some("runtime_policy_1".to_string()))
            .with_runtime_policy_key(Some(json!({"key": "policy_key"})))
            .with_mb_policy(Some("measured boot policy content".to_string()))
            .with_mb_policy_name(Some("mb_policy_1".to_string()))
            .with_ima_sign_verification_keys(Some("ima_keys".to_string()))
            .with_revocation_key(Some("revocation_key".to_string()))
            .with_accept_tpm_hash_algs(Some(vec![
                "sha256".to_string(),
                "sha1".to_string(),
            ]))
            .with_accept_tpm_encryption_algs(Some(vec![
                "rsa".to_string(),
                "ecc".to_string(),
            ]))
            .with_accept_tpm_signing_algs(Some(vec![
                "rsa".to_string(),
                "ecdsa".to_string(),
            ]))
            .with_metadata(Some("{}".to_string()))
            .with_payload(Some("test payload".to_string()))
            .with_cert_dir(Some("/path/to/certs".to_string()))
            .with_supported_version(Some("2.1".to_string()));

            // Validate that all fields are set correctly
            assert_eq!(
                request.cloudagent_ip,
                Some("192.168.1.100".to_string())
            );
            assert_eq!(request.cloudagent_port, Some(9002));
            assert_eq!(request.verifier_ip, "127.0.0.1");
            assert_eq!(request.verifier_port, 8881);
            assert_eq!(request.tpm_policy, "{}");

            assert!(request.ak_tpm.is_some());
            assert!(request.mtls_cert.is_some());
            assert!(request.v.is_some());

            assert_eq!(
                request.runtime_policy,
                Some("runtime policy content".to_string())
            );
            assert_eq!(
                request.runtime_policy_name,
                Some("runtime_policy_1".to_string())
            );
            assert!(request.runtime_policy_key.is_some());

            assert_eq!(
                request.mb_policy,
                Some("measured boot policy content".to_string())
            );
            assert_eq!(
                request.mb_policy_name,
                Some("mb_policy_1".to_string())
            );

            assert_eq!(
                request.ima_sign_verification_keys,
                Some("ima_keys".to_string())
            );
            assert_eq!(
                request.revocation_key,
                Some("revocation_key".to_string())
            );

            assert!(request.accept_tpm_hash_algs.is_some());
            assert!(request.accept_tpm_encryption_algs.is_some());
            assert!(request.accept_tpm_signing_algs.is_some());

            assert_eq!(request.metadata, Some("{}".to_string()));
            assert_eq!(request.payload, Some("test payload".to_string()));
            assert_eq!(request.cert_dir, Some("/path/to/certs".to_string()));
            assert_eq!(request.supported_version, Some("2.1".to_string()));
        }

        #[test]
        fn test_add_agent_request_validation_all_fields() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{\"pcr\": [15]}".to_string(),
            )
            .with_accept_tpm_hash_algs(Some(vec!["sha256".to_string()]))
            .with_accept_tpm_encryption_algs(Some(vec!["rsa".to_string()]))
            .with_accept_tpm_signing_algs(Some(vec!["rsa".to_string()]))
            .with_metadata(Some("{\"test\": \"value\"}".to_string()))
            .with_supported_version(Some("2.1".to_string()));

            // Should validate successfully
            assert!(request.validate().is_ok());
        }

        #[test]
        fn test_add_agent_request_validation_invalid_metadata() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_metadata(Some("invalid json {".to_string()));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid JSON in metadata"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_hash_algorithm() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_accept_tpm_hash_algs(Some(vec![
                "invalid_hash".to_string(),
            ]));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Unknown TPM hash algorithm"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_encryption_algorithm() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_accept_tpm_encryption_algs(Some(vec![
                "invalid_enc".to_string()
            ]));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Unknown TPM encryption algorithm"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_signing_algorithm() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_accept_tpm_signing_algs(Some(vec![
                "invalid_sign".to_string()
            ]));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Unknown TPM signing algorithm"));
        }

        #[test]
        fn test_add_agent_request_validation_invalid_api_version() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_supported_version(Some(
                "invalid.version.format".to_string(),
            ));

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid API version format"));
        }

        #[test]
        fn test_serialization_all_fields() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            )
            .with_runtime_policy_name(Some("test_policy".to_string()))
            .with_accept_tpm_hash_algs(Some(vec!["sha256".to_string()]))
            .with_metadata(Some("{}".to_string()));

            let serialized = serde_json::to_string(&request).unwrap(); //#[allow_ci]
            let json_value: Value =
                serde_json::from_str(&serialized).unwrap(); //#[allow_ci]

            // Check that optional agent fields are present when set
            assert_eq!(json_value["cloudagent_ip"], "192.168.1.100");
            assert_eq!(json_value["cloudagent_port"], 9002);
            assert_eq!(json_value["verifier_ip"], "127.0.0.1");
            assert_eq!(json_value["verifier_port"], 8881);
            assert_eq!(json_value["tpm_policy"], "{}");

            // Check that optional fields are present when set
            assert_eq!(json_value["runtime_policy_name"], "test_policy");
            assert_eq!(json_value["accept_tpm_hash_algs"], json!(["sha256"]));
            assert_eq!(json_value["metadata"], "{}");

            // Check that None fields are not serialized
            assert!(json_value.get("runtime_policy").is_none());
            assert!(json_value.get("mb_policy").is_none());
        }
    }

    // Test validation helper functions
    mod validation_helper_tests {
        use super::*;

        #[test]
        fn test_is_valid_tpm_hash_algorithm() {
            // Valid algorithms
            assert!(is_valid_tpm_hash_algorithm("sha1"));
            assert!(is_valid_tpm_hash_algorithm("SHA256"));
            assert!(is_valid_tpm_hash_algorithm("sha384"));
            assert!(is_valid_tpm_hash_algorithm("sha512"));
            assert!(is_valid_tpm_hash_algorithm("sha3-256"));
            assert!(is_valid_tpm_hash_algorithm("sm3-256"));

            // Invalid algorithms
            assert!(!is_valid_tpm_hash_algorithm("md5"));
            assert!(!is_valid_tpm_hash_algorithm("invalid"));
            assert!(!is_valid_tpm_hash_algorithm(""));
        }

        #[test]
        fn test_is_valid_tpm_encryption_algorithm() {
            // Valid algorithms
            assert!(is_valid_tpm_encryption_algorithm("rsa"));
            assert!(is_valid_tpm_encryption_algorithm("ECC"));
            assert!(is_valid_tpm_encryption_algorithm("aes"));
            assert!(is_valid_tpm_encryption_algorithm("oaep"));
            assert!(is_valid_tpm_encryption_algorithm("ecdh"));

            // Invalid algorithms
            assert!(!is_valid_tpm_encryption_algorithm("des"));
            assert!(!is_valid_tpm_encryption_algorithm("invalid"));
            assert!(!is_valid_tpm_encryption_algorithm(""));
        }

        #[test]
        fn test_is_valid_tpm_signing_algorithm() {
            // Valid algorithms
            assert!(is_valid_tpm_signing_algorithm("rsa"));
            assert!(is_valid_tpm_signing_algorithm("ECC"));
            assert!(is_valid_tpm_signing_algorithm("ecdsa"));
            assert!(is_valid_tpm_signing_algorithm("rsassa"));
            assert!(is_valid_tpm_signing_algorithm("hmac"));

            // Invalid algorithms
            assert!(!is_valid_tpm_signing_algorithm("dsa"));
            assert!(!is_valid_tpm_signing_algorithm("invalid"));
            assert!(!is_valid_tpm_signing_algorithm(""));
        }

        #[test]
        fn test_is_valid_api_version() {
            // Valid versions
            assert!(is_valid_api_version("2.1"));
            assert!(is_valid_api_version("3.0"));
            assert!(is_valid_api_version("10.99"));

            // Invalid versions
            assert!(!is_valid_api_version("2"));
            assert!(!is_valid_api_version("2.1.3"));
            assert!(!is_valid_api_version("v2.1"));
            assert!(!is_valid_api_version("2.x"));
            assert!(!is_valid_api_version(""));
            assert!(!is_valid_api_version("invalid"));
        }
    }

    // Test Optional cloudagent_ip/cloudagent_port in AddAgentRequest
    mod optional_agent_fields {
        use super::*;

        #[test]
        fn test_add_agent_request_with_none_ip_port() {
            let request = AddAgentRequest::new(
                None,
                None,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            );

            assert_eq!(request.cloudagent_ip, None);
            assert_eq!(request.cloudagent_port, None);
        }

        #[test]
        fn test_add_agent_request_none_fields_not_serialized() {
            let request = AddAgentRequest::new(
                None,
                None,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            );

            let serialized = serde_json::to_string(&request).unwrap(); //#[allow_ci]
            let json_value: Value =
                serde_json::from_str(&serialized).unwrap(); //#[allow_ci]

            // cloudagent_ip and cloudagent_port should not be in JSON when None
            assert!(json_value.get("cloudagent_ip").is_none());
            assert!(json_value.get("cloudagent_port").is_none());

            // Required fields should be present
            assert_eq!(json_value["verifier_ip"], "127.0.0.1");
            assert_eq!(json_value["verifier_port"], 8881);
        }

        #[test]
        fn test_add_agent_request_some_fields_serialized() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            );

            let serialized = serde_json::to_string(&request).unwrap(); //#[allow_ci]
            let json_value: Value =
                serde_json::from_str(&serialized).unwrap(); //#[allow_ci]

            assert_eq!(json_value["cloudagent_ip"], "192.168.1.100");
            assert_eq!(json_value["cloudagent_port"], 9002);
        }

        #[test]
        fn test_validate_with_none_ip_port_succeeds() {
            // When IP/port are None, validation should succeed
            // (push model doesn't require them)
            let request = AddAgentRequest::new(
                None,
                None,
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            );

            assert!(request.validate().is_ok());
        }

        #[test]
        fn test_validate_with_empty_ip_fails() {
            let request = AddAgentRequest::new(
                Some(String::new()),
                Some(9002),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            );

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Agent IP cannot be empty"));
        }

        #[test]
        fn test_validate_with_zero_port_fails() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(0),
                "127.0.0.1".to_string(),
                8881,
                "{}".to_string(),
            );

            let result = request.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Agent port cannot be zero"));
        }

        #[test]
        fn test_add_agent_params_with_pull_model() {
            let params = AddAgentParams {
                agent_id: "test-agent",
                ip: None,
                port: None,
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: false,
                pull_model: true,
                tpm_policy: None,
                wait_for_attestation: false,
                attestation_timeout: 60,
            };

            assert!(!params.push_model);
            assert!(params.pull_model);
        }

        #[test]
        fn test_add_agent_params_with_wait_for_attestation() {
            let params = AddAgentParams {
                agent_id: "test-agent",
                ip: None,
                port: None,
                verifier_ip: None,
                runtime_policy: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: true,
                pull_model: false,
                tpm_policy: None,
                wait_for_attestation: true,
                attestation_timeout: 120,
            };

            assert!(params.wait_for_attestation);
            assert_eq!(params.attestation_timeout, 120);
        }
    }
}
