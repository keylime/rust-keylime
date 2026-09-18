// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Types and validation helpers for agent commands

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
    /// Optional name for the runtime policy in the verifier database
    pub runtime_policy_name: Option<&'a str>,
    /// Optional path to public key file for DSSE signature verification
    pub runtime_policy_sig_key: Option<&'a str>,
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
    /// Allow proceeding with unverified TPM quotes (INSECURE: for development only)
    #[cfg_attr(not(feature = "api-v2"), allow(dead_code))]
    pub allow_unverified_quote: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_port: Option<u16>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_refstate: Option<String>,

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

impl AddAgentRequest {
    /// Create a new agent request with the required fields.
    ///
    /// Policy-related fields (`runtime_policy`, `runtime_policy_name`,
    /// `runtime_policy_key`, `mb_policy_name`) are
    /// initialized to empty strings so the verifier always receives them.
    /// Use builder methods to override these defaults.
    #[must_use]
    pub fn new(
        cloudagent_ip: Option<String>,
        cloudagent_port: Option<u16>,
        verifier_ip: Option<String>,
        verifier_port: Option<u16>,
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
            runtime_policy: Some(String::new()),
            runtime_policy_name: Some(String::new()),
            runtime_policy_key: Some(Value::String(String::new())),
            mb_policy: None,
            mb_policy_name: Some(String::new()),
            mb_refstate: None,
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
    pub fn with_runtime_policy(mut self, policy: Option<String>) -> Self {
        self.runtime_policy = policy;
        self
    }

    /// Set the measured boot policy
    #[must_use]
    pub fn with_mb_policy(mut self, policy: Option<String>) -> Self {
        self.mb_policy = policy;
        self
    }

    /// Set the payload
    #[must_use]
    pub fn with_payload(mut self, payload: Option<String>) -> Self {
        self.payload = payload;
        self
    }

    /// Set the certificate directory
    #[must_use]
    pub fn with_cert_dir(mut self, cert_dir: Option<String>) -> Self {
        self.cert_dir = cert_dir;
        self
    }

    /// Set the runtime policy name
    #[must_use]
    #[allow(dead_code)] // Used when --runtime-policy-name CLI arg is wired up
    pub fn with_runtime_policy_name(
        mut self,
        policy_name: Option<String>,
    ) -> Self {
        self.runtime_policy_name = policy_name;
        self
    }

    /// Set the runtime policy signature key
    #[must_use]
    #[allow(dead_code)] // Used when --runtime-policy-key CLI arg is wired up
    pub fn with_runtime_policy_key(
        mut self,
        policy_key: Option<Value>,
    ) -> Self {
        self.runtime_policy_key = policy_key;
        self
    }

    /// Set the measured boot policy name
    #[must_use]
    pub fn with_mb_policy_name(
        mut self,
        policy_name: Option<String>,
    ) -> Self {
        self.mb_policy_name = policy_name;
        self
    }

    /// Set the IMA signature verification keys
    #[must_use]
    pub fn with_ima_sign_verification_keys(
        mut self,
        keys: Option<String>,
    ) -> Self {
        self.ima_sign_verification_keys = keys;
        self
    }

    /// Set the revocation key
    #[must_use]
    pub fn with_revocation_key(mut self, key: Option<String>) -> Self {
        self.revocation_key = key;
        self
    }

    /// Set the accepted TPM hash algorithms
    #[must_use]
    pub fn with_accept_tpm_hash_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_hash_algs = algs;
        self
    }

    /// Set the accepted TPM encryption algorithms
    #[must_use]
    pub fn with_accept_tpm_encryption_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_encryption_algs = algs;
        self
    }

    /// Set the accepted TPM signing algorithms
    #[must_use]
    pub fn with_accept_tpm_signing_algs(
        mut self,
        algs: Option<Vec<String>>,
    ) -> Self {
        self.accept_tpm_signing_algs = algs;
        self
    }

    /// Set the metadata
    #[must_use]
    pub fn with_metadata(mut self, metadata: Option<String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the supported API version
    #[must_use]
    pub fn with_supported_version(mut self, version: Option<String>) -> Self {
        self.supported_version = version;
        self
    }

    /// Set the measured boot refstate
    #[must_use]
    pub fn with_mb_refstate(mut self, refstate: Option<String>) -> Self {
        self.mb_refstate = refstate;
        self
    }
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
            runtime_policy_name: None,
            runtime_policy_sig_key: None,
            mb_policy: None,
            payload: None,
            cert_dir: None,
            verify: true,
            push_model: false,
            pull_model: false,
            tpm_policy: None,
            allow_unverified_quote: false,
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
            runtime_policy_name: None,
            runtime_policy_sig_key: None,
            mb_policy: Some("/path/to/measured_boot.json"),
            payload: Some("/path/to/payload.txt"),
            cert_dir: Some("/path/to/certs"),
            verify: false,
            push_model: true,
            pull_model: false,
            tpm_policy: Some("{\"test\": \"policy\"}"),
            allow_unverified_quote: false,
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
                runtime_policy_name: None,
                runtime_policy_sig_key: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: false,
                pull_model: false,
                tpm_policy: None,
                allow_unverified_quote: false,
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
                runtime_policy_name: None,
                runtime_policy_sig_key: None,
                mb_policy: Some("/etc/keylime/measured_boot.json"),
                payload: Some("/etc/keylime/payload.txt"),
                cert_dir: Some("/etc/keylime/certs"),
                verify: true,
                push_model: true,
                pull_model: false,
                tpm_policy: Some("{\"pcr\": [\"15\"]}"),
                allow_unverified_quote: false,
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
                runtime_policy_name: None,
                runtime_policy_sig_key: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false, // Verification different in push model
                push_model: true,
                pull_model: false,
                tpm_policy: None,
                allow_unverified_quote: false,
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
                Some("127.0.0.1".to_string()),
                Some(8881),
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
            assert_eq!(request.verifier_ip, Some("127.0.0.1".to_string()));
            assert_eq!(request.verifier_port, Some(8881));
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
        fn test_serialization_all_fields() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                Some("127.0.0.1".to_string()),
                Some(8881),
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

            // Policy fields serialize as empty strings by default
            assert_eq!(json_value["runtime_policy"], "");
            // mb_policy is absent when not set
            assert!(json_value.get("mb_policy").is_none());
        }
    }

    // Test Optional cloudagent_ip/cloudagent_port/verifier_ip/verifier_port
    mod optional_agent_fields {
        use super::*;

        #[test]
        fn test_add_agent_request_with_none_ip_port() {
            let request = AddAgentRequest::new(
                None,
                None,
                Some("127.0.0.1".to_string()),
                Some(8881),
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
                None,
                None,
                "{}".to_string(),
            );

            let serialized = serde_json::to_string(&request).unwrap(); //#[allow_ci]
            let json_value: Value =
                serde_json::from_str(&serialized).unwrap(); //#[allow_ci]

            // Optional fields are absent when None
            assert!(json_value.get("cloudagent_ip").is_none());
            assert!(json_value.get("cloudagent_port").is_none());
            assert!(json_value.get("verifier_ip").is_none());
            assert!(json_value.get("verifier_port").is_none());
        }

        #[test]
        fn test_add_agent_request_some_fields_serialized() {
            let request = AddAgentRequest::new(
                Some("192.168.1.100".to_string()),
                Some(9002),
                Some("127.0.0.1".to_string()),
                Some(8881),
                "{}".to_string(),
            );

            let serialized = serde_json::to_string(&request).unwrap(); //#[allow_ci]
            let json_value: Value =
                serde_json::from_str(&serialized).unwrap(); //#[allow_ci]

            assert_eq!(json_value["cloudagent_ip"], "192.168.1.100");
            assert_eq!(json_value["cloudagent_port"], 9002);
            assert_eq!(json_value["verifier_ip"], "127.0.0.1");
            assert_eq!(json_value["verifier_port"], 8881);
        }

        #[test]
        fn test_add_agent_params_with_pull_model() {
            let params = AddAgentParams {
                agent_id: "test-agent",
                ip: None,
                port: None,
                verifier_ip: None,
                runtime_policy: None,
                runtime_policy_name: None,
                runtime_policy_sig_key: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: false,
                pull_model: true,
                tpm_policy: None,
                wait_for_attestation: false,
                attestation_timeout: 60,
                allow_unverified_quote: false,
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
                runtime_policy_name: None,
                runtime_policy_sig_key: None,
                mb_policy: None,
                payload: None,
                cert_dir: None,
                verify: false,
                push_model: true,
                pull_model: false,
                tpm_policy: None,
                wait_for_attestation: true,
                attestation_timeout: 120,
                allow_unverified_quote: false,
            };

            assert!(params.wait_for_attestation);
            assert_eq!(params.attestation_timeout, 120);
        }
    }
}
