// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! DSSE (Dead Simple Signing Envelope) implementation.
//!
//! Implements the DSSE protocol for signing and verifying policy payloads.
//! Supports ECDSA P-256 and X.509 certificate signing backends.
//!
//! Reference: <https://github.com/secure-systems-lab/dsse>

pub mod ecdsa_backend;
pub mod x509_backend;

use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use serde::{Deserialize, Serialize};

/// Keylime policy DSSE payload type.
pub const KEYLIME_PAYLOAD_TYPE: &str = "application/vnd.keylime+json";

/// DSSE envelope structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// Base64-encoded payload.
    pub payload: String,

    /// Content type of the payload.
    pub payload_type: String,

    /// List of signatures.
    pub signatures: Vec<DsseSignature>,
}

/// A single signature within a DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Key identifier (fingerprint or base64-encoded certificate).
    pub keyid: String,

    /// Base64-encoded signature bytes.
    pub sig: String,
}

/// Result of successful verification.
pub struct VerifiedPayload {
    /// Content type.
    pub payload_type: String,

    /// Decoded payload bytes.
    pub payload: Vec<u8>,

    /// Names of signers that validated successfully.
    pub recognized_signers: Vec<String>,
}

/// Trait for signing DSSE payloads.
pub trait Signer {
    /// Sign a message and return the raw signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;

    /// Return the key identifier for this signer.
    fn keyid(&self) -> String;
}

/// Trait for verifying DSSE signatures.
pub trait Verifier {
    /// Verify a signature against a message.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

/// Pre-Authentication Encoding per DSSE specification.
///
/// Format: `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
///
/// This is the exact byte sequence that gets signed/verified.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let pt_bytes = payload_type.as_bytes();
    let mut result = Vec::new();

    result.extend_from_slice(b"DSSEv1 ");
    result.extend_from_slice(pt_bytes.len().to_string().as_bytes());
    result.push(b' ');
    result.extend_from_slice(pt_bytes);
    result.push(b' ');
    result.extend_from_slice(payload.len().to_string().as_bytes());
    result.push(b' ');
    result.extend_from_slice(payload);

    result
}

/// Sign a payload and produce a DSSE envelope.
pub fn sign_payload(
    payload: &[u8],
    payload_type: &str,
    signer: &dyn Signer,
) -> Result<DsseEnvelope, String> {
    let pae_bytes = pae(payload_type, payload);
    let signature = signer.sign(&pae_bytes)?;

    Ok(DsseEnvelope {
        payload: Base64.encode(payload),
        payload_type: payload_type.to_string(),
        signatures: vec![DsseSignature {
            keyid: signer.keyid(),
            sig: Base64.encode(signature),
        }],
    })
}

/// Verify a DSSE envelope against a set of named verifiers.
///
/// Returns the decoded payload and list of recognized signers if
/// at least one signature is valid.
pub fn verify_envelope(
    envelope: &DsseEnvelope,
    verifiers: &[(&str, &dyn Verifier)],
) -> Result<VerifiedPayload, String> {
    let payload = Base64
        .decode(&envelope.payload)
        .map_err(|e| format!("Invalid base64 payload: {e}"))?;

    let pae_bytes = pae(&envelope.payload_type, &payload);

    let mut recognized_signers = Vec::new();

    for sig_entry in &envelope.signatures {
        let sig_bytes = Base64
            .decode(&sig_entry.sig)
            .map_err(|e| format!("Invalid base64 signature: {e}"))?;

        for (name, verifier) in verifiers {
            if verifier.verify(&pae_bytes, &sig_bytes) {
                recognized_signers.push(name.to_string());
            }
        }
    }

    if recognized_signers.is_empty() {
        return Err("No valid signature found".to_string());
    }

    Ok(VerifiedPayload {
        payload_type: envelope.payload_type.clone(),
        payload,
        recognized_signers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pae_construction() {
        let result = pae("application/vnd.keylime+json", b"hello world");
        let expected =
            b"DSSEv1 28 application/vnd.keylime+json 11 hello world";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_empty_payload() {
        let result = pae("text/plain", b"");
        let expected = b"DSSEv1 10 text/plain 0 ";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_envelope_serialization() {
        let envelope = DsseEnvelope {
            payload: Base64.encode(b"test"),
            payload_type: KEYLIME_PAYLOAD_TYPE.to_string(),
            signatures: vec![DsseSignature {
                keyid: "test-key".to_string(),
                sig: Base64.encode(b"fake-sig"),
            }],
        };

        let json = serde_json::to_string(&envelope).unwrap(); //#[allow_ci]
        let parsed: DsseEnvelope = serde_json::from_str(&json).unwrap(); //#[allow_ci]

        assert_eq!(parsed.payload_type, KEYLIME_PAYLOAD_TYPE);
        assert_eq!(parsed.signatures.len(), 1);
        assert_eq!(parsed.signatures[0].keyid, "test-key");
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Use the ECDSA backend for integration test
        let signer = ecdsa_backend::EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let verifier =
            ecdsa_backend::EcdsaVerifier::from_signer(&signer).unwrap(); //#[allow_ci]

        let payload = b"test policy content";
        let envelope =
            sign_payload(payload, KEYLIME_PAYLOAD_TYPE, &signer).unwrap(); //#[allow_ci]

        let verifier_ref: &dyn Verifier = &verifier;
        let result =
            verify_envelope(&envelope, &[("test", verifier_ref)]).unwrap(); //#[allow_ci]

        assert_eq!(result.payload, payload);
        assert_eq!(result.payload_type, KEYLIME_PAYLOAD_TYPE);
        assert_eq!(result.recognized_signers, vec!["test"]);
    }

    #[test]
    fn test_verify_invalid_signature() {
        let signer = ecdsa_backend::EcdsaSigner::generate().unwrap(); //#[allow_ci]

        // Create a different key for verification
        let other_signer = ecdsa_backend::EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let other_verifier =
            ecdsa_backend::EcdsaVerifier::from_signer(&other_signer).unwrap(); //#[allow_ci]

        let envelope =
            sign_payload(b"test", KEYLIME_PAYLOAD_TYPE, &signer).unwrap(); //#[allow_ci]

        let verifier_ref: &dyn Verifier = &other_verifier;
        let result =
            verify_envelope(&envelope, &[("wrong-key", verifier_ref)]);

        assert!(result.is_err());
    }
}
