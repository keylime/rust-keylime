// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy validation and signature verification.

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::policy_tools::dsse::{
    self, ecdsa_backend::EcdsaVerifier, x509_backend::X509Verifier,
    DsseEnvelope, Verifier,
};
use serde_json::Value;

/// Execute the policy validate command.
pub async fn execute(
    _file: &str,
    _policy_type: Option<&str>,
    _signature_key: Option<&str>,
    _output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    Err(KeylimectlError::validation(
        "policy validate is not yet implemented",
    ))
}

/// Verify a DSSE signature on a signed policy file.
pub async fn verify_signature(
    file: &str,
    key: &str,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    // Read the signed policy (DSSE envelope)
    let envelope_content = std::fs::read_to_string(file).map_err(|e| {
        KeylimectlError::validation(format!(
            "Failed to read signed policy '{file}': {e}"
        ))
    })?;

    let envelope: DsseEnvelope = serde_json::from_str(&envelope_content)
        .map_err(|e| {
            KeylimectlError::validation(format!("Invalid DSSE envelope: {e}"))
        })?;

    // Read the key/certificate file
    let key_content = std::fs::read(key).map_err(|e| {
        KeylimectlError::validation(format!(
            "Failed to read key file '{key}': {e}"
        ))
    })?;

    let key_str = std::str::from_utf8(&key_content).unwrap_or("");

    // Determine if this is a certificate or public key
    let verifiers: Vec<(&str, Box<dyn Verifier>)> = if key_str
        .contains("BEGIN CERTIFICATE")
    {
        vec![(
            "x509",
            Box::new(X509Verifier::from_cert_pem(&key_content).map_err(
                |e| {
                    KeylimectlError::validation(format!(
                        "Failed to load certificate: {e}"
                    ))
                },
            )?),
        )]
    } else {
        vec![(
            "ecdsa",
            Box::new(EcdsaVerifier::from_pem(&key_content).map_err(|e| {
                KeylimectlError::validation(format!(
                    "Failed to load public key: {e}"
                ))
            })?),
        )]
    };

    let verifier_refs: Vec<(&str, &dyn Verifier)> = verifiers
        .iter()
        .map(|(name, v)| (*name, v.as_ref()))
        .collect();

    match dsse::verify_envelope(&envelope, &verifier_refs) {
        Ok(result) => {
            output.info(format!(
                "Signature verified successfully by: {}",
                result.recognized_signers.join(", ")
            ));
            output.info(format!("Payload type: {}", result.payload_type));
            output.info(format!(
                "Payload size: {} bytes",
                result.payload.len()
            ));

            Ok(serde_json::json!({
                "valid": true,
                "payload_type": result.payload_type,
                "recognized_signers": result.recognized_signers,
                "payload_size": result.payload.len()
            }))
        }
        Err(e) => {
            output.info(format!("Signature verification failed: {e}"));
            Ok(serde_json::json!({
                "valid": false,
                "error": e
            }))
        }
    }
}
