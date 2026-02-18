// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy validation and signature verification.

use base64::Engine;

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::policy_tools::dsse::{
    self, ecdsa_backend::EcdsaVerifier, x509_backend::X509Verifier,
    DsseEnvelope, Verifier,
};
use crate::policy_tools::validation::{self, ValidationResult};
use serde_json::Value;

/// Execute the policy validate command.
pub async fn execute(
    file: &str,
    policy_type: Option<&str>,
    signature_key: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    // Read the policy file
    let content = std::fs::read_to_string(file).map_err(|e| {
        KeylimectlError::validation(format!(
            "Failed to read policy file '{file}': {e}"
        ))
    })?;

    let mut json_value: Value =
        serde_json::from_str(&content).map_err(|e| {
            KeylimectlError::validation(format!(
                "Policy file is not valid JSON: {e}"
            ))
        })?;

    // If this is a DSSE envelope, extract the inner payload
    if json_value.get("payloadType").is_some()
        && json_value.get("payload").is_some()
        && json_value.get("signatures").is_some()
    {
        output.info("Detected DSSE envelope, extracting payload");
        let envelope: DsseEnvelope = serde_json::from_value(json_value)
            .map_err(|e| {
                KeylimectlError::validation(format!(
                    "Invalid DSSE envelope: {e}"
                ))
            })?;
        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(&envelope.payload)
            .map_err(|e| {
                KeylimectlError::validation(format!(
                    "Failed to decode DSSE payload: {e}"
                ))
            })?;
        json_value = serde_json::from_slice(&payload_bytes).map_err(|e| {
            KeylimectlError::validation(format!(
                "DSSE payload is not valid JSON: {e}"
            ))
        })?;
    }

    // Determine policy type
    let detected_type =
        policy_type.or_else(|| validation::detect_policy_type(&json_value));

    let policy_type_str = match detected_type {
        Some(t) => t,
        None => {
            return Err(KeylimectlError::validation(
                "Could not auto-detect policy type. Use --type to specify one of: runtime, measured-boot, tpm",
            ));
        }
    };

    output.info(format!("Validating {policy_type_str} policy from {file}"));

    // Validate based on type
    let result = match policy_type_str {
        "runtime" => {
            let policy: crate::policy_tools::runtime_policy::RuntimePolicy =
                serde_json::from_value(json_value.clone()).map_err(|e| {
                    KeylimectlError::validation(format!(
                        "Failed to parse as runtime policy: {e}"
                    ))
                })?;
            validation::validate_runtime_policy(&policy)
        }
        "measured-boot" => {
            let policy: crate::policy_tools::measured_boot_policy::MeasuredBootPolicy =
                serde_json::from_value(json_value.clone())
                    .map_err(|e| {
                        KeylimectlError::validation(format!(
                            "Failed to parse as measured boot policy: {e}"
                        ))
                    })?;
            validation::validate_measured_boot_policy(&policy)
        }
        "tpm" => {
            let policy: crate::policy_tools::tpm_policy::TpmPolicy =
                serde_json::from_value(json_value.clone()).map_err(|e| {
                    KeylimectlError::validation(format!(
                        "Failed to parse as TPM policy: {e}"
                    ))
                })?;
            validation::validate_tpm_policy(&policy)
        }
        other => {
            return Err(KeylimectlError::validation(
                format!(
                    "Unknown policy type '{other}'. Expected: runtime, measured-boot, tpm"
                ),
            ));
        }
    };

    // If a signature key is provided, also verify the DSSE signature
    if let Some(key) = signature_key {
        let sig_result = verify_signature(file, key, output).await?;
        if sig_result.get("valid") != Some(&Value::Bool(true)) {
            output.info("Signature verification failed");
            return Ok(serde_json::json!({
                "valid": false,
                "policy_type": policy_type_str,
                "signature_valid": false,
                "errors": [{"code": "signature_invalid", "message": "DSSE signature verification failed"}]
            }));
        }
    }

    // Format and return results
    format_validation_result(&result, policy_type_str, output)
}

/// Format validation result as JSON and print messages.
fn format_validation_result(
    result: &ValidationResult,
    policy_type: &str,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    if result.valid {
        output.info(format!("Policy validation passed ({policy_type})"));
    } else {
        output.info(format!("Policy validation failed ({policy_type})"));
    }

    for error in &result.errors {
        output.info(format!("  ERROR [{}]: {}", error.code, error.message));
    }

    for warning in &result.warnings {
        output.info(format!(
            "  WARNING [{}]: {}",
            warning.code, warning.message
        ));
    }

    let errors_json: Vec<Value> = result
        .errors
        .iter()
        .map(|e| {
            serde_json::json!({
                "code": e.code,
                "message": e.message
            })
        })
        .collect();

    let warnings_json: Vec<Value> = result
        .warnings
        .iter()
        .map(|w| {
            serde_json::json!({
                "code": w.code,
                "message": w.message
            })
        })
        .collect();

    Ok(serde_json::json!({
        "valid": result.valid,
        "policy_type": policy_type,
        "errors": errors_json,
        "warnings": warnings_json
    }))
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
