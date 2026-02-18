// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! One-shot evidence verification via the verifier.

use crate::client::factory;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::VerifyAction;
use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use serde_json::{json, Value};

/// Execute the verify evidence command.
pub async fn execute(
    action: &VerifyAction,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let VerifyAction::Evidence {
        nonce,
        quote,
        hash_alg,
        tpm_ak,
        tpm_ek,
        runtime_policy,
        ima_measurement_list,
        mb_policy,
        mb_log,
        tpm_policy,
        evidence_type,
    } = action;

    output.info(format!("Verifying {evidence_type} attestation evidence"));

    // Build the evidence data object
    let data = build_evidence_data(
        nonce,
        quote,
        hash_alg,
        tpm_ak,
        tpm_ek,
        runtime_policy.as_deref(),
        ima_measurement_list.as_deref(),
        mb_policy.as_deref(),
        mb_log.as_deref(),
        tpm_policy.as_deref(),
    )?;

    let request_body = json!({
        "type": evidence_type,
        "data": data,
    });

    // Connect to the verifier and send the evidence
    let client = factory::get_verifier().await?;

    output.info("Sending evidence to verifier...");

    let response = client.verify_evidence(request_body).await?;

    // Parse and display the result
    format_evidence_result(&response, output)
}

/// Build the evidence data object from CLI arguments.
#[allow(clippy::too_many_arguments)]
fn build_evidence_data(
    nonce: &str,
    quote_path: &str,
    hash_alg: &str,
    tpm_ak_path: &str,
    tpm_ek_path: &str,
    runtime_policy_path: Option<&str>,
    ima_ml_path: Option<&str>,
    mb_policy_path: Option<&str>,
    mb_log_path: Option<&str>,
    tpm_policy_path: Option<&str>,
) -> Result<Value, KeylimectlError> {
    // Read and base64-encode binary files
    let quote_data = read_and_b64(quote_path)?;
    let tpm_ak_data = read_and_b64(tpm_ak_path)?;
    let tpm_ek_data = read_and_b64(tpm_ek_path)?;

    let mut data = json!({
        "nonce": nonce,
        "quote": quote_data,
        "hash_alg": hash_alg,
        "tpm_ak": tpm_ak_data,
        "tpm_ek": tpm_ek_data,
    });

    // Add optional policy files
    if let Some(path) = runtime_policy_path {
        let content = read_file_string(path)?;
        data["runtime_policy"] = Value::String(content);
    }

    if let Some(path) = ima_ml_path {
        let content = read_file_string(path)?;
        data["ima_measurement_list"] = Value::String(content);
    }

    if let Some(path) = mb_policy_path {
        let content = read_file_string(path)?;
        data["mb_policy"] = Value::String(content);
    }

    if let Some(path) = mb_log_path {
        let content = read_and_b64(path)?;
        data["mb_log"] = Value::String(content);
    }

    if let Some(path) = tpm_policy_path {
        let content = read_file_string(path)?;
        data["tpm_policy"] = Value::String(content);
    }

    // Verify at least one policy is provided
    if runtime_policy_path.is_none()
        && mb_policy_path.is_none()
        && tpm_policy_path.is_none()
    {
        return Err(KeylimectlError::validation(
            "At least one policy must be provided (--runtime-policy, --mb-policy, or --tpm-policy)",
        ));
    }

    Ok(data)
}

/// Read a file and return its contents as a base64 string.
fn read_and_b64(path: &str) -> Result<String, KeylimectlError> {
    let data = std::fs::read(path).map_err(|e| {
        KeylimectlError::validation(format!(
            "Failed to read file '{path}': {e}"
        ))
    })?;
    Ok(Base64.encode(&data))
}

/// Read a file and return its contents as a UTF-8 string.
fn read_file_string(path: &str) -> Result<String, KeylimectlError> {
    std::fs::read_to_string(path).map_err(|e| {
        KeylimectlError::validation(format!(
            "Failed to read file '{path}': {e}"
        ))
    })
}

/// Format and display the evidence verification result.
fn format_evidence_result(
    response: &Value,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let results = response.get("results").unwrap_or(response);

    let valid = results
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if valid {
        output.info("Evidence verification: PASSED");
    } else {
        output.info("Evidence verification: FAILED");

        // Display failures if present
        if let Some(failures) =
            results.get("failures").and_then(|f| f.as_array())
        {
            for failure in failures {
                let failure_type = failure
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown");
                let message = failure
                    .get("context")
                    .and_then(|c| c.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("No details");
                output.info(format!("  [{failure_type}]: {message}"));
            }
        }
    }

    Ok(json!({
        "valid": valid,
        "results": results,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_evidence_data_missing_policy() {
        let result = build_evidence_data(
            "nonce123",
            "/nonexistent/quote",
            "sha256",
            "/nonexistent/ak",
            "/nonexistent/ek",
            None,
            None,
            None,
            None,
            None,
        );
        // Should fail because file doesn't exist
        // (or because no policy is provided)
        assert!(result.is_err());
    }

    #[test]
    fn test_format_evidence_result_valid() {
        let response = json!({
            "code": 200,
            "status": "Success",
            "results": {
                "valid": true,
                "claims": {},
                "failures": []
            }
        });

        let output = OutputHandler::new(crate::OutputFormat::Json, false);
        let result = format_evidence_result(&response, &output).unwrap(); //#[allow_ci]
        assert_eq!(result.get("valid"), Some(&Value::Bool(true)));
    }

    #[test]
    fn test_format_evidence_result_invalid() {
        let response = json!({
            "code": 200,
            "status": "Success",
            "results": {
                "valid": false,
                "claims": {},
                "failures": [{
                    "type": "pcr_mismatch",
                    "context": {
                        "message": "PCR 0 does not match expected value"
                    }
                }]
            }
        });

        let output = OutputHandler::new(crate::OutputFormat::Json, false);
        let result = format_evidence_result(&response, &output).unwrap(); //#[allow_ci]
        assert_eq!(result.get("valid"), Some(&Value::Bool(false)));
    }

    #[test]
    fn test_read_and_b64() {
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), b"test data").unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let result = read_and_b64(&path).unwrap(); //#[allow_ci]
        let decoded = Base64.decode(&result).unwrap(); //#[allow_ci]
        assert_eq!(decoded, b"test data");
    }

    #[test]
    fn test_read_file_string() {
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), "text content").unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let result = read_file_string(&path).unwrap(); //#[allow_ci]
        assert_eq!(result, "text content");
    }
}
