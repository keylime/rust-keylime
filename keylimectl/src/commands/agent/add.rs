// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent add (enrollment) command
//!
//! Handles both pull model (API 2.x) and push model (API 3.0+) enrollment.

#[cfg(feature = "api-v2")]
use super::attestation::{
    perform_agent_attestation, perform_key_delivery, verify_key_derivation,
};
use super::helpers::{
    load_payload_file, load_policy_file, resolve_tpm_policy_enhanced,
};
use super::types::AddAgentParams;
#[cfg(feature = "api-v2")]
use super::types::AddAgentRequest;
#[cfg(feature = "api-v2")]
use crate::client::agent::AgentClient;
use crate::client::factory;
use crate::client::verifier::VerifierClient;
use crate::commands::error::CommandError;
#[cfg(feature = "api-v2")]
use crate::config::singleton::get_config;
use crate::output::OutputHandler;
use base64::{engine::general_purpose::STANDARD, Engine};
use log::debug;
use serde_json::{json, Value};

/// Add (enroll) an agent to the verifier for continuous attestation monitoring
///
/// This function implements the correct Keylime enrollment workflow:
///
/// 1. **Check Registration**: Verify agent is registered with registrar
/// 2. **Enroll with Verifier**: Add agent to verifier with attestation policy
///
/// The flow differs based on API version:
/// - **API 2.x (Pull Model)**: Includes TPM quote verification and key exchange
/// - **API 3.0+ (Push Model)**: Simplified enrollment, agent pushes attestations
pub(super) async fn add_agent(
    params: AddAgentParams<'_>,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if params.agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    if params.agent_id.len() > 255 {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot exceed 255 characters".to_string(),
        ));
    }

    // Check for control characters that might cause issues
    if params.agent_id.chars().any(|c| c.is_control()) {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot contain control characters".to_string(),
        ));
    }

    output.info(format!("Adding agent {} to verifier", params.agent_id));

    // Step 1: Get agent data from registrar
    output.step(1, 4, "Retrieving agent data from registrar");

    let registrar_client = factory::get_registrar().await.map_err(|e| {
        CommandError::resource_error("registrar", e.to_string())
    })?;
    let agent_data = registrar_client
        .get_agent(params.agent_id)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "registrar",
                format!("Failed to retrieve agent data: {e}"),
            )
        })?;

    let agent_data = match agent_data {
        Some(data) => data,
        None => {
            return Err(CommandError::agent_operation_failed(
                params.agent_id,
                "enrollment",
                format!(
                    "Agent not found in registrar. \
                     Ensure the agent is running and has completed TPM registration. \
                     Check with: keylimectl agent status --registrar {}",
                    params.agent_id
                ),
            ));
        }
    };

    // Step 2: Determine API version and enrollment approach
    output.step(2, 4, "Detecting verifier API version");

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error("verifier", e.to_string())
    })?;

    let api_version =
        verifier_client.api_version().parse::<f32>().unwrap_or(2.1);

    // Determine enrollment model based on flags and API version:
    // 1. Explicit --push-model flag: always push
    // 2. Explicit --pull-model flag: always pull (with deprecation warning for v3.x)
    // 3. Auto-detect: push for API >= 3.0, pull for API < 3.0
    let is_push_model = if params.push_model {
        true
    } else if params.pull_model {
        if api_version >= 3.0 {
            log::warn!(
                "Pull model is deprecated for API v{api_version} verifiers. \
                 Consider using push model (default) instead."
            );
        }
        false
    } else {
        // Auto-detect based on API version
        #[cfg(feature = "api-v3")]
        {
            api_version >= 3.0
        }
        #[cfg(not(feature = "api-v3"))]
        {
            false
        }
    };

    debug!(
        "Detected API version: {api_version}, push model: {is_push_model}"
    );

    // Determine agent connection details
    let agent_ip = params.ip.map(|s| s.to_string()).or_else(|| {
        agent_data
            .get("ip")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
    });

    let agent_port = params.port.or_else(|| {
        agent_data
            .get("port")
            .and_then(|v| v.as_u64().map(|n| n as u16))
    });

    // Extract agent mTLS certificate from registrar data.
    // Used as trusted root CA when connecting directly to the agent.
    #[cfg(feature = "api-v2")]
    let agent_mtls_cert =
        agent_data.get("mtls_cert").and_then(|v| v.as_str());

    // Pull model requires IP and port for direct agent communication
    if !is_push_model {
        if agent_ip.is_none() {
            return Err(CommandError::invalid_parameter(
                "ip",
                "Agent IP address is required for pull model".to_string(),
            ));
        }
        if agent_port.is_none() {
            return Err(CommandError::invalid_parameter(
                "port",
                "Agent port is required for pull model".to_string(),
            ));
        }
    }

    // Use defaults for push model if not available from registrar
    let agent_ip = agent_ip.unwrap_or_else(|| "0.0.0.0".to_string());
    let agent_port = agent_port.unwrap_or(0);

    // Step 3: Perform attestation for pull model
    #[allow(unused_assignments, unused_variables)]
    let attestation_result: Option<Value> = if !is_push_model {
        #[cfg(feature = "api-v2")]
        {
            output.step(3, 4, "Performing TPM attestation (pull model)");

            // Create agent client for direct communication
            let agent_client = AgentClient::builder()
                .agent_ip(&agent_ip)
                .agent_port(agent_port)
                .config(get_config())
                .agent_cert(agent_mtls_cert)
                .build()
                .await
                .map_err(|e| {
                    CommandError::resource_error("agent", e.to_string())
                })?;

            // Perform TPM quote verification
            perform_agent_attestation(
                &agent_client,
                &agent_data,
                params.agent_id,
                output,
            )
            .await?
        }
        #[cfg(not(feature = "api-v2"))]
        {
            return Err(CommandError::invalid_parameter(
                "push_model",
                "Pull model is not available (api-v2 feature not enabled). \
                 Use --push-model for API v3.0+ enrollment."
                    .to_string(),
            ));
        }
    } else {
        output.step(3, 4, "Skipping agent attestation (push model)");
        None
    };

    // Step 4: Enroll agent with verifier
    output.step(4, 4, "Enrolling agent with verifier");

    // Build the request payload based on API version
    #[cfg(feature = "api-v2")]
    let cv_agent_ip = params.verifier_ip.unwrap_or(&agent_ip);

    // Resolve TPM policy with enhanced precedence handling
    let tpm_policy =
        resolve_tpm_policy_enhanced(params.tpm_policy, params.mb_policy)?;

    // Build enrollment request with version-appropriate fields
    #[allow(unused_mut)]
    let mut request = if is_push_model {
        // API 3.0+: Simplified enrollment for push model
        build_push_model_request(
            params.agent_id,
            &tpm_policy,
            &agent_data,
            params.runtime_policy,
            params.mb_policy,
            &agent_ip,
            agent_port,
        )?
    } else {
        #[cfg(feature = "api-v2")]
        {
            // API 2.x: Full enrollment with direct agent communication
            let mut request = AddAgentRequest::new(
                Some(cv_agent_ip.to_string()),
                Some(agent_port),
                get_config().verifier.ip.clone(),
                get_config().verifier.port,
                tpm_policy,
            )
            .with_ak_tpm(agent_data.get("aik_tpm").cloned())
            .with_mtls_cert(agent_data.get("mtls_cert").cloned())
            .with_metadata(
                agent_data
                    .get("metadata")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("{}".to_string())),
            ) // Use agent metadata or default
            .with_ima_sign_verification_keys(
                agent_data
                    .get("ima_sign_verification_keys")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("".to_string())),
            ) // Use agent IMA keys or default
            .with_revocation_key(
                agent_data
                    .get("revocation_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("".to_string())),
            ) // Use agent revocation key or default
            .with_accept_tpm_hash_algs(Some(vec![
                "sha512".to_string(),
                "sha384".to_string(),
                "sha256".to_string(),
            ]))
            .with_accept_tpm_encryption_algs(Some(vec![
                "ecc".to_string(),
                "rsa".to_string(),
            ]))
            .with_accept_tpm_signing_algs(Some(vec![
                "ecschnorr".to_string(),
                "rsassa".to_string(),
            ]))
            .with_supported_version(
                agent_data
                    .get("supported_version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("2.1".to_string())),
            ) // Use agent supported version or default
            .with_mb_policy_name(
                agent_data
                    .get("mb_policy_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("".to_string())),
            ) // Use agent MB policy name or default
            .with_mb_policy(
                agent_data
                    .get("mb_policy")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("".to_string())),
            ); // Use agent MB policy or default

            // Add V key from attestation if available
            if let Some(attestation) = &attestation_result {
                if let Some(v_key) = attestation.get("v_key") {
                    request = request.with_v_key(Some(v_key.clone()));
                }
            }

            serde_json::to_value(request)?
        }
        #[cfg(not(feature = "api-v2"))]
        {
            return Err(CommandError::invalid_parameter(
                "push_model",
                "Pull model is not available (api-v2 feature not enabled). \
                 Use --push-model for API v3.0+ enrollment."
                    .to_string(),
            ));
        }
    };

    // Ensure policy fields always have defaults (the Python verifier
    // expects these fields to be present as strings, not absent/null)
    if let Some(obj) = request.as_object_mut() {
        let _ = obj.entry("runtime_policy").or_insert(json!(""));
        let _ = obj.entry("runtime_policy_name").or_insert(json!(""));
        let _ = obj.entry("runtime_policy_key").or_insert(json!(""));
        let _ = obj.entry("runtime_policy_sig").or_insert(json!(""));
        let _ = obj.entry("mb_policy_name").or_insert(json!(""));
    }

    // Add policies if provided (base64-encoded as expected by verifier)
    if let Some(policy_path) = params.runtime_policy {
        let policy_content = load_policy_file(policy_path)?;
        let policy_b64 = STANDARD.encode(policy_content.as_bytes());
        if let Some(obj) = request.as_object_mut() {
            let _ =
                obj.insert("runtime_policy".to_string(), json!(policy_b64));
        }
    }

    if let Some(policy_path) = params.mb_policy {
        let policy_content = load_policy_file(policy_path)?;
        let policy_b64 = STANDARD.encode(policy_content.as_bytes());
        if let Some(obj) = request.as_object_mut() {
            let _ = obj.insert("mb_policy".to_string(), json!(policy_b64));
        }
    }

    // Add payload if provided
    if let Some(payload_path) = params.payload {
        let payload_content = load_payload_file(payload_path)?;
        if let Some(obj) = request.as_object_mut() {
            let _ = obj.insert("payload".to_string(), json!(payload_content));
        }
    }

    if let Some(cert_dir_path) = params.cert_dir {
        // For now, just pass the path - in future could generate cert package
        if let Some(obj) = request.as_object_mut() {
            let _ = obj.insert(
                "cert_dir".to_string(),
                json!(cert_dir_path.to_string()),
            );
        }
    }

    let response = verifier_client
        .add_agent(params.agent_id, request)
        .await
        .map_err(|e| {
            let model = if is_push_model { "push" } else { "pull" };
            CommandError::resource_error(
                "verifier",
                format!(
                    "Failed to enroll agent ({model} model): {e}. \
                     Retry with: keylimectl agent add {agent_id}",
                    agent_id = params.agent_id
                ),
            )
        })?;

    // Step 5: Perform legacy key delivery for API < 3.0
    #[cfg(feature = "api-v2")]
    if !is_push_model && attestation_result.is_some() {
        let agent_client = AgentClient::builder()
            .agent_ip(&agent_ip)
            .agent_port(agent_port)
            .config(get_config())
            .agent_cert(agent_mtls_cert)
            .build()
            .await
            .map_err(|e| {
                CommandError::resource_error(
                    "agent",
                    format!(
                        "Key delivery failed (agent enrolled but key not delivered): {e}. \
                         Remove and re-add: keylimectl agent remove {} && keylimectl agent add {}",
                        params.agent_id, params.agent_id
                    ),
                )
            })?;

        // Deliver U key and payload to agent
        if let Some(attestation) = attestation_result {
            perform_key_delivery(
                &agent_client,
                &attestation,
                params.payload,
                output,
            )
            .await?;

            // Verify key derivation if requested
            if params.verify {
                output.info("Performing key derivation verification");
                verify_key_derivation(&agent_client, &attestation, output)
                    .await?;
            }
        }
    }

    let enrollment_type = if is_push_model {
        "push model"
    } else {
        "pull model"
    };
    output.info(format!(
        "Agent {} successfully enrolled with verifier ({})",
        params.agent_id, enrollment_type
    ));

    // Optional: Wait for first attestation to complete
    let attestation_state = if params.wait_for_attestation {
        output.info("Waiting for first attestation to complete...");
        let state = poll_attestation_status(
            verifier_client,
            params.agent_id,
            params.attestation_timeout,
            output,
        )
        .await?;
        Some(state)
    } else {
        None
    };

    let mut result = json!({
        "status": "success",
        "message": format!("Agent {} enrolled successfully ({})", params.agent_id, enrollment_type),
        "agent_id": params.agent_id,
        "api_version": api_version,
        "push_model": is_push_model,
        "results": response
    });

    if let Some(state) = attestation_state {
        result["attestation_state"] = json!(state);
    }

    Ok(result)
}

/// Build enrollment request for push model (API 3.0+)
///
/// Creates a simplified enrollment request for push model attestation.
/// In push model, the agent will initiate attestations, so no direct
/// agent communication or key exchange is needed during enrollment.
fn build_push_model_request(
    agent_id: &str,
    tpm_policy: &str,
    agent_data: &Value,
    runtime_policy: Option<&str>,
    mb_policy: Option<&str>,
    cloudagent_ip: &str,
    cloudagent_port: u16,
) -> Result<Value, CommandError> {
    debug!("Building push model enrollment request for agent {agent_id}");

    // Load and encode runtime policy (required field, use empty string if not provided)
    let runtime_policy_b64 = if let Some(policy_path) = runtime_policy {
        let policy_content = load_policy_file(policy_path)?;
        STANDARD.encode(policy_content.as_bytes())
    } else {
        String::new() // Empty string if no policy provided
    };

    // Load and encode measured boot policy (use empty string if not provided)
    let mb_policy_b64 = if let Some(policy_path) = mb_policy {
        let policy_content = load_policy_file(policy_path)?;
        STANDARD.encode(policy_content.as_bytes())
    } else {
        String::new() // Empty string if no policy provided
    };

    let request = json!({
        "v": agent_data.get("v"),
        "cloudagent_ip": cloudagent_ip,
        "cloudagent_port": cloudagent_port,
        "tpm_policy": tpm_policy,
        "ak_tpm": agent_data.get("aik_tpm"),
        "mtls_cert": agent_data.get("mtls_cert"),
        "runtime_policy_name": null,
        "runtime_policy": runtime_policy_b64,
        "runtime_policy_sig": "",
        "runtime_policy_key": "",
        "mb_refstate": "null",
        "mb_policy_name": null,
        "mb_policy": mb_policy_b64,
        "ima_sign_verification_keys": agent_data.get("ima_sign_verification_keys").and_then(|v| v.as_str()).unwrap_or("[]"),
        "metadata": agent_data.get("metadata").and_then(|v| v.as_str()).unwrap_or("{}"),
        "revocation_key": agent_data.get("revocation_key").and_then(|v| v.as_str()).unwrap_or(""),
        "accept_tpm_hash_algs": ["sha512", "sha384", "sha256", "sha1"],
        "accept_tpm_encryption_algs": ["ecc", "rsa"],
        "accept_tpm_signing_algs": ["ecschnorr", "rsassa"],
        "supported_version": agent_data.get("supported_version").and_then(|v| v.as_str()).unwrap_or("2.0")
    });

    debug!("Push model request built successfully");
    Ok(request)
}

/// Extract operational state from verifier agent data as a human-readable string.
///
/// The verifier returns `operational_state` as an integer (0-10) or
/// occasionally as a string. This function handles both and converts
/// integers to their string representation.
fn extract_operational_state(data: &Value) -> Option<String> {
    let raw = data
        .pointer("/results/operational_state")
        .or_else(|| data.get("operational_state"));

    match raw {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => n.as_u64().map(operational_state_to_str),
        _ => None,
    }
}

/// Convert an operational state integer to a human-readable string.
///
/// State values are defined in keylime/common/states.py.
fn operational_state_to_str(state: u64) -> String {
    match state {
        0 => "Registered".to_string(),
        1 => "Start".to_string(),
        2 => "Saved".to_string(),
        3 => "Get Quote".to_string(),
        4 => "Get Quote (retry)".to_string(),
        5 => "Provide V".to_string(),
        6 => "Provide V (retry)".to_string(),
        7 => "Failed".to_string(),
        8 => "Terminated".to_string(),
        9 => "Invalid Quote".to_string(),
        10 => "Tenant Failed".to_string(),
        _ => format!("Unknown ({state})"),
    }
}

/// Poll verifier for agent attestation status until it reaches PASS or FAIL.
///
/// The verifier response includes an `attestation_status` field that is
/// computed from the agent's operational state (for pull mode) or from
/// attestation history (for push mode). The possible values are:
/// - `"PENDING"`: attestation has not yet completed
/// - `"PASS"`: agent has been successfully attested
/// - `"FAIL"`: attestation failed
///
/// Returns the attestation status string on success ("PASS").
/// Returns an error if the agent enters a failure state or the timeout expires.
async fn poll_attestation_status(
    verifier_client: &VerifierClient,
    agent_id: &str,
    timeout_secs: u64,
    output: &OutputHandler,
) -> Result<String, CommandError> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let poll_interval = std::time::Duration::from_secs(2);

    loop {
        if start.elapsed() > timeout {
            return Err(CommandError::agent_operation_failed(
                agent_id,
                "attestation",
                format!(
                    "Timed out waiting for attestation after {timeout_secs}s. \
                     The agent may still complete attestation. \
                     Check status with: keylimectl agent status {agent_id}"
                ),
            ));
        }

        match verifier_client.get_agent(agent_id).await {
            Ok(Some(data)) => {
                let attestation_status = extract_attestation_status(&data);
                let operational_state = extract_operational_state(&data);

                match attestation_status {
                    Some("FAIL") => {
                        // Collect failure details from the response
                        let severity = data
                            .pointer("/results/severity_level")
                            .or_else(|| data.get("severity_level"))
                            .and_then(|v| v.as_u64());
                        let last_event = data
                            .pointer("/results/last_event_id")
                            .or_else(|| data.get("last_event_id"))
                            .and_then(|v| v.as_str());

                        let mut reason =
                            String::from("Agent attestation failed");
                        if let Some(state) = operational_state {
                            reason.push_str(&format!(" (state: {state})"));
                        }
                        if let Some(severity) = severity {
                            reason
                                .push_str(&format!(", severity: {severity}"));
                        }
                        if let Some(event) = last_event {
                            reason
                                .push_str(&format!(", last event: {event}"));
                        }

                        return Err(CommandError::agent_operation_failed(
                            agent_id,
                            "attestation",
                            reason,
                        ));
                    }
                    Some("PASS") => {
                        output.info(format!(
                            "Agent {agent_id} attestation successful"
                        ));
                        return Ok("PASS".to_string());
                    }
                    _ => {
                        // PENDING or missing — keep polling
                        debug!(
                            "Agent attestation status: {:?}, operational_state: {:?}, waiting...",
                            attestation_status, operational_state
                        );
                    }
                }
            }
            Ok(None) => {
                debug!("Agent not yet visible on verifier, waiting...");
            }
            Err(e) => {
                debug!("Error polling agent status: {e}, retrying...");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Extract attestation_status from verifier agent data
///
/// The verifier computes this field based on operational_state (pull mode)
/// or attestation history (push mode). Values: "PENDING", "PASS", "FAIL".
fn extract_attestation_status(data: &Value) -> Option<&str> {
    data.get("results")
        .and_then(|r| r.get("attestation_status"))
        .and_then(|s| s.as_str())
        .or_else(|| data.get("attestation_status").and_then(|s| s.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_operational_state_nested_integer() {
        let data = json!({
            "results": {
                "operational_state": 3
            }
        });
        assert_eq!(
            extract_operational_state(&data),
            Some("Get Quote".to_string())
        );
    }

    #[test]
    fn test_extract_operational_state_nested_string() {
        let data = json!({
            "results": {
                "operational_state": "Get Quote"
            }
        });
        assert_eq!(
            extract_operational_state(&data),
            Some("Get Quote".to_string())
        );
    }

    #[test]
    fn test_extract_operational_state_top_level() {
        let data = json!({
            "operational_state": 7
        });
        assert_eq!(
            extract_operational_state(&data),
            Some("Failed".to_string())
        );
    }

    #[test]
    fn test_extract_operational_state_missing() {
        let data = json!({
            "other_field": "value"
        });
        assert_eq!(extract_operational_state(&data), None);
    }

    #[test]
    fn test_extract_operational_state_empty() {
        let data = json!({});
        assert_eq!(extract_operational_state(&data), None);
    }

    #[test]
    fn test_extract_operational_state_prefers_nested() {
        let data = json!({
            "operational_state": 1,
            "results": {
                "operational_state": 3
            }
        });
        assert_eq!(
            extract_operational_state(&data),
            Some("Get Quote".to_string())
        );
    }

    #[test]
    fn test_operational_state_to_str() {
        assert_eq!(operational_state_to_str(0), "Registered");
        assert_eq!(operational_state_to_str(1), "Start");
        assert_eq!(operational_state_to_str(2), "Saved");
        assert_eq!(operational_state_to_str(3), "Get Quote");
        assert_eq!(operational_state_to_str(4), "Get Quote (retry)");
        assert_eq!(operational_state_to_str(5), "Provide V");
        assert_eq!(operational_state_to_str(6), "Provide V (retry)");
        assert_eq!(operational_state_to_str(7), "Failed");
        assert_eq!(operational_state_to_str(8), "Terminated");
        assert_eq!(operational_state_to_str(9), "Invalid Quote");
        assert_eq!(operational_state_to_str(10), "Tenant Failed");
        assert_eq!(operational_state_to_str(99), "Unknown (99)");
    }

    #[test]
    fn test_extract_attestation_status() {
        let data = json!({
            "results": {
                "attestation_status": "PASS"
            }
        });
        assert_eq!(extract_attestation_status(&data), Some("PASS"));

        let data = json!({
            "attestation_status": "FAIL"
        });
        assert_eq!(extract_attestation_status(&data), Some("FAIL"));

        let data = json!({});
        assert_eq!(extract_attestation_status(&data), None);
    }

    #[test]
    fn test_model_auto_detection_logic() {
        // Test the auto-detection logic that determines push vs pull model
        // This tests the decision matrix without requiring async/network calls

        struct ModelParams {
            push_model: bool,
            pull_model: bool,
            api_version: f32,
        }

        fn determine_model(params: &ModelParams) -> bool {
            if params.push_model {
                true
            } else if params.pull_model {
                false
            } else {
                params.api_version >= 3.0
            }
        }

        // Explicit --push-model always wins
        assert!(determine_model(&ModelParams {
            push_model: true,
            pull_model: false,
            api_version: 2.1,
        }));
        assert!(determine_model(&ModelParams {
            push_model: true,
            pull_model: false,
            api_version: 3.0,
        }));

        // Explicit --pull-model forces pull
        assert!(!determine_model(&ModelParams {
            push_model: false,
            pull_model: true,
            api_version: 2.1,
        }));
        assert!(!determine_model(&ModelParams {
            push_model: false,
            pull_model: true,
            api_version: 3.0,
        }));

        // Auto-detect: push for v3.x, pull for v2.x
        assert!(!determine_model(&ModelParams {
            push_model: false,
            pull_model: false,
            api_version: 2.0,
        }));
        assert!(!determine_model(&ModelParams {
            push_model: false,
            pull_model: false,
            api_version: 2.1,
        }));
        assert!(determine_model(&ModelParams {
            push_model: false,
            pull_model: false,
            api_version: 3.0,
        }));
        assert!(determine_model(&ModelParams {
            push_model: false,
            pull_model: false,
            api_version: 3.1,
        }));
    }
}
