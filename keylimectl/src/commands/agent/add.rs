// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent add (enrollment) command
//!
//! Handles both pull model (API 2.x) and push model (API 3.0+) enrollment.

use super::attestation::{
    perform_agent_attestation, perform_key_delivery, verify_key_derivation,
};
use super::helpers::{
    load_payload_file, load_policy_file, resolve_tpm_policy_enhanced,
};
use super::types::{AddAgentParams, AddAgentRequest};
use crate::client::agent::AgentClient;
use crate::client::factory;
use crate::commands::error::CommandError;
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
            return Err(CommandError::agent_not_found(
                params.agent_id.to_string(),
                "registrar",
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

    // Use push model if explicitly requested via --push-model flag
    // This skips direct agent communication and uses API v3.0 for verifier requests
    let is_push_model = params.push_model;

    if is_push_model {
        debug!(
            "Detected API version: auto-detected (overridden to 3.0), using API version: {api_version}, push model: {is_push_model}"
        );
    } else {
        debug!(
            "Detected API version: {api_version}, using API version: {api_version}, push model: {is_push_model}"
        );
    }

    // Determine agent connection details
    let agent_ip = params
        .ip
        .map(|s| s.to_string())
        .or_else(|| {
            agent_data
                .get("ip")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
        })
        .ok_or_else(|| {
            CommandError::invalid_parameter(
                "ip",
                "Agent IP address is required".to_string(),
            )
        })?;

    let agent_port = params
        .port
        .or_else(|| {
            agent_data
                .get("port")
                .and_then(|v| v.as_u64().map(|n| n as u16))
        })
        .ok_or_else(|| {
            CommandError::invalid_parameter(
                "port",
                "Agent port is required".to_string(),
            )
        })?;

    // Step 3: Perform attestation for pull model
    let attestation_result = if !is_push_model {
        output.step(3, 4, "Performing TPM attestation (pull model)");

        // Create agent client for direct communication
        let agent_client = AgentClient::builder()
            .agent_ip(&agent_ip)
            .agent_port(agent_port)
            .config(get_config())
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
    } else {
        output.step(3, 4, "Skipping agent attestation (push model)");
        None
    };

    // Step 4: Enroll agent with verifier
    output.step(4, 4, "Enrolling agent with verifier");

    // Build the request payload based on API version
    let cv_agent_ip = params.verifier_ip.unwrap_or(&agent_ip);

    // Resolve TPM policy with enhanced precedence handling
    let tpm_policy =
        resolve_tpm_policy_enhanced(params.tpm_policy, params.mb_policy)?;

    // Build enrollment request with version-appropriate fields
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
        // API 2.x: Full enrollment with direct agent communication
        let mut request = AddAgentRequest::new(
            cv_agent_ip.to_string(),
            agent_port,
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
            "sha256".to_string(),
            "sha1".to_string(),
        ])) // Add required TPM hash algorithms
        .with_accept_tpm_encryption_algs(Some(vec![
            "rsa".to_string(),
            "ecc".to_string(),
        ])) // Add required TPM encryption algorithms
        .with_accept_tpm_signing_algs(Some(vec![
            "rsa".to_string(),
            "ecdsa".to_string(),
        ])) // Add required TPM signing algorithms
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
    };

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
            CommandError::resource_error(
                "verifier",
                format!("Failed to add agent: {e}"),
            )
        })?;

    // Step 5: Perform legacy key delivery for API < 3.0
    if !is_push_model && attestation_result.is_some() {
        let agent_client = AgentClient::builder()
            .agent_ip(&agent_ip)
            .agent_port(agent_port)
            .config(get_config())
            .build()
            .await
            .map_err(|e| {
                CommandError::resource_error("agent", e.to_string())
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

    Ok(json!({
        "status": "success",
        "message": format!("Agent {} enrolled successfully ({})", params.agent_id, enrollment_type),
        "agent_id": params.agent_id,
        "api_version": api_version,
        "push_model": is_push_model,
        "results": response
    }))
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
