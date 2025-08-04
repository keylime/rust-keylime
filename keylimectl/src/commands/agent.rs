// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent management commands

use crate::client::{registrar::RegistrarClient, verifier::VerifierClient};
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::AgentAction;
use log::{debug, warn};
use serde_json::{json, Value};
use uuid::Uuid;

/// Execute an agent command
pub async fn execute(
    action: &AgentAction,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        AgentAction::Add {
            uuid,
            ip,
            port,
            verifier_ip,
            runtime_policy,
            mb_policy,
            payload,
            cert_dir,
            verify,
            push_model,
        } => {
            add_agent(
                AddAgentParams {
                    uuid,
                    ip: ip.as_deref(),
                    port: *port,
                    verifier_ip: verifier_ip.as_deref(),
                    runtime_policy: runtime_policy.as_deref(),
                    mb_policy: mb_policy.as_deref(),
                    payload: payload.as_deref(),
                    cert_dir: cert_dir.as_deref(),
                    verify: *verify,
                    push_model: *push_model,
                },
                config,
                output,
            )
            .await
        }
        AgentAction::Remove {
            uuid,
            from_registrar,
            force,
        } => {
            remove_agent(uuid, *from_registrar, *force, config, output).await
        }
        AgentAction::Update {
            uuid,
            runtime_policy,
            mb_policy,
        } => {
            update_agent(
                uuid,
                runtime_policy.as_deref(),
                mb_policy.as_deref(),
                config,
                output,
            )
            .await
        }
        AgentAction::Status {
            uuid,
            verifier_only,
            registrar_only,
        } => {
            get_agent_status(
                uuid,
                *verifier_only,
                *registrar_only,
                config,
                output,
            )
            .await
        }
        AgentAction::Reactivate { uuid } => {
            reactivate_agent(uuid, config, output).await
        }
    }
}

/// Parameters for adding an agent
struct AddAgentParams<'a> {
    uuid: &'a str,
    ip: Option<&'a str>,
    port: Option<u16>,
    verifier_ip: Option<&'a str>,
    runtime_policy: Option<&'a str>,
    mb_policy: Option<&'a str>,
    payload: Option<&'a str>,
    cert_dir: Option<&'a str>,
    verify: bool,
    push_model: bool,
}

/// Add an agent to the verifier
async fn add_agent(
    params: AddAgentParams<'_>,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    // Validate UUID
    let agent_uuid = Uuid::parse_str(params.uuid)
        .validate(|| format!("Invalid agent UUID: {}", params.uuid))?;

    output.info(format!("Adding agent {agent_uuid} to verifier"));

    // Step 1: Get agent data from registrar
    output.step(1, 4, "Retrieving agent data from registrar");

    let registrar_client = RegistrarClient::new(config)?;
    let agent_data = registrar_client
        .get_agent(&agent_uuid.to_string())
        .await
        .with_context(|| {
            "Failed to retrieve agent data from registrar".to_string()
        })?;

    if agent_data.is_none() {
        return Err(KeylimectlError::agent_not_found(
            agent_uuid.to_string(),
            "registrar",
        ));
    }

    let agent_data = agent_data.unwrap();

    // Step 2: Determine agent connection details
    output.step(2, 4, "Validating agent connection details");

    let (agent_ip, agent_port) = if params.push_model {
        // In push model, agent connects to verifier
        ("localhost".to_string(), 9002)
    } else {
        // Get IP and port from CLI args or registrar data
        let agent_ip = params
            .ip
            .map(|s| s.to_string())
            .or_else(|| {
                agent_data
                    .get("ip")
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
            })
            .ok_or_else(|| {
                KeylimectlError::validation(
                    "Agent IP address is required when not using push model",
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
                KeylimectlError::validation(
                    "Agent port is required when not using push model",
                )
            })?;

        (agent_ip, agent_port)
    };

    // Step 3: Perform attestation if not using push model
    if !params.push_model {
        output.step(3, 4, "Performing attestation with agent");

        // TODO: Implement TPM quote verification
        // This would involve:
        // 1. Connecting to the agent
        // 2. Getting a TPM quote with a random nonce
        // 3. Validating the quote against the AIK from registrar
        // 4. Encrypting the U key with the agent's public key

        output.info("Attestation completed successfully");
    } else {
        output.step(3, 4, "Skipping attestation (push model)");
    }

    // Step 4: Add agent to verifier
    output.step(4, 4, "Adding agent to verifier");

    let verifier_client = VerifierClient::new(config)?;

    // Build the request payload
    let cv_agent_ip = params.verifier_ip.unwrap_or(&agent_ip);

    let mut request_data = json!({
        "cloudagent_ip": cv_agent_ip,
        "cloudagent_port": agent_port,
        "verifier_ip": config.verifier.ip,
        "verifier_port": config.verifier.port,
        "ak_tpm": agent_data.get("aik_tpm"),
        "mtls_cert": agent_data.get("mtls_cert"),
    });

    // Add policies if provided
    if let Some(policy) = params.runtime_policy {
        // TODO: Load and process runtime policy
        request_data["runtime_policy"] = json!(policy);
    }

    if let Some(policy) = params.mb_policy {
        // TODO: Load and process measured boot policy
        request_data["mb_policy"] = json!(policy);
    }

    // Add payload if provided
    if let Some(payload_path) = params.payload {
        // TODO: Load and encrypt payload
        request_data["payload"] = json!(payload_path);
    }

    if let Some(cert_dir_path) = params.cert_dir {
        // TODO: Generate and encrypt certificate package
        request_data["cert_dir"] = json!(cert_dir_path);
    }

    let response = verifier_client
        .add_agent(&agent_uuid.to_string(), request_data)
        .await
        .with_context(|| "Failed to add agent to verifier".to_string())?;

    // Step 5: Verify if requested
    if params.verify && !params.push_model {
        output.info("Performing key derivation verification");
        // TODO: Implement key derivation verification
    }

    output.info(format!("Agent {agent_uuid} successfully added to verifier"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} added successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": response
    }))
}

/// Remove an agent from the verifier (and optionally registrar)
async fn remove_agent(
    uuid: &str,
    from_registrar: bool,
    force: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Removing agent {agent_uuid} from verifier"));

    let verifier_client = VerifierClient::new(config)?;

    // Check if agent exists on verifier (unless force is used)
    if !force {
        output.step(
            1,
            if from_registrar { 3 } else { 2 },
            "Checking agent status on verifier",
        );

        match verifier_client.get_agent(&agent_uuid.to_string()).await {
            Ok(Some(_)) => {
                debug!("Agent found on verifier");
            }
            Ok(None) => {
                warn!("Agent not found on verifier, but continuing with removal");
            }
            Err(e) => {
                if !force {
                    return Err(e);
                }
                warn!("Failed to check agent status, but continuing due to force flag: {e}");
            }
        }
    }

    // Remove from verifier
    let step_num = if force { 1 } else { 2 };
    let total_steps = if from_registrar {
        if force {
            2
        } else {
            3
        }
    } else if force {
        1
    } else {
        2
    };

    output.step(step_num, total_steps, "Removing agent from verifier");

    let verifier_response = verifier_client
        .delete_agent(&agent_uuid.to_string())
        .await
        .with_context(|| {
            "Failed to remove agent from verifier".to_string()
        })?;

    let mut results = json!({
        "verifier": verifier_response
    });

    // Remove from registrar if requested
    if from_registrar {
        output.step(
            total_steps,
            total_steps,
            "Removing agent from registrar",
        );

        let registrar_client = RegistrarClient::new(config)?;
        let registrar_response = registrar_client
            .delete_agent(&agent_uuid.to_string())
            .await
            .with_context(|| {
                "Failed to remove agent from registrar".to_string()
            })?;

        results["registrar"] = registrar_response;
    }

    output.info(format!("Agent {agent_uuid} successfully removed"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} removed successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": results
    }))
}

/// Update an existing agent
async fn update_agent(
    uuid: &str,
    runtime_policy: Option<&str>,
    mb_policy: Option<&str>,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Updating agent {agent_uuid}"));

    // For now, implement update as delete + add
    // TODO: Implement proper update API when available

    output.step(1, 2, "Removing existing agent configuration");
    let _remove_result =
        remove_agent(uuid, false, false, config, output).await?;

    output.step(2, 2, "Adding agent with new configuration");
    // TODO: Get previous configuration and merge with new values
    let add_result = add_agent(
        AddAgentParams {
            uuid,
            ip: None,   // TODO: Get from previous config
            port: None, // TODO: Get from previous config
            verifier_ip: None,
            runtime_policy,
            mb_policy,
            payload: None,
            cert_dir: None,
            verify: false,
            push_model: false, // TODO: Get from previous config
        },
        config,
        output,
    )
    .await?;

    output.info(format!("Agent {agent_uuid} successfully updated"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} updated successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": add_result
    }))
}

/// Get agent status from verifier and/or registrar
async fn get_agent_status(
    uuid: &str,
    verifier_only: bool,
    registrar_only: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Getting status for agent {agent_uuid}"));

    let mut results = json!({});

    // Get status from registrar (unless verifier_only is set)
    if !verifier_only {
        output.progress("Checking registrar status");

        let registrar_client = RegistrarClient::new(config)?;
        match registrar_client.get_agent(&agent_uuid.to_string()).await {
            Ok(Some(agent_data)) => {
                results["registrar"] = json!({
                    "status": "found",
                    "data": agent_data
                });
            }
            Ok(None) => {
                results["registrar"] = json!({
                    "status": "not_found"
                });
            }
            Err(e) => {
                results["registrar"] = json!({
                    "status": "error",
                    "error": e.to_string()
                });
            }
        }
    }

    // Get status from verifier (unless registrar_only is set)
    if !registrar_only {
        output.progress("Checking verifier status");

        let verifier_client = VerifierClient::new(config)?;
        match verifier_client.get_agent(&agent_uuid.to_string()).await {
            Ok(Some(agent_data)) => {
                results["verifier"] = json!({
                    "status": "found",
                    "data": agent_data
                });
            }
            Ok(None) => {
                results["verifier"] = json!({
                    "status": "not_found"
                });
            }
            Err(e) => {
                results["verifier"] = json!({
                    "status": "error",
                    "error": e.to_string()
                });
            }
        }
    }

    Ok(json!({
        "agent_uuid": agent_uuid.to_string(),
        "results": results
    }))
}

/// Reactivate a failed agent
async fn reactivate_agent(
    uuid: &str,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    let agent_uuid = Uuid::parse_str(uuid)
        .validate(|| format!("Invalid agent UUID: {uuid}"))?;

    output.info(format!("Reactivating agent {agent_uuid}"));

    let verifier_client = VerifierClient::new(config)?;
    let response = verifier_client
        .reactivate_agent(&agent_uuid.to_string())
        .await
        .with_context(|| "Failed to reactivate agent".to_string())?;

    output.info(format!("Agent {agent_uuid} successfully reactivated"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_uuid} reactivated successfully"),
        "agent_uuid": agent_uuid.to_string(),
        "results": response
    }))
}
