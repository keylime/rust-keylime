// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Agent removal command

use crate::client::factory;
use crate::client::verifier::VerifierClient;
use crate::commands::error::CommandError;
use crate::config::singleton::get_config;
use crate::output::OutputHandler;
use log::{debug, warn};
use serde_json::{json, Value};

/// Remove an agent from the verifier (and optionally registrar)
///
/// When the verifier responds to DELETE with 202 Accepted (meaning an
/// in-flight attestation cycle is still completing), this function polls
/// until the agent is fully gone before returning. Callers can therefore
/// assume the agent is no longer present on the verifier when this
/// function succeeds.
pub(super) async fn remove_agent(
    agent_id: &str,
    registrar: bool,
    force: bool,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    // Validate agent ID
    if agent_id.is_empty() {
        return Err(CommandError::invalid_parameter(
            "agent_id",
            "Agent ID cannot be empty".to_string(),
        ));
    }

    output.info(format!("Removing agent {agent_id} from verifier"));

    let verifier_client = factory::get_verifier().await.map_err(|e| {
        CommandError::resource_error("verifier", e.to_string())
    })?;

    // Check if agent exists on verifier (unless force is used)
    if !force {
        output.step(
            1,
            if registrar { 3 } else { 2 },
            "Checking agent status on verifier",
        );

        match verifier_client.get_agent(agent_id).await {
            Ok(Some(_)) => {
                debug!("Agent found on verifier");
            }
            Ok(None) => {
                warn!("Agent not found on verifier, but continuing with removal");
            }
            Err(e) => {
                if !force {
                    return Err(CommandError::resource_error(
                        "verifier",
                        e.to_string(),
                    ));
                }
                warn!("Failed to check agent status, but continuing due to force flag: {e}");
            }
        }
    }

    // Remove from verifier
    let step_num = if force { 1 } else { 2 };
    let total_steps = if registrar {
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

    let verifier_response =
        verifier_client.delete_agent(agent_id).await.map_err(|e| {
            CommandError::resource_error(
                "verifier",
                format!("Failed to remove agent: {e}"),
            )
        })?;

    // If the verifier returned 202 Accepted, deletion is asynchronous:
    // an in-flight attestation cycle is still running. Poll until the
    // agent is fully gone so the caller gets a clean post-condition.
    let http_status = verifier_response
        .get("http_status")
        .and_then(|v| v.as_u64())
        .unwrap_or(200);

    if http_status == 202 {
        poll_agent_removal(verifier_client, agent_id, output).await?;
    }

    let mut results = json!({
        "verifier": verifier_response
    });

    // Remove from registrar if requested
    if registrar {
        output.step(
            total_steps,
            total_steps,
            "Removing agent from registrar",
        );

        let registrar_client =
            factory::get_registrar().await.map_err(|e| {
                CommandError::resource_error("registrar", e.to_string())
            })?;
        let registrar_response =
            registrar_client.delete_agent(agent_id).await.map_err(|e| {
                CommandError::resource_error(
                    "registrar",
                    format!("Failed to remove agent: {e}"),
                )
            })?;

        results["registrar"] = registrar_response;
    }

    output.info(format!("Agent {agent_id} successfully removed"));

    Ok(json!({
        "status": "success",
        "message": format!("Agent {agent_id} removed successfully"),
        "agent_id": agent_id,
        "results": results
    }))
}

/// Poll the verifier until the agent is fully removed (returns 404).
///
/// After a DELETE returns 202, the verifier processes the removal
/// asynchronously while the current attestation cycle completes. This
/// function waits with exponential backoff until the agent is gone.
async fn poll_agent_removal(
    verifier_client: &VerifierClient,
    agent_id: &str,
    output: &OutputHandler,
) -> Result<(), CommandError> {
    let config = get_config();
    let max_retries = config.client.max_retries as usize;
    let retry_interval = config.client.retry_interval;
    let exponential_backoff = config.client.exponential_backoff;

    let wait_handle = output.start_wait(format!(
        "Waiting for verifier to complete deletion of agent {agent_id}..."
    ));

    for attempt in 0..=max_retries {
        match verifier_client.get_agent(agent_id).await {
            Ok(None) => {
                drop(wait_handle);
                debug!(
                    "Agent {agent_id} fully removed after {attempt} poll(s)"
                );
                return Ok(());
            }
            Ok(Some(_)) => {
                if attempt >= max_retries {
                    drop(wait_handle);
                    return Err(CommandError::agent_operation_failed(
                        agent_id,
                        "remove",
                        format!(
                            "Verifier did not finish removing the agent after \
                             {max_retries} retries. Try again with: \
                             keylimectl agent remove {agent_id}"
                        ),
                    ));
                }

                let delay = compute_backoff(
                    retry_interval,
                    exponential_backoff,
                    attempt,
                );
                wait_handle.set_message(format!(
                    "Agent {agent_id} still present on verifier, \
                     retrying in {delay:.1}s (attempt {}/{max_retries})",
                    attempt + 1
                ));
                debug!(
                    "Agent {agent_id} still present, sleeping {delay:.1}s \
                     (attempt {attempt}/{max_retries})"
                );
                tokio::time::sleep(std::time::Duration::from_secs_f64(delay))
                    .await;
            }
            Err(e) => {
                drop(wait_handle);
                return Err(CommandError::resource_error(
                    "verifier",
                    format!("Failed to poll agent deletion status: {e}"),
                ));
            }
        }
    }

    // Unreachable: the loop returns in all branches when attempt == max_retries
    Ok(())
}

/// Compute the delay before the next retry attempt.
///
/// With exponential backoff: delay = interval * 2^attempt, capped at 60s.
/// Without: delay = interval (constant).
fn compute_backoff(
    retry_interval: f64,
    exponential_backoff: bool,
    attempt: usize,
) -> f64 {
    let delay = if exponential_backoff {
        retry_interval * 2.0_f64.powi(attempt as i32)
    } else {
        retry_interval
    };
    delay.min(60.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_backoff_linear() {
        let delay = compute_backoff(1.0, false, 0);
        assert!((delay - 1.0).abs() < f64::EPSILON);
        let delay = compute_backoff(1.0, false, 5);
        assert!((delay - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_backoff_exponential() {
        assert!((compute_backoff(1.0, true, 0) - 1.0).abs() < f64::EPSILON);
        assert!((compute_backoff(1.0, true, 1) - 2.0).abs() < f64::EPSILON);
        assert!((compute_backoff(1.0, true, 2) - 4.0).abs() < f64::EPSILON);
        assert!((compute_backoff(1.0, true, 3) - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_backoff_cap() {
        // Should be capped at 60 seconds
        let delay = compute_backoff(1.0, true, 10); // 2^10 = 1024
        assert!((delay - 60.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_backoff_custom_interval() {
        assert!((compute_backoff(2.0, true, 2) - 8.0).abs() < f64::EPSILON);
        assert!((compute_backoff(0.5, true, 3) - 4.0).abs() < f64::EPSILON);
    }
}
