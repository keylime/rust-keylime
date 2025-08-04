// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! List commands for various resources

use crate::client::{registrar::RegistrarClient, verifier::VerifierClient};
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::ListResource;
use serde_json::{json, Value};

/// Execute a list command
pub async fn execute(
    resource: &ListResource,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match resource {
        ListResource::Agents { detailed } => {
            list_agents(*detailed, config, output).await
        }
        ListResource::Policies => list_runtime_policies(config, output).await,
        ListResource::MeasuredBootPolicies => {
            list_mb_policies(config, output).await
        }
    }
}

/// List all agents
async fn list_agents(
    detailed: bool,
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    if detailed {
        output.info("Retrieving detailed agent information from both verifier and registrar");
    } else {
        output.info("Listing agents from verifier");
    }

    let verifier_client = VerifierClient::new(config)?;

    if detailed {
        // Get detailed info from verifier
        let verifier_data = verifier_client
            .get_bulk_info(config.verifier.id.as_deref())
            .await
            .with_context(|| {
                "Failed to get bulk agent info from verifier".to_string()
            })?;

        // Also get registrar data for complete picture
        let registrar_client = RegistrarClient::new(config)?;
        let registrar_data =
            registrar_client.list_agents().await.with_context(|| {
                "Failed to list agents from registrar".to_string()
            })?;

        Ok(json!({
            "detailed": true,
            "verifier": verifier_data,
            "registrar": registrar_data
        }))
    } else {
        // Just get basic list from verifier
        let verifier_data = verifier_client
            .list_agents(config.verifier.id.as_deref())
            .await
            .with_context(|| {
                "Failed to list agents from verifier".to_string()
            })?;

        Ok(verifier_data)
    }
}

/// List runtime policies
async fn list_runtime_policies(
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info("Listing runtime policies");

    let verifier_client = VerifierClient::new(config)?;
    let policies = verifier_client
        .list_runtime_policies()
        .await
        .with_context(|| {
            "Failed to list runtime policies from verifier".to_string()
        })?;

    Ok(policies)
}

/// List measured boot policies
async fn list_mb_policies(
    config: &Config,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    output.info("Listing measured boot policies");

    let verifier_client = VerifierClient::new(config)?;
    let policies =
        verifier_client.list_mb_policies().await.with_context(|| {
            "Failed to list measured boot policies from verifier".to_string()
        })?;

    Ok(policies)
}
