// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! List commands for various Keylime resources
//!
//! This module provides comprehensive listing functionality for all major Keylime resources,
//! including agents, runtime policies, and measured boot policies. It offers both basic
//! and detailed views depending on user requirements.
//!
//! # Resource Types
//!
//! The list command supports several resource types:
//!
//! 1. **Agents**: List all agents registered with the system
//!    - Basic view: Shows agent status from verifier
//!    - Detailed view: Combines data from both verifier and registrar
//! 2. **Runtime Policies**: List all runtime/IMA policies
//! 3. **Measured Boot Policies**: List all measured boot policies
//!
//! # Agent Listing Modes
//!
//! ## Basic Mode
//! - Retrieves agent list from verifier only
//! - Shows operational state and basic status
//! - Faster operation, suitable for quick status checks
//! - Shows: UUID, operational state
//!
//! ## Detailed Mode
//! - Retrieves comprehensive data from both verifier and registrar
//! - Shows complete agent information including TPM data
//! - Slower operation but provides complete picture
//! - Shows: UUID, operational state, IP, port, TPM keys, registration info
//!
//! # Policy Listing
//!
//! Policy listing provides an overview of all configured policies:
//! - Policy names and metadata
//! - Creation and modification timestamps
//! - Policy status and validation state
//!
//! # Performance Considerations
//!
//! - Basic agent listing is optimized for speed
//! - Detailed listing may take longer with many agents
//! - Policy listing is generally fast as policies are typically fewer
//! - Results are paginated automatically for large deployments
//!
//! # Examples
//!
//! ```rust
//! use keylimectl::commands::list;
//! use keylimectl::config::Config;
//! use keylimectl::output::OutputHandler;
//! use keylimectl::ListResource;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::default();
//! let output = OutputHandler::new(crate::OutputFormat::Json, false);
//!
//! // List agents with basic information
//! let basic_agents = ListResource::Agents { detailed: false };
//! let result = list::execute(&basic_agents, &config, &output).await?;
//!
//! // List agents with detailed information
//! let detailed_agents = ListResource::Agents { detailed: true };
//! let result = list::execute(&detailed_agents, &config, &output).await?;
//!
//! // List runtime policies
//! let policies = ListResource::Policies;
//! let result = list::execute(&policies, &config, &output).await?;
//!
//! // List measured boot policies
//! let mb_policies = ListResource::MeasuredBootPolicies;
//! let result = list::execute(&mb_policies, &config, &output).await?;
//! # Ok(())
//! # }
//! ```

use crate::client::{registrar::RegistrarClient, verifier::VerifierClient};
use crate::config::Config;
use crate::error::{ErrorContext, KeylimectlError};
use crate::output::OutputHandler;
use crate::ListResource;
use serde_json::{json, Value};

/// Execute a resource listing command
///
/// This is the main entry point for all resource listing operations. It dispatches
/// to the appropriate handler based on the resource type and manages the complete
/// operation lifecycle including data retrieval, formatting, and result reporting.
///
/// # Arguments
///
/// * `resource` - The specific resource type to list (Agents, Policies, or MeasuredBootPolicies)
/// * `config` - Configuration containing service endpoints and authentication settings
/// * `output` - Output handler for progress reporting and result formatting
///
/// # Returns
///
/// Returns a JSON value containing the listing results. The structure varies by resource type:
///
/// ## Agent Listing (Basic)
/// ```json
/// {
///   "results": {
///     "agent-uuid-1": "operational_state",
///     "agent-uuid-2": "operational_state"
///   }
/// }
/// ```
///
/// ## Agent Listing (Detailed)
/// ```json
/// {
///   "detailed": true,
///   "verifier": {
///     "results": {
///       "agent-uuid-1": {
///         "operational_state": "Get Quote",
///         "ip": "192.168.1.100",
///         "port": 9002
///       }
///     }
///   },
///   "registrar": {
///     "results": {
///       "agent-uuid-1": {
///         "aik_tpm": "base64-encoded-key",
///         "ek_tpm": "base64-encoded-key",
///         "ip": "192.168.1.100",
///         "port": 9002,
///         "active": true
///       }
///     }
///   }
/// }
/// ```
///
/// ## Policy Listing
/// ```json
/// {
///   "results": {
///     "policy-name-1": {
///       "created": "2025-01-01T00:00:00Z",
///       "last_modified": "2025-01-02T12:00:00Z"
///     }
///   }
/// }
/// ```
///
/// # Error Handling
///
/// This function handles various error conditions:
/// - Network failures when communicating with services
/// - Service unavailability (verifier or registrar down)
/// - Authentication/authorization failures
/// - Empty result sets (no resources found)
///
/// # Performance Notes
///
/// - Basic agent listing is optimized for speed
/// - Detailed agent listing requires two API calls (verifier + registrar)
/// - Policy listing is typically fast due to smaller data volumes
/// - Large deployments may experience longer response times
///
/// # Examples
///
/// ```rust
/// use keylimectl::commands::list;
/// use keylimectl::config::Config;
/// use keylimectl::output::OutputHandler;
/// use keylimectl::ListResource;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::default();
/// let output = OutputHandler::new(crate::OutputFormat::Json, false);
///
/// // List agents (basic)
/// let agents = ListResource::Agents { detailed: false };
/// let result = list::execute(&agents, &config, &output).await?;
/// println!("Found {} agents", result["results"].as_object().unwrap().len());
///
/// // List policies
/// let policies = ListResource::Policies;
/// let result = list::execute(&policies, &config, &output).await?;
/// # Ok(())
/// # }
/// ```
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
