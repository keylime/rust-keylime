// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Diagnostic information commands for keylimectl
//!
//! Provides subcommands for inspecting configuration, server status,
//! agents, and TLS certificates. These commands are designed to work
//! even when configuration is incomplete.

mod agent_info;
mod registrar_info;
mod self_info;
mod tls_info;
mod verifier_info;

use serde_json::Value;

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::InfoSubcommand;

/// Execute the info command dispatcher.
pub async fn execute(
    subcommand: &Option<InfoSubcommand>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match subcommand {
        None => self_info::execute(output),
        Some(InfoSubcommand::Verifier) => {
            verifier_info::execute(output).await
        }
        Some(InfoSubcommand::Registrar) => {
            registrar_info::execute(output).await
        }
        Some(InfoSubcommand::Agent { agent_id }) => {
            agent_info::execute(agent_id, output).await
        }
        Some(InfoSubcommand::Tls) => tls_info::execute(output),
    }
}
