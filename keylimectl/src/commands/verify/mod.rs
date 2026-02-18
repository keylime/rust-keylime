// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Attestation verification commands.

mod evidence;

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::VerifyAction;
use serde_json::Value;

/// Execute a verify command.
pub async fn execute(
    action: &VerifyAction,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        VerifyAction::Evidence { .. } => {
            evidence::execute(action, output).await
        }
    }
}
