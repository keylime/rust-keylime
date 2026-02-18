// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! One-shot evidence verification via the verifier.

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::VerifyAction;
use serde_json::Value;

/// Execute the verify evidence command.
pub async fn execute(
    _action: &VerifyAction,
    _output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    Err(KeylimectlError::validation(
        "verify evidence is not yet implemented",
    ))
}
