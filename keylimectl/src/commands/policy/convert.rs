// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Legacy policy format conversion.

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use serde_json::Value;

/// Execute the policy convert command.
pub async fn execute(
    _file: &str,
    _output_file: &str,
    _excludelist: Option<&str>,
    _verification_keys: Option<&str>,
    _output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    Err(KeylimectlError::validation(
        "policy convert is not yet implemented",
    ))
}
