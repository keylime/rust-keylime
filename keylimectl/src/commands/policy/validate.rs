// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy validation and signature verification.

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use serde_json::Value;

/// Execute the policy validate command.
pub async fn execute(
    _file: &str,
    _policy_type: Option<&str>,
    _signature_key: Option<&str>,
    _output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    Err(KeylimectlError::validation(
        "policy validate is not yet implemented",
    ))
}

/// Verify a DSSE signature on a signed policy file.
pub async fn verify_signature(
    _file: &str,
    _key: &str,
    _output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    Err(KeylimectlError::validation(
        "policy verify-signature is not yet implemented",
    ))
}
