// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy signing using DSSE (Dead Simple Signing Envelope).

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::SigningBackend;
use serde_json::Value;

/// Execute the policy sign command.
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    _file: &str,
    _keyfile: Option<&str>,
    _keypath: Option<&str>,
    _backend: &SigningBackend,
    _output_file: Option<&str>,
    _cert_outfile: Option<&str>,
    _output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    Err(KeylimectlError::validation(
        "policy sign is not yet implemented",
    ))
}
