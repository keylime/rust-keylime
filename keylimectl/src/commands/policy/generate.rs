// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Local policy generation commands.
//!
//! Generates runtime, measured boot, and TPM policies from local
//! input sources without requiring network connectivity.

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::GenerateSubcommand;
use serde_json::Value;

/// Execute a policy generation subcommand.
pub async fn execute(
    subcommand: &GenerateSubcommand,
    _output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match subcommand {
        GenerateSubcommand::Runtime { .. } => {
            Err(KeylimectlError::validation(
                "policy generate runtime is not yet implemented",
            ))
        }
        GenerateSubcommand::MeasuredBoot { .. } => {
            Err(KeylimectlError::validation(
                "policy generate measured-boot is not yet implemented",
            ))
        }
        GenerateSubcommand::Tpm { .. } => Err(KeylimectlError::validation(
            "policy generate tpm is not yet implemented",
        )),
    }
}
