// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy management commands for keylimectl.
//!
//! This module provides both verifier-side policy CRUD operations and
//! local policy tools (generation, signing, validation, conversion).

mod convert;
mod crud;
mod generate;
mod sign;
mod validate;

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::PolicyAction;
use serde_json::Value;

/// Execute a policy command.
pub async fn execute(
    action: &PolicyAction,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match action {
        // Verifier-side CRUD operations
        PolicyAction::Create { .. }
        | PolicyAction::Show { .. }
        | PolicyAction::Update { .. }
        | PolicyAction::Delete { .. } => {
            crud::execute(action, output).await
        }

        // Local policy generation
        PolicyAction::Generate { subcommand } => {
            generate::execute(subcommand, output).await
        }

        // Policy signing
        PolicyAction::Sign {
            file,
            keyfile,
            keypath,
            backend,
            output: output_file,
            cert_outfile,
        } => {
            sign::execute(
                file,
                keyfile.as_deref(),
                keypath.as_deref(),
                backend,
                output_file.as_deref(),
                cert_outfile.as_deref(),
                output,
            )
            .await
        }

        // Signature verification
        PolicyAction::VerifySignature { file, key } => {
            validate::verify_signature(file, key, output).await
        }

        // Policy validation
        PolicyAction::Validate {
            file,
            policy_type,
            signature_key,
        } => {
            validate::execute(
                file,
                policy_type.as_deref(),
                signature_key.as_deref(),
                output,
            )
            .await
        }

        // Legacy policy conversion
        PolicyAction::Convert {
            file,
            output: output_file,
            excludelist,
            verification_keys,
        } => {
            convert::execute(
                file,
                output_file,
                excludelist.as_deref(),
                verification_keys.as_deref(),
                output,
            )
            .await
        }
    }
}
