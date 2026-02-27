// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Interactive wizard for evidence verification.

use crate::client::factory;
use crate::commands::verify::evidence;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use dialoguer::{Confirm, Input, Select};
use serde_json::{json, Value};

/// Map a dialoguer error to a `KeylimectlError`.
fn input_err(e: dialoguer::Error) -> KeylimectlError {
    KeylimectlError::Validation(format!("Failed to read user input: {e}"))
}

/// Run the interactive evidence verification wizard.
pub async fn run(
    defaults: &Defaults<'_>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    eprintln!();
    eprintln!("Evidence Verification Wizard");
    eprintln!("============================");
    eprintln!();

    // ── Step 1: Evidence type ─────────────────────────────────────
    eprintln!("Step 1: Evidence type");
    eprintln!();

    let type_options = ["tpm", "tee"];
    let default_type_idx = type_options
        .iter()
        .position(|&t| t == defaults.evidence_type)
        .unwrap_or(0);

    let type_idx = Select::new()
        .with_prompt("Evidence type")
        .items(type_options)
        .default(default_type_idx)
        .interact()
        .map_err(input_err)?;

    let evidence_type = type_options[type_idx];

    // ── Step 2: Required files ────────────────────────────────────
    eprintln!();
    eprintln!("Step 2: Required files");
    eprintln!();

    let nonce: String = Input::new()
        .with_prompt("Nonce")
        .default(defaults.nonce.unwrap_or("").to_string())
        .interact_text()
        .map_err(input_err)?;

    if nonce.trim().is_empty() {
        return Err(KeylimectlError::Validation("Nonce is required".into()));
    }

    let quote: String = Input::new()
        .with_prompt("TPM quote file path")
        .default(defaults.quote.unwrap_or("").to_string())
        .interact_text()
        .map_err(input_err)?;

    if quote.trim().is_empty() {
        return Err(KeylimectlError::Validation(
            "TPM quote file is required".into(),
        ));
    }

    let tpm_ak: String = Input::new()
        .with_prompt("TPM Attestation Key (AK) file path")
        .default(defaults.tpm_ak.unwrap_or("").to_string())
        .interact_text()
        .map_err(input_err)?;

    if tpm_ak.trim().is_empty() {
        return Err(KeylimectlError::Validation(
            "TPM AK file is required".into(),
        ));
    }

    let tpm_ek: String = Input::new()
        .with_prompt("TPM Endorsement Key (EK) file path")
        .default(defaults.tpm_ek.unwrap_or("").to_string())
        .interact_text()
        .map_err(input_err)?;

    if tpm_ek.trim().is_empty() {
        return Err(KeylimectlError::Validation(
            "TPM EK file is required".into(),
        ));
    }

    // ── Step 3: Hash algorithm ────────────────────────────────────
    eprintln!();
    eprintln!("Step 3: Hash algorithm");
    eprintln!();

    let alg_options = ["sha256", "sha1", "sha384", "sha512"];
    let default_alg_idx = alg_options
        .iter()
        .position(|&a| a == defaults.hash_alg)
        .unwrap_or(0);

    let alg_idx = Select::new()
        .with_prompt("Hash algorithm")
        .items(alg_options)
        .default(default_alg_idx)
        .interact()
        .map_err(input_err)?;

    let hash_alg = alg_options[alg_idx];

    // ── Step 4: Policies ──────────────────────────────────────────
    eprintln!();
    eprintln!("Step 4: Policies (at least one required)");
    eprintln!();

    let use_runtime = Confirm::new()
        .with_prompt("Include runtime policy?")
        .default(defaults.runtime_policy.is_some())
        .interact()
        .map_err(input_err)?;

    let runtime_policy = if use_runtime {
        let path: String = Input::new()
            .with_prompt("Runtime policy file path")
            .default(defaults.runtime_policy.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    let use_mb = Confirm::new()
        .with_prompt("Include measured boot policy?")
        .default(defaults.mb_policy.is_some())
        .interact()
        .map_err(input_err)?;

    let mb_policy = if use_mb {
        let path: String = Input::new()
            .with_prompt("Measured boot policy file path")
            .default(defaults.mb_policy.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    let use_tpm = Confirm::new()
        .with_prompt("Include TPM policy?")
        .default(defaults.tpm_policy.is_some())
        .interact()
        .map_err(input_err)?;

    let tpm_policy = if use_tpm {
        let path: String = Input::new()
            .with_prompt("TPM policy file path")
            .default(defaults.tpm_policy.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    if runtime_policy.is_none() && mb_policy.is_none() && tpm_policy.is_none()
    {
        return Err(KeylimectlError::Validation(
            "At least one policy must be provided".into(),
        ));
    }

    // ── Step 5: Measurement logs ──────────────────────────────────
    eprintln!();
    eprintln!("Step 5: Measurement logs");
    eprintln!();

    let ima_ml = if runtime_policy.is_some() {
        let path: String = Input::new()
            .with_prompt("IMA measurement list file (empty to skip)")
            .default(defaults.ima_measurement_list.unwrap_or("").to_string())
            .allow_empty(true)
            .interact_text()
            .map_err(input_err)?;
        if path.trim().is_empty() {
            None
        } else {
            Some(path)
        }
    } else {
        None
    };

    let mb_log = if mb_policy.is_some() {
        let path: String = Input::new()
            .with_prompt("Measured boot log file (empty to skip)")
            .default(defaults.mb_log.unwrap_or("").to_string())
            .allow_empty(true)
            .interact_text()
            .map_err(input_err)?;
        if path.trim().is_empty() {
            None
        } else {
            Some(path)
        }
    } else {
        None
    };

    // ── Step 6: Confirm ───────────────────────────────────────────
    eprintln!();

    eprintln!("  Evidence type: {evidence_type}");
    eprintln!("  Nonce:         {nonce}");
    eprintln!("  Quote:         {quote}");
    eprintln!("  TPM AK:        {tpm_ak}");
    eprintln!("  TPM EK:        {tpm_ek}");
    eprintln!("  Algorithm:     {hash_alg}");
    if let Some(ref p) = runtime_policy {
        eprintln!("  Runtime policy: {p}");
    }
    if let Some(ref p) = ima_ml {
        eprintln!("  IMA log:       {p}");
    }
    if let Some(ref p) = mb_policy {
        eprintln!("  MB policy:     {p}");
    }
    if let Some(ref p) = mb_log {
        eprintln!("  MB log:        {p}");
    }
    if let Some(ref p) = tpm_policy {
        eprintln!("  TPM policy:    {p}");
    }
    eprintln!();

    let confirm = Confirm::new()
        .with_prompt("Send to verifier for verification?")
        .default(true)
        .interact()
        .map_err(input_err)?;

    if !confirm {
        return Err(KeylimectlError::Validation("Cancelled by user".into()));
    }

    // ── Verify ────────────────────────────────────────────────────
    eprintln!();

    let data = evidence::build_evidence_data(
        &nonce,
        &quote,
        hash_alg,
        &tpm_ak,
        &tpm_ek,
        runtime_policy.as_deref(),
        ima_ml.as_deref(),
        mb_policy.as_deref(),
        mb_log.as_deref(),
        tpm_policy.as_deref(),
    )?;

    let request_body = json!({
        "type": evidence_type,
        "data": data,
    });

    let client = factory::get_verifier().await?;

    output.info("Sending evidence to verifier...");

    let response = client.verify_evidence(request_body).await?;

    evidence::format_evidence_result(&response, output)
}

/// Default values for the wizard, populated from CLI arguments.
#[derive(Debug)]
pub struct Defaults<'a> {
    /// Evidence type (tpm or tee).
    pub evidence_type: &'a str,
    /// Nonce.
    pub nonce: Option<&'a str>,
    /// TPM quote file path.
    pub quote: Option<&'a str>,
    /// Hash algorithm.
    pub hash_alg: &'a str,
    /// TPM AK file path.
    pub tpm_ak: Option<&'a str>,
    /// TPM EK file path.
    pub tpm_ek: Option<&'a str>,
    /// Runtime policy file path.
    pub runtime_policy: Option<&'a str>,
    /// IMA measurement list file path.
    pub ima_measurement_list: Option<&'a str>,
    /// Measured boot policy file path.
    pub mb_policy: Option<&'a str>,
    /// Measured boot log file path.
    pub mb_log: Option<&'a str>,
    /// TPM policy file path.
    pub tpm_policy: Option<&'a str>,
}
