// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Interactive wizard for TPM policy generation.

use crate::commands::policy::generate;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde_json::Value;

/// PCR descriptions for the interactive selector.
const PCR_DESCRIPTIONS: [&str; 24] = [
    "PCR  0: S-CRTM, BIOS, firmware",
    "PCR  1: Host platform configuration",
    "PCR  2: Option ROM code",
    "PCR  3: Option ROM configuration and data",
    "PCR  4: IPL code (boot loaders, shim, GRUB)",
    "PCR  5: IPL configuration and data",
    "PCR  6: State transitions and wake events",
    "PCR  7: Secure Boot state",
    "PCR  8: Kernel command line (GRUB)",
    "PCR  9: Initrd, kernel (GRUB)",
    "PCR 10: IMA",
    "PCR 11: (application-specific)",
    "PCR 12: (application-specific)",
    "PCR 13: (application-specific)",
    "PCR 14: (application-specific)",
    "PCR 15: (application-specific)",
    "PCR 16: Debug",
    "PCR 17: DRTM / TXT",
    "PCR 18: Trusted OS (TXT)",
    "PCR 19: Trusted OS (TXT)",
    "PCR 20: Trusted OS (TXT)",
    "PCR 21: (defined by OS)",
    "PCR 22: (defined by OS)",
    "PCR 23: Application support",
];

/// Map a dialoguer error to a `KeylimectlError`.
fn input_err(e: dialoguer::Error) -> KeylimectlError {
    KeylimectlError::Validation(format!("Failed to read user input: {e}"))
}

/// Run the interactive TPM policy generation wizard.
pub fn run(
    defaults: &Defaults<'_>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    eprintln!();
    eprintln!("TPM Policy Generation Wizard");
    eprintln!("============================");
    eprintln!();

    // ── Step 1: PCR source ────────────────────────────────────────
    eprintln!("Step 1: PCR source");
    eprintln!();

    let source_options = ["Read from PCR values file", "Read from local TPM"];
    let default_source = if defaults.from_tpm { 1 } else { 0 };

    let source_idx = Select::new()
        .with_prompt("Where should PCR values be read from?")
        .items(source_options)
        .default(default_source)
        .interact()
        .map_err(input_err)?;

    let from_tpm = source_idx == 1;

    let pcr_file = if !from_tpm {
        let path: String = Input::new()
            .with_prompt("PCR values file path")
            .default(defaults.pcr_file.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    // ── Step 2: PCR indices ───────────────────────────────────────
    eprintln!();
    eprintln!("Step 2: PCR indices");
    eprintln!();

    // Pre-select PCRs from defaults (default: 0-7)
    let preselected: Vec<bool> = (0..24)
        .map(|i| defaults.pcr_indices.contains(&(i as u32)))
        .collect();

    let selected = MultiSelect::new()
        .with_prompt("Which PCR indices should be included in the policy?")
        .items(PCR_DESCRIPTIONS)
        .defaults(&preselected)
        .interact()
        .map_err(input_err)?;

    if selected.is_empty() {
        return Err(KeylimectlError::Validation(
            "At least one PCR index must be selected".into(),
        ));
    }

    let pcr_indices: Vec<u32> = selected.iter().map(|&i| i as u32).collect();
    let pcrs_str = pcr_indices
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");

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

    // ── Step 4: Output ────────────────────────────────────────────
    eprintln!();
    eprintln!("Step 4: Output");
    eprintln!();

    let output_raw: String = Input::new()
        .with_prompt("Output file (empty for stdout)")
        .default(defaults.output_file.unwrap_or("").to_string())
        .allow_empty(true)
        .interact_text()
        .map_err(input_err)?;

    let output_file = if output_raw.trim().is_empty() {
        None
    } else {
        Some(output_raw)
    };

    // ── Step 5: Confirm ───────────────────────────────────────────
    eprintln!();

    eprintln!(
        "  Source:     {}",
        if from_tpm { "local TPM" } else { "file" }
    );
    eprintln!("  PCR indices: {pcrs_str}");
    eprintln!("  Algorithm:   {hash_alg}");
    eprintln!();

    let confirm = Confirm::new()
        .with_prompt("Generate this policy?")
        .default(true)
        .interact()
        .map_err(input_err)?;

    if !confirm {
        return Err(KeylimectlError::Validation("Cancelled by user".into()));
    }

    // ── Generate ──────────────────────────────────────────────────
    eprintln!();

    generate::generate_tpm(
        pcr_file.as_deref(),
        from_tpm,
        &pcrs_str,
        None, // mask not used in wizard — pcrs_str is explicit
        hash_alg,
        output_file.as_deref(),
        output,
    )
    .map_err(KeylimectlError::from)
}

/// Default values for the wizard, populated from CLI arguments.
#[derive(Debug)]
pub struct Defaults<'a> {
    /// PCR values file path.
    pub pcr_file: Option<&'a str>,
    /// Whether to read from the local TPM.
    pub from_tpm: bool,
    /// PCR indices to include.
    pub pcr_indices: Vec<u32>,
    /// Hash algorithm.
    pub hash_alg: &'a str,
    /// Output file.
    pub output_file: Option<&'a str>,
}
