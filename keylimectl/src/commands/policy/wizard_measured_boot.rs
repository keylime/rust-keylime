// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Interactive wizard for measured boot policy generation.

use crate::commands::policy::generate;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::policy_tools::measured_boot_gen;
use dialoguer::{Confirm, Input};
use serde_json::Value;
use std::path::Path;

/// Default UEFI event log path.
const DEFAULT_EVENTLOG_PATH: &str =
    "/sys/kernel/security/tpm0/binary_bios_measurements";

/// Map a dialoguer error to a `KeylimectlError`.
fn input_err(e: dialoguer::Error) -> KeylimectlError {
    KeylimectlError::Validation(format!("Failed to read user input: {e}"))
}

/// Run the interactive measured boot policy generation wizard.
pub fn run(
    defaults: &Defaults<'_>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    eprintln!();
    eprintln!("Measured Boot Policy Generation Wizard");
    eprintln!("======================================");
    eprintln!();

    // ── Step 1: Event log ─────────────────────────────────────────
    eprintln!("Step 1: Event log");
    eprintln!();

    let eventlog_path: String = Input::new()
        .with_prompt("UEFI event log file")
        .default(defaults.eventlog_file.to_string())
        .interact_text()
        .map_err(input_err)?;

    // ── Step 2: Secure Boot ───────────────────────────────────────
    eprintln!();
    eprintln!("Step 2: Secure Boot");
    eprintln!();

    let include_secureboot = Confirm::new()
        .with_prompt("Include Secure Boot variables?")
        .default(!defaults.without_secureboot)
        .interact()
        .map_err(input_err)?;

    // ── Step 3: Preview ───────────────────────────────────────────
    eprintln!();
    eprintln!("Step 3: Event log preview");
    eprintln!();

    let path = Path::new(&eventlog_path);
    match measured_boot_gen::get_eventlog_stats(path) {
        Ok(stats) => {
            eprintln!("  Total events:     {}", stats.total_events);
            eprintln!("  S-CRTM entries:   {}", stats.scrtm_entries);
            eprintln!("  Secure Boot entries: {}", stats.secureboot_entries);
            eprintln!(
                "  Algorithms:       {}",
                if stats.algorithms.is_empty() {
                    "(none detected)".to_string()
                } else {
                    stats.algorithms.join(", ")
                }
            );
        }
        Err(e) => {
            eprintln!("  (Could not preview event log: {e})");
            eprintln!(
                "  The policy will still be generated if the file becomes available."
            );
        }
    }

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

    generate::generate_measured_boot(
        &eventlog_path,
        !include_secureboot,
        output_file.as_deref(),
        output,
    )
    .map_err(KeylimectlError::from)
}

/// Default values for the wizard, populated from CLI arguments.
#[derive(Debug)]
pub struct Defaults<'a> {
    /// UEFI event log file path.
    pub eventlog_file: &'a str,
    /// Whether to exclude Secure Boot variables.
    pub without_secureboot: bool,
    /// Output file.
    pub output_file: Option<&'a str>,
}

impl<'a> Default for Defaults<'a> {
    fn default() -> Self {
        Self {
            eventlog_file: DEFAULT_EVENTLOG_PATH,
            without_secureboot: false,
            output_file: None,
        }
    }
}
