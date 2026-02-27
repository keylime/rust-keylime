// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Interactive wizard for runtime policy generation.

use crate::commands::policy::generate;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde_json::Value;

/// Default IMA measurement list path.
const DEFAULT_IMA_PATH: &str =
    "/sys/kernel/security/ima/ascii_runtime_measurements";

/// Map a dialoguer error to a `KeylimectlError`.
fn input_err(e: dialoguer::Error) -> KeylimectlError {
    KeylimectlError::Validation(format!("Failed to read user input: {e}"))
}

/// Run the interactive runtime policy generation wizard.
///
/// Prompts the user for input sources and options, then delegates to
/// the existing `generate::generate_runtime()` function.
#[allow(clippy::too_many_lines)]
pub async fn run(
    defaults: &Defaults<'_>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    eprintln!();
    eprintln!("Runtime Policy Generation Wizard");
    eprintln!("================================");
    eprintln!();

    // ── Step 1: Input sources ───────────────────────────────────────
    eprintln!("Step 1: Select input sources");
    eprintln!();

    #[allow(unused_mut)]
    let mut source_labels: Vec<&str> = vec![
        "IMA measurement list",
        "Allowlist file",
        "Root filesystem scan",
        "Initramfs / ramdisk directory",
    ];

    #[cfg(feature = "rpm-repo")]
    {
        source_labels.push("Local RPM repository");
        source_labels.push("Remote RPM repository");
    }

    // Pre-select sources that were provided via CLI args.
    let preselected: Vec<bool> = source_labels
        .iter()
        .enumerate()
        .map(|(i, _)| match i {
            0 => defaults.ima_measurement_list.is_some(),
            1 => defaults.allowlist.is_some(),
            2 => defaults.rootfs.is_some(),
            3 => defaults.ramdisk_dir.is_some(),
            #[cfg(feature = "rpm-repo")]
            4 => defaults.local_rpm_repo.is_some(),
            #[cfg(feature = "rpm-repo")]
            5 => defaults.remote_rpm_repo.is_some(),
            _ => false,
        })
        .collect();

    let selected = MultiSelect::new()
        .with_prompt("Which input sources should be used?")
        .items(&source_labels)
        .defaults(&preselected)
        .interact()
        .map_err(input_err)?;

    let use_ima = selected.contains(&0);
    let use_allowlist = selected.contains(&1);
    let use_rootfs = selected.contains(&2);
    let use_ramdisk = selected.contains(&3);
    #[cfg(feature = "rpm-repo")]
    let use_local_rpm = selected.contains(&4);
    #[cfg(feature = "rpm-repo")]
    let use_remote_rpm = selected.contains(&5);

    // ── Step 2: Paths for each selected source ──────────────────────
    eprintln!();
    eprintln!("Step 2: Configure selected sources");
    eprintln!();

    let ima_path = if use_ima {
        let path: String = Input::new()
            .with_prompt("IMA measurement list path")
            .default(
                defaults
                    .ima_measurement_list
                    .unwrap_or(DEFAULT_IMA_PATH)
                    .to_string(),
            )
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    let allowlist_path = if use_allowlist {
        let path: String = Input::new()
            .with_prompt("Allowlist file path")
            .default(defaults.allowlist.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    let rootfs_path = if use_rootfs {
        let path: String = Input::new()
            .with_prompt("Root filesystem path")
            .default(defaults.rootfs.unwrap_or("/").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    let skip_paths: Vec<String> = if use_rootfs {
        let default_skip = if defaults.skip_path.is_empty() {
            String::new()
        } else {
            defaults.skip_path.join(", ")
        };

        let raw: String = Input::new()
            .with_prompt(
                "Paths to skip during scan (comma-separated, empty for none)",
            )
            .default(default_skip)
            .allow_empty(true)
            .interact_text()
            .map_err(input_err)?;

        if raw.trim().is_empty() {
            vec![]
        } else {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
    } else {
        vec![]
    };

    let ramdisk_path = if use_ramdisk {
        let path: String = Input::new()
            .with_prompt("Initramfs / ramdisk directory (e.g., /boot)")
            .default(defaults.ramdisk_dir.unwrap_or("/boot").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    #[cfg(feature = "rpm-repo")]
    let local_rpm_path = if use_local_rpm {
        let path: String = Input::new()
            .with_prompt("Local RPM repository directory")
            .default(defaults.local_rpm_repo.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };
    #[cfg(not(feature = "rpm-repo"))]
    let local_rpm_path: Option<String> = None;

    #[cfg(feature = "rpm-repo")]
    let remote_rpm_url = if use_remote_rpm {
        let url: String = Input::new()
            .with_prompt("Remote RPM repository URL")
            .default(defaults.remote_rpm_repo.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(url)
    } else {
        None
    };
    #[cfg(not(feature = "rpm-repo"))]
    let remote_rpm_url: Option<String> = None;

    // ── Step 3: IMA options ─────────────────────────────────────────
    eprintln!();
    eprintln!("Step 3: IMA options");
    eprintln!();

    let get_keyrings = Confirm::new()
        .with_prompt("Include keyrings entries?")
        .default(defaults.keyrings)
        .interact()
        .map_err(input_err)?;

    let ignored_keyrings: Vec<String> = if get_keyrings {
        let default_ignored = if defaults.ignored_keyrings.is_empty() {
            String::new()
        } else {
            defaults.ignored_keyrings.join(", ")
        };

        let raw: String = Input::new()
            .with_prompt(
                "Keyrings to ignore (comma-separated, empty for none)",
            )
            .default(default_ignored)
            .allow_empty(true)
            .interact_text()
            .map_err(input_err)?;

        if raw.trim().is_empty() {
            vec![]
        } else {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
    } else {
        vec![]
    };

    let get_ima_buf = Confirm::new()
        .with_prompt("Include ima-buf entries?")
        .default(defaults.ima_buf)
        .interact()
        .map_err(input_err)?;

    // ── Step 4: Hash algorithm ──────────────────────────────────────
    eprintln!();
    eprintln!("Step 4: Hash algorithm");
    eprintln!();

    let alg_options = ["auto-detect", "sha256", "sha1", "sha384", "sha512"];
    let default_alg_idx = defaults
        .hash_alg
        .and_then(|a| alg_options.iter().position(|&o| o == a))
        .unwrap_or(0);

    let alg_idx = Select::new()
        .with_prompt("Hash algorithm")
        .items(alg_options)
        .default(default_alg_idx)
        .interact()
        .map_err(input_err)?;

    let hash_alg = if alg_idx == 0 {
        None // auto-detect
    } else {
        Some(alg_options[alg_idx].to_string())
    };

    // ── Step 5: Additional options ──────────────────────────────────
    eprintln!();
    eprintln!("Step 5: Additional options");
    eprintln!();

    let merge_base = Confirm::new()
        .with_prompt("Merge into an existing base policy?")
        .default(defaults.base_policy.is_some())
        .interact()
        .map_err(input_err)?;

    let base_policy_path = if merge_base {
        let path: String = Input::new()
            .with_prompt("Base policy file path")
            .default(defaults.base_policy.unwrap_or("").to_string())
            .interact_text()
            .map_err(input_err)?;
        Some(path)
    } else {
        None
    };

    let excludelist_raw: String = Input::new()
        .with_prompt("Exclude list file (empty for none)")
        .default(defaults.excludelist.unwrap_or("").to_string())
        .allow_empty(true)
        .interact_text()
        .map_err(input_err)?;

    let excludelist_path = if excludelist_raw.trim().is_empty() {
        None
    } else {
        Some(excludelist_raw)
    };

    // ── Step 6: Output ──────────────────────────────────────────────
    eprintln!();
    eprintln!("Step 6: Output");
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

    // ── Generate ────────────────────────────────────────────────────
    eprintln!();

    generate::generate_runtime(
        ima_path.as_deref(),
        allowlist_path.as_deref(),
        rootfs_path.as_deref(),
        &skip_paths,
        base_policy_path.as_deref(),
        excludelist_path.as_deref(),
        output_file.as_deref(),
        get_keyrings,
        get_ima_buf,
        &ignored_keyrings,
        hash_alg.as_deref(),
        ramdisk_path.as_deref(),
        local_rpm_path.as_deref(),
        remote_rpm_url.as_deref(),
        output,
    )
    .await
    .map_err(KeylimectlError::from)
}

/// Default values for the wizard, populated from CLI arguments.
pub struct Defaults<'a> {
    /// IMA measurement list path.
    pub ima_measurement_list: Option<&'a str>,
    /// Allowlist file path.
    pub allowlist: Option<&'a str>,
    /// Root filesystem path.
    pub rootfs: Option<&'a str>,
    /// Paths to skip during filesystem scan.
    pub skip_path: &'a [String],
    /// Base policy to merge into.
    pub base_policy: Option<&'a str>,
    /// Exclude list file.
    pub excludelist: Option<&'a str>,
    /// Output file.
    pub output_file: Option<&'a str>,
    /// Include keyrings.
    pub keyrings: bool,
    /// Include ima-buf entries.
    pub ima_buf: bool,
    /// Keyrings to ignore.
    pub ignored_keyrings: &'a [String],
    /// Hash algorithm.
    pub hash_alg: Option<&'a str>,
    /// Ramdisk directory.
    pub ramdisk_dir: Option<&'a str>,
    /// Local RPM repository.
    #[cfg_attr(not(feature = "rpm-repo"), allow(dead_code))]
    pub local_rpm_repo: Option<&'a str>,
    /// Remote RPM repository.
    #[cfg_attr(not(feature = "rpm-repo"), allow(dead_code))]
    pub remote_rpm_repo: Option<&'a str>,
}
