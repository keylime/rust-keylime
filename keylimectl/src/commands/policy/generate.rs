// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Local policy generation commands.
//!
//! Generates runtime, measured boot, and TPM policies from local
//! input sources without requiring network connectivity.

use crate::commands::error::CommandError;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::policy_tools::filesystem;
use crate::policy_tools::ima_parser;
use crate::policy_tools::initrd;
use crate::policy_tools::measured_boot_gen;
use crate::policy_tools::runtime_policy::RuntimePolicy;
use crate::policy_tools::tpm_policy_gen;
use crate::GenerateSubcommand;
use serde_json::Value;
use std::path::Path;

/// Execute a policy generation subcommand.
pub async fn execute(
    subcommand: &GenerateSubcommand,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    match subcommand {
        GenerateSubcommand::Runtime {
            interactive,
            ima_measurement_list,
            allowlist,
            rootfs,
            skip_path,
            base_policy,
            excludelist,
            output: output_file,
            keyrings,
            ima_buf,
            ignored_keyrings,
            add_ima_signature_verification_key: _, // Step 5
            hash_alg,
            ramdisk_dir,
            local_rpm_repo,
            remote_rpm_repo,
        } => {
            if *interactive {
                #[cfg(feature = "wizard")]
                {
                    let defaults = super::wizard_runtime::Defaults {
                        ima_measurement_list: ima_measurement_list.as_deref(),
                        allowlist: allowlist.as_deref(),
                        rootfs: rootfs.as_deref(),
                        skip_path,
                        base_policy: base_policy.as_deref(),
                        excludelist: excludelist.as_deref(),
                        output_file: output_file.as_deref(),
                        keyrings: *keyrings,
                        ima_buf: *ima_buf,
                        ignored_keyrings,
                        hash_alg: hash_alg.as_deref(),
                        ramdisk_dir: ramdisk_dir.as_deref(),
                        local_rpm_repo: local_rpm_repo.as_deref(),
                        remote_rpm_repo: remote_rpm_repo.as_deref(),
                    };
                    return super::wizard_runtime::run(&defaults, output).await;
                }
                #[cfg(not(feature = "wizard"))]
                {
                    return Err(KeylimectlError::Validation(
                        "Interactive mode requires the 'wizard' feature. \
                         Rebuild with: cargo build --features wizard"
                            .into(),
                    ));
                }
            }
            generate_runtime(
                ima_measurement_list.as_deref(),
                allowlist.as_deref(),
                rootfs.as_deref(),
                skip_path,
                base_policy.as_deref(),
                excludelist.as_deref(),
                output_file.as_deref(),
                *keyrings,
                *ima_buf,
                ignored_keyrings,
                hash_alg.as_deref(),
                ramdisk_dir.as_deref(),
                local_rpm_repo.as_deref(),
                remote_rpm_repo.as_deref(),
                output,
            )
            .await
            .map_err(KeylimectlError::from)
        }
        GenerateSubcommand::MeasuredBoot {
            interactive,
            eventlog_file,
            without_secureboot,
            output: output_file,
        } => {
            if *interactive {
                #[cfg(feature = "wizard")]
                {
                    let defaults = super::wizard_measured_boot::Defaults {
                        eventlog_file,
                        without_secureboot: *without_secureboot,
                        output_file: output_file.as_deref(),
                    };
                    return super::wizard_measured_boot::run(&defaults, output);
                }
                #[cfg(not(feature = "wizard"))]
                {
                    return Err(KeylimectlError::Validation(
                        "Interactive mode requires the 'wizard' feature. \
                         Rebuild with: cargo build --features wizard"
                            .into(),
                    ));
                }
            }
            generate_measured_boot(
                eventlog_file,
                *without_secureboot,
                output_file.as_deref(),
                output,
            )
            .map_err(KeylimectlError::from)
        }
        GenerateSubcommand::Tpm {
            interactive,
            pcr_file,
            from_tpm,
            pcrs,
            mask,
            hash_alg,
            output: output_file,
        } => {
            if *interactive {
                #[cfg(feature = "wizard")]
                {
                    use crate::policy_tools::tpm_policy_gen;
                    let pcr_indices = if let Some(mask_str) = mask.as_deref() {
                        crate::policy_tools::tpm_policy::TpmPolicy::parse_mask(mask_str)
                            .unwrap_or_else(|_| vec![0, 1, 2, 3, 4, 5, 6, 7])
                    } else {
                        tpm_policy_gen::parse_pcr_indices(pcrs)
                            .unwrap_or_else(|_| vec![0, 1, 2, 3, 4, 5, 6, 7])
                    };
                    let defaults = super::wizard_tpm::Defaults {
                        pcr_file: pcr_file.as_deref(),
                        from_tpm: *from_tpm,
                        pcr_indices,
                        hash_alg,
                        output_file: output_file.as_deref(),
                    };
                    return super::wizard_tpm::run(&defaults, output);
                }
                #[cfg(not(feature = "wizard"))]
                {
                    return Err(KeylimectlError::Validation(
                        "Interactive mode requires the 'wizard' feature. \
                         Rebuild with: cargo build --features wizard"
                            .into(),
                    ));
                }
            }
            generate_tpm(
                pcr_file.as_deref(),
                *from_tpm,
                pcrs,
                mask.as_deref(),
                hash_alg,
                output_file.as_deref(),
                output,
            )
            .map_err(KeylimectlError::from)
        }
    }
}

/// Generate a runtime policy from IMA logs, allowlists, and other sources.
#[allow(clippy::too_many_arguments)]
pub(super) async fn generate_runtime(
    ima_measurement_list: Option<&str>,
    allowlist: Option<&str>,
    rootfs: Option<&str>,
    skip_path: &[String],
    base_policy: Option<&str>,
    excludelist: Option<&str>,
    output_file: Option<&str>,
    get_keyrings: bool,
    get_ima_buf: bool,
    ignored_keyrings: &[String],
    hash_alg: Option<&str>,
    ramdisk_dir: Option<&str>,
    local_rpm_repo: Option<&str>,
    remote_rpm_repo: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    let mut policy = if let Some(base_path) = base_policy {
        load_base_policy(base_path)?
    } else {
        RuntimePolicy::new()
    };

    let mut detected_algorithm: Option<String> = hash_alg.map(String::from);

    // Parse IMA measurement list
    if let Some(ima_path) = ima_measurement_list {
        let path = Path::new(ima_path);
        if path.exists() {
            output.info(format!("Parsing IMA measurement list: {ima_path}"));

            let ima_data = ima_parser::parse_ima_measurement_list(
                path,
                get_keyrings,
                get_ima_buf,
                ignored_keyrings,
            )?;

            // Use detected algorithm if not explicitly specified
            if detected_algorithm.is_none() {
                detected_algorithm = ima_data.detected_algorithm;
            }

            // Merge digests
            for (file_path, digests) in &ima_data.digests {
                for digest in digests {
                    policy.add_digest(file_path.clone(), digest.clone());
                }
            }

            // Merge keyrings
            for (keyring, digests) in &ima_data.keyrings {
                for digest in digests {
                    policy.add_keyring(keyring.clone(), digest.clone());
                }
            }

            // Merge ima-buf
            for (name, digests) in &ima_data.ima_buf {
                for digest in digests {
                    policy.add_ima_buf(name.clone(), digest.clone());
                }
            }

            output.info(format!(
                "Extracted {} file digests from IMA log",
                ima_data.digests.len()
            ));
        } else {
            log::debug!("IMA measurement list not found: {ima_path}");
        }
    }

    // Parse allowlist
    if let Some(allowlist_path) = allowlist {
        let path = Path::new(allowlist_path);
        output.info(format!("Parsing allowlist: {allowlist_path}"));

        // Auto-detect format: try JSON first, fall back to flat text
        let allowlist_digests = if allowlist_path.ends_with(".json") {
            ima_parser::parse_json_allowlist(path)?
        } else {
            match ima_parser::parse_json_allowlist(path) {
                Ok(d) => d,
                Err(_) => ima_parser::parse_flat_allowlist(path)?,
            }
        };

        for (file_path, digests) in &allowlist_digests {
            for digest in digests {
                policy.add_digest(file_path.clone(), digest.clone());
            }
        }

        output.info(format!(
            "Loaded {} entries from allowlist",
            allowlist_digests.len()
        ));
    }

    // Scan filesystem
    if let Some(rootfs_path) = rootfs {
        let algorithm = detected_algorithm.as_deref().unwrap_or("sha256");

        output.info(format!(
            "Scanning filesystem: {rootfs_path} (algorithm: {algorithm})"
        ));

        let root = Path::new(rootfs_path);
        let fs_digests = tokio::task::spawn_blocking({
            let root = root.to_path_buf();
            let skip = skip_path.to_vec();
            let alg = algorithm.to_string();
            move || {
                filesystem::scan_filesystem(
                    &root, &skip, &alg,
                )
            }
        })
        .await
        .map_err(|e| {
            CommandError::from(
                crate::commands::error::PolicyGenerationError::FilesystemScan {
                    path: root.to_path_buf(),
                    reason: format!("Task join error: {e}"),
                },
            )
        })??;

        for (file_path, digests) in &fs_digests {
            for digest in digests {
                policy.add_digest(file_path.clone(), digest.clone());
            }
        }

        output.info(format!(
            "Scanned {} files from filesystem",
            fs_digests.len()
        ));
    }

    // Extract initramfs digests
    if let Some(ramdisk_path) = ramdisk_dir {
        let algorithm = detected_algorithm.as_deref().unwrap_or("sha256");

        output
            .info(format!("Extracting initramfs files from: {ramdisk_path}"));

        let ramdisk_dir_path = std::path::PathBuf::from(ramdisk_path);

        // Check read access (may require root for /boot)
        crate::policy_tools::privilege::check_dir_readable(
            &ramdisk_dir_path,
            &format!("policy generate runtime --ramdisk-dir {ramdisk_path}"),
        )?;

        let initrd_digests = tokio::task::spawn_blocking({
            let alg = algorithm.to_string();
            move || initrd::process_ramdisk_dir(&ramdisk_dir_path, &alg)
        })
        .await
        .map_err(|e| {
            CommandError::from(
                crate::commands::error::PolicyGenerationError::Output {
                    path: std::path::PathBuf::from(ramdisk_path),
                    reason: format!("Task join error: {e}"),
                },
            )
        })??;

        for (file_path, digests) in &initrd_digests {
            for digest in digests {
                policy.add_digest(file_path.clone(), digest.clone());
            }
        }

        output.info(format!(
            "Extracted {} file digests from initramfs",
            initrd_digests.len()
        ));
    }

    // Analyze local RPM repository
    if let Some(rpm_dir) = local_rpm_repo {
        #[cfg(feature = "rpm-repo")]
        {
            use crate::policy_tools::rpm_repo;

            output.info(format!("Analyzing local RPM repository: {rpm_dir}"));

            let rpm_dir_path = std::path::PathBuf::from(rpm_dir);

            crate::policy_tools::privilege::check_dir_readable(
                &rpm_dir_path,
                &format!(
                    "policy generate runtime --local-rpm-repo {rpm_dir}"
                ),
            )?;

            let rpm_digests = tokio::task::spawn_blocking({
                move || rpm_repo::analyze_local_repo(&rpm_dir_path)
            })
            .await
            .map_err(|e| {
                CommandError::from(
                    crate::commands::error::PolicyGenerationError::RpmParse {
                        path: std::path::PathBuf::from(rpm_dir),
                        reason: format!("Task join error: {e}"),
                    },
                )
            })??;

            for (file_path, digests) in &rpm_digests {
                for digest in digests {
                    policy.add_digest(file_path.clone(), digest.clone());
                }
            }

            output.info(format!(
                "Extracted {} file digests from local RPM repository",
                rpm_digests.len()
            ));
        }

        #[cfg(not(feature = "rpm-repo"))]
        {
            let _ = rpm_dir;
            return Err(CommandError::from(
                crate::commands::error::PolicyGenerationError::UnsupportedAlgorithm {
                    algorithm: "--local-rpm-repo requires the 'rpm-repo' feature flag. \
                        Rebuild with: cargo build --features rpm-repo".to_string(),
                },
            ));
        }
    }

    // Analyze remote RPM repository
    if let Some(rpm_url) = remote_rpm_repo {
        #[cfg(feature = "rpm-repo")]
        {
            use crate::policy_tools::rpm_repo;

            output
                .info(format!("Analyzing remote RPM repository: {rpm_url}"));

            let rpm_digests = rpm_repo::analyze_remote_repo(rpm_url).await?;

            for (file_path, digests) in &rpm_digests {
                for digest in digests {
                    policy.add_digest(file_path.clone(), digest.clone());
                }
            }

            output.info(format!(
                "Extracted {} file digests from remote RPM repository",
                rpm_digests.len()
            ));
        }

        #[cfg(not(feature = "rpm-repo"))]
        {
            let _ = rpm_url;
            return Err(CommandError::from(
                crate::commands::error::PolicyGenerationError::UnsupportedAlgorithm {
                    algorithm: "--remote-rpm-repo requires the 'rpm-repo' feature flag. \
                        Rebuild with: cargo build --features rpm-repo".to_string(),
                },
            ));
        }
    }

    // Parse exclude list
    if let Some(excludelist_path) = excludelist {
        let path = Path::new(excludelist_path);
        output.info(format!("Parsing exclude list: {excludelist_path}"));

        let excludes = ima_parser::parse_excludelist(path)?;
        for pattern in &excludes {
            policy.add_exclude(pattern.clone());
        }

        output.info(format!("Loaded {} exclude patterns", excludes.len()));
    }

    // Set ignored keyrings
    for keyring in ignored_keyrings {
        policy.add_ignored_keyring(keyring.clone());
    }

    // Set hash algorithm
    if let Some(alg) = &detected_algorithm {
        policy.set_log_hash_alg(alg.clone());
    }

    // Serialize the policy
    let policy_json = serde_json::to_value(&policy)?;

    // Write to file or return for stdout display
    if let Some(out_path) = output_file {
        let json_str = serde_json::to_string_pretty(&policy_json)?;
        std::fs::write(out_path, &json_str).map_err(|e| {
            CommandError::from(
                crate::commands::error::PolicyGenerationError::Output {
                    path: std::path::PathBuf::from(out_path),
                    reason: e.to_string(),
                },
            )
        })?;
        output.info(format!("Policy written to {out_path}"));
        output.info(format!(
            "Policy contains {} file digests, {} exclude patterns",
            policy.digest_count(),
            policy.exclude_count()
        ));
    }

    Ok(policy_json)
}

/// Generate a measured boot policy from a UEFI event log.
pub(super) fn generate_measured_boot(
    eventlog_file: &str,
    without_secureboot: bool,
    output_file: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    let path = Path::new(eventlog_file);
    output.info(format!("Parsing UEFI event log: {eventlog_file}"));

    let include_secureboot = !without_secureboot;
    let policy =
        measured_boot_gen::generate_from_eventlog(path, include_secureboot)?;

    output.info(format!(
        "Generated measured boot policy (secureboot: {})",
        if include_secureboot { "yes" } else { "no" }
    ));
    output.info(format!(
        "  PK entries: {}, KEK entries: {}, db entries: {}, dbx entries: {}",
        policy.pk.len(),
        policy.kek.len(),
        policy.db.len(),
        policy.dbx.len()
    ));
    output.info(format!(
        "  Kernel entries: {}, S-CRTM/BIOS entries: {}",
        policy.kernels.len(),
        policy.scrtm_and_bios.len()
    ));
    output.info(format!(
        "  MOK digests: {}, MOKx digests: {}, vendor_db entries: {}",
        policy.mokdig.len(),
        policy.mokxdig.len(),
        policy.vendor_db.len()
    ));

    let policy_json = serde_json::to_value(&policy)?;

    if let Some(out_path) = output_file {
        let json_str = serde_json::to_string_pretty(&policy_json)?;
        std::fs::write(out_path, &json_str)?;
        output.info(format!("Measured boot policy written to {out_path}"));
    }

    Ok(policy_json)
}

/// Generate a TPM policy from PCR values.
pub(super) fn generate_tpm(
    pcr_file: Option<&str>,
    from_tpm: bool,
    pcrs_str: &str,
    mask: Option<&str>,
    hash_alg: &str,
    output_file: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, CommandError> {
    if from_tpm {
        // Determine PCR indices first (needed for both paths)
        let pcr_indices = if let Some(mask_str) = mask {
            crate::policy_tools::tpm_policy::TpmPolicy::parse_mask(mask_str)
                .map_err(|e| {
                CommandError::from(
                    crate::commands::error::PolicyGenerationError::Output {
                        path: "<mask>".into(),
                        reason: e,
                    },
                )
            })?
        } else {
            tpm_policy_gen::parse_pcr_indices(pcrs_str)?
        };

        #[cfg(any(feature = "tpm-local", feature = "tpm-quote-validation"))]
        {
            output.info(format!(
                "Reading PCR values from local TPM (algorithm: {hash_alg})"
            ));
            output.info(format!("PCR indices: {:?}", pcr_indices));

            let policy =
                tpm_policy_gen::generate_from_tpm(&pcr_indices, hash_alg)?;

            output.info(format!(
                "Generated TPM policy with mask: {}",
                policy.mask
            ));
            output.info(format!("  {} PCR values", policy.pcr_values.len()));

            let policy_json = serde_json::to_value(&policy)?;

            if let Some(out_path) = output_file {
                let json_str = serde_json::to_string_pretty(&policy_json)?;
                std::fs::write(out_path, &json_str)?;
                output.info(format!("TPM policy written to {out_path}"));
            }

            return Ok(policy_json);
        }

        #[cfg(not(any(
            feature = "tpm-local",
            feature = "tpm-quote-validation"
        )))]
        {
            // Suppress unused variable warnings
            let _ = (hash_alg, pcr_indices);
            return Err(CommandError::from(
                crate::commands::error::PolicyGenerationError::UnsupportedAlgorithm {
                    algorithm: "Reading from local TPM requires the 'tpm-local' or 'tpm-quote-validation' feature flag. \
                        Rebuild with: cargo build --features tpm-local".to_string(),
                },
            ));
        }
    }

    let pcr_file = pcr_file.ok_or_else(|| {
        CommandError::from(
            crate::commands::error::PolicyGenerationError::Output {
                path: "<pcr-file>".into(),
                reason: "Either --pcr-file or --from-tpm is required"
                    .to_string(),
            },
        )
    })?;

    // Determine PCR indices from mask or pcrs argument
    let pcr_indices = if let Some(mask_str) = mask {
        crate::policy_tools::tpm_policy::TpmPolicy::parse_mask(mask_str)
            .map_err(|e| {
                CommandError::from(
                    crate::commands::error::PolicyGenerationError::Output {
                        path: "<mask>".into(),
                        reason: e,
                    },
                )
            })?
    } else {
        tpm_policy_gen::parse_pcr_indices(pcrs_str)?
    };

    output.info(format!("Reading PCR values from: {pcr_file}"));
    output.info(format!("PCR indices: {:?}", pcr_indices));

    let policy = tpm_policy_gen::generate_from_file(
        Path::new(pcr_file),
        &pcr_indices,
    )?;

    output.info(format!("Generated TPM policy with mask: {}", policy.mask));
    output.info(format!("  {} PCR values", policy.pcr_values.len()));

    let policy_json = serde_json::to_value(&policy)?;

    if let Some(out_path) = output_file {
        let json_str = serde_json::to_string_pretty(&policy_json)?;
        std::fs::write(out_path, &json_str)?;
        output.info(format!("TPM policy written to {out_path}"));
    }

    Ok(policy_json)
}

/// Load a base policy from a JSON file.
fn load_base_policy(path: &str) -> Result<RuntimePolicy, CommandError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        CommandError::from(
            crate::commands::error::PolicyGenerationError::AllowlistParse {
                path: std::path::PathBuf::from(path),
                reason: format!("Failed to read base policy: {e}"),
            },
        )
    })?;

    let policy: RuntimePolicy =
        serde_json::from_str(&content).map_err(|e| {
            CommandError::from(
                crate::commands::error::PolicyGenerationError::AllowlistParse {
                    path: std::path::PathBuf::from(path),
                    reason: format!(
                        "Failed to parse base policy: {e}"
                    ),
                },
            )
        })?;

    Ok(policy)
}
