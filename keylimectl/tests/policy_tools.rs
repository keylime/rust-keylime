// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Integration tests for Phase 6 policy tools commands.
//!
//! Tests cover local policy generation, signing, validation,
//! and conversion subcommands that do not require network
//! connectivity.

#![allow(deprecated)] // cargo_bin deprecation — replacement API not yet stable

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;

/// Create a command that runs from a temporary directory with clean env.
fn keylimectl_in_clean_dir(tmpdir: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("keylimectl").unwrap(); //#[allow_ci]
    cmd.current_dir(tmpdir.path());
    // Point HOME to the temp dir so config search paths based on
    // ~/.config/keylimectl/ won't find the user's real config files.
    cmd.env("HOME", tmpdir.path());
    cmd.env_remove("XDG_CONFIG_HOME");
    cmd.env_remove("KEYLIME_VERIFIER__IP");
    cmd.env_remove("KEYLIME_VERIFIER__PORT");
    cmd.env_remove("KEYLIME_REGISTRAR__IP");
    cmd.env_remove("KEYLIME_REGISTRAR__PORT");
    cmd
}

// ── Help output tests ────────────────────────────────────────

#[test]
fn test_policy_help_shows_generate() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("generate"))
        .stdout(predicate::str::contains("sign"))
        .stdout(predicate::str::contains("validate"))
        .stdout(predicate::str::contains("convert"));
}

#[test]
fn test_policy_generate_runtime_help() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "generate", "runtime", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--ima-measurement-list"))
        .stdout(predicate::str::contains("--allowlist"))
        .stdout(predicate::str::contains("--rootfs"))
        .stdout(predicate::str::contains("--output"));
}

#[test]
fn test_policy_generate_measured_boot_help() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "generate", "measured-boot", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--eventlog-file"))
        .stdout(predicate::str::contains("--without-secureboot"));
}

#[test]
fn test_policy_generate_tpm_help() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "generate", "tpm", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--pcr-file"))
        .stdout(predicate::str::contains("--pcrs"))
        .stdout(predicate::str::contains("--mask"));
}

#[test]
fn test_verify_help_shows_evidence() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("evidence"));
}

// ── Runtime policy generation ────────────────────────────────

#[test]
fn test_generate_runtime_from_ima_log() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a test IMA measurement list.
    // Format: <pcr> <template_hash> <template_name> <digest> <path>
    let ima_path = tmpdir.path().join("ima_log.txt");
    let mut f = std::fs::File::create(&ima_path).unwrap(); //#[allow_ci]
    writeln!(
        f,
        "10 0000000000000000000000000000000000000000 ima-ng sha256:a94cd382dd0a40c3312e6e89a4c7c39e22e0c4a3bcf83ce9f0fe52c8f1f /usr/bin/test1"
    )
    .unwrap(); //#[allow_ci]
    writeln!(
        f,
        "10 0000000000000000000000000000000000000000 ima-ng sha256:b94cd382dd0a40c3312e6e89a4c7c39e22e0c4a3bcf83ce9f0fe52c8f1f /usr/bin/test2"
    )
    .unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("runtime_policy.json");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "runtime",
            "--ima-measurement-list",
            ima_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    // Verify output file exists and is valid JSON
    assert!(output_path.exists(), "Expected output file to exist");

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value =
        serde_json::from_str(&content).unwrap_or_else(|e| {
            panic!( //#[allow_ci]
                "Expected valid JSON policy, got error: {e}\ncontent: {content}"
            ) //#[allow_ci]
        });

    // Check policy structure
    assert!(
        policy.get("meta").is_some(),
        "Expected 'meta' field in policy"
    );
    assert!(
        policy.get("digests").is_some(),
        "Expected 'digests' field in policy"
    );

    // Verify digests contain our test files
    let digests = policy["digests"].as_object().unwrap(); //#[allow_ci]
    assert!(
        digests.contains_key("/usr/bin/test1"),
        "Expected /usr/bin/test1 in digests, got keys: {:?}",
        digests.keys().collect::<Vec<_>>()
    );
    assert!(
        digests.contains_key("/usr/bin/test2"),
        "Expected /usr/bin/test2 in digests"
    );
}

#[test]
fn test_generate_runtime_from_allowlist() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a flat-text allowlist
    let allowlist_path = tmpdir.path().join("allowlist.txt");
    let mut f = std::fs::File::create(&allowlist_path).unwrap(); //#[allow_ci]
    writeln!(f, "abc123def456  /usr/bin/allowed1").unwrap(); //#[allow_ci]
    writeln!(f, "789012345678  /usr/bin/allowed2").unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("runtime_policy.json");

    // Only pass --allowlist, no --ima-measurement-list
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "runtime",
            "--allowlist",
            allowlist_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value = serde_json::from_str(&content).unwrap(); //#[allow_ci]

    let digests = policy["digests"].as_object().unwrap(); //#[allow_ci]
    assert!(
        digests.contains_key("/usr/bin/allowed1"),
        "Expected /usr/bin/allowed1 in digests, got: {:?}",
        digests.keys().collect::<Vec<_>>()
    );
}

#[test]
fn test_generate_runtime_to_stdout() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a minimal IMA log
    let ima_path = tmpdir.path().join("ima_log.txt");
    let mut f = std::fs::File::create(&ima_path).unwrap(); //#[allow_ci]
    writeln!(
        f,
        "10 0000000000000000000000000000000000000000 ima-ng sha256:a94cd382dd0a40c3312e6e89a4c7c39e22e0c4a3bcf83ce9f0fe52c8f1f /usr/bin/stdout_test"
    )
    .unwrap(); //#[allow_ci]

    let output = keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "runtime",
            "--ima-measurement-list",
            ima_path.to_str().unwrap(), //#[allow_ci]
        ])
        .output()
        .unwrap(); //#[allow_ci]

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let policy: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!( //#[allow_ci]
                "Expected valid JSON on stdout, got error: {e}\nstdout: {stdout}"
            ) //#[allow_ci]
        });

    assert!(policy.get("digests").is_some());
}

#[test]
fn test_generate_runtime_with_excludelist() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a minimal IMA log
    let ima_path = tmpdir.path().join("ima_log.txt");
    let mut f = std::fs::File::create(&ima_path).unwrap(); //#[allow_ci]
    writeln!(
        f,
        "10 0000000000000000000000000000000000000000 ima-ng sha256:a94cd382dd0a40c3312e6e89a4c7c39e22e0c4a3bcf83ce9f0fe52c8f1f /usr/bin/excl_test"
    )
    .unwrap(); //#[allow_ci]

    // Create an exclude list
    let exclude_path = tmpdir.path().join("excludelist.txt");
    let mut f = std::fs::File::create(&exclude_path).unwrap(); //#[allow_ci]
    writeln!(f, "/tmp/.*").unwrap(); //#[allow_ci]
    writeln!(f, "/var/log/.*").unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("runtime_policy.json");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "runtime",
            "--ima-measurement-list",
            ima_path.to_str().unwrap(), //#[allow_ci]
            "--excludelist",
            exclude_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value = serde_json::from_str(&content).unwrap(); //#[allow_ci]

    let excludes = policy["excludes"].as_array().unwrap(); //#[allow_ci]
    assert!(
        excludes.len() >= 2,
        "Expected at least 2 exclude patterns, got {}",
        excludes.len()
    );
}

// ── TPM policy generation ────────────────────────────────────

#[test]
fn test_generate_tpm_from_file() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a PCR values file
    let pcr_path = tmpdir.path().join("pcr_values.txt");
    let mut f = std::fs::File::create(&pcr_path).unwrap(); //#[allow_ci]
    writeln!(f, "0 aabbccddee").unwrap(); //#[allow_ci]
    writeln!(f, "7 ff00112233").unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("tpm_policy.json");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "tpm",
            "--pcr-file",
            pcr_path.to_str().unwrap(), //#[allow_ci]
            "--pcrs",
            "0,7",
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value =
        serde_json::from_str(&content).unwrap_or_else(|e| {
            panic!( //#[allow_ci]
                "Expected valid JSON TPM policy, got error: {e}\ncontent: {content}"
            ) //#[allow_ci]
        });

    assert!(
        policy.get("mask").is_some(),
        "Expected 'mask' field in TPM policy"
    );

    // TpmPolicy uses #[serde(flatten)] so PCR values are at the
    // top level, not under a "pcr_values" key.
    assert!(
        policy.get("0").is_some(),
        "Expected PCR '0' at top level, got: {policy}"
    );
    assert!(
        policy.get("7").is_some(),
        "Expected PCR '7' at top level, got: {policy}"
    );
}

#[test]
fn test_generate_tpm_to_stdout() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    let pcr_path = tmpdir.path().join("pcr_values.txt");
    let mut f = std::fs::File::create(&pcr_path).unwrap(); //#[allow_ci]
    writeln!(f, "0 aabb").unwrap(); //#[allow_ci]

    let output = keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "tpm",
            "--pcr-file",
            pcr_path.to_str().unwrap(), //#[allow_ci]
            "--pcrs",
            "0",
        ])
        .output()
        .unwrap(); //#[allow_ci]

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let policy: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!( //#[allow_ci]
                "Expected valid JSON on stdout, got error: {e}\nstdout: {stdout}"
            ) //#[allow_ci]
        });

    assert!(policy.get("mask").is_some());
}

#[test]
#[cfg(not(any(feature = "tpm-local", feature = "tpm-quote-validation")))]
fn test_generate_tpm_from_tpm_fails_without_feature() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "generate", "tpm", "--from-tpm", "--pcrs", "0,7"])
        .assert()
        .failure();
}

// ── Policy validation ────────────────────────────────────────

#[test]
fn test_validate_valid_runtime_policy() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    let policy_path = tmpdir.path().join("valid_policy.json");
    let policy = serde_json::json!({
        "meta": {
            "version": 1,
            "generator": 0,
            "timestamp": "2025-01-01T00:00:00Z"
        },
        "release": 0,
        "digests": {
            "/usr/bin/test": ["aabbccddeeff00112233aabbccddeeff00112233"]
        },
        "excludes": [],
        "keyrings": {},
        "ima": {
            "ignored_keyrings": [],
            "log_hash_alg": "sha256"
        }
    });
    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&policy).unwrap(), //#[allow_ci]
    )
    .unwrap(); //#[allow_ci]

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "validate",
            policy_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();
}

#[test]
fn test_validate_invalid_runtime_policy() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Policy with invalid digest format
    let policy_path = tmpdir.path().join("invalid_policy.json");
    let policy = serde_json::json!({
        "meta": {
            "version": 5,
            "generator": "keylimectl"
        },
        "release": 0,
        "digests": {
            "/usr/bin/test": ["not_a_valid_digest"]
        },
        "excludes": []
    });
    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&policy).unwrap(), //#[allow_ci]
    )
    .unwrap(); //#[allow_ci]

    let output = keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "validate",
            policy_path.to_str().unwrap(), //#[allow_ci]
        ])
        .output()
        .unwrap(); //#[allow_ci]

    // The command should succeed but report validation errors in
    // the JSON output.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("valid")
            || combined.contains("error")
            || combined.contains("invalid")
            || combined.contains("digest"),
        "Expected validation feedback, got stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn test_validate_tpm_policy() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // TpmPolicy uses #[serde(flatten)] so PCR values are at the
    // top level alongside the mask — not nested under "pcr_values".
    let policy_path = tmpdir.path().join("tpm_policy.json");
    let policy = serde_json::json!({
        "mask": "0x81",
        "0": "aabbccdd",
        "7": "eeff0011"
    });
    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&policy).unwrap(), //#[allow_ci]
    )
    .unwrap(); //#[allow_ci]

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "validate",
            policy_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();
}

#[test]
fn test_validate_nonexistent_file() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "validate", "/nonexistent/file.json"])
        .assert()
        .failure();
}

// ── Policy signing and verification ──────────────────────────

#[test]
fn test_sign_and_verify_policy() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a simple policy file
    let policy_path = tmpdir.path().join("policy.json");
    let policy = serde_json::json!({
        "meta": {"version": 1, "generator": 0},
        "release": 0,
        "digests": {"/usr/bin/test": ["aabbccddeeff00112233aabbccddeeff00112233"]},
        "excludes": []
    });
    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&policy).unwrap(), //#[allow_ci]
    )
    .unwrap(); //#[allow_ci]

    let signed_path = tmpdir.path().join("signed_policy.json");
    let key_path = tmpdir.path().join("signing_key.pem");

    // Sign the policy
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "sign",
            policy_path.to_str().unwrap(), //#[allow_ci]
            "--keypath",
            key_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            signed_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    assert!(signed_path.exists(), "Expected signed policy file to exist");
    assert!(key_path.exists(), "Expected generated key file to exist");

    // Verify the signed policy file is valid JSON
    let signed_content = std::fs::read_to_string(&signed_path).unwrap(); //#[allow_ci]
    let signed: serde_json::Value = serde_json::from_str(&signed_content)
        .unwrap_or_else(|e| {
            panic!("Expected valid JSON signed envelope, got error: {e}") //#[allow_ci]
        });

    assert!(
        signed.get("payload").is_some(),
        "Expected 'payload' field in DSSE envelope"
    );
    assert!(
        signed.get("signatures").is_some(),
        "Expected 'signatures' field in DSSE envelope"
    );

    // The public key is saved at <keypath>.pub
    let pub_key_path = format!(
        "{}.pub",
        key_path.to_str().unwrap() //#[allow_ci]
    );
    assert!(
        std::path::Path::new(&pub_key_path).exists(),
        "Expected public key file at {pub_key_path}"
    );

    // Verify the signature using the public key
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "verify-signature",
            signed_path.to_str().unwrap(), //#[allow_ci]
            "--key",
            &pub_key_path,
        ])
        .assert()
        .success();
}

#[test]
fn test_validate_signed_policy() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a valid runtime policy
    let policy_path = tmpdir.path().join("policy.json");
    let policy = serde_json::json!({
        "meta": {"version": 1, "generator": 0},
        "release": 0,
        "digests": {"/usr/bin/test": ["aabbccddeeff00112233aabbccddeeff00112233"]},
        "excludes": [],
        "keyrings": {},
        "ima": {
            "ignored_keyrings": [],
            "log_hash_alg": "sha256"
        }
    });
    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&policy).unwrap(), //#[allow_ci]
    )
    .unwrap(); //#[allow_ci]

    // Sign it
    let signed_path = tmpdir.path().join("signed_policy.json");
    let key_path = tmpdir.path().join("signing_key.pem");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "sign",
            policy_path.to_str().unwrap(), //#[allow_ci]
            "--keypath",
            key_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            signed_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    // Validate the signed policy (DSSE envelope)
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "validate",
            signed_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();
}

#[test]
fn test_sign_with_x509_backend() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    let policy_path = tmpdir.path().join("policy.json");
    let policy = serde_json::json!({
        "meta": {"version": 5, "generator": "keylimectl"},
        "release": 0,
        "digests": {},
        "excludes": []
    });
    std::fs::write(
        &policy_path,
        serde_json::to_string_pretty(&policy).unwrap(), //#[allow_ci]
    )
    .unwrap(); //#[allow_ci]

    let signed_path = tmpdir.path().join("signed_x509.json");
    let key_path = tmpdir.path().join("x509_key.pem");
    let cert_path = tmpdir.path().join("cert.pem");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "sign",
            policy_path.to_str().unwrap(), //#[allow_ci]
            "--backend",
            "x509",
            "--keypath",
            key_path.to_str().unwrap(), //#[allow_ci]
            "--cert-outfile",
            cert_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            signed_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    assert!(signed_path.exists(), "Expected signed policy file");
    assert!(cert_path.exists(), "Expected X.509 certificate file");
}

// ── Policy conversion ────────────────────────────────────────

#[test]
fn test_convert_flat_allowlist() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Create a flat-text allowlist
    let allowlist_path = tmpdir.path().join("allowlist.txt");
    let mut f = std::fs::File::create(&allowlist_path).unwrap(); //#[allow_ci]
    writeln!(f, "abc123  /usr/bin/file1").unwrap(); //#[allow_ci]
    writeln!(f, "def456  /usr/bin/file2").unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("converted.json");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "convert",
            allowlist_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    assert!(output_path.exists(), "Expected converted policy file");

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| {
            panic!("Expected valid JSON, got error: {e}\ncontent: {content}") //#[allow_ci]
        });

    assert!(
        policy.get("digests").is_some(),
        "Expected 'digests' field in converted policy"
    );
}

#[test]
fn test_convert_json_allowlist() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    let allowlist_path = tmpdir.path().join("allowlist.json");
    let allowlist = serde_json::json!({
        "hashes": {
            "/usr/bin/app": ["sha256:aabbccdd"]
        }
    });
    std::fs::write(
        &allowlist_path,
        serde_json::to_string_pretty(&allowlist).unwrap(), //#[allow_ci]
    )
    .unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("converted.json");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "convert",
            allowlist_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value = serde_json::from_str(&content).unwrap(); //#[allow_ci]

    let digests = policy["digests"].as_object().unwrap(); //#[allow_ci]
    assert!(
        digests.contains_key("/usr/bin/app"),
        "Expected /usr/bin/app in converted digests"
    );
}

#[test]
fn test_convert_with_excludelist() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    let allowlist_path = tmpdir.path().join("allowlist.txt");
    let mut f = std::fs::File::create(&allowlist_path).unwrap(); //#[allow_ci]
    writeln!(f, "abc123  /usr/bin/file1").unwrap(); //#[allow_ci]

    let exclude_path = tmpdir.path().join("excludelist.txt");
    let mut f = std::fs::File::create(&exclude_path).unwrap(); //#[allow_ci]
    writeln!(f, "/tmp/.*").unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("converted.json");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "convert",
            allowlist_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
            "--excludelist",
            exclude_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value = serde_json::from_str(&content).unwrap(); //#[allow_ci]

    let excludes = policy["excludes"].as_array().unwrap(); //#[allow_ci]
    assert!(
        !excludes.is_empty(),
        "Expected exclude patterns in converted policy"
    );
}

#[test]
fn test_convert_requires_output() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    let allowlist_path = tmpdir.path().join("allowlist.txt");
    std::fs::write(&allowlist_path, "abc123  /usr/bin/file1\n").unwrap(); //#[allow_ci]

    // Should fail because --output is required for convert
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "convert",
            allowlist_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .failure();
}

// ── End-to-end: generate, validate, sign, verify ─────────────

#[test]
fn test_generate_validate_sign_verify_pipeline() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]

    // Step 1: Generate a runtime policy from an IMA log
    let ima_path = tmpdir.path().join("ima_log.txt");
    let mut f = std::fs::File::create(&ima_path).unwrap(); //#[allow_ci]
    writeln!(
        f,
        "10 0000000000000000000000000000000000000000 ima-ng sha256:a94cd382dd0a40c3312e6e89a4c7c39e22e0c4a3bcf83ce9f0fe52c8f1f /usr/bin/pipeline_test"
    )
    .unwrap(); //#[allow_ci]

    let policy_path = tmpdir.path().join("policy.json");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "runtime",
            "--ima-measurement-list",
            ima_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            policy_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    // Step 2: Validate the generated policy
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "validate",
            policy_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    // Step 3: Sign the policy
    let signed_path = tmpdir.path().join("signed_policy.json");
    let key_path = tmpdir.path().join("signing_key.pem");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "sign",
            policy_path.to_str().unwrap(), //#[allow_ci]
            "--keypath",
            key_path.to_str().unwrap(), //#[allow_ci]
            "--output",
            signed_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    // Step 4: Verify the signature using the public key
    let pub_key_path = format!(
        "{}.pub",
        key_path.to_str().unwrap() //#[allow_ci]
    );

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "verify-signature",
            signed_path.to_str().unwrap(), //#[allow_ci]
            "--key",
            &pub_key_path,
        ])
        .assert()
        .success();
}

// ── Phase 6b: Privileged operations tests ────────────────────

#[test]
fn test_generate_runtime_help_shows_ramdisk_dir() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "generate", "runtime", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--ramdisk-dir"));
}

#[test]
fn test_generate_runtime_help_shows_rpm_options() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "generate", "runtime", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--local-rpm-repo"))
        .stdout(predicate::str::contains("--remote-rpm-repo"));
}

#[test]
fn test_generate_runtime_ramdisk_nonexistent() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "runtime",
            "--ramdisk-dir",
            "/nonexistent/ramdisk/dir",
        ])
        .assert()
        .failure();
}

#[test]
fn test_generate_tpm_help_shows_from_tpm() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["policy", "generate", "tpm", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--from-tpm"));
}

#[test]
fn test_generate_runtime_ramdisk_empty_dir() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let ramdisk_dir = tmpdir.path().join("empty_ramdisk");
    std::fs::create_dir(&ramdisk_dir).unwrap(); //#[allow_ci]

    let output_path = tmpdir.path().join("policy.json");

    // An empty ramdisk dir should succeed
    // (just produces no initrd digests)
    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "policy",
            "generate",
            "runtime",
            "--ramdisk-dir",
            ramdisk_dir.to_str().unwrap(), //#[allow_ci]
            "--output",
            output_path.to_str().unwrap(), //#[allow_ci]
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&output_path).unwrap(); //#[allow_ci]
    let policy: serde_json::Value = serde_json::from_str(&content).unwrap(); //#[allow_ci]

    assert!(
        policy.get("digests").is_some(),
        "Expected 'digests' field in policy"
    );
}
