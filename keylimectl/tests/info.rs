// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Integration tests for `keylimectl info` command.
//!
//! These tests exercise the info subcommands that do not require
//! network connectivity (i.e., `info` and `info tls`).

#![allow(deprecated)] // cargo_bin deprecation — replacement API not yet stable

use assert_cmd::Command;
use predicates::prelude::*;

/// Create a command that runs from a temporary directory with clean env.
fn keylimectl_in_clean_dir(tmpdir: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("keylimectl").unwrap(); //#[allow_ci]
    cmd.current_dir(tmpdir.path());
    // Point HOME to the temp dir so config search paths based on
    // ~/.config/keylimectl/ won't find the user's real config files.
    cmd.env("HOME", tmpdir.path());
    cmd.env_remove("XDG_CONFIG_HOME");
    // Suppress env vars that might affect config loading
    cmd.env_remove("KEYLIME_VERIFIER__IP");
    cmd.env_remove("KEYLIME_VERIFIER__PORT");
    cmd.env_remove("KEYLIME_REGISTRAR__IP");
    cmd.env_remove("KEYLIME_REGISTRAR__PORT");
    cmd.env_remove("KEYLIME_CLIENT__TIMEOUT");
    cmd
}

#[test]
fn test_info_exits_successfully() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .arg("info")
        .assert()
        .success();
}

#[test]
fn test_info_json_output_valid() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir)
        .arg("info")
        .output()
        .unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| {
            panic!( //#[allow_ci]
                "Expected valid JSON output, got error: {e}\nstdout: {stdout}"
            )
        });

    // Should have top-level keys
    assert!(
        parsed.get("keylimectl").is_some(),
        "Expected 'keylimectl' key in JSON output"
    );
    assert!(
        parsed.get("config_files").is_some(),
        "Expected 'config_files' key in JSON output"
    );
    assert!(
        parsed.get("effective_config").is_some(),
        "Expected 'effective_config' key in JSON output"
    );
}

#[test]
fn test_info_shows_version() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir)
        .arg("info")
        .output()
        .unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap(); //#[allow_ci]

    let version = &parsed["keylimectl"]["version"];
    assert!(
        version.is_string(),
        "Expected version string, got: {version}"
    );
}

#[test]
fn test_info_shows_features() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir)
        .arg("info")
        .output()
        .unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap(); //#[allow_ci]

    let features = &parsed["keylimectl"]["features"];
    assert!(
        features["api-v2"].is_boolean(),
        "Expected api-v2 feature flag"
    );
    assert!(
        features["api-v3"].is_boolean(),
        "Expected api-v3 feature flag"
    );
}

#[test]
fn test_info_shows_default_config() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir)
        .arg("info")
        .output()
        .unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap(); //#[allow_ci]

    let effective = &parsed["effective_config"];

    // Check default verifier config
    assert_eq!(
        effective["verifier"]["ip"]["value"], "127.0.0.1",
        "Expected default verifier IP"
    );
    assert_eq!(
        effective["verifier"]["port"]["value"], 8881,
        "Expected default verifier port"
    );
    assert_eq!(
        effective["verifier"]["ip"]["source"], "default",
        "Expected 'default' source for verifier IP"
    );
}

#[test]
fn test_info_config_files_searched() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir)
        .arg("info")
        .output()
        .unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap(); //#[allow_ci]

    let config_files = &parsed["config_files"];
    assert!(
        config_files["loaded_from"].is_null(),
        "Expected no config file loaded in clean dir"
    );
    assert!(
        config_files["searched"].is_array(),
        "Expected searched paths array"
    );
    let searched = config_files["searched"].as_array().unwrap(); //#[allow_ci]
    assert!(!searched.is_empty(), "Expected non-empty searched paths");
}

#[test]
fn test_info_tls_exits_successfully() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .args(["info", "tls"])
        .assert()
        .success();
}

#[test]
fn test_info_tls_json_structure() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir)
        .args(["info", "tls"])
        .output()
        .unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!( //#[allow_ci]
                "Expected valid JSON for info tls, got error: {e}\nstdout: {stdout}"
            )
        });

    assert!(
        parsed.get("tls_config").is_some(),
        "Expected 'tls_config' key"
    );
    assert!(
        parsed.get("certificates").is_some(),
        "Expected 'certificates' key"
    );
    assert!(parsed.get("issues").is_some(), "Expected 'issues' key");
    assert!(
        parsed.get("suggestions").is_some(),
        "Expected 'suggestions' key"
    );
}

#[test]
fn test_info_tls_with_missing_certs() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir)
        .args(["info", "tls"])
        .output()
        .unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap(); //#[allow_ci]

    // Default config has cert paths that don't exist on the test system
    let issues = parsed["issues"].as_array().unwrap(); //#[allow_ci]
    assert!(
        !issues.is_empty(),
        "Expected issues when default cert files don't exist"
    );
}

#[test]
fn test_info_diag_alias() {
    // "diag" is an alias for "info"
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .arg("diag")
        .assert()
        .success();
}

#[test]
fn test_help_shows_info_command() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("info"));
}
