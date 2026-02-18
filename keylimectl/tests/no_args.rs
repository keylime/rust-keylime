// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Integration tests for keylimectl no-argument behavior.

#![allow(deprecated)] // cargo_bin deprecation — replacement API not yet stable

use assert_cmd::Command;
use predicates::prelude::*;

/// Create a command that runs from a temporary directory where no config
/// files exist, ensuring predictable default behavior.
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
    cmd
}

#[test]
fn test_no_args_exits_successfully() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir).assert().success();
}

#[test]
fn test_no_args_shows_config_summary() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir).output().unwrap(); //#[allow_ci]

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Config summary goes to stderr
    assert!(
        stderr.contains("Verifier:"),
        "Expected config summary with 'Verifier:' on stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("Registrar:"),
        "Expected config summary with 'Registrar:' on stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("TLS:"),
        "Expected config summary with 'TLS:' on stderr, got: {stderr}"
    );
}

#[test]
fn test_no_args_shows_help_with_subcommands() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir).output().unwrap(); //#[allow_ci]

    let stdout = String::from_utf8_lossy(&output.stdout);
    // clap help goes to stdout
    assert!(
        stdout.contains("Usage:"),
        "Expected 'Usage:' in help output on stdout, got: {stdout}"
    );
    // Dynamically generated subcommand list should include these
    assert!(
        stdout.contains("agent"),
        "Expected 'agent' subcommand in help output, got: {stdout}"
    );
    assert!(
        stdout.contains("configure"),
        "Expected 'configure' subcommand in help output, got: {stdout}"
    );
}

#[test]
fn test_no_args_shows_default_config_values() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir).output().unwrap(); //#[allow_ci]

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Default configuration values
    assert!(
        stderr.contains("127.0.0.1:8881"),
        "Expected default verifier address '127.0.0.1:8881', got: {stderr}"
    );
    assert!(
        stderr.contains("127.0.0.1:8891"),
        "Expected default registrar address '127.0.0.1:8891', got: {stderr}"
    );
    assert!(
        stderr.contains("(defaults)"),
        "Expected '(defaults)' since no config file exists, got: {stderr}"
    );
}

#[test]
fn test_no_args_no_config_file_message() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let output = keylimectl_in_clean_dir(&tmpdir).output().unwrap(); //#[allow_ci]

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No configuration file found"),
        "Expected 'No configuration file found' message, got: {stderr}"
    );
}

#[test]
fn test_help_flag_works() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("keylimectl"));
}

#[test]
fn test_version_flag_works() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    keylimectl_in_clean_dir(&tmpdir)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("keylimectl"));
}

#[test]
fn test_configure_non_interactive() {
    let tmpdir = tempfile::tempdir().unwrap(); //#[allow_ci]
    let config_path = tmpdir.path().join(".keylimectl").join("config.toml");

    keylimectl_in_clean_dir(&tmpdir)
        .args([
            "configure",
            "--non-interactive",
            "--scope",
            "local",
            "--verifier-ip",
            "10.0.0.1",
            "--verifier-port",
            "9001",
        ])
        .assert()
        .success();

    // Verify the config file was created
    assert!(
        config_path.exists(),
        "Expected config file at {config_path:?}"
    );

    // Verify it contains expected values
    let contents = std::fs::read_to_string(&config_path).unwrap(); //#[allow_ci]
    assert!(
        contents.contains("10.0.0.1"),
        "Expected verifier IP in config file"
    );
    assert!(
        contents.contains("9001"),
        "Expected verifier port in config file"
    );
}
