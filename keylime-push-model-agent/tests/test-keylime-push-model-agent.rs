// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use assert_cmd::Command;
use predicates::prelude::*;

const KEYLIME_PUSH_MODEL_AGENT_BINARY: &str = "keylime_push_model_agent";
const ERROR_SENDING_REQUEST: &str =
    "error sending request for url (http://1.2.3.4:5678/v3.0/agents/12345678/attestations)";
const ERROR_SENDING_LOCALHOST_REQUEST: &str =
    "error sending request for url (http://localhost:3000/v3.0/agents/12345678/attestations)";

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn print_help_test() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin(KEYLIME_PUSH_MODEL_AGENT_BINARY)?;
        cmd.arg("-h");
        cmd.assert().success().stdout(predicate::str::contains(
            KEYLIME_PUSH_MODEL_AGENT_BINARY,
        ));
        Ok(())
    }

    #[test]
    fn connection_error_test() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin(KEYLIME_PUSH_MODEL_AGENT_BINARY)?;
        cmd.arg("-v")
            .arg("http://1.2.3.4:5678")
            .arg("--timeout")
            .arg("10")
            .arg("--agent-identifier")
            .arg("12345678")
            .arg("--message-type")
            .arg("attestation")
            .arg("--method")
            .arg("--avoid-registration")
            .arg("true")
            .arg("POST");
        cmd.assert()
            .success()
            .stderr(predicate::str::contains(ERROR_SENDING_REQUEST));
        Ok(())
    }
    #[test]
    fn mockoon_based_test() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin(KEYLIME_PUSH_MODEL_AGENT_BINARY)?;
        cmd.arg("-v")
            .arg("http://localhost:3000")
            .arg("--avoid-registration")
            .arg("true")
            .arg("--timeout")
            .arg("1000");
        // Check if MOCKOON environment variable is set and, if so, assume
        // that the mock server is running in port 3000 and response will be received
        // in less than 1 second.
        if std::env::var("MOCKOON").is_ok() {
            cmd.assert().success();
        } else {
            // If MOCKOON is not set, assume that the server is not running
            // and we expect an error.
            cmd.assert().success().stderr(predicate::str::contains(
                ERROR_SENDING_LOCALHOST_REQUEST,
            ));
        }
        Ok(())
    }
}
