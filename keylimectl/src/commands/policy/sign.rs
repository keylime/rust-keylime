// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Policy signing using DSSE (Dead Simple Signing Envelope).

use crate::error::KeylimectlError;
use crate::output::OutputHandler;
use crate::policy_tools::dsse::{
    self, ecdsa_backend::EcdsaSigner, x509_backend::X509Signer,
    KEYLIME_PAYLOAD_TYPE,
};
use crate::SigningBackend;
use serde_json::Value;

/// Execute the policy sign command.
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    file: &str,
    keyfile: Option<&str>,
    keypath: Option<&str>,
    backend: &SigningBackend,
    output_file: Option<&str>,
    cert_outfile: Option<&str>,
    output: &OutputHandler,
) -> Result<Value, KeylimectlError> {
    // Read the policy file
    let policy_content = std::fs::read(file).map_err(|e| {
        KeylimectlError::validation(format!(
            "Failed to read policy file '{file}': {e}"
        ))
    })?;

    // Validate it's valid JSON
    let _: Value = serde_json::from_slice(&policy_content).map_err(|e| {
        KeylimectlError::validation(format!(
            "Policy file is not valid JSON: {e}"
        ))
    })?;

    // Create the signer based on backend
    let envelope = match backend {
        SigningBackend::Ecdsa => {
            sign_ecdsa(&policy_content, keyfile, keypath, output)?
        }
        SigningBackend::X509 => sign_x509(
            &policy_content,
            keyfile,
            keypath,
            cert_outfile,
            output,
        )?,
    };

    let envelope_json = serde_json::to_value(&envelope)?;

    // Write to file or stdout
    if let Some(out_path) = output_file {
        let json_str = serde_json::to_string_pretty(&envelope_json)?;
        std::fs::write(out_path, &json_str).map_err(|e| {
            KeylimectlError::validation(format!(
                "Failed to write output file: {e}"
            ))
        })?;
        output.info(format!("Signed policy written to {out_path}"));
    } else {
        output.success(envelope_json.clone());
    }

    Ok(envelope_json)
}

/// Sign using ECDSA backend.
fn sign_ecdsa(
    payload: &[u8],
    keyfile: Option<&str>,
    keypath: Option<&str>,
    output: &OutputHandler,
) -> Result<dsse::DsseEnvelope, KeylimectlError> {
    let signer = if let Some(kf) = keyfile {
        output.info(format!("Loading ECDSA key from {kf}"));
        EcdsaSigner::from_pem_file(kf).map_err(|e| {
            KeylimectlError::validation(format!("Failed to load key: {e}"))
        })?
    } else {
        output.info("Generating new ECDSA P-256 key pair");
        let s = EcdsaSigner::generate().map_err(|e| {
            KeylimectlError::validation(format!(
                "Failed to generate key: {e}"
            ))
        })?;

        let key_path = keypath.unwrap_or("keylime-ecdsa-key.pem");
        s.save_private_key(key_path).map_err(|e| {
            KeylimectlError::validation(format!("Failed to save key: {e}"))
        })?;
        output.info(format!("Private key saved to {key_path}"));

        // Save public key
        let pub_path = format!("{key_path}.pub");
        std::fs::write(&pub_path, s.public_key_pem()).map_err(|e| {
            KeylimectlError::validation(format!(
                "Failed to save public key: {e}"
            ))
        })?;
        output.info(format!("Public key saved to {pub_path}"));

        s
    };

    dsse::sign_payload(payload, KEYLIME_PAYLOAD_TYPE, &signer).map_err(|e| {
        KeylimectlError::validation(format!("Signing failed: {e}"))
    })
}

/// Sign using X.509 backend.
fn sign_x509(
    payload: &[u8],
    keyfile: Option<&str>,
    keypath: Option<&str>,
    cert_outfile: Option<&str>,
    output: &OutputHandler,
) -> Result<dsse::DsseEnvelope, KeylimectlError> {
    let signer = if let Some(kf) = keyfile {
        let cert_path = cert_outfile.ok_or_else(|| {
            KeylimectlError::validation(
                "X.509 backend requires --cert-outfile when using --keyfile",
            )
        })?;
        output.info(format!(
            "Loading key from {kf} and certificate from {cert_path}"
        ));
        X509Signer::from_files(kf, cert_path).map_err(|e| {
            KeylimectlError::validation(format!(
                "Failed to load key/cert: {e}"
            ))
        })?
    } else {
        output.info(
            "Generating new ECDSA P-256 key pair and X.509 certificate",
        );

        let cert_path = cert_outfile.unwrap_or("keylime-cert.pem");
        let s = X509Signer::generate(Some(cert_path)).map_err(|e| {
            KeylimectlError::validation(format!(
                "Failed to generate key/cert: {e}"
            ))
        })?;
        output.info(format!("Certificate saved to {cert_path}"));

        let key_path = keypath.unwrap_or("keylime-ecdsa-key.pem");
        s.save_private_key(key_path).map_err(|e| {
            KeylimectlError::validation(format!("Failed to save key: {e}"))
        })?;
        output.info(format!("Private key saved to {key_path}"));

        s
    };

    dsse::sign_payload(payload, KEYLIME_PAYLOAD_TYPE, &signer).map_err(|e| {
        KeylimectlError::validation(format!("Signing failed: {e}"))
    })
}
