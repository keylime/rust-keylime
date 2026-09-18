// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! PGP detached signature verification for RPM repository metadata.

use sequoia_openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::KeyHandle;

use crate::commands::error::PolicyGenerationError;

struct Helper {
    cert: sequoia_openpgp::Cert,
}

impl VerificationHelper for Helper {
    fn get_certs(
        &mut self,
        _ids: &[KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(
        &mut self,
        structure: MessageStructure,
    ) -> sequoia_openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    if result.is_ok() {
                        return Ok(());
                    }
                }
            }
        }
        Err(anyhow::anyhow!("No valid signature found"))
    }
}

/// Verify a PGP detached signature.
///
/// `key_data` — ASCII-armored or binary PGP public key.
/// `sig_data` — ASCII-armored or binary detached signature.
/// `body`     — The signed content.
/// `path`     — Used in error messages to identify the signed file.
pub fn verify_detached_signature(
    key_data: &[u8],
    sig_data: &[u8],
    body: &[u8],
    path: &std::path::Path,
) -> Result<(), PolicyGenerationError> {
    let policy = &StandardPolicy::new();

    let cert = sequoia_openpgp::Cert::from_reader(key_data).map_err(|e| {
        PolicyGenerationError::GpgVerification {
            path: path.to_path_buf(),
            reason: format!("Failed to parse PGP key: {e}"),
        }
    })?;

    let helper = Helper { cert };

    let mut verifier = DetachedVerifierBuilder::from_reader(sig_data)
        .map_err(|e| PolicyGenerationError::GpgVerification {
            path: path.to_path_buf(),
            reason: format!("Failed to parse PGP signature: {e}"),
        })?
        .with_policy(policy, None, helper)
        .map_err(|e| PolicyGenerationError::GpgVerification {
            path: path.to_path_buf(),
            reason: format!("Verification setup failed: {e}"),
        })?;

    verifier.verify_bytes(body).map_err(|e| {
        PolicyGenerationError::GpgVerification {
            path: path.to_path_buf(),
            reason: format!("Signature verification failed: {e}"),
        }
    })?;

    Ok(())
}

/// Load GPG key bytes from a file, mapping IO errors to PolicyGenerationError.
pub fn load_key_file(
    key_path: &std::path::Path,
) -> Result<Vec<u8>, PolicyGenerationError> {
    std::fs::read(key_path).map_err(|e| {
        PolicyGenerationError::GpgVerification {
            path: key_path.to_path_buf(),
            reason: format!("Failed to read GPG key file: {e}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::policy::StandardPolicy;
    use sequoia_openpgp::serialize::stream::{Message, Signer};
    use sequoia_openpgp::serialize::SerializeInto;

    use super::*;

    fn make_test_cert_and_sign(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let policy = StandardPolicy::new();

        let (cert, _rev) = CertBuilder::new()
            .add_signing_subkey()
            .generate()
            .expect("key generation failed");

        let pub_key = cert.armored().to_vec().expect("key export failed");

        let keypair = cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .expect("no signing key")
            .key()
            .clone()
            .parts_into_secret()
            .expect("secret key unavailable")
            .into_keypair()
            .expect("keypair construction failed");

        let mut sig_bytes: Vec<u8> = Vec::new();
        {
            let message = Message::new(&mut sig_bytes);
            let mut signer = Signer::new(message, keypair)
                .expect("signer construction failed")
                .detached()
                .build()
                .expect("signer build failed");
            signer.write_all(data).expect("write failed");
            signer.finalize().expect("finalize failed");
        }

        (pub_key, sig_bytes)
    }

    #[test]
    fn test_valid_signature() {
        let body = b"repomd.xml content";
        let (pub_key, sig) = make_test_cert_and_sign(body);
        let path = std::path::Path::new("repomd.xml");

        assert!(verify_detached_signature(&pub_key, &sig, body, path).is_ok());
    }

    #[test]
    fn test_tampered_body_fails() {
        let body = b"repomd.xml content";
        let (pub_key, sig) = make_test_cert_and_sign(body);
        let path = std::path::Path::new("repomd.xml");

        let tampered = b"tampered repomd.xml content";
        assert!(verify_detached_signature(&pub_key, &sig, tampered, path)
            .is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let body = b"repomd.xml content";
        let (_, sig) = make_test_cert_and_sign(body);
        let (other_pub_key, _) = make_test_cert_and_sign(b"other");
        let path = std::path::Path::new("repomd.xml");

        assert!(verify_detached_signature(&other_pub_key, &sig, body, path)
            .is_err());
    }

    #[test]
    fn test_bad_key_data_fails() {
        let path = std::path::Path::new("repomd.xml");
        let result = verify_detached_signature(
            b"not a pgp key",
            b"not a signature",
            b"body",
            path,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_load_key_file_missing() {
        let result = load_key_file(std::path::Path::new("/nonexistent/key"));
        assert!(result.is_err());
    }
}
