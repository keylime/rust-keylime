// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! ECDSA P-256 signing and verification backend for DSSE.

use super::{DsseError, Signer, Verifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign;
use std::path::Path;

/// ECDSA P-256 signer.
pub struct EcdsaSigner {
    private_key: PKey<Private>,
    public_key_pem: Vec<u8>,
}

impl std::fmt::Debug for EcdsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaSigner")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl EcdsaSigner {
    /// Generate a new ECDSA P-256 key pair.
    pub fn generate() -> Result<Self, DsseError> {
        let group =
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| {
                DsseError::KeyError {
                    reason: format!("Failed to create EC group: {e}"),
                }
            })?;
        let ec_key =
            EcKey::generate(&group).map_err(|e| DsseError::KeyError {
                reason: format!("Failed to generate EC key: {e}"),
            })?;
        let private_key =
            PKey::from_ec_key(ec_key).map_err(|e| DsseError::KeyError {
                reason: format!("Failed to wrap EC key: {e}"),
            })?;

        let public_key_pem =
            private_key.public_key_to_pem().map_err(|e| {
                DsseError::KeyError {
                    reason: format!("Failed to encode public key: {e}"),
                }
            })?;

        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    /// Load an ECDSA signer from a PEM-encoded private key file.
    pub fn from_pem_file(path: &str) -> Result<Self, DsseError> {
        let pem = std::fs::read(path).map_err(|e| DsseError::KeyError {
            reason: format!("Failed to read key file: {e}"),
        })?;

        let private_key = PKey::private_key_from_pem(&pem).map_err(|e| {
            DsseError::KeyError {
                reason: format!("Failed to parse private key: {e}"),
            }
        })?;

        // Verify it is a P-256 EC key — reject other curves.
        let ec_key =
            private_key.ec_key().map_err(|_| DsseError::KeyError {
                reason: "Key is not an EC key".to_string(),
            })?;
        if ec_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(DsseError::KeyError {
                reason: "EC key must use the P-256 (prime256v1) curve"
                    .to_string(),
            });
        }

        let public_key_pem =
            private_key.public_key_to_pem().map_err(|e| {
                DsseError::KeyError {
                    reason: format!("Failed to encode public key: {e}"),
                }
            })?;

        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    /// Save the private key to a PEM file with restricted permissions (0o600).
    ///
    /// Uses [`crate::policy_tools::privilege::write_sensitive_file`] to create
    /// the file with the correct permissions atomically, avoiding a TOCTOU race
    /// between file creation and a subsequent `chmod` call.
    pub fn save_private_key(&self, path: &str) -> Result<(), DsseError> {
        let pem =
            self.private_key.private_key_to_pem_pkcs8().map_err(|e| {
                DsseError::KeyError {
                    reason: format!("Failed to encode private key: {e}"),
                }
            })?;

        crate::policy_tools::privilege::write_sensitive_file(
            Path::new(path),
            &pem,
        )
        .map_err(|e| DsseError::KeyError {
            reason: format!("Failed to write key file: {e}"),
        })
    }

    /// Get the public key in PEM format.
    pub fn public_key_pem(&self) -> &[u8] {
        &self.public_key_pem
    }
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DsseError> {
        let mut signer =
            sign::Signer::new(MessageDigest::sha256(), &self.private_key)
                .map_err(|e| DsseError::SigningFailed {
                    reason: format!("Failed to create signer: {e}"),
                })?;

        signer
            .update(message)
            .map_err(|e| DsseError::SigningFailed {
                reason: format!("Failed to update signer: {e}"),
            })?;

        signer.sign_to_vec().map_err(|e| DsseError::SigningFailed {
            reason: format!("Failed to sign: {e}"),
        })
    }

    fn keyid(&self) -> String {
        // SHA-256 hash of the public key PEM
        use openssl::hash::{hash, MessageDigest};
        match hash(MessageDigest::sha256(), &self.public_key_pem) {
            Ok(digest) => hex::encode(digest),
            Err(_) => String::new(),
        }
    }
}

/// ECDSA P-256 verifier.
pub struct EcdsaVerifier {
    public_key: PKey<Public>,
    public_key_pem: Vec<u8>,
}

impl EcdsaVerifier {
    /// Create a verifier from a PEM-encoded public key.
    pub fn from_pem(pem: &[u8]) -> Result<Self, DsseError> {
        let public_key = PKey::public_key_from_pem(pem).map_err(|e| {
            DsseError::KeyError {
                reason: format!("Failed to parse public key: {e}"),
            }
        })?;

        Ok(Self {
            public_key,
            public_key_pem: pem.to_vec(),
        })
    }

    /// Create a verifier from a PEM-encoded public key file.
    pub fn from_pem_file(path: &str) -> Result<Self, DsseError> {
        let pem = std::fs::read(path).map_err(|e| DsseError::KeyError {
            reason: format!("Failed to read key file: {e}"),
        })?;
        Self::from_pem(pem.as_slice())
    }

    /// Create a verifier from a signer's public key.
    #[allow(dead_code)] // Used only in tests; see test_sign_and_verify_roundtrip in dsse/mod.rs
    pub fn from_signer(signer: &EcdsaSigner) -> Result<Self, DsseError> {
        Self::from_pem(signer.public_key_pem())
    }
}

impl Verifier for EcdsaVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsseError> {
        let mut verifier =
            sign::Verifier::new(MessageDigest::sha256(), &self.public_key)
                .map_err(|e| DsseError::VerificationFailed {
                    reason: format!("Failed to create verifier: {e}"),
                })?;

        verifier.update(message).map_err(|e| {
            DsseError::VerificationFailed {
                reason: format!("Failed to update verifier: {e}"),
            }
        })?;

        verifier.verify(signature).map_err(|e| {
            DsseError::VerificationFailed {
                reason: format!("Verification operation failed: {e}"),
            }
        })
    }

    fn keyid(&self) -> String {
        use openssl::hash::{hash, MessageDigest};
        match hash(MessageDigest::sha256(), &self.public_key_pem) {
            Ok(digest) => hex::encode(digest),
            Err(_) => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let signer = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        assert!(!signer.keyid().is_empty());
        assert!(!signer.public_key_pem().is_empty());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let verifier = EcdsaVerifier::from_signer(&signer).unwrap(); //#[allow_ci]

        let message = b"test message";
        let signature = signer.sign(message).unwrap(); //#[allow_ci]

        assert!(verifier.verify(message, &signature).unwrap()); //#[allow_ci]
    }

    #[test]
    fn test_verify_wrong_message() {
        let signer = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let verifier = EcdsaVerifier::from_signer(&signer).unwrap(); //#[allow_ci]

        let signature = signer.sign(b"original message").unwrap(); //#[allow_ci]

        assert!(!verifier.verify(b"different message", &signature).unwrap()); //#[allow_ci]
    }

    #[test]
    fn test_verify_wrong_key() {
        let signer1 = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let signer2 = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let verifier2 = EcdsaVerifier::from_signer(&signer2).unwrap(); //#[allow_ci]

        let message = b"test message";
        let signature = signer1.sign(message).unwrap(); //#[allow_ci]

        assert!(!verifier2.verify(message, &signature).unwrap()); //#[allow_ci]
    }

    #[test]
    fn test_save_and_load_key() {
        let signer = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let message = b"test message";
        let original_sig = signer.sign(message).unwrap(); //#[allow_ci]

        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        signer.save_private_key(&path).unwrap(); //#[allow_ci]

        let loaded = EcdsaSigner::from_pem_file(&path).unwrap(); //#[allow_ci]

        // Verify with the loaded key's public key
        let verifier = EcdsaVerifier::from_signer(&loaded).unwrap(); //#[allow_ci]
        assert!(verifier.verify(message, &original_sig).unwrap()); //#[allow_ci]

        // Verify keyid is the same
        assert_eq!(signer.keyid(), loaded.keyid());
    }

    #[test]
    fn test_from_pem_file_rejects_non_p256_key() {
        use openssl::ec::EcGroup;
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap(); //#[allow_ci]
        let ec_key = EcKey::generate(&group).unwrap(); //#[allow_ci]
        let pkey = PKey::from_ec_key(ec_key).unwrap(); //#[allow_ci]
        let pem = pkey.private_key_to_pem_pkcs8().unwrap(); //#[allow_ci]

        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &pem).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let result = EcdsaSigner::from_pem_file(&path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err() //#[allow_ci]
            .to_string()
            .contains("P-256"));
    }

    #[test]
    fn test_keyid_is_hex_sha256() {
        let signer = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let keyid = signer.keyid();

        // SHA-256 hex digest is 64 chars
        assert_eq!(keyid.len(), 64);
        assert!(keyid.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
