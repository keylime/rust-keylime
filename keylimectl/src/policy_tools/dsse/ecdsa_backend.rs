// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! ECDSA P-256 signing and verification backend for DSSE.

use super::{Signer, Verifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign;

/// ECDSA P-256 signer.
pub struct EcdsaSigner {
    private_key: PKey<Private>,
    public_key_pem: Vec<u8>,
}

impl EcdsaSigner {
    /// Generate a new ECDSA P-256 key pair.
    pub fn generate() -> Result<Self, String> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| format!("Failed to create EC group: {e}"))?;
        let ec_key = EcKey::generate(&group)
            .map_err(|e| format!("Failed to generate EC key: {e}"))?;
        let private_key = PKey::from_ec_key(ec_key)
            .map_err(|e| format!("Failed to wrap EC key: {e}"))?;

        let public_key_pem = private_key
            .public_key_to_pem()
            .map_err(|e| format!("Failed to encode public key: {e}"))?;

        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    /// Load an ECDSA signer from a PEM-encoded private key file.
    pub fn from_pem_file(path: &str) -> Result<Self, String> {
        let pem = std::fs::read(path)
            .map_err(|e| format!("Failed to read key file: {e}"))?;

        let private_key = PKey::private_key_from_pem(&pem)
            .map_err(|e| format!("Failed to parse private key: {e}"))?;

        // Verify it's an EC key
        if private_key.ec_key().is_err() {
            return Err("Key is not an EC key".to_string());
        }

        let public_key_pem = private_key
            .public_key_to_pem()
            .map_err(|e| format!("Failed to encode public key: {e}"))?;

        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    /// Save the private key to a PEM file.
    pub fn save_private_key(&self, path: &str) -> Result<(), String> {
        let pem = self
            .private_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| format!("Failed to encode private key: {e}"))?;

        std::fs::write(path, &pem)
            .map_err(|e| format!("Failed to write key file: {e}"))?;

        // Set restrictive permissions (0o600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(|e| {
                format!("Failed to set key file permissions: {e}")
            })?;
        }

        Ok(())
    }

    /// Get the public key in PEM format.
    pub fn public_key_pem(&self) -> &[u8] {
        &self.public_key_pem
    }
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let mut signer =
            sign::Signer::new(MessageDigest::sha256(), &self.private_key)
                .map_err(|e| format!("Failed to create signer: {e}"))?;

        signer
            .update(message)
            .map_err(|e| format!("Failed to update signer: {e}"))?;

        signer
            .sign_to_vec()
            .map_err(|e| format!("Failed to sign: {e}"))
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
}

impl EcdsaVerifier {
    /// Create a verifier from a PEM-encoded public key.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let public_key = PKey::public_key_from_pem(pem)
            .map_err(|e| format!("Failed to parse public key: {e}"))?;

        Ok(Self { public_key })
    }

    /// Create a verifier from a PEM-encoded public key file.
    #[allow(dead_code)]
    pub fn from_pem_file(path: &str) -> Result<Self, String> {
        let pem = std::fs::read(path)
            .map_err(|e| format!("Failed to read key file: {e}"))?;
        Self::from_pem(pem.as_slice())
    }

    /// Create a verifier from a signer's public key.
    #[allow(dead_code)]
    pub fn from_signer(signer: &EcdsaSigner) -> Result<Self, String> {
        Self::from_pem(signer.public_key_pem())
    }
}

impl Verifier for EcdsaVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let mut verifier = match sign::Verifier::new(
            MessageDigest::sha256(),
            &self.public_key,
        ) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if verifier.update(message).is_err() {
            return false;
        }

        verifier.verify(signature).unwrap_or(false)
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

        assert!(verifier.verify(message, &signature));
    }

    #[test]
    fn test_verify_wrong_message() {
        let signer = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let verifier = EcdsaVerifier::from_signer(&signer).unwrap(); //#[allow_ci]

        let signature = signer.sign(b"original message").unwrap(); //#[allow_ci]

        assert!(!verifier.verify(b"different message", &signature));
    }

    #[test]
    fn test_verify_wrong_key() {
        let signer1 = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let signer2 = EcdsaSigner::generate().unwrap(); //#[allow_ci]
        let verifier2 = EcdsaVerifier::from_signer(&signer2).unwrap(); //#[allow_ci]

        let message = b"test message";
        let signature = signer1.sign(message).unwrap(); //#[allow_ci]

        assert!(!verifier2.verify(message, &signature));
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
        assert!(verifier.verify(message, &original_sig));

        // Verify keyid is the same
        assert_eq!(signer.keyid(), loaded.keyid());
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
