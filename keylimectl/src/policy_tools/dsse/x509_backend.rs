// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! X.509 certificate-based signing and verification backend for DSSE.
//!
//! Uses ECDSA P-256 with SHA-256 for signing, with the key identifier
//! being the base64-encoded X.509 certificate.

use super::{Signer, Verifier};
use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509};

/// X.509 certificate-based signer.
pub struct X509Signer {
    private_key: PKey<Private>,
    certificate_pem: Vec<u8>,
}

impl X509Signer {
    /// Generate a new key pair and self-signed certificate.
    pub fn generate(cert_path: Option<&str>) -> Result<Self, String> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| format!("Failed to create EC group: {e}"))?;
        let ec_key = EcKey::generate(&group)
            .map_err(|e| format!("Failed to generate EC key: {e}"))?;
        let private_key = PKey::from_ec_key(ec_key)
            .map_err(|e| format!("Failed to wrap EC key: {e}"))?;

        let certificate_pem =
            build_self_signed_cert(&private_key, "keylimectl", 30)?;

        if let Some(path) = cert_path {
            std::fs::write(path, &certificate_pem)
                .map_err(|e| format!("Failed to write certificate: {e}"))?;
        }

        Ok(Self {
            private_key,
            certificate_pem,
        })
    }

    /// Load a signer from existing key and certificate files.
    pub fn from_files(
        key_path: &str,
        cert_path: &str,
    ) -> Result<Self, String> {
        let key_pem = std::fs::read(key_path)
            .map_err(|e| format!("Failed to read key file: {e}"))?;
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| format!("Failed to read certificate file: {e}"))?;

        let private_key = PKey::private_key_from_pem(&key_pem)
            .map_err(|e| format!("Failed to parse private key: {e}"))?;

        // Verify the certificate is valid
        let _cert = X509::from_pem(&cert_pem)
            .map_err(|e| format!("Failed to parse certificate: {e}"))?;

        Ok(Self {
            private_key,
            certificate_pem: cert_pem,
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

    /// Get the certificate in PEM format.
    #[allow(dead_code)]
    pub fn certificate_pem(&self) -> &[u8] {
        &self.certificate_pem
    }
}

impl Signer for X509Signer {
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
        // Base64-encode the certificate PEM
        Base64.encode(&self.certificate_pem)
    }
}

/// X.509 certificate-based verifier.
pub struct X509Verifier {
    public_key: PKey<Public>,
}

impl X509Verifier {
    /// Create a verifier from a PEM-encoded X.509 certificate.
    pub fn from_cert_pem(pem: &[u8]) -> Result<Self, String> {
        let cert = X509::from_pem(pem)
            .map_err(|e| format!("Failed to parse certificate: {e}"))?;

        let public_key = cert.public_key().map_err(|e| {
            format!("Failed to extract public key from cert: {e}")
        })?;

        Ok(Self { public_key })
    }

    /// Create a verifier from a PEM-encoded certificate file.
    #[allow(dead_code)]
    pub fn from_cert_file(path: &str) -> Result<Self, String> {
        let pem = std::fs::read(path)
            .map_err(|e| format!("Failed to read certificate file: {e}"))?;
        Self::from_cert_pem(&pem)
    }

    /// Create a verifier from a signer's certificate.
    #[allow(dead_code)]
    pub fn from_signer(signer: &X509Signer) -> Result<Self, String> {
        Self::from_cert_pem(signer.certificate_pem())
    }
}

impl Verifier for X509Verifier {
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

/// Build a self-signed X.509 v3 certificate.
fn build_self_signed_cert(
    private_key: &PKey<Private>,
    subject_name: &str,
    expiration_days: u32,
) -> Result<Vec<u8>, String> {
    let mut builder = openssl::x509::X509Builder::new()
        .map_err(|e| format!("Failed to create X509 builder: {e}"))?;

    // Version 3
    builder
        .set_version(2)
        .map_err(|e| format!("Failed to set version: {e}"))?;

    // Serial number
    let serial = BigNum::from_u32(1)
        .and_then(|bn| bn.to_asn1_integer())
        .map_err(|e| format!("Failed to create serial: {e}"))?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| format!("Failed to set serial: {e}"))?;

    // Subject and issuer (same for self-signed)
    let mut name_builder = X509NameBuilder::new()
        .map_err(|e| format!("Failed to create name builder: {e}"))?;
    name_builder
        .append_entry_by_text("CN", subject_name)
        .map_err(|e| format!("Failed to add CN: {e}"))?;
    let name = name_builder.build();

    builder
        .set_subject_name(&name)
        .map_err(|e| format!("Failed to set subject: {e}"))?;
    builder
        .set_issuer_name(&name)
        .map_err(|e| format!("Failed to set issuer: {e}"))?;

    // Validity period
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|e| format!("Failed to create not_before: {e}"))?;
    let not_after = Asn1Time::days_from_now(expiration_days)
        .map_err(|e| format!("Failed to create not_after: {e}"))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| format!("Failed to set not_before: {e}"))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| format!("Failed to set not_after: {e}"))?;

    // Public key
    builder
        .set_pubkey(private_key)
        .map_err(|e| format!("Failed to set public key: {e}"))?;

    // Extensions
    let basic_constraints = BasicConstraints::new()
        .build()
        .map_err(|e| format!("Failed to build basic constraints: {e}"))?;
    builder
        .append_extension(basic_constraints)
        .map_err(|e| format!("Failed to append basic constraints: {e}"))?;

    let san = SubjectAlternativeName::new()
        .dns(subject_name)
        .build(&builder.x509v3_context(None, None))
        .map_err(|e| format!("Failed to build SAN: {e}"))?;
    builder
        .append_extension(san)
        .map_err(|e| format!("Failed to append SAN: {e}"))?;

    // Sign
    builder
        .sign(private_key, MessageDigest::sha256())
        .map_err(|e| format!("Failed to sign certificate: {e}"))?;

    let cert = builder.build();
    cert.to_pem()
        .map_err(|e| format!("Failed to encode certificate: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_signer() {
        let signer = X509Signer::generate(None).unwrap(); //#[allow_ci]
        assert!(!signer.keyid().is_empty());
        assert!(!signer.certificate_pem().is_empty());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = X509Signer::generate(None).unwrap(); //#[allow_ci]
        let verifier = X509Verifier::from_signer(&signer).unwrap(); //#[allow_ci]

        let message = b"test message";
        let signature = signer.sign(message).unwrap(); //#[allow_ci]

        assert!(verifier.verify(message, &signature));
    }

    #[test]
    fn test_verify_wrong_message() {
        let signer = X509Signer::generate(None).unwrap(); //#[allow_ci]
        let verifier = X509Verifier::from_signer(&signer).unwrap(); //#[allow_ci]

        let signature = signer.sign(b"original").unwrap(); //#[allow_ci]

        assert!(!verifier.verify(b"different", &signature));
    }

    #[test]
    fn test_save_and_load() {
        let signer = X509Signer::generate(None).unwrap(); //#[allow_ci]
        let message = b"test message";
        let original_sig = signer.sign(message).unwrap(); //#[allow_ci]

        let key_file = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        let cert_file = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]

        let key_path = key_file.path().to_string_lossy().to_string();
        let cert_path = cert_file.path().to_string_lossy().to_string();

        signer.save_private_key(&key_path).unwrap(); //#[allow_ci]
        std::fs::write(&cert_path, signer.certificate_pem()).unwrap(); //#[allow_ci]

        let loaded = X509Signer::from_files(&key_path, &cert_path).unwrap(); //#[allow_ci]

        let verifier = X509Verifier::from_signer(&loaded).unwrap(); //#[allow_ci]
        assert!(verifier.verify(message, &original_sig));
    }

    #[test]
    fn test_keyid_is_base64_cert() {
        let signer = X509Signer::generate(None).unwrap(); //#[allow_ci]
        let keyid = signer.keyid();

        // Should be valid base64
        let decoded = Base64.decode(&keyid);
        assert!(decoded.is_ok());

        // Decoded should be a valid PEM certificate
        let pem = decoded.unwrap(); //#[allow_ci]
        assert!(std::str::from_utf8(&pem)
            .unwrap() //#[allow_ci]
            .contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_certificate_saved_to_file() {
        let cert_file = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        let cert_path = cert_file.path().to_string_lossy().to_string();

        let _signer = X509Signer::generate(Some(&cert_path)).unwrap(); //#[allow_ci]

        let cert_contents = std::fs::read_to_string(&cert_path).unwrap(); //#[allow_ci]
        assert!(cert_contents.contains("BEGIN CERTIFICATE"));
    }
}
