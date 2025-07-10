// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors
use openssl::hash::MessageDigest;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use thiserror::Error;
use tss_esapi::{
    abstraction::AsymmetricAlgorithmSelection,
    interface_types::{
        algorithm::{
            AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
        },
        ecc::EccCurve,
        key_bits::RsaKeyBits,
    },
    structures::{HashScheme, SignatureScheme},
};

// This error needs to be public because we implement TryFrom for public types
#[derive(Error, Debug)]
pub enum AlgorithmError {
    #[error("Hashing Algorithm {0} not supported")]
    UnsupportedHashingAlgorithm(String),

    #[error("Encryption Algorithm {0} not supported")]
    UnsupportedEncryptionAlgorithm(String),

    #[error("Signing algorithm {0} not supported")]
    UnsupportedSigningAlgorithm(String),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
}

pub fn hash_to_hashing_algorithm(
    hash_algorithm: HashAlgorithm,
) -> HashingAlgorithm {
    match hash_algorithm {
        HashAlgorithm::Sha1 => HashingAlgorithm::Sha1,
        HashAlgorithm::Sha256 => HashingAlgorithm::Sha256,
        HashAlgorithm::Sm3_256 => HashingAlgorithm::Sm3_256,
        HashAlgorithm::Sha384 => HashingAlgorithm::Sha384,
        HashAlgorithm::Sha512 => HashingAlgorithm::Sha512,
    }
}

impl TryFrom<tss_esapi::interface_types::algorithm::HashingAlgorithm>
    for HashAlgorithm
{
    type Error = AlgorithmError;

    fn try_from(
        tss_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    ) -> Result<Self, Self::Error> {
        match tss_alg {
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha1 => Ok(HashAlgorithm::Sha1),
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256 => Ok(HashAlgorithm::Sha256),
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384 => Ok(HashAlgorithm::Sha384),
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512 => Ok(HashAlgorithm::Sha512),
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sm3_256 => Ok(HashAlgorithm::Sm3_256),
            _ => Err(AlgorithmError::UnsupportedHashingAlgorithm(format!(
                "Unable to convert tss-esapi HashingAlgorithm: {tss_alg:?}"
            ))),
        }
    }
}

impl TryFrom<&str> for HashAlgorithm {
    type Error = AlgorithmError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "sha1" => Ok(HashAlgorithm::Sha1),
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha384" => Ok(HashAlgorithm::Sha384),
            "sha512" => Ok(HashAlgorithm::Sha512),
            "sm3_256" => Ok(HashAlgorithm::Sm3_256),
            _ => {
                Err(AlgorithmError::UnsupportedHashingAlgorithm(value.into()))
            }
        }
    }
}
impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha384 => "sha384",
            HashAlgorithm::Sha512 => "sha512",
            HashAlgorithm::Sm3_256 => "sm3_256",
        };
        write!(f, "{value}")
    }
}

impl From<HashAlgorithm> for HashingAlgorithm {
    fn from(hashing_algorithm: HashAlgorithm) -> Self {
        match hashing_algorithm {
            HashAlgorithm::Sha1 => HashingAlgorithm::Sha1,
            HashAlgorithm::Sha256 => HashingAlgorithm::Sha256,
            HashAlgorithm::Sha384 => HashingAlgorithm::Sha384,
            HashAlgorithm::Sha512 => HashingAlgorithm::Sha512,
            HashAlgorithm::Sm3_256 => HashingAlgorithm::Sm3_256,
        }
    }
}

impl From<HashAlgorithm> for MessageDigest {
    fn from(hash_algorithm: HashAlgorithm) -> Self {
        match hash_algorithm {
            HashAlgorithm::Sha1 => MessageDigest::sha1(),
            HashAlgorithm::Sha256 => MessageDigest::sha256(),
            HashAlgorithm::Sha384 => MessageDigest::sha384(),
            HashAlgorithm::Sha512 => MessageDigest::sha512(),
            HashAlgorithm::Sm3_256 => MessageDigest::sm3(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ecc192,
    Ecc224,
    Ecc256,
    Ecc384,
    Ecc521,
    EccSm2,
}

#[derive(Eq, PartialEq, Debug)]
pub enum KeyClass {
    Asymmetric,
    Symmetric,
}

impl fmt::Display for KeyClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            KeyClass::Asymmetric => "asymmetric",
            KeyClass::Symmetric => "symmetric",
        };
        write!(f, "{value}")
    }
}

pub fn get_key_class(&tpm_encryption_alg: &EncryptionAlgorithm) -> KeyClass {
    match tpm_encryption_alg {
        EncryptionAlgorithm::Rsa1024 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Rsa2048 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Rsa3072 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Rsa4096 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Ecc192 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Ecc224 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Ecc256 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Ecc384 => KeyClass::Asymmetric,
        EncryptionAlgorithm::Ecc521 => KeyClass::Asymmetric,
        EncryptionAlgorithm::EccSm2 => KeyClass::Asymmetric,
    }
}

pub fn get_key_size(tpm_encryption_alg: &EncryptionAlgorithm) -> usize {
    match tpm_encryption_alg {
        EncryptionAlgorithm::Rsa1024 => 1024,
        EncryptionAlgorithm::Rsa2048 => 2048,
        EncryptionAlgorithm::Rsa3072 => 3072,
        EncryptionAlgorithm::Rsa4096 => 4096,
        EncryptionAlgorithm::Ecc192 => 192,
        EncryptionAlgorithm::Ecc224 => 224,
        EncryptionAlgorithm::Ecc256 => 256,
        EncryptionAlgorithm::Ecc384 => 384,
        EncryptionAlgorithm::Ecc521 => 521,
        EncryptionAlgorithm::EccSm2 => 256,
    }
}

impl From<EncryptionAlgorithm> for AsymmetricAlgorithm {
    fn from(enc_alg: EncryptionAlgorithm) -> Self {
        match enc_alg {
            EncryptionAlgorithm::Rsa1024 => AsymmetricAlgorithm::Rsa,
            EncryptionAlgorithm::Rsa2048 => AsymmetricAlgorithm::Rsa,
            EncryptionAlgorithm::Rsa3072 => AsymmetricAlgorithm::Rsa,
            EncryptionAlgorithm::Rsa4096 => AsymmetricAlgorithm::Rsa,
            EncryptionAlgorithm::Ecc192 => AsymmetricAlgorithm::Ecc,
            EncryptionAlgorithm::Ecc224 => AsymmetricAlgorithm::Ecc,
            EncryptionAlgorithm::Ecc256 => AsymmetricAlgorithm::Ecc,
            EncryptionAlgorithm::Ecc384 => AsymmetricAlgorithm::Ecc,
            EncryptionAlgorithm::Ecc521 => AsymmetricAlgorithm::Ecc,
            EncryptionAlgorithm::EccSm2 => AsymmetricAlgorithm::Ecc,
        }
    }
}

impl From<EncryptionAlgorithm> for AsymmetricAlgorithmSelection {
    fn from(enc_alg: EncryptionAlgorithm) -> Self {
        match enc_alg {
            EncryptionAlgorithm::Rsa1024 => {
                AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa1024)
            }
            EncryptionAlgorithm::Rsa2048 => {
                AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)
            }
            EncryptionAlgorithm::Rsa3072 => {
                AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa3072)
            }
            EncryptionAlgorithm::Rsa4096 => {
                AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa4096)
            }
            EncryptionAlgorithm::Ecc192 => {
                AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP192)
            }
            EncryptionAlgorithm::Ecc224 => {
                AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP224)
            }
            EncryptionAlgorithm::Ecc256 => {
                AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256)
            }
            EncryptionAlgorithm::Ecc384 => {
                AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384)
            }
            EncryptionAlgorithm::Ecc521 => {
                AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP521)
            }
            EncryptionAlgorithm::EccSm2 => {
                AsymmetricAlgorithmSelection::Ecc(EccCurve::Sm2P256)
            }
        }
    }
}

impl TryFrom<&str> for EncryptionAlgorithm {
    type Error = AlgorithmError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            /* Use default key size and curve if not explicitly specified */
            "rsa" => Ok(EncryptionAlgorithm::Rsa2048),
            "ecc" => Ok(EncryptionAlgorithm::Ecc256),
            "rsa1024" => Ok(EncryptionAlgorithm::Rsa1024),
            "rsa2048" => Ok(EncryptionAlgorithm::Rsa2048),
            "rsa3072" => Ok(EncryptionAlgorithm::Rsa3072),
            "rsa4096" => Ok(EncryptionAlgorithm::Rsa4096),
            "ecc192" => Ok(EncryptionAlgorithm::Ecc192),
            "ecc_nist_p192" => Ok(EncryptionAlgorithm::Ecc192),
            "ecc224" => Ok(EncryptionAlgorithm::Ecc224),
            "ecc_nist_p224" => Ok(EncryptionAlgorithm::Ecc224),
            "ecc256" => Ok(EncryptionAlgorithm::Ecc256),
            "ecc_nist_p256" => Ok(EncryptionAlgorithm::Ecc256),
            "ecc384" => Ok(EncryptionAlgorithm::Ecc384),
            "ecc_nist_p384" => Ok(EncryptionAlgorithm::Ecc384),
            "ecc521" => Ok(EncryptionAlgorithm::Ecc521),
            "ecc_nist_p521" => Ok(EncryptionAlgorithm::Ecc521),
            "ecc_sm2" => Ok(EncryptionAlgorithm::EccSm2),
            "ecc_sm2_p256" => Ok(EncryptionAlgorithm::EccSm2),
            _ => Err(AlgorithmError::UnsupportedEncryptionAlgorithm(
                value.into(),
            )),
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            EncryptionAlgorithm::Rsa1024 => "rsa1024",
            EncryptionAlgorithm::Rsa2048 => "rsa", /* for backwards compatibility */
            EncryptionAlgorithm::Rsa3072 => "rsa3072",
            EncryptionAlgorithm::Rsa4096 => "rsa4096",
            EncryptionAlgorithm::Ecc192 => "ecc192",
            EncryptionAlgorithm::Ecc224 => "ecc224",
            EncryptionAlgorithm::Ecc256 => "ecc", /* for backwards compatibility */
            EncryptionAlgorithm::Ecc384 => "ecc384",
            EncryptionAlgorithm::Ecc521 => "ecc521",
            EncryptionAlgorithm::EccSm2 => "ecc_sm2",
        };
        write!(f, "{value}")
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignAlgorithm {
    RsaSsa,
    RsaPss,
    EcDsa,
    //    EcDaa, // Requires special SignatureScheme construction that is not yet implemented
    EcSchnorr,
}

impl SignAlgorithm {
    pub fn to_signature_scheme(
        self,
        hash_alg: HashAlgorithm,
    ) -> SignatureScheme {
        let hash_scheme = HashScheme::new(hash_alg.into());
        match self {
            SignAlgorithm::RsaSsa => SignatureScheme::RsaSsa { hash_scheme },
            SignAlgorithm::RsaPss => SignatureScheme::RsaPss { hash_scheme },
            SignAlgorithm::EcDsa => SignatureScheme::EcDsa { hash_scheme },
            //            SignAlgorithm::EcDaa => SignatureScheme::EcDaa{/*TODO*/},
            SignAlgorithm::EcSchnorr => {
                SignatureScheme::EcSchnorr { hash_scheme }
            }
        }
    }
}

impl From<SignAlgorithm> for SignatureSchemeAlgorithm {
    fn from(sign_alg: SignAlgorithm) -> Self {
        match sign_alg {
            SignAlgorithm::RsaSsa => SignatureSchemeAlgorithm::RsaSsa,
            SignAlgorithm::RsaPss => SignatureSchemeAlgorithm::RsaPss,
            SignAlgorithm::EcDsa => SignatureSchemeAlgorithm::EcDsa,
            //            SignAlgorithm::ECDAA => SignatureSchemeAlgorithm::EcDaa,
            SignAlgorithm::EcSchnorr => SignatureSchemeAlgorithm::EcSchnorr,
        }
    }
}

impl TryFrom<&str> for SignAlgorithm {
    type Error = AlgorithmError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "rsassa" => Ok(SignAlgorithm::RsaSsa),
            "rsapss" => Ok(SignAlgorithm::RsaPss),
            "ecdsa" => Ok(SignAlgorithm::EcDsa),
            //            "ecdaa" => Ok(SignAlgorithm::EcDaa),
            "ecschnorr" => Ok(SignAlgorithm::EcSchnorr),
            _ => {
                Err(AlgorithmError::UnsupportedSigningAlgorithm(value.into()))
            }
        }
    }
}

impl fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            SignAlgorithm::RsaSsa => "rsassa",
            SignAlgorithm::RsaPss => "rsapss",
            SignAlgorithm::EcDsa => "ecdsa",
            //           SignAlgorithm::ECDAA => "ecdaa",
            SignAlgorithm::EcSchnorr => "ecschnorr",
        };
        write!(f, "{value}")
    }
}

pub fn get_ecc_curve_key_size(curve_id: EccCurve) -> u16 {
    match curve_id {
        EccCurve::NistP192 => 192,
        EccCurve::NistP224 => 224,
        EccCurve::NistP256 => 256,
        EccCurve::NistP384 => 384,
        EccCurve::NistP521 => 521,
        EccCurve::BnP256 => 256,
        EccCurve::BnP638 => 638,
        EccCurve::Sm2P256 => 256,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hash_tryfrom() {
        let result = HashAlgorithm::try_from("sha1");
        assert!(result.is_ok());
        let result = HashAlgorithm::try_from("sha256");
        assert!(result.is_ok());
        let result = HashAlgorithm::try_from("sha384");
        assert!(result.is_ok());
        let result = HashAlgorithm::try_from("sha512");
        assert!(result.is_ok());
        let result = HashAlgorithm::try_from("sm3_256");
        assert!(result.is_ok());
    }
    #[test]
    fn test_unsupported_hash_tryfrom() {
        let result = HashAlgorithm::try_from("unsupported");
        assert!(result.is_err());
    }
    #[test]
    fn test_encrypt_try_from() {
        let result = EncryptionAlgorithm::try_from("rsa");
        assert!(result.is_ok_and(|r| r == EncryptionAlgorithm::Rsa2048));
        let result = EncryptionAlgorithm::try_from("ecc");
        assert!(result.is_ok_and(|r| r == EncryptionAlgorithm::Ecc256));
        let result = EncryptionAlgorithm::try_from("rsa4096");
        assert!(result.is_ok_and(|r| r == EncryptionAlgorithm::Rsa4096));
        let result = EncryptionAlgorithm::try_from("ecc256");
        assert!(result.is_ok_and(|r| r == EncryptionAlgorithm::Ecc256));
    }
    #[test]
    fn test_unsupported_encrypt_try_from() {
        let result = EncryptionAlgorithm::try_from("unsupported");
        assert!(result.is_err());
    }
    #[test]
    fn test_sign_tryfrom() {
        let result = SignAlgorithm::try_from("rsassa");
        assert!(result.is_ok());
        let result = SignAlgorithm::try_from("rsapss");
        assert!(result.is_ok());
        let result = SignAlgorithm::try_from("ecdsa");
        assert!(result.is_ok());
        let result = SignAlgorithm::try_from("ecschnorr");
        assert!(result.is_ok());
    }
    #[test]
    fn test_unsupported_sign_tryfrom() {
        let result = SignAlgorithm::try_from("unsupported");
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_to_hashing_algorithm() {
        let cases = [
            (HashAlgorithm::Sha1, HashingAlgorithm::Sha1),
            (HashAlgorithm::Sha256, HashingAlgorithm::Sha256),
            (HashAlgorithm::Sha384, HashingAlgorithm::Sha384),
            (HashAlgorithm::Sha512, HashingAlgorithm::Sha512),
            (HashAlgorithm::Sm3_256, HashingAlgorithm::Sm3_256),
        ];

        for (input, output) in cases {
            let alg = hash_to_hashing_algorithm(input);
            assert_eq!(alg, output);
        }
    }

    #[test]
    fn test_get_key_class() {
        let algorithms = [
            (EncryptionAlgorithm::Rsa1024, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Rsa2048, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Rsa3072, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Rsa4096, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Ecc192, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Ecc224, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Ecc256, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Ecc384, KeyClass::Asymmetric),
            (EncryptionAlgorithm::Ecc521, KeyClass::Asymmetric),
            (EncryptionAlgorithm::EccSm2, KeyClass::Asymmetric),
        ];
        for (alg, kclass) in algorithms {
            let key_class = get_key_class(&alg);
            assert_eq!(key_class, kclass, "Key class mismatch for {alg}");
        }
    } // test_get_key_class

    #[test]
    fn test_get_key_size() {
        let algorithms = [
            (EncryptionAlgorithm::Rsa1024, 1024),
            (EncryptionAlgorithm::Rsa2048, 2048),
            (EncryptionAlgorithm::Rsa3072, 3072),
            (EncryptionAlgorithm::Rsa4096, 4096),
            (EncryptionAlgorithm::Ecc192, 192),
            (EncryptionAlgorithm::Ecc224, 224),
            (EncryptionAlgorithm::Ecc256, 256),
            (EncryptionAlgorithm::Ecc384, 384),
            (EncryptionAlgorithm::Ecc521, 521),
            (EncryptionAlgorithm::EccSm2, 256),
        ];
        for (alg, expected_size) in algorithms {
            let key_size = get_key_size(&alg);
            assert_eq!(
                key_size, expected_size,
                "Key size mismatch for {alg}"
            );
        }
    } // test_get_key_size

    #[test]
    fn test_get_ecc_curve_key_size() {
        let curves = [
            (EccCurve::NistP192, 192),
            (EccCurve::NistP224, 224),
            (EccCurve::NistP256, 256),
            (EccCurve::NistP384, 384),
            (EccCurve::NistP521, 521),
            (EccCurve::BnP256, 256),
            (EccCurve::BnP638, 638),
            (EccCurve::Sm2P256, 256),
        ];
        for (curve_id, expected_size) in curves {
            let size = get_ecc_curve_key_size(curve_id);
            assert_eq!(size, expected_size);
        }
    } // test_get_ecc_curve_key_size

    #[test]
    fn test_key_class_display() {
        let algorithms = [
            (KeyClass::Asymmetric, "asymmetric"),
            (KeyClass::Symmetric, "symmetric"),
        ];
        for (kclass, expected) in algorithms {
            assert_eq!(kclass.to_string(), expected);
        }
    } // test_key_class_display

    #[test]
    fn test_unsupported_encryption_tryfrom() {
        let result = EncryptionAlgorithm::try_from("invalid-rsa-type");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AlgorithmError::UnsupportedEncryptionAlgorithm(_)
        ));
    } // test_unsupported_encryption_tryfrom

    #[test]
    fn test_unsupported_signing_tryfrom() {
        let result = SignAlgorithm::try_from("invalid-signing-scheme");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AlgorithmError::UnsupportedSigningAlgorithm(_)
        ));
    } // test_unsupported_signing_tryfrom
}
