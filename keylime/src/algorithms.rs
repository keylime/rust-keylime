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
}
