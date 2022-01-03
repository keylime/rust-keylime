// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use thiserror::Error;
use tss_esapi::{
    interface_types::algorithm::{
        AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
    },
    structures::{HashScheme, SignatureScheme},
    tss2_esys::TPMT_SIG_SCHEME,
};

// This error needs to be public because we implement TryFrom for public types
#[derive(Error, Debug)]
pub enum AlgorithmError {
    #[error("{0}")]
    Hash(String),
    #[error("{0}")]
    Encrypt(String),
    #[error("{0}")]
    Sign(String),
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
            _ => Err(AlgorithmError::Hash(format!(
                "Hash algorithm {} is not supported by Keylime",
                value
            ))),
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
        write!(f, "{}", value)
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Rsa,
    Ecc,
}

impl From<EncryptionAlgorithm> for AsymmetricAlgorithm {
    fn from(enc_alg: EncryptionAlgorithm) -> Self {
        match enc_alg {
            EncryptionAlgorithm::Rsa => AsymmetricAlgorithm::Rsa,
            EncryptionAlgorithm::Ecc => AsymmetricAlgorithm::Ecc,
        }
    }
}

impl TryFrom<&str> for EncryptionAlgorithm {
    type Error = AlgorithmError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "rsa" => Ok(EncryptionAlgorithm::Rsa),
            "ecc" => Ok(EncryptionAlgorithm::Ecc),
            _ => Err(AlgorithmError::Encrypt(format!(
                "Encryption alogorithm {} not supported by Keylime",
                value
            ))),
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            EncryptionAlgorithm::Rsa => "rsa",
            EncryptionAlgorithm::Ecc => "ecc",
        };
        write!(f, "{}", value)
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
            _ => Err(AlgorithmError::Sign(format!(
                "Signing algorithm {} not supported by Keylime",
                value
            ))),
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
        write!(f, "{}", value)
    }
}
