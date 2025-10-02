// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

pub mod auth_tag;
pub mod encrypted_data;
pub mod symmkey;
pub mod x509;

use base64::{engine::general_purpose, Engine as _};
use log::*;
use openssl::{
    ec::{EcGroupRef, EcKey},
    encrypt::Decrypter,
    hash::MessageDigest,
    memcmp,
    nid::Nid,
    pkcs5,
    pkey::{Id, PKey, PKeyRef, Private, Public},
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode},
    symm::Cipher,
    x509::store::X509StoreBuilder,
    x509::X509,
};
use picky_asn1_x509::SubjectPublicKeyInfo;
use std::{
    fs::{read_to_string, set_permissions, Permissions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    string::{FromUtf8Error, String},
};
use thiserror::Error;

use crate::algorithms::EncryptionAlgorithm;

pub const AES_128_KEY_LEN: usize = 16;
pub const AES_256_KEY_LEN: usize = 32;
pub const AES_BLOCK_SIZE: usize = 16;
pub const AUTH_TAG_LEN: usize = 48;

#[derive(Error, Debug)]
pub enum CryptoError {
    /// Error decoding base64
    #[error("failed to decode base64")]
    Base64DecodeError(#[from] base64::DecodeError),

    /// Error decrypting AES GCM encrypted data
    #[error("failed to decrypt AES GCM encrypted data")]
    DecryptAEADError(#[source] openssl::error::ErrorStack),

    /// Error obtaining generating EC private key
    #[error("failed to generate EC private key")]
    ECGeneratePrivateKeyError(#[source] openssl::error::ErrorStack),

    /// Error obtaining EC private key from structure
    #[error("failed to get EC private key from structure")]
    ECGetPrivateKeyError(#[source] openssl::error::ErrorStack),

    /// Error creating EcGroup from NID
    #[error("failed to create EcGroup from NID")]
    ECGroupFromNidError(#[source] openssl::error::ErrorStack),

    /// Error creating EcKey structure from public point
    #[error("failed to create EcKey structure from public point")]
    ECKeyFromPublicPointError(#[source] openssl::error::ErrorStack),

    /// File not found
    #[error("could not find file {0}")]
    FileNotFound(String),

    /// Error creating file
    #[error("failed to create file {file}")]
    FSCreateError {
        file: String,
        source: std::io::Error,
    },

    /// Error calculating hash
    #[error("failed to calculate hash")]
    HashError(#[source] openssl::error::ErrorStack),

    /// Error generating HMAC
    #[error("Failed generating HMAC: {message}")]
    HMACError {
        message: String,
        source: openssl::error::ErrorStack,
    },

    /// Infallible
    #[error("Infallible")]
    Infallible(#[source] std::convert::Infallible),

    /// Invalid HMAC
    #[error("invalid HMAC")]
    InvalidHMAC,

    /// Invalid input length
    #[error("Invalid input length {length}")]
    InvalidInputLength { length: usize },

    /// Invalid key length
    #[error("Invalid key length {length}")]
    InvalidKeyLength { length: usize },

    /// Read error
    #[error("failed to read")]
    IOReadError(#[source] std::io::Error),

    /// Write error
    #[error("failed to write")]
    IOWriteError(#[source] std::io::Error),

    /// Error setting file permission
    #[error("failed to set file permission")]
    IOSetPermissionError(#[source] std::io::Error),

    /// Error deriving key from password with PBKDF2
    #[error("failed to derive key from password with PBKDF2")]
    PBKDF2Error(#[source] openssl::error::ErrorStack),

    /// Error creating PKey structure from EcKey structure
    #[error("failed to create PKey structure from EcKey structure")]
    PKeyFromEcKeyError(#[source] openssl::error::ErrorStack),

    /// Error creating PKey structure from RSA structure
    #[error("failed to create PKey structure from RSA structure")]
    PKeyFromRSAError(#[source] openssl::error::ErrorStack),

    /// Error creating PKey structure for HMAC key
    #[error("failed to create PKey structure for HMAC key")]
    PKeyHMACNewError(#[source] openssl::error::ErrorStack),

    /// Error encoding PKey structure in PKCS#8 format
    #[error("failed to encode PKey structure in PKCS#8 format")]
    PKeyToPKCS8(#[source] openssl::error::ErrorStack),

    /// Error decoding private key from PEM
    #[error("failed to decode private key from PEM")]
    PrivateKeyFromPEMError(#[source] openssl::error::ErrorStack),

    /// Error decoding public key from DER
    #[error("failed to decode public key from DER")]
    PublicKeyFromDERError(#[source] openssl::error::ErrorStack),

    /// Error obtaining ECC public key from structure
    #[error("failed to get ECC public key from structure")]
    PublicKeyGetECCError(#[source] openssl::error::ErrorStack),

    /// Error encoding public key in DER format
    #[error("failed to encode public key in DER format")]
    PublicKeyToDERError(#[source] openssl::error::ErrorStack),

    /// Error encoding public key in PEM format
    #[error("failed to encode public key in PEM format")]
    PublicKeyToPEMError(#[source] openssl::error::ErrorStack),

    /// Error composing RSA public key structure from public components
    #[error(
        "failed to compose RSA public key structure from public components"
    )]
    RSAFromComponents(#[source] openssl::error::ErrorStack),

    /// Error generating RSA key pair
    #[error("failed to generate RSA key pair")]
    RSAGenerateError(#[source] openssl::error::ErrorStack),

    /// Error obtaining RSA private key from structure
    #[error("failed to get RSA private key from structure")]
    RSAGetPrivateKeyError(#[source] openssl::error::ErrorStack),

    /// Error obtaining RSA public key from structure
    #[error("failed to get RSA public key from structure")]
    RSAGetPublicKeyError(#[source] openssl::error::ErrorStack),

    /// RSA OAEP decrypt error
    #[error("RSA OAEP decrypt error: {message}")]
    RSAOAEPDecryptError {
        message: String,
        source: openssl::error::ErrorStack,
    },

    /// Error signing data
    #[error("failed to sign data: {message}")]
    SignError {
        message: String,
        source: openssl::error::ErrorStack,
    },

    /// Error generating TLS context
    #[error("Failed to generate TLS context: {message}")]
    SSLContextBuilderError {
        message: String,
        source: openssl::error::ErrorStack,
    },

    /// Error getting String from UTF-8 Vec
    #[error("failed to create String from UTF-8 Vec")]
    StringFromVec(#[from] FromUtf8Error),

    /// Error converting ECC public key into TSS structure
    #[error("failed to convert ECC public key into TSS structure")]
    SubjectPublicKeyInfoFromECCError(#[source] tss_esapi::Error),

    /// Error converting RSA public key into TSS structure
    #[error("failed to convert RSA public key into TSS structure")]
    SubjectPublicKeyInfoFromRSAError(#[source] tss_esapi::Error),

    /// Error converting TSS Public structure into SubjectPublicKeyInfo
    #[error(
        "failed to convert TSS Public structure into SubjectPublicKeyInfo"
    )]
    SubjectPublicKeyInfoFromTSSPublicError(#[source] tss_esapi::Error),

    /// Error encoding SubjectPublicKeyInfo in DER format
    #[error("failed to encode SubjectPublicKeyInfo in DER format")]
    SubjectPublicKeyInfoToDERError(#[source] picky_asn1_der::Asn1DerError),

    /// Error taking object ownership
    #[error("failed to take object ownership")]
    ToOwnedError(#[source] openssl::error::ErrorStack),

    /// Unsupported key algorithm
    #[error("unsupported key algorithm: {id}")]
    UnsupportedKeyAlgorithm { id: String },

    /// Error verifying signature
    #[error("Signature verification failed: {message}")]
    VerifyError {
        message: String,
        source: openssl::error::ErrorStack,
    },

    /// Trusted X509 certificate store builder error
    #[error("Trusted certificate store builder error: {message}")]
    X509StoreBuilderError {
        message: String,
        source: openssl::error::ErrorStack,
    },

    /// Error loading X509 certificate chain from PEM file
    #[error("failed to load X509 certificate chain from PEM file")]
    X509ChainFromPEMError(#[source] openssl::error::ErrorStack),

    /// Error loading X509 certificate from DER file
    #[error("failed to load X509 certificate from DER file")]
    X509FromDERError(#[source] openssl::error::ErrorStack),

    /// Error loading X509 certificate from PEM file
    #[error("failed to load X509 certificate from PEM file")]
    X509FromPEMError(#[source] openssl::error::ErrorStack),

    /// Error obtaining certificate public key
    #[error("failed to get certificate public key")]
    X509GetPublicError(#[source] openssl::error::ErrorStack),

    /// Error encoding X509 certificate in DER format
    #[error("failed to encode X509 certificate in DER format")]
    X509ToDERError(#[source] openssl::error::ErrorStack),

    /// Error encoding X509 certificate in PEM format
    #[error("failed to encode X509 certificate in PEM format")]
    X509ToPEMError(#[source] openssl::error::ErrorStack),

    /// Unsupported key algorithm in X509 certificate
    #[error("unsupported key algorithm in X509 certificate: {id}")]
    X509UnsupportedKeyAlgorithm { id: String },
}

/// Load a X509 certificate in DER format from file
pub fn load_x509_der(input_cert_path: &Path) -> Result<X509, CryptoError> {
    let contents =
        std::fs::read(input_cert_path).map_err(CryptoError::IOReadError)?;

    X509::from_der(&contents).map_err(CryptoError::X509FromDERError)
}

/// Load X509 certificate in PEM format from file
pub fn load_x509_pem(input_cert_path: &Path) -> Result<X509, CryptoError> {
    let contents =
        std::fs::read(input_cert_path).map_err(CryptoError::IOReadError)?;

    X509::from_pem(&contents).map_err(CryptoError::X509FromPEMError)
}

/// Load a X509 certificate in PEM or DER format from a given path
pub fn load_x509(path: &Path) -> Result<X509, CryptoError> {
    if path.exists() {
        load_x509_der(path).or(load_x509_pem(path))
    } else {
        Err(CryptoError::FileNotFound(path.display().to_string()))
    }
}

/// Load X509 certificate chain in PEM format from file
fn load_x509_cert_chain(
    input_cert_path: &Path,
) -> Result<Vec<X509>, CryptoError> {
    let contents =
        read_to_string(input_cert_path).map_err(CryptoError::IOReadError)?;

    X509::stack_from_pem(contents.as_bytes())
        .map_err(CryptoError::X509ChainFromPEMError)
}

/// Load X509 certificate chains in PEM format from a list of files
pub fn load_x509_cert_list(
    input_cert_list: Vec<&Path>,
) -> Result<Vec<X509>, CryptoError> {
    let mut loaded = Vec::<X509>::new();

    // This is necessary to avoid choking on failures loading certs from a file
    for cert in input_cert_list {
        match load_x509_cert_chain(cert) {
            Ok(mut s) => {
                loaded.append(&mut s);
            }
            Err(e) => {
                warn!("Could not load certs from {}: {}", cert.display(), e);
            }
        }
    }
    Ok(loaded)
}

/// Write a X509 certificate to a file in PEM format
pub fn write_x509(cert: &X509, file_path: &Path) -> Result<(), CryptoError> {
    let mut file = std::fs::File::create(file_path).map_err(|source| {
        CryptoError::FSCreateError {
            file: file_path.display().to_string(),
            source,
        }
    })?;
    _ = file
        .write(&cert.to_pem().map_err(CryptoError::X509ToPEMError)?)
        .map_err(CryptoError::IOWriteError)?;
    Ok(())
}

/// Get the X509 certificate public key
pub fn x509_get_pubkey(cert: &X509) -> Result<PKey<Public>, CryptoError> {
    cert.public_key().map_err(CryptoError::X509GetPublicError)
}

/// Encode the X509 certificate in PEM format
///
/// The certificate is returned as a String
pub fn x509_to_pem(cert: &X509) -> Result<String, CryptoError> {
    String::from_utf8(cert.to_pem().map_err(CryptoError::X509ToPEMError)?)
        .map_err(CryptoError::StringFromVec)
}

/// Encode the X509 certificate in DER format
///
/// The certificate is returned as a Vec<u8>
pub fn x509_to_der(cert: &X509) -> Result<Vec<u8>, CryptoError> {
    cert.to_der().map_err(CryptoError::X509ToDERError)
}

/// Encode a TSS Public key in PEM format
///
/// The public key is returned as a Vec<u8>
pub fn tss_pubkey_to_pem(
    pubkey: tss_esapi::structures::Public,
) -> Result<Vec<u8>, CryptoError> {
    // Converting Public TSS key to PEM
    let key = SubjectPublicKeyInfo::try_from(pubkey)
        .map_err(CryptoError::SubjectPublicKeyInfoFromTSSPublicError)?;
    let key_der = picky_asn1_der::to_vec(&key)
        .map_err(CryptoError::SubjectPublicKeyInfoToDERError)?;
    let openssl_key = PKey::public_key_from_der(&key_der)
        .map_err(CryptoError::PublicKeyFromDERError)?;
    let pem = openssl_key
        .public_key_to_pem()
        .map_err(CryptoError::PublicKeyToPEMError)?;

    Ok(pem)
}

/// Calculate the hash of the input data using the given Message Digest algorithm
pub fn hash(
    data: &[u8],
    algorithm: MessageDigest,
) -> Result<Vec<u8>, CryptoError> {
    Ok(openssl::hash::hash(algorithm, data)
        .map_err(CryptoError::HashError)?
        .to_vec())
}

/// Check an x509 certificate contains a specific public key
pub fn check_x509_key(
    cert: &X509,
    tpm_key: &tss_esapi::structures::Public,
) -> Result<bool, CryptoError> {
    // Id:RSA_PSS only added in rust-openssl from v0.10.59; remove this let and use Id::RSA_PSS after update
    // Id taken from https://boringssl.googlesource.com/boringssl/+/refs/heads/master/include/openssl/nid.h#4039
    let id_rsa_pss: Id = Id::from_raw(912);
    match cert
        .public_key()
        .map_err(CryptoError::X509GetPublicError)?
        .id()
    {
        Id::RSA => {
            let cert_n = cert
                .public_key()
                .map_err(CryptoError::X509GetPublicError)?
                .rsa()
                .map_err(CryptoError::RSAGetPublicKeyError)?
                .n()
                .to_vec();
            let mut cert_n_str = format!("{cert_n:?}");
            _ = cert_n_str.pop();
            _ = cert_n_str.remove(0);
            let key = SubjectPublicKeyInfo::try_from(tpm_key.clone())
                .map_err(CryptoError::SubjectPublicKeyInfoFromRSAError)?;
            let key_der = picky_asn1_der::to_vec(&key)
                .map_err(CryptoError::SubjectPublicKeyInfoToDERError)?;
            let key_der_str = format!("{key_der:?}");

            Ok(key_der_str.contains(&cert_n_str))
        }
        cert_id if cert_id == id_rsa_pss => {
            let cert_n = cert
                .public_key()
                .map_err(CryptoError::X509GetPublicError)?
                .rsa()
                .map_err(CryptoError::RSAGetPublicKeyError)?
                .n()
                .to_vec();
            let mut cert_n_str = format!("{cert_n:?}");
            _ = cert_n_str.pop();
            _ = cert_n_str.remove(0);
            let key = SubjectPublicKeyInfo::try_from(tpm_key.clone())
                .map_err(CryptoError::SubjectPublicKeyInfoFromRSAError)?;
            let key_der = picky_asn1_der::to_vec(&key)
                .map_err(CryptoError::SubjectPublicKeyInfoToDERError)?;
            let key_der_str = format!("{key_der:?}");

            Ok(key_der_str.contains(&cert_n_str))
        }
        Id::EC => {
            let cert_n = cert
                .public_key()
                .map_err(CryptoError::X509GetPublicError)?
                .ec_key()
                .map_err(CryptoError::PublicKeyGetECCError)?
                .public_key_to_der()
                .map_err(CryptoError::PublicKeyToDERError)?;
            let mut cert_n_str = format!("{cert_n:?}");
            _ = cert_n_str.pop();
            _ = cert_n_str.remove(0);
            let key = SubjectPublicKeyInfo::try_from(tpm_key.clone())
                .map_err(CryptoError::SubjectPublicKeyInfoFromECCError)?;
            let key_der = picky_asn1_der::to_vec(&key)
                .map_err(CryptoError::SubjectPublicKeyInfoToDERError)?;
            let key_der_str = format!("{key_der:?}");

            Ok(key_der_str.contains(&cert_n_str))
        }
        id => Err(CryptoError::X509UnsupportedKeyAlgorithm {
            id: format!("{id:?}"),
        }),
    }
}

/// Detect a template from a certificate
/// Templates defined in: TPM 2.0 Keys for Device Identity and Attestation at https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
pub fn match_cert_to_template(cert: &X509) -> Result<String, CryptoError> {
    // Id:RSA_PSS only added in rust-openssl from v0.10.59; remove this let and use Id::RSA_PSS after update
    // Id taken from https://boringssl.googlesource.com/boringssl/+/refs/heads/master/include/openssl/nid.h#4039
    let id_rsa_pss: Id = Id::from_raw(912);
    match cert
        .public_key()
        .map_err(CryptoError::X509GetPublicError)?
        .id()
    {
        Id::RSA => match cert
            .public_key()
            .map_err(CryptoError::X509GetPublicError)?
            .bits()
        {
            2048 => Ok("H-1".to_string()),
            _ => Ok("".to_string()),
        },
        cert_id if cert_id == id_rsa_pss => match cert
            .public_key()
            .map_err(CryptoError::X509GetPublicError)?
            .bits()
        {
            2048 => Ok("H-1".to_string()),
            _ => Ok("".to_string()),
        },
        Id::EC => match cert
            .public_key()
            .map_err(CryptoError::X509GetPublicError)?
            .bits()
        {
            256 => match cert
                .public_key()
                .map_err(CryptoError::X509GetPublicError)?
                .ec_key()
                .map_err(CryptoError::PublicKeyGetECCError)?
                .group()
                .curve_name()
            {
                Some(Nid::SECP256K1) => Ok("H-2".to_string()),
                _ => Ok("H-5".to_string()),
            },
            384 => Ok("H-3".to_string()),
            521 => Ok("H-4".to_string()),
            _ => Ok("".to_string()),
        },
        id => Err(CryptoError::X509UnsupportedKeyAlgorithm {
            id: format!("{id:?}"),
        }),
    }
}

/// Read a PEM file and returns the public and private keys
pub fn load_key_pair(
    key_path: &Path,
    key_password: Option<&str>,
) -> Result<(PKey<Public>, PKey<Private>), CryptoError> {
    let pem = std::fs::read(key_path).map_err(CryptoError::IOReadError)?;
    let private = match key_password {
        Some(pw) => {
            if pw.is_empty() {
                PKey::private_key_from_pem(&pem)
                    .map_err(CryptoError::PrivateKeyFromPEMError)?
            } else {
                PKey::private_key_from_pem_passphrase(&pem, pw.as_bytes())
                    .map_err(CryptoError::PrivateKeyFromPEMError)?
            }
        }
        None => PKey::private_key_from_pem(&pem)
            .map_err(CryptoError::PrivateKeyFromPEMError)?,
    };
    let public = pkey_pub_from_priv(&private)?;
    Ok((public, private))
}

/// Write a private key to a file.
///
/// If a passphrase is provided, the key will be stored encrypted using AES-256-CBC
pub fn write_key_pair(
    key: &PKey<Private>,
    file_path: &Path,
    passphrase: Option<&str>,
) -> Result<(), CryptoError> {
    // Write the generated key to the file
    let mut file = std::fs::File::create(file_path).map_err(|source| {
        CryptoError::FSCreateError {
            file: file_path.display().to_string(),
            source,
        }
    })?;
    match passphrase {
        Some(pw) => {
            if pw.is_empty() {
                _ = file
                    .write(
                        &key.private_key_to_pem_pkcs8()
                            .map_err(CryptoError::PKeyToPKCS8)?,
                    )
                    .map_err(CryptoError::IOWriteError)?;
            } else {
                _ = file
                    .write(
                        &key.private_key_to_pem_pkcs8_passphrase(
                            openssl::symm::Cipher::aes_256_cbc(),
                            pw.as_bytes(),
                        )
                        .map_err(CryptoError::PKeyToPKCS8)?,
                    )
                    .map_err(CryptoError::IOWriteError)?;
            }
        }
        None => {
            _ = file
                .write(
                    &key.private_key_to_pem_pkcs8()
                        .map_err(CryptoError::PKeyToPKCS8)?,
                )
                .map_err(CryptoError::IOWriteError)?;
        }
    }
    set_permissions(file_path, Permissions::from_mode(0o600))
        .map_err(CryptoError::IOSetPermissionError)?;
    Ok(())
}

/// Load an existing key pair from a file or generate a new one if it doesn't exist
///
/// This function implements the load-or-generate pattern for asymmetric keys:
/// - If the file exists, it loads the key and optionally validates the algorithm
/// - If the file doesn't exist, it generates a new key with the specified algorithm and saves it
///
/// # Arguments
///
/// * `path` - Path to the key file
/// * `password` - Optional password to encrypt/decrypt the key
/// * `algorithm` - The encryption algorithm to use (e.g., RSA 2048, ECC 256)
/// * `validate_algorithm` - Whether to validate that a loaded key matches the specified algorithm
///
/// # Returns
///
/// A tuple containing the public and private keys
///
/// # Errors
///
/// Returns an error if:
/// - The file exists but cannot be loaded
/// - The file exists and validation is enabled, but the key doesn't match the algorithm
/// - A new key cannot be generated or saved
pub fn load_or_generate_key(
    path: &Path,
    password: Option<&str>,
    algorithm: EncryptionAlgorithm,
    validate_algorithm: bool,
) -> Result<(PKey<Public>, PKey<Private>), CryptoError> {
    use openssl::ec::EcGroup;

    if path.exists() {
        // Load existing key
        let (public, private) = load_key_pair(path, password)?;

        // Validate algorithm if requested
        if validate_algorithm {
            validate_key_algorithm(&private, algorithm)?;
        }

        Ok((public, private))
    } else {
        // Generate new key with the specified algorithm
        let (public, private) = match algorithm {
            EncryptionAlgorithm::Rsa1024 => rsa_generate_pair(1024)?,
            EncryptionAlgorithm::Rsa2048 => rsa_generate_pair(2048)?,
            EncryptionAlgorithm::Rsa3072 => rsa_generate_pair(3072)?,
            EncryptionAlgorithm::Rsa4096 => rsa_generate_pair(4096)?,
            EncryptionAlgorithm::Ecc192 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME192V1)
                    .map_err(CryptoError::ECGroupFromNidError)?;
                ecc_generate_pair(&group)?
            }
            EncryptionAlgorithm::Ecc224 => {
                let group = EcGroup::from_curve_name(Nid::SECP224R1)
                    .map_err(CryptoError::ECGroupFromNidError)?;
                ecc_generate_pair(&group)?
            }
            EncryptionAlgorithm::Ecc256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                    .map_err(CryptoError::ECGroupFromNidError)?;
                ecc_generate_pair(&group)?
            }
            EncryptionAlgorithm::Ecc384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1)
                    .map_err(CryptoError::ECGroupFromNidError)?;
                ecc_generate_pair(&group)?
            }
            EncryptionAlgorithm::Ecc521 => {
                let group = EcGroup::from_curve_name(Nid::SECP521R1)
                    .map_err(CryptoError::ECGroupFromNidError)?;
                ecc_generate_pair(&group)?
            }
            EncryptionAlgorithm::EccSm2 => {
                let group = EcGroup::from_curve_name(Nid::SM2)
                    .map_err(CryptoError::ECGroupFromNidError)?;
                ecc_generate_pair(&group)?
            }
        };

        // Save the key to the file
        write_key_pair(&private, path, password)?;

        Ok((public, private))
    }
}

fn rsa_generate(key_size: u32) -> Result<PKey<Private>, CryptoError> {
    PKey::from_rsa(
        Rsa::generate(key_size).map_err(CryptoError::RSAGenerateError)?,
    )
    .map_err(CryptoError::PKeyFromRSAError)
}

/// Generate RSA key pair with the given size
///
/// Returns a tuple containing the PKey<Public> and PKey<Private>
pub fn rsa_generate_pair(
    key_size: u32,
) -> Result<(PKey<Public>, PKey<Private>), CryptoError> {
    let private = rsa_generate(key_size)?;
    let public = pkey_pub_from_priv(&private)?;

    Ok((public, private))
}

/// Validate that a private key matches the specified encryption algorithm
///
/// Returns Ok(()) if the key matches the algorithm, otherwise returns an error
pub fn validate_key_algorithm(
    key: &PKey<Private>,
    algorithm: EncryptionAlgorithm,
) -> Result<(), CryptoError> {
    use crate::algorithms::{get_key_class, get_key_size, KeyClass};

    // Determine the expected key class and ID
    let key_class = get_key_class(&algorithm);
    let expected_key_id = match key_class {
        KeyClass::Asymmetric => match algorithm {
            EncryptionAlgorithm::Rsa1024
            | EncryptionAlgorithm::Rsa2048
            | EncryptionAlgorithm::Rsa3072
            | EncryptionAlgorithm::Rsa4096 => Id::RSA,
            EncryptionAlgorithm::Ecc192
            | EncryptionAlgorithm::Ecc224
            | EncryptionAlgorithm::Ecc256
            | EncryptionAlgorithm::Ecc384
            | EncryptionAlgorithm::Ecc521
            | EncryptionAlgorithm::EccSm2 => Id::EC,
        },
        KeyClass::Symmetric => {
            return Err(CryptoError::UnsupportedKeyAlgorithm {
                id: "Symmetric algorithms not supported for key validation"
                    .to_string(),
            });
        }
    };

    // Check if the key algorithm matches
    if key.id() != expected_key_id {
        return Err(CryptoError::UnsupportedKeyAlgorithm {
            id: format!("{:?}", key.id()),
        });
    }

    // Check if the key size matches
    let key_bits = key.bits();
    let expected_bits = get_key_size(&algorithm);
    if key_bits as usize != expected_bits {
        return Err(CryptoError::InvalidKeyLength {
            length: key_bits as usize,
        });
    }

    Ok(())
}

/// Generate a ECC key pair on given group
///
/// Returns a tuple containing the PKey<Public> and PKey<Private>
pub fn ecc_generate_pair(
    group: &EcGroupRef,
) -> Result<(PKey<Public>, PKey<Private>), CryptoError> {
    let private = PKey::from_ec_key(
        EcKey::generate(group)
            .map_err(CryptoError::ECGeneratePrivateKeyError)?,
    )
    .map_err(CryptoError::PKeyFromEcKeyError)?;
    let public = pkey_pub_from_priv(&private)?;

    Ok((public, private))
}

fn pkey_pub_from_priv(
    privkey: &PKey<Private>,
) -> Result<PKey<Public>, CryptoError> {
    match privkey.id() {
        Id::RSA => {
            let rsa = Rsa::from_public_components(
                privkey
                    .rsa()
                    .map_err(CryptoError::RSAGetPrivateKeyError)?
                    .n()
                    .to_owned()
                    .map_err(CryptoError::ToOwnedError)?,
                privkey
                    .rsa()
                    .map_err(CryptoError::RSAGetPrivateKeyError)?
                    .e()
                    .to_owned()
                    .map_err(CryptoError::ToOwnedError)?,
            )
            .map_err(CryptoError::RSAFromComponents)?;
            PKey::from_rsa(rsa).map_err(CryptoError::PKeyFromRSAError)
        }
        Id::EC => {
            let ec_key = privkey
                .ec_key()
                .map_err(CryptoError::ECGetPrivateKeyError)?;

            let pubkey =
                EcKey::from_public_key(ec_key.group(), ec_key.public_key())
                    .map_err(CryptoError::ECKeyFromPublicPointError)?;

            PKey::from_ec_key(pubkey).map_err(CryptoError::PKeyFromEcKeyError)
        }
        id => Err(CryptoError::UnsupportedKeyAlgorithm {
            id: format!("{id:?}"),
        }),
    }
}

pub fn pkey_pub_to_pem(pubkey: &PKey<Public>) -> Result<String, CryptoError> {
    pubkey
        .public_key_to_pem()
        .map_err(CryptoError::PublicKeyToPEMError)
        .and_then(|s| {
            String::from_utf8(s).map_err(CryptoError::StringFromVec)
        })
}

pub fn generate_tls_context(
    tls_cert: &X509,
    key: &PKey<Private>,
    ca_certs: Vec<X509>,
) -> Result<SslAcceptorBuilder, CryptoError> {
    let mut ssl_context_builder = SslAcceptor::mozilla_intermediate_v5(
        SslMethod::tls(),
    )
    .map_err(|source| CryptoError::SSLContextBuilderError {
        message: "failed to create Context Builder object".into(),
        source,
    })?;
    ssl_context_builder
        .set_certificate(tls_cert)
        .map_err(|source| CryptoError::SSLContextBuilderError {
            message: "failed to set SSL server certificate".into(),
            source,
        })?;
    ssl_context_builder.set_private_key(key).map_err(|source| {
        CryptoError::SSLContextBuilderError {
            message: "failed to set SSL server private key".into(),
            source,
        }
    })?;

    // Build verification cert store.
    let mut mtls_store_builder =
        X509StoreBuilder::new().map_err(|source| {
            CryptoError::X509StoreBuilderError {
                message:
                    "failed to create X509 certificate store builder object"
                        .into(),
                source,
            }
        })?;
    for cert in ca_certs {
        mtls_store_builder
            .add_cert(cert)
            .map_err(|source| CryptoError::X509StoreBuilderError{
                message: "failed to add certificate to X509 trusted certificate store".into(),
                    source,
            })?;
    }

    let mtls_store = mtls_store_builder.build();
    ssl_context_builder
        .set_verify_cert_store(mtls_store)
        .map_err(|source| CryptoError::SSLContextBuilderError {
            message: "failed to set SSL server trusted certificate store"
                .into(),
            source,
        })?;

    // Enable mutual TLS verification
    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.set(SslVerifyMode::PEER, true);
    verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
    ssl_context_builder.set_verify(verify_mode);

    Ok(ssl_context_builder)
}

/*
 * Inputs: password to derive key
 *         shared salt
 * Output: derived key
 *
 * Take in a password and shared salt, and derive a key based on the
 * PBKDF2-HMAC key derivation function. Parameters match that of
 * Python-Keylime.
 *
 * NOTE: This uses SHA-1 as the KDF's hash function in order to match the
 * implementation of PBKDF2 in the Python version of Keylime. PyCryptodome's
 * PBKDF2 function defaults to SHA-1 unless otherwise specified, and
 * Python-Keylime uses this default.
 */
pub fn pbkdf2(
    input_password: String,
    input_salt: String,
) -> Result<String, CryptoError> {
    let password = input_password.as_bytes();
    let salt = input_salt.as_bytes();
    let count = 2000;
    // PyCryptodome's PBKDF2 binding allows key length to be specified
    // explicitly as a parameter; here, key length is implicitly defined in
    // the length of the 'key' variable.
    let mut key = [0; 32];
    pkcs5::pbkdf2_hmac(
        password,
        salt,
        count,
        MessageDigest::sha1(),
        &mut key,
    )
    .map_err(CryptoError::PBKDF2Error)?;
    Ok(hex::encode(&key[..]))
}

/*
 * Input: Trusted public key, and remote message and signature
 * Output: true if they are verified, otherwise false
 *
 * Verify a remote message and signature against a local rsa cert
 */
pub fn asym_verify(
    keypair: &PKeyRef<Public>,
    message: &str,
    signature: &str,
) -> Result<bool, CryptoError> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), keypair)
        .map_err(|source| CryptoError::VerifyError {
            message: "failed to create signature verifier object".into(),
            source,
        })?;
    verifier
        .set_rsa_padding(Padding::PKCS1_PSS)
        .map_err(|source| CryptoError::VerifyError {
            message: "failed to set signature verifier padding algorithm"
                .into(),
            source,
        })?;
    verifier
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|source| CryptoError::VerifyError {
            message:
                "failed to set signature verifier Message Digest algorithm"
                    .into(),
            source,
        })?;
    verifier
        .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::MAXIMUM_LENGTH)
        .map_err(|source| CryptoError::VerifyError {
            message: "failed to set signature verifier RSA PSS salt length"
                .into(),
            source,
        })?;
    verifier.update(message.as_bytes()).map_err(|source| {
        CryptoError::VerifyError {
            message: "failed adding input data to signature verifier".into(),
            source,
        }
    })?;
    verifier
        .verify(
            &general_purpose::STANDARD
                .decode(signature.as_bytes())
                .map_err(CryptoError::Base64DecodeError)?,
        )
        .map_err(|source| CryptoError::VerifyError {
            message: "invalid signature".into(),
            source,
        })
}

/*
 * Inputs: OpenSSL RSA key
 *         ciphertext to be decrypted
 * Output: decrypted plaintext
 *
 * Take in an RSA-encrypted ciphertext and an RSA private key and decrypt the
 * ciphertext based on PKCS1 OAEP.
 */
pub fn rsa_oaep_decrypt(
    priv_key: &PKey<Private>,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut decrypter = Decrypter::new(priv_key).map_err(|source| {
        CryptoError::RSAOAEPDecryptError {
            message: "failed to create RSA decrypter object".into(),
            source,
        }
    })?;

    decrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|source| CryptoError::RSAOAEPDecryptError {
            message: "failed to set RSA decrypter padding".into(),
            source,
        })?;
    decrypter
        .set_rsa_mgf1_md(MessageDigest::sha1())
        .map_err(|source| CryptoError::RSAOAEPDecryptError {
            message: "failed to set RSA decrypter Message Digest algorithm"
                .into(),
            source,
        })?;
    decrypter
        .set_rsa_oaep_md(MessageDigest::sha1())
        .map_err(|source| CryptoError::RSAOAEPDecryptError {
            message:
                "failed to set RSA decrypter OAEP Message Digest algorithm"
                    .into(),
            source,
        })?;

    // Create an output buffer
    let buffer_len = decrypter.decrypt_len(data).map_err(|source| {
        CryptoError::RSAOAEPDecryptError {
            message: "failed to get RSA decrypter output length".into(),
            source,
        }
    })?;
    let mut decrypted = vec![0; buffer_len];

    // Decrypt and truncate the buffer
    let decrypted_len =
        decrypter.decrypt(data, &mut decrypted).map_err(|source| {
            CryptoError::RSAOAEPDecryptError {
                message: "failed to decrypt data with RSA OAEP".into(),
                source,
            }
        })?;
    decrypted.truncate(decrypted_len);

    Ok(decrypted)
}

/*
 * Inputs: secret key
 *        message to sign
 * Output: signed HMAC result
 *
 * Sign message and return HMAC result string
 */
pub fn compute_hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pkey = PKey::hmac(key).map_err(CryptoError::PKeyHMACNewError)?;
    // SHA-384 is used as the underlying hash algorithm.
    //
    // Reference:
    // https://keylime-docs.readthedocs.io/en/latest/rest_apis.html#post--v1.0-keys-ukey
    // https://github.com/keylime/keylime/blob/910b38b296038b187a020c095dc747e9c46cbef3/keylime/crypto.py#L151
    let mut signer =
        Signer::new(MessageDigest::sha384(), &pkey).map_err(|source| {
            CryptoError::SignError {
                message: "failed creating Signer object".into(),
                source,
            }
        })?;
    signer
        .update(data)
        .map_err(|source| CryptoError::SignError {
            message: "failed to add input data to Signer".into(),
            source,
        })?;
    signer
        .sign_to_vec()
        .map_err(|source| CryptoError::SignError {
            message: "failed to generate signature".into(),
            source,
        })
}

pub fn verify_hmac(
    key: &[u8],
    data: &[u8],
    hmac: &[u8],
) -> Result<(), CryptoError> {
    let pkey = PKey::hmac(key).map_err(CryptoError::PKeyHMACNewError)?;
    // SHA-384 is used as the underlying hash algorithm.
    //
    // Reference:
    // https://keylime-docs.readthedocs.io/en/latest/rest_apis.html#post--v1.0-keys-ukey
    // https://github.com/keylime/keylime/blob/910b38b296038b187a020c095dc747e9c46cbef3/keylime/crypto.py#L151
    let mut signer =
        Signer::new(MessageDigest::sha384(), &pkey).map_err(|source| {
            CryptoError::HMACError {
                message: "failed to create Signer object".into(),
                source,
            }
        })?;
    signer
        .update(data)
        .map_err(|source| CryptoError::HMACError {
            message: "failed to add input data to Signer".into(),
            source,
        })?;

    if !memcmp::eq(
        &signer
            .sign_to_vec()
            .map_err(|source| CryptoError::HMACError {
                message: "failed to generate HMAC".into(),
                source,
            })?,
        hmac,
    ) {
        return Err(CryptoError::InvalidHMAC);
    }

    Ok(())
}

pub fn decrypt_aead(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = match key.len() {
        AES_128_KEY_LEN => Cipher::aes_128_gcm(),
        AES_256_KEY_LEN => Cipher::aes_256_gcm(),
        other => return Err(CryptoError::InvalidKeyLength { length: other }),
    };

    // Parse out payload IV, tag, ciphertext.  Note that Keylime
    // currently uses 16-byte IV, while the recommendation in SP
    // 800-38D is 12-byte.
    //
    // Reference:
    // https://github.com/keylime/keylime/blob/1663a7702b3286152b38dbcb715a9eb6705e05e9/keylime/crypto.py#L191
    let length = data.len();
    if length < AES_BLOCK_SIZE * 2 {
        return Err(CryptoError::InvalidInputLength { length });
    }
    let (iv, rest) = data.split_at(AES_BLOCK_SIZE);
    let (ciphertext, tag) = rest.split_at(rest.len() - AES_BLOCK_SIZE);

    openssl::symm::decrypt_aead(cipher, key, Some(iv), &[], ciphertext, tag)
        .map_err(CryptoError::DecryptAEADError)
}

pub mod testing {
    use super::*;
    use openssl::encrypt::Encrypter;
    use std::path::{Path, PathBuf};

    #[derive(Error, Debug)]
    pub enum CryptoTestError {
        /// Crypto error
        #[error("CryptoError")]
        CryptoError(#[from] CryptoError),

        /// IO error
        #[error("IOError")]
        IoError(#[from] std::io::Error),

        /// OpenSSL error
        #[error("IOError")]
        OpenSSLError(#[from] openssl::error::ErrorStack),

        /// Invalid IV length
        #[error("Invalid IV length: expected {expected} got {got}")]
        InvalidIVLen { expected: usize, got: usize },
    }

    pub fn rsa_import_pair(
        path: impl AsRef<Path>,
    ) -> Result<(PKey<Public>, PKey<Private>), CryptoTestError> {
        let contents = read_to_string(path)?;
        let private = PKey::private_key_from_pem(contents.as_bytes())?;
        let public = pkey_pub_from_priv(&private)?;
        Ok((public, private))
    }

    pub fn pkey_pub_from_pem(
        pem: &str,
    ) -> Result<PKey<Public>, CryptoTestError> {
        PKey::<Public>::public_key_from_pem(pem.as_bytes())
            .map_err(CryptoTestError::OpenSSLError)
    }

    pub fn rsa_oaep_encrypt(
        pub_key: &PKey<Public>,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoTestError> {
        let mut encrypter = Encrypter::new(pub_key)?;

        encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        encrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
        encrypter.set_rsa_oaep_md(MessageDigest::sha1())?;

        // Create an output buffer
        let buffer_len = encrypter.encrypt_len(data)?;
        let mut encrypted = vec![0; buffer_len];

        // Encrypt and truncate the buffer
        let encrypted_len = encrypter.encrypt(data, &mut encrypted)?;
        encrypted.truncate(encrypted_len);

        Ok(encrypted)
    }

    pub fn encrypt_aead(
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoTestError> {
        let cipher = match key.len() {
            AES_128_KEY_LEN => Cipher::aes_128_gcm(),
            AES_256_KEY_LEN => Cipher::aes_256_gcm(),
            other => {
                return Err(
                    CryptoError::InvalidKeyLength { length: other }.into()
                );
            }
        };
        let iv_len = iv.len();
        if iv_len != AES_BLOCK_SIZE {
            return Err(CryptoTestError::InvalidIVLen {
                expected: AES_BLOCK_SIZE,
                got: iv_len,
            });
        }
        let mut tag = vec![0u8; AES_BLOCK_SIZE];
        let ciphertext = openssl::symm::encrypt_aead(
            cipher,
            key,
            Some(iv),
            &[],
            data,
            &mut tag,
        )?;

        let mut result =
            Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
        result.extend(iv);
        result.extend(ciphertext);
        result.extend(tag);
        Ok(result)
    }

    pub fn rsa_generate(
        key_size: u32,
    ) -> Result<PKey<Private>, CryptoTestError> {
        super::rsa_generate(key_size).map_err(CryptoTestError::CryptoError)
    }

    pub fn write_x509_der(
        cert: &X509,
        file_path: &Path,
    ) -> Result<(), CryptoTestError> {
        let mut file =
            std::fs::File::create(file_path).map_err(|source| {
                CryptoError::FSCreateError {
                    file: file_path.display().to_string(),
                    source,
                }
            })?;
        _ = file
            .write(&cert.to_der().map_err(CryptoError::X509ToDERError)?)
            .map_err(CryptoError::IOWriteError)?;
        Ok(())
    }

    /// Generates a full set of TLS certificates (CA, server, client) for testing purposes.
    ///
    /// # Arguments
    /// * `temp_dir` - The temporary directory to write the certificate files into.
    ///
    /// # Returns
    /// A tuple containing the paths to the generated files:
    /// (ca_cert, server_cert, server_key, client_cert, client_key)
    pub fn generate_tls_certs_for_test(
        temp_dir: &Path,
    ) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        use std::fs::File;
        use std::io::Write;

        // Define paths
        let ca_path = temp_dir.join("ca.pem");
        let server_cert_path = temp_dir.join("server_cert.pem");
        let server_key_path = temp_dir.join("server_key.pem");
        let client_cert_path = temp_dir.join("client_cert.pem");
        let client_key_path = temp_dir.join("client_key.pem");

        // Generate CA
        let ca_key = rsa_generate(2048).expect("Failed to generate CA key");
        let ca_cert = x509::CertificateBuilder::new()
            .private_key(&ca_key)
            .common_name("Test CA")
            .build()
            .expect("Failed to build CA cert");

        // Generate server certificate
        let server_key =
            rsa_generate(2048).expect("Failed to generate server key");
        let server_cert = x509::CertificateBuilder::new()
            .private_key(&server_key)
            .common_name("localhost")
            .add_ips(vec!["127.0.0.1"])
            .build()
            .expect("Failed to build server cert");

        // Generate client certificate
        let client_key =
            rsa_generate(2048).expect("Failed to generate client key");
        let client_cert = x509::CertificateBuilder::new()
            .private_key(&client_key)
            .common_name("test-client")
            .build()
            .expect("Failed to build client cert");

        // Write files
        let mut ca_file =
            File::create(&ca_path).expect("Failed to create CA file");
        ca_file
            .write_all(
                &ca_cert.to_pem().expect("Failed to convert CA to PEM"),
            )
            .expect("Failed to write CA cert");

        let mut server_cert_file = File::create(&server_cert_path)
            .expect("Failed to create server cert file");
        server_cert_file
            .write_all(
                &server_cert
                    .to_pem()
                    .expect("Failed to convert server cert to PEM"),
            )
            .expect("Failed to write server cert");

        let mut server_key_file = File::create(&server_key_path)
            .expect("Failed to create server key file");
        server_key_file
            .write_all(
                &server_key
                    .private_key_to_pem_pkcs8()
                    .expect("Failed to convert key to PEM"),
            )
            .expect("Failed to write server key");

        let mut client_cert_file = File::create(&client_cert_path)
            .expect("Failed to create client cert file");
        client_cert_file
            .write_all(
                &client_cert
                    .to_pem()
                    .expect("Failed to convert client cert to PEM"),
            )
            .expect("Failed to write client cert");

        let mut client_key_file = File::create(&client_key_path)
            .expect("Failed to create client key file");
        client_key_file
            .write_all(
                &client_key
                    .private_key_to_pem_pkcs8()
                    .expect("Failed to convert key to PEM"),
            )
            .expect("Failed to write client key");

        (
            ca_path,
            server_cert_path,
            server_key_path,
            client_cert_path,
            client_key_path,
        )
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::x509::CertificateBuilder;
    use std::{fs, path::Path};
    use testing::{encrypt_aead, rsa_import_pair, rsa_oaep_encrypt};

    // compare with the result from python output
    #[test]
    fn test_compute_hmac() {
        let key = String::from("mysecret");
        let message = String::from("hellothere");
        let mac =
            compute_hmac(key.as_bytes(), message.as_bytes()).map(hex::encode);
        assert_eq!(
            format!(
                "{}{}",
                "b8558314f515931c8d9b329805978fe77b9bb020b05406c0e",
                "f189d89846ff8f5f0ca10e387d2c424358171df7f896f9f"
            ),
            mac.unwrap() //#[allow_ci]
        );
    }

    // Test KDF to ensure derived password matches result derived from Python
    // functions.
    #[test]
    fn test_kdf() {
        let password = String::from("myverysecretsecret");
        let salt = String::from("thesaltiestsalt");
        let key = pbkdf2(password, salt);
        assert_eq!(
            "8a6de415abb8b27de5c572c8137bd14e5658395f9a2346e0b1ad8b9d8b9028af"
                .to_string(),
            key.unwrap() //#[allow_ci]
        );
    }

    #[test]
    fn test_hmac_verification() {
        // Generate a keypair
        let (pub_key, priv_key) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        let data = b"hello, world!";
        let data2 = b"hola, mundo!";

        // Sign the data
        let mut signer =
            Signer::new(MessageDigest::sha256(), &priv_key).unwrap(); //#[allow_ci]
        signer.update(data).unwrap(); //#[allow_ci]
        signer.update(data2).unwrap(); //#[allow_ci]
        let signature = signer.sign_to_vec().unwrap(); //#[allow_ci]

        // Verify the data
        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &pub_key).unwrap(); //#[allow_ci]
        verifier.update(data).unwrap(); //#[allow_ci]
        verifier.update(data2).unwrap(); //#[allow_ci]
        assert!(verifier.verify(&signature).unwrap()); //#[allow_ci]
    }

    #[test]
    fn test_rsa_oaep() {
        // Import a keypair
        let rsa_key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("test-rsa.pem");

        let (pub_key, priv_key) = rsa_import_pair(rsa_key_path)
            .expect("unable to import RSA key pair");
        let plaintext = b"0123456789012345";
        let ciphertext = rsa_oaep_encrypt(&pub_key, &plaintext[..])
            .expect("unable to encrypt");

        // We can't check against the fixed ciphertext, as OAEP
        // involves randomness. Check with a round-trip instead.
        let decrypted = rsa_oaep_decrypt(&priv_key, &ciphertext[..])
            .expect("unable to decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_aead_short() {
        let key = b"0123456789012345";
        let iv = b"ABCDEFGHIJKLMNOP";
        let plaintext = b"test string, longer than the block size";
        let ciphertext = encrypt_aead(&key[..], &iv[..], &plaintext[..])
            .expect("unable to encrypt");
        let expected = hex::decode("4142434445464748494A4B4C4D4E4F50B2198661586C9839CCDD0B1D5B4FF92FA9C0E6477C4E8E42C19ACD9E8061DD1E759401337DA285A70580E6A2E10B5D3A09994F46D90AB6").unwrap(); //#[allow_ci]
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_decrypt_aead_short() {
        let key = b"0123456789012345";
        let ciphertext = hex::decode("4142434445464748494A4B4C4D4E4F50B2198661586C9839CCDD0B1D5B4FF92FA9C0E6477C4E8E42C19ACD9E8061DD1E759401337DA285A70580E6A2E10B5D3A09994F46D90AB6").unwrap(); //#[allow_ci]
        let plaintext = decrypt_aead(&key[..], &ciphertext[..])
            .expect("unable to decrypt");
        let expected = b"test string, longer than the block size";
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn test_encrypt_aead_long() {
        let key = b"01234567890123450123456789012345";
        let iv = b"ABCDEFGHIJKLMNOP";
        let plaintext = b"test string, longer than the block size";
        let ciphertext = encrypt_aead(&key[..], &iv[..], &plaintext[..])
            .expect("unable to encrypt");
        let expected = hex::decode("4142434445464748494A4B4C4D4E4F50FCE7CA78C08FB1D5E04DB3C4AA6B6ED2F09C4AD7985BD1DB9FF15F9FDA869D0C01B27FF4618737BB53C84D256455AAB53B9AC7EAF88C4B").unwrap(); //#[allow_ci]
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_decrypt_aead_long() {
        let key = b"01234567890123450123456789012345";
        let ciphertext = hex::decode("4142434445464748494A4B4C4D4E4F50FCE7CA78C08FB1D5E04DB3C4AA6B6ED2F09C4AD7985BD1DB9FF15F9FDA869D0C01B27FF4618737BB53C84D256455AAB53B9AC7EAF88C4B").unwrap(); //#[allow_ci]
        let plaintext = decrypt_aead(&key[..], &ciphertext[..])
            .expect("unable to decrypt");
        let expected = b"test string, longer than the block size";
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn test_encrypt_aead_invalid_key_length() {
        let key = b"0123456789012345012345678901234";
        let iv = b"ABCDEFGHIJKLMNOP";
        let plaintext = b"test string, longer than the block size";
        let result = encrypt_aead(&key[..], &iv[..], &plaintext[..]);
        assert!(result.is_err())
    }

    #[test]
    fn test_encrypt_aead_invalid_iv_length() {
        let key = b"01234567890123450123456789012345";
        let iv = b"ABCDEFGHIJKLMN";
        let plaintext = b"test string, longer than the block size";
        let result = encrypt_aead(&key[..], &iv[..], &plaintext[..]);
        assert!(result.is_err())
    }

    #[test]
    fn test_decrypt_aead_invalid_key_length() {
        let key = b"0123456789012345012345678901234";
        let ciphertext = hex::decode("4142434445464748494A4B4C4D4E4F50FCE7CA78C08FB1D5E04DB3C4AA6B6ED2F09C4AD7985BD1DB9FF15F9FDA869D0C01B27FF4618737BB53C84D256455AAB53B9AC7EAF88C4B").unwrap(); //#[allow_ci]
        let result = decrypt_aead(&key[..], &ciphertext[..]);
        assert!(result.is_err())
    }

    #[test]
    fn test_decrypt_aead_invalid_ciphertext_length() {
        let key = b"0123456789012345";
        let ciphertext = hex::decode("41424344").unwrap(); //#[allow_ci]
        let result = decrypt_aead(&key[..], &ciphertext[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_asym_verify() {
        // Import test keypair
        let rsa_key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("test-rsa.pem");

        // Get RSA keys
        let contents = read_to_string(rsa_key_path);
        let private =
            PKey::private_key_from_pem(contents.unwrap().as_bytes()).unwrap(); //#[allow_ci]
        let public = pkey_pub_from_priv(&private).unwrap(); //#[allow_ci]

        let message = String::from("Hello World!");

        // Get known valid signature
        let signature_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("test-rsa.sig");

        let signature = read_to_string(signature_path).unwrap(); //#[allow_ci]

        assert!(asym_verify(&public, &message, &signature).unwrap()) //#[allow_ci]
    }

    #[test]
    fn test_password() {
        // Import test keypair
        let rsa_key_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("test-rsa.pem");

        // Get RSA keys
        let (_public, private) = rsa_import_pair(rsa_key_path).unwrap(); //#[allow_ci]

        // Create temporary directory and files names
        let temp_dir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let encrypted_path =
            Path::new(&temp_dir.path()).join("encrypted.pem");
        let empty_pw_path = Path::new(&temp_dir.path()).join("empty_pw.pem");
        let none_pw_path = Path::new(&temp_dir.path()).join("none_pw.pem");

        let message = b"Hello World!";

        // Write keys to files
        assert!(write_key_pair(&private, &encrypted_path, Some("password"))
            .is_ok());
        assert!(write_key_pair(&private, &empty_pw_path, Some("")).is_ok());
        assert!(write_key_pair(&private, &none_pw_path, None).is_ok());

        // Read keys from files
        let (_, priv_from_encrypted) =
            load_key_pair(&encrypted_path, Some("password")).unwrap(); //#[allow_ci]
        let (_, priv_from_empty) =
            load_key_pair(&empty_pw_path, Some("")).unwrap(); //#[allow_ci]
        let (_, priv_from_none) = load_key_pair(&none_pw_path, None).unwrap(); //#[allow_ci]

        for keypair in [
            priv_from_encrypted.as_ref(),
            priv_from_empty.as_ref(),
            priv_from_none.as_ref(),
        ] {
            // Sign the data
            let mut signer =
                Signer::new(MessageDigest::sha256(), keypair).unwrap(); //#[allow_ci]
            signer.update(message).unwrap(); //#[allow_ci]
            let signature = signer.sign_to_vec().unwrap(); //#[allow_ci]

            // Verify the data
            let mut verifier =
                Verifier::new(MessageDigest::sha256(), keypair).unwrap(); //#[allow_ci]
            verifier.update(message).unwrap(); //#[allow_ci]
            assert!(verifier.verify(&signature).unwrap()); //#[allow_ci]
        }
    }

    #[test]
    fn test_hash() {
        let input = "hello world!".as_bytes();
        let h = hash(input, MessageDigest::sha256());
        assert!(h.is_ok());
        let hex = hex::encode(h.unwrap()); //#[allow_ci]
        assert_eq!(hex, "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9");

        let h = hash(input, MessageDigest::sha384());
        assert!(h.is_ok());
        let hex = hex::encode(h.unwrap()); //#[allow_ci]
        assert_eq!(hex, "d33d40f7010ce34aa86efd353630309ed5c3d7ffac66d988825cf699f4803ccdf3f033230612f0945332fb580d8af805");

        let h = hash(input, MessageDigest::sha512());
        assert!(h.is_ok());
        let hex = hex::encode(h.unwrap()); //#[allow_ci]
        assert_eq!(hex, "db9b1cd3262dee37756a09b9064973589847caa8e53d31a9d142ea2701b1b28abd97838bb9a27068ba305dc8d04a45a1fcf079de54d607666996b3cc54f6b67c");
    }

    fn test_x509(privkey: &PKey<Private>, pubkey: PKey<Public>) {
        let tempdir = tempfile::tempdir().unwrap(); //#[allow_ci]

        let r = CertificateBuilder::new()
            .private_key(privkey)
            .common_name("uuidA")
            .build();

        assert!(r.is_ok());
        let cert_a = r.unwrap(); //#[allow_ci]
        let cert_a_path = tempdir.path().join("cert_a.pem");
        let r = write_x509(&cert_a, &cert_a_path);
        assert!(r.is_ok());
        assert!(cert_a_path.exists());

        let r = CertificateBuilder::new()
            .private_key(privkey)
            .common_name("uuidB")
            .add_ips(vec!["1.2.3.4"])
            .build();

        assert!(r.is_ok());
        let cert_b = r.unwrap(); //#[allow_ci]
        let cert_b_path = tempdir.path().join("cert_b.pem");
        let r = write_x509(&cert_b, &cert_b_path);
        assert!(r.is_ok());
        assert!(cert_b_path.exists());

        let loaded_chain = load_x509_cert_chain(&cert_a_path);
        assert!(loaded_chain.is_ok());
        let mut loaded_chain = loaded_chain.unwrap(); //#[allow_ci]
        assert_eq!(loaded_chain.len(), 1);
        let loaded_a = loaded_chain.pop().unwrap(); //#[allow_ci]

        let a_str = read_to_string(&cert_a_path).unwrap(); //#[allow_ci]
        let b_str = read_to_string(&cert_b_path).unwrap(); //#[allow_ci]
        let concat = a_str + &b_str;
        let concat_path = tempdir.path().join("concat.pem");
        fs::write(&concat_path, concat).unwrap(); //#[allow_ci]

        // Load a single certificate from a file with multiple certificates
        let r = load_x509_pem(&concat_path);
        assert!(r.is_ok());

        let cert = r.unwrap(); //#[allow_ci]

        // Test getting public key from cert
        let pubkey_from_cert = x509_get_pubkey(&cert)
            .expect("Failed to get public key from certificate");
        assert_eq!(
            pubkey
                .public_key_to_der()
                .expect("Failed to convert public key to DER"),
            pubkey_from_cert
                .public_key_to_der()
                .expect("Failed to convert public key to DER")
        );

        // Test converting certificate to DER
        let r = x509_to_der(&cert);
        assert!(r.is_ok());

        // Test converting certificate to PEM
        let r = x509_to_pem(&cert);
        assert!(r.is_ok());

        // Test loading DER certificate
        let der_path = tempdir.path().join("cert.der");
        let r = testing::write_x509_der(&cert, &der_path);
        assert!(r.is_ok());
        let r = load_x509_der(&der_path);
        assert!(r.is_ok());

        // Loading multiple PEM certs should work when loading chain
        let r = load_x509_cert_chain(&concat_path);
        assert!(r.is_ok());
        let chain = r.unwrap(); //#[allow_ci]
        assert!(chain.len() == 2);

        // Test adding loading certs from a list, including an non-existing file
        let non_existing =
            Path::new("/non_existing_path/non_existing_cert.pem");
        let cert_list: Vec<&Path> =
            vec![&cert_a_path, non_existing, &cert_b_path];
        let r = load_x509_cert_list(cert_list);
        assert!(r.is_ok());
        let loaded_list = r.unwrap(); //#[allow_ci]
        assert!(loaded_list.len() == 2);

        let r = generate_tls_context(&loaded_a, privkey, loaded_list);
        assert!(r.is_ok());
    }

    #[test]
    fn test_x509_rsa() {
        let (pubkey, privkey) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        test_x509(&privkey, pubkey);
    }

    #[test]
    #[ignore]
    fn test_x509_long_rsa() {
        for length in [3072, 4096] {
            let (pubkey, privkey) = rsa_generate_pair(length).unwrap(); //#[allow_ci]
            test_x509(&privkey, pubkey);
        }
    }

    #[test]
    fn test_x509_ecc() {
        use openssl::ec::EcGroup;

        for group in [
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(), //#[allow_ci]
            EcGroup::from_curve_name(Nid::SECP256K1).unwrap(), //#[allow_ci]
            EcGroup::from_curve_name(Nid::SECP384R1).unwrap(), //#[allow_ci],
            EcGroup::from_curve_name(Nid::SECP521R1).unwrap(), //#[allow_ci]
        ] {
            let (pubkey, privkey) = ecc_generate_pair(&group).unwrap(); //#[allow_ci]

            test_x509(&privkey, pubkey);
        }
    }
    #[test]
    fn test_match_cert_to_template() {
        for (file_name, template) in
            [("test-cert.pem", "H-1"), ("prime256v1.cert.pem", "H-5")]
        {
            let cert_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data")
                .join(file_name);

            let r = load_x509_pem(&cert_path);
            assert!(r.is_ok());

            let cert = r.unwrap(); //#[allow_ci]

            let r = match_cert_to_template(&cert);
            assert!(r.is_ok());
            let s = r.unwrap(); //#[allow_ci]
            assert_eq!(s, template);
        }
    }

    #[test]
    fn test_validate_key_algorithm_rsa_2048() {
        // Generate RSA 2048 key and validate it
        let (_, private_key) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        let result = validate_key_algorithm(
            &private_key,
            EncryptionAlgorithm::Rsa2048,
        );
        assert!(result.is_ok(), "RSA 2048 key should validate successfully");
    }

    #[test]
    fn test_validate_key_algorithm_rsa_3072() {
        // Generate RSA 3072 key and validate it
        let (_, private_key) = rsa_generate_pair(3072).unwrap(); //#[allow_ci]
        let result = validate_key_algorithm(
            &private_key,
            EncryptionAlgorithm::Rsa3072,
        );
        assert!(result.is_ok(), "RSA 3072 key should validate successfully");
    }

    #[test]
    fn test_validate_key_algorithm_rsa_4096() {
        // Generate RSA 4096 key and validate it
        let (_, private_key) = rsa_generate_pair(4096).unwrap(); //#[allow_ci]
        let result = validate_key_algorithm(
            &private_key,
            EncryptionAlgorithm::Rsa4096,
        );
        assert!(result.is_ok(), "RSA 4096 key should validate successfully");
    }

    #[test]
    fn test_validate_key_algorithm_wrong_size() {
        // Generate RSA 2048 key but validate as RSA 4096
        let (_, private_key) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        let result = validate_key_algorithm(
            &private_key,
            EncryptionAlgorithm::Rsa4096,
        );
        assert!(
            result.is_err(),
            "RSA 2048 key should fail RSA 4096 validation"
        );

        // Verify it's specifically an InvalidKeyLength error
        match result {
            Err(CryptoError::InvalidKeyLength { length }) => {
                assert_eq!(length, 2048, "Error should report 2048 bit key");
            }
            _ => panic!("Expected InvalidKeyLength error"), //#[allow_ci]
        }
    }

    #[test]
    fn test_validate_key_algorithm_ecc_256() {
        use openssl::ec::EcGroup;

        // Generate ECC 256 key and validate it
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(); //#[allow_ci]
        let (_, private_key) = ecc_generate_pair(&group).unwrap(); //#[allow_ci]
        let result =
            validate_key_algorithm(&private_key, EncryptionAlgorithm::Ecc256);
        assert!(result.is_ok(), "ECC 256 key should validate successfully");
    }

    #[test]
    fn test_validate_key_algorithm_ecc_384() {
        use openssl::ec::EcGroup;

        // Generate ECC 384 key and validate it
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap(); //#[allow_ci]
        let (_, private_key) = ecc_generate_pair(&group).unwrap(); //#[allow_ci]
        let result =
            validate_key_algorithm(&private_key, EncryptionAlgorithm::Ecc384);
        assert!(result.is_ok(), "ECC 384 key should validate successfully");
    }

    #[test]
    fn test_load_or_generate_key_creates_new() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap(); //#[allow_ci]
        let key_path = dir.path().join("test-key.pem");

        // File doesn't exist, should generate new key
        assert!(!key_path.exists());

        let result = load_or_generate_key(
            &key_path,
            None,
            EncryptionAlgorithm::Rsa2048,
            false,
        );

        assert!(result.is_ok(), "Should generate new key successfully");
        assert!(key_path.exists(), "Key file should be created");

        // Verify the key is valid RSA 2048
        let (_, private_key) = result.unwrap(); //#[allow_ci]
        let validation = validate_key_algorithm(
            &private_key,
            EncryptionAlgorithm::Rsa2048,
        );
        assert!(validation.is_ok(), "Generated key should be RSA 2048");
    }

    #[test]
    fn test_load_or_generate_key_loads_existing() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap(); //#[allow_ci]
        let key_path = dir.path().join("test-key.pem");

        // First, generate and save a key
        let (pub1, priv1) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        write_key_pair(&priv1, &key_path, None).unwrap(); //#[allow_ci]

        // Now load it using load_or_generate_key
        let result = load_or_generate_key(
            &key_path,
            None,
            EncryptionAlgorithm::Rsa2048,
            false,
        );

        assert!(result.is_ok(), "Should load existing key successfully");

        let (pub2, _priv2) = result.unwrap(); //#[allow_ci]

        // Verify it's the same key by comparing public keys
        let pub1_der = pub1.public_key_to_der().unwrap(); //#[allow_ci]
        let pub2_der = pub2.public_key_to_der().unwrap(); //#[allow_ci]
        assert_eq!(
            pub1_der, pub2_der,
            "Loaded key should be the same as saved key"
        );
    }

    #[test]
    fn test_load_or_generate_key_with_password() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap(); //#[allow_ci]
        let key_path = dir.path().join("test-key-encrypted.pem");
        let password = "test_password_123";

        // Generate key with password
        let result = load_or_generate_key(
            &key_path,
            Some(password),
            EncryptionAlgorithm::Rsa2048,
            false,
        );

        assert!(result.is_ok(), "Should generate encrypted key successfully");
        assert!(key_path.exists(), "Encrypted key file should be created");

        let (pub1, _) = result.unwrap(); //#[allow_ci]

        // Load the same key with password
        let result2 = load_or_generate_key(
            &key_path,
            Some(password),
            EncryptionAlgorithm::Rsa2048,
            false,
        );

        assert!(result2.is_ok(), "Should load encrypted key successfully");

        let (pub2, _) = result2.unwrap(); //#[allow_ci]

        // Verify it's the same key
        let pub1_der = pub1.public_key_to_der().unwrap(); //#[allow_ci]
        let pub2_der = pub2.public_key_to_der().unwrap(); //#[allow_ci]
        assert_eq!(pub1_der, pub2_der, "Loaded key should be the same");
    }

    #[test]
    fn test_load_or_generate_key_validates_algorithm() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap(); //#[allow_ci]
        let key_path = dir.path().join("test-key.pem");

        // Generate and save an RSA 2048 key
        let (_, priv_key) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        write_key_pair(&priv_key, &key_path, None).unwrap(); //#[allow_ci]

        // Try to load it as RSA 4096 with validation enabled
        let result = load_or_generate_key(
            &key_path,
            None,
            EncryptionAlgorithm::Rsa4096,
            true, // Enable validation
        );

        assert!(
            result.is_err(),
            "Should fail validation when key size doesn't match"
        );

        // Verify it's an InvalidKeyLength error
        match result {
            Err(CryptoError::InvalidKeyLength { length }) => {
                assert_eq!(
                    length, 2048,
                    "Error should report actual key size"
                );
            }
            _ => panic!("Expected InvalidKeyLength error"), //#[allow_ci]
        }
    }

    #[test]
    fn test_load_or_generate_key_without_validation() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap(); //#[allow_ci]
        let key_path = dir.path().join("test-key.pem");

        // Generate and save an RSA 2048 key
        let (pub1, priv1) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        write_key_pair(&priv1, &key_path, None).unwrap(); //#[allow_ci]

        // Load it as RSA 4096 but with validation disabled
        let result = load_or_generate_key(
            &key_path,
            None,
            EncryptionAlgorithm::Rsa4096,
            false, // Disable validation
        );

        assert!(
            result.is_ok(),
            "Should load successfully when validation is disabled"
        );

        let (pub2, _) = result.unwrap(); //#[allow_ci]

        // Verify it loaded the existing key (not generated a new one)
        let pub1_der = pub1.public_key_to_der().unwrap(); //#[allow_ci]
        let pub2_der = pub2.public_key_to_der().unwrap(); //#[allow_ci]
        assert_eq!(pub1_der, pub2_der, "Should load existing key");
    }

    #[test]
    fn test_load_or_generate_key_rsa_3072() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap(); //#[allow_ci]
        let key_path = dir.path().join("test-key-3072.pem");

        // Generate RSA 3072 key
        let result = load_or_generate_key(
            &key_path,
            None,
            EncryptionAlgorithm::Rsa3072,
            true,
        );

        assert!(result.is_ok(), "Should generate RSA 3072 key successfully");

        let (_, private_key) = result.unwrap(); //#[allow_ci]
        let validation = validate_key_algorithm(
            &private_key,
            EncryptionAlgorithm::Rsa3072,
        );
        assert!(validation.is_ok(), "Generated key should be RSA 3072");
    }

    #[test]
    fn test_load_or_generate_key_ecc_256() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap(); //#[allow_ci]
        let key_path = dir.path().join("test-ecc-256.pem");

        // Generate ECC 256 key
        let result = load_or_generate_key(
            &key_path,
            None,
            EncryptionAlgorithm::Ecc256,
            true,
        );

        assert!(result.is_ok(), "Should generate ECC 256 key successfully");

        let (_, private_key) = result.unwrap(); //#[allow_ci]
        let validation =
            validate_key_algorithm(&private_key, EncryptionAlgorithm::Ecc256);
        assert!(validation.is_ok(), "Generated key should be ECC 256");
    }
}
