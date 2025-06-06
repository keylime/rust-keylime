// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{
    algorithms::{
        AlgorithmError, EncryptionAlgorithm, HashAlgorithm, SignAlgorithm,
    },
    crypto,
};
use base64::{engine::general_purpose, Engine as _};
use log::*;
use std::{
    convert::{TryFrom, TryInto},
    io::Read,
    str::FromStr,
    sync::{Arc, Mutex, OnceLock},
};

use thiserror::Error;
use tss_esapi::handles::SessionHandle;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{DigestList, SymmetricDefinition};

use openssl::{
    hash::{Hasher, MessageDigest},
    memcmp,
    pkey::{HasPublic, Id, PKeyRef, Public},
    x509::X509,
};

use tss_esapi::{
    abstraction::{
        ak, ek, nv,
        pcr::{read_all, PcrData},
        DefaultKey,
    },
    attributes::{
        object::ObjectAttributesBuilder, session::SessionAttributesBuilder,
    },
    constants::{
        response_code::Tss2ResponseCodeKind, session_type::SessionType,
        AlgorithmIdentifier, CapabilityType,
    },
    handles::{
        AuthHandle, KeyHandle, ObjectHandle, PcrHandle, PersistentTpmHandle,
        TpmHandle,
    },
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, NvAuth},
        session_handles::AuthSession,
        structure_tags::AttestationType,
    },
    structures::{
        Attest, AttestInfo, Auth, CapabilityData, Data, Digest, DigestValues,
        EccParameter, EccPoint, EccScheme, EncryptedSecret, HashScheme,
        IdObject, KeyDerivationFunctionScheme, Name, PcrSelectionList,
        PcrSelectionListBuilder, PcrSlot, Private as TssPrivate,
        Public as TssPublic, PublicBuilder, PublicEccParametersBuilder,
        PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
        Signature, SignatureScheme, SymmetricDefinitionObject, Ticket,
        VerifiedTicket,
    },
    tcti_ldr::TctiNameConf,
    traits::Marshall,
    tss2_esys::{TPML_DIGEST, TPML_PCR_SELECTION},
    Error::Tss2Error,
};

use crate::algorithms::{
    HashAlgorithm as KeylimeInternalHashAlgorithm,
    SignAlgorithm as KeylimeInternalSignAlgorithm,
};
use tss_esapi::interface_types::algorithm::HashingAlgorithm as TssEsapiHashingAlgorithm;

/// Maximum size of nonce used in `quote`.
pub const MAX_NONCE_SIZE: usize = 64;
const TPML_DIGEST_SIZE: usize = std::mem::size_of::<TPML_DIGEST>();
const TPML_PCR_SELECTION_SIZE: usize =
    std::mem::size_of::<TPML_PCR_SELECTION>();

// IDevID policy and unique constants
const IDEVID_AUTH_POLICY_SHA512: [u8; 64] = [
    0x7d, 0xd7, 0x50, 0x0f, 0xd6, 0xc1, 0xb9, 0x4f, 0x97, 0xa6, 0xaf, 0x91,
    0x0d, 0xa1, 0x47, 0x30, 0x1e, 0xf2, 0x8f, 0x66, 0x2f, 0xee, 0x06, 0xf2,
    0x25, 0xa4, 0xcc, 0xad, 0xda, 0x3b, 0x4e, 0x6b, 0x38, 0xe6, 0x6b, 0x2f,
    0x3a, 0xd5, 0xde, 0xe1, 0xa0, 0x50, 0x3c, 0xd2, 0xda, 0xed, 0xb1, 0xe6,
    0x8c, 0xfe, 0x4f, 0x84, 0xb0, 0x3a, 0x8c, 0xd2, 0x2b, 0xb6, 0xa9, 0x76,
    0xf0, 0x71, 0xa7, 0x2f,
];
const IDEVID_AUTH_POLICY_SHA384: [u8; 48] = [
    0x4d, 0xb1, 0xaa, 0x83, 0x6d, 0x0b, 0x56, 0x15, 0xdf, 0x6e, 0xe5, 0x3a,
    0x40, 0xef, 0x70, 0xc6, 0x1c, 0x21, 0x7f, 0x43, 0x03, 0xd4, 0x46, 0x95,
    0x92, 0x59, 0x72, 0xbc, 0x92, 0x70, 0x06, 0xcf, 0xa5, 0xcb, 0xdf, 0x6d,
    0xc1, 0x8c, 0x4d, 0xbe, 0x32, 0x9b, 0x2f, 0x15, 0x42, 0xc3, 0xdd, 0x33,
];
const IDEVID_AUTH_POLICY_SHA256: [u8; 32] = [
    0xad, 0x6b, 0x3a, 0x22, 0x84, 0xfd, 0x69, 0x8a, 0x07, 0x10, 0xbf, 0x5c,
    0xc1, 0xb9, 0xbd, 0xf1, 0x5e, 0x25, 0x32, 0xe3, 0xf6, 0x01, 0xfa, 0x4b,
    0x93, 0xa6, 0xa8, 0xfa, 0x8d, 0xe5, 0x79, 0xea,
];
const UNIQUE_IDEVID: [u8; 6] = [0x49, 0x44, 0x45, 0x56, 0x49, 0x44];

//  IAK policy and unique constants
const IAK_AUTH_POLICY_SHA512: [u8; 64] = [
    0x80, 0x60, 0xd1, 0xfb, 0x31, 0x71, 0x6a, 0x29, 0xe4, 0x8a, 0x6e, 0x5f,
    0xec, 0xe0, 0x88, 0xbc, 0xfc, 0x1b, 0x27, 0x8f, 0xc1, 0x62, 0x25, 0x5e,
    0x81, 0xc3, 0xec, 0xa3, 0x54, 0x4c, 0xd4, 0x4a, 0xf9, 0x44, 0x10, 0xc3,
    0x71, 0x5d, 0x56, 0x1c, 0xcc, 0xd9, 0xe3, 0x9a, 0x6c, 0xb2, 0x64, 0x6d,
    0x43, 0x53, 0x5b, 0xb5, 0x4e, 0xa8, 0x87, 0x10, 0xde, 0xb5, 0xf7, 0x83,
    0x6b, 0xd9, 0xb5, 0x86,
];
const IAK_AUTH_POLICY_SHA384: [u8; 48] = [
    0x12, 0x9d, 0x94, 0xeb, 0xf8, 0x45, 0x56, 0x65, 0x2c, 0x6e, 0xef, 0x43,
    0xbb, 0xb7, 0x57, 0x51, 0x2a, 0xc8, 0x7e, 0x52, 0xbe, 0x7b, 0x34, 0x9c,
    0xa6, 0xce, 0x4d, 0x82, 0x6f, 0x74, 0x9f, 0xcf, 0x67, 0x2f, 0x51, 0x71,
    0x6c, 0x5c, 0xbb, 0x60, 0x5f, 0x31, 0x3b, 0xf3, 0x45, 0xaa, 0xb3, 0x12,
];
const IAK_AUTH_POLICY_SHA256: [u8; 32] = [
    0x54, 0x37, 0x18, 0x23, 0x26, 0xe4, 0x14, 0xfc, 0xa7, 0x97, 0xd5, 0xf1,
    0x74, 0x61, 0x5a, 0x16, 0x41, 0xf6, 0x12, 0x55, 0x79, 0x7c, 0x3a, 0x2b,
    0x22, 0xc2, 0x1d, 0x12, 0x0b, 0x2d, 0x1e, 0x07,
];
const UNIQUE_IAK: [u8; 3] = [0x49, 0x41, 0x4b];

const RSA_EK_CERTIFICATE_CHAIN_START: u32 = 0x01c00100;
const RSA_EK_CERTIFICATE_CHAIN_END: u32 = 0x01c001ff;

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.5 Revision 2
// Section B.6
const POLICY_A_SHA384: [u8; 48] = [
    0x8b, 0xbf, 0x22, 0x66, 0x53, 0x7c, 0x17, 0x1c, 0xb5, 0x6e, 0x40, 0x3c,
    0x4d, 0xc1, 0xd4, 0xb6, 0x4f, 0x43, 0x26, 0x11, 0xdc, 0x38, 0x6e, 0x6f,
    0x53, 0x20, 0x50, 0xc3, 0x27, 0x8c, 0x93, 0x0e, 0x14, 0x3e, 0x8b, 0xb1,
    0x13, 0x38, 0x24, 0xcc, 0xb4, 0x31, 0x05, 0x38, 0x71, 0xc6, 0xdb, 0x53,
];
const POLICY_A_SHA512: [u8; 64] = [
    0x1e, 0x3b, 0x76, 0x50, 0x2c, 0x8a, 0x14, 0x25, 0xaa, 0x0b, 0x7b, 0x3f,
    0xc6, 0x46, 0xa1, 0xb0, 0xfa, 0xe0, 0x63, 0xb0, 0x3b, 0x53, 0x68, 0xf9,
    0xc4, 0xcd, 0xde, 0xca, 0xff, 0x08, 0x91, 0xdd, 0x68, 0x2b, 0xac, 0x1a,
    0x85, 0xd4, 0xd8, 0x32, 0xb7, 0x81, 0xea, 0x45, 0x19, 0x15, 0xde, 0x5f,
    0xc5, 0xbf, 0x0d, 0xc4, 0xa1, 0x91, 0x7c, 0xd4, 0x2f, 0xa0, 0x41, 0xe3,
    0xf9, 0x98, 0xe0, 0xee,
];
const POLICY_A_SM3_256: [u8; 32] = [
    0xc6, 0x7f, 0x7d, 0x35, 0xf6, 0x6f, 0x3b, 0xec, 0x13, 0xc8, 0x9f, 0xe8,
    0x98, 0x92, 0x1c, 0x65, 0x1b, 0x0c, 0xb5, 0xa3, 0x8a, 0x92, 0x69, 0x0a,
    0x62, 0xa4, 0x3c, 0x00, 0x12, 0xe4, 0xfb, 0x8b,
];
const POLICY_C_SHA384: [u8; 48] = [
    0xd6, 0x03, 0x2c, 0xe6, 0x1f, 0x2f, 0xb3, 0xc2, 0x40, 0xeb, 0x3c, 0xf6,
    0xa3, 0x32, 0x37, 0xef, 0x2b, 0x6a, 0x16, 0xf4, 0x29, 0x3c, 0x22, 0xb4,
    0x55, 0xe2, 0x61, 0xcf, 0xfd, 0x21, 0x7a, 0xd5, 0xb4, 0x94, 0x7c, 0x2d,
    0x73, 0xe6, 0x30, 0x05, 0xee, 0xd2, 0xdc, 0x2b, 0x35, 0x93, 0xd1, 0x65,
];
const POLICY_C_SHA512: [u8; 64] = [
    0x58, 0x9e, 0xe1, 0xe1, 0x46, 0x54, 0x47, 0x16, 0xe8, 0xde, 0xaf, 0xe6,
    0xdb, 0x24, 0x7b, 0x01, 0xb8, 0x1e, 0x9f, 0x9c, 0x7d, 0xd1, 0x6b, 0x81,
    0x4a, 0xa1, 0x59, 0x13, 0x87, 0x49, 0x10, 0x5f, 0xba, 0x53, 0x88, 0xdd,
    0x1d, 0xea, 0x70, 0x2f, 0x35, 0x24, 0x0c, 0x18, 0x49, 0x33, 0x12, 0x1e,
    0x2c, 0x61, 0xb8, 0xf5, 0x0d, 0x3e, 0xf9, 0x13, 0x93, 0xa4, 0x9a, 0x38,
    0xc3, 0xf7, 0x3f, 0xc8,
];
const POLICY_C_SM3_256: [u8; 32] = [
    0x2d, 0x4e, 0x81, 0x57, 0x8c, 0x35, 0x31, 0xd9, 0xbd, 0x1c, 0xdd, 0x7d,
    0x02, 0xba, 0x29, 0x8d, 0x56, 0x99, 0xa3, 0xe3, 0x9f, 0xc3, 0x55, 0x1b,
    0xfe, 0xff, 0xcf, 0x13, 0x2b, 0x49, 0xe1, 0x1d,
];

/// TpmError wraps all possible errors raised in tpm.rs
#[derive(Error, Debug)]
pub enum TpmError {
    /// Public key does not match with certificate
    #[error("{0} key does not match with certificate. Check template in configuration.")]
    PublicKeyCertificateMismatch(String),

    /// Unsupported hashing algorithm error
    #[error("Unsupported hashing algorithm : {alg:?}")]
    UnsupportedHashingAlgorithm { alg: HashingAlgorithm },

    /// Error creating EK object
    #[error("Error creating EK object")]
    TSSCreateEKError { source: tss_esapi::Error },

    /// Error creating AK object
    #[error("Error creating AK object")]
    TSSCreateAKError { source: tss_esapi::Error },

    /// Error loading AK object
    #[error("Error loading AK object")]
    TSSLoadAKError { source: tss_esapi::Error },

    /// Error flushing object handle
    #[error("Error flushing object handle")]
    TSSFlushContext { source: tss_esapi::Error },

    /// Error creating new persistent TPM handle
    #[error("Error creating handle for persistent TPM object in {handle}")]
    TSSNewPersistentHandleError {
        handle: String,
        source: tss_esapi::Error,
    },

    /// Error creating handle from persistent TPM handle
    #[error("Error creating handle from persistent TPM handle {handle}")]
    TSSHandleFromPersistentHandleError {
        handle: String,
        source: tss_esapi::Error,
    },

    /// Error setting auth for persistent TPM handle
    #[error("Error setting auth for persistent TPM handle {handle}")]
    TSSHandleSetAuthError {
        handle: String,
        source: tss_esapi::Error,
    },

    /// Error returned in case of error creating new Primary Key
    #[error("Error creating primary key")]
    TSSCreatePrimaryError { source: tss_esapi::Error },

    /// Error building PCR Selection list
    #[error("Error building PCR Selection list")]
    TSSPCRSelectionBuildError { source: tss_esapi::Error },

    /// Error obtaining digest value from an authorization policy
    #[error("Error obtaining digest value from an authorization policy")]
    TSSDigestFromAuthPolicyError { source: tss_esapi::Error },

    /// Error creating encrypted challenge with MakeCredential
    #[error("Error creating encrypted challenge with MakeCredential")]
    TSSMakeCredentialError { source: tss_esapi::Error },

    /// Error obtaining RSA public key from IDevID
    #[error("Error obtaining RSA public key from IDevID")]
    TSSPublicKeyFromIDevID { source: tss_esapi::Error },

    /// Error obtaining RSA public key from IAK
    #[error("Error obtaining RSA public key from IAK")]
    TSSPublicKeyFromIAK { source: tss_esapi::Error },

    /// Error building Object Attributes
    #[error("Error building Object Attributes: {source}")]
    TSSObjectAttributesBuildError { source: tss_esapi::Error },

    /// Error building public RSA parameters
    #[error("Error building public RSA parameters")]
    TSSPublicRSAParametersBuildError { source: tss_esapi::Error },

    /// Error building public ECC parameters
    #[error("Error building public ECC parameters")]
    TSSPublicECCParametersBuildError { source: tss_esapi::Error },

    /// Error building IDevID key
    #[error("Error building IDevID key")]
    TSSIDevIDKeyBuildError { source: tss_esapi::Error },

    /// Error building IAK key
    #[error("Error building IAK key")]
    TSSIAKKeyBuildError { source: tss_esapi::Error },

    /// Error obtaining ECC parameter from IDevID
    #[error("Error obtaining ECC parameter from IDevID")]
    TSSECCParameterFromIDevIDError { source: tss_esapi::Error },

    /// Error obtaining ECC parameter from IAK
    #[error("Error obtaining ECC parameter from IAK")]
    TSSECCParameterFromIAKError { source: tss_esapi::Error },

    /// Error obtaining object name
    #[error("Error obtaining object name")]
    TSSGetNameError { source: tss_esapi::Error },

    /// Error returned in case of failure reading EK public information
    #[error("Error reading EK public info")]
    TSSReadPublicError { source: tss_esapi::Error },

    /// Error returned in case of failure obtaining SymmetricDefinition from Cipher
    #[error("Error converting Cipher to SymmetricDefinition")]
    TSSSymmetricDefinitionFromCipher { source: tss_esapi::Error },

    /// Error returned in case of failure starting authentication session
    #[error("Error starting authentication session")]
    TSSStartAuthenticationSessionError { source: tss_esapi::Error },

    /// Error setting authentication session attributes
    #[error("Error setting authentication session attributes")]
    TSSSessionSetAttributesError { source: tss_esapi::Error },

    /// Error setting authentication to object handle
    #[error("Error setting authentication to object handle")]
    TSSTrSetAuth { source: tss_esapi::Error },

    /// Error converting to TSS Digest from digest value
    #[error("Error converting to TSS Digest from digest value")]
    TSSDigestFromValue { source: tss_esapi::Error },

    /// Error creating a TCTI context
    #[error("Error creating TCTI context")]
    TSSTctiContextError { source: tss_esapi::Error },

    /// Error marshalling TPMS_ATTEST structure
    #[error("Error marshalling TPMS_ATTEST structure")]
    TSSMarshallAttestError { source: tss_esapi::Error },

    /// Error marshalling TPMT_SIGNATURE structure
    #[error("Error marshalling TPMT_SIGNATURE structure")]
    TSSMarshallSignatureError { source: tss_esapi::Error },

    /// Error getting PCR data
    #[error("Error getting PCR data from TPM")]
    TSSPCRListError { source: tss_esapi::Error },

    /// Error generating quote
    #[error("Error generating quote")]
    TSSQuoteError { source: tss_esapi::Error },

    /// Error verifying signature
    #[error("Error verifying signature")]
    TSSVerifySign { source: tss_esapi::Error },

    /// Unexpected attested type in quote
    #[error("Unexpected attested type in quote: expected {expected:?} got {got:?}")]
    UnexpectedAttestedType {
        expected: AttestationType,
        got: AttestationType,
    },

    /// Too many mismatches between attested data and PCR values
    #[error("Consistent race condition: PCR data and attestation data mismatched on all {attempts} attempts")]
    TooManyAttestationMismatches { attempts: i32 },

    /// Error converting nonce to the Data structure
    #[error("Error converting nonce to Data structure")]
    DataFromNonce,

    /// Empty authentication session returned by start_auth_session()
    #[error(
        "Error starting authentication session: Empty authentication session"
    )]
    EmptyAuthenticationSessionError,

    /// Error parsing number from string
    #[error("Number parsing error from string {origin}")]
    NumParse {
        origin: String,
        source: std::num::ParseIntError,
    },

    /// Error converting TSS_MAGIC number from MakeCredential keyblob header to u32
    #[error(
        "Error converting TSS_MAGIC number from MakeCredential keyblob header {header:?} to u32"
    )]
    KeyblobParseMagicNumberError { header: Vec<u8> },

    /// Error converting version from MakeCredential keyblob header to u32
    #[error(
        "Error converting version from MakeCredential keyblob header {header:?} to u32"
    )]
    KeyblobParseVersionError { header: Vec<u8> },

    /// Error converting credential size from MakeCredential keyblob to u16
    #[error(
        "Error converting credential size from MakeCredential keyblob {value:?} to u16"
    )]
    KeyblobParseCredSizeError { value: Vec<u8> },

    /// Error converting secret size from MakeCredential keyblob to u16
    #[error(
        "Error converting secret size from MakeCredential keyblob {value:?} to u16"
    )]
    KeyblobParseSecreSizeError { value: Vec<u8> },

    /// Error parsing credential from MakeCredential keyblob header
    #[error("Error parsing credential from MakeCredential keyblob header")]
    KeyblobParseCredential,

    /// Error parsing encrypted secret from MakeCredential keyblob
    #[error("Error parsing encrypted secret from MakeCredential keyblob")]
    KeyblobParseEncryptedSecret,

    /// Mismatching MakeCredential keyblob header TSS_MAGIC number
    #[error("Mismatching MakeCredential keyblob header TSS_MAGIC number: expected {expected}, got {got}")]
    KeyblobInvalidMagicNumber { expected: u32, got: u32 },

    /// Unexpected MakeCredential keyblob version number
    #[error("Unexpected MakeCredential keyblob header version number: expected {expected}, got {got}")]
    InvalidKeyblobVersion { expected: u32, got: u32 },

    /// Error parsing the value in TCTI env var
    #[error("Error parsing TCTI configuration from env var 'TCTI' {path}")]
    TctiNameError {
        path: String,
        source: tss_esapi::Error,
    },

    /// Error getting RSA public key from PKey
    #[error("Error getting RSA public key from PKey")]
    OpenSSLRSAFromPKey { source: openssl::error::ErrorStack },

    /// Error PEM encoding public key
    #[error("Error encoding public key in PEM format")]
    OpenSSLPublicKeyToPEM { source: openssl::error::ErrorStack },

    /// Error creating Hasher
    #[error("Error creating Hasher")]
    OpenSSLHasherNew { source: openssl::error::ErrorStack },

    /// Error updating Hasher
    #[error("Error updating Hasher")]
    OpenSSLHasherUpdate { source: openssl::error::ErrorStack },

    /// Error finishing Hasher
    #[error("Error finishing Hasher")]
    OpenSSLHasherFinish { source: openssl::error::ErrorStack },

    /// Error when trying to decode the EK certificate
    #[error("EK certificate parsing error")]
    EKCertParsing(#[from] picky_asn1_der::Asn1DerError),

    /// Number conversion error
    #[error("Error converting number")]
    TryFromInt(#[from] std::num::TryFromIntError),

    /// Base64 decoding error
    #[error("base64 decode error")]
    Base64Decode(#[from] base64::DecodeError),

    /// Hex decoding error
    #[error("hex decode error")]
    HexDecodeError(String),

    /// Malformed PCR selection mask
    #[error("Malformed PCR selection mask: {0}")]
    MalformedPCRSelectionMask(String),

    /// Not implemented error
    #[error("{0} is not yet implemented")]
    NotImplemented(String),

    /// Read IO error
    #[error("Error reading {what}")]
    IoReadError {
        what: String,
        source: std::io::Error,
    },

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Infallible error
    #[error("Infallible")]
    Infallible(#[from] std::convert::Infallible),

    /// Generic catch-all TPM device error
    #[error("TSS2 Error: {err:?}, kind: {kind:?}, {message}")]
    Tss2 {
        err: tss_esapi::Error,
        kind: Option<Tss2ResponseCodeKind>,
        message: String,
    },

    /// Generic catch-all Algorithm error
    #[error("AlgorithmError")]
    AlgorithmError(#[from] AlgorithmError),

    /// Generic catch-all crypto error
    #[error("CryptoError")]
    CryptoError(#[from] crypto::CryptoError),

    /// Generic catch-all error
    #[error("{0}")]
    Other(String),

    /// Unsupported Hash algorithm error
    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(String),

    /// Error trying to read key name from bytes
    #[error("Name From Bytes Error: {0}")]
    NameFromBytesError(String),
}

impl From<tss_esapi::Error> for TpmError {
    fn from(err: tss_esapi::Error) -> Self {
        let kind = if let Tss2Error(tss2_rc) = err {
            tss2_rc.kind()
        } else {
            None
        };
        let message = format!("{err}");

        TpmError::Tss2 { err, kind, message }
    }
}

type Result<T> = std::result::Result<T, TpmError>;

/// Holds the output of create_ek.
#[derive(Clone, Debug)]
pub struct EKResult {
    pub key_handle: KeyHandle,
    pub ek_cert: Option<Vec<u8>>,
    pub public: TssPublic,
    pub ek_chain: Option<Vec<u8>>,
}

impl EKResult {
    pub fn to_pem(&self) -> Option<String> {
        let mut ca_chain: Vec<Vec<u8>> = Vec::new();

        match &self.ek_chain {
            Some(chain) => {
                ca_chain.extend(split_der_certificates(chain));
            }
            None => {
                debug!("* No EK certificate chain");
            }
        }

        match &self.ek_cert {
            Some(cert) => {
                ca_chain.push(cert.clone());
            }
            None => {
                debug!("* No EK certificate");
            }
        }

        match der_to_pem(ca_chain) {
            Ok(pem) => Some(pem),
            Err(err) => {
                error!("Failed to transform certificate chain to PEM format, due to {err:?}");
                None
            }
        }
    }
}

/// Holds the output of create_ak.
#[derive(Clone, Debug)]
pub struct AKResult {
    pub public: TssPublic,
    pub private: TssPrivate,
}

/// Holds the output of create_iak.
#[derive(Clone, Debug)]
pub struct IAKResult {
    pub public: TssPublic,
    pub handle: tss_esapi::handles::KeyHandle,
    pub is_persistent: bool,
}

/// Holds the output of create_idevid.
#[derive(Clone, Debug)]
pub struct IDevIDResult {
    pub public: TssPublic,
    pub handle: tss_esapi::handles::KeyHandle,
    pub is_persistent: bool,
}

/// Holds the Public result from create_idevid_public_from_default_template
#[derive(Clone, Debug)]
pub struct IDevIDPublic {
    pub public: TssPublic,
}

/// Holds the Public result from create_iak_public_from_default_template
#[derive(Clone, Debug)]
pub struct IAKPublic {
    pub public: TssPublic,
}

/// Wrapper around tss_esapi::Context.
#[derive(Debug)]
pub struct Context<'a> {
    inner: &'a Arc<Mutex<tss_esapi::Context>>,
}

static TPM_CTX: OnceLock<Arc<Mutex<tss_esapi::Context>>> = OnceLock::new();

impl Context<'_> {
    /// Creates a connection context.
    pub fn new() -> Result<Self> {
        let tcti_path = match std::env::var("TCTI") {
            Ok(val) => val,
            Err(_) => if std::path::Path::new("/dev/tpmrm0").exists() {
                "device:/dev/tpmrm0"
            } else {
                "device:/dev/tpm0"
            }
            .to_string(),
        };

        let tcti = TctiNameConf::from_str(&tcti_path).map_err(|error| {
            TpmError::TctiNameError {
                path: tcti_path.to_string(),
                source: error,
            }
        })?;

        let ctx = TPM_CTX.get_or_init(||
        {
            let mut tpmctx = tss_esapi::Context::new(tcti).map_err(|error| {
                TpmError::TSSTctiContextError { source: error }}).expect("Failed to create TPM context");

            //  Retrieve the TPM Vendor, this allows us to warn if someone is using a
            // Software TPM ("SW")
            if tss_esapi::utils::get_tpm_vendor(&mut tpmctx).unwrap().contains("SW") { //#[allow_ci]
                warn!("INSECURE: Keylime is currently using a software TPM emulator rather than a real hardware TPM.");
                warn!("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.");
                warn!("INSECURE: Only use Keylime in this mode for testing or debugging purposes.");
            }

            Arc::new(Mutex::new(tpmctx))
        });

        Ok(Self { inner: ctx })
    }

    pub fn inner(self) -> Arc<Mutex<tss_esapi::Context>> {
        Arc::clone(self.inner)
    }

    // Tries to parse the EK certificate and re-encodes it to remove potential padding
    fn check_ek_cert(&mut self, cert: &[u8]) -> Result<Vec<u8>> {
        let parsed_cert: picky_asn1_der::Asn1RawDer =
            picky_asn1_der::from_bytes(cert)?;
        Ok(picky_asn1_der::to_vec(&parsed_cert)?)
    }

    /// Creates an EK, returns the key handle and public certificate
    /// in `EKResult`.
    ///
    /// # Arguments
    ///
    /// `alg`: The EK algorithm
    /// `handle`: Optional; if provided, the EK in the provided handle is used instead of creating
    /// a new EK.
    ///
    /// # Returns
    ///
    /// An `EKResult` structure if successful, a TPMError otherwise
    pub fn create_ek(
        &mut self,
        alg: EncryptionAlgorithm,
        handle: Option<&str>,
    ) -> Result<EKResult> {
        let mut ctx = self.inner.lock().unwrap(); //#[allow_ci]

        // Retrieve EK handle, EK pub cert, and TPM pub object
        let key_handle: KeyHandle = match handle {
            Some(v) => {
                if v.is_empty() {
                    ek::create_ek_object_2(&mut ctx, alg.into(), DefaultKey)
                        .map_err(|source| TpmError::TSSCreateEKError {
                            source,
                        })?
                } else {
                    let handle =
                        u32::from_str_radix(v.trim_start_matches("0x"), 16)
                            .map_err(|source| TpmError::NumParse {
                            origin: v.to_string(),
                            source,
                        })?;

                    ctx.tr_from_tpm_public(TpmHandle::Persistent(
                        PersistentTpmHandle::new(handle).map_err(
                            |source| TpmError::TSSNewPersistentHandleError {
                                handle: v.to_string(),
                                source,
                            },
                        )?,
                    ))
                    .map_err(|source| {
                        TpmError::TSSHandleFromPersistentHandleError {
                            handle: v.to_string(),
                            source,
                        }
                    })?
                    .into()
                }
            }
            None => ek::create_ek_object_2(&mut ctx, alg.into(), DefaultKey)
                .map_err(|source| TpmError::TSSCreateEKError { source })?,
        };

        let cert = match ek::retrieve_ek_pubcert(&mut ctx, alg.into()) {
            Ok(cert) => match self.check_ek_cert(&cert) {
                Ok(cert_checked) => Some(cert_checked),
                Err(_) => {
                    warn!("EK certificate in TPM NVRAM is not ASN.1 DER encoded");
                    Some(cert)
                }
            },
            Err(_) => {
                warn!("No EK certificate found in TPM NVRAM");
                None
            }
        };

        let (tpm_pub, _, _) = ctx
            .read_public(key_handle)
            .map_err(|source| TpmError::TSSReadPublicError { source })?;

        let chain = match read_ek_ca_chain(&mut ctx) {
            Ok(der_data) => {
                if !der_data.is_empty() {
                    info!("Found EK certificate chain in TPM NVRAM")
                }
                Some(der_data)
            }
            Err(_) => {
                warn!("Failed reading EK certificate chain from TPM NVRAM");
                None
            }
        };

        Ok(EKResult {
            key_handle,
            ek_cert: cert,
            public: tpm_pub,
            ek_chain: chain,
        })
    }

    /// Creates an AK
    ///
    /// # Arguments
    ///
    /// * `handle`: The associated EK handle
    /// * `hash_alg`: The digest algorithm used for signing with the created AK
    /// * `key_alg`:  The key type used for signing with the created AK
    /// * `sign_alg`: The created AK signing algorithm
    ///
    /// Returns an `AKResult` structure if successful and a `TPMError` otherwise
    pub fn create_ak(
        &mut self,
        handle: KeyHandle,
        hash_alg: HashAlgorithm,
        key_alg: EncryptionAlgorithm,
        sign_alg: SignAlgorithm,
    ) -> Result<AKResult> {
        let ak = ak::create_ak_2(
            &mut self.inner.lock().unwrap(), //#[allow_ci]
            handle,
            hash_alg.into(),
            key_alg.into(),
            sign_alg.into(),
            None,
            DefaultKey,
        )
        .map_err(|source| TpmError::TSSCreateAKError { source })?;
        Ok(AKResult {
            public: ak.out_public,
            private: ak.out_private,
        })
    }

    /// Loads an existing AK associated with `handle` and `ak`.
    ///
    /// # Arguments
    ///
    /// `handle`: The associated EK handle
    /// `ak`: The `AKResult` structure containing the private and public keys to load
    ///
    /// # Return
    ///
    /// The loaded AK KeyHandle if successful, a TPMError otherwise
    pub fn load_ak(
        &mut self,
        handle: KeyHandle,
        ak: &AKResult,
    ) -> Result<KeyHandle> {
        let ak_handle = ak::load_ak(
            &mut self.inner.lock().unwrap(), //#[allow_ci]
            handle,
            None,
            ak.private.clone(),
            ak.public.clone(),
        )
        .map_err(|source| TpmError::TSSLoadAKError { source })?;
        Ok(ak_handle)
    }

    /// Load a key handle from a string of the handle location
    /// If a password is supplied, authorise the handle
    /// # Arguments
    ///
    /// `handle` : The string of the handle, eg. from config
    /// `password` ; The string password, to be converted to hex if there is the "hex:" prefix
    ///
    /// # Return
    /// The corresponding KeyHandle, or a TPMError
    fn get_key_handle(
        &mut self,
        handle: &str,
        password: &str,
    ) -> Result<KeyHandle> {
        let mut ctx = self.inner.lock().unwrap(); //#[allow_ci]
        let handle = u32::from_str_radix(handle.trim_start_matches("0x"), 16)
            .map_err(|source| TpmError::NumParse {
                origin: handle.to_string(),
                source,
            })?;
        let key_handle: KeyHandle = ctx
            .tr_from_tpm_public(TpmHandle::Persistent(
                PersistentTpmHandle::new(handle).map_err(|source| {
                    TpmError::TSSNewPersistentHandleError {
                        handle: handle.to_string(),
                        source,
                    }
                })?,
            ))
            .map_err(|source| TpmError::TSSHandleFromPersistentHandleError {
                handle: handle.to_string(),
                source,
            })?
            .into();
        if !password.is_empty() {
            let auth = if password.starts_with("hex:") {
                let (_, hex_password) = password.split_at(4);
                let decoded_password =
                    hex::decode(hex_password).map_err(|_| {
                        TpmError::HexDecodeError(
                            "Hex decode error for identity auth value."
                                .to_string(),
                        )
                    })?;
                Auth::try_from(decoded_password)?
            } else {
                Auth::try_from(password.as_bytes())?
            };
            ctx.tr_set_auth(key_handle.into(), auth).map_err(|source| {
                TpmError::TSSHandleSetAuthError {
                    handle: handle.to_string(),
                    source,
                }
            })?;
        };

        Ok(key_handle)
    }

    /// Create an IDevID object from one persisted in TPM using its handle
    pub fn idevid_from_handle(
        &mut self,
        handle: &str,
        password: &str,
    ) -> Result<IDevIDResult> {
        let idevid_handle = self.get_key_handle(handle, password)?;
        let (idevid_pub, _, _) = self
            .inner
            .lock()
            .unwrap() //#[allow_ci]
            .read_public(idevid_handle)
            .map_err(|source| TpmError::TSSReadPublicError { source })?;
        Ok(IDevIDResult {
            public: idevid_pub,
            handle: idevid_handle,
            is_persistent: true,
        })
    }

    /// Create an IAK object from one persisted in TPM using its handle
    pub fn iak_from_handle(
        &mut self,
        handle: &str,
        password: &str,
    ) -> Result<IAKResult> {
        let iak_handle = self.get_key_handle(handle, password)?;
        let (iak_pub, _, _) = self
            .inner
            .lock()
            .unwrap() //#[allow_ci]
            .read_public(iak_handle)
            .map_err(|source| TpmError::TSSReadPublicError { source })?;
        Ok(IAKResult {
            public: iak_pub,
            handle: iak_handle,
            is_persistent: true,
        })
    }

    /// Creates an IDevID
    pub fn create_idevid(
        &mut self,
        asym_alg: AsymmetricAlgorithm,
        name_alg: HashingAlgorithm,
    ) -> Result<IDevIDResult> {
        let key_pub = Self::create_idevid_public_from_default_template(
            asym_alg, name_alg,
        )?;

        let pcr_selection_list =
            self.get_pcr_selection_list(HashingAlgorithm::Sha256)?;

        let primary_key = self
            .inner
            .lock()
            .unwrap() //#[allow_ci]
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Endorsement,
                    key_pub.public,
                    None,
                    None,
                    None,
                    Some(pcr_selection_list),
                )
            })
            .map_err(|source| TpmError::TSSCreatePrimaryError { source })?;

        Ok(IDevIDResult {
            public: primary_key.out_public,
            handle: primary_key.key_handle,
            is_persistent: false,
        })
    }

    /// Mount the template for IDevID
    fn create_idevid_public_from_default_template(
        asym_alg: AsymmetricAlgorithm,
        name_alg: HashingAlgorithm,
    ) -> Result<IDevIDPublic> {
        let obj_attrs_builder = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_st_clear(false)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_admin_with_policy(true)
            .with_no_da(false)
            .with_encrypted_duplication(false)
            .with_sign_encrypt(true)
            .with_decrypt(false)
            // restricted=0 for DevIDs
            .with_restricted(false);

        let obj_attrs = obj_attrs_builder.build().map_err(|source| {
            TpmError::TSSObjectAttributesBuildError { source }
        })?;

        let (auth_policy, key_bits, curve_id) = match name_alg {
            HashingAlgorithm::Sha256 => (
                IDEVID_AUTH_POLICY_SHA256[0..32].to_vec(),
                RsaKeyBits::Rsa2048,
                EccCurve::NistP256,
            ),
            HashingAlgorithm::Sm3_256 => (
                IDEVID_AUTH_POLICY_SHA256[0..32].to_vec(),
                RsaKeyBits::Rsa2048,
                EccCurve::Sm2P256,
            ),
            HashingAlgorithm::Sha384 => (
                IDEVID_AUTH_POLICY_SHA384[0..48].to_vec(),
                RsaKeyBits::Rsa3072,
                EccCurve::NistP384,
            ),
            HashingAlgorithm::Sha512 => (
                IDEVID_AUTH_POLICY_SHA512[0..64].to_vec(),
                RsaKeyBits::Rsa4096,
                EccCurve::NistP521,
            ),
            _ => (
                IDEVID_AUTH_POLICY_SHA256[0..32].to_vec(),
                RsaKeyBits::Rsa2048,
                EccCurve::NistP256,
            ),
        };

        let key_builder = match asym_alg {
            AsymmetricAlgorithm::Rsa => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(name_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(auth_policy).map_err(
                    |source| TpmError::TSSDigestFromAuthPolicyError {
                        source,
                    },
                )?)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(key_bits)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.restricted())
                        .build()
                        .map_err(|source| {
                            TpmError::TSSPublicRSAParametersBuildError {
                                source,
                            }
                        })?,
                )
                .with_rsa_unique_identifier(
                    PublicKeyRsa::try_from(&UNIQUE_IDEVID[0..6]).map_err(
                        |source| TpmError::TSSPublicKeyFromIDevID { source },
                    )?,
                ),
            AsymmetricAlgorithm::Ecc => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(name_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(auth_policy).map_err(
                    |source| TpmError::TSSDigestFromAuthPolicyError {
                        source,
                    },
                )?)
                .with_ecc_parameters(
                    PublicEccParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(
                            name_alg,
                        )))
                        .with_curve(curve_id)
                        .with_key_derivation_function_scheme(
                            KeyDerivationFunctionScheme::Null,
                        )
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.restricted())
                        .build()
                        .map_err(|source| {
                            TpmError::TSSPublicECCParametersBuildError {
                                source,
                            }
                        })?,
                )
                .with_ecc_unique_identifier(EccPoint::new(
                    EccParameter::try_from(&UNIQUE_IDEVID[0..6]).map_err(
                        |source| TpmError::TSSECCParameterFromIDevIDError {
                            source,
                        },
                    )?,
                    EccParameter::try_from(&UNIQUE_IDEVID[0..6]).map_err(
                        |source| TpmError::TSSECCParameterFromIDevIDError {
                            source,
                        },
                    )?,
                )),
            // Defaulting to RSA on null
            AsymmetricAlgorithm::Null => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(
                    Digest::try_from(
                        IDEVID_AUTH_POLICY_SHA256[0..32].to_vec(),
                    )
                    .map_err(|source| {
                        TpmError::TSSDigestFromAuthPolicyError { source }
                    })?,
                )
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(RsaKeyBits::Rsa2048)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.decrypt())
                        .build()
                        .map_err(|source| {
                            TpmError::TSSPublicRSAParametersBuildError {
                                source,
                            }
                        })?,
                )
                .with_rsa_unique_identifier(
                    PublicKeyRsa::try_from(&UNIQUE_IDEVID[0..6]).map_err(
                        |source| TpmError::TSSPublicKeyFromIDevID { source },
                    )?,
                ),
        };

        Ok(IDevIDPublic {
            public: key_builder.build().map_err(|source| {
                TpmError::TSSIDevIDKeyBuildError { source }
            })?,
        })
    }

    /// Creates an IAK
    pub fn create_iak(
        &mut self,
        asym_alg: AsymmetricAlgorithm,
        name_alg: HashingAlgorithm,
    ) -> Result<IAKResult> {
        let key_pub = Self::create_iak_public_from_default_template(
            asym_alg, name_alg,
        )?;

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                    PcrSlot::Slot4,
                    PcrSlot::Slot5,
                    PcrSlot::Slot6,
                    PcrSlot::Slot7,
                ],
            )
            .build()
            .map_err(|source| TpmError::TSSPCRSelectionBuildError {
                source,
            })?;

        let primary_key = self
            .inner
            .lock()
            .unwrap() //#[allow_ci]
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Endorsement,
                    key_pub.public,
                    None,
                    None,
                    None,
                    Some(pcr_selection_list),
                )
            })
            .map_err(|source| TpmError::TSSCreatePrimaryError { source })?;

        Ok(IAKResult {
            public: primary_key.out_public,
            handle: primary_key.key_handle,
            is_persistent: false,
        })
    }

    /// Mount the template for IAK
    pub(crate) fn create_iak_public_from_default_template(
        asym_alg: AsymmetricAlgorithm,
        name_alg: HashingAlgorithm,
    ) -> Result<IAKPublic> {
        let obj_attrs_builder = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_st_clear(false)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_admin_with_policy(true)
            .with_no_da(false)
            .with_encrypted_duplication(false)
            .with_sign_encrypt(true)
            .with_decrypt(false)
            // restricted=1 for AKs
            .with_restricted(true);

        let obj_attrs = obj_attrs_builder.build().map_err(|source| {
            TpmError::TSSObjectAttributesBuildError { source }
        })?;

        let (auth_policy, key_bits, curve_id) = match name_alg {
            HashingAlgorithm::Sha256 => (
                IAK_AUTH_POLICY_SHA256[0..32].to_vec(),
                RsaKeyBits::Rsa2048,
                EccCurve::NistP256,
            ),
            HashingAlgorithm::Sm3_256 => (
                IAK_AUTH_POLICY_SHA256[0..32].to_vec(),
                RsaKeyBits::Rsa2048,
                EccCurve::Sm2P256,
            ),
            HashingAlgorithm::Sha384 => (
                IAK_AUTH_POLICY_SHA384[0..48].to_vec(),
                RsaKeyBits::Rsa3072,
                EccCurve::NistP384,
            ),
            HashingAlgorithm::Sha512 => (
                IAK_AUTH_POLICY_SHA512[0..64].to_vec(),
                RsaKeyBits::Rsa4096,
                EccCurve::NistP521,
            ),
            _ => (
                IAK_AUTH_POLICY_SHA256[0..32].to_vec(),
                RsaKeyBits::Rsa2048,
                EccCurve::NistP256,
            ),
        };

        let key_builder = match asym_alg {
            AsymmetricAlgorithm::Rsa => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(name_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(auth_policy).map_err(
                    |source| TpmError::TSSDigestFromAuthPolicyError {
                        source,
                    },
                )?)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_scheme(RsaScheme::RsaPss(HashScheme::new(
                            name_alg,
                        )))
                        .with_key_bits(key_bits)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.restricted())
                        .build()
                        .map_err(|source| {
                            TpmError::TSSPublicRSAParametersBuildError {
                                source,
                            }
                        })?,
                )
                .with_rsa_unique_identifier(
                    PublicKeyRsa::try_from(&UNIQUE_IAK[0..3]).map_err(
                        |source| TpmError::TSSPublicKeyFromIAK { source },
                    )?,
                ),
            AsymmetricAlgorithm::Ecc => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(name_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(auth_policy).map_err(
                    |source| TpmError::TSSDigestFromAuthPolicyError {
                        source,
                    },
                )?)
                .with_ecc_parameters(
                    PublicEccParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(
                            name_alg,
                        )))
                        .with_curve(curve_id)
                        .with_key_derivation_function_scheme(
                            KeyDerivationFunctionScheme::Null,
                        )
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.restricted())
                        .build()
                        .map_err(|source| {
                            TpmError::TSSPublicECCParametersBuildError {
                                source,
                            }
                        })?,
                )
                .with_ecc_unique_identifier(EccPoint::new(
                    EccParameter::try_from(&UNIQUE_IAK[0..3]).map_err(
                        |source| TpmError::TSSECCParameterFromIAKError {
                            source,
                        },
                    )?,
                    EccParameter::try_from(&UNIQUE_IAK[0..3]).map_err(
                        |source| TpmError::TSSECCParameterFromIAKError {
                            source,
                        },
                    )?,
                )),
            AsymmetricAlgorithm::Null => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(
                    Digest::try_from(IAK_AUTH_POLICY_SHA256[0..32].to_vec())
                        .map_err(|source| {
                            TpmError::TSSDigestFromAuthPolicyError { source }
                        })?,
                )
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(RsaKeyBits::Rsa2048)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.decrypt())
                        .build()
                        .map_err(|source| {
                            TpmError::TSSPublicRSAParametersBuildError {
                                source,
                            }
                        })?,
                )
                .with_rsa_unique_identifier(
                    PublicKeyRsa::try_from(&UNIQUE_IAK[0..3]).map_err(
                        |source| TpmError::TSSPublicKeyFromIAK { source },
                    )?,
                ),
        };

        Ok(IAKPublic {
            public: key_builder
                .build()
                .map_err(|source| TpmError::TSSIAKKeyBuildError { source })?,
        })
    }

    /// Creates an empty authentication session
    fn create_empty_session(
        &mut self,
        ctx: &mut tss_esapi::Context,
        ses_type: SessionType,
        symmetric: SymmetricDefinition,
        hash_alg: HashingAlgorithm,
    ) -> Result<AuthSession> {
        let Some(session) = ctx
            .start_auth_session(
                None, None, None, ses_type, symmetric, hash_alg,
            )
            .map_err(|source| {
                TpmError::TSSStartAuthenticationSessionError { source }
            })?
        else {
            return Err(TpmError::EmptyAuthenticationSessionError);
        };

        let (ses_attrs, ses_attrs_mask) = SessionAttributesBuilder::new()
            .with_encrypt(true)
            .with_decrypt(true)
            .build();

        ctx.tr_sess_set_attributes(session, ses_attrs, ses_attrs_mask)
            .map_err(|source| TpmError::TSSSessionSetAttributesError {
                source,
            })?;
        Ok(session)
    }

    /// Activates credentials with given secret `keyblob`, AK, and EK.
    pub fn activate_credential(
        &mut self,
        keyblob: Vec<u8>,
        ak: KeyHandle,
        ek: KeyHandle,
    ) -> Result<Digest> {
        let mut ctx = self.inner.lock().unwrap(); //#[allow_ci]

        let (credential, secret) = parse_cred_and_secret(keyblob)?;
        let mut policy_digests = DigestList::new();
        let (parent_public, _, _) = ctx.read_public(ek)?;
        let ek_hash_alg = parent_public.name_hashing_algorithm();
        let ek_symmetric =
            parent_public.symmetric_algorithm().ok_or_else(|| {
                TpmError::TSSReadPublicError {
                    source: tss_esapi::Error::WrapperError(
                        tss_esapi::WrapperErrorKind::InvalidParam,
                    ),
                }
            })?;
        match ek_hash_alg {
            HashingAlgorithm::Sha384 => {
                policy_digests
                    .add(Digest::try_from(POLICY_A_SHA384.as_slice())?)?;
                policy_digests
                    .add(Digest::try_from(POLICY_C_SHA384.as_slice())?)?;
            }
            HashingAlgorithm::Sha512 => {
                policy_digests
                    .add(Digest::try_from(POLICY_A_SHA512.as_slice())?)?;
                policy_digests
                    .add(Digest::try_from(POLICY_C_SHA512.as_slice())?)?;
            }
            HashingAlgorithm::Sm3_256 => {
                policy_digests
                    .add(Digest::try_from(POLICY_A_SM3_256.as_slice())?)?;
                policy_digests
                    .add(Digest::try_from(POLICY_C_SM3_256.as_slice())?)?;
            }
            _ => (),
        };

        let ek_auth = self.create_empty_session(
            &mut ctx,
            SessionType::Policy,
            ek_symmetric.into(),
            ek_hash_alg,
        )?;

        // We authorize session according to the EK profile spec
        let result = ctx
            .execute_with_temporary_object(
                SessionHandle::from(ek_auth).into(),
                |ctx, _| {
                    let _ = ctx.execute_with_nullauth_session(|ctx| {
                        ctx.policy_secret(
                            PolicySession::try_from(ek_auth)?,
                            AuthHandle::Endorsement,
                            Default::default(),
                            Default::default(),
                            Default::default(),
                            None,
                        )
                    })?;
                    if !policy_digests.is_empty() {
                        ctx.policy_or(
                            PolicySession::try_from(ek_auth)?,
                            policy_digests,
                        )?
                    }
                    ctx.execute_with_sessions(
                        (Some(AuthSession::Password), Some(ek_auth), None),
                        |ctx| {
                            ctx.activate_credential(
                                ak, ek, credential, secret,
                            )
                        },
                    )
                },
            )
            .map_err(TpmError::from);

        // Clear sessions after use
        ctx.clear_sessions();

        result
    }

    /// This function certifies an attestation key with the IAK, using any qualifying data provided,
    /// producing an attestation document and signature
    pub fn certify_credential_with_iak(
        &mut self,
        qualifying_data: Data,
        ak: KeyHandle,
        iak: KeyHandle,
    ) -> Result<(Attest, Signature)> {
        let mut ctx = self.inner.lock().unwrap(); //#[allow_ci]

        let result = ctx
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |context| {
                    context.certify(
                        ak.into(),
                        iak,
                        qualifying_data,
                        SignatureScheme::Null,
                    )
                },
            )
            .map_err(TpmError::from);

        // Clear sessions after use
        ctx.clear_sessions();

        result
    }

    /// This function extends PCR#16 with the digest, then creates a PcrList
    /// from the given mask and PCR#16.
    fn build_pcr_list(
        &mut self,
        digest: DigestValues,
        mask: u32,
        hash_alg: HashingAlgorithm,
    ) -> Result<PcrSelectionList> {
        // extend digest into pcr16
        self.inner
            .lock()
            .unwrap() //#[allow_ci]
            .execute_with_nullauth_session(|ctx| {
                ctx.pcr_reset(PcrHandle::Pcr16)?;
                ctx.pcr_extend(PcrHandle::Pcr16, digest.to_owned())
            })?;

        // translate mask to vec of pcrs
        let mut pcrs = read_mask(mask)?;

        // add pcr16 if it isn't in the vec already
        if !pcrs.contains(&PcrSlot::Slot16) {
            let mut slot16 = vec![PcrSlot::Slot16];
            pcrs.append(&mut slot16);
        }

        let mut pcrlist = PcrSelectionListBuilder::new();
        pcrlist = pcrlist.with_selection(hash_alg, &pcrs);
        let pcrlist = pcrlist.build()?;

        Ok(pcrlist)
    }

    /// Calculates a TPM quote of `nonce` over PCRs indicated with `mask`.
    ///
    /// `mask` is a `u32` value, e.g., 0x408000, translating bits that
    /// are set to PCRs to include in the list. The LSB in the mask
    /// corresponds to PCR#0. Note that PCR#16 is always included even
    /// if the bit is not set in `mask`.
    pub fn quote(
        &mut self,
        nonce: &[u8],
        mask: u32,
        pubkey: &PKeyRef<Public>,
        ak_handle: KeyHandle,
        hash_alg: HashAlgorithm,
        sign_alg: SignAlgorithm,
    ) -> Result<String> {
        let nk_digest = pubkey_to_tpm_digest(pubkey, hash_alg)?;

        let pcrlist =
            self.build_pcr_list(nk_digest, mask, hash_alg.into())?;

        let mut ctx = self.inner.lock().unwrap(); //#[allow_ci]

        let (attestation, sig, pcrs_read, pcr_data) = ctx
            .execute_with_nullauth_session(|ctx| {
                perform_quote_and_pcr_read(
                    ctx,
                    ak_handle,
                    nonce,
                    pcrlist,
                    sign_alg.to_signature_scheme(hash_alg),
                    hash_alg.into(),
                )
            })?;

        encode_quote_string(attestation, sig, pcrs_read, pcr_data)
    }

    /// Get the name of the object
    pub fn get_name(&mut self, handle: ObjectHandle) -> Result<Name> {
        self.inner
            .lock()
            .unwrap() //#[allow_ci]
            .tr_get_name(handle)
            .map_err(|source| TpmError::TSSGetNameError { source })
    }

    /// Make credential: encrypt a challenge which can only be decrypted using the corresponding
    /// private EK and AK name
    ///
    /// This will return a blob encoded following the tpm2-tools format:
    ///
    /// BLOB = TSS_MAGIC (0xBADCCODE) + BLOB_VERSION +
    ///        len(CREDENTIAL) + CREDENTIAL +
    ///        len(SECRET) + SECRET
    ///
    /// All the lengths are big endian encoded
    pub fn make_credential(
        &mut self,
        ek_handle: KeyHandle,
        credential: Digest,
        name: Name,
    ) -> Result<Vec<u8>> {
        let (credential, secret) = self
            .inner
            .lock()
            .unwrap() //#[allow_ci]
            .make_credential(ek_handle, credential, name)
            .map_err(|source| TpmError::TSSMakeCredentialError { source })?;

        let mut blob = Vec::new();

        // tpm2-tools specific header, added to keep compatibility
        blob.extend(TSS_MAGIC.to_be_bytes());
        // blob version number, should be 1
        blob.extend(u32::to_be_bytes(1));

        // Append big endian encoded credential length followed by the credential
        let cred_len: u16 =
            credential.len().try_into().map_err(TpmError::TryFromInt)?;
        blob.extend(cred_len.to_be_bytes());
        blob.extend(credential.as_slice());

        // Append big endian encoded secret length followed by the secret
        let secret_len: u16 =
            secret.len().try_into().map_err(TpmError::TryFromInt)?;
        blob.extend(secret_len.to_be_bytes());
        blob.extend(secret.as_slice());

        Ok(blob)
    }

    /// Flush object handle context
    ///
    /// # Arguments:
    ///
    /// * handle (ObjectHandle): The object handle to flush
    pub fn flush_context(&mut self, handle: ObjectHandle) -> Result<()> {
        self.inner
            .lock()
            .unwrap() //#[allow_ci]
            .flush_context(handle)
            .map_err(|source| TpmError::TSSFlushContext { source })
    }

    /// Set authentication to object handle
    ///
    /// # Arguments:
    ///
    /// * handle (ObjectHandle): Object handle
    /// * auth (Auth): Authentication to set to the handle
    pub fn tr_set_auth(
        &mut self,
        handle: ObjectHandle,
        auth: Auth,
    ) -> Result<()> {
        self.inner
            .lock()
            .unwrap() //#[allow_ci]
            .tr_set_auth(handle, auth)
            .map_err(|source| TpmError::TSSTrSetAuth { source })
    }

    /// Verify signature
    ///
    /// # Arguments:
    ///
    /// * key_handle (KeyHandle): The public key handle
    /// * digest (Digest): The signed Digest
    /// * signature (Signature): The signature to verify
    pub fn verify_signature(
        &mut self,
        key_handle: KeyHandle,
        digest: Digest,
        signature: Signature,
    ) -> Result<VerifiedTicket> {
        self.inner
            .lock()
            .unwrap() //#[allow_ci]
            .verify_signature(key_handle, digest, signature)
            .map_err(|source| TpmError::TSSVerifySign { source })
    }

    /// Get the PCR selection list
    pub fn get_pcr_selection_list(
        &mut self,
        hash_algorithm: HashingAlgorithm,
    ) -> Result<PcrSelectionList> {
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(
                hash_algorithm,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                    PcrSlot::Slot4,
                    PcrSlot::Slot5,
                    PcrSlot::Slot6,
                    PcrSlot::Slot7,
                ],
            )
            .build()
            .map_err(|source| TpmError::TSSPCRSelectionBuildError {
                source,
            })?;
        Ok(pcr_selection_list)
    }

    /// Helper function to extract selected PCR banks from a PcrSelectionList.
    pub fn pcr_banks(
        &mut self,
        expected_hash_algorithm: HashAlgorithm,
    ) -> Result<Vec<u32>> {
        let mut selected_pcr_numbers: Vec<u32> = Vec::new();
        let hashing_algorithm = crate::algorithms::hash_to_hashing_algorithm(
            expected_hash_algorithm,
        );
        let pcr_selection_list =
            self.get_pcr_selection_list(hashing_algorithm)?;
        for selection in pcr_selection_list.get_selections() {
            if selection.hashing_algorithm() == hashing_algorithm {
                let selected_slots = selection.selected();
                for pcr_slot in selected_slots {
                    let pcr_mask_value: u32 = pcr_slot.into();
                    if pcr_mask_value > 0 {
                        let pcr_index = pcr_mask_value.trailing_zeros();
                        selected_pcr_numbers.push(pcr_index);
                    }
                }
                let mut sorted_pcr_numbers: Vec<u32> =
                    selected_pcr_numbers.into_iter().collect();
                sorted_pcr_numbers.sort_unstable();
                return Ok(sorted_pcr_numbers);
            }
        }
        Err(TpmError::TSSPCRSelectionBuildError {
            source: tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::InvalidParam,
            ),
        })
    }

    /// Queries the TPM and returns a list of the supported hashing algorithms.
    pub fn get_supported_hash_algorithms(
        &mut self,
    ) -> Result<Vec<KeylimeInternalHashAlgorithm>> {
        let mut ctx = self.inner.lock().unwrap(); //#[allow_ci]

        const MAX_ALGS_TO_QUERY: u32 = 128;
        let (capability_data, _more) = ctx
            .get_capability(CapabilityType::Algorithms, 0, MAX_ALGS_TO_QUERY)
            .map_err(TpmError::from)?;

        let mut supported_algs = Vec::new();
        if let CapabilityData::Algorithms(alg_list) = capability_data {
            for alg_prop in alg_list.iter() {
                // Get the attributes using the correct public method
                let attributes = alg_prop.algorithm_properties();

                // Filter for algorithms that have the 'hashing' attribute set
                if attributes.hash() {
                    // Get the algorithm identifier using the correct public method
                    let tss_public_alg = alg_prop.algorithm_identifier();

                    if let Ok(tss_hash_alg) =
                        TssEsapiHashingAlgorithm::try_from(tss_public_alg)
                    {
                        if let Ok(keylime_alg) =
                            KeylimeInternalHashAlgorithm::try_from(
                                tss_hash_alg,
                            )
                        {
                            supported_algs.push(keylime_alg);
                        }
                    }
                }
            }
        }
        Ok(supported_algs)
    }

    /// Queries the TPM and returns a list of signing algorithms supported by your application.
    pub fn get_supported_signing_algorithms(
        &mut self,
    ) -> Result<Vec<KeylimeInternalSignAlgorithm>> {
        let mut ctx = self.inner.lock().unwrap(); //#[allow_ci]

        const MAX_ALGS_TO_QUERY: u32 = 128;
        let (capability_data, _more) = ctx
            .get_capability(CapabilityType::Algorithms, 0, MAX_ALGS_TO_QUERY)
            .map_err(TpmError::from)?;

        let mut supported_algs = Vec::new();

        if let CapabilityData::Algorithms(alg_list) = capability_data {
            for alg_prop in alg_list.iter() {
                let attributes = alg_prop.algorithm_properties();
                if attributes.asymmetric() && attributes.signing() {
                    let algorithm_id = alg_prop.algorithm_identifier();
                    match algorithm_id {
                        AlgorithmIdentifier::RsaSsa => {
                            supported_algs
                                .push(KeylimeInternalSignAlgorithm::RsaSsa);
                        }
                        AlgorithmIdentifier::RsaPss => {
                            supported_algs
                                .push(KeylimeInternalSignAlgorithm::RsaPss);
                        }
                        AlgorithmIdentifier::EcDsa => {
                            supported_algs
                                .push(KeylimeInternalSignAlgorithm::EcDsa);
                        }
                        AlgorithmIdentifier::EcSchnorr => {
                            supported_algs.push(
                                KeylimeInternalSignAlgorithm::EcSchnorr,
                            );
                        }
                        _ => {} // Ignore other types
                    }
                }
            }
        }
        supported_algs.sort_unstable_by_key(|a| format!("{:?}", a));
        supported_algs.dedup();

        Ok(supported_algs)
    }

    /// Wrapper for get_supported_hash_algorithms that returns the results as a vector of strings.
    pub fn get_supported_hash_algorithms_as_strings(
        &mut self,
    ) -> Result<Vec<String>> {
        let supported_algs: Vec<KeylimeInternalHashAlgorithm> =
            self.get_supported_hash_algorithms()?;
        let alg_strings: Vec<String> =
            supported_algs.iter().map(|alg| alg.to_string()).collect();
        Ok(alg_strings)
    }

    /// Wrapper for get_supported_signing_algorithms that returns the results as a vector of strings.
    pub fn get_supported_signing_algorithms_as_strings(
        &mut self,
    ) -> Result<Vec<String>> {
        let supported_algs: Vec<KeylimeInternalSignAlgorithm> =
            self.get_supported_signing_algorithms()?;
        let alg_strings: Vec<String> =
            supported_algs.iter().map(|alg| alg.to_string()).collect();

        Ok(alg_strings)
    }
}

// Ensure that TPML_PCR_SELECTION and TPML_DIGEST have known sizes
assert_eq_size!(TPML_PCR_SELECTION, [u8; 132]);
assert_eq_size!(TPML_DIGEST, [u8; 532]);

/// Serialize a TPML_PCR_SELECTION into a Vec<u8>
/// The serialization will adjust the data endianness as necessary and add paddings to keep the
/// memory aligment.
fn serialize_pcrsel(pcr_selection: &TPML_PCR_SELECTION) -> Vec<u8> {
    let mut output = Vec::with_capacity(TPML_PCR_SELECTION_SIZE);
    output.extend(u32::to_le_bytes(pcr_selection.count));
    for selection in pcr_selection.pcrSelections.iter() {
        output.extend(selection.hash.to_le_bytes());
        output.extend(selection.sizeofSelect.to_le_bytes());
        output.extend(selection.pcrSelect);
        output.extend([0u8; 1]); // padding to keep the memory alignment
    }
    output
}

// Serialize a TPML_DIGEST into a Vec<u8>
// The serialization will adjust the data endianness as necessary.
fn serialize_digest(digest_list: &TPML_DIGEST) -> Vec<u8> {
    let mut output = Vec::with_capacity(TPML_DIGEST_SIZE);
    output.extend(u32::to_le_bytes(digest_list.count));
    for digest in digest_list.digests.iter() {
        output.extend(digest.size.to_le_bytes());
        output.extend(digest.buffer);
    }
    output
}

// Recreate how tpm2-tools creates the PCR out file. Roughly, this is a
// TPML_PCR_SELECTION + number of TPML_DIGESTS + TPML_DIGESTs.
// Reference:
// https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_quote.c#L47-L91
//
// Note: tpm2-tools does not use its own documented marshaling functions for this output,
// so the below code recreates the idiosyncratic format tpm2-tools expects. The lengths
// of the vectors were determined by introspection into running tpm2-tools code. This is
// not ideal, and we should aim to move away from it if possible.
fn pcrdata_to_vec(
    selection_list: PcrSelectionList,
    pcrdata: PcrData,
) -> Vec<u8> {
    const DIGEST_SIZE: usize = std::mem::size_of::<TPML_DIGEST>();

    let pcrsel: TPML_PCR_SELECTION = selection_list.into();
    let pcrsel_vec = serialize_pcrsel(&pcrsel);

    let digest: Vec<TPML_DIGEST> = pcrdata.into();
    let num_tpml_digests = digest.len() as u32;
    let mut digest_vec = Vec::with_capacity(digest.len() * DIGEST_SIZE);

    for d in digest {
        let vec = serialize_digest(&d);
        digest_vec.extend(vec);
    }

    let mut data_vec =
        Vec::with_capacity(pcrsel_vec.len() + 4 + digest_vec.len());

    data_vec.extend(&pcrsel_vec);
    data_vec.extend(num_tpml_digests.to_le_bytes());
    data_vec.extend(&digest_vec);

    data_vec
}

const TSS_MAGIC: u32 = 3135029470;

/// Parse credential and encrypted secret from the MakeCredential keyblob
fn parse_cred_and_secret(
    keyblob: Vec<u8>,
) -> Result<(IdObject, EncryptedSecret)> {
    let magic =
        u32::from_be_bytes(keyblob[0..4].try_into().map_err(|_| {
            TpmError::KeyblobParseMagicNumberError {
                header: keyblob[0..4].into(),
            }
        })?);
    let version =
        u32::from_be_bytes(keyblob[4..8].try_into().map_err(|_| {
            TpmError::KeyblobParseVersionError {
                header: keyblob[4..8].into(),
            }
        })?);

    if magic != TSS_MAGIC {
        return Err(TpmError::KeyblobInvalidMagicNumber {
            expected: TSS_MAGIC,
            got: magic,
        });
    }

    if version != 1 {
        return Err(TpmError::InvalidKeyblobVersion {
            expected: 1,
            got: version,
        });
    }

    let credsize =
        u16::from_be_bytes(keyblob[8..10].try_into().map_err(|_| {
            TpmError::KeyblobParseCredSizeError {
                value: keyblob[8..10].into(),
            }
        })?);

    let _secretsize = u16::from_be_bytes(
        keyblob[(10 + credsize as usize)..(12 + credsize as usize)]
            .try_into()
            .map_err(|_| TpmError::KeyblobParseSecreSizeError {
                value: keyblob
                    [(10 + credsize as usize)..(12 + credsize as usize)]
                    .into(),
            })?,
    );

    let credential = &keyblob[10..(10 + credsize as usize)];
    let secret = &keyblob[(12 + credsize as usize)..];

    let credential = IdObject::try_from(credential)
        .map_err(|_| TpmError::KeyblobParseCredential)?;
    let secret = EncryptedSecret::try_from(secret)
        .map_err(|_| TpmError::KeyblobParseEncryptedSecret)?;

    Ok((credential, secret))
}

/// Takes a public PKey and returns a DigestValue of it.
fn pubkey_to_tpm_digest<T: HasPublic>(
    pubkey: &PKeyRef<T>,
    hash_algo: HashAlgorithm,
) -> Result<DigestValues> {
    let mut keydigest = DigestValues::new();

    let keybytes = match pubkey.id() {
        Id::RSA => pubkey
            .rsa()
            .map_err(|source| TpmError::OpenSSLRSAFromPKey { source })?
            .public_key_to_pem()
            .map_err(|source| TpmError::OpenSSLPublicKeyToPEM { source })?,
        other_id => {
            return Err(TpmError::NotImplemented(format!(
                "Converting to digest value for key type {other_id:?}"
            )));
        }
    };

    let hashing_algo = HashingAlgorithm::from(hash_algo);
    let mut hasher =
        Hasher::new(hash_alg_to_message_digest(hashing_algo)?)
            .map_err(|source| TpmError::OpenSSLHasherNew { source })?;
    hasher
        .update(&keybytes)
        .map_err(|source| TpmError::OpenSSLHasherUpdate { source })?;
    let hashvec = hasher
        .finish()
        .map_err(|source| TpmError::OpenSSLHasherFinish { source })?;
    keydigest.set(
        hashing_algo,
        Digest::try_from(hashvec.as_ref())
            .map_err(|source| TpmError::TSSDigestFromValue { source })?,
    );

    Ok(keydigest)
}

/// Reads a mask indicating PCRs to include in a Quote.
///
/// The masks are sent from the tenant and cloud verifier to indicate
/// the PCRs to include in a Quote. The LSB in the mask corresponds to
/// PCR0. For example, keylime-agent.conf specifies PCRs 15 and 22 under
/// [tenant][tpm_policy]. As a bit mask, this would be represented as
/// 0b010000001000000000000000, which translates to 0x408000.
///
/// The mask is a string because it is sent as a string from the tenant
/// and verifier. The output from this function can be used to call a
/// Quote from the TSS ESAPI.
fn read_mask(mask: u32) -> Result<Vec<PcrSlot>> {
    let mut pcrs = Vec::new();

    // check which bits are set
    for i in 0..32 {
        if mask & (1 << i) != 0 {
            pcrs.push(
                match i {
                    0 => PcrSlot::Slot0,
                    1 => PcrSlot::Slot1,
                    2 => PcrSlot::Slot2,
                    3 => PcrSlot::Slot3,
                    4 => PcrSlot::Slot4,
                    5 => PcrSlot::Slot5,
                    6 => PcrSlot::Slot6,
                    7 => PcrSlot::Slot7,
                    8 => PcrSlot::Slot8,
                    9 => PcrSlot::Slot9,
                    10 => PcrSlot::Slot10,
                    11 => PcrSlot::Slot11,
                    12 => PcrSlot::Slot12,
                    13 => PcrSlot::Slot13,
                    14 => PcrSlot::Slot14,
                    15 => PcrSlot::Slot15,
                    16 => PcrSlot::Slot16,
                    17 => PcrSlot::Slot17,
                    18 => PcrSlot::Slot18,
                    19 => PcrSlot::Slot19,
                    20 => PcrSlot::Slot20,
                    21 => PcrSlot::Slot21,
                    22 => PcrSlot::Slot22,
                    23 => PcrSlot::Slot23,
                    bit => return Err(TpmError::MalformedPCRSelectionMask(format!("only pcrs 0-23 can be included in integrity quote, but mask included pcr {bit:?}"))),
                },
            )
        }
    }

    Ok(pcrs)
}

/// Checks if `pcr` is included in `mask`.
pub fn check_mask(mask: u32, pcr: &PcrSlot) -> Result<bool> {
    let selected_pcrs = read_mask(mask)?;
    Ok(selected_pcrs.contains(pcr))
}

/// This encodes a quote string as input to Python Keylime's quote checking functionality.
/// The quote, signature, and pcr blob are concatenated with ':' separators. To match the
/// expected format, the quote, signature, and pcr blob must be base64 encoded before concatenation.
///
/// Reference:
/// https://github.com/keylime/keylime/blob/2dd9e5c968f33bf77110092af9268d13db1806c6 \
/// /keylime/tpm/tpm_main.py#L964-L975
fn encode_quote_string(
    att: Attest,
    sig: Signature,
    pcrs_read: PcrSelectionList,
    pcr_data: PcrData,
) -> Result<String> {
    // marshal structs to vec in expected formats. these formats are
    // dictated by tpm2_tools.
    let att_vec = att
        .marshall()
        .map_err(|source| TpmError::TSSMarshallAttestError { source })?;
    let sig_vec = sig
        .marshall()
        .map_err(|source| TpmError::TSSMarshallSignatureError { source })?;
    let pcr_vec = pcrdata_to_vec(pcrs_read, pcr_data);

    // base64 encoding
    let att_str = general_purpose::STANDARD.encode(att_vec);
    let sig_str = general_purpose::STANDARD.encode(sig_vec);
    let pcr_str = general_purpose::STANDARD.encode(pcr_vec);

    // create concatenated string
    let mut quote = String::new();
    quote.push('r');
    quote.push_str(&att_str);
    quote.push(':');
    quote.push_str(&sig_str);
    quote.push(':');
    quote.push_str(&pcr_str);

    Ok(quote)
}

/// The pcr blob corresponds to the pcr out file that records the list of PCR values,
/// specified by tpm2tools, ex. 'tpm2_quote ... -o <pcrfilename>'. Read more here:
/// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_quote.1.md
///
/// It is required by Python Keylime's check_quote functionality. For how the quote is
/// checked, see:
/// https://github.com/keylime/keylime/blob/2dd9e5c968f33bf77110092af9268d13db1806c6/ \
/// keylime/tpm/tpm_main.py#L990
///
/// For how the quote is created, see:
/// https://github.com/keylime/keylime/blob/2dd9e5c968f33bf77110092af9268d13db1806c6/ \
/// keylime/tpm/tpm_main.py#L965
///
fn make_pcr_blob(
    context: &mut tss_esapi::Context,
    pcrlist: PcrSelectionList,
) -> Result<(PcrSelectionList, PcrData)> {
    let pcr_data = context
        .execute_without_session(|ctx| read_all(ctx, pcrlist.clone()))
        .map_err(|source| TpmError::TSSPCRListError { source })?;
    Ok((pcrlist, pcr_data))
}

/// Takes a TSS ESAPI HashingAlgorithm and returns the corresponding OpenSSL
/// MessageDigest.
fn hash_alg_to_message_digest(
    hash_alg: HashingAlgorithm,
) -> Result<MessageDigest> {
    match hash_alg {
        HashingAlgorithm::Sha256 => Ok(MessageDigest::sha256()),
        HashingAlgorithm::Sha1 => Ok(MessageDigest::sha1()),
        HashingAlgorithm::Sha384 => Ok(MessageDigest::sha384()),
        HashingAlgorithm::Sha512 => Ok(MessageDigest::sha512()),
        HashingAlgorithm::Sm3_256 => Ok(MessageDigest::sm3()),
        other => Err(TpmError::UnsupportedHashingAlgorithm { alg: other }),
    }
}

/// Check if the data attested in the quote matches the data read from the TPM PCRs
fn check_if_pcr_data_and_attestation_match(
    hash_algo: HashingAlgorithm,
    pcr_data: &PcrData,
    attestation: Attest,
) -> Result<bool> {
    let pcr_data = Vec::<TPML_DIGEST>::from(pcr_data.clone());

    let quote_info = match attestation.attested() {
        AttestInfo::Quote { info } => info,
        _ => {
            return Err(TpmError::UnexpectedAttestedType {
                expected: AttestationType::Quote,
                got: attestation.attestation_type(),
            })
        }
    };

    let attested_pcr = quote_info.pcr_digest().value();

    let mut hasher = Hasher::new(hash_alg_to_message_digest(hash_algo)?)
        .map_err(|source| TpmError::OpenSSLHasherNew { source })?;
    for tpml_digest in pcr_data {
        for i in 0..tpml_digest.count {
            let pcr = tpml_digest.digests[i as usize];
            hasher
                .update(&pcr.buffer[..pcr.size as usize])
                .map_err(|source| TpmError::OpenSSLHasherUpdate { source })?;
        }
    }
    let pcr_digest = hasher
        .finish()
        .map_err(|source| TpmError::OpenSSLHasherFinish { source })?;

    log::trace!(
        "Attested to PCR digest: {:?}, read PCR digest: {:?}",
        attested_pcr,
        pcr_digest,
    );

    Ok(memcmp::eq(attested_pcr, &pcr_digest))
}

const NUM_ATTESTATION_ATTEMPTS: i32 = 5;

/// Obtain a quote from the TPM and read the PCRs.
///
/// The attested data is compared with the data read from the PCRs to check if they match before
/// returning the values. This is necessary because the quote generation and the reading of PCR
/// values are performed in separate operations, which may cause deviations due to possible changes
/// in the PCR values between the two operations.
fn perform_quote_and_pcr_read(
    context: &mut tss_esapi::Context,
    ak_handle: KeyHandle,
    nonce: &[u8],
    pcrlist: PcrSelectionList,
    sign_scheme: SignatureScheme,
    hash_alg: HashingAlgorithm,
) -> Result<(Attest, Signature, PcrSelectionList, PcrData)> {
    let nonce: tss_esapi::structures::Data =
        nonce.try_into().map_err(|_| TpmError::DataFromNonce)?;

    for attempt in 0..NUM_ATTESTATION_ATTEMPTS {
        // TSS ESAPI quote does not create pcr blob, so create it separately
        let (pcrs_read, pcr_data) = make_pcr_blob(context, pcrlist.clone())?;

        // create quote
        let (attestation, sig) = context
            .quote(ak_handle, nonce.clone(), sign_scheme, pcrs_read.clone())
            .map_err(|source| TpmError::TSSQuoteError { source })?;

        // Check whether the attestation and pcr_data match
        if check_if_pcr_data_and_attestation_match(
            hash_alg,
            &pcr_data,
            attestation.clone(),
        )? {
            return Ok((attestation, sig, pcrs_read, pcr_data));
        }

        log::info!(
            "PCR data and attestation data mismatched on attempt {}",
            attempt
        );
    }

    log::error!("PCR data and attestation data mismatched on all {} attempts, giving up", NUM_ATTESTATION_ATTEMPTS);
    Err(TpmError::TooManyAttestationMismatches {
        attempts: NUM_ATTESTATION_ATTEMPTS,
    })
}

/// Return the asymmetric and name algorithms, either by matching to a template or using the user
/// specified algorithms
///
/// If the template config option is set to "", "detect" or "default", the template will be matched
/// to the certs
///
/// If a template has been specified, that will be used
///
/// If the option has been set to "manual", or some other not-empty string, the user specified
/// algorithms will be used
///
pub fn get_idevid_template(
    detect_str: &str,
    template_str: &str,
    asym_alg_str: &str,
    name_alg_str: &str,
) -> Result<(AsymmetricAlgorithm, HashingAlgorithm)> {
    let template_str = if ["", "detect", "default"].contains(&template_str) {
        detect_str
    } else {
        template_str
    };
    let (asym_alg, name_alg) = match template_str {
        "H-1" => (AsymmetricAlgorithm::Rsa, HashingAlgorithm::Sha256),
        "H-2" => (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sha256),
        "H-3" => (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sha384),
        "H-4" => (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sha512),
        "H-5" => (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sm3_256),
        _ => (
            EncryptionAlgorithm::try_from(asym_alg_str)?.into(),
            HashingAlgorithm::from(HashAlgorithm::try_from(name_alg_str)?),
        ),
    };
    Ok((asym_alg, name_alg))
}

/// Check if a public key and certificate match
///
/// The provided label is used to generate logging messages
pub fn check_pubkey_match_cert(
    pubkey: &TssPublic,
    certificate: &X509,
    label: &str,
) -> Result<()> {
    if crypto::check_x509_key(certificate, pubkey)? {
        info!("{label} public key matches certificate.");
        Ok(())
    } else {
        error!("{label} public key does not match certificate. Check template in configuration.");
        Err(TpmError::PublicKeyCertificateMismatch(label.to_string()))
    }
}

/// Find certificates (DER format) in binary data and split them
///
/// # Arguments
///
/// `der_data`: Binary data containing certificates in DER format
///
/// # Returns
///
/// 'Vec<Vec<u8>>', a vector ob certificates in DER format
pub fn split_der_certificates(der_data: &[u8]) -> Vec<Vec<u8>> {
    let mut certificates = Vec::new();
    let mut offset = 0;
    while offset < der_data.len() {
        // Check if the current byte indicates the start of a sequence (0x30)
        if der_data[offset] != 0x30 {
            break; // Not a valid certificate start
        }
        // Read the length of the sequence
        let length_byte = der_data[offset + 1];
        let cert_length = if length_byte & 0x80 == 0 {
            // Short form length
            length_byte as usize + 2 // +2 for the tag and length byte
        } else {
            // Long form length
            let length_of_length = (length_byte & 0x7F) as usize;
            let length_bytes =
                &der_data[offset + 2..offset + 2 + length_of_length];
            let cert_length = length_bytes
                .iter()
                .fold(0, |acc, &b| (acc << 8) | b as usize);
            cert_length + 2 + length_of_length // +2 for the tag and length byte
        };
        // Extract the certificate
        let cert = der_data[offset..offset + cert_length].to_vec();
        certificates.push(cert);
        // Move the offset to the next certificate
        offset += cert_length;
    }
    certificates
}

/// Convert a vector of der certificates into a single string with all certificates in PEM format.
///
/// # Arguments
///
/// `der_certificates`: Vector of certificates in DER format
///
/// # Returns
///
/// A `String` containing all concatenated certificates in PEM format (order is maintained)
pub fn der_to_pem(
    der_certificates: Vec<Vec<u8>>,
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let mut pem_string = String::new();
    for der in der_certificates.iter().rev() {
        // Convert DER to X509
        let cert = X509::from_der(der)?;
        // Convert X509 to PEM format
        let pem = cert.to_pem()?;
        // Append the PEM string to the result
        pem_string.push_str(&String::from_utf8(pem)?);
    }
    Ok(pem_string)
}

/// Read certificate chain from TPM.
///
/// Read content of NV Handle 0x01c00100 - 0x01c001ff
///
/// # Returns
///
/// `Vec<u8>', binary data of certificate chain
pub fn read_ek_ca_chain(
    context: &mut tss_esapi::Context,
) -> tss_esapi::Result<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();

    // Get handles for NV-Index in range 0x01c00100 - 0x01c001ff
    let (capabilities, _) = context.get_capability(
        CapabilityType::Handles,
        RSA_EK_CERTIFICATE_CHAIN_START,
        RSA_EK_CERTIFICATE_CHAIN_END - RSA_EK_CERTIFICATE_CHAIN_START,
    )?;

    if let CapabilityData::Handles(handle_list) = capabilities {
        for handle in handle_list.iter() {
            if let TpmHandle::NvIndex(nv_idx) = handle {
                // Attempt to get the NV authorization handle
                let nv_auth_handle =
                    context.execute_without_session(|ctx| {
                        ctx.tr_from_tpm_public(*handle)
                            .map(|v| NvAuth::NvIndex(v.into()))
                    })?;

                // Read the full NV data
                let data = context.execute_with_nullauth_session(|ctx| {
                    nv::read_full(ctx, nv_auth_handle, *nv_idx)
                })?;

                result.extend(data);
            } else {
                // Handle other types of handles if necessary
                break; // Skip non-NvIndex handles
            }
        }
    }

    Ok(result) // Return the accumulated result
}

pub mod testing {

    use super::*;
    #[cfg(feature = "testing")]
    use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
    use tss_esapi::{
        constants::structure_tags::StructureTag,
        structures::{Attest, AttestBuffer, DigestList},
        tss2_esys::{
            Tss2_MU_TPMT_SIGNATURE_Unmarshal, TPM2B_ATTEST, TPM2B_DIGEST,
            TPMS_PCR_SELECTION, TPMT_SIGNATURE,
        },
    };

    #[cfg(feature = "testing")]
    pub static MUTEX: OnceLock<Arc<AsyncMutex<()>>> = OnceLock::new();

    macro_rules! create_unmarshal_fn {
        ($func:ident, $tpmobj:ty, $unmarshal:ident) => {
            fn $func(val: &[u8]) -> Result<$tpmobj> {
                let mut resp = <$tpmobj>::default();
                let mut offset = 0;

                unsafe {
                    let res = $unmarshal(
                        val[..].as_ptr(),
                        val.len().try_into()?,
                        &mut offset,
                        &mut resp,
                    );
                    if res != 0 {
                        return Err(TpmError::Other(format!(
                            "Error converting"
                        )));
                    }
                }
                Ok(resp)
            }
        };
    }

    create_unmarshal_fn!(
        vec_to_sig,
        TPMT_SIGNATURE,
        Tss2_MU_TPMT_SIGNATURE_Unmarshal
    );

    /// Initialize testing mutex
    #[cfg(feature = "testing")]
    pub async fn lock_tests<'a>() -> AsyncMutexGuard<'a, ()> {
        MUTEX
            .get_or_init(|| Arc::new(AsyncMutex::new(())))
            .lock()
            .await
    }

    /// Deserialize a TPML_PCR_SELECTION from a &[u8] slice.
    /// The deserialization will adjust the data endianness as necessary.
    fn deserialize_pcrsel(pcrsel_vec: &[u8]) -> Result<TPML_PCR_SELECTION> {
        if pcrsel_vec.len() != TPML_PCR_SELECTION_SIZE {
            return Err(TpmError::InvalidRequest(format!(
                "Unexpected PCR selection size: Expected {} but got {}",
                TPML_PCR_SELECTION_SIZE,
                pcrsel_vec.len()
            )));
        }

        let mut reader = std::io::Cursor::new(pcrsel_vec);
        let mut count_vec = [0u8; 4];
        reader.read_exact(&mut count_vec).map_err(|source| {
            TpmError::IoReadError {
                what: "PCR selection count from slice".into(),
                source,
            }
        })?;
        let count = u32::from_le_bytes(count_vec);

        let mut pcr_selections: [TPMS_PCR_SELECTION; 16] =
            [TPMS_PCR_SELECTION::default(); 16];

        for selection in &mut pcr_selections {
            let mut hash_vec = [0u8; 2];
            reader.read_exact(&mut hash_vec).map_err(|source| {
                TpmError::IoReadError {
                    what: "PCR selection hash from slice".into(),
                    source,
                }
            })?;
            selection.hash = u16::from_le_bytes(hash_vec);

            let mut size_vec = [0u8; 1];
            reader.read_exact(&mut size_vec).map_err(|source| {
                TpmError::IoReadError {
                    what: "PCR selection size from slice".into(),
                    source,
                }
            })?;
            selection.sizeofSelect = u8::from_le_bytes(size_vec);

            reader.read_exact(&mut selection.pcrSelect).map_err(
                |source| TpmError::IoReadError {
                    what: "PCR selection from slice".into(),
                    source,
                },
            )?;
        }

        Ok(TPML_PCR_SELECTION {
            count,
            pcrSelections: pcr_selections,
        })
    }

    // Deserialize a TPML_DIGEST from a &[u8] slice.
    // The deserialization will adjust the data endianness as necessary.
    fn deserialize_digest(digest_vec: &[u8]) -> Result<TPML_DIGEST> {
        if digest_vec.len() != TPML_DIGEST_SIZE {
            return Err(TpmError::InvalidRequest(format!(
                "Unexpected digest size: Expected {} but got {}",
                TPML_DIGEST_SIZE,
                digest_vec.len()
            )));
        }

        let mut reader = std::io::Cursor::new(digest_vec);
        let mut count_vec = [0u8; 4];

        reader.read_exact(&mut count_vec).map_err(|source| {
            TpmError::IoReadError {
                what: "Digest count from slice".into(),
                source,
            }
        })?;
        let count = u32::from_le_bytes(count_vec);

        let mut digests: [TPM2B_DIGEST; 8] = [TPM2B_DIGEST::default(); 8];

        for digest in &mut digests {
            let mut size_vec = [0u8; 2];
            reader.read_exact(&mut size_vec).map_err(|source| {
                TpmError::IoReadError {
                    what: "Digest size from slice".into(),
                    source,
                }
            })?;
            digest.size = u16::from_le_bytes(size_vec);
            reader.read_exact(&mut digest.buffer).map_err(|source| {
                TpmError::IoReadError {
                    what: "Digest from slice".into(),
                    source,
                }
            })?;
        }

        Ok(TPML_DIGEST { count, digests })
    }

    fn vec_to_pcrdata(val: &[u8]) -> Result<(PcrSelectionList, PcrData)> {
        let mut reader = std::io::Cursor::new(val);
        let mut pcrsel_vec = [0u8; TPML_PCR_SELECTION_SIZE];
        reader.read_exact(&mut pcrsel_vec).map_err(|source| {
            TpmError::IoReadError {
                what: "PCR selection size from slice".into(),
                source,
            }
        })?;

        let pcrsel = deserialize_pcrsel(&pcrsel_vec)?;
        let pcrlist: PcrSelectionList = pcrsel.try_into()?;

        let mut count_vec = [0u8; 4];
        reader.read_exact(&mut count_vec).map_err(|source| {
            TpmError::IoReadError {
                what: "PCR selection count from slice".into(),
                source,
            }
        })?;
        let count = u32::from_le_bytes(count_vec);
        // Always 1 PCR digest should follow
        if count != 1 {
            return Err(TpmError::InvalidRequest(format!(
                "Expected 1 PCR digest, got {}",
                count
            )));
        }

        let mut digest_vec = [0u8; TPML_DIGEST_SIZE];
        reader.read_exact(&mut digest_vec).map_err(|source| {
            TpmError::IoReadError {
                what: "Digest from slice".into(),
                source,
            }
        })?;
        let digest = deserialize_digest(&digest_vec)?;
        let mut digest_list = DigestList::new();
        for i in 0..digest.count {
            digest_list.add(digest.digests[i as usize].try_into()?)?;
        }

        let pcrdata = PcrData::create(&pcrlist, &digest_list)?;
        Ok((pcrlist, pcrdata))
    }

    pub fn decode_quote_string(
        quote: &str,
    ) -> Result<(AttestBuffer, Signature, PcrSelectionList, PcrData)> {
        if !quote.starts_with('r') {
            return Err(TpmError::InvalidRequest(
                "Quote string should start with 'r'".into(),
            ));
        }
        // extract components from the concatenated string
        let mut split = quote[1..].split(':');
        let att_str = split.next().ok_or(TpmError::InvalidRequest(
            "Malformed quote string, could not parse quote".into(),
        ))?;
        let sig_str = split.next().ok_or(TpmError::InvalidRequest(
            "Malformed quote string, could not parse signature".into(),
        ))?;
        let pcr_str = split.next().ok_or(TpmError::InvalidRequest(
            "Malformed quote string, could not parse the PCR blob".into(),
        ))?;

        // base64 decoding
        let att_comp_finished = general_purpose::STANDARD.decode(att_str)?;
        let sig_comp_finished = general_purpose::STANDARD.decode(sig_str)?;
        let pcr_comp_finished = general_purpose::STANDARD.decode(pcr_str)?;

        let sig: Signature = vec_to_sig(&sig_comp_finished)?.try_into()?;
        let (pcrsel, pcrdata) = vec_to_pcrdata(&pcr_comp_finished)?;

        let mut att = TPM2B_ATTEST {
            size: att_comp_finished.len().try_into()?,
            ..Default::default()
        };
        att.attestationData[0..att_comp_finished.len()]
            .copy_from_slice(&att_comp_finished);
        Ok((att.try_into()?, sig, pcrsel, pcrdata))
    }

    /// This performs the same checks as in tpm2_checkquote, namely:
    /// signature, nonce, and PCR digests from the quote.
    ///
    /// Reference:
    /// https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_checkquote.c
    pub fn check_quote(
        context: &mut Context,
        ak_handle: KeyHandle,
        quote: &str,
        nonce: &[u8],
    ) -> Result<()> {
        let (att, sig, pcrsel, pcrdata) = decode_quote_string(quote)?;

        // Verify the signature matches message digest. We do not
        // bother unmarshalling the AK to OpenSSL PKey, but just use
        // Esys_VerifySignature with loaded AK
        let mut hasher = Hasher::new(MessageDigest::sha256())
            .map_err(|source| TpmError::OpenSSLHasherNew { source })?;
        hasher
            .update(att.value())
            .map_err(|source| TpmError::OpenSSLHasherUpdate { source })?;
        let digest = hasher
            .finish()
            .map_err(|source| TpmError::OpenSSLHasherFinish { source })?;
        let digest: Digest = digest.as_ref().try_into().unwrap(); //#[allow_ci]
        match context.verify_signature(ak_handle, digest, sig) {
            Ok(ticket) if ticket.tag() == StructureTag::Verified => {}
            _ => {
                return Err(TpmError::Other(
                    "unable to verify quote signature".to_string(),
                ))
            }
        }

        // Ensure nonce is the same as given
        let attestation: Attest = att.try_into()?;
        if attestation.extra_data().value() != nonce {
            return Err(TpmError::Other("nonce does not match".to_string()));
        }

        // Also ensure digest from quote matches PCR digest
        let pcrbank = pcrdata
            .pcr_bank(HashingAlgorithm::Sha256)
            .ok_or_else(|| TpmError::Other("no SHA256 bank".to_string()))?;
        let mut hasher = Hasher::new(MessageDigest::sha256())
            .map_err(|source| TpmError::OpenSSLHasherNew { source })?;
        for &sel in pcrsel.get_selections() {
            for i in &sel.selected() {
                if let Some(digest) = pcrbank.get_digest(*i) {
                    hasher.update(digest.value()).map_err(|source| {
                        TpmError::OpenSSLHasherUpdate { source }
                    })?;
                }
            }
        }
        let digest = hasher
            .finish()
            .map_err(|source| TpmError::OpenSSLHasherFinish { source })?;
        let quote_info = match attestation.attested() {
            AttestInfo::Quote { info } => info,
            _ => {
                return Err(TpmError::Other(format!(
                    "Expected attestation type TPM2_ST_ATTEST_QUOTE, got {:?}",
                    attestation.attestation_type()
                )));
            }
        };
        if quote_info.pcr_digest().value() != digest.as_ref() {
            return Err(TpmError::Other(
                "PCR digest does not match".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[cfg(feature = "testing")]
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        path::Path,
    };

    #[test]
    fn test_pubkey_to_digest() {
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;

        let rsa = Rsa::generate(2048).unwrap(); //#[allow_ci]
        let pkey = PKey::from_rsa(rsa).unwrap(); //#[allow_ci]

        assert!(pubkey_to_tpm_digest(pkey.as_ref(), HashAlgorithm::Sha256)
            .is_ok());
    }

    #[test]
    fn test_mask() {
        assert_eq!(read_mask(0x0).unwrap(), vec![]); //#[allow_ci]

        assert_eq!(read_mask(0x1).unwrap(), vec![PcrSlot::Slot0]); //#[allow_ci]

        assert_eq!(read_mask(0x2).unwrap(), vec![PcrSlot::Slot1]); //#[allow_ci]

        assert_eq!(read_mask(0x4).unwrap(), vec![PcrSlot::Slot2]); //#[allow_ci]

        assert_eq!(
            read_mask(0x5).unwrap(), //#[allow_ci]
            vec![PcrSlot::Slot0, PcrSlot::Slot2]
        );

        assert_eq!(
            read_mask(0x6).unwrap(), //#[allow_ci]
            vec![PcrSlot::Slot1, PcrSlot::Slot2]
        );

        assert_eq!(read_mask(0x800000).unwrap(), vec![PcrSlot::Slot23]); //#[allow_ci]

        assert_eq!(
            read_mask(0xffffff).unwrap(), //#[allow_ci]
            vec![
                PcrSlot::Slot0,
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
                PcrSlot::Slot8,
                PcrSlot::Slot9,
                PcrSlot::Slot10,
                PcrSlot::Slot11,
                PcrSlot::Slot12,
                PcrSlot::Slot13,
                PcrSlot::Slot14,
                PcrSlot::Slot15,
                PcrSlot::Slot16,
                PcrSlot::Slot17,
                PcrSlot::Slot18,
                PcrSlot::Slot19,
                PcrSlot::Slot20,
                PcrSlot::Slot21,
                PcrSlot::Slot22,
                PcrSlot::Slot23
            ]
        );

        assert!(read_mask(0x1ffffff).is_err());
    }

    #[test]
    fn test_check_mask() {
        // Test simply reading a mask
        let r = read_mask(0xFFFF);
        assert!(r.is_ok(), "Result: {r:?}");

        // Test with mask containing the PCR
        let should_be_true = check_mask(0xFFFF, &PcrSlot::Slot10)
            .expect("failed to check mask");
        assert!(should_be_true);

        // Test a mask not containing the specific PCR
        let should_be_false = check_mask(0xFFFD, &PcrSlot::Slot1)
            .expect("failed to check mask");
        assert!(!should_be_false);

        // Test that trying a mask with bits not in the range from 0 to 23 fails
        let r = check_mask(1 << 24, &PcrSlot::Slot1);
        assert!(r.is_err());
    }

    #[test]
    fn test_get_idevid_template() {
        let cases = [
            ("H-1", (AsymmetricAlgorithm::Rsa, HashingAlgorithm::Sha256)),
            ("H-2", (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sha256)),
            ("H-3", (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sha384)),
            ("H-4", (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sha512)),
            ("H-5", (AsymmetricAlgorithm::Ecc, HashingAlgorithm::Sm3_256)),
        ];

        for (input, output) in cases {
            let algs = get_idevid_template("manual", input, "", "")
                .expect("failed to get IDevID template");
            assert_eq!(algs, output);
        }

        let auto = ["", "detect", "default"];

        for keyword in auto {
            let algs = get_idevid_template("H-1", keyword, "", "")
                .expect("failed to get IDevID template");
            assert_eq!(
                algs,
                (AsymmetricAlgorithm::Rsa, HashingAlgorithm::Sha256)
            );
        }
    }

    #[test]
    #[cfg(feature = "testing")]
    fn test_quote_encode_decode() {
        let quote_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-data")
            .join("test-quote.txt");

        let f =
            File::open(quote_path).expect("unable to open test-quote.txt");
        let mut f = BufReader::new(f);
        let mut buf = String::new();
        let _ = f.read_line(&mut buf).expect("unable to read quote");
        let buf = buf.trim_end();

        let (att, sig, pcrsel, pcrdata) = testing::decode_quote_string(buf)
            .expect("unable to decode quote");

        let attestation: Attest =
            att.try_into().expect("unable to unmarshal attestation");

        let encoded = encode_quote_string(attestation, sig, pcrsel, pcrdata)
            .expect("unable to encode quote");

        assert_eq!(encoded, buf);
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_create_ek() {
        let _mutex = testing::lock_tests().await;
        let mut ctx = Context::new().unwrap(); //#[allow_ci]
        let algs =
            [EncryptionAlgorithm::Rsa2048, EncryptionAlgorithm::Ecc256];
        // TODO: create persistent handle and add to be tested: Some("0x81000000"),
        let handles = [Some(""), None];

        for alg in algs {
            for handle in handles {
                let r = ctx.create_ek(alg, handle);
                assert!(r.is_ok());
                let ek = r.unwrap(); //#[allow_ci]

                // Flush context to free TPM memory
                let r = ctx.flush_context(ek.key_handle.into());
                assert!(r.is_ok(), "Result: {r:?}");
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_create_and_load_ak() {
        let _mutex = testing::lock_tests().await;
        let mut ctx = Context::new().unwrap(); //#[allow_ci]

        let r = ctx.create_ek(EncryptionAlgorithm::Rsa2048, None);
        assert!(r.is_ok(), "Result: {r:?}");

        let ek_result = r.unwrap(); //#[allow_ci]
        let ek_handle = ek_result.key_handle;

        let eng_algs =
            [EncryptionAlgorithm::Rsa1024, EncryptionAlgorithm::Rsa2048];

        let hash_algs = [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            //HashingAlgorithm::Sha512, // Not supported by swtpm
            //HashingAlgorithm::Sm3_256, // Not supported by swtpm
            //HashingAlgorithm::Sha3_384, // Not supported by swtpm
            //HashingAlgorithm::Sha3_512, // Not supported by swtpm
            //HashingAlgorithm::Sha1, // Not supported by swtpm
        ];
        let sign_algs = [
            SignAlgorithm::RsaSsa,
            SignAlgorithm::RsaPss,
            // - ECC keys creation requires this: https://github.com/parallaxsecond/rust-tss-esapi/pull/464
            //   Probably this will be released on tss_esapi version 8.0.0, which includes API
            //   breakage
            // SignAlgorithm::EcDsa,
            // SignAlgorithm::EcSchnorr,
        ];

        for sign in sign_algs {
            for enc in eng_algs {
                for hash in hash_algs {
                    let r = ctx.create_ak(ek_handle, hash, enc, sign);
                    assert!(r.is_ok(), "Result: {r:?}");
                    let ak = r.unwrap(); //#[allow_ci]

                    let r = ctx.load_ak(ek_handle, &ak);
                    assert!(r.is_ok(), "Result: {r:?}");
                    let handle = r.unwrap(); //#[allow_ci]

                    // Flush context to free TPM memory
                    let r = ctx.flush_context(handle.into());
                    assert!(r.is_ok(), "Result: {r:?}");
                }
            }
        }

        // Flush context to free TPM memory
        let r = ctx.flush_context(ek_handle.into());
        assert!(r.is_ok(), "Result: {r:?}");
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_create_idevid() {
        let _mutex = testing::lock_tests().await;
        let asym_algs = [AsymmetricAlgorithm::Rsa, AsymmetricAlgorithm::Ecc];
        let hash_algs = [
            HashingAlgorithm::Sha256,
            HashingAlgorithm::Sha384,
            //HashingAlgorithm::Sha512, // Not supported by swtpm
            //HashingAlgorithm::Sm3_256, // Not supported by swtpm
            //HashingAlgorithm::Sha3_384, // Not supported by swtpm
            //HashingAlgorithm::Sha3_512, // Not supported by swtpm
            //HashingAlgorithm::Sha1, // Not supported by swtpm
        ];

        let mut ctx = Context::new().unwrap(); //#[allow_ci]

        for asym in asym_algs {
            for hash in hash_algs {
                println!("Creating IDevID with {asym:?} and {hash:?}");
                let r = ctx.create_idevid(asym, hash);
                assert!(r.is_ok(), "Result: {r:?}");
                println!(
                    "Successfully created IDevID with {asym:?} and {hash:?}"
                );
                let idevid = r.unwrap(); //#[allow_ci]
                let r = ctx.flush_context(idevid.handle.into());
                assert!(r.is_ok(), "Result: {r:?}");
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_create_iak() {
        let _mutex = testing::lock_tests().await;
        let mut ctx = Context::new().unwrap(); //#[allow_ci]

        let asym_algs = [AsymmetricAlgorithm::Rsa, AsymmetricAlgorithm::Ecc];
        let hash_algs = [
            HashingAlgorithm::Sha256,
            HashingAlgorithm::Sha384,
            //HashingAlgorithm::Sha512, // Not supported by swtpm
            //HashingAlgorithm::Sm3_256, // Not supported by swtpm
            //HashingAlgorithm::Sha3_384, // Not supported by swtpm
            //HashingAlgorithm::Sha3_512, // Not supported by swtpm
            //HashingAlgorithm::Sha1, // Not supported by swtpm
        ];

        for asym in asym_algs {
            for hash in hash_algs {
                println!("Creating IAK with {asym:?} and {hash:?}");
                let r = ctx.create_iak(asym, hash);
                assert!(r.is_ok(), "Result: {r:?}");
                println!(
                    "Successfully created IAK with {asym:?} and {hash:?}"
                );
                let iak = r.unwrap(); //#[allow_ci]
                let r = ctx.flush_context(iak.handle.into());
                assert!(r.is_ok(), "Result: {r:?}");
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_activate_credential() {
        let _mutex = testing::lock_tests().await;
        let mut ctx = Context::new().unwrap(); //#[allow_ci]

        // Create EK
        let ek_result = ctx
            .create_ek(EncryptionAlgorithm::Rsa2048, None)
            .expect("failed to create EK");
        let ek_handle = ek_result.key_handle;

        // Create AK
        let ak = ctx
            .create_ak(
                ek_handle,
                HashAlgorithm::Sha256,
                EncryptionAlgorithm::Rsa2048,
                SignAlgorithm::RsaSsa,
            )
            .expect("failed to create AK");

        // Get AK handle
        let ak_handle =
            ctx.load_ak(ek_handle, &ak).expect("failed to load AK");

        // Get AK name
        let name = ctx
            .get_name(ak_handle.into())
            .expect("failed to get AK name");

        // Generate random challenge
        let mut challenge: [u8; 32] = [0; 32];
        let r = openssl::rand::rand_priv_bytes(&mut challenge);
        assert!(r.is_ok(), "Result: {r:?}");

        let credential = Digest::try_from(challenge.as_ref())
            .expect("Failed to convert random bytes to Digest structure");

        // Make credential, which encrypts the challenge
        let keyblob = ctx
            .make_credential(ek_handle, credential.clone(), name)
            .expect("failed to create keyblob");

        // Activate credential, which decrypts the challenge
        let decrypted = ctx
            .activate_credential(keyblob, ak_handle, ek_handle)
            .expect("failed to decrypt challenge");
        assert_eq!(decrypted, credential);

        // Flush context to free TPM memory
        let r = ctx.flush_context(ek_handle.into());
        assert!(r.is_ok(), "Result: {r:?}");
        let r = ctx.flush_context(ak_handle.into());
        assert!(r.is_ok(), "Result: {r:?}");
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_certify_credential_with_iak() {
        let _mutex = testing::lock_tests().await;
        let mut ctx = Context::new().unwrap(); //#[allow_ci]

        // Create EK
        let ek_result = ctx
            .create_ek(EncryptionAlgorithm::Rsa2048, None)
            .expect("failed to create EK");
        let ek_handle = ek_result.key_handle;

        // Create AK
        let ak = ctx
            .create_ak(
                ek_handle,
                HashAlgorithm::Sha256,
                EncryptionAlgorithm::Rsa2048,
                SignAlgorithm::RsaSsa,
            )
            .expect("failed to create ak");

        let ak_handle =
            ctx.load_ak(ek_handle, &ak).expect("failed to load AK");

        let iak_handle = ctx
            .create_iak(AsymmetricAlgorithm::Rsa, HashingAlgorithm::Sha256)
            .expect("failed to create IAK")
            .handle;

        let qualifying_data = "some_uuid".as_bytes();

        let r = ctx.certify_credential_with_iak(
            Data::try_from(qualifying_data).unwrap(), //#[allow_ci]
            ak_handle,
            iak_handle,
        );
        assert!(r.is_ok(), "Result: {r:?}");

        // Flush context to free TPM memory
        let r = ctx.flush_context(ek_handle.into());
        assert!(r.is_ok(), "Result: {r:?}");
        let r = ctx.flush_context(ak_handle.into());
        assert!(r.is_ok(), "Result: {r:?}");
        let r = ctx.flush_context(iak_handle.into());
        assert!(r.is_ok(), "Result: {r:?}");
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_pcr_banks() {
        let _mutex = testing::lock_tests().await;
        let mut ctx = Context::new().unwrap(); //#[allow_ci]
        let banks = ctx.pcr_banks(HashAlgorithm::Sha256);
        assert!(banks.is_ok(), "Result: {banks:?}");
        assert!(!banks.unwrap().is_empty(), "No PCR banks found"); //#[allow_ci]
    } // test_pcr_banks
}
