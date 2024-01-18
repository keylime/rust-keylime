// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::algorithms::{
    AlgorithmError, EncryptionAlgorithm, HashAlgorithm, SignAlgorithm,
};
use base64::{engine::general_purpose, Engine as _};
use log::*;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use thiserror::Error;

use openssl::{
    hash::{Hasher, MessageDigest},
    memcmp,
    pkey::{HasPublic, Id, PKeyRef, Public},
};

use tss_esapi::{
    abstraction::{
        ak,
        cipher::Cipher,
        ek,
        pcr::{read_all, PcrData},
        DefaultKey,
    },
    attributes::{
        object::ObjectAttributesBuilder, session::SessionAttributesBuilder,
    },
    constants::{
        response_code::Tss2ResponseCodeKind, session_type::SessionType,
    },
    handles::{
        AuthHandle, KeyHandle, PcrHandle, PersistentTpmHandle, TpmHandle,
    },
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Attest, AttestInfo, Data, Digest, DigestValues, EccParameter,
        EccPoint, EccScheme, EncryptedSecret, HashScheme, IdObject,
        KeyDerivationFunctionScheme, PcrSelectionList,
        PcrSelectionListBuilder, PcrSlot, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, Signature, SignatureScheme,
        SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::Marshall,
    tss2_esys::{TPML_DIGEST, TPML_PCR_SELECTION},
    Error::Tss2Error,
};

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

/// Return the asymmetric and name algorithms, either by matching to a template or using the user specified algorithms
/// If the template config option is set to "", "detect" or "default", the template will be matched to the certs
/// If a template has been specified, that will be used
/// If the option has been set to "manual", or some other not-empty string, the user specified algorithms will be used
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
            AsymmetricAlgorithm::from(EncryptionAlgorithm::try_from(
                asym_alg_str,
            )?),
            HashingAlgorithm::from(HashAlgorithm::try_from(name_alg_str)?),
        ),
    };
    Ok((asym_alg, name_alg))
}

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("TSS2 Error: {err:?}, kind: {kind:?}, {message}")]
    Tss2 {
        err: tss_esapi::Error,
        kind: Option<Tss2ResponseCodeKind>,
        message: String,
    },
    #[error("AlgorithmError: {0}")]
    AlgorithmError(#[from] AlgorithmError),
    #[error("Infallible: {0}")]
    Infallible(#[from] std::convert::Infallible),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Number parsing error: {0}")]
    NumParse(#[from] std::num::ParseIntError),
    #[error("OpenSSL error: {0}")]
    OpenSSL(#[from] openssl::error::ErrorStack),
    #[error("Error converting number: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid request")]
    InvalidRequest,
    #[error("{0}")]
    Other(String),
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
    pub public: tss_esapi::structures::Public,
}

/// Holds the output of create_ak.
#[derive(Clone, Debug)]
pub struct AKResult {
    pub public: tss_esapi::structures::Public,
    pub private: tss_esapi::structures::Private,
}

/// Holds the output of create_iak.
#[derive(Clone, Debug)]
pub struct IAKResult {
    pub public: tss_esapi::structures::Public,
    pub handle: tss_esapi::handles::KeyHandle,
}

/// Holds the output of create_idevid.
#[derive(Clone, Debug)]
pub struct IDevIDResult {
    pub public: tss_esapi::structures::Public,
    pub handle: tss_esapi::handles::KeyHandle,
}

/// Holds the Public result from create_idevid_public_from_default_template
#[derive(Clone, Debug)]
pub struct IDevIDPublic {
    pub public: tss_esapi::structures::Public,
}

/// Holds the Public result from create_iak_public_from_default_template
#[derive(Clone, Debug)]
pub struct IAKPublic {
    pub public: tss_esapi::structures::Public,
}

/// Wrapper around tss_esapi::Context.
#[derive(Debug)]
pub struct Context {
    inner: tss_esapi::Context,
}

impl AsRef<tss_esapi::Context> for Context {
    fn as_ref(&self) -> &tss_esapi::Context {
        &self.inner
    }
}

impl AsMut<tss_esapi::Context> for Context {
    fn as_mut(&mut self) -> &mut tss_esapi::Context {
        &mut self.inner
    }
}

impl Context {
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

        let tcti = TctiNameConf::from_str(&tcti_path)?;
        Ok(Self {
            inner: tss_esapi::Context::new(tcti)?,
        })
    }

    /// Creates an EK, returns the key handle and public certificate
    /// in `EKResult`.
    pub fn create_ek(
        &mut self,
        alg: EncryptionAlgorithm,
        handle: Option<&str>,
    ) -> Result<EKResult> {
        // Retrieve EK handle, EK pub cert, and TPM pub object
        let key_handle = match handle {
            Some(v) => {
                if v.is_empty() {
                    ek::create_ek_object(
                        &mut self.inner,
                        alg.into(),
                        DefaultKey,
                    )?
                } else {
                    let handle =
                        u32::from_str_radix(v.trim_start_matches("0x"), 16)?;
                    self.inner
                        .tr_from_tpm_public(TpmHandle::Persistent(
                            PersistentTpmHandle::new(handle)?,
                        ))?
                        .into()
                }
            }
            None => {
                ek::create_ek_object(&mut self.inner, alg.into(), DefaultKey)?
            }
        };
        let cert = match ek::retrieve_ek_pubcert(&mut self.inner, alg.into())
        {
            Ok(v) => Some(v),
            Err(_) => {
                warn!("No EK certificate found in TPM NVRAM");
                None
            }
        };
        let (tpm_pub, _, _) = self.inner.read_public(key_handle)?;
        Ok(EKResult {
            key_handle,
            ek_cert: cert,
            public: tpm_pub,
        })
    }

    /// Creates an AK.
    pub fn create_ak(
        &mut self,
        handle: KeyHandle,
        hash_alg: HashAlgorithm,
        sign_alg: SignAlgorithm,
    ) -> Result<AKResult> {
        let ak = ak::create_ak(
            &mut self.inner,
            handle,
            hash_alg.into(),
            sign_alg.into(),
            None,
            DefaultKey,
        )?;
        Ok(AKResult {
            public: ak.out_public,
            private: ak.out_private,
        })
    }

    /// Loads an existing AK associated with `handle` and `ak`.
    pub fn load_ak(
        &mut self,
        handle: KeyHandle,
        ak: &AKResult,
    ) -> Result<KeyHandle> {
        let ak_handle = ak::load_ak(
            &mut self.inner,
            handle,
            None,
            ak.private.clone(),
            ak.public.clone(),
        )?;
        Ok(ak_handle)
    }

    // Creates IDevID
    pub fn create_idevid(
        &mut self,
        asym_alg: AsymmetricAlgorithm,
        name_alg: HashingAlgorithm,
    ) -> Result<IDevIDResult> {
        let key_pub = Self::create_idevid_public_from_default_template(
            asym_alg, name_alg,
        );

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
            .expect("Failed to build PcrSelectionList");

        let primary_key = self
            .inner
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Endorsement,
                    key_pub.unwrap().public, //#[allow_ci]
                    None,
                    None,
                    None,
                    Some(pcr_selection_list),
                )
            })
            .unwrap(); //#[allow_ci]

        Ok(IDevIDResult {
            public: primary_key.out_public,
            handle: primary_key.key_handle,
        })
    }

    /// Mount the template for IDevID

    pub(crate) fn create_idevid_public_from_default_template(
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

        let obj_attrs = obj_attrs_builder.build()?;

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
                .with_auth_policy(Digest::try_from(auth_policy)?)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(key_bits)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.restricted())
                        .build()?,
                )
                .with_rsa_unique_identifier(PublicKeyRsa::try_from(
                    &UNIQUE_IDEVID[0..6],
                )?),
            AsymmetricAlgorithm::Ecc => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(name_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(auth_policy)?)
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
                        .build()?,
                )
                .with_ecc_unique_identifier(EccPoint::new(
                    EccParameter::try_from(&UNIQUE_IDEVID[0..6])?,
                    EccParameter::try_from(&UNIQUE_IDEVID[0..6])?,
                )),
            // Defaulting to RSA on null
            AsymmetricAlgorithm::Null => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(
                    IDEVID_AUTH_POLICY_SHA256[0..32].to_vec(),
                )?)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(RsaKeyBits::Rsa2048)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.decrypt())
                        .build()?,
                )
                .with_rsa_unique_identifier(PublicKeyRsa::try_from(
                    &UNIQUE_IDEVID[0..6],
                )?),
        };

        Ok(IDevIDPublic {
            public: key_builder.build().unwrap(), //#[allow_ci]
        })
    }

    // Creates IAK
    pub fn create_iak(
        &mut self,
        asym_alg: AsymmetricAlgorithm,
        name_alg: HashingAlgorithm,
    ) -> Result<IAKResult> {
        let key_pub =
            Self::create_iak_public_from_default_template(asym_alg, name_alg);

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
            .expect("Failed to build PcrSelectionList");

        let primary_key = self
            .inner
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Endorsement,
                    key_pub.unwrap().public, //#[allow_ci]
                    None,
                    None,
                    None,
                    Some(pcr_selection_list),
                )
            })
            .unwrap(); //#[allow_ci]

        Ok(IAKResult {
            public: primary_key.out_public,
            handle: primary_key.key_handle,
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

        let obj_attrs = obj_attrs_builder.build()?;

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
                RsaKeyBits::Rsa2048,
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
                .with_auth_policy(Digest::try_from(auth_policy)?)
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
                        .build()?,
                )
                .with_rsa_unique_identifier(PublicKeyRsa::try_from(
                    &UNIQUE_IAK[0..3],
                )?),
            AsymmetricAlgorithm::Ecc => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(name_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(auth_policy)?)
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
                        .build()?,
                )
                .with_ecc_unique_identifier(EccPoint::new(
                    EccParameter::try_from(&UNIQUE_IAK[0..3])?,
                    EccParameter::try_from(&UNIQUE_IAK[0..3])?,
                )),
            AsymmetricAlgorithm::Null => PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(Digest::try_from(
                    IAK_AUTH_POLICY_SHA256[0..32].to_vec(),
                )?)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(SymmetricDefinitionObject::Null)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(RsaKeyBits::Rsa2048)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.decrypt())
                        .build()?,
                )
                .with_rsa_unique_identifier(PublicKeyRsa::try_from(
                    &UNIQUE_IAK[0..3],
                )?),
        };

        Ok(IAKPublic {
            public: key_builder.build().unwrap(), //#[allow_ci]
        })
    }

    fn create_empty_session(
        &mut self,
        ses_type: SessionType,
    ) -> Result<AuthSession> {
        let session = self.inner.start_auth_session(
            None,
            None,
            None,
            ses_type,
            Cipher::aes_128_cfb().try_into()?,
            HashingAlgorithm::Sha256,
        )?;
        let (ses_attrs, ses_attrs_mask) = SessionAttributesBuilder::new()
            .with_encrypt(true)
            .with_decrypt(true)
            .build();
        self.inner.tr_sess_set_attributes(
            session.unwrap(), //#[allow_ci]
            ses_attrs,
            ses_attrs_mask,
        )?;
        Ok(session.unwrap()) //#[allow_ci]
    }

    /// Activates credentials with given secret `keyblob`, AK, and EK.
    pub fn activate_credential(
        &mut self,
        keyblob: Vec<u8>,
        ak: KeyHandle,
        ek: KeyHandle,
    ) -> Result<Digest> {
        let (credential, secret) = parse_cred_and_secret(keyblob)?;

        let ek_auth = self.create_empty_session(SessionType::Policy)?;

        // We authorize ses2 with PolicySecret(ENDORSEMENT) as per PolicyA
        let _ = self.inner.execute_with_nullauth_session(|context| {
            context.policy_secret(
                ek_auth.try_into()?,
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })?;

        self.inner
            .execute_with_sessions(
                (Some(AuthSession::Password), Some(ek_auth), None),
                |context| {
                    context.activate_credential(ak, ek, credential, secret)
                },
            )
            .map_err(TpmError::from)
    }

    //This function certifies an attestation key with the IAK, using any qualifying data provided,
    //producing an attestation document and signature
    pub fn certify_credential_with_iak(
        &mut self,
        qualifying_data: Data,
        ak: KeyHandle,
        iak: KeyHandle,
    ) -> Result<(Attest, Signature)> {
        self.inner
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
            .map_err(TpmError::from)
    }

    // This function extends Pcr16 with the digest, then creates a PcrList
    // from the given mask and pcr16.
    fn build_pcr_list(
        &mut self,
        digest: DigestValues,
        mask: u32,
        hash_alg: HashingAlgorithm,
    ) -> Result<PcrSelectionList> {
        // extend digest into pcr16
        self.inner.execute_with_nullauth_session(|ctx| {
            ctx.pcr_reset(PcrHandle::Pcr16)?;
            ctx.pcr_extend(PcrHandle::Pcr16, digest.to_owned())
        })?;

        // translate mask to vec of pcrs
        let mut pcrs = read_mask(mask)?;

        // add pcr16 if it isn't in the vec already
        if !pcrs.iter().any(|&pcr| pcr == PcrSlot::Slot16) {
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
    /// are set to pcrs to include in the list. The LSB in the mask
    /// corresponds to PCR0. Note that PCR16 is always included even
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

        let (attestation, sig, pcrs_read, pcr_data) =
            self.inner.execute_with_nullauth_session(|ctx| {
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
}

// Ensure that TPML_PCR_SELECTION and TPML_DIGEST have known sizes
assert_eq_size!(TPML_PCR_SELECTION, [u8; 132]);
assert_eq_size!(TPML_DIGEST, [u8; 532]);

// Serialize a TPML_PCR_SELECTION into a Vec<u8>
// The serialization will adjust the data endianness as necessary and add paddings to keep the
// memory aligment.
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

fn parse_cred_and_secret(
    keyblob: Vec<u8>,
) -> Result<(IdObject, EncryptedSecret)> {
    let magic = u32::from_be_bytes(keyblob[0..4].try_into().unwrap()); //#[allow_ci]
    let version = u32::from_be_bytes(keyblob[4..8].try_into().unwrap()); //#[allow_ci]

    if magic != TSS_MAGIC {
        return Err(TpmError::Other(format!("Error parsing cred and secret; TSS_MAGIC number {magic} does not match expected value {TSS_MAGIC}")));
    }
    if version != 1 {
        return Err(TpmError::Other(format!(
            "Error parsing cred and secret; version {version} is not 1"
        )));
    }

    let credsize = u16::from_be_bytes(keyblob[8..10].try_into().unwrap()); //#[allow_ci]
    let _secretsize = u16::from_be_bytes(
        keyblob[(10 + credsize as usize)..(12 + credsize as usize)]
            .try_into()
            .unwrap(), //#[allow_ci]
    );

    let credential = &keyblob[10..(10 + credsize as usize)];
    let secret = &keyblob[(12 + credsize as usize)..];

    let credential = IdObject::try_from(credential)?;
    let secret = EncryptedSecret::try_from(secret)?;

    Ok((credential, secret))
}

// Takes a public PKey and returns a DigestValue of it.
fn pubkey_to_tpm_digest<T: HasPublic>(
    pubkey: &PKeyRef<T>,
    hash_algo: HashAlgorithm,
) -> Result<DigestValues> {
    let mut keydigest = DigestValues::new();

    let keybytes = match pubkey.id() {
        Id::RSA => pubkey.rsa()?.public_key_to_pem()?,
        other_id => {
            return Err(TpmError::Other(format!(
            "Converting to digest value for key type {other_id:?} is not yet implemented"
            )));
        }
    };

    let hashing_algo = HashingAlgorithm::from(hash_algo);
    let mut hasher = Hasher::new(hash_alg_to_message_digest(hashing_algo)?)?;
    hasher.update(&keybytes)?;
    let hashvec = hasher.finish()?;
    keydigest.set(hashing_algo, Digest::try_from(hashvec.as_ref())?);

    Ok(keydigest)
}

// Reads a mask indicating PCRs to include.
//
// The masks are sent from the tenant and cloud verifier to indicate
// the PCRs to include in a Quote. The LSB in the mask corresponds to
// PCR0. For example, keylime-agent.conf specifies PCRs 15 and 22 under
// [tenant][tpm_policy]. As a bit mask, this would be represented as
// 0b010000001000000000000000, which translates to 0x408000.
//
// The mask is a string because it is sent as a string from the tenant
// and verifier. The output from this function can be used to call a
// Quote from the TSS ESAPI.
//
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
                    bit => return Err(TpmError::Other(format!("malformed mask in integrity quote: only pcrs 0-23 can be included, but mask included pcr {bit:?}"))),
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

// This encodes a quote string as input to Python Keylime's quote checking functionality.
// The quote, signature, and pcr blob are concatenated with ':' separators. To match the
// expected format, the quote, signature, and pcr blob must be base64 encoded before concatenation.
//
// Reference:
// https://github.com/keylime/keylime/blob/2dd9e5c968f33bf77110092af9268d13db1806c6 \
// /keylime/tpm/tpm_main.py#L964-L975
fn encode_quote_string(
    att: Attest,
    sig: Signature,
    pcrs_read: PcrSelectionList,
    pcr_data: PcrData,
) -> Result<String> {
    // marshal structs to vec in expected formats. these formats are
    // dictated by tpm2_tools.
    let att_vec = att.marshall()?;
    let sig_vec = sig.marshall()?;
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

// The pcr blob corresponds to the pcr out file that records the list of PCR values,
// specified by tpm2tools, ex. 'tpm2_quote ... -o <pcrfilename>'. Read more here:
// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_quote.1.md
//
// It is required by Python Keylime's check_quote functionality. For how the quote is
// checked, see:
// https://github.com/keylime/keylime/blob/2dd9e5c968f33bf77110092af9268d13db1806c6/ \
// keylime/tpm/tpm_main.py#L990
//
// For how the quote is created, see:
// https://github.com/keylime/keylime/blob/2dd9e5c968f33bf77110092af9268d13db1806c6/ \
// keylime/tpm/tpm_main.py#L965
//
fn make_pcr_blob(
    context: &mut tss_esapi::Context,
    pcrlist: PcrSelectionList,
) -> Result<(PcrSelectionList, PcrData)> {
    let pcr_data = context
        .execute_without_session(|ctx| read_all(ctx, pcrlist.clone()))?;
    Ok((pcrlist, pcr_data))
}

// Takes a TSS ESAPI HashingAlgorithm and returns the corresponding OpenSSL
// MessageDigest.
fn hash_alg_to_message_digest(
    hash_alg: HashingAlgorithm,
) -> Result<MessageDigest> {
    match hash_alg {
        HashingAlgorithm::Sha256 => Ok(MessageDigest::sha256()),
        HashingAlgorithm::Sha1 => Ok(MessageDigest::sha1()),
        HashingAlgorithm::Sha384 => Ok(MessageDigest::sha384()),
        HashingAlgorithm::Sha512 => Ok(MessageDigest::sha512()),
        HashingAlgorithm::Sm3_256 => Ok(MessageDigest::sm3()),
        other => Err(TpmError::Other(format!(
            "Unsupported hashing algorithm: {other:?}"
        ))),
    }
}

fn check_if_pcr_data_and_attestation_match(
    hash_algo: HashingAlgorithm,
    pcr_data: &PcrData,
    attestation: Attest,
) -> Result<bool> {
    let pcr_data = Vec::<TPML_DIGEST>::try_from(pcr_data.clone())?;
    let quote_info = match attestation.attested() {
        AttestInfo::Quote { info } => info,
        _ => {
            return Err(TpmError::Other(format!(
                "Expected attestation type TPM2_ST_ATTEST_QUOTE, got {:?}",
                attestation.attestation_type()
            )));
        }
    };

    let attested_pcr = quote_info.pcr_digest().value();

    let mut hasher = Hasher::new(hash_alg_to_message_digest(hash_algo)?)?;
    for tpml_digest in pcr_data {
        for i in 0..tpml_digest.count {
            let pcr = tpml_digest.digests[i as usize];
            hasher.update(&pcr.buffer[..pcr.size as usize])?;
        }
    }
    let pcr_digest = hasher.finish()?;

    log::trace!(
        "Attested to PCR digest: {:?}, read PCR digest: {:?}",
        attested_pcr,
        pcr_digest,
    );

    Ok(memcmp::eq(attested_pcr, &pcr_digest))
}

const NUM_ATTESTATION_ATTEMPTS: i32 = 5;

fn perform_quote_and_pcr_read(
    context: &mut tss_esapi::Context,
    ak_handle: KeyHandle,
    nonce: &[u8],
    pcrlist: PcrSelectionList,
    sign_scheme: SignatureScheme,
    hash_alg: HashingAlgorithm,
) -> Result<(Attest, Signature, PcrSelectionList, PcrData)> {
    let nonce: tss_esapi::structures::Data = nonce.try_into()?;

    for attempt in 0..NUM_ATTESTATION_ATTEMPTS {
        // TSS ESAPI quote does not create pcr blob, so create it separately
        let (pcrs_read, pcr_data) = make_pcr_blob(context, pcrlist.clone())?;

        // create quote
        let (attestation, sig) = context.quote(
            ak_handle,
            nonce.clone(),
            sign_scheme,
            pcrs_read.clone(),
        )?;

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
    Err(TpmError::Other(
        "Consistent race condition: can't make attestation match pcr_data"
            .to_string(),
    ))
}

pub mod testing {
    use super::*;
    use std::io::prelude::*;
    use tss_esapi::constants::structure_tags::StructureTag;
    use tss_esapi::structures::{Attest, AttestBuffer, DigestList, Ticket};
    use tss_esapi::tss2_esys::{
        Tss2_MU_TPMT_SIGNATURE_Unmarshal, TPM2B_ATTEST, TPM2B_DIGEST,
        TPMS_PCR_SELECTION, TPMT_SIGNATURE,
    };

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

    // Deserialize a TPML_PCR_SELECTION from a &[u8] slice.
    // The deserialization will adjust the data endianness as necessary.
    fn deserialize_pcrsel(pcrsel_vec: &[u8]) -> Result<TPML_PCR_SELECTION> {
        if pcrsel_vec.len() != TPML_PCR_SELECTION_SIZE {
            return Err(TpmError::InvalidRequest);
        }

        let mut reader = std::io::Cursor::new(pcrsel_vec);
        let mut count_vec = [0u8; 4];
        reader.read_exact(&mut count_vec)?;
        let count = u32::from_le_bytes(count_vec);

        let mut pcr_selections: [TPMS_PCR_SELECTION; 16] =
            [TPMS_PCR_SELECTION::default(); 16];

        for selection in &mut pcr_selections {
            let mut hash_vec = [0u8; 2];
            reader.read_exact(&mut hash_vec)?;
            selection.hash = u16::from_le_bytes(hash_vec);

            let mut size_vec = [0u8; 1];
            reader.read_exact(&mut size_vec)?;
            selection.sizeofSelect = u8::from_le_bytes(size_vec);

            reader.read_exact(&mut selection.pcrSelect)?;
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
            return Err(TpmError::InvalidRequest);
        }

        let mut reader = std::io::Cursor::new(digest_vec);
        let mut count_vec = [0u8; 4];

        reader.read_exact(&mut count_vec)?;
        let count = u32::from_le_bytes(count_vec);

        let mut digests: [TPM2B_DIGEST; 8] = [TPM2B_DIGEST::default(); 8];

        for digest in &mut digests {
            let mut size_vec = [0u8; 2];
            reader.read_exact(&mut size_vec)?;
            digest.size = u16::from_le_bytes(size_vec);
            reader.read_exact(&mut digest.buffer)?;
        }

        Ok(TPML_DIGEST { count, digests })
    }

    fn vec_to_pcrdata(val: &[u8]) -> Result<(PcrSelectionList, PcrData)> {
        let mut reader = std::io::Cursor::new(val);
        let mut pcrsel_vec = [0u8; TPML_PCR_SELECTION_SIZE];
        reader.read_exact(&mut pcrsel_vec)?;

        let pcrsel = deserialize_pcrsel(&pcrsel_vec)?;
        let pcrlist: PcrSelectionList = pcrsel.try_into()?;

        let mut count_vec = [0u8; 4];
        reader.read_exact(&mut count_vec)?;
        let count = u32::from_le_bytes(count_vec);
        // Always 1 PCR digest should follow
        if count != 1 {
            return Err(TpmError::InvalidRequest);
        }

        let mut digest_vec = [0u8; TPML_DIGEST_SIZE];
        reader.read_exact(&mut digest_vec)?;
        let digest = deserialize_digest(&digest_vec)?;
        let mut digest_list = DigestList::new();
        for i in 0..digest.count {
            digest_list.add(digest.digests[i as usize].try_into()?)?;
        }

        let pcrdata = PcrData::create(&pcrlist, &digest_list)?;
        Ok((pcrlist, pcrdata))
    }

    pub(crate) fn decode_quote_string(
        quote: &str,
    ) -> Result<(AttestBuffer, Signature, PcrSelectionList, PcrData)> {
        if !quote.starts_with('r') {
            return Err(TpmError::InvalidRequest);
        }
        // extract components from the concatenated string
        let mut split = quote[1..].split(':');
        let att_str = split.next().ok_or(TpmError::InvalidRequest)?;
        let sig_str = split.next().ok_or(TpmError::InvalidRequest)?;
        let pcr_str = split.next().ok_or(TpmError::InvalidRequest)?;

        // base64 decoding
        let att_comp_finished = general_purpose::STANDARD.decode(att_str)?;
        let sig_comp_finished = general_purpose::STANDARD.decode(sig_str)?;
        let pcr_comp_finished = general_purpose::STANDARD.decode(pcr_str)?;

        let sig: Signature = vec_to_sig(&sig_comp_finished)?.try_into()?;
        let (pcrsel, pcrdata) = vec_to_pcrdata(&pcr_comp_finished)?;

        let mut att = TPM2B_ATTEST {
            size: att_comp_finished
                .len()
                .try_into()
                .or(Err(TpmError::InvalidRequest))?,
            ..Default::default()
        };
        att.attestationData[0..att_comp_finished.len()]
            .copy_from_slice(&att_comp_finished);
        Ok((att.try_into()?, sig, pcrsel, pcrdata))
    }

    // This performs the same checks as in tpm2_checkquote, namely:
    // signature, nonce, and PCR digests from the quote.
    //
    // Reference:
    // https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_checkquote.c
    pub fn check_quote(
        context: &mut tss_esapi::Context,
        ak_handle: KeyHandle,
        quote: &str,
        nonce: &[u8],
    ) -> Result<()> {
        let (att, sig, pcrsel, pcrdata) = decode_quote_string(quote)?;

        // Verify the signature matches message digest. We do not
        // bother unmarshalling the AK to OpenSSL PKey, but just use
        // Esys_VerifySignature with loaded AK
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        hasher.update(att.value())?;
        let digest = hasher.finish()?;
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
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        for &sel in pcrsel.get_selections() {
            for i in &sel.selected() {
                if let Some(digest) = pcrbank.get_digest(*i) {
                    hasher.update(digest.value())?;
                }
            }
        }
        let digest = hasher.finish()?;
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

#[test]
fn quote_encode_decode() {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    let quote_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-data")
        .join("test-quote.txt");

    let f = File::open(quote_path).expect("unable to open test-quote.txt");
    let mut f = BufReader::new(f);
    let mut buf = String::new();
    let _ = f.read_line(&mut buf).expect("unable to read quote");
    let buf = buf.trim_end();

    let (att, sig, pcrsel, pcrdata) =
        testing::decode_quote_string(buf).expect("unable to decode quote");

    let attestation: Attest =
        att.try_into().expect("unable to unmarshal attestation");

    let encoded = encode_quote_string(attestation, sig, pcrsel, pcrdata)
        .expect("unable to encode quote");

    assert_eq!(encoded, buf);
}

#[test]
fn pubkey_to_digest() {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    let rsa = Rsa::generate(2048).unwrap(); //#[allow_ci]
    let pkey = PKey::from_rsa(rsa).unwrap(); //#[allow_ci]

    assert!(
        pubkey_to_tpm_digest(pkey.as_ref(), HashAlgorithm::Sha256).is_ok()
    );
}

#[test]
fn mask() {
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
