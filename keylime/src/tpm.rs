// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::algorithms::{EncryptionAlgorithm, HashAlgorithm, SignAlgorithm};
use crate::endian::LocalEndianness;
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
    attributes::session::SessionAttributesBuilder,
    constants::{
        response_code::Tss2ResponseCodeKind, session_type::SessionType,
    },
    handles::{
        AuthHandle, KeyHandle, PcrHandle, PersistentTpmHandle, TpmHandle,
    },
    interface_types::{
        algorithm::HashingAlgorithm, session_handles::AuthSession,
    },
    structures::{
        Attest, AttestInfo, Digest, DigestValues, EncryptedSecret, IdObject,
        PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Signature,
        SignatureScheme,
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

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("TSS2 Error: {err:?}, kind: {kind:?}, {message}")]
    Tss2 {
        err: tss_esapi::Error,
        kind: Option<Tss2ResponseCodeKind>,
        message: String,
    },
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
    output.extend(u32::local_endianness(pcr_selection.count));
    for selection in pcr_selection.pcrSelections.iter() {
        output.extend(u16::local_endianness(selection.hash));
        output.extend(u8::local_endianness(selection.sizeofSelect));
        output.extend(selection.pcrSelect);
        output.extend([0u8; 1]); // padding to keep the memory alignment
    }
    output
}

// Serialize a TPML_DIGEST into a Vec<u8>
// The serialization will adjust the data endianness as necessary.
fn serialize_digest(digest_list: &TPML_DIGEST) -> Vec<u8> {
    let mut output = Vec::with_capacity(TPML_DIGEST_SIZE);
    output.extend(u32::local_endianness(digest_list.count));
    for digest in digest_list.digests.iter() {
        output.extend(u16::local_endianness(digest.size));
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
    data_vec.extend(u32::local_endianness(num_tpml_digests));
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
