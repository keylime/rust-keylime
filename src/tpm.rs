// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#[macro_use]
use log::*;

use std::convert::{TryFrom, TryInto};
use std::io::prelude::*;
use std::str::FromStr;

use crate::{
    quotes_handler::KeylimeIdQuote, Error as KeylimeError, QuoteData, Result,
};

use actix_web::web::Data;

use openssl::{
    hash::{Hasher, MessageDigest},
    memcmp,
    pkey::{Id, PKeyRef, Public},
};

use flate2::{write::ZlibEncoder, Compression};

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
        session_type::SessionType,
        tss::{TPM2_ALG_NULL, TPM2_ST_ATTEST_QUOTE},
    },
    handles::{AuthHandle, KeyHandle, PcrHandle},
    interface_types::{
        algorithm::{
            AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
        },
        session_handles::AuthSession,
    },
    structures::{
        Attest, AttestInfo, Digest, DigestValues, EncryptedSecret,
        HashScheme, IdObject, Name, PcrSelectionList,
        PcrSelectionListBuilder, PcrSlot, Signature, SignatureScheme,
    },
    tcti_ldr::TctiNameConf,
    tss2_esys::{
        Tss2_MU_TPM2B_PUBLIC_Marshal, Tss2_MU_TPMS_ATTEST_Marshal,
        Tss2_MU_TPMS_ATTEST_Unmarshal, Tss2_MU_TPMT_SIGNATURE_Marshal,
        TPM2B_ATTEST, TPM2B_PUBLIC, TPML_DIGEST, TPML_PCR_SELECTION,
        TPMS_ATTEST, TPMS_SCHEME_HASH, TPMT_SIGNATURE, TPMT_SIG_SCHEME,
        TPMU_SIG_SCHEME,
    },
    utils::TpmsContext,
    Context,
};

/*
 * Input: None
 * Return: Connection context
 *
 * Example call:
 * let mut ctx = tpm::get_tpm2_ctx();
 */
pub(crate) fn get_tpm2_ctx() -> Result<Context> {
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
    Context::new(tcti).map_err(|e| e.into())
}

/*
 * Input: Connection context, asymmetric algo (optional)
 * Return: (Key handle, public cert, TPM public object)
 * Example call:
 * let (key, cert, tpm_pub) = tpm::create_ek(context, Some(AsymmetricAlgorithm::Rsa))
 */
pub(crate) fn create_ek(
    context: &mut Context,
    alg: AsymmetricAlgorithm,
) -> Result<(KeyHandle, Option<Vec<u8>>, Vec<u8>)> {
    // Retrieve EK handle, EK pub cert, and TPM pub object
    let handle = ek::create_ek_object(context, alg, DefaultKey)?;
    let cert = match ek::retrieve_ek_pubcert(context, alg) {
        Ok(v) => Some(v),
        Err(_) => {
            warn!("No EK certificate found in TPM NVRAM");
            None
        }
    };
    let (tpm_pub, _, _) = context.read_public(handle)?;
    let tpm_pub_vec = pub_to_vec(tpm_pub.try_into()?);

    Ok((handle, cert, tpm_pub_vec))
}

// Multiple TPM objects need to be marshaled for Quoting. This macro will
// create the appropriate functions when called below. The macro is intended
// to help with any future similar marshaling functions.
macro_rules! create_marshal_fn {
    ($func:ident, $tpmobj:ty, $marshal:ident) => {
        fn $func(t: $tpmobj) -> Vec<u8> {
            let mut offset = 0;
            let size = std::mem::size_of::<$tpmobj>();

            let mut tpm_vec = Vec::with_capacity(size);
            unsafe {
                let res = $marshal(
                    &t,
                    tpm_vec.as_mut_ptr(),
                    tpm_vec.capacity().try_into().unwrap(), //#[allow_ci]
                    &mut offset,
                );
                if res != 0 {
                    panic!("out of memory or invalid data from TPM"); //#[allow_ci]
                }

                // offset is a buffer, so after marshaling function is called it holds the
                // number of bytes written to the vector
                tpm_vec.set_len(offset as usize);
            }

            tpm_vec
        }
    };
}

// These marshaling functions use the macro above and are based on this format:
// https://github.com/fedora-iot/clevis-pin-tpm2/blob/main/src/tpm_objects.rs#L64
// ... and on these marshaling functions:
// https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi-sys/src/ \
// bindings/x86_64-unknown-linux-gnu.rs#L16010
//
// Functions can be created using the following form:
// create_marshal_fn!(name_of_function_to_create, struct_to_be_marshaled, marshaling_function);
//
create_marshal_fn!(pub_to_vec, TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Marshal);
create_marshal_fn!(
    sig_to_vec,
    TPMT_SIGNATURE,
    Tss2_MU_TPMT_SIGNATURE_Marshal
);
create_marshal_fn!(tpms_att_to_vec, TPMS_ATTEST, Tss2_MU_TPMS_ATTEST_Marshal);

// Ensure that TPML_PCR_SELECTION and TPML_DIGEST have known sizes
assert_eq_size!(TPML_PCR_SELECTION, [u8; 132]);
assert_eq_size!(TPML_DIGEST, [u8; 532]);

// Recreate how tpm2-tools creates the PCR out file. Roughly, this is a
// TPML_PCR_SELECTION + number of TPML_DIGESTS + TPML_DIGESTs.
// Reference:
// https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_quote.c#L47-L91
//
// Note: tpm2-tools does not use its own documented marshaling functions for this output,
// so the below code recreates the idiosyncratic format tpm2-tools expects. The lengths
// of the vectors were determined by introspection into running tpm2-tools code. This is
// not ideal, and we should aim to move away from it if possible.
pub(crate) fn pcrdata_to_vec(
    selection_list: PcrSelectionList,
    pcrdata: PcrData,
) -> Vec<u8> {
    const PCRSEL_SIZE: usize = std::mem::size_of::<TPML_PCR_SELECTION>();
    const DIGEST_SIZE: usize = std::mem::size_of::<TPML_DIGEST>();

    let mut pcrsel: TPML_PCR_SELECTION = selection_list.into();
    pcrsel.count = pcrsel.count.to_le();
    let pcrsel_vec: [u8; PCRSEL_SIZE] =
        unsafe { std::mem::transmute(pcrsel) };

    let digest: Vec<TPML_DIGEST> = pcrdata.into();
    let num_tpml_digests = digest.len() as u32;
    let mut digest_vec = Vec::with_capacity(digest.len() * DIGEST_SIZE);

    for d in digest {
        let vec: [u8; DIGEST_SIZE] = unsafe { std::mem::transmute(d) };
        digest_vec.extend(vec);
    }

    let mut data_vec =
        Vec::with_capacity(pcrsel_vec.len() + 4 + digest_vec.len());

    data_vec.extend(&pcrsel_vec);
    data_vec.extend(&num_tpml_digests.to_le_bytes());
    data_vec.extend(&digest_vec);

    data_vec
}

/* Converts a hex value in the form of a string (ex. from keylime.conf's
 * ek_handle) to a key handle.
 *
 * Input: &str
 * Return: Key handle
 *
 * Example call:
 * let ek_handle = tpm::ek_from_hex_str("0x81000000");
 */
pub(crate) fn ek_from_hex_str(val: &str) -> Result<KeyHandle> {
    let val = val.trim_start_matches("0x");
    Ok(KeyHandle::from(u32::from_str_radix(val, 16)?))
}

/* Creates AK and returns a tuple of its handle, name, and tpm2b_public as a vector.
 *
 * Input: Connection context, parent key's KeyHandle.
 * Return: (Key handle, key name, TPM public object as a vector)
 * Example call:
 * let (key, name, tpm_pub) = tpm::create_ak(context, ek_handle)
*/
pub(crate) fn create_ak(
    ctx: &mut Context,
    handle: KeyHandle,
    hash_alg: HashingAlgorithm,
    sign_alg: SignatureSchemeAlgorithm,
) -> Result<(KeyHandle, Name, Vec<u8>)> {
    let ak =
        ak::create_ak(ctx, handle, hash_alg, sign_alg, None, DefaultKey)?;
    let ak_tpm2b_pub = ak.out_public.clone();
    let tpm2_pub_vec = pub_to_vec(ak_tpm2b_pub.try_into()?);
    let ak_handle =
        ak::load_ak(ctx, handle, None, ak.out_private, ak.out_public)?;
    let (_, name, _) = ctx.read_public(ak_handle)?;
    Ok((ak_handle, name, tpm2_pub_vec))
}

pub(crate) fn store_ak(
    ctx: &mut Context,
    ak_handle: KeyHandle,
) -> Result<TpmsContext> {
    let ak_context = ctx.context_save(ak_handle.into())?;
    Ok(ak_context)
}

pub(crate) fn load_ak(
    ctx: &mut Context,
    ak: TpmsContext,
) -> Result<(KeyHandle, Name, Vec<u8>)> {
    let ak_handle: KeyHandle = ctx.context_load(ak)?.into();

    let (ak_public, ak_name, _) = ctx.read_public(ak_handle)?;
    let ak_pub_vec = pub_to_vec(ak_public.try_into()?);
    Ok((ak_handle, ak_name, ak_pub_vec))
}

const TSS_MAGIC: u32 = 3135029470;

fn parse_cred_and_secret(
    keyblob: Vec<u8>,
) -> Result<(IdObject, EncryptedSecret)> {
    let magic = u32::from_be_bytes(keyblob[0..4].try_into().unwrap()); //#[allow_ci]
    let version = u32::from_be_bytes(keyblob[4..8].try_into().unwrap()); //#[allow_ci]

    if magic != TSS_MAGIC {
        return Err(KeylimeError::Other(format!("Error parsing cred and secret; TSS_MAGIC number {} does not match expected value {}", magic, TSS_MAGIC)));
    }
    if version != 1 {
        return Err(KeylimeError::Other(format!(
            "Error parsing cred and secret; version {} is not 1",
            version
        )));
    }

    let credsize = u16::from_be_bytes(keyblob[8..10].try_into().unwrap()); //#[allow_ci]
    let secretsize = u16::from_be_bytes(
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

fn create_empty_session(
    ctx: &mut Context,
    ses_type: SessionType,
) -> Result<AuthSession> {
    let session = ctx.start_auth_session(
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
    ctx.tr_sess_set_attributes(session.unwrap(), ses_attrs, ses_attrs_mask)?; //#[allow_ci]
    Ok(session.unwrap()) //#[allow_ci]
}

pub(crate) fn activate_credential(
    ctx: &mut Context,
    keyblob: Vec<u8>,
    ak: KeyHandle,
    ek: KeyHandle,
) -> Result<Digest> {
    let (credential, secret) = parse_cred_and_secret(keyblob)?;

    let ek_auth = create_empty_session(ctx, SessionType::Policy)?;

    // We authorize ses2 with PolicySecret(ENDORSEMENT) as per PolicyA
    let _ = ctx.execute_with_nullauth_session(|context| {
        context.policy_secret(
            ek_auth.try_into()?,
            AuthHandle::Endorsement,
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        )
    })?;

    let resp = ctx
        .execute_with_sessions(
            (Some(AuthSession::Password), Some(ek_auth), None),
            |context| context.activate_credential(ak, ek, credential, secret),
        )
        .map_err(KeylimeError::from);

    ctx.flush_context(ek.into())?;

    resp
}

// Takes a public PKey and returns a DigestValue of it.
// Note: Currently, this creates a DigestValue including both SHA256 and
// SHA1 because these banks are checked by Keylime on the Python side.
pub(crate) fn pubkey_to_tpm_digest(
    pubkey: &PKeyRef<Public>,
) -> Result<DigestValues> {
    let mut keydigest = DigestValues::new();

    let keybytes = match pubkey.id() {
        Id::RSA => pubkey.rsa()?.public_key_to_pem()?,
        other_id => {
            return Err(KeylimeError::Other(format!(
            "Converting to digest value for key type {:?} is not yet implemented",
            other_id
            )));
        }
    };

    // SHA256
    let mut hasher = openssl::sha::Sha256::new();
    hasher.update(&keybytes);
    let mut hashvec: Vec<u8> = hasher.finish().into();
    keydigest.set(HashingAlgorithm::Sha256, Digest::try_from(hashvec)?);
    // SHA1
    let mut hasher = openssl::sha::Sha1::new();
    hasher.update(&keybytes);
    let mut hashvec: Vec<u8> = hasher.finish().into();
    keydigest.set(HashingAlgorithm::Sha1, Digest::try_from(hashvec)?);

    Ok(keydigest)
}

// Reads a mask in the form of some hex value, ex. "0x408000",
// translating bits that are set to pcrs to include in the list.
//
// The masks are sent from the tenant and cloud verifier to indicate
// the PCRs to include in a Quote. The LSB in the mask corresponds to
// PCR0. For example, keylime.conf specifies PCRs 15 and 22 under
// [tenant][tpm_policy]. As a bit mask, this would be represented as
// 0b010000001000000000000000, which translates to 0x408000.
//
// The mask is a string because it is sent as a string from the tenant
// and verifier. The output from this function can be used to call a
// Quote from the TSS ESAPI.
//
pub(crate) fn read_mask(mask: &str) -> Result<Vec<PcrSlot>> {
    let mut pcrs = Vec::new();

    let num = u32::from_str_radix(mask.trim_start_matches("0x"), 16)?;

    // check which bits are set
    for i in 0..32 {
        if num & (1 << i) != 0 {
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
                    bit => return Err(KeylimeError::Other(format!("malformed mask in integrity quote: only pcrs 0-23 can be included, but mask included pcr {:?}", bit))),
                },
            )
        }
    }

    Ok(pcrs)
}

//This checks if a PCR is contained in a mask
pub(crate) fn check_mask(mask: &str, pcr: &PcrSlot) -> Result<bool> {
    let selected_pcrs = read_mask(mask)?;
    Ok(selected_pcrs.contains(pcr))
}

// This encodes a quote string as input to Python Keylime's quote checking functionality.
// The quote, signature, and pcr blob are concatenated with ':' separators. To match the
// expected format, the quote, signature, and pcr blob must be individually compressed
// with zlib at the default compression level and then base64 encoded before concatenation.
//
// Reference:
// https://github.com/keylime/keylime/blob/2dd9e5c968f33bf77110092af9268d13db1806c6 \
// /keylime/tpm/tpm_main.py#L964-L975
pub(crate) fn encode_quote_string(
    att: Attest,
    sig: Signature,
    pcrs_read: PcrSelectionList,
    pcr_data: PcrData,
) -> Result<String> {
    // marshal structs to vec in expected formats. these formats are
    // dictated by tpm2_tools.
    let att_vec = tpms_att_to_vec(att.into());
    let sig_vec = sig_to_vec(sig.try_into()?);
    let pcr_vec = pcrdata_to_vec(pcrs_read, pcr_data);

    // zlib compression
    let mut att_comp = ZlibEncoder::new(Vec::new(), Compression::default());
    att_comp.write_all(&att_vec);
    let att_comp_finished = att_comp.finish()?;

    let mut sig_comp = ZlibEncoder::new(Vec::new(), Compression::default());
    sig_comp.write_all(&sig_vec);
    let sig_comp_finished = sig_comp.finish()?;

    let mut pcr_comp = ZlibEncoder::new(Vec::new(), Compression::default());
    pcr_comp.write_all(&pcr_vec);
    let pcr_comp_finished = pcr_comp.finish()?;

    // base64 encoding
    let att_str = base64::encode(att_comp_finished);
    let sig_str = base64::encode(sig_comp_finished);
    let pcr_str = base64::encode(pcr_comp_finished);

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

// This function extends Pcr16 with the digest, then creates a PcrList
// from the given mask and pcr16.
// Note: Currently, this will build the list for both SHA256 and SHA1 as
// necessary for the Python components of Keylime.
pub(crate) fn build_pcr_list(
    context: &mut Context,
    digest: DigestValues,
    mask: Option<&str>,
    hash_alg: HashingAlgorithm,
) -> Result<PcrSelectionList> {
    // extend digest into pcr16
    context.execute_with_nullauth_session(|ctx| {
        ctx.pcr_reset(PcrHandle::Pcr16)?;
        ctx.pcr_extend(PcrHandle::Pcr16, digest.to_owned())
    })?;

    // translate mask to vec of pcrs
    let mut pcrs = match mask {
        Some(m) => read_mask(m)?,
        None => Vec::new(),
    };

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
pub(crate) fn make_pcr_blob(
    context: &mut Context,
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
        other => Err(KeylimeError::Other(format!(
            "Unsupported hashing algorithm: {:?}",
            other
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
            return Err(KeylimeError::Other(format!(
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
    mut context: &mut Context,
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
        if (check_if_pcr_data_and_attestation_match(
            hash_alg,
            &pcr_data,
            attestation.clone(),
        )?) {
            return Ok((attestation, sig, pcrs_read, pcr_data));
        }

        log::info!(
            "PCR data and attestation data mismatched on attempt {}",
            attempt
        );
    }

    log::error!("PCR data and attestation data mismatched on all {} attempts, giving up", NUM_ATTESTATION_ATTEMPTS);
    Err(KeylimeError::Other(
        "Consistent race condition: can't make attestation match pcr_data"
            .to_string(),
    ))
}

// Despite the return type, this function is used for both Identity and
// Integrity Quotes. The Quote handler will add additional information to
// turn an Identity Quote into an Integrity Quote.
pub(crate) fn quote(
    nonce: &[u8],
    mask: Option<&str>,
    data: Data<QuoteData>,
) -> Result<KeylimeIdQuote> {
    let nk_digest = pubkey_to_tpm_digest(&data.pub_key)?;

    // must unwrap here due to lock mechanism
    // https://github.com/rust-lang-nursery/failure/issues/192
    let mut context = data.tpmcontext.lock().unwrap(); //#[allow_ci]

    let pcrlist =
        build_pcr_list(&mut context, nk_digest, mask, data.hash_alg.into())?;

    let (attestation, sig, pcrs_read, pcr_data) = context
        .execute_with_nullauth_session(|ctx| {
            perform_quote_and_pcr_read(
                ctx,
                data.ak_handle,
                nonce,
                pcrlist,
                data.sign_alg.to_signature_scheme(data.hash_alg),
                data.hash_alg.into(),
            )
        })?;

    let quote = encode_quote_string(attestation, sig, pcrs_read, pcr_data)?;

    Ok(KeylimeIdQuote {
        quote,
        hash_alg: data.hash_alg.to_string(),
        enc_alg: data.enc_alg.to_string(),
        sign_alg: data.sign_alg.to_string(),
        pubkey: "".to_string(),
    })
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use flate2::read::ZlibDecoder;
    use tss_esapi::constants::structure_tags::StructureTag;
    use tss_esapi::structures::{Attest, AttestBuffer, DigestList, Ticket};
    use tss_esapi::tss2_esys::Tss2_MU_TPMT_SIGNATURE_Unmarshal;

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
                        return Err(KeylimeError::Other(format!(
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

    fn vec_to_pcrdata(val: &[u8]) -> Result<(PcrSelectionList, PcrData)> {
        const PCRSEL_SIZE: usize = std::mem::size_of::<TPML_PCR_SELECTION>();
        const DIGEST_SIZE: usize = std::mem::size_of::<TPML_DIGEST>();

        let mut reader = std::io::Cursor::new(val);
        let mut pcrsel_vec = [0u8; PCRSEL_SIZE];
        let len = reader.read(&mut pcrsel_vec)?;
        if len != pcrsel_vec.len() {
            return Err(KeylimeError::InvalidRequest);
        }
        let mut pcrsel = unsafe {
            std::mem::transmute::<[u8; PCRSEL_SIZE], TPML_PCR_SELECTION>(
                pcrsel_vec,
            )
        };
        let pcrlist: PcrSelectionList = pcrsel.try_into()?;

        let mut count_vec = [0u8; 4];
        let len = reader.read(&mut count_vec)?;
        if len < count_vec.len() {
            return Err(KeylimeError::InvalidRequest);
        }
        let count = u32::from_le_bytes(count_vec);
        // Always 1 PCR digest should follow
        if count != 1 {
            return Err(KeylimeError::InvalidRequest);
        }

        let mut digest_vec = [0u8; DIGEST_SIZE];
        let len = reader.read(&mut digest_vec)?;
        if len != digest_vec.len() {
            return Err(KeylimeError::InvalidRequest);
        }
        let mut digest = unsafe {
            std::mem::transmute::<[u8; DIGEST_SIZE], TPML_DIGEST>(digest_vec)
        };
        let mut digest_list = DigestList::new();
        for i in 0..digest.count {
            digest_list.add(digest.digests[i as usize].try_into()?);
        }

        let pcrdata = PcrData::create(&pcrlist, &digest_list)?;
        Ok((pcrlist, pcrdata))
    }

    pub(crate) fn decode_quote_string(
        quote: &str,
    ) -> Result<(AttestBuffer, Signature, PcrSelectionList, PcrData)> {
        if !quote.starts_with('r') {
            return Err(KeylimeError::InvalidRequest);
        }
        // extract components from the concatenated string
        let mut split = quote[1..].split(':');
        let att_str = split.next().ok_or(KeylimeError::InvalidRequest)?;
        let sig_str = split.next().ok_or(KeylimeError::InvalidRequest)?;
        let pcr_str = split.next().ok_or(KeylimeError::InvalidRequest)?;

        // base64 decoding
        let att_comp_finished = base64::decode(att_str)?;
        let sig_comp_finished = base64::decode(sig_str)?;
        let pcr_comp_finished = base64::decode(pcr_str)?;

        // zlib uncompression
        let mut att_comp = ZlibDecoder::new(att_comp_finished.as_slice());
        let mut att_vec = Vec::new();
        let _ = att_comp.read_to_end(&mut att_vec)?;

        let mut sig_comp = ZlibDecoder::new(sig_comp_finished.as_slice());
        let mut sig_vec = Vec::new();
        let _ = sig_comp.read_to_end(&mut sig_vec)?;

        let mut pcr_comp = ZlibDecoder::new(pcr_comp_finished.as_slice());
        let mut pcr_vec = Vec::new();
        let _ = pcr_comp.read_to_end(&mut pcr_vec)?;

        let sig: Signature = vec_to_sig(&sig_vec)?.try_into()?;
        let (pcrsel, pcrdata) = vec_to_pcrdata(&pcr_vec)?;

        let mut att = TPM2B_ATTEST {
            size: att_vec
                .len()
                .try_into()
                .or(Err(KeylimeError::InvalidRequest))?,
            ..Default::default()
        };
        att.attestationData[0..att_vec.len()].copy_from_slice(&att_vec);
        Ok((att.try_into()?, sig, pcrsel, pcrdata))
    }

    // This performs the same checks as in tpm2_checkquote, namely:
    // signature, nonce, and PCR digests from the quote.
    //
    // Reference:
    // https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_checkquote.c
    pub(crate) fn check_quote(
        context: &mut Context,
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
                return Err(KeylimeError::Other(
                    "unable to verify quote signature".to_string(),
                ))
            }
        }

        // Ensure nonce is the same as given
        let attestation: Attest = att.try_into()?;
        if attestation.extra_data().value() != nonce {
            return Err(KeylimeError::Other(
                "nonce does not match".to_string(),
            ));
        }

        // Also ensure digest from quote matches PCR digest
        let pcrbank =
            pcrdata.pcr_bank(HashingAlgorithm::Sha256).ok_or_else(|| {
                KeylimeError::Other("no SHA256 bank".to_string())
            })?;
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
                return Err(KeylimeError::Other(format!(
                    "Expected attestation type TPM2_ST_ATTEST_QUOTE, got {:?}",
                    attestation.attestation_type()
                )));
            }
        };
        if quote_info.pcr_digest().value() != digest.as_ref() {
            return Err(KeylimeError::Other(
                "PCR digest does not match".to_string(),
            ));
        }

        Ok(())
    }
}

#[test]
fn quote_encode_decode() {
    use std::fs::File;
    use std::io::BufReader;
    use std::path::Path;

    let quote_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-data")
        .join("test-quote.txt");

    let f = File::open(&quote_path).expect("unable to open test-quote.txt");
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

#[ignore] // This will only work as an integration test because it needs keylime.conf
#[test]
fn pubkey_to_digest() {
    let (key, _) = crate::crypto::rsa_generate_pair(2048).unwrap(); //#[allow_ci]
    let digest = pubkey_to_tpm_digest(&key).unwrap(); //#[allow_ci]
}

#[test]
fn ek_from_hex() {
    assert_eq!(
        ek_from_hex_str("0x81000000").unwrap(), //#[allow_ci]
        ek_from_hex_str("81000000").unwrap()    //#[allow_ci]
    );
    assert_eq!(
        ek_from_hex_str("0xdeadbeef").unwrap(), //#[allow_ci]
        ek_from_hex_str("deadbeef").unwrap()    //#[allow_ci]
    );

    assert!(ek_from_hex_str("a").is_ok());
    assert!(ek_from_hex_str("18bb9").is_ok());

    assert!(ek_from_hex_str("qqq").is_err());
    assert!(ek_from_hex_str("0xqqq").is_err());
    assert!(ek_from_hex_str("0xdeadbeefqwerty").is_err());
    assert!(ek_from_hex_str("0x0x0x").is_err());
}

#[test]
fn mask() {
    assert_eq!(read_mask("0x0").unwrap(), vec![]); //#[allow_ci]

    assert_eq!(read_mask("0x1").unwrap(), vec![PcrSlot::Slot0]); //#[allow_ci]

    assert_eq!(read_mask("0x2").unwrap(), vec![PcrSlot::Slot1]); //#[allow_ci]

    assert_eq!(read_mask("0x4").unwrap(), vec![PcrSlot::Slot2]); //#[allow_ci]

    assert_eq!(
        read_mask("0x5").unwrap(), //#[allow_ci]
        vec![PcrSlot::Slot0, PcrSlot::Slot2]
    );

    assert_eq!(
        read_mask("0x6").unwrap(), //#[allow_ci]
        vec![PcrSlot::Slot1, PcrSlot::Slot2]
    );

    assert_eq!(read_mask("0x800000").unwrap(), vec![PcrSlot::Slot23]); //#[allow_ci]

    assert_eq!(
        read_mask("0xffffff").unwrap(), //#[allow_ci]
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

    assert!(read_mask("0x1ffffff").is_err());
}
