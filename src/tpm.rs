// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use crate::{common::config_get, Error as KeylimeError, Result};

use openssl::{
    pkey::{Id, PKeyRef, Public},
    rsa::Rsa,
};

use tss_esapi::{
    abstraction::{ak, cipher::Cipher, ek, DefaultKey},
    attributes::session::SessionAttributesBuilder,
    constants::{session_type::SessionType, tss::TPM2_ALG_NULL},
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
        session_handles::AuthSession,
    },
    structures::{Digest, DigestValues, EncryptedSecret, IDObject, Name},
    tss2_esys::{
        Tss2_MU_TPM2B_PUBLIC_Marshal, TPM2B_PUBLIC, TPMS_SCHEME_HASH,
        TPMT_SIG_SCHEME, TPMU_SIG_SCHEME,
    },
    Context, Tcti,
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

    let tcti = Tcti::from_str(&tcti_path)?;
    unsafe { Context::new(tcti) }.map_err(|e| e.into())
}

/*
 * Input: Connection context, asymmetric algo (optional)
 * Return: (Key handle, public cert, TPM public object)
 * Example call:
 * let (key, cert, tpm_pub) = tpm::create_ek(context, Some(AsymmetricAlgorithm::Rsa))
 */
pub(crate) fn create_ek(
    context: &mut Context,
    alg: Option<AsymmetricAlgorithm>,
) -> Result<(KeyHandle, Vec<u8>, Vec<u8>)> {
    // Set encryption algorithm
    let alg = match alg {
        Some(a) => a,
        None => {
            match config_get(
                "cloud_agent",
                "tpm_encryption_alg",
            )?
            .as_str()
            {
                "rsa" => AsymmetricAlgorithm::Rsa,
                "ecc" => AsymmetricAlgorithm::Ecc,
                _ => return Err(KeylimeError::Configuration(String::from("Encryption algorithm provided in keylime.conf is not supported")))
            }
        }
    };

    // Retrieve EK handle, EK pub cert, and TPM pub object
    let handle = ek::create_ek_object(context, alg, DefaultKey)?;
    let cert = ek::retrieve_ek_pubcert(context, alg)?;
    let (tpm_pub, _, _) = context.read_public(handle)?;

    // Convert TPM pub object to Vec<u8>
    // See: https://github.com/fedora-iot/clevis-pin-tpm2/blob/master/src/tpm_objects.rs#L64
    let mut offset = 0u64;
    let mut tpm_pub_vec = Vec::with_capacity((tpm_pub.size + 4) as usize);

    unsafe {
        let res = Tss2_MU_TPM2B_PUBLIC_Marshal(
            &tpm_pub,
            tpm_pub_vec.as_mut_ptr(),
            tpm_pub_vec.capacity() as u64,
            &mut offset,
        );
        if res != 0 {
            panic!("out of memory or invalid data received from TPM"); //#[allow_ci]
        }
        tpm_pub_vec.set_len(offset as usize);
    }

    Ok((handle, cert, tpm_pub_vec))
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

/* Convert TPM pub object to Vec<u8>
 * https://github.com/fedora-iot/clevis-pin-tpm2/blob/master/src/tpm_objects.rs#L64
*/
pub(crate) fn tpm_pub_to_vec(tpm_pub: TPM2B_PUBLIC) -> Vec<u8> {
    let mut offset = 0u64;
    let mut tpm_pub_vec = Vec::with_capacity((tpm_pub.size + 4) as usize);

    unsafe {
        let res = Tss2_MU_TPM2B_PUBLIC_Marshal(
            &tpm_pub,
            tpm_pub_vec.as_mut_ptr(),
            tpm_pub_vec.capacity() as u64,
            &mut offset,
        );
        if res != 0 {
            panic!("out of memory or invalid data received from TPM"); //#[allow_ci]
        }
        tpm_pub_vec.set_len(offset as usize);
    }

    tpm_pub_vec
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
) -> Result<(KeyHandle, Name, Vec<u8>)> {
    let ak = ak::create_ak(
        ctx,
        handle,
        HashingAlgorithm::Sha256,
        SignatureScheme::RsaSsa,
        None,
        DefaultKey,
    )?;
    let ak_tpm2b_pub = ak.out_public;
    let tpm2_pub_vec = tpm_pub_to_vec(ak_tpm2b_pub);
    let ak_handle =
        ak::load_ak(ctx, handle, None, ak.out_private, ak.out_public)?;
    let (_, name, _) = ctx.read_public(ak_handle)?;
    Ok((ak_handle, name, tpm2_pub_vec))
}

const TSS_MAGIC: u32 = 3135029470;

fn parse_cred_and_secret(
    keyblob: Vec<u8>,
) -> Result<(IDObject, EncryptedSecret)> {
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

    let credential = IDObject::try_from(credential)?;
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

    ctx.flush_context(ak.into())?;
    ctx.flush_context(ek.into())?;

    resp
}

// Returns TSS struct corresponding to an algorithm specified as a string, ex.
// the string from the keylime.conf file.
pub(crate) fn get_hash_alg(alg: String) -> Result<HashingAlgorithm> {
    match alg.as_str() {
        "sha256" => Ok(HashingAlgorithm::Sha256),
        other => {
            Err(KeylimeError::Other(format!("{:?} not implemented", alg)))
        }
    }
}

#[derive(Debug)]
pub(crate) enum TpmSigScheme {
    AlgNull,
}

impl Default for TpmSigScheme {
    fn default() -> Self {
        TpmSigScheme::AlgNull
    }
}

// Returns TSS struct corresponding to a signature scheme.
pub(crate) fn get_sig_scheme(
    scheme: TpmSigScheme,
) -> Result<TPMT_SIG_SCHEME> {
    match scheme {
        // The TPM2_ALG_NULL sig scheme can be filled out with placeholder data
        // in the details field.
        TpmSigScheme::AlgNull => Ok(TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: TPMU_SIG_SCHEME {
                any: TPMS_SCHEME_HASH {
                    hashAlg: TPM2_ALG_NULL,
                },
            },
        }),
        _ => Err(KeylimeError::Other(format!(
            "The signature scheme {:?} is not implemented",
            scheme
        ))),
    }
}

// Takes a public PKey and returns a DigestValue of it.
pub(crate) fn pubkey_to_tpm_digest(
    pubkey: &PKeyRef<Public>,
    algo: HashingAlgorithm,
) -> Result<DigestValues> {
    match pubkey.id() {
        Id::RSA => {
            let mut keydigest = DigestValues::new();
            let rsa = pubkey.rsa()?.public_key_to_pem()?;

            match algo {
                HashingAlgorithm::Sha256 => {
                    let mut hasher = openssl::sha::Sha256::new();
                    hasher.update(&rsa);
                    let hash = hasher.finish();
                    let mut hashvec = Vec::new();
                    hashvec.extend(&hash);

                    let digest = Digest::try_from(hashvec)?;
                    keydigest.set(algo, digest);
                    Ok(keydigest)
                }
                other_alg => {
                    return Err(KeylimeError::Other(format!(
                        "Algorithm {:?} not yet supported in pubkey to digest conversion", other_alg   
                    )));
                }
            }
        }
        other_id => {
            return Err(KeylimeError::Other(format!(
            "Converting to digest value for key type {:?} is not yet implemented",
            other_id
            )));
        }
    }
}

#[ignore] // This will only work as an integration test because it needs keylime.conf
#[test]
fn pubkey_to_digest() {
    let (key, _) = crate::crypto::rsa_generate_pair(2048).unwrap(); //#[allow_ci]
    let hash_alg =
        get_hash_alg(config_get("cloud_agent", "tpm_hash_alg").unwrap()) //#[allow_ci]
            .unwrap(); //#[allow_ci]

    let digest = pubkey_to_tpm_digest(&key, hash_alg).unwrap(); //#[allow_ci]
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
