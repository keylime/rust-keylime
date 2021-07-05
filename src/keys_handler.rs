// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{
    common::{AES_BLOCK_SIZE, AGENT_UUID_LEN, AUTH_TAG_LEN, KEY_LEN},
    Error, Result,
};
use actix_web::{web, HttpResponse, Responder};
use log::*;
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Padding,
    sign::Signer,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Verify {
    challenge: String,
}

#[derive(Deserialize)]
pub struct UkeyJson {
    b64_encrypted_key: String, // this will be handled as a blob once wired in
    auth_tag: String,
}

// Helper function for combining U and V keys and storing output to a buffer.
pub(crate) fn xor_to_outbuf(
    outbuf: &mut [u8],
    a: &[u8],
    b: &[u8],
) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::Other(
            "cannot xor differing length slices".to_string(),
        ));
    }
    for (out, (x, y)) in outbuf.iter_mut().zip(a.iter().zip(b)) {
        *out = *x ^ *y;
    }

    Ok(())
}

// Computes HMAC over agent UUID with provided key (payload decryption key) and
// checks that this matches the provided auth_tag.
pub(crate) fn check_hmac(
    key: &[u8; KEY_LEN],
    uuid: &[u8],
    auth_tag: &[u8; AUTH_TAG_LEN],
) -> Result<()> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha384(), &pkey)?;
    signer.update(uuid)?;
    let hmac = signer.sign_to_vec()?;
    let hmac = hex::encode(hmac);

    if hmac.len() != auth_tag.len() {
        return Err(Error::Other(format!(
            "hmac len {} does not == auth_tag.len() {}",
            hmac.len(),
            auth_tag.len()
        )));
    }

    let auth_tag_string = String::from_utf8(auth_tag.to_vec())?;
    if hmac != auth_tag_string {
        return Err(Error::Other(format!(
            "hmac check failed: hmac {} != auth_tag {}",
            hmac, auth_tag_string
        )));
    }

    info!("HMAC check passed");
    Ok(())
}

// Attempt to combine U and V keys into the payload decryption key. An HMAC over
// the agent's UUID using the decryption key must match the provided authentication
// tag. Returning None is okay here in case we are still waiting on another handler to
// process data.
pub(crate) fn try_combine_keys(
    key1: &[u8; KEY_LEN],
    key2: &[u8; KEY_LEN],
    symm_key_out: &mut [u8; KEY_LEN],
    uuid: &[u8],
    auth_tag: &[u8; AUTH_TAG_LEN],
) -> Result<Option<()>> {
    // U, V keys and auth_tag must be present for this to succeed
    if key1 == &[0u8; KEY_LEN]
        || key2 == &[0u8; KEY_LEN]
        || auth_tag == &[0u8; AUTH_TAG_LEN]
    {
        debug!("Still waiting on u or v key or auth_tag");
        return Ok(None);
    }

    // TODO: u and v keys should be sets

    xor_to_outbuf(&mut symm_key_out[..], &key1[..], &key2[..]);

    check_hmac(symm_key_out, uuid, auth_tag)?;

    Ok(Some(()))
}

// Uses NK (key for encrypting data from verifier or tenant to agent in transit) to
// decrypt U and V keys, which will be combined into one key that can decrypt the
// payload.
//
// Reference:
// https://github.com/keylime/keylime/blob/f3c31b411dd3dd971fd9d614a39a150655c6797c/ \
// keylime/crypto.py#L118
pub(crate) fn decrypt_u_or_v_key(
    nk_priv: &PKey<Private>,
    encrypted_key: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut decrypter = Decrypter::new(nk_priv)?;

    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha1())?;

    // Create an output buffer
    let buffer_len = decrypter.decrypt_len(&encrypted_key)?;
    let mut decrypted = vec![0; buffer_len];

    // Decrypt and truncate the buffer
    let decrypted_len = decrypter.decrypt(&encrypted_key, &mut decrypted)?;
    decrypted.truncate(decrypted_len);

    Ok(decrypted)
}

pub async fn ukey(param: web::Json<UkeyJson>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "b64_encrypted_key: {} auth_tag: {}",
        param.b64_encrypted_key, param.auth_tag
    ))
}
