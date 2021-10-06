// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::crypto;
use crate::{
    common::{
        KeySet, SymmKey, AES_BLOCK_SIZE, AGENT_UUID_LEN, AUTH_TAG_LEN,
        KEY_LEN,
    },
    Error, QuoteData, Result,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use log::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeUKey {
    auth_tag: String,
    encrypted_key: String,
    payload: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeVKey {
    encrypted_key: String,
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

// Attempt to combine U and V keys into the payload decryption key. An HMAC over
// the agent's UUID using the decryption key must match the provided authentication
// tag. Returning None is okay here in case we are still waiting on another handler to
// process data.
pub(crate) fn try_combine_keys(
    keyset1: &mut KeySet,
    keyset2: &mut KeySet,
    symm_key_out: &mut SymmKey,
    uuid: &[u8],
    auth_tag: &[u8; AUTH_TAG_LEN],
) -> Result<Option<()>> {
    // U, V keys and auth_tag must be present for this to succeed
    if keyset1.all_empty()
        || keyset2.all_empty()
        || auth_tag == &[0u8; AUTH_TAG_LEN]
    {
        debug!("Still waiting on u or v key or auth_tag");
        return Ok(None);
    }

    for key1 in &keyset1.set {
        for key2 in &keyset2.set {
            xor_to_outbuf(
                &mut symm_key_out.bytes[..],
                &key1.bytes[..],
                &key2.bytes[..],
            );

            // Computes HMAC over agent UUID with provided key (payload decryption key) and
            // checks that this matches the provided auth_tag.
            let auth_tag = hex::decode(auth_tag)?;
            if crypto::verify_hmac(&symm_key_out.bytes, uuid, &auth_tag)
                .is_ok()
            {
                info!(
                    "Successfully derived symmetric payload decryption key"
                );

                keyset1.clear();
                keyset2.clear();
                return Ok(Some(()));
            }
        }
    }

    Err(Error::Other(
        "HMAC check failed for all U and V key combinations".to_string(),
    ))
}

// We can't simply accept payload as web::Json<KeylimeUKey>, as the
// Content-Type header is currently missing, which is required by
// actix-web 3:
// https://github.com/actix/actix-web/blob/web-v3.3.3/src/types/json.rs#L339
pub async fn u_key(
    body: web::Bytes,
    req: HttpRequest,
    quote_data: web::Data<QuoteData>,
) -> impl Responder {
    info!("Received ukey");

    let key: KeylimeUKey = serde_json::from_slice(&body.to_vec())?;

    // must unwrap when using lock
    // https://github.com/rust-lang-nursery/failure/issues/192
    let mut global_current_keyset = quote_data.ukeys.lock().unwrap(); //#[allow_ci]
    let mut global_other_keyset = quote_data.vkeys.lock().unwrap(); //#[allow_ci]
    let mut global_symm_key = quote_data.payload_symm_key.lock().unwrap(); //#[allow_ci]
    let mut global_encr_payload = quote_data.encr_payload.lock().unwrap(); //#[allow_ci]
    let mut global_auth_tag = quote_data.auth_tag.lock().unwrap(); //#[allow_ci]

    // get key and decode it from web data
    let encrypted_key =
        base64::decode(&key.encrypted_key).map_err(Error::from)?;
    // Uses NK (key for encrypting data from verifier or tenant to agent in transit) to
    // decrypt U and V keys, which will be combined into one key that can decrypt the
    // payload.
    //
    // Reference:
    // https://github.com/keylime/keylime/blob/f3c31b411dd3dd971fd9d614a39a150655c6797c/ \
    // keylime/crypto.py#L118
    let decrypted_key =
        crypto::rsa_oaep_decrypt(&quote_data.priv_key, &encrypted_key)?;

    global_current_keyset
        .set
        .push(SymmKey::from_vec(decrypted_key));

    // note: the auth_tag shouldn't be base64 decoded here
    global_auth_tag.copy_from_slice(key.auth_tag.as_bytes());

    if let Some(payload) = &key.payload {
        let encr_payload = base64::decode(&payload).map_err(Error::from)?;
        global_encr_payload.extend(encr_payload.iter());
    }

    let _ = try_combine_keys(
        &mut global_current_keyset,
        &mut global_other_keyset,
        &mut global_symm_key,
        quote_data.agent_uuid.as_bytes(),
        &global_auth_tag,
    )?;

    HttpResponse::Ok().await
}

// We can't simply accept payload as web::Json<KeylimeVKey>, as the
// Content-Type header is currently missing, which is required by
// actix-web 3:
// https://github.com/actix/actix-web/blob/web-v3.3.3/src/types/json.rs#L339
pub async fn v_key(
    body: web::Bytes,
    req: HttpRequest,
    quote_data: web::Data<QuoteData>,
) -> impl Responder {
    info!("Received vkey");

    let key: KeylimeVKey = serde_json::from_slice(&body.to_vec())?;

    // must unwrap when using lock
    // https://github.com/rust-lang-nursery/failure/issues/192
    let mut global_current_keyset = quote_data.vkeys.lock().unwrap(); //#[allow_ci]
    let mut global_other_keyset = quote_data.ukeys.lock().unwrap(); //#[allow_ci]
    let mut global_symm_key = quote_data.payload_symm_key.lock().unwrap(); //#[allow_ci]
    let mut global_encr_payload = quote_data.encr_payload.lock().unwrap(); //#[allow_ci]
    let mut global_auth_tag = quote_data.auth_tag.lock().unwrap(); //#[allow_ci]

    // get key and decode it from web data
    let encrypted_key =
        base64::decode(&key.encrypted_key).map_err(Error::from)?;
    // Uses NK (key for encrypting data from verifier or tenant to agent in transit) to
    // decrypt U and V keys, which will be combined into one key that can decrypt the
    // payload.
    //
    // Reference:
    // https://github.com/keylime/keylime/blob/f3c31b411dd3dd971fd9d614a39a150655c6797c/ \
    // keylime/crypto.py#L118
    let decrypted_key =
        crypto::rsa_oaep_decrypt(&quote_data.priv_key, &encrypted_key)?;

    global_current_keyset
        .set
        .push(SymmKey::from_vec(decrypted_key));

    let _ = try_combine_keys(
        &mut global_current_keyset,
        &mut global_other_keyset,
        &mut global_symm_key,
        quote_data.agent_uuid.as_bytes(),
        &global_auth_tag,
    )?;

    HttpResponse::Ok().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{KeylimeConfig, API_VERSION, KEY_LEN};
    use crate::crypto::compute_hmac;
    #[cfg(feature = "testing")]
    use crate::crypto::testing::rsa_oaep_encrypt;
    use actix_web::{test, web, App};
    use openssl::{
        encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding,
        sign::Signer,
    };

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn test_u_or_v_key() {
        let test_config = KeylimeConfig::default();
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route(
                    &format!("/{}/keys/ukey", API_VERSION),
                    web::post().to(u_key),
                )
                .route(
                    &format!("/{}/keys/vkey", API_VERSION),
                    web::post().to(v_key),
                ),
        )
        .await;

        let u: &[u8; KEY_LEN] = b"01234567890123456789012345678901";
        let v: &[u8; KEY_LEN] = b"ABCDEFGHIJABCDEFGHIJABCDEFGHIJAB";
        let mut k = vec![0u8; KEY_LEN];
        xor_to_outbuf(&mut k, u, v).unwrap(); //#[allow_ci]

        let encrypted_key = rsa_oaep_encrypt(&quotedata.pub_key, u).unwrap(); //#[allow_ci]

        let auth_tag =
            compute_hmac(&k, test_config.agent_uuid.as_bytes()).unwrap(); //#[allow_ci]

        let ukey = KeylimeUKey {
            encrypted_key: base64::encode(&encrypted_key),
            auth_tag: hex::encode(auth_tag),
            payload: None,
        };

        let req = test::TestRequest::post()
            .uri(&format!("/{}/keys/ukey", API_VERSION,))
            .set_json(&ukey)
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());

        let encrypted_key = rsa_oaep_encrypt(&quotedata.pub_key, v).unwrap(); //#[allow_ci]

        let vkey = KeylimeVKey {
            encrypted_key: base64::encode(&encrypted_key),
        };

        let req = test::TestRequest::post()
            .uri(&format!("/{}/keys/vkey", API_VERSION,))
            .set_json(&vkey)
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());

        let key = quotedata.payload_symm_key.lock().unwrap(); //#[allow_ci]
        assert!(!key.is_empty());
        assert_eq!(key.bytes, k.as_slice());
    }
}
