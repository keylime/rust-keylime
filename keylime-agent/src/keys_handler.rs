// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{
    config::KeylimeConfig,
    payloads::{Payload, PayloadMessage},
    Error, QuoteData, Result,
};
use actix_web::{http, web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use keylime::{
    crypto::{
        self,
        auth_tag::AuthTag,
        encrypted_data::EncryptedData,
        symmkey::{KeySet, SymmKey},
    },
    json_wrapper::JsonWrapper,
};
use log::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::TryInto;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeUKey {
    auth_tag: String,
    encrypted_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeVKey {
    encrypted_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeylimePubkey {
    pubkey: String,
}

#[derive(Deserialize, Debug)]
pub struct KeylimeChallenge {
    challenge: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeHMAC {
    hmac: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct UKey {
    decrypted_key: SymmKey,
    auth_tag: AuthTag,
    payload: Option<EncryptedData>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct VKey {
    decrypted_key: SymmKey,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum KeyMessage {
    UKey(UKey),
    VKey(VKey),
    Shutdown,
    GetSymmKey,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum SymmKeyMessage {
    SymmKey(Option<SymmKey>),
}

// Attempt to combine U and V keys into the payload decryption key. An HMAC over
// the agent's UUID using the decryption key must match the provided authentication
// tag. Returning None is okay here in case we are still waiting on another handler to
// process data.
fn try_combine_keys(
    ukeys: &mut Vec<UKey>,
    vkeys: &mut Vec<VKey>,
    uuid: &[u8],
) -> Option<(SymmKey, Option<Payload>)> {
    // U, V keys and auth_tag must be present for this to succeed
    if ukeys.is_empty() || vkeys.is_empty() {
        debug!("Still waiting on u or v key");
        return None;
    }

    for ukey in ukeys.iter() {
        for vkey in vkeys.iter() {
            let symm_key = match ukey.decrypted_key.xor(&vkey.decrypted_key) {
                Ok(k) => k,
                Err(e) => {
                    continue;
                }
            };

            // Computes HMAC over agent UUID with provided key (payload decryption key) and
            // checks that this matches the provided auth_tag.
            if crypto::verify_hmac(
                symm_key.as_ref(),
                uuid,
                ukey.auth_tag.as_ref(),
            )
            .is_ok()
            {
                info!(
                    "Successfully derived symmetric payload decryption key"
                );

                let payload =
                    ukey.payload.as_ref().map(|encrypted_payload| Payload {
                        symm_key: symm_key.clone(),
                        encrypted_payload: encrypted_payload.clone(),
                    });

                ukeys.clear();
                vkeys.clear();

                return Some((symm_key, payload));
            }
        }
    }

    warn!("HMAC check failed for all U and V key combinations");
    None
}

async fn u_key(
    body: web::Json<KeylimeUKey>,
    req: HttpRequest,
    quote_data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    debug!("Received ukey");

    // get key and decode it from web data
    let encrypted_key = match general_purpose::STANDARD
        .decode(&body.encrypted_key)
        .map_err(Error::from)
    {
        Ok(k) => k,
        Err(e) => {
            warn!(
                    "POST u_key returning 400 response. Invalid base64 encoding in encrypted_key: {e}"
                );
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("Invalid base64 encoding in encrypted_key: {e}"),
            ));
        }
    };

    // Uses NK (key for encrypting data from verifier or tenant to agent in transit) to
    // decrypt U and V keys, which will be combined into one key that can decrypt the
    // payload.
    //
    // Reference:
    // https://github.com/keylime/keylime/blob/f3c31b411dd3dd971fd9d614a39a150655c6797c/ \
    // keylime/crypto.py#L118
    let decrypted_key = match crypto::rsa_oaep_decrypt(
        &quote_data.priv_key,
        &encrypted_key,
    )
    .map_err(Error::from)
    {
        Ok(k) => k,
        Err(e) => {
            warn!("POST u_key returning 400 response. Failed to decrypt encrypted_key: {e}");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("Failed to decrypt encrypted_key: {e}"),
            ));
        }
    };

    let decrypted_key: SymmKey = match decrypted_key.as_slice().try_into() {
        Ok(k) => k,
        Err(e) => {
            warn!("POST u_key returning 400 response. Invalid decrypted key: {e}");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("Invalid decrypted key: {e}"),
            ));
        }
    };

    let auth_tag = match hex::decode(&body.auth_tag).map_err(Error::from) {
        Ok(t) => t,
        Err(e) => {
            warn!("POST u_key returning 400 response: Invalid hex encoding in auth_tag: {e}");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("Invalid hex encoding in auth_tag: {e}"),
            ));
        }
    };

    let auth_tag = match auth_tag.as_slice().try_into() {
        Ok(t) => t,
        Err(e) => {
            warn!("POST u_key returning 400 response: {e}");
            return HttpResponse::BadRequest()
                .json(JsonWrapper::error(400, e));
        }
    };

    let payload = match &body.payload {
        Some(data) => match general_purpose::STANDARD
            .decode(data)
            .map_err(Error::from)
        {
            Ok(d) => Some(d.into()),
            Err(e) => {
                warn!("POST u_key returning 400 response. Invalid base64 encoding in payload: {e}");
                return HttpResponse::BadRequest().json(JsonWrapper::error(
                    400,
                    format!("Invalid base64 encoding in payload: {e}"),
                ));
            }
        },
        None => None,
    };

    let m = KeyMessage::UKey(UKey {
        decrypted_key,
        auth_tag,
        payload,
    });

    debug!("Sending UKey message to keys worker");

    if let Err(e) = quote_data.keys_tx.send((m, None)).await {
        warn!("Failed to send UKey message to keys worker");
        return HttpResponse::InternalServerError().json(JsonWrapper::error(
            500,
            "Failed to send UKey message to keys worker".to_string(),
        ));
    }

    HttpResponse::Ok().json(JsonWrapper::success(()))
}

async fn v_key(
    body: web::Json<KeylimeVKey>,
    req: HttpRequest,
    quote_data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    debug!("Received vkey");

    // get key and decode it from web data
    let encrypted_key = match general_purpose::STANDARD
        .decode(&body.encrypted_key)
        .map_err(Error::from)
    {
        Ok(k) => k,
        Err(e) => {
            warn!("POST v_key returning 400 response. Invalid base64 encoding in encrypted_key: {e}");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("Invalid base64 encoding in encrypted_key: {e}"),
            ));
        }
    };

    // Uses NK (key for encrypting data from verifier or tenant to agent in transit) to
    // decrypt U and V keys, which will be combined into one key that can decrypt the
    // payload.
    //
    // Reference:
    // https://github.com/keylime/keylime/blob/f3c31b411dd3dd971fd9d614a39a150655c6797c/ \
    // keylime/crypto.py#L118
    let decrypted_key = match crypto::rsa_oaep_decrypt(
        &quote_data.priv_key,
        &encrypted_key,
    )
    .map_err(Error::from)
    {
        Ok(k) => k,
        Err(e) => {
            warn!("POST v_key returning 400 response. Failed to decrypt encrypted_key: {e}");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("Failed to decrypt encrypted_key: {e}"),
            ));
        }
    };

    let decrypted_key: SymmKey = match decrypted_key.as_slice().try_into() {
        Ok(k) => k,
        Err(e) => {
            warn!("POST v_key returning 400 response. Decrypted key is invalid: {e}");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                format!("Decrypted key is invalid: {e}"),
            ));
        }
    };

    let m = KeyMessage::VKey(VKey { decrypted_key });

    debug!("Sending VKey message to keys worker");

    if let Err(e) = quote_data.keys_tx.send((m, None)).await {
        warn!("Failed to send VKey message to keys worker");
        return HttpResponse::InternalServerError().json(JsonWrapper::error(
            500,
            "Failed to send VKey message to keys worker".to_string(),
        ));
    }

    HttpResponse::Ok().json(JsonWrapper::success(()))
}

async fn pubkey(
    req: HttpRequest,
    data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    match crypto::pkey_pub_to_pem(&data.pub_key) {
        Ok(pubkey) => {
            let response = JsonWrapper::success(KeylimePubkey { pubkey });
            info!("GET pubkey returning 200 response.");

            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            debug!("Unable to retrieve public key: {:?}", e);
            HttpResponse::InternalServerError().json(JsonWrapper::error(
                500,
                "Unable to retrieve public key".to_string(),
            ))
        }
    }
}

async fn get_symm_key(
    keys_tx: Sender<(KeyMessage, Option<oneshot::Sender<SymmKeyMessage>>)>,
) -> Result<Option<SymmKey>> {
    let (resp_tx, resp_rx) = oneshot::channel::<SymmKeyMessage>();

    debug!("Sending GetSymmKey message to keys worker");

    if let Err(e) =
        keys_tx.send((KeyMessage::GetSymmKey, Some(resp_tx))).await
    {
        return Err(Error::Sender(format!(
            "Failed to send GetSymmKey message: {e}"
        )));
    };

    match resp_rx.await {
        Ok(message) => match message {
            SymmKeyMessage::SymmKey(symmkey) => Ok(symmkey),
            _ => Err(Error::Receiver(
                "Invalid response for GetSymmKey message".to_string(),
            )),
        },
        Err(e) => Err(Error::Receiver(format!(
            "Failed to receive SymmKey message: {e}"
        ))),
    }
}

async fn verify(
    param: web::Query<KeylimeChallenge>,
    req: HttpRequest,
    data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    if param.challenge.is_empty() {
        warn!(
            "GET key challenge returning 400 response. No challenge provided"
        );
        return HttpResponse::BadRequest()
            .json(JsonWrapper::error(400, "No challenge provided."));
    }

    if !param.challenge.chars().all(char::is_alphanumeric) {
        warn!("GET key challenge returning 400 response. Parameters should be strictly alphanumeric: {}", param.challenge);
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!(
                "Parameters should be strictly alphanumeric: {}",
                param.challenge
            ),
        ));
    }

    // Send a message requesting the symmetric key
    if let Ok(key) = get_symm_key(data.keys_tx.clone()).await {
        let k = match key {
            Some(k) => k,
            None => {
                warn!("GET key challenge returning 400 response. Bootstrap key not available");
                return HttpResponse::BadRequest().json(JsonWrapper::error(
                    400,
                    "Bootstrap key not yet available.",
                ));
            }
        };

        match crypto::compute_hmac(k.as_ref(), param.challenge.as_bytes()) {
            Ok(hmac) => {
                let response = JsonWrapper::success(KeylimeHMAC {
                    hmac: hex::encode(hmac),
                });

                info!("GET key challenge returning 200 response.");
                HttpResponse::Ok().json(response)
            }
            Err(e) => {
                warn!("GET key challenge failed: {:?}", e);
                HttpResponse::InternalServerError().json(JsonWrapper::error(
                    500,
                    "GET key challenge failed".to_string(),
                ))
            }
        }
    } else {
        warn!("GET key challenge returning 500 response. Failed to get bootstrap key.");
        HttpResponse::InternalServerError()
            .json(JsonWrapper::error(500, "Failed to get bootstrap key."))
    }
}

async fn request_run_payload(
    payloads_tx: Sender<PayloadMessage>,
    payload: Payload,
) -> Result<()> {
    let m = PayloadMessage::RunPayload(payload);
    if let Err(e) = payloads_tx.send(m).await {
        warn!("Failed to send RunPayload message to payloads worker");
        return Err(Error::Sender(
            "Failed to send RunPayload message to payloads worker"
                .to_string(),
        ));
    }
    debug!("Sent RunPayload message to payloads worker");
    Ok(())
}

async fn process_keys(
    mut ukeys: &mut Vec<UKey>,
    mut vkeys: &mut Vec<VKey>,
    uuid: String,
    payloads_tx: Sender<PayloadMessage>,
    run_payload: bool,
) -> Option<SymmKey> {
    match try_combine_keys(ukeys, vkeys, uuid.as_bytes()) {
        Some((key, p)) => {
            if run_payload {
                if let Some(payload) = p {
                    match request_run_payload(payloads_tx.clone(), payload)
                        .await
                    {
                        Ok(_) => {
                            debug!(
                                "Sent RunPayload message to payloads worker"
                            );
                        }
                        Err(e) => {
                            warn!("{e}");
                        }
                    }
                }
            } else {
                warn!("agent mTLS is disabled, and unless 'enable_insecure_payload' is set to 'True', payloads cannot be deployed'");
            }

            Some(key)
        }
        None => None,
    }
}

pub(crate) async fn worker(
    run_payload: bool,
    uuid: String,
    mut keys_rx: Receiver<(
        KeyMessage,
        Option<oneshot::Sender<SymmKeyMessage>>,
    )>,
    mut payloads_tx: Sender<PayloadMessage>,
) -> Result<()> {
    let mut ukeys: Vec<UKey> = Vec::new();
    let mut vkeys: Vec<VKey> = Vec::new();
    let mut symm_key: Option<SymmKey> = None;

    debug!("Starting keys worker");

    // Receive message
    while let Some((message, resp_tx)) = keys_rx.recv().await {
        match message {
            KeyMessage::GetSymmKey => {
                if let Some(r) = resp_tx {
                    if let Err(e) =
                        r.send(SymmKeyMessage::SymmKey(symm_key.clone()))
                    {
                        debug!("Failed to send SymmKey message");
                    }
                } else {
                    debug!("Empty receiver in GetSymmKey message");
                }
            }
            KeyMessage::Shutdown => {
                keys_rx.close();
            }
            KeyMessage::UKey(ukey) => {
                // Store received data
                ukeys.push(ukey);
                if let Some(key) = process_keys(
                    &mut ukeys,
                    &mut vkeys,
                    uuid.clone(),
                    payloads_tx.clone(),
                    run_payload,
                )
                .await
                {
                    symm_key = Some(key);
                }
            }
            KeyMessage::VKey(vkey) => {
                // Store received data
                vkeys.push(vkey);
                if let Some(key) = process_keys(
                    &mut ukeys,
                    &mut vkeys,
                    uuid.clone(),
                    payloads_tx.clone(),
                    run_payload,
                )
                .await
                {
                    symm_key = Some(key);
                }
            }
        }
    }

    debug!("Shutting down keys worker");
    Ok(())
}

/// Handles the default case for the /keys scope
async fn keys_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = "URI not supported, only /pubkey and /verify are supported for GET in /keys interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        http::Method::POST => {
            error = 400;
            message = "URI not supported, only /ukey and /vkey are supported for POST in /keys interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported in /keys interface";
            response = HttpResponse::MethodNotAllowed()
                .insert_header(http::header::Allow(vec![
                    http::Method::GET,
                    http::Method::POST,
                ]))
                .json(JsonWrapper::error(error, message));
        }
    };

    warn!(
        "{} returning {} response. {}",
        req.head().method,
        error,
        message
    );

    response
}

/// Configure the endpoints for the /keys scope
pub(crate) fn configure_keys_endpoints(cfg: &mut web::ServiceConfig) {
    _ = cfg
        .service(web::resource("/pubkey").route(web::get().to(pubkey)))
        .service(web::resource("/ukey").route(web::post().to(u_key)))
        .service(web::resource("/verify").route(web::get().to(verify)))
        .service(web::resource("/vkey").route(web::post().to(v_key)))
        .default_service(web::to(keys_default));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "testing")]
    use crate::crypto::testing::{
        encrypt_aead, pkey_pub_from_pem, rsa_oaep_encrypt,
    };
    use crate::{
        config::KeylimeConfig,
        crypto::{compute_hmac, AES_128_KEY_LEN, AES_256_KEY_LEN},
        payloads,
    };
    use actix_rt::Arbiter;
    use actix_web::{test, web, App};
    use openssl::{
        encrypt::Encrypter,
        hash::MessageDigest,
        pkey::{PKey, Public},
        rand::rand_bytes,
        rsa::Padding,
        sign::Signer,
    };
    use serde_json::{json, Value};
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };
    use tokio::sync::mpsc;

    // Enough length for testing both AES-128 and AES-256
    const U: &[u8; AES_256_KEY_LEN] = b"01234567890123456789012345678901";
    const V: &[u8; AES_256_KEY_LEN] = b"ABCDEFGHIJABCDEFGHIJABCDEFGHIJAB";

    fn prepare_keys(
        key_len: usize,
        payload: Option<EncryptedData>,
        uuid: String,
    ) -> (UKey, VKey, SymmKey) {
        let mut u_buf = [0; AES_256_KEY_LEN];
        let mut v_buf = [0; AES_256_KEY_LEN];

        rand_bytes(&mut u_buf).unwrap(); //#[allow_ci]
        rand_bytes(&mut v_buf).unwrap(); //#[allow_ci]

        let u: SymmKey = u_buf[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let v: SymmKey = v_buf[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let k = u.xor(&v).unwrap(); //#[allow_ci]

        let hmac = compute_hmac(k.as_ref(), uuid.as_bytes()).unwrap(); //#[allow_ci]
        let auth_tag: AuthTag = hmac.as_slice().try_into().unwrap(); //#[allow_ci]

        let ukey = UKey {
            decrypted_key: u,
            auth_tag,
            payload,
        };
        let vkey = VKey { decrypted_key: v };

        (ukey, vkey, k)
    }

    #[cfg(feature = "testing")]
    fn prepare_encrypted_keys(
        key_len: usize,
        payload: Option<EncryptedData>,
        uuid: String,
        pubkey: &PKey<Public>,
    ) -> (KeylimeUKey, KeylimeVKey, SymmKey) {
        let (ukey, vkey, k) = prepare_keys(key_len, payload, uuid);

        let encrypted_u =
            rsa_oaep_encrypt(pubkey, ukey.decrypted_key.as_ref()).unwrap(); //#[allow_ci]
        let encrypted_v =
            rsa_oaep_encrypt(pubkey, vkey.decrypted_key.as_ref()).unwrap(); //#[allow_ci]
        let encoded_auth_tag = hex::encode(ukey.auth_tag.as_ref());

        let enc_u = KeylimeUKey {
            auth_tag: encoded_auth_tag,
            encrypted_key: general_purpose::STANDARD.encode(encrypted_u),
            payload: ukey
                .payload
                .map(|p| general_purpose::STANDARD.encode(p.as_ref())),
        };

        let enc_v = KeylimeVKey {
            encrypted_key: general_purpose::STANDARD.encode(encrypted_v),
        };

        (enc_u, enc_v, k)
    }

    fn test_combine_keys(key_len: usize) {
        let mut ukeys = Vec::new();
        let mut vkeys = Vec::new();
        let uuid = "test-uuid";

        let (u, v, k) = prepare_keys(key_len, None, uuid.to_string());

        ukeys.push(u);
        vkeys.push(v);

        let result =
            try_combine_keys(&mut ukeys, &mut vkeys, uuid.as_bytes());
        assert!(result.is_some());

        // Check the keys list are emptied after a successful combination
        assert!(ukeys.is_empty());
        assert!(vkeys.is_empty());

        let (u, _, _) = prepare_keys(key_len, None, uuid.to_string());
        let (u2, v2, k2) = prepare_keys(key_len, None, uuid.to_string());
        let (u3, _, _) = prepare_keys(key_len, None, uuid.to_string());

        // Check that missing ukeys, vkeys, or auth_tag makes it to return None
        ukeys.push(u);
        let result =
            try_combine_keys(&mut ukeys, &mut vkeys, uuid.as_bytes());
        assert!(result.is_none());

        // Check that failed auth_tag_verification returns None
        vkeys.push(v2);
        let result =
            try_combine_keys(&mut ukeys, &mut vkeys, uuid.as_bytes());
        assert!(result.is_none());

        // Check that the keys vecs are untouched
        assert!(ukeys.len() == 1);
        assert!(vkeys.len() == 1);

        ukeys.push(u3);
        let result =
            try_combine_keys(&mut ukeys, &mut vkeys, uuid.as_bytes());
        assert!(result.is_none());

        // Check that the keys vecs are untouched
        assert!(ukeys.len() == 2);
        assert!(vkeys.len() == 1);

        // Check finally matching the keys
        ukeys.push(u2);
        let result =
            try_combine_keys(&mut ukeys, &mut vkeys, uuid.as_bytes());
        assert!(result.is_some());
        // Check the keys list are emptied after a successful combination
        assert!(ukeys.is_empty());
        assert!(vkeys.is_empty());

        if let Some((k, p)) = result {
            assert!(k == k2);
        }
    }

    #[test]
    async fn test_combine_keys_short() {
        test_combine_keys(AES_128_KEY_LEN);
    }

    #[test]
    async fn test_combine_keys_long() {
        test_combine_keys(AES_256_KEY_LEN);
    }

    #[actix_rt::test]
    async fn test_process_keys() {
        let mut ukeys = Vec::new();
        let mut vkeys = Vec::new();
        let uuid = "test-uuid";
        let data = "some_encrypted_data";
        let (u, v, k) = prepare_keys(
            AES_128_KEY_LEN,
            Some(data.as_bytes().into()),
            uuid.to_string(),
        );
        let (u256, _, _) = prepare_keys(
            AES_256_KEY_LEN,
            Some(data.as_bytes().into()),
            uuid.to_string(),
        );
        let (mut payload_tx, mut payload_rx) =
            mpsc::channel::<PayloadMessage>(1);
        let arbiter = Arbiter::new();

        let k_clone = k.clone();
        assert!(arbiter.spawn(Box::pin(async move {
            let msg = payload_rx.recv().await;
            assert!(msg.is_some());
            if let Some(m) = msg {
                assert!(
                    m == PayloadMessage::RunPayload(Payload {
                        symm_key: k_clone,
                        encrypted_payload: data.as_bytes().into(),
                    })
                );
            };
        })));

        // Push bogus key with different length
        ukeys.push(u256);
        ukeys.push(u);
        let result = process_keys(
            &mut ukeys,
            &mut vkeys,
            uuid.to_string(),
            payload_tx.clone(),
            true,
        )
        .await;
        assert!(result.is_none());

        // Check that the keys vecs are untouched
        assert!(ukeys.len() == 2);

        vkeys.push(v);
        let result = process_keys(
            &mut ukeys,
            &mut vkeys,
            uuid.to_string(),
            payload_tx,
            true,
        )
        .await;
        assert!(result.is_some());
        if let Some(key) = result {
            assert!(key == k);
        }
    }

    #[actix_rt::test]
    async fn test_keys_default() {
        let mut app = test::init_service(
            App::new().service(web::resource("/").to(keys_default)),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);

        let req = test::TestRequest::post()
            .uri("/")
            .data("some data")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);

        let req = test::TestRequest::delete().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let headers = resp.headers();

        assert!(headers.contains_key("allow"));
        assert_eq!(
            headers.get("allow").unwrap().to_str().unwrap(), //#[allow_ci]
            "GET, POST"
        );

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 405);
    }

    #[cfg(feature = "testing")]
    async fn test_u_or_v_key(key_len: usize, payload: Option<&[u8]>) {
        let test_config = KeylimeConfig::default();
        let (mut fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]

        // Create temporary working directory and secure mount
        let temp_workdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        fixture.secure_mount =
            PathBuf::from(&temp_workdir.path().join("tmpfs-dev"));
        fs::create_dir(&fixture.secure_mount).unwrap(); //#[allow_ci]

        // Replace the channels on the fixture with some local ones
        let (mut payload_tx, mut payload_rx) =
            mpsc::channel::<PayloadMessage>(1);

        let (mut keys_tx, mut keys_rx) = mpsc::channel::<(
            KeyMessage,
            Option<oneshot::Sender<SymmKeyMessage>>,
        )>(1);

        fixture.payload_tx = payload_tx.clone();
        fixture.keys_tx = keys_tx.clone();

        let quotedata = web::Data::new(fixture);
        let pubkey = quotedata.pub_key.clone();

        // Run server
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("/vX.Y/keys/ukey", web::post().to(u_key))
                .route("/vX.Y/keys/vkey", web::post().to(v_key))
                .route("/vX.Y/keys/verify", web::get().to(verify)),
        )
        .await;

        let u: SymmKey = U[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let v: SymmKey = V[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let k = u.xor(&v).unwrap(); //#[allow_ci]

        let payload = payload.map(|payload| {
            let iv = b"ABCDEFGHIJKLMNOP";
            encrypt_aead(k.as_ref(), &iv[..], payload).unwrap() //#[allow_ci]
        });

        let uuid = test_config.agent.uuid;
        let auth_tag = compute_hmac(k.as_ref(), uuid.as_bytes()).unwrap(); //#[allow_ci]

        let arbiter = Arbiter::new();
        let p_tx = payload_tx.clone();
        let uuid_clone = uuid.clone();
        // Run keys worker
        assert!(arbiter.spawn(Box::pin(async move {
            let result = worker(true, uuid_clone, keys_rx, p_tx).await;

            if result.is_err() {
                debug!("keys worker failed: {:?}", result);
            }
        })));

        let k_clone = k.clone();
        let p_clone = payload.clone();

        // Run fake payloads worker
        assert!(arbiter.spawn(Box::pin(async move {
            while let Some(msg) = payload_rx.recv().await {
                match msg {
                    PayloadMessage::Shutdown => {
                        payload_rx.close();
                    }
                    PayloadMessage::RunPayload(run_payload) => {
                        assert!(
                            run_payload.symm_key.as_ref() == k_clone.as_ref()
                        );
                        if let Some(ref p) = p_clone {
                            assert!(
                                run_payload.encrypted_payload.as_ref()
                                    == p.as_slice()
                            );
                        }
                    }
                }
            }

            if !Arbiter::current().stop() {
                debug!("couldn't stop current arbiter");
            }
        })));

        let encrypted_key =
            rsa_oaep_encrypt(&quotedata.pub_key, u.as_ref()).unwrap(); //#[allow_ci]

        let ukey = KeylimeUKey {
            encrypted_key: general_purpose::STANDARD.encode(&encrypted_key),
            auth_tag: hex::encode(auth_tag),
            payload: payload.map(|p| general_purpose::STANDARD.encode(p)),
        };

        let req = test::TestRequest::post()
            .uri("/vX.Y/keys/ukey")
            .set_json(&ukey)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let encrypted_key =
            rsa_oaep_encrypt(&quotedata.pub_key, v.as_ref()).unwrap(); //#[allow_ci]

        let vkey = KeylimeVKey {
            encrypted_key: general_purpose::STANDARD.encode(&encrypted_key),
        };

        let req = test::TestRequest::post()
            .uri("/vX.Y/keys/vkey")
            .set_json(&vkey)
            .to_request();

        // Check that while the key is not complete it is still ok to ask for the key
        let result = get_symm_key(keys_tx.clone()).await;
        assert!(result.is_ok());
        let key = result.unwrap(); //#[allow_ci]
        assert!(key.is_none());

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Check that after sending both U and V keys, the key is properly combined
        let result = get_symm_key(keys_tx.clone()).await;
        assert!(result.is_ok());
        let key = result.unwrap(); //#[allow_ci]
        assert!(key.is_some());
        if let Some(received) = key {
            assert!(received.as_ref() == k.as_ref());
        };

        // Test verify which calculates an HMAC on the challenge using the combined key as key
        let challenge = "1234567890ABCDEFGHIJ";
        let expected =
            compute_hmac(k.as_ref(), challenge.as_bytes()).unwrap(); //#[allow_ci]
        let req = test::TestRequest::get()
            .uri(format!("/vX.Y/keys/verify?challenge={challenge}").as_ref())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeHMAC> =
            test::read_body_json(resp).await;
        let response_hmac = hex::decode(&result.results.hmac).unwrap(); //#[allow_ci]

        assert_eq!(&response_hmac, &expected);

        // Test that sending part of a new key will not affect the current key until both parts are
        // received
        let (new_u, new_v, new_k) =
            prepare_encrypted_keys(key_len, None, uuid, &pubkey);
        let req = test::TestRequest::post()
            .uri("/vX.Y/keys/ukey")
            .set_json(&new_u)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // We expect the key to be the old one
        let result = get_symm_key(keys_tx.clone()).await;
        assert!(result.is_ok());
        let key = result.unwrap(); //#[allow_ci]
        assert!(key.is_some());
        if let Some(received) = key {
            assert!(received.as_ref() == k.as_ref());
        };

        let req = test::TestRequest::post()
            .uri("/vX.Y/keys/vkey")
            .set_json(&new_v)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Now that both parts were sent, we expect the key to be the new one
        let result = get_symm_key(keys_tx.clone()).await;
        assert!(result.is_ok());
        let key = result.unwrap(); //#[allow_ci]
        assert!(key.is_some());
        if let Some(received) = key {
            assert!(received.as_ref() == new_k.as_ref());
        };

        // Send Shutdown message to the workers for a graceful shutdown
        keys_tx.send((KeyMessage::Shutdown, None)).await.unwrap(); //#[allow_ci]
        payload_tx.send(PayloadMessage::Shutdown).await.unwrap(); //#[allow_ci]
        arbiter.join();

        // Explicitly drop QuoteData to cleanup keys
        drop(quotedata);
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn test_u_or_v_key_short() {
        test_u_or_v_key(AES_128_KEY_LEN, None).await;
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn test_u_or_v_key_long() {
        test_u_or_v_key(AES_256_KEY_LEN, None).await;
    }

    #[cfg(feature = "testing")]
    #[actix_rt::test]
    async fn test_pubkey() {
        let (fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]
        let quotedata = web::Data::new(fixture);
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("/vX.Y/keys/pubkey", web::get().to(pubkey)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/vX.Y/keys/pubkey")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimePubkey> =
            test::read_body_json(resp).await;
        assert!(pkey_pub_from_pem(&result.results.pubkey)
            .unwrap() //#[allow_ci]
            .public_eq(&quotedata.pub_key));

        // Explicitly drop QuoteData to cleanup keys
        drop(quotedata);
    }
}
