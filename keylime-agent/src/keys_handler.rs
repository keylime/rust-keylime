// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::crypto;
use crate::{
    common::{
        AuthTag, EncryptedData, JsonWrapper, KeySet, SymmKey, AES_BLOCK_SIZE,
        AGENT_UUID_LEN, AUTH_TAG_LEN,
    },
    config::KeylimeConfig,
    payloads::{PayloadMessage, RunPayload},
    Error, QuoteData, Result,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
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
    keyset1: &mut KeySet,
    keyset2: &mut KeySet,
    uuid: &[u8],
    auth_tag: &Option<AuthTag>,
) -> Option<SymmKey> {
    // U, V keys and auth_tag must be present for this to succeed
    if keyset1.is_empty() || keyset2.is_empty() || auth_tag.is_none() {
        debug!("Still waiting on u or v key or auth_tag");
        return None;
    }

    for key1 in keyset1.iter() {
        for key2 in keyset2.iter() {
            let symm_key_out = match key1.xor(key2) {
                Ok(k) => k,
                Err(e) => {
                    continue;
                }
            };
            if let Some(tag) = auth_tag {
                // Computes HMAC over agent UUID with provided key (payload decryption key) and
                // checks that this matches the provided auth_tag.
                if crypto::verify_hmac(
                    symm_key_out.as_ref(),
                    uuid,
                    tag.as_ref(),
                )
                .is_ok()
                {
                    info!(
                        "Successfully derived symmetric payload decryption key"
                    );

                    keyset1.clear();
                    keyset2.clear();
                    return Some(symm_key_out);
                }
            }
        }
    }

    warn!("HMAC check failed for all U and V key combinations");
    None
}

pub(crate) async fn u_key(
    body: web::Json<KeylimeUKey>,
    req: HttpRequest,
    quote_data: web::Data<QuoteData>,
) -> impl Responder {
    debug!("Received ukey");

    // get key and decode it from web data
    let encrypted_key = match base64::decode(&body.encrypted_key)
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
        Some(data) => match base64::decode(data).map_err(Error::from) {
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

pub(crate) async fn v_key(
    body: web::Json<KeylimeVKey>,
    req: HttpRequest,
    quote_data: web::Data<QuoteData>,
) -> impl Responder {
    debug!("Received vkey");

    // get key and decode it from web data
    let encrypted_key = match base64::decode(&body.encrypted_key)
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

pub(crate) async fn pubkey(
    req: HttpRequest,
    data: web::Data<QuoteData>,
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

pub(crate) async fn verify(
    param: web::Query<KeylimeChallenge>,
    req: HttpRequest,
    data: web::Data<QuoteData>,
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
    symm_key: SymmKey,
    encrypted_payload: Option<EncryptedData>,
) -> Result<()> {
    if let Some(p) = &encrypted_payload {
        let m = PayloadMessage::RunPayload(RunPayload {
            symm_key,
            encrypted_payload: p.clone(),
        });
        debug!("Sending RunPayload message to payloads worker");
        if let Err(e) = payloads_tx.send(m).await {
            warn!("Failed to send RunPayload message to payloads worker");
            return Err(Error::Sender(
                "Failed to send RunPayload message to payloads worker"
                    .to_string(),
            ));
        }
    }
    Ok(())
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
    let mut ukeys: KeySet = Vec::new();
    let mut vkeys: KeySet = Vec::new();
    let mut auth_tag: Option<AuthTag> = None;
    let mut encrypted_payload: Option<EncryptedData> = None;
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
                encrypted_payload = ukey.payload;
                auth_tag = Some(ukey.auth_tag);
                ukeys.push(ukey.decrypted_key);

                match try_combine_keys(
                    &mut ukeys,
                    &mut vkeys,
                    uuid.as_bytes(),
                    &auth_tag,
                ) {
                    Some(k) => {
                        if run_payload {
                            match request_run_payload(
                                payloads_tx.clone(),
                                k.clone(),
                                encrypted_payload.clone(),
                            )
                            .await
                            {
                                Ok(_) => {
                                    debug!("Sent RunPayload message to payloads worker");
                                }
                                Err(e) => {
                                    warn!("Failed to send RunPayload message to payloads worker");
                                }
                            }
                        } else {
                            warn!("agent mTLS is disabled, and unless 'enable_insecure_payload' is set to 'True', payloads cannot be deployed'");
                        }
                        // Store combined key
                        symm_key = Some(k);
                    }
                    None => {
                        continue;
                    }
                }
            }
            KeyMessage::VKey(vkey) => {
                // Store received data
                vkeys.push(vkey.decrypted_key);

                match try_combine_keys(
                    &mut ukeys,
                    &mut vkeys,
                    uuid.as_bytes(),
                    &auth_tag,
                ) {
                    Some(k) => {
                        // Only run payload scripts if mTLS is enabled or 'enable_insecure_payload' option is set
                        if run_payload {
                            match request_run_payload(
                                payloads_tx.clone(),
                                k.clone(),
                                encrypted_payload.clone(),
                            )
                            .await
                            {
                                Ok(_) => {
                                    debug!("Sent RunPayload message to payloads worker");
                                }
                                Err(e) => {
                                    warn!("Failed to send RunPayload message to payloads worker");
                                }
                            }
                        } else {
                            warn!("agent mTLS is disabled, and unless 'enable_insecure_payload' is set to 'True', payloads cannot be deployed'");
                        }
                        // Store combined key
                        symm_key = Some(k);
                    }
                    None => {
                        continue;
                    }
                }
            }
        }
    }

    debug!("Shutting down keys worker");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "testing")]
    use crate::crypto::testing::{
        encrypt_aead, pkey_pub_from_pem, rsa_oaep_encrypt,
    };
    use crate::{
        common::{AES_128_KEY_LEN, AES_256_KEY_LEN, API_VERSION},
        config::KeylimeConfig,
        crypto::compute_hmac,
        payloads,
    };
    use actix_rt::Arbiter;
    use actix_web::{test, web, App};
    use openssl::{
        encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding,
        sign::Signer,
    };
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };
    use tokio::sync::mpsc;

    // Enough length for testing both AES-128 and AES-256
    const U: &[u8; AES_256_KEY_LEN] = b"01234567890123456789012345678901";
    const V: &[u8; AES_256_KEY_LEN] = b"ABCDEFGHIJABCDEFGHIJABCDEFGHIJAB";

    fn test_combine_keys(key_len: usize) {
        let u: SymmKey = U[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let v: SymmKey = V[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let mut ukeys = vec![u.clone()];
        let mut vkeys = vec![v.clone()];
        let k = u.xor(&v).unwrap(); //#[allow_ci]
        let uuid = "test-uuid";
        let hmac = compute_hmac(k.as_ref(), uuid.as_bytes()).unwrap(); //#[allow_ci]
        let auth_tag: AuthTag = hmac.as_slice().try_into().unwrap(); //#[allow_ci]
        let result = try_combine_keys(
            &mut ukeys,
            &mut vkeys,
            uuid.as_bytes(),
            &Some(auth_tag),
        );
        assert!(result.is_some());

        // Check the keys list are emptied after a successful combination
        assert!(ukeys.is_empty());
        assert!(vkeys.is_empty());

        // Check that missing ukeys, vkeys, or auth_tag makes it to return None
        ukeys.push(u);
        let auth_tag: AuthTag = vec![0u8; 48].as_slice().try_into().unwrap(); //#[allow_ci]
        let result = try_combine_keys(
            &mut ukeys,
            &mut vkeys,
            uuid.as_bytes(),
            &Some(auth_tag.clone()),
        );
        assert!(result.is_none()); //#[allow_ci]

        // Check that invalid auth_tag makes the combination to fail
        vkeys.push(v);
        let result = try_combine_keys(
            &mut ukeys,
            &mut vkeys,
            uuid.as_bytes(),
            &Some(auth_tag),
        );
        assert!(result.is_none());

        // Check that the keys vecs are untouched
        assert!(ukeys.len() == 1);
        assert!(vkeys.len() == 1);
    }

    #[test]
    async fn test_combine_keys_short() {
        test_combine_keys(AES_128_KEY_LEN);
    }

    #[test]
    async fn test_combine_keys_long() {
        test_combine_keys(AES_256_KEY_LEN);
    }

    #[cfg(feature = "testing")]
    async fn test_u_or_v_key(key_len: usize, payload: Option<&[u8]>) {
        let test_config = KeylimeConfig::default();
        let mut fixture = QuoteData::fixture().unwrap(); //#[allow_ci]

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

        // Run server
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route(
                    &format!("/{API_VERSION}/keys/ukey"),
                    web::post().to(u_key),
                )
                .route(
                    &format!("/{API_VERSION}/keys/vkey"),
                    web::post().to(v_key),
                )
                .route(
                    &format!("/{API_VERSION}/keys/verify"),
                    web::get().to(verify),
                ),
        )
        .await;

        let u: SymmKey = U[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let v: SymmKey = V[..key_len][..].try_into().unwrap(); //#[allow_ci]
        let k = u.xor(&v).unwrap(); //#[allow_ci]

        let payload = payload.map(|payload| {
            let iv = b"ABCDEFGHIJKLMNOP";
            encrypt_aead(k.as_ref(), &iv[..], payload).unwrap() //#[allow_ci]
        });

        let auth_tag =
            compute_hmac(k.as_ref(), test_config.agent.uuid.as_bytes())
                .unwrap(); //#[allow_ci]

        let arbiter = Arbiter::new();

        let p_tx = payload_tx.clone();
        // Run keys worker
        assert!(arbiter.spawn(Box::pin(async move {
            let result =
                worker(true, test_config.agent.uuid.clone(), keys_rx, p_tx)
                    .await;

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
            encrypted_key: base64::encode(&encrypted_key),
            auth_tag: hex::encode(auth_tag),
            payload: payload.map(base64::encode),
        };

        let req = test::TestRequest::post()
            .uri(&format!("/{API_VERSION}/keys/ukey"))
            .set_json(&ukey)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let encrypted_key =
            rsa_oaep_encrypt(&quotedata.pub_key, v.as_ref()).unwrap(); //#[allow_ci]

        let vkey = KeylimeVKey {
            encrypted_key: base64::encode(&encrypted_key),
        };

        let req = test::TestRequest::post()
            .uri(&format!("/{API_VERSION}/keys/vkey"))
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
            .uri(&format!("/{API_VERSION}/keys/verify?challenge={challenge}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeHMAC> =
            test::read_body_json(resp).await;
        let response_hmac = hex::decode(&result.results.hmac).unwrap(); //#[allow_ci]

        assert_eq!(&response_hmac, &expected);

        // Send Shutdown message to the workers for a graceful shutdown
        keys_tx.send((KeyMessage::Shutdown, None)).await.unwrap(); //#[allow_ci]
        payload_tx
            .send(payloads::PayloadMessage::Shutdown)
            .await
            .unwrap(); //#[allow_ci]
        arbiter.join();
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
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{API_VERSION}/keys/pubkey"),
                web::get().to(pubkey),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!("/{API_VERSION}/keys/pubkey"))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimePubkey> =
            test::read_body_json(resp).await;
        assert!(pkey_pub_from_pem(&result.results.pubkey)
            .unwrap() //#[allow_ci]
            .public_eq(&quotedata.pub_key));
    }
}
