// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{tpm, Error as KeylimeError, QuoteData};

use actix_web::{web, HttpResponse, Responder};
use log::*;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;

const IMA_PATH: &str = "/sys/kernel/security/ima/ascii_runtime_measurements";

#[derive(Deserialize)]
pub struct Ident {
    nonce: String,
}

#[derive(Deserialize)]
pub struct Integ {
    nonce: String,
    mask: String,
    vmask: String,
    partial: String,
}

// The fields of this struct and their default values must
// match what is expected by Python Keylime.
#[derive(Serialize, Debug)]
pub(crate) struct KeylimeIdQuote {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub pubkey: String,
}

impl Default for KeylimeIdQuote {
    fn default() -> Self {
        KeylimeIdQuote {
            quote: String::from("r"),
            hash_alg: String::from("sha256"),
            enc_alg: String::from("rsa"),
            sign_alg: String::from("rsassa"),
            pubkey: String::from(""),
        }
    }
}

// The fields of this struct and their default values must
// match what is expected by Python Keylime.
#[derive(Serialize, Debug)]
pub(crate) struct KeylimeIntegrityQuote {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub pubkey: String,
    pub ima_measurement_list: String,
}

impl KeylimeIntegrityQuote {
    fn from_id_quote(idquote: KeylimeIdQuote, ima: String) -> Self {
        KeylimeIntegrityQuote {
            quote: idquote.quote,
            hash_alg: idquote.hash_alg,
            enc_alg: idquote.enc_alg,
            sign_alg: idquote.sign_alg,
            pubkey: idquote.pubkey,
            ima_measurement_list: ima,
        }
    }
}

#[derive(Serialize)]
struct JsonIdWrapper {
    code: u32,
    status: String,
    results: KeylimeIdQuote,
}

// The fields of this struct and their default values must
// match what is expected by Python Keylime.
#[derive(Serialize)]
struct JsonIntegWrapper {
    code: u32,
    status: String,
    results: KeylimeIntegrityQuote,
}

impl JsonIdWrapper {
    fn new(results: KeylimeIdQuote) -> Self {
        JsonIdWrapper {
            code: 200,
            status: String::from("Success"),
            results,
        }
    }
}

impl JsonIntegWrapper {
    fn new(results: KeylimeIntegrityQuote) -> Self {
        JsonIntegWrapper {
            code: 200,
            status: String::from("Success"),
            results,
        }
    }
}

// This is a Quote request from the tenant, which does not check
// integrity measurement. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub)), NK_pub }
pub async fn identity(
    param: web::Query<Ident>,
    data: web::Data<QuoteData>,
) -> impl Responder {
    // nonce can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        HttpResponse::BadRequest()
            .body(format!(
                "Parameters should be strictly alphanumeric: {}",
                param.nonce
            ))
            .await
    } else {
        info!("Calling Identity Quote with nonce: {}", param.nonce);

        let mut quote =
            tpm::quote(param.nonce.as_bytes(), None, data.clone())?;
        quote.pubkey = String::from_utf8(
            data.pub_key
                .public_key_to_pem()
                .map_err(KeylimeError::from)?,
        )
        .map_err(KeylimeError::from)?;

        let response = JsonIdWrapper::new(quote);
        HttpResponse::Ok().json(response).await
    }
}

// This is a Quote request from the cloud verifier, which will check
// integrity measurement. The PCRs inclued in the Quote will be specified
// by the mask, vmask. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub), xi:yi), NK_pub}
// where xi:yi are additional PCRs to be included in the quote.
pub async fn integrity(
    param: web::Query<Integ>,
    data: web::Data<QuoteData>,
) -> impl Responder {
    // nonce, mask, vmask can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        HttpResponse::BadRequest()
            .body(format!(
                "nonce should be strictly alphanumeric: {}",
                param.nonce
            ))
            .await
    } else if !param.mask.chars().all(char::is_alphanumeric) {
        HttpResponse::BadRequest()
            .body(format!(
                "mask should be strictly alphanumeric: {}",
                param.mask
            ))
            .await
    // TODO: Will we ever need to use the vmask?
    } else if !param.vmask.chars().all(char::is_alphanumeric) {
        HttpResponse::BadRequest()
            .body(format!(
                "vmask should be strictly alphanumeric: {}",
                param.vmask
            ))
            .await
    } else {
        info!("Calling Integrity Quote with nonce: {}", param.nonce);

        let mut quote = tpm::quote(
            param.nonce.as_bytes(),
            Some(&param.mask),
            data.clone(),
        )?;

        let mut quote = KeylimeIntegrityQuote::from_id_quote(
            quote,
            read_to_string(IMA_PATH)?,
        );

        quote.pubkey = String::from_utf8(
            data.pub_key
                .public_key_to_pem()
                .map_err(KeylimeError::from)?,
        )
        .map_err(KeylimeError::from)?;

        let response = JsonIntegWrapper::new(quote);
        HttpResponse::Ok().json(response).await
    }
}
