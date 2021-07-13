// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{tpm, Error as KeylimeError, QuoteData};

use crate::common::{IMA_ML, KEY_LEN};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use log::*;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;

#[derive(Deserialize)]
pub struct Ident {
    nonce: String,
}

#[derive(Deserialize)]
pub struct Integ {
    nonce: String,
    mask: String,
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
// match what is expected by Python Keylime. Because the Python
// verifier resends the vkey based on whether there is a pubkey
// field included in the returned data, we must use a struct
// without this field after attestation is complete.
#[derive(Serialize, Debug)]
pub(crate) struct KeylimeIntegrityQuotePreAttestation {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub pubkey: String,
    pub ima_measurement_list: String,
}

impl KeylimeIntegrityQuotePreAttestation {
    fn from_id_quote(
        idquote: KeylimeIdQuote,
        ima: String,
        pubkey: String,
    ) -> Self {
        KeylimeIntegrityQuotePreAttestation {
            quote: idquote.quote,
            hash_alg: idquote.hash_alg,
            enc_alg: idquote.enc_alg,
            sign_alg: idquote.sign_alg,
            pubkey,
            ima_measurement_list: ima,
        }
    }
}

#[derive(Serialize, Debug)]
pub(crate) struct KeylimeIntegrityQuotePostAttestation {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub ima_measurement_list: String,
}

impl KeylimeIntegrityQuotePostAttestation {
    fn from_id_quote(idquote: KeylimeIdQuote, ima: String) -> Self {
        KeylimeIntegrityQuotePostAttestation {
            quote: idquote.quote,
            hash_alg: idquote.hash_alg,
            enc_alg: idquote.enc_alg,
            sign_alg: idquote.sign_alg,
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
struct JsonIntegWrapperPreAttestation {
    code: u32,
    status: String,
    results: KeylimeIntegrityQuotePreAttestation,
}

#[derive(Serialize)]
struct JsonIntegWrapperPostAttestation {
    code: u32,
    status: String,
    results: KeylimeIntegrityQuotePostAttestation,
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

impl JsonIntegWrapperPreAttestation {
    fn new(results: KeylimeIntegrityQuotePreAttestation) -> Self {
        JsonIntegWrapperPreAttestation {
            code: 200,
            status: String::from("Success"),
            results,
        }
    }
}

impl JsonIntegWrapperPostAttestation {
    fn new(results: KeylimeIntegrityQuotePostAttestation) -> Self {
        JsonIntegWrapperPostAttestation {
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
    req: HttpRequest,
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
        info!(
            "GET invoked from {:?} with uri {}",
            req.connection_info().remote_addr().unwrap(), //#[allow_ci]
            req.uri()
        );
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
        info!("GET identity quote returning 200 response");
        HttpResponse::Ok().json(response).await
    }
}

// This is a Quote request from the cloud verifier, which will check
// integrity measurement. The PCRs included in the Quote will be specified
// by the mask. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub), xi:yi), NK_pub}
// where xi:yi are additional PCRs to be included in the quote.
pub async fn integrity(
    req: HttpRequest,
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
    } else {
        info!(
            "GET invoked from {:?} with uri {}",
            req.connection_info().remote_addr().unwrap(), //#[allow_ci]
            req.uri()
        );
        info!("Calling Integrity Quote with nonce: {}", param.nonce);

        let mut quote = tpm::quote(
            param.nonce.as_bytes(),
            Some(&param.mask),
            data.clone(),
        )?;

        // pubkey should only be sent for the first quote request; otherwise
        // the verifier will keep sending a v key every time. we check whether
        // it's the first quote request by seeing if the symmetric key has been
        // derived (which happens after both u and v key are received once).
        let symm_key = data.payload_symm_key.lock().unwrap(); //#[allow_ci]
        if *symm_key == [0u8; KEY_LEN] {
            let quote = KeylimeIntegrityQuotePreAttestation::from_id_quote(
                quote,
                read_to_string(IMA_ML)?,
                String::from_utf8(
                    data.pub_key
                        .public_key_to_pem()
                        .map_err(KeylimeError::from)?,
                )
                .map_err(KeylimeError::from)?,
            );
            let response = JsonIntegWrapperPreAttestation::new(quote);
            info!("GET integrity quote returning 200 response");
            HttpResponse::Ok().json(response).await
        } else {
            let quote = KeylimeIntegrityQuotePostAttestation::from_id_quote(
                quote,
                read_to_string(IMA_ML)?,
            );

            let response = JsonIntegWrapperPostAttestation::new(quote);
            info!("GET integrity quote returning 200 response");
            HttpResponse::Ok().json(response).await
        }
    }
}
