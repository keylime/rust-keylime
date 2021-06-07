// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

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

pub async fn identity(param: web::Query<Ident>) -> impl Responder {
    // nonce can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        HttpResponse::BadRequest()
            .body(format!(
                "Parameters should be strictly alphanumeric: {}",
                param.nonce
            ))
            .await
    } else {
        // place holder for identity quote code
        HttpResponse::Ok()
            .body(format!(
                "Calling Identity Quote with nonce: {}",
                param.nonce
            ))
            .await
    }
}

pub async fn integrity(param: web::Query<Integ>) -> impl Responder {
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
    } else if !param.vmask.chars().all(char::is_alphanumeric) {
        HttpResponse::BadRequest()
            .body(format!(
                "vmask should be strictly alphanumeric: {}",
                param.vmask
            ))
            .await
    } else {
        // place holder for integrity quote code
        HttpResponse::Ok()
            .body(format!(
                "Calling Integrity Quote with nonce: {}",
                param.nonce
            ))
            .await
    }
}
