// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{
    error::Error, registrar_agent::serialize_as_base64, tpm, QuoteData,
};
use actix_web::{web, HttpResponse, Responder};
use log::*;
use openssl::pkey::{PKey, Private, Public};
use serde::{Deserialize, Serialize};
use std::{convert::TryInto, sync::Mutex};
use tss_esapi::Context;

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

// TODO: Is this how things will be parsed on the tenant side?
// Reference: https://github.com/keylime/keylime/blob/master/keylime/tpm/tpm_main.py#L1014
// TODO: What is the PCR blob supposed to be?
#[derive(Debug, Serialize, Deserialize)]
pub struct Quote<'a> {
    #[serde(serialize_with = "serialize_as_base64")]
    pub quote: &'a [u8],
    #[serde(serialize_with = "serialize_as_base64")]
    pub signature: &'a [u8],
    #[serde(serialize_with = "serialize_as_base64")]
    pub pcrblob: &'a [u8],
    #[serde(serialize_with = "serialize_as_base64")]
    pub nk_pub: &'a [u8],
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

        let idquote = tpm::quote(param.nonce.as_bytes(), None, data)?;

        HttpResponse::Ok().json(idquote).await
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
    } else if !param.vmask.chars().all(char::is_alphanumeric) {
        HttpResponse::BadRequest()
            .body(format!(
                "vmask should be strictly alphanumeric: {}",
                param.vmask
            ))
            .await
    } else {
        info!("Calling Itegrity Quote with nonce: {}", param.nonce);

        // todo: mask or vmask?
        let integrityquote =
            tpm::quote(param.nonce.as_bytes(), Some(&param.mask), data)?;

        HttpResponse::Ok().json(integrityquote).await
    }
}
