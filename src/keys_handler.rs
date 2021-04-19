// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

use crate::QuoteData;

#[derive(Deserialize)]
pub struct Verify {
    challenge: String,
}

#[derive(Deserialize)]
pub struct UkeyJson {
    b64_encrypted_key: String, // this will be handled as a blog once wired in
    auth_tag: String,
}

pub async fn verify(
    param: web::Query<Verify>,
    data: web::Data<QuoteData>,
) -> impl Responder {
    HttpResponse::Ok().body(format!("Challenge: {}", param.challenge))
}

pub async fn ukey(
    param: web::Json<UkeyJson>,
    data: web::Data<QuoteData>,
) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "b64_encrypted_key: {} auth_tag: {}",
        param.b64_encrypted_key, param.auth_tag
    ))
}
