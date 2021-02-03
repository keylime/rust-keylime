use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

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
