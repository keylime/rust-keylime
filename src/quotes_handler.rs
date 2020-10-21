use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Ident {
    nonce: String,
}

pub async fn identity(param: web::Query<Ident>) -> impl Responder {
    HttpResponse::Ok().body(format!("Nonce: {}", param.nonce))
}
