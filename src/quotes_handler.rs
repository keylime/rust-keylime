// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{tpm, Error as KeylimeError, QuoteData};

use crate::common::JsonWrapper;
use crate::ima::read_measurement_list;
use crate::serialization::serialize_maybe_base64;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use log::*;
use serde::{Deserialize, Serialize};
use std::fs::{read, read_to_string};
use tss_esapi::structures::PcrSlot;

#[derive(Deserialize)]
pub struct Ident {
    nonce: String,
}

#[derive(Deserialize)]
pub struct Integ {
    nonce: String,
    mask: String,
    partial: String,
    ima_ml_entry: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct KeylimeQuote {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub pubkey: Option<String>,
    pub ima_measurement_list: Option<String>,
    pub mb_measurement_list: Option<Vec<u8>>,
    pub ima_measurement_list_entry: Option<u64>,
}

// This is a Quote request from the tenant, which does not check
// integrity measurement. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub)), NK_pub }
pub async fn identity(
    req: HttpRequest,
    param: web::Query<Ident>,
    data: web::Data<QuoteData>,
) -> impl Responder {
    info!(
        "GET invoked from {:?} with uri {}",
        req.connection_info().remote_addr().unwrap(), //#[allow_ci]
        req.uri()
    );

    // nonce can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric");
        return HttpResponse::BadRequest()
            .body(format!(
                "Parameters should be strictly alphanumeric: {}",
                param.nonce
            ))
            .await;
    }

    if param.nonce.len() > tpm::MAX_NONCE_SIZE {
        warn!("Get quote returning 400 response. Nonce is too long (max size {}): {}",
              tpm::MAX_NONCE_SIZE,
              param.nonce.len()
        );
        return HttpResponse::BadRequest()
            .body(format!(
                "Nonce is too long (max size {}): {}",
                tpm::MAX_NONCE_SIZE,
                param.nonce
            ))
            .await;
    }

    info!("Calling Identity Quote with nonce: {}", param.nonce);

    let mut quote = tpm::quote(param.nonce.as_bytes(), None, data.clone())?;
    quote.pubkey = Some(
        String::from_utf8(
            data.pub_key
                .public_key_to_pem()
                .map_err(KeylimeError::from)?,
        )
        .map_err(KeylimeError::from)?,
    );

    let response = JsonWrapper::new(quote);
    info!("GET identity quote returning 200 response");
    HttpResponse::Ok().json(response).await
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
    info!(
        "GET invoked from {:?} with uri {}",
        req.connection_info().remote_addr().unwrap(), //#[allow_ci]
        req.uri()
    );

    // nonce, mask, vmask can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric");
        return HttpResponse::BadRequest()
            .body(format!(
                "nonce should be strictly alphanumeric: {}",
                param.nonce
            ))
            .await;
    }

    if !param.mask.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric");
        return HttpResponse::BadRequest()
            .body(format!(
                "mask should be strictly alphanumeric: {}",
                param.mask
            ))
            .await;
    }

    if param.nonce.len() > tpm::MAX_NONCE_SIZE {
        warn!("Get quote returning 400 response. Nonce is too long (max size {}): {}",
              tpm::MAX_NONCE_SIZE,
              param.nonce.len()
        );
        return HttpResponse::BadRequest()
            .body(format!(
                "Nonce is too long (max size: {}): {}",
                tpm::MAX_NONCE_SIZE,
                param.nonce.len()
            ))
            .await;
    }

    // If partial="0", include the public key in the quote
    let pubkey = match &param.partial[..] {
        "0" => Some(
            String::from_utf8(
                data.pub_key
                    .public_key_to_pem()
                    .map_err(KeylimeError::from)?,
            )
            .map_err(KeylimeError::from)?,
        ),
        "1" => None,
        _ => {
            warn!("Get quote returning 400 response. uri must contain key 'partial' and value '0' or '1'");
            return HttpResponse::BadRequest()
                .body("uri must contain key 'partial' and value '0' or '1'")
                .await;
        }
    };

    info!(
        "Calling Integrity Quote with nonce: {}, mask: {}",
        param.nonce, param.mask
    );

    // If an index was provided, the request is for the entries starting from the given index
    // (iterative attestation). Otherwise the request is for the whole list.
    let nth_entry = match &param.ima_ml_entry {
        None => 0,
        Some(idx) => idx.parse::<u64>().unwrap_or(0),
    };

    // Generate the ID quote.
    let id_quote =
        tpm::quote(param.nonce.as_bytes(), Some(&param.mask), data.clone())?;

    // If PCR 0 is included in the mask, obtain the measured boot
    let mut mb_measurement_list = None;
    if tpm::check_mask(&param.mask, &PcrSlot::Slot0)? {
        let measuredboot_ml = read(&data.measuredboot_ml_path);
        mb_measurement_list = match measuredboot_ml {
            Ok(ml) => Some(ml),
            Err(e) => {
                warn!("TPM2 event log not available");
                None
            }
        };
    }

    // Generate the measurement list
    let ima_ml_path = &data.ima_ml_path;
    let (ima_measurement_list, ima_measurement_list_entry, num_entries) =
        read_measurement_list(
            &mut data.ima_ml.lock().unwrap(), //#[allow_ci]
            ima_ml_path,
            nth_entry,
        )?;

    // Generate the final quote based on the ID quote
    let quote = KeylimeQuote {
        pubkey,
        ima_measurement_list,
        mb_measurement_list,
        ima_measurement_list_entry,
        ..id_quote
    };

    let response = JsonWrapper::new(quote);
    info!("GET integrity quote returning 200 response");
    HttpResponse::Ok().json(response).await
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common::API_VERSION, crypto::testing::pkey_pub_from_pem};
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_identity() {
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{}/quotes/identity", API_VERSION),
                web::get().to(identity),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/{}/quotes/identity?nonce=1234567890ABCDEFHIJ",
                API_VERSION,
            ))
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(
            pkey_pub_from_pem(result.results.pubkey.unwrap().as_bytes()) //#[allow_ci]
                .unwrap() //#[allow_ci]
                .public_eq(&quotedata.pub_key)
        );
        assert!(result.results.quote.starts_with('r'));

        let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
        tpm::testing::check_quote(
            &mut context,
            quotedata.ak_handle,
            &result.results.quote,
            b"1234567890ABCDEFHIJ",
        )
        .expect("unable to verify quote");
    }

    #[actix_rt::test]
    async fn test_integrity_pre() {
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{}/quotes/integrity", API_VERSION),
                web::get().to(integrity),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/{}/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&vmask=0x808000&partial=0",
                API_VERSION,
            ))
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(
            pkey_pub_from_pem(result.results.pubkey.unwrap().as_bytes()) //#[allow_ci]
                .unwrap() //#[allow_ci]
                .public_eq(&quotedata.pub_key)
        );

        let ima_ml_path = &quotedata.ima_ml_path;
        let ima_ml = read_to_string(ima_ml_path).unwrap(); //#[allow_ci]
        assert_eq!(
            result.results.ima_measurement_list.unwrap().as_str(), //#[allow_ci]
            ima_ml
        );
        assert!(result.results.quote.starts_with('r'));

        let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
        tpm::testing::check_quote(
            &mut context,
            quotedata.ak_handle,
            &result.results.quote,
            b"1234567890ABCDEFHIJ",
        )
        .expect("unable to verify quote");
    }

    #[actix_rt::test]
    async fn test_integrity_post() {
        let quotedata = web::Data::new(QuoteData::fixture().unwrap()); //#[allow_ci]
        let mut app =
            test::init_service(App::new().app_data(quotedata.clone()).route(
                &format!("/{}/quotes/integrity", API_VERSION),
                web::get().to(integrity),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri(&format!(
                "/{}/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&vmask=0x808000&partial=1",
                API_VERSION,
            ))
            .to_request();

        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");

        let ima_ml_path = &quotedata.ima_ml_path;
        let ima_ml = read_to_string(&ima_ml_path).unwrap(); //#[allow_ci]
        assert_eq!(
            result.results.ima_measurement_list.unwrap().as_str(), //#[allow_ci]
            ima_ml
        );
        assert!(result.results.quote.starts_with('r'));

        let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
        tpm::testing::check_quote(
            &mut context,
            quotedata.ak_handle,
            &result.results.quote,
            b"1234567890ABCDEFHIJ",
        )
        .expect("unable to verify quote");
    }
}
