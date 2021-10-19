// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{tpm, Error as KeylimeError, QuoteData};

use crate::serialization::serialize_maybe_base64;
use crate::ima::read_measurement_list;
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
}

// The fields of this struct and their default values must
// match what is expected by Python Keylime.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct KeylimeIdQuote {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub pubkey: String,
}

// The fields of this struct and their default values must
// match what is expected by Python Keylime. Because the Python
// verifier resends the vkey based on whether there is a pubkey
// field included in the returned data, we must use a struct
// without this field after attestation is complete.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct KeylimeIntegrityQuotePreAttestation {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub pubkey: String,
    pub ima_measurement_list: String,
    #[serde(
        serialize_with = "serialize_maybe_base64",
        skip_serializing_if = "Option::is_none"
    )]
    pub mb_measurement_list: Option<Vec<u8>>,
    pub ima_measurement_list_entry: u64,
}

impl KeylimeIntegrityQuotePreAttestation {
    fn from_id_quote(
        idquote: KeylimeIdQuote,
        ima: String,
        pubkey: String,
        mb: Option<Vec<u8>>,
        ima_measurement_list_entry: u64,
    ) -> Self {
        KeylimeIntegrityQuotePreAttestation {
            quote: idquote.quote,
            hash_alg: idquote.hash_alg,
            enc_alg: idquote.enc_alg,
            sign_alg: idquote.sign_alg,
            pubkey,
            ima_measurement_list: ima,
            mb_measurement_list: mb,
            ima_measurement_list_entry,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct KeylimeIntegrityQuotePostAttestation {
    pub quote: String, // 'r' + quote + sig + pcrblob
    pub hash_alg: String,
    pub enc_alg: String,
    pub sign_alg: String,
    pub ima_measurement_list: String,
    #[serde(
        serialize_with = "serialize_maybe_base64",
        skip_serializing_if = "Option::is_none"
    )]
    pub mb_measurement_list: Option<Vec<u8>>,
    pub ima_measurement_list_entry: u64,
}

impl KeylimeIntegrityQuotePostAttestation {
    fn from_id_quote(
        idquote: KeylimeIdQuote,
        ima: String,
        mb: Option<Vec<u8>>,
        ima_measurement_list_entry: u64,
    ) -> Self {
        KeylimeIntegrityQuotePostAttestation {
            quote: idquote.quote,
            hash_alg: idquote.hash_alg,
            enc_alg: idquote.enc_alg,
            sign_alg: idquote.sign_alg,
            ima_measurement_list: ima,
            mb_measurement_list: mb,
            ima_measurement_list_entry,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct JsonIdWrapper {
    code: u32,
    status: String,
    results: KeylimeIdQuote,
}

// The fields of this struct and their default values must
// match what is expected by Python Keylime.
#[derive(Serialize, Deserialize)]
struct JsonIntegWrapperPreAttestation {
    code: u32,
    status: String,
    results: KeylimeIntegrityQuotePreAttestation,
}

#[derive(Serialize, Deserialize)]
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
        info!(
            "Calling Integrity Quote with nonce: {}, mask: {}",
            param.nonce, param.mask
        );

        let partial = req.uri().query().unwrap(); //#[allow_ci]
        let partial = if partial.contains("partial=0") {
            0
        } else if partial.contains("partial=1") {
            1
        } else {
            return HttpResponse::BadRequest()
                .body("uri must contain key 'partial' and value '0' or '1'")
                .await;
        };

        let ima_ml_entry = req.uri().query().unwrap();
        let nth_entry = match ima_ml_entry.find("ima_ml_entry=") {
            None => 0,
            Some(idx) => {
                let number = &ima_ml_entry[idx + 13..];
                let last: usize = number
                    .find(|c: char| !c.is_numeric())
                    .unwrap_or(number.len());
                number[..last].parse().unwrap_or(0)
            }
        };

        let mut quote = tpm::quote(
            param.nonce.as_bytes(),
            Some(&param.mask),
            data.clone(),
        )?;

        let mut mb_measurement_list = None;
        let measuredboot_ml = read(&data.measuredboot_ml_path);
        // Only add log if a measured boot PCR 0 is actually in the mask
        if tpm::check_mask(&param.mask, &PcrSlot::Slot0)? {
            mb_measurement_list = match measuredboot_ml {
                Ok(ml) => Some(ml),
                Err(e) => {
                    warn!("TPM2 event log not available");
                    None
                }
            };
        }

        let ima_ml_path = &data.ima_ml_path;
        let (ima_ml, nth_entry, num_entries) =
            read_measurement_list(&mut data.ima_ml.lock().unwrap(), &ima_ml_path, nth_entry)?;

        if partial == 0 {
            let quote = KeylimeIntegrityQuotePreAttestation::from_id_quote(
                quote,
                ima_ml,
                String::from_utf8(
                    data.pub_key
                        .public_key_to_pem()
                        .map_err(KeylimeError::from)?,
                )
                .map_err(KeylimeError::from)?,
                mb_measurement_list,
                nth_entry,
            );
            let response = JsonIntegWrapperPreAttestation::new(quote);
            info!("GET integrity quote returning 200 response");
            HttpResponse::Ok().json(response).await
        } else {
            let quote = KeylimeIntegrityQuotePostAttestation::from_id_quote(
                quote,
                ima_ml,
                mb_measurement_list,
                nth_entry,
            );

            let response = JsonIntegWrapperPostAttestation::new(quote);
            info!("GET integrity quote returning 200 response");
            HttpResponse::Ok().json(response).await
        }
    }
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

        let result: JsonIdWrapper = test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(pkey_pub_from_pem(result.results.pubkey.as_bytes())
            .unwrap() //#[allow_ci]
            .public_eq(&quotedata.pub_key));
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

        let result: JsonIntegWrapperPreAttestation =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(pkey_pub_from_pem(result.results.pubkey.as_bytes())
            .unwrap() //#[allow_ci]
            .public_eq(&quotedata.pub_key));

        let ima_ml_path = &quotedata.ima_ml_path;
        let ima_ml = read_to_string(ima_ml_path).unwrap(); //#[allow_ci]
        assert_eq!(result.results.ima_measurement_list.as_str(), ima_ml);
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

        let result: JsonIntegWrapperPostAttestation =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");

        let ima_ml_path = &quotedata.ima_ml_path;
        let ima_ml = read_to_string(&ima_ml_path).unwrap(); //#[allow_ci]
        assert_eq!(result.results.ima_measurement_list.as_str(), ima_ml);
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
