use crate::{context_info_handler, json_dump, struct_filler};
use actix_web::http::StatusCode;
use keylime::error::Error as KeylimeError;
use log::{debug, info};
use reqwest::{header::HeaderMap, Client};
use std::time::Duration;

pub struct ResponseInformation {
    pub status_code: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

pub async fn send_negotiation(
    avoid_tpm: bool,
    json_file: Option<String>,
    url: &str,
    timeout: u64,
) -> Result<ResponseInformation, KeylimeError> {
    let mut context_info = context_info_handler::get_context_info(avoid_tpm)
        .map_err(|e| {
            KeylimeError::Other(format!("Failed to get context info: {}", e))
        })?;
    let mut filler =
        struct_filler::get_filler_request(json_file, context_info.as_mut());

    let json_value = json_dump::dump_attestation_request_to_value(
        &filler.get_attestation_request(),
    );

    let client = Client::new();
    let reqcontent = json_value?.to_string();
    debug!("Request body: {:?}", reqcontent);

    let response = client
        .post(url)
        .body(reqcontent)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .timeout(Duration::from_millis(timeout))
        .send()
        .await?;

    let sc = response.status();
    let headers = response.headers().clone();
    info!("Response code:{}", response.status());
    info!("Response headers: {:?}", headers);

    let response_body = response.text().await?;
    if !response_body.is_empty() {
        info!("Response body: {}", response_body);
    }

    let rsp = ResponseInformation {
        status_code: sc,
        headers,
        body: response_body,
    };

    Ok(rsp)
}
