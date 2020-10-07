#[macro_use]
use log::*;

#[macro_use]
use serde_derive;

#[macro_use]
use serde_json;

use base64;
use flate2;
use futures;
use hex;
use hyper;
use ini;
use libc;
use openssl;
use pretty_env_logger;
use rustc_serialize;
use serde;
use tempfile;

mod cmd_exec;
mod common;
mod crypto;
mod error;
mod hash;
mod secure_mount;
mod tpm;

use common::config_get;
use common::set_response_content;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json::Map;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use error::{Error, Result};

static NOTFOUND: &[u8] = b"Not Found";

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    // Get a context to work with the TPM
    let mut ctx = tpm::get_tpm2_ctx()?;

    let cloudagent_ip =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_ip")?;
    let cloudagent_port =
        config_get("/etc/keylime.conf", "cloud_agent", "cloudagent_port")?;
    let endpoint = format!("{}:{}", cloudagent_ip, cloudagent_port);

    info!("Starting server...");

    let addr = (endpoint).parse().expect("Cannot parse IP & Port");

    let service = make_service_fn(|_| async {
        Ok::<_, Error>(service_fn(response_function))
    });
    let server = Server::bind(&addr).serve(service);

    info!("Listening on http://{}", addr);

    // run server forever
    //hyper::rt::run(server);
    server.await?;

    Ok(())
}

async fn response_function(req: Request<Body>) -> Result<Response<Body>> {
    let mut my_response: Response<Body> =
        Response::new("Nothing here.".into());

    // Process input api path
    let parameters = common::get_restful_parameters(req.uri().path());

    // Loop scope wrap around the request handling
    // Exit: Encounter error early exit or exit at the end to the scope
    match req.method() {
        &Method::GET => {
            get_request_handler(&mut my_response, parameters)?;
        }

        &Method::POST => {
            post_request_handler(&mut my_response, parameters)?;
        }

        _ => {
            warn!("Bad request type {}", req.uri());
            *my_response.body_mut() = "Not Found.".into();
        }
    }

    Ok(my_response)
    //Box::new(future::ok(my_response))
}

fn post_request_handler(
    my_response: &mut Response<Body>,
    parameters: HashMap<&str, &str>,
) -> Result<()> {
    let mut response_map = Map::new();
    match parameters.get(&"keys") {
        Some(&"ukey") => {
            set_response_content(
                200,
                "Add u key",
                response_map,
                my_response,
            )?;
            Ok(())
        }
        Some(&"vkey") => {
            set_response_content(
                200,
                "Add v key",
                response_map,
                my_response,
            )?;
            Ok(())
        }
        _ => {
            set_response_content(
                400,
                "Bad Request",
                response_map,
                my_response,
            )?;
            Err(Error::InvalidRequest)
        }
    }
}

fn get_request_handler(
    my_response: &mut Response<Body>,
    parameters: HashMap<&str, &str>,
) -> Result<()> {
    info!("GET invoked");

    // Invalid request handling
    // if parameters.is_empty() {
    //     if let Err(e) = set_response_content(
    //         400,
    //         "Not Implemented: Use /v2/keys/ or /v2/quotes/ interfaces.",
    //         Map::new(),
    //         my_response,
    //     ) {
    //         return emsg(
    //             "Failed to edit response content. Error {}.",
    //             Some(e),
    //         );
    //     }
    //     return emsg(
    //         "Error: Invalid API request. Abort the handling process.",
    //         None::<String>,
    //     );
    // }

    // if parameters.contains_key("keys") {
    //     let mut response_map = Map::new();

    //     match parameters.get(&"keys") {
    //         // Check K value is available to use the do_hmac function
    //         // Crypto request will do hmac for the challenge
    //         // PYthon version function : crypto.do_hmac(self.server.K, challenge)
    //         Some(&"verify") => {
    //             // Sample request: /keys/verify/challenge/foo
    //             // retrieve challenge from the request body
    //             let challenge = match parameters.get(&"challenge") {
    //                 Some(c) => c,
    //                 None => {
    //                     if let Err(e) = set_response_content(
    //                         400,
    //                         "Challenge is missing.",
    //                         response_map,
    //                         my_response,
    //                     ) {
    //                         return emsg(
    //                             "Failed to edit response content.",
    //                             Some(e),
    //                         );
    //                     }
    //                     return emsg("Error: Challenge is missing for verify reqeust. Abort the handling process.", None::<String>);
    //                 }
    //             };

    //             // create hmac for the challenge
    //             match crypto::do_hmac(
    //                 common::KEY.to_string(),
    //                 challenge.to_string(),
    //             ) {
    //                 Ok(hmac) => {
    //                     response_map.insert("hmac".into(), hmac.into());
    //                     if let Err(e) = set_response_content(
    //                         200,
    //                         "Success",
    //                         response_map,
    //                         my_response,
    //                     ) {
    //                         return emsg(
    //                             "Failed to edit response content.",
    //                             Some(e),
    //                         );
    //                     }
    //                 }

    //                 Err(e) => {
    //                     if let Err(e) = set_response_content(
    //                         400,
    //                         "HMAC failed.",
    //                         Map::new(),
    //                         my_response,
    //                     ) {
    //                         return emsg(
    //                             "Failed to edit response content. Error {}.",
    //                             Some(e),
    //                         );
    //                     }
    //                 }
    //             }
    //         }

    //         // Verify pubkey which is the exported rsa pub key
    //         // Python version: self.server.rsapublickey_exportable
    //         Some(&"pubkey") => {
    //             // GET /keys/pubkey/
    //             response_map.insert(
    //                 "pubkey".into(),
    //                 common::RSA_PUBLICKEY_EXPORTABLE.into(),
    //             );

    //             if let Err(e) = set_response_content(
    //                 200,
    //                 "Success",
    //                 response_map,
    //                 my_response,
    //             ) {
    //                 return emsg(
    //                     "Failed to edit the response content body.",
    //                     Some(e),
    //                 );
    //             }
    //         }

    //         _ => {
    //             if let Err(e) = set_response_content(
    //                 400,
    //                 "Invalid request for keys",
    //                 response_map,
    //                 my_response,
    //             ) {
    //                 return emsg(
    //                     "Failed to edit the response content. Error {}.",
    //                     Some(e),
    //                 );
    //             }
    //         }
    //     }

    // // quote request: response include quote and ima_measurement_list
    // } else if parameters.contains_key("quotes") {
    //     // Only one of these two is available, the other one is None\
    //     let pcr_mask = parameters.get(&"mask");
    //     let vpcr_mask = parameters.get(&"vmask");
    //     let mut response_map = Map::new();
    //     let mut ima_mask: String;
    //     let nonce = parameters.get(&"nonce");

    //     // If nonce is not available, it is an invalid request
    //     if let None = nonce {
    //         if let Err(e) = set_response_content(
    //             400,
    //             "Invalid reqeust",
    //             response_map,
    //             my_response,
    //         ) {
    //             return emsg("Failed to edit response content.", Some(e));
    //         }
    //         return emsg(
    //             "GET quote returning 400 response. Nonce is not avaiable.",
    //             None::<String>,
    //         );
    //     }

    //     // verify all parameters is available inside the request body
    //     let (n, p, v) = match (nonce, pcr_mask, vpcr_mask) {
    //         (Some(n), Some(p), Some(v)) => (n, p, v),
    //         _ => {
    //             if let Err(e) = set_response_content(
    //                 400,
    //                 "Bad request",
    //                 response_map,
    //                 my_response,
    //             ) {
    //                 return emsg("Failed to edit response content.", Some(e));
    //             }
    //             return emsg("GET quote return 400 response. Bad request: nonce, pcr_mask, vpcr_mask can't be None.", None::<String>);
    //         }
    //     };

    //     let nonce_isalnum = n.chars().all(char::is_alphanumeric);
    //     let pcr_mask_isalnum = p.chars().all(char::is_alphanumeric);
    //     let vpcr_mask_isalnum = v.chars().all(char::is_alphanumeric);

    //     if !(nonce_isalnum
    //         && (pcr_mask == None || pcr_mask_isalnum)
    //         && (vpcr_mask == None || vpcr_mask_isalnum))
    //     {
    //         if let Err(e) = set_response_content(
    //              400,
    //              "Bad Request. Parameters should be strictly alphanumeric string.",
    //              response_map,
    //              my_response,
    //              ) {
    //              return emsg("Failed to edit the response content body.", Some(e));
    //          }

    //         return emsg("GET quote return 400 response. Parameters should all be strictly alphanumeric.", None::<String>);
    //     }

    //     let mut quote: String;
    //     let quotes = match parameters.get(&"quotes") {
    //         Some(q) => q,
    //         None => {
    //             if let Err(e) = set_response_content(
    //                 400,
    //                 "Quote is missing in request.",
    //                 response_map,
    //                 my_response,
    //             ) {
    //                 return emsg(
    //                     "Failed to edit response content body.",
    //                     Some(e),
    //                 );
    //             }
    //             return emsg(
    //                 "Bad Request. Quote is missing in request.",
    //                 None::<String>,
    //             );
    //         }
    //     };

    //     // identtity quotes are always shallow
    //     if !vtpm_flag || quotes == &"identity" {
    //         quote = match tpm::create_quote(
    //             n.to_string(),
    //             common::RSA_PUBLICKEY_EXPORTABLE.to_string(),
    //             p.to_string(),
    //         ) {
    //             Ok(q) => q,
    //             Err(err) => {
    //                 if let Err(e) = set_response_content(
    //                     400,
    //                     "Failed to use quote from TPM.",
    //                     response_map,
    //                     my_response,
    //                 ) {
    //                     return emsg(
    //                         "Faild to edit the response content body.",
    //                         Some(e),
    //                     );
    //                 }
    //                 return emsg(
    //                     "TPM error. Failed to create quote from TPM.",
    //                     Some(err.description().to_string()),
    //                 );
    //             }
    //         };

    //         ima_mask = p.to_string();
    //     } else {
    //         quote = match tpm::create_deep_quote(
    //             n.to_string(),
    //             common::RSA_PUBLICKEY_EXPORTABLE.to_string(),
    //             v.to_string(),
    //             p.to_string(),
    //         ) {
    //             Ok(q) => q,
    //             Err(err) => {
    //                 if let Err(e) = set_response_content(
    //                     400,
    //                     "Failed to create deep quote from TPM.",
    //                     response_map,
    //                     my_response,
    //                 ) {
    //                     return emsg(
    //                         "Failed to edit response content body.",
    //                         Some(e),
    //                     );
    //                 }
    //                 return emsg(
    //                     "TPM error. Failed to create deep quote from TPM.",
    //                     Some(err.description().to_string()),
    //                 );
    //             }
    //         };

    //         ima_mask = v.to_string();
    //     }

    //     if parameters.contains_key(&"partial")
    //         && parameters.get(&"partial") == None
    //         || parameters.get(&"partial") == Some(&"1")
    //     {
    //         response_map.insert("quote".into(), quote.into());
    //     } else {
    //         response_map.insert("quote".into(), quote.into());
    //         response_map.insert(
    //             "pubkey".into(),
    //             common::RSA_PUBLICKEY_EXPORTABLE.into(),
    //         );
    //     }

    //     if tpm::check_mask(ima_mask.to_string(), common::IMA_PCR) {
    //         match common::STUB_IMA {
    //             true => {
    //                 let temp_path = Path::new(common::IMA_ML_STUB);
    //                 if !temp_path.exists() {
    //                     return emsg(
    //                         "IMA measurement list not available.",
    //                         None::<String>,
    //                     );
    //                 }
    //                 let buffer =
    //                     match read_in_file(common::IMA_ML_STUB.to_string()) {
    //                         Ok(b) => b,
    //                         Err(e) => {
    //                             return emsg(
    //                                 "Failed to read IMA_ML_STUB file.",
    //                                 Some(e),
    //                             );
    //                         }
    //                     };

    //                 let mut contents = String::new();
    //             }
    //             false => {
    //                 let temp_path = Path::new(common::IMA_ML);
    //                 if !temp_path.exists() {
    //                     return emsg(
    //                         "IMA measurement list not available.",
    //                         None::<String>,
    //                     );
    //                 }
    //                 let buffer =
    //                     match read_in_file(common::IMA_ML.to_string()) {
    //                         Ok(b) => b,
    //                         Err(e) => {
    //                             return emsg(
    //                                 "Failed to read IMA_ML file.",
    //                                 Some(e),
    //                             );
    //                         }
    //                     };

    //                 response_map
    //                     .insert("ima_measurement_list".into(), buffer.into());
    //             }
    //         }
    //     }
    //     if let Err(e) =
    //         set_response_content(200, "Success", response_map, my_response)
    //     {
    //         return emsg(
    //             "Failed to edit the response content body.",
    //             Some(e),
    //         );
    //     }
    // } else {
    //     if let Err(e) =
    //         set_response_content(400, "Bad Request.", Map::new(), my_response)
    //     {
    //         return emsg(
    //             "Failed to edit the response content body.",
    //             Some(e),
    //         );
    //     }
    //     return emsg("Bad Request. Invalid request content.", None::<String>);
    // }
    Ok(())
}

/*
 * Input: file path
 * Output: file content
 *
 * Helper function to help the keylime agent read file and get the file
 * content. It is not from the original python version. Because rust needs
 * to handle error in result, it is good to keep this function seperate from
 * the main function.
 */
fn read_in_file(path: String) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    fn init_logger() {
        pretty_env_logger::init();
        info!("Initialized logger for testing suite.");
        assert!(true);
    }

    #[test]
    fn test_read_in_file() {
        assert_eq!(
            read_in_file("test-data/test_input.txt".to_string())
                .expect("File doesn't exist"),
            String::from("Hello World!\n")
        );
    }
}
