#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate serde_json;

extern crate base64;
extern crate flate2;
extern crate futures;
extern crate hex;
extern crate hyper;
extern crate libc;
extern crate openssl;
extern crate pretty_env_logger;
extern crate rustc_serialize;
extern crate serde;
extern crate tempfile;

mod common;
mod crypto;
mod secure_mount;
mod tpm;

use futures::future;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json::Map;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

type BoxFut = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;

static NOTFOUND: &[u8] = b"Not Found";

fn main() {
    pretty_env_logger::init();
    info!("Starting server...");

    /* Should be port 3000 eventually */
    let addr = "127.0.0.1:1337".parse().unwrap();

    let server = Server::bind(&addr)
        .serve(|| service_fn(response_function))
        .map_err(|e| error!("server error: {}", e));

    info!("Listening on http://{}", addr);

    // run server forever
    hyper::rt::run(server);
}

fn response_function(req: Request<Body>) -> BoxFut {
    let res;

    // need a method to process input api path !!
    let parameters = common::get_restful_parameters(req.uri().path());

    match req.method() {
        &Method::GET => {
            info!("GET invoded");

            // invalid requestd handling
            if parameters.is_empty() {
                res = common::json_response_content(
                    200,
                    "Not Implemented: Use /v2/keys/ or /v2/quotes/ interfaces".to_string(),
                    Map::new(),
                );
            } else if parameters.contains_key("keys") {
                let mut response = Map::new();

                match parameters.get(&"keys") {
                    // check Kb value is available to perform the do_hmac
                    // crypto request verify will do hmac for the challenge
                    // orignal function: crypto.do_hmac(self.server.K,
                    // challenge)
                    Some(&"verify") => {
                        /* /keys/verify/challenge/blablabla */
                        let challenge = parameters.get(&"challenge");
                        let result = crypto::do_hmac(
                            common::KEY.to_string(),
                            challenge.unwrap().to_string(),
                        );
                        match result {
                            Ok(hmac) => {
                                info!(
                                    "
                                    GET keys/verify challenge returning 200
                                    response.
                                    "
                                );
                                response.insert("hmac".into(), hmac.into());
                                res = common::json_response_content(
                                    200,
                                    "Success".to_string(),
                                    response,
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "GET keys/verify challenge returning 400
                                    response. HMAC call failed with error:\n
                                    {}",
                                    e
                                );
                                res = common::json_response_content(
                                    400,
                                    "Bad Request".to_string(),
                                    Map::new(),
                                );
                            }
                        }
                    }

                    // pubkey export the rsa pub key
                    // original: self.server.rsapublickey_exportable
                    Some(&"pubkey") => {
                        /* /keys/pubkey/ */
                        response.insert(
                            "pubkey".into(),
                            common::RSA_PUBLICKEY_EXPORTABLE.into(),
                        );

                        res = common::json_response_content(
                            200,
                            "Success".to_string(),
                            response,
                        );

                        info!("GET pubkey return 200 response.");
                    }

                    _ => {
                        res = common::json_response_content(
                            400,
                            "Invalid value for keys".to_string(),
                            Map::new(),
                        );
                    }
                };

            // qutoe request: response include quote and ima_measurement_list
            } else if parameters.contains_key("quotes") {
                // only one of these two is available, the other is None if it
                // is not in the HashMap
                let pcr_mask = parameters.get(&"mask");
                let vpcr_mask = parameters.get(&"vmask");
                let mut ima_mask: String;
                let nonce = parameters.get(&"nonce");

                // input not valied without nonce attribute
                if let None = nonce {
                    warn!("GET quote returning 400 response. nonce not provided as an HTTP parameter in request");
                    res = common::json_response_content(
                        400,
                        "Bad Request".to_string(),
                        Map::new(),
                    );
                } else {
                    // check parameters, there all should be strictly alphanumeric
                    let nouce_isalnum =
                        nonce.unwrap().chars().all(char::is_alphanumeric);
                    let pcr_isalnum =
                        pcr_mask.unwrap().chars().all(char::is_alphanumeric);
                    let vpcr_isalnum =
                        vpcr_mask.unwrap().chars().all(char::is_alphanumeric);

                    if !(nouce_isalnum
                        && (pcr_mask == None || pcr_isalnum)
                        && (vpcr_mask == None || vpcr_isalnum))
                    {
                        warn!("GET quote returning 400 response. parameters should be strictly alphanumeric");
                        res = common::json_response_content(
                            400,
                            "Bad Request".to_string(),
                            Map::new(),
                        );
                    } else {
                        let mut quote: String;

                        // identity quotes are always shallow
                        if !tpm::is_vtpm().unwrap()
                            || parameters.get(&"quotes").unwrap()
                                == &"identity"
                        {
                            quote = tpm::create_quote(
                                nonce.unwrap().to_string(),
                                common::RSA_PUBLICKEY_EXPORTABLE.to_string(),
                                pcr_mask.unwrap().to_string(),
                            )
                            .unwrap();
                            // tpm quote placeholder
                            ima_mask = pcr_mask.unwrap().to_string();
                        } else {
                            quote = tpm::create_deep_quote(
                                nonce.unwrap().to_string(),
                                common::RSA_PUBLICKEY_EXPORTABLE.to_string(),
                                vpcr_mask.unwrap().to_string(),
                                pcr_mask.unwrap().to_string(),
                            )
                            .unwrap();
                            ima_mask = vpcr_mask.unwrap().to_string();
                        }

                        let mut response = Map::new();

                        if parameters.contains_key(&"partial")
                            && parameters.get(&"partial") == None
                            || parameters.get(&"partial") == Some(&"1")
                        {
                            response.insert("quote".into(), quote.into());
                        } else {
                            response.insert("quote".into(), quote.into());
                            response.insert(
                                "pubkey".into(),
                                common::RSA_PUBLICKEY_EXPORTABLE.into(),
                            );
                        }

                        if tpm::check_mask(
                            ima_mask.to_string(),
                            common::IMA_PCR,
                        ) {
                            match common::STUB_IMA {
                                true => {
                                    let temp_path =
                                        Path::new(common::IMA_ML_STUB);
                                    if temp_path.exists() {
                                        let buffer = read_in_file(
                                            common::IMA_ML_STUB.to_string(),
                                        );

                                        let mut contents = String::new();
                                        match buffer {
                                            Ok(b) => contents = b,
                                            Err(_) => {}
                                        }
                                        response.insert(
                                            "ima_measurement_list".into(),
                                            contents.into(),
                                        );
                                    } else {
                                        warn!(
                                            "IMA measurement list not available: {}",
                                            common::IMA_ML_STUB,
                                        );
                                    }
                                }

                                false => {
                                    let temp_path = Path::new(common::IMA_ML);
                                    if temp_path.exists() {
                                        let buffer = read_in_file(
                                            common::IMA_ML.to_string(),
                                        );

                                        let mut contents = String::new();
                                        match buffer {
                                            Ok(b) => contents = b,
                                            Err(_) => {}
                                        }

                                        response.insert(
                                            "ima_measurement_list".into(),
                                            contents.into(),
                                        );
                                    } else {
                                        warn!(
                                            "IMA measurement list not available: {}",
                                            common::IMA_ML,
                                        );
                                    }
                                }
                            }
                        }

                        info!(
                            "GET {} quote returning 200 response",
                            parameters["quote"],
                        );

                        res = common::json_response_content(
                            200,
                            "Success".to_string(),
                            response,
                        );
                    }
                }
            } else {
                warn!("Bad GET request for {}", req.uri());
                res = common::json_response_content(
                    400,
                    "Fail".to_string(),
                    Map::new(),
                );
            }
        }

        &Method::POST => match parameters.get(&"keys") {
            Some(&"ukey") => {
                res = common::json_response_content(
                    400,
                    "Success".to_string(),
                    Map::new(),
                );
                info!("adding u key");
            }

            Some(&"vkey") => {
                res = common::json_response_content(
                    400,
                    "Success".to_string(),
                    Map::new(),
                );
                info!("adding v key");
            }

            _ => {
                warn!("Bad POST request to {}", req.uri());
                res = common::json_response_content(
                    400,
                    "Fail".to_string(),
                    Map::new(),
                );
            }
        },

        _ => {
            warn!("Bad request type {}", req.uri());
            let body = Body::from(NOTFOUND);
            res = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(body)
                .unwrap();
        }
    }

    Box::new(future::ok(res))
}

/*
 * Input: file path
 * Output: file content
 *
 * Helper function to help the keylime node read file and get the file
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
            read_in_file("test_input.txt".to_string())
                .expect("File doesn't exist"),
            String::from("Hello World!\n")
        );
    }
}
