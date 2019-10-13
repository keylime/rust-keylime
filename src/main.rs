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

use common::emsg;
use common::set_response_content;
use futures::future;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json::Map;
use std::collections::HashMap;
use std::error::Error;
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
    let addr = ([127, 0, 0, 1], 1337).into();

    let server = Server::bind(&addr)
        .serve(|| service_fn(response_function))
        .map_err(|e| error!("server error: {}", e));

    info!("Listening on http://{}", addr);

    // run server forever
    hyper::rt::run(server);
}

fn response_function(req: Request<Body>) -> BoxFut {
    let mut my_response: Response<Body> =
        Response::new("Nothing here.".into());

    // Process input api path
    let parameters = common::get_restful_parameters(req.uri().path());

    // Loop scope wrap around the request handling
    // Exit: Encounter error early exit or exit at the end to the scope
    match req.method() {
        &Method::GET => {
            match get_request_handler(&mut my_response, parameters) {
                Ok(()) => {
                    info!("Get request handled successfully.");
                }

                Err(e) => {
                    error!("Failed to handle get request with error {}.", e);
                }
            }
        }

        &Method::POST => {
            match post_request_handler(&mut my_response, parameters) {
                Ok(()) => {
                    info!("Post request handled successfully.");
                }
                Err(e) => {
                    error!("Failed to handle post request with error {}.", e);
                }
            }
        }

        _ => {
            warn!("Bad request type {}", req.uri());
            *my_response.body_mut() = "Not Found.".into();
        }
    }

    Box::new(future::ok(my_response))
}

fn post_request_handler(
    my_response: &mut Response<Body>,
    parameters: HashMap<&str, &str>,
) -> Result<(), Box<String>> {
    let mut response_map = Map::new();
    match parameters.get(&"keys") {
        Some(&"ukey") => {
            if let Err(e) = set_response_content(
                200,
                "Add u key",
                response_map,
                my_response,
            ) {
                return emsg(
                    "Failed to edit the response content body.",
                    Some(e),
                );
            }
            Ok(())
        }
        Some(&"vkey") => {
            if let Err(e) = set_response_content(
                200,
                "Add v key",
                response_map,
                my_response,
            ) {
                return emsg(
                    "Failed to edit the response content body.",
                    Some(e),
                );
            }
            Ok(())
        }
        _ => {
            if let Err(e) = set_response_content(
                400,
                "Bad Request",
                response_map,
                my_response,
            ) {
                return emsg(
                    "Failed to edit the response content body.",
                    Some(e),
                );
            }
            emsg("Bad Request. Invalid post request.", None::<String>)
        }
    }
}

fn get_request_handler(
    my_response: &mut Response<Body>,
    parameters: HashMap<&str, &str>,
) -> Result<(), Box<String>> {
    info!("GET invoked");

    // Invalid request handling
    if parameters.is_empty() {
        if let Err(e) = set_response_content(
            400,
            "Not Implemented: Use /v2/keys/ or /v2/quotes/ interfaces.",
            Map::new(),
            my_response,
        ) {
            return emsg(
                "Failed to edit response content. Error {}.",
                Some(e),
            );
        }
        return emsg(
            "Error: Invalid API request. Abort the handling process.",
            None::<String>,
        );
    }

    if parameters.contains_key("keys") {
        let mut response_map = Map::new();

        match parameters.get(&"keys") {
            // Check K value is available to use the do_hmac function
            // Crypto request will do hmac for the challenge
            // PYthon version function : crypto.do_hmac(self.server.K, challenge)
            Some(&"verify") => {
                // Sample request: /keys/verify/challenge/foo
                // retrieve challenge from the request body
                let challenge = match parameters.get(&"challenge") {
                    Some(c) => c,
                    None => {
                        if let Err(e) = set_response_content(
                            400,
                            "Challenge is missing.",
                            response_map,
                            my_response,
                        ) {
                            return emsg(
                                "Failed to edit response content.",
                                Some(e),
                            );
                        }
                        return emsg("Error: Challenge is missing for verify reqeust. Abort the handling process.", None::<String>);
                    }
                };

                // create hmac for the challenge
                match crypto::do_hmac(
                    common::KEY.to_string(),
                    challenge.to_string(),
                ) {
                    Ok(hmac) => {
                        response_map.insert("hmac".into(), hmac.into());
                        if let Err(e) = set_response_content(
                            200,
                            "Success",
                            response_map,
                            my_response,
                        ) {
                            return emsg(
                                "Failed to edit response content.",
                                Some(e),
                            );
                        }
                    }

                    Err(e) => {
                        if let Err(e) = set_response_content(
                            400,
                            "HMAC failed.",
                            Map::new(),
                            my_response,
                        ) {
                            return emsg(
                                "Failed to edit response content. Error {}.",
                                Some(e),
                            );
                        }
                    }
                }
            }

            // Verify pubkey which is the exported rsa pub key
            // Python version: self.server.rsapublickey_exportable
            Some(&"pubkey") => {
                // GET /keys/pubkey/
                response_map.insert(
                    "pubkey".into(),
                    common::RSA_PUBLICKEY_EXPORTABLE.into(),
                );

                if let Err(e) = set_response_content(
                    200,
                    "Success",
                    response_map,
                    my_response,
                ) {
                    return emsg(
                        "Failed to edit the response content body.",
                        Some(e),
                    );
                }
            }

            _ => {
                if let Err(e) = set_response_content(
                    400,
                    "Invalid request for keys",
                    response_map,
                    my_response,
                ) {
                    return emsg(
                        "Failed to edit the response content. Error {}.",
                        Some(e),
                    );
                }
            }
        }

    // quote request: response include quote and ima_measurement_list
    } else if parameters.contains_key("quotes") {
        // Only one of these two is available, the other one is None\
        let pcr_mask = parameters.get(&"mask");
        let vpcr_mask = parameters.get(&"vmask");
        let mut response_map = Map::new();
        let mut ima_mask: String;
        let nonce = parameters.get(&"nonce");

        // If nonce is not available, it is an invalid request
        if let None = nonce {
            if let Err(e) = set_response_content(
                400,
                "Invalid reqeust",
                response_map,
                my_response,
            ) {
                return emsg("Failed to edit response content.", Some(e));
            }
            return emsg(
                "GET quote returning 400 response. Nonce is not avaiable.",
                None::<String>,
            );
        }

        // verify all parameters is available inside the request body
        let (n, p, v) = match (nonce, pcr_mask, vpcr_mask) {
            (Some(n), Some(p), Some(v)) => (n, p, v),
            _ => {
                if let Err(e) = set_response_content(
                    400,
                    "Bad request",
                    response_map,
                    my_response,
                ) {
                    return emsg("Failed to edit response content.", Some(e));
                }
                return emsg("GET quote return 400 response. Bad request: nonce, pcr_mask, vpcr_mask can't be None.", None::<String>);
            }
        };

        let nonce_isalnum = n.chars().all(char::is_alphanumeric);
        let pcr_mask_isalnum = p.chars().all(char::is_alphanumeric);
        let vpcr_mask_isalnum = v.chars().all(char::is_alphanumeric);

        if !(nonce_isalnum
            && (pcr_mask == None || pcr_mask_isalnum)
            && (vpcr_mask == None || vpcr_mask_isalnum))
        {
            if let Err(e) = set_response_content(
                 400,
                 "Bad Request. Parameters should be strictly alphanumeric string.",
                 response_map,
                 my_response,
                 ) {
                 return emsg("Failed to edit the response content body.", Some(e));
             }

            return emsg("GET quote return 400 response. Parameters should all be strictly alphanumeric.", None::<String>);
        }

        let mut quote: String;
        let vtpm_flag = tpm::is_vtpm();
        let quotes = match parameters.get(&"quotes") {
            Some(q) => q,
            None => {
                if let Err(e) = set_response_content(
                    400,
                    "Quote is missing in request.",
                    response_map,
                    my_response,
                ) {
                    return emsg(
                        "Failed to edit response content body.",
                        Some(e),
                    );
                }
                return emsg(
                    "Bad Request. Quote is missing in request.",
                    None::<String>,
                );
            }
        };

        // identtity quotes are always shallow
        if !vtpm_flag || quotes == &"identity" {
            quote = match tpm::create_quote(
                n.to_string(),
                common::RSA_PUBLICKEY_EXPORTABLE.to_string(),
                p.to_string(),
            ) {
                Ok(q) => q,
                Err(err) => {
                    if let Err(e) = set_response_content(
                        400,
                        "Failed to crate quote from TPM.",
                        response_map,
                        my_response,
                    ) {
                        return emsg(
                            "Faild to edit the response content body.",
                            Some(e),
                        );
                    }
                    return emsg(
                        "TPM error. Failed to create quote from TPM.",
                        Some(err.description().to_string()),
                    );
                }
            };

            ima_mask = p.to_string();
        } else {
            quote = match tpm::create_deep_quote(
                n.to_string(),
                common::RSA_PUBLICKEY_EXPORTABLE.to_string(),
                v.to_string(),
                p.to_string(),
            ) {
                Ok(q) => q,
                Err(err) => {
                    if let Err(e) = set_response_content(
                        400,
                        "Failed to create deep quote from TPM.",
                        response_map,
                        my_response,
                    ) {
                        return emsg(
                            "Failed to edit response content body.",
                            Some(e),
                        );
                    }
                    return emsg(
                        "TPM error. Failed to create deep quote from TPM.",
                        Some(err.description().to_string()),
                    );
                }
            };

            ima_mask = v.to_string();
        }

        if parameters.contains_key(&"partial")
            && parameters.get(&"partial") == None
            || parameters.get(&"partial") == Some(&"1")
        {
            response_map.insert("quote".into(), quote.into());
        } else {
            response_map.insert("quote".into(), quote.into());
            response_map.insert(
                "pubkey".into(),
                common::RSA_PUBLICKEY_EXPORTABLE.into(),
            );
        }

        if tpm::check_mask(ima_mask.to_string(), common::IMA_PCR) {
            match common::STUB_IMA {
                true => {
                    let temp_path = Path::new(common::IMA_ML_STUB);
                    if !temp_path.exists() {
                        return emsg(
                            "IMA measurement list not available.",
                            None::<String>,
                        );
                    }
                    let buffer =
                        match read_in_file(common::IMA_ML_STUB.to_string()) {
                            Ok(b) => b,
                            Err(e) => {
                                return emsg(
                                    "Failed to read IMA_ML_STUB file.",
                                    Some(e),
                                );
                            }
                        };

                    let mut contents = String::new();
                }
                false => {
                    let temp_path = Path::new(common::IMA_ML);
                    if !temp_path.exists() {
                        return emsg(
                            "IMA measurement list not available.",
                            None::<String>,
                        );
                    }
                    let buffer =
                        match read_in_file(common::IMA_ML.to_string()) {
                            Ok(b) => b,
                            Err(e) => {
                                return emsg(
                                    "Failed to read IMA_ML file.",
                                    Some(e),
                                );
                            }
                        };

                    response_map
                        .insert("ima_measurement_list".into(), buffer.into());
                }
            }
        }
        if let Err(e) =
            set_response_content(200, "Success", response_map, my_response)
        {
            return emsg(
                "Failed to edit the response content body.",
                Some(e),
            );
        }
    } else {
        if let Err(e) =
            set_response_content(400, "Bad Request.", Map::new(), my_response)
        {
            return emsg(
                "Failed to edit the response content body.",
                Some(e),
            );
        }
        return emsg("Bad Request. Invalid request content.", None::<String>);
    }
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
