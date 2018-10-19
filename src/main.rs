extern crate pretty_env_logger;
#[macro_use]
extern crate log;

extern crate serde_json;
extern crate futures;
extern crate libc;
extern crate hyper;
extern crate tempfile;
extern crate rustc_serialize;


pub mod common;
pub mod tpm;

use futures::future;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};

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
    let mut res = Response::default();

    // need a method to process input api path !!
    let parameters = common::get_restful_parameters(req.uri().path());

    match req.method() {
        &Method::GET => {
            // keys request
            if parameters.contains_key("keys") {
                match parameters.get(&"keys") {
                    // check Kb value is available to perform the do_hmac
                    // crypto request
                    // verify will do hmac for the challenge
                    // orignal: crypto.do_hmac(self.server.K, challenge)
                    Some(&"verify") => {
                        /* /keys/verify/challenge/blablabla */
                        let _challenge = parameters.get(&"challenge");
                        let hmac_result = String::from("hmac placeholder");
                        res = common::json_response_content(
                            200,
                            "Success".to_string(),
                            hmac_result,
                        );
                    }

                    // pubkey export the rsa pub key
                    // original: self.server.rsapublickey_exportable
                    Some(&"pubkey") => {
                        /* /keys/pubkey/ */
                        let pubkey_placeholder =
                            String::from("pubkey_placeholder");
                        res = common::json_response_content(
                            200,
                            "Success".to_string(),
                            pubkey_placeholder,
                        );
                    }

                    _ => {
                        res = common::json_response_content(
                            400,
                            "Fail".to_string(),
                            "uri is not supported".to_string(),
                        );
                    }
                };

            // quote resques
            // tpm implementation need for quote

            // response include quote and ima_measurement_list
            } else if parameters.contains_key("quotes") {
                let _nouce = parameters.get(&"nouce").unwrap();

                // only one of these two is available, the other is None if it
                // is not in the HashMap
                let pcr_mask = parameters.get(&"mask").unwrap();
                let vpcr_mask = parameters.get(&"vmask").unwrap();
                let mut ima_mask: &str;

                match parameters.get(&"quotes") {
                    Some(&"identity") => {
                        // vtpm option
                        ima_mask = vpcr_mask; // take ownership
                    }

                    _ => {
                        ima_mask = pcr_mask;
                    }
                }

                info!(
                    "Now it should use ima_mask: {} to check with tpm",
                    ima_mask
                );
                res = common::json_response_content(
                    400,
                    "Fail".to_string(),
                    "Check with tpm using imaMask".to_string(),
                );
            } else {
                warn!("Bad GET request for {}", req.uri());
                res = common::json_response_content(
                    400,
                    "Fail".to_string(),
                    "uri is not supported".to_string(),
                );
            }
        }

        &Method::POST => match parameters.get(&"keys") {
            Some(&"ukey") => {
                res = common::json_response_content(
                    400,
                    "Success".to_string(),
                    "u key added".to_string(),
                );
                info!("adding u key");
            }

            Some(&"vkey") => {
                res = common::json_response_content(
                    400,
                    "Success".to_string(),
                    "v key added".to_string(),
                );
                info!("adding v key");
            }

            _ => {
                warn!("Bad POST request to {}", req.uri());
                res = common::json_response_content(
                    400,
                    "Fail".to_string(),
                    "uri not supported".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_get_restful_parameters() {
        let mut map = HashMap::new();
        map.insert("verify", "pubkey");
        map.insert("api_version", "2");

        // "{"api_version": "v2", "verify": "pubkey"}"
        assert_eq!(common::get_restful_parameters("/v2/verify/pubkey"), map);
    }
}
