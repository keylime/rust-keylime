extern crate futures;
extern crate hyper;
extern crate common;
extern crate pretty_env_logger;


use futures::future;
use hyper::rt::{Future, Stream};
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, server, StatusCode};
use std::collections::HashMap;

type BoxFut = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;


fn main() {
    println!("Hello, world!");

    pretty_env_logger::init();

    let addr = ([127.0,0.1], 3000).into();

    let server = Server::bind(&addr)
    	.serve(|| service_fn(response_function))
    	.map_err(|e| eprintln!("server erro: {}", e));

    println!("Listening no http://{}", addr);

    // run server for-ever
    hyper::rt::run(server);
}


fn response_function(req: Request<Body>) -> BoxFut {
	let mut response = Response::new(Body::empty));


	// need a method to process input api path !!
	let mut parameters = common::et_restful_parameters(req.uri().path());

	match req.method() {

		&Method::GET => {
			if parameters.contains_key("keys") {
				match parameters.get(&"keys") {

					// verify will do hmac for the challenge
					// orignal: crypto.do_hmac(self.server.K, challenge) 
					Some("verify") => {
						let res = common::json_response_content(200, "Success", parameters.get("challenge"));
					}

					// pubkey export the rsa pub key
					// original: self.server.rsapublickey_exportable
					Some("pubkey") => {
						let res = common::json_response_content(200, "Success", "pubkey_placeholder");
					}
				};

			// tpm implementation need for quote
			}else if parameters.contains_key("quotes") {

			}else{
				let res = common::json_response_content(400, "fail","Uri is not supported");
			}
		}

		&Method::POST => {

		}

		_  =>  {
			let body = Body::from(NOTFOUND);
			Box::enw(future::ok(Response::builder().
				.status(StatusCode::NOT_FOUND)
				.body(body)
				.unwrap())
		}

	};

	Box::new(future::ok(res))
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn test_get_restful_parameters() {
    	let mut map = HashMap::new();
    	map.insert("verify", "pubkey");
    	map.insert("api_version", "2");

    	// "{"api_version": "v2", "verify": "pubkey"}"	
    	assert_eq!(common::get_restful_parameters("/v2/verify/pubkey"), map);
    }
}
