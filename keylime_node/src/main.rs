extern crate futures;
extern crate hyper;

use futures::future;
use hyper::rt::{Future, Stream};
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, server, StatusCode};

type BoxFut = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;


fn main() {
    println!("Hello, world!");

    pretty_env_logger::init();

    let addr = ([127.0.0.1], 3000).into();

    let server = Server::bind(&addr)
    	.serve(|| service_fn(response_function))
    	.map_err(|e| epringln!("server erro: {}", e));

    println!("Listening no http://{}", addr);

    // run server for-ever
    hyper::rt::run(server);
}


fn response_function(req: Request<Body>) -> BoxFut {
	let mut response = Response::new(Body::empty));


	// need a method to process input api path
	match (req.method(), req.uri().path()){

		(&Method::GET, "/v2/keys/pubkey") => {

		}

		(&Method::GET, "/v2/keys/vkey") => {

		}

		// api request: /v2/keys/verify/challenge/#
		// challenge = #
		// "response['hmac'] = crypto.do_hmac(self.server.K, challenge)"
		// 
		// need a crypto library to fullfill this funcitonality
		// hmac should be consistenc with the original cropytodome version - Charlie
		// 
		// response: 200, success, response
		(&Method::GET, "/v2/keys/verify") => {

		}

		// Haven't implemnt yet
		// (&Method::GET, "/v2/keys/verify/challenge") => {

		// }

		// (&Method::GET, "/v2/quotes/integrity") => {

		// }

		// (&Method::GET, "/v2/quotes/integrity/nouce/*/mask/*/vmask/*/partial/*/") => {

		// }

		// (&Method::GET, "/v2/quotes/identity") => {

		// }

		// (&Method::GET, "/v2/quotes/identity/nouce/*/") => {

		// }

		_  =>  {
			let body = Body::from(NOTFOUND);
			Box::enw(future::ok(Response::builder().
				.status(StatusCode::NOT_FOUND)
				.body(body)
				.unwrap())
		}

	}
}

fn 
