// use std::vec::Vec<&str>;
// use std::string::String;

#[cfg(test)]
mod tests {

	use super::*;

    #[test]
    fn test_split_string() {
        assert_eq!(string_split_by_seperator("/v2/verify/pubkey", '/'), ["v2", "verify", "pubkey"]);
    }
}


// fn json_response_content(code: i32, status: &str, results: &str) -> Response {

// 	extern crate futures;
// 	extern crate hyper;
// 	extern crate serde_json;

// 	use hyper::{Response, StatusCode, Body};


// 	let data = vec![code, status, results];

// 	let res = match serde_json::to_string(&data){
// 		Ok(json) => {
// 			// return a json response
// 			Response::builder()
// 				.header(header::CONTENT_TYPE, "application/json")
// 				.body(Body::from(json))
// 				.unwrap()
// 		}

// 		Err(e) => {
// 			eprintln!("serializing json: {}", e);

// 			Response::buildre()
// 				.status(StatusCode::INTERNAL_SERVER_ERROR)
// 				.body(Body::from("Internal Server Error"))
// 				.unwrap();
// 		}
// 	}
// }

fn string_split_by_seperator(data: &str, seperator: char) -> Vec<&str> {

	let mut v: Vec<&str> = data.split(seperator).collect();
	v.remove(0);
	v
}

// fn get_restful_parameters(urlstring: &str) -> 