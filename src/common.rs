use super::*;
use hyper::{Response, StatusCode, Body, header};
use std::collections::HashMap;
use rustc_serialize::json::Json;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Read, Write};
use libc::{umask, geteuid};
use std::path::Path;
use std::process::Command;
use std::process::Output;
use std::{thread, time};
use std::time::{Duration, SystemTime};
use tempfile::tempfile;
use tempfile::NamedTempFile;


pub const BOOTSTRAP_KEY_SIZE: usize = 32;
pub const STUB_VTPM: bool = false;


/*
 * convert the input into a Response struct
 * 
 * Parameters: code number, status string, content string
 * Return: Combine all information into a Response struct
 */
pub fn json_response_content(code: i32, status: String, results: String)
                             -> Response<Body> {
    let data = vec![code.to_string(), status, results];

    match serde_json::to_string(&data){
        Ok(json) => {
            // return a json response
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json))
                .unwrap()
        }

        // This is unnecessary here，probably won't fail
        Err(e) => {
            error!("serializing json: {}", e);

            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap()
        }
    }
}


/*
 * seperate url path by '/', first element is dropped since it is an empty
 * string
 *
 * Paramters: string and delimiter
 * return: Vector of string contains the path content in original order
 */
pub fn string_split_by_seperator(data: &str, seperator: char) -> Vec<&str> {
    let mut v: Vec<&str> = data.split(seperator).collect();
    v.remove(0);
    v
}


// hashmap doesn't own the parameters, just borrow it

/*
 * convert a api resquest path to a map that contains the key and value in
 * pair from the original api request
 *
 * Parameters: api string
 * Return: map with api key and value
 */
pub fn get_restful_parameters(urlstring: &str) -> HashMap<&str, &str> {
    let mut parameters = HashMap::new();

    let list = string_split_by_seperator(urlstring, '/');
    if list.len() <= 1 {
        return parameters;
    }

    let (_, right) = list[0].split_at(1);
    parameters.insert("api_version", right);

    /* TODO comment why this drops the first element */
    for x in 1..(list.len() - 1) {
        parameters.insert(list[x], list[x + 1]);
    }
    parameters
}


// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_string() {
        assert_eq!(string_split_by_seperator("/v2/verify/pubkey", '/'),
                   ["v2", "verify", "pubkey"]);
    }

    #[test]
    fn test_get_restful_parameters() {
        let mut map = HashMap::new();
        map.insert("verify", "pubkey");
        map.insert("api_version", "2");

        // "{"api_version": "v2", "verify": "pubkey"}"  
        assert_eq!(get_restful_parameters("/v2/verify/pubkey"), map);
    }
}
