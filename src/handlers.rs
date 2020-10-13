#[macro_use]
use log::*;

use crate::common;
use crate::error;

use common::set_response_content;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json::Map;
use std::collections::HashMap;

use error::{Error, Result};

pub(crate) async fn response_function(
    req: Request<Body>)
    -> Result<Response<Body>> {
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

pub(crate) fn post_request_handler(
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

pub(crate) fn get_request_handler(
    my_response: &mut Response<Body>,
    parameters: HashMap<&str, &str>,
) -> Result<()> {
    info!("GET invoked");
    Ok(())
}
