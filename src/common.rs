extern crate config;
extern crate futures;
extern crate hyper;
extern crate serde_json;

use hyper::{header, Body, Response, StatusCode};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;

/*
 * Constants and static variables
 */
pub const STUB_VTPM: bool = false;
pub const STUB_IMA: bool = true;
pub const TPM_DATA_PCR: usize = 16;
pub const IMA_PCR: usize = 10;
pub static RSA_PUBLICKEY_EXPORTABLE: &'static str = "rsa placeholder";
pub static TPM_TOOLS_PATH: &'static str = "/usr/local/bin/";
pub static IMA_ML_STUB: &'static str =
    "../scripts/ima/ascii_runtime_measurements";
pub static IMA_ML: &'static str =
    "/sys/kernel/security/ima/ascii_runtime_measurements";
pub static KEY: &'static str = "secret";
pub static WORK_DIR: &'static str = "/tmp";
pub static MOUNT_SECURE: bool = true;
pub const EXIT_SUCCESS: i32 = 0;

/*
 * Input: key in configuration file
 * Return: Option wrap the associated value
 *
 * Read the config file and retrieve the value based on the given key.
 */
pub fn get_config_parameter(key: &str) -> Result<String, String> {
    let mut configs = config::Config::default();
    match configs.merge(config::File::from(Path::new("config.yml"))) {
        Ok(_) => {}
        Err(e) => {
            return Err(format!("Failed to merge config file, error: {}.", e))
        }
    };

    let config_param = match configs.try_into::<HashMap<String, String>>() {
        Ok(m) => m,
        Err(e) => {
            return Err(format!(
                "Failed to deserialize file into map, error: {}.",
                e
            ))
        }
    };

    match config_param.get(key) {
        Some(value) => Ok(value.to_string()),
        None => Err(format!("Key value not exist.")),
    }
}

/*
 * Input: Response status code
 *        Response result status
 *        Json output content
 *
 * Return: HTTP Respnose struct
 *
 * convert the input into HTTP Response struct with json output formatting.
 * Follow original python-keylime echo_json_response() output structure. But
 * there are two difference between this response json content and the
 * original echo_json_response() response json content.
 * 1. The serde_json crate sorts keys in alphebetic order, which is
 * different than the python version response structure.
 * 2. There is no space in the json content, but python version response
 * content contains white space in between keys.
 */
pub fn json_response_content(
    code: i32,
    status: String,
    results: Map<String, Value>,
) -> Response<Body> {
    let integerated_result = json!({
        "status": status,
        "code": code,
        "results": results,
    });

    match serde_json::to_string(&integerated_result) {
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
 * Input: URL string
 *
 * Ouput: Map contains the request type and content in the request
 *
 * Convert a api resquest path to a map that contains the key and value, which
 * are the requested function and content given in pair from the original url.
 * Same implementation as the original python version get_resrful_parameters()
 * function.
 */
pub fn get_restful_parameters(urlstring: &str) -> HashMap<&str, &str> {
    let mut parameters = HashMap::new();
    let list: Vec<&str> = urlstring.split('/').collect();

    // error hanlding, empty url
    if list.len() <= 0 {
        return parameters;
    }

    // capture the version number
    let (_, right) = list[1].split_at(1);
    parameters.insert("api_version", right);

    // starting from the second element, which is the first requested function
    for x in 2..(list.len() - 1) {
        parameters.insert(list[x], list[x + 1]);
    }
    parameters
}

/*
 * Input: path directory to be changed owner to root
 * Return: Result contains execution result
 *         - directory name for successful execution
 *         - -1 code for failure execution.
 *
 * If privilege requirement is met, change the owner of the path to root
 * This function is unsafely using libc. Result is returned indicating
 * execution result.
 */
pub fn chownroot(path: String) -> Result<String, i32> {
    unsafe {
        // check privilege
        if libc::geteuid() != 0 {
            error!("Privilege level unable to change ownership to root for file: {}", path);
            return Err(-1);
        }

        // change directory owner to root
        if libc::chown(path.as_bytes().as_ptr() as *const i8, 0, 0) != 0 {
            error!("Failed to change file {} owner.", path);
            return Err(-1);
        }

        info!("Changed file {} owner to root.", path);
        Ok(path)
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    // Test the get_restful_parameters function with a given sampel url
    #[test]
    fn test_get_restful_parameters() {
        let mut map = HashMap::new();
        map.insert("verify", "pubkey");
        map.insert("api_version", "2");

        // Map content "{"api_version": "v2", "verify": "pubkey"}"
        assert_eq!(
            get_restful_parameters("127.0.0.1:1337/v2/verify/pubkey"),
            map
        );
    }

    #[test]
    fn test_get_config_parameters_exist() {
        let result = get_config_parameter("secure_size").unwrap();
        assert_eq!(result, "1m");
    }

    #[test]
    fn test_get_config_parameters_not_exist() {
        assert!(!get_config_parameter("foo").is_ok());
    }
}
