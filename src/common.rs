use crate::error::{Error, Result};

use hyper::header::HeaderValue;
use hyper::{header, Body, Response, StatusCode};
use ini::Ini;
use log::*;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::process;

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

// Secure mount of tpmfs (False is generally used for development environments)
pub static MOUNT_SECURE: bool = true;

/*
 * Input: config file location (e.g. /etc/keylime.conf), [section] and key
 * Return: Returns the matched key
 *
 * Example call:
 * let port = common::config_get("/etc/keylime.conf""general","cloudagent_port");
 */
pub(crate) fn config_get(
    conf_name: &str,
    section: &str,
    key: &str,
) -> Result<String> {
    let conf = Ini::load_from_file(conf_name)?;
    let section = match conf.section(Some(section.to_owned())) {
        Some(section) => section,
        None =>
        // TODO: Make Error::Configuration an alternative with data instead of string
        {
            return Err(Error::Configuration(format!(
                "Cannot find section called {} in file {}",
                section, conf_name
            )))
        }
    };
    let value = match section.get(key) {
        Some(value) => value,
        None =>
        // TODO: Make Error::Configuration an alternative with data instead of string
        {
            return Err(Error::Configuration(format!(
                "Cannot find key {} in fine {}",
                key, conf_name
            )))
        }
    };

    Ok(value.clone())
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
pub(crate) fn set_response_content(
    code: i32,
    status: &str,
    results: Map<String, Value>,
    response: &mut Response<Body>,
) -> Result<()> {
    let integerated_result = json!({
        "status": status,
        "code": code,
        "results": results,
    });

    let s = serde_json::to_string(&integerated_result)?;
    // Dereferencing apply here because it needs to derefer the variable
    // so it can assign the new value to it. But changing the headers
    // doesn't require dereference is because that it uses the returned
    // header reference and update it instead of changing it, so no
    // dereference is needed in this case.
    *response.body_mut() = s.into();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(())
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
pub(crate) fn get_restful_parameters(urlstring: &str) -> HashMap<&str, &str> {
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
pub(crate) fn chownroot(path: String) -> Result<String> {
    unsafe {
        // check privilege
        if libc::geteuid() != 0 {
            error!("Privilege level unable to change ownership to root for file: {}", path);
            return Err(Error::Permission);
        }

        // change directory owner to root
        if libc::chown(path.as_bytes().as_ptr() as *const i8, 0, 0) != 0 {
            error!("Failed to change file {} owner.", path);
            return Err(Error::Permission);
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
    fn test_set_response_content() {
        let mut my_res: Response<Body> = Response::new("nothing".into());
        assert!(
            set_response_content(0, "Ok", Map::new(), &mut my_res).is_ok()
        );
    }

    #[test]
    fn test_config_get_parameters_exist() {
        //let result = config_get("keylime.conf", "general", "cloudagent_port");
        //assert_eq!(result, "9002");
    }
}
