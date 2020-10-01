extern crate base64;
extern crate flate2;

use super::*;
use cmd_exec;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use keylime_error;
use openssl::sha;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::str;
use std::time::Duration;
use tempfile::NamedTempFile;

const MAX_TRY: usize = 10;
const RETRY_SLEEP: Duration = Duration::from_millis(50);
const TPM_IO_ERROR: i32 = 5;
const RETRY: usize = 4;
static EMPTYMASK: &'static str = "1";

/***************************************************************
ftpm_initialize.py
Following are function from tpm_initialize.py program
*****************************************************************/

/*
 * Input:
 *     content key in tpmdata
 * Return:
 *     Value string
 *     keylime_error::KeylimeTpmError
 *
 * Getting the tpm data struct and convert it to a json value object to
 * retrive a particular value by the given key inside the tpm data.
 */
fn get_tpm_metadata_content(
    key: &str,
) -> Result<String, keylime_error::KeylimeTpmError> {
    let tpm_data = read_tpm_data()?;
    let remove: &[_] = &['"', ' ', '/'];
    tpm_data.get(key).map_or_else(
        || {
            Err(keylime_error::KeylimeTpmError::new_tpm_rust_error(
                format!("Key: {} is missing in tpmdata.json", key).as_str(),
            ))
        },
        |content| {
            content.as_str().map_or_else(
                || {
                    Err(keylime_error::KeylimeTpmError::new_tpm_rust_error(
                        "Failed to convert Value to stirng.",
                    ))
                },
                |s| Ok(s.to_string().trim_matches(remove).to_string()),
            )
        },
    )
}

/*
 * Input:
 *      tpm data key
 *      tpm data value
 * Return:
 *      success
 *      keylime_error::KeylimeTpmError
 *
 * Set the corresponding tpm data key with new value and save the new content
 * to tpmdata.json. This version remove global tpmdata variable. Read the
 * file before write the content to the file.
 */
fn set_tpm_metadata_content(
    key: &str,
    value: &str,
) -> Result<(), keylime_error::KeylimeTpmError> {
    let mut tpm_data = read_tpm_data()?;
    match tpm_data.get_mut(key) {
        Some(ptr) => *ptr = json!(value),
        None => {
            return Err(keylime_error::KeylimeTpmError::new_tpm_rust_error(
                format!("Key: {} is missing in tpmdata.json", key).as_str(),
            ));
        }
    };

    write_tpm_data(tpm_data)?;
    Ok(())
}

/*
 * Return:
 *     TPM data
 *     keylime_error::KeylimeTpmError
 *
 * Read in tpmdata.json file and convert it to a pre-defined struct. Now its
 * using the sample tpmdata.json in the crate root directory for testing. The
 * format the same as the original python version. Result is returned to
 * caller for error handling.
 */
fn read_tpm_data() -> Result<Value, keylime_error::KeylimeTpmError> {
    let file = File::open("tpmdata.json")?;
    let data: Value = serde_json::from_reader(file)?;
    Ok(data)
}

/*
 * Input: tpmdata in Value type
 * Return:
 *     success
 *     keylime_error::KeylimeTpmError
 *
 * Write the tpmdata to tpmdata.json file with result indicating execution
 * result. Different implementation than the original python version, which
 * changes the global variable tpmdata to local scope variable. Because it
 * could read the data before write instead of using a static type to store
 * it globally.
 */
fn write_tpm_data(data: Value) -> Result<(), keylime_error::KeylimeTpmError> {
    let mut buffer = BufWriter::new(File::create("tpmdata.json")?);
    let data_string = serde_json::to_string_pretty(&data)?;
    buffer.write(data_string.as_bytes())?;

    // Use flush to ensure all the intermediately buffered contents
    // reach their destination
    buffer.flush()?;
    Ok(())
}

/*
 * Return:
 *     true for vtpm/false otherwise
 *
 * If tpm is a tpm elumator, return true, other wise return false
 */
pub fn is_vtpm() -> bool {
    match common::STUB_VTPM {
        true => return true,
        false => match get_tpm_manufacturer() {
            Ok(data) => data == "EtHZ",
            Err(e) => {
                warn!("Fail to get tpm manufacturer. {}", e);
                false
            }
        },
    }
}

/*
 * Return:
 *     manufacture information
 *     keylime_error::KeylimeTpmError
 *
 * getting the tpm manufacturer information
 * is_vtpm helper method
 */
fn get_tpm_manufacturer() -> Result<String, keylime_error::KeylimeTpmError> {
    let (return_output, _) =
        cmd_exec::run("getcapability -cap 1a".to_string(), None)?;
    let lines: Vec<&str> = return_output.split("\n").collect();
    let mut manufacturer = String::new();
    for line in lines {
        let line_tmp = String::from(line);
        let token: Vec<&str> = line_tmp.split_whitespace().collect();
        if token.len() == 3 {
            if token[0] == "VendorID" && token[1] == ":" {
                return Ok(token[2].to_string());
            }
        }
    }
    Err(keylime_error::KeylimeTpmError::new_tpm_rust_error(
        "TPM manufacture information is missing.",
    ))
}

/***************************************************************
tpm_quote.py
Following are function from tpm_quote.py program
*****************************************************************/

/*
 * Input:
 *     nonce string
 *     data that needs to be pass to the pcr
 *     pcrmask
 *
 * Output:
 *     quote from tpm pcr
 *     keylime_error::KeylimeTpmError
 *
 * Getting quote form tpm, same implementation as the original python version.
 */
pub fn create_quote(
    nonce: String,
    data: String,
    mut pcrmask: String,
) -> Result<String, keylime_error::KeylimeTpmError> {
    let temp_file = NamedTempFile::new()?;
    let quote_path = match temp_file.path().to_str() {
        None => {
            return Err(keylime_error::KeylimeTpmError::new_tpm_rust_error(
                "Can't retrieve temp file path.",
            ));
        }
        Some(p) => p,
    };

    let key_handle = get_tpm_metadata_content("aik_handle")?;
    let aik_password = get_tpm_metadata_content("aik_pw")?;
    if pcrmask == "".to_string() {
        pcrmask = EMPTYMASK.to_string();
    }

    if !(data == "".to_string()) {
        let pcrmask_int: i32 = pcrmask.parse()?;

        pcrmask =
            format!("0x{}", (pcrmask_int + (1 << common::TPM_DATA_PCR)));
        let mut command = format!("pcrreset -ix {}", common::TPM_DATA_PCR);

        // RUN
        cmd_exec::run(command, None)?;

        // Use SHA1 to hash the data
        let mut hasher = sha::Sha1::new();
        hasher.update(data.as_bytes());
        let data_sha1_hash = hasher.finish();

        command = format!(
            "extend -ix {} -ic {}",
            common::TPM_DATA_PCR,
            hex::encode(data_sha1_hash),
        );

        // RUN
        cmd_exec::run(command, None)?;
    }

    // store quote into the temp file that will be extracted later
    let command = format!(
        "tpmquote -hk {} -pwdk {} -bm {} -nonce {} -noverify -oq {}",
        key_handle, aik_password, pcrmask, nonce, quote_path,
    );

    let (_, quote_raw) = cmd_exec::run(command, Some(quote_path))?;
    let mut quote_return = String::from("r");
    quote_return.push_str(&base64_zlib_encode(quote_raw)?);
    Ok(quote_return)
}

/*
 * Input:
 *     nonce string
 *     data that needs to be pass to the pcr
 *     pcrmask
 *
 * Output:
 *     deep quote string from tpm pcr
 *     keylime_error::KeylimeTpmError
 *
 * Getting deep quote form tpm, same implementation as the original python
 * version. Same  procedures as quote by this is a deep quote.
 */
pub fn create_deep_quote(
    nonce: String,
    data: String,
    mut pcrmask: String,
    mut vpcrmask: String,
) -> Result<String, keylime_error::KeylimeTpmError> {
    let temp_file = NamedTempFile::new()?;
    let quote_path = match temp_file.path().to_str() {
        None => {
            return Err(keylime_error::KeylimeTpmError::new_tpm_rust_error(
                "Can't retieve temp file path.",
            ));
        }
        Some(p) => p,
    };
    let key_handle = get_tpm_metadata_content("aik_handle")?;
    let aik_password = get_tpm_metadata_content("aik_pw")?;
    let owner_password = get_tpm_metadata_content("owner_pw")?;

    if pcrmask == "".to_string() {
        pcrmask = EMPTYMASK.to_string();
    }

    if vpcrmask == "".to_string() {
        vpcrmask = EMPTYMASK.to_string();
    }

    if !(data == "".to_string()) {
        let vpcrmask_int: i32 = vpcrmask.parse()?;
        vpcrmask =
            format!("0x{}", (vpcrmask_int + (1 << common::TPM_DATA_PCR)));
        let mut command = format!("pcrreset -ix {}", common::TPM_DATA_PCR);

        //RUN
        cmd_exec::run(command, None)?;
        let mut hasher = sha::Sha1::new();
        hasher.update(data.as_bytes());
        let data_sha1_hash = hasher.finish();

        command = format!(
            "extend -ix {} -ic {}",
            common::TPM_DATA_PCR,
            hex::encode(data_sha1_hash),
        );

        //RUN
        cmd_exec::run(command, None)?;
    }

    // store quote into the temp file that will be extracted later
    let command = format!(
        "deepquote -vk {} -hm {} -vm {} -nonce {} -pwdo {} -pwdk {} -oq {}",
        key_handle,
        pcrmask,
        vpcrmask,
        nonce,
        owner_password,
        aik_password,
        quote_path,
    );

    // RUN
    let (_, quote_raw) = cmd_exec::run(command, Some(quote_path))?;
    let mut quote_return = String::from("d");
    quote_return.push_str(&quote_raw);
    Ok(quote_return)
}

/*
 * Input: string to be encoded
 * Output:
 *     encoded string output
 *     keylime_error::KeylimeTpmError
 *
 * Use zlib to compression the input and encoded with base64 encoding
 * method
 *
 * It doesn't given the same hex output as python but python is able to
 * decode the hex output and give back the original text message. No able
 * to test with identical python function output string.
 */
fn base64_zlib_encode(
    data: String,
) -> Result<String, keylime_error::KeylimeTpmError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data.as_bytes())?;
    let compressed_bytes = encoder.finish()?;
    Ok(base64::encode(&compressed_bytes))
}

/*
 * Input: ima mask
 *        ima pcr
 * Output: match result
 *
 * If ima_mask match ima_pcr return true, otherwise, return false. Same as
 * original python version.
 */
pub fn check_mask(ima_mask: String, ima_pcr: usize) -> bool {
    if ima_mask.is_empty() {
        return false;
    }
    let ima_mask_int: i32 = match ima_mask.parse() {
        Ok(i) => i,
        Err(e) => {
            error!("Failed to parse ima_mask to integer. Error {}.", e);
            return false; // temporary return false for error
        }
    };
    match (1 << ima_pcr) & ima_mask_int {
        0 => return false,
        _ => return true,
    }
}

/*
 * Input: quote string
 * Output: deep quote check result boolean
 *
 * Check the quote string, if it is deep quote string, return true, otherwise,
 * return false. Same as the original python version.
 */
pub fn is_deep_quote(quote: String) -> bool {
    let first_char = &quote[0..1];
    match first_char {
        "d" => true,
        "r" => false,
        _ => {
            warn!("Invalid quote type {}", quote);
            false
        }
    }
}

/***************************************************************
tpm_nvram.py
Following are function from tpm_nvram.py program
*****************************************************************/

/***************************************************************
tpm_exec.py
Following are function from tpm_exec.py program
*****************************************************************/

/*
 * These test are for Centos and tpm4720 elmulator install environment. It
 * test tpm command before execution.
 */
#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;

    #[test]
    fn test_is_deep_quote() {
        assert_eq!(is_deep_quote(String::from("dqewrtypuo")), true);
    }

    // The following test will base on the system capability to run. TPM is
    // require to run those tests.
    #[test]
    fn test_is_vtpm() {
        match command_exist("getcapability") {
            true => assert_eq!(is_vtpm(), false),
            false => assert!(true),
        }
    }

    #[test]
    fn test_get_manufacturer() {
        match command_exist("getcapability") {
            true => assert_eq!(get_tpm_manufacturer().unwrap(), "IBM"),
            false => assert!(true),
        }
    }

    #[test]
    fn test_get_tpm_metadata_1() {
        assert!(set_tpmdata_test().is_ok());

        // using test tpmdata.json content must present, system won't panic
        let remove: &[_] = &['"', ' ', '/'];
        let password = get_tpm_metadata_content("aik_handle")
            .expect("Failed to get aik_handle.");
        assert_eq!(password.trim_matches(remove), String::from("FB1F19E0"));
    }

    #[test]
    fn test_get_tpm_metadata_2() {
        assert!(set_tpmdata_test().is_ok());

        // foo is not a key in tpmdata, this call should fail
        assert!(!get_tpm_metadata_content("foo").is_ok());
    }

    #[test]
    fn test_write_tpm_metadata() {
        assert!(set_tpmdata_test().is_ok());
        set_tpm_metadata_content("owner_pw", "hello")
            .expect("Failed to set owner_pw.");

        // using test tpmdata.json content must present, system won't panic
        let remove: &[_] = &['"', ' ', '/'];
        let password = get_tpm_metadata_content("owner_pw")
            .expect("Failed to get owner_pw.");
        assert_eq!(password.trim_matches(remove), String::from("hello"));
    }

    /*
     * Input: command name
     * Output: checkout command result
     *
     * Look for the command in path, if command is there return true, if
     * command is not exist return false.
     */
    fn command_exist(command: &str) -> bool {
        if let Ok(path) = env::var("PATH") {
            for pp in path.split(":") {
                let command_path = format!("{}/{}", pp, command);
                if fs::metadata(command_path).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    /*
     * copy tpmdata_test.json file to tpmdata.json for testing
     */
    fn set_tpmdata_test() -> Result<(), Box<Error>> {
        let file = File::open("test-data/tpmdata_test.json")?;
        let data: Value = serde_json::from_reader(file)?;
        let mut buffer = BufWriter::new(File::create("tpmdata.json")?);
        let data_string = serde_json::to_string_pretty(&data)?;
        buffer.write(data_string.as_bytes())?;
        buffer.flush()?;
        Ok(())
    }
}
