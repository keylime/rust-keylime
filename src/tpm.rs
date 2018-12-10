extern crate base64;
extern crate flate2;

use super::*;
use common::emsg;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use openssl::sha;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::io::Read;
use std::process::Command;
use std::process::Output;
use std::str;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use tempfile::NamedTempFile;

const MAX_TRY: usize = 10;
const RETRY_SLEEP: Duration = Duration::from_millis(50);
const TPM_IO_ERROR: i32 = 5;
const RETRY: usize = 4;
pub const EXIT_SUCCESS: i32 = 0;
const BOOTSTRAP_KEY_SIZE: usize = 32;
static EMPTYMASK: &'static str = "1";

/***************************************************************
ftpm_initialize.py
Following are function from tpm_initialize.py program
*****************************************************************/

/*
 * Return: Result wrap named temp file name or error
 *
 * Make a temp file and return its file path.
 */
fn create_and_get_temp_file_path() -> Result<String, Box<String>> {
    match NamedTempFile::new() {
        Ok(tmp_file) => match tmp_file.path().to_str() {
            Some(s) => Ok(s.to_string()),
            None => emsg(
                format!("Failed to get temp file path string. Error")
                    .as_str(),
                None::<String>,
            ),
        },
        Err(e) => emsg(
            format!("Failed to create a  tempfile. Error {}.", e).as_str(),
            Some(e),
        ),
    }
}

/*
 * Input: key to write to nvram
 * Output: write key result
 *
 * Write the given key to TPM nvram. Same implementation as the original
 * python-keylime version. Return value contains the error that needs to be
 * handled.
 */
pub fn nvram_write_key(key: &str) -> Result<(), Box<String>> {
    let owner_password = get_tpm_metadata_content("owner_pw")?;
    let tmp_file_path = create_and_get_temp_file_path()?;

    // Define a space in nvram
    run(
        format!(
            "nv_definespace -pwdo {} -in 1 -sz {} -pwdd {} -per 40004",
            owner_password, BOOTSTRAP_KEY_SIZE, owner_password
        ),
        EXIT_SUCCESS,
        true,
        false,
        String::new(),
    );

    // wrtie key to TPM nvram
    let (_, return_code, _) = run(
        format!(
            "nv_writevalue -pwdd {} -in 1 -if {:?}",
            owner_password, tmp_file_path
        ),
        EXIT_SUCCESS,
        true,
        false,
        String::new(),
    );

    if let Some(c) = return_code {
        info!("Success added key to temp file with exit code {}", c)
    };

    Ok(())
}

/*
 * Output: Result wraps the retrieved key if succeed
 *
 * Read the key stared in nvram. Same implementation as the original
 * python-keylime version. Result is wrapped for error handling.
 */
pub fn nvram_read_key() -> Result<String, Box<String>> {
    let owner_password = get_tpm_metadata_content("owner_pw")?;
    let tmp_file_path = create_and_get_temp_file_path()?;

    // Read U key from TPM nvram
    let (return_output, return_code, key) = run(
        format!(
            "nv_readvalue -pwdd {} -in 1 -sz {} -of {:?}",
            owner_password, BOOTSTRAP_KEY_SIZE, tmp_file_path,
        ),
        EXIT_SUCCESS,
        true,
        false,
        tmp_file_path,
    );

    let content = match String::from_utf8(return_output) {
        Ok(c) => c,
        Err(e) => return emsg("Failed to convert output to String.", Some(e)),
    };

    let first_line = match content.split("\n").next() {
        Some(s) => s,
        None => {
            return emsg(
                "Output has no content, unable to handle error.",
                None::<String>,
            )
        }
    };

    // Execution result error handling
    if let Some(c) = return_code {
        if c != EXIT_SUCCESS
            && first_line.len() > 0
            && (first_line
                .starts_with("Error Illegal index from NV_ReadValue")
                || first_line.starts_with("Error Authentication failed"))
        {
            return emsg("No stored U in TPM NVRAM", None::<String>);
        } else if c != EXIT_SUCCESS {
            let message = format!(
                "nv_readvalue failed with code {} and output {}",
                c, content
            );
            return emsg(message.as_str(), None::<String>);
        }
    }

    if let Some(k) = key {
        if k.len() != BOOTSTRAP_KEY_SIZE {
            return emsg("Invalid key length from nvram", None::<String>);
        }
        Ok(k)
    } else {
        emsg("Key is None.", None::<String>)
    }
}

/*
 * Output: Result wraps the retrieved ekcert key if succeed
 *
 * Read the ekcert key stared in nvram. Same implementation as the original
 * python-keylime version. Result is wrapped for error handling.
 */
fn nvram_read_ekcert() -> Result<String, Box<String>> {
    let owner_password = get_tpm_metadata_content("owner_pw")?;
    let tmp_file_path = create_and_get_temp_file_path()?;

    // Read ekcert key from TPM nvram
    let (return_output, return_code, key) = run(
        format!(
            "nv_readvalue -pwdd {} -in 1000f000 -cert -of {:?}",
            owner_password, tmp_file_path,
        ),
        EXIT_SUCCESS,
        false,
        true,
        tmp_file_path,
    );

    let content = match String::from_utf8(return_output) {
        Ok(c) => c,
        Err(e) => return emsg("Failed to convert output to String.", Some(e)),
    };

    // Execution result error handling
    if let Some(c) = return_code {
        let first_line = match content.split("/n").next() {
            Some(s) => s,
            None => {
                return emsg(
                    "Output has no content. Unable to handle error.",
                    None::<String>,
                )
            }
        };

        if c != EXIT_SUCCESS
            && first_line.len() > 0
            && first_line.starts_with("Error Illegal index from NV_ReadValue")
        {
            return emsg(
                "No EK certificate found in TPM NVRAM",
                None::<String>,
            );
        } else if c != EXIT_SUCCESS {
            return emsg(
                format!(
                "nv_readvalue for ekcert failed with code {} and output {}",
                c, content
            )
                .as_str(),
                None::<String>,
            );
        }

        if let Some(k) = key {
            Ok(base64::encode(k.as_bytes()))
        } else {
            emsg("Failed to retrieve key, key is None.", None::<String>)
        }
    } else {
        emsg("Return code is None, failed to proceed.", None::<String>)
    }
}

/*
 * Input: content key in tpmdata
 * Return: Result wrap value string or error message
 *
 * Getting the tpm data struct and convert it to a json value object to
 * retrive a particular value by the given key inside the tpm data.
 */
fn get_tpm_metadata_content(key: &str) -> Result<String, Box<String>> {
    let tpm_data = match read_tpm_data() {
        Ok(data) => data,
        Err(e) => return emsg("Failed to read tpmdata.json.", Some(e)),
    };

    let remove: &[_] = &['"', ' ', '/'];
    match tpm_data.get(key) {
        Some(content) => match content.as_str() {
            Some(s) => Ok(s.to_string().trim_matches(remove).to_string()),
            None => emsg("Can't convert to string", None::<String>),
        },
        None => emsg("Key doesn't exist", None::<String>),
    }
}

/*
 * Input: tpm data key
 *        tpm data value
 * Return: Result wrap success or error code -1
 *
 * Set the corresponding tpm data key with new value and save the new content
 * to tpmdata.json. This version remove global tpmdata variable. Read the file
 * before write the content to the file.
 */
fn set_tpm_metadata_content(
    key: &str,
    value: &str,
) -> Result<(), Box<String>> {
    let mut tpm_data = match read_tpm_data() {
        Ok(data) => data,
        Err(e) => return emsg("Fail to read tpmdata.json.", Some(e)),
    };

    match tpm_data.get_mut(key) {
        Some(ptr) => *ptr = json!(value),
        None => return emsg("Key doesn't exist", None::<String>),
    };

    if let Err(e) = write_tpm_data(tpm_data) {
        return emsg("Failed to write data to dpmdata.json", Some(e));
    }
    Ok(())
}

/*
 * Return: Result wrap TPM data or Error Message
 *
 * Read in tpmdata.json file and convert it to a pre-defined struct. Now its
 * using the sample tpmdata.json in the crate root directory for testing. The
 * format the same as the original python version. Result is returned to
 * caller for error handling.
 */
fn read_tpm_data() -> Result<Value, Box<String>> {
    let file = match File::open("tpmdata.json") {
        Ok(f) => f,
        Err(e) => return emsg("Failed to open tpmdata.json.", Some(e)),
    };

    let data: Value = match serde_json::from_reader(file) {
        Ok(d) => d,
        Err(e) => return emsg("Failed to convert tpm data to Json.", Some(e)),
    };

    Ok(data)
}

/*
 * Input: tpmdata in Value type
 * Return: Result wrap success or io Error
 *
 * Write the tpmdata to tpmdata.json file with result indicating execution
 * result. Different implementation than the original python version, which
 * changes the global variable tpmdata to local scope variable. Because it
 * could read the data before write instead of using a static type to store
 * it globally.
 */
fn write_tpm_data(data: Value) -> Result<(), Box<String>> {
    let mut buffer = match File::create("tpmdata.json") {
        Ok(f) => BufWriter::new(f),
        Err(e) => return emsg("Failed to open tpmdata.json.", Some(e)),
    };

    let data_string = match serde_json::to_string_pretty(&data) {
        Ok(d) => d,
        Err(e) => return emsg("Failed to convert tpm data to Json.", Some(e)),
    };

    match buffer.write(data_string.as_bytes()) {
        Ok(s) => info!("Wrote {} byte to file.", s),
        Err(e) => return emsg("Failed to write to tpmdata.json.", Some(e)),
    };

    // Use flush to ensure all the intermediately buffered contents
    // reach their destination
    if let Err(e) = buffer.flush() {
        return emsg("Failed to flush to tpm data file.", Some(e));
    }
    Ok(())
}

/*
 * input: None
 * output: boolean
 *
 * If tpm is a tpm elumator, return true, other wise return false
 */
pub fn is_vtpm() -> Option<bool> {
    match common::STUB_VTPM {
        true => Some(true),
        false => {
            let tpm_manufacturer = get_tpm_manufacturer();
            Some(tpm_manufacturer.unwrap() == "ETHZ")
        }
    }
}

/*
 * getting the tpm manufacturer information
 * is_vtpm helper method
 */
fn get_tpm_manufacturer() -> Option<String> {
    let (return_output, _return_code, _file_output) = run(
        "getcapability -cap 1a".to_string(),
        EXIT_SUCCESS,
        true,
        false,
        String::new(),
    );
    let content_result = String::from_utf8(return_output);
    let content = content_result.unwrap();

    let lines: Vec<&str> = content.split("\n").collect();
    let mut manufacturer = String::new();
    for line in lines {
        let line_tmp = String::from(line);
        let token: Vec<&str> = line_tmp.split_whitespace().collect();
        if token.len() == 3 {
            match (token[0], token[1]) {
                ("VendorID", ":") => manufacturer = token[2].to_string(),
                _ => {}
            }
        }
    }
    Some(manufacturer)
}

/***************************************************************
tpm_quote.py
Following are function from tpm_quote.py program
*****************************************************************/

/*
 * Input: nonce string
 *        data that needs to be pass to the pcr
 *        pcrmask
 *
 * Output: quote from tpm pcr
 *
 * Getting quote form tpm, same implementation as the original python version.
 */
pub fn create_quote(
    nonce: String,
    data: String,
    mut pcrmask: String,
) -> Option<String> {
    let quote_path = NamedTempFile::new().unwrap();
    let key_handle = match get_tpm_metadata_content("aik_handle") {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to get tpm aik_handle with error {}.", e);
            return None;
        }
    };

    let aik_password = match get_tpm_metadata_content("aik_pw") {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to get tpm aik_pw with error {}.", e);
            return None;
        }
    };

    if pcrmask == "".to_string() {
        pcrmask = EMPTYMASK.to_string();
    }

    if !(data == "".to_string()) {
        let pcrmask_int: i32 = pcrmask.parse().unwrap();
        pcrmask =
            format!("0x{}", (pcrmask_int + (1 << common::TPM_DATA_PCR)));
        let mut command = format!("pcrreset -ix {}", common::TPM_DATA_PCR);

        // RUN
        run(command, EXIT_SUCCESS, true, false, String::new());

        // Use SHA1 to hash the data
        let mut hasher = sha::Sha1::new();
        hasher.update(data.as_bytes());
        let data_sha1_hash = hasher.finish();

        command = format!(
            "extend -ix {} -ic {}",
            common::TPM_DATA_PCR,
            hex::encode(data_sha1_hash),
        );

        run(command, EXIT_SUCCESS, true, false, String::new());
    }

    // store quote into the temp file that will be extracted later
    let command = format!(
        "tpmquote -hk {} -pwdk {} -bm {} -nonce {} -noverify -oq {}",
        key_handle,
        aik_password,
        pcrmask,
        nonce,
        quote_path.path().to_str().unwrap().to_string(),
    );

    let (_return_output, _exit_code, quote_raw) = run(
        command,
        EXIT_SUCCESS,
        true,
        false,
        quote_path.path().to_string_lossy().to_string(),
    );

    let mut quote_return = String::from("r");
    quote_return.push_str(&base64_zlib_encode(quote_raw.unwrap()));
    Some(quote_return)
}

/*
 * Input: nonce string
 *        data that needs to be pass to the pcr
 *        pcrmask
 *
 * Output: deep quote from tpm pcr
 *
 * Getting deep quote form tpm, same implementation as the original python
 * version. Same  procedures as quote by this is a deep quote.
 */
pub fn create_deep_quote(
    nonce: String,
    data: String,
    mut pcrmask: String,
    mut vpcrmask: String,
) -> Option<String> {
    let quote_path = NamedTempFile::new().unwrap();
    let key_handle = match get_tpm_metadata_content("aik_handle") {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to get tpm aik_handle with error {}.", e);
            return None;
        }
    };

    let aik_password = match get_tpm_metadata_content("aik_pw") {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to get tpm aik_pw with error {}.", e);
            return None;
        }
    };

    let owner_password = match get_tpm_metadata_content("owner_pw") {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to get tpm owner_pw with error {}.", e);
            return None;
        }
    };

    if pcrmask == "".to_string() {
        pcrmask = EMPTYMASK.to_string();
    }

    if vpcrmask == "".to_string() {
        vpcrmask = EMPTYMASK.to_string();
    }

    if !(data == "".to_string()) {
        let vpcrmask_int: i32 = vpcrmask.parse().unwrap();
        vpcrmask =
            format!("0x{}", (vpcrmask_int + (1 << common::TPM_DATA_PCR)));
        let mut command = format!("pcrreset -ix {}", common::TPM_DATA_PCR);

        // RUN
        run(command, EXIT_SUCCESS, true, false, String::new());

        let mut hasher = sha::Sha1::new();
        hasher.update(data.as_bytes());
        let data_sha1_hash = hasher.finish();

        command = format!(
            "extend -ix {} -ic {}",
            common::TPM_DATA_PCR,
            hex::encode(data_sha1_hash),
        );

        // RUN
        run(command, EXIT_SUCCESS, true, false, String::new());
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
        quote_path.path().to_str().unwrap(),
    );

    // RUN
    let (_return_output, _exit_code, quote_raw) = run(
        command,
        EXIT_SUCCESS,
        true,
        false,
        quote_path.path().to_string_lossy().to_string(),
    );

    let mut quote_return = String::from("d");
    quote_return.push_str(&base64_zlib_encode(quote_raw.unwrap()));
    Some(quote_return)
}

/*
 * Input: string to be encoded
 * Output: encoded string output
 *
 * Use zlib to compression the input and encoded with base64 encoding
 * method
 *
 * It doesn't given the same hex output as python but python is able to
 * decode the hex output and give back the original text message. No able
 * to test with identical python function output string.
 */
fn base64_zlib_encode(data: String) -> String {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());

    match e.write_all(data.as_bytes()) {
        Ok(_) => {
            let compressed_bytes = e.finish();
            match compressed_bytes {
                Ok(e) => base64::encode(&e),
                Err(_) => String::from(""),
            }
        }
        Err(_) => String::from("Encode Fail!"),
    }
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
    let ima_mask_int: i32 = ima_mask.parse().unwrap();
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
 * Input:
 *     cmd: command to be executed
 *     except_code: return code that needs extra handling
 *     raise_on_error: raise exception/panic while encounter error option
 *     lock: lock engage option
 *     output_path: file output location
 * return:
 *     tuple contains (standard output, return code, and file output)
 *
 * Execute tpm command through shell commands and return the execution
 * result in a tuple. Implement as original python version. Haven't
 * implemented tpm stubbing and metric.
 */
pub fn run<'a>(
    command: String,
    except_code: i32,
    raise_on_error: bool,
    _lock: bool,
    output_path: String,
) -> (Vec<u8>, Option<i32>, Option<String>) {
    /* stubbing  placeholder */

    // tokenize input command
    let words: Vec<&str> = command.split(" ").collect();
    let mut number_tries = 0;
    let args = &words[1..words.len()];
    let cmd = &words[0];

    // setup environment variable
    let mut env_vars: HashMap<String, String> = HashMap::new();
    for (key, value) in env::vars() {
        // println!("{}: {}", key, value);
        env_vars.insert(key.to_string(), value.to_string());
    }

    env_vars.insert("TPM_SERVER_PORT".to_string(), "9998".to_string());
    env_vars.insert("TPM_SERVER_NAME".to_string(), "localhost".to_string());
    env_vars
        .get_mut("PATH")
        .unwrap()
        .push_str(common::TPM_TOOLS_PATH);

    let mut t_diff: u64 = 0;
    let mut output: Output;

    loop {
        let t0 = SystemTime::now();

        // command execution
        output = Command::new(&cmd)
            .args(args)
            .envs(&env_vars)
            .output()
            .expect("failed to execute process");

        // measure execution time
        match t0.duration_since(t0) {
            Ok(t_delta) => t_diff = t_delta.as_secs(),
            Err(_) => {}
        }
        info!("Time cost: {}", t_diff);

        // assume the system is linux
        println!("number tries: {:?}", number_tries);

        match output.status.code().unwrap() {
            TPM_IO_ERROR => {
                number_tries += 1;
                if number_tries >= MAX_TRY {
                    error!("TPM appears to be in use by another application.  Keylime is incompatible with other TPM TSS applications like trousers/tpm-tools. Please uninstall or disable.");
                    break;
                }

                info!(
                    "Failed to call TPM {}/{} times, trying again in {} seconds...",
                    number_tries,
                    MAX_TRY,
                    RETRY,
                );

                thread::sleep(RETRY_SLEEP);
            }
            _ => break,
        }
    }

    let return_output = output.stdout;
    let return_code = output.status.code();

    if return_code.unwrap() != except_code && raise_on_error {
        panic!(
            "Command: {} returned {}, expected {}, output {}",
            command,
            return_code.unwrap(),
            except_code.to_string(),
            String::from_utf8_lossy(&return_output),
        );
    }

    let mut file_output: String = String::new();

    match read_file_output_path(output_path) {
        Ok(content) => file_output = content,
        Err(_) => {}
    }

    /* metric output placeholder */

    (return_output, return_code, Some(file_output))
}

/*
 * input: file name
 * return: the content of the file int Result<>
 *
 * run method helper method
 * read in the file and  return the content of the file into a Result enum
 */
fn read_file_output_path(output_path: String) -> std::io::Result<String> {
    let mut file = File::open(output_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

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
    fn test_create_temp_file() {
        assert!(create_and_get_temp_file_path().is_ok());
    }

    #[test]
    fn test_read_file_output_path() {
        assert_eq!(
            read_file_output_path("test_input.txt".to_string()).unwrap(),
            "Hello World!\n"
        );
    }

    #[test]
    fn test_is_deep_quote() {
        assert_eq!(is_deep_quote(String::from("dqewrtypuo")), true);
    }

    // The following test will base on the system capability to run. TPM is
    // require to run those tests.
    #[test]
    fn test_is_vtpm() {
        match command_exist("getcapability") {
            true => assert_eq!(is_vtpm().unwrap(), false),
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
    fn test_run_command() {
        match command_exist("getrandom") {
            true => {
                let command = "getrandom -size 8 -out foo.out".to_string();
                run(command, EXIT_SUCCESS, true, false, String::new());

                let p = Path::new("foo.out");
                assert_eq!(p.exists(), true);
                match fs::remove_file("foo.out") {
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
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
        let file = File::open("tpmdata_test.json")?;
        let data: Value = serde_json::from_reader(file)?;
        let mut buffer = BufWriter::new(File::create("tpmdata.json")?);
        let data_string = serde_json::to_string_pretty(&data)?;
        buffer.write(data_string.as_bytes())?;
        buffer.flush()?;
        Ok(())
    }
}
