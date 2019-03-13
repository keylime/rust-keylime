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

static EMPTYMASK: &'static str = "1";

/***************************************************************
ftpm_initialize.py
Following are function from tpm_initialize.py program
*****************************************************************/

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
 * to tpmdata.json. This version remove global tpmdata variable. Read the
 * file before write the content to the file.
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
 * Input: None
 * Return: boolean
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
 * Return: Result wrap the manufacture information
 *
 * getting the tpm manufacturer information
 * is_vtpm helper method
 */
fn get_tpm_manufacturer() -> Result<String, Box<String>> {
    let (return_output, _, _) =
        run("getcapability -cap 1a".to_string(), EXIT_SUCCESS, None)?;

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
    emsg("Vendor information not found.", None::<String>)
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
    let temp_file = match NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to create new temporary file. Error {}.?", e);
            return None;
        }
    };

    let quote_path = match temp_file.path().to_str() {
        Some(s) => s,
        None => return None,
    };

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
        let pcrmask_int: i32 = match pcrmask.parse() {
            Ok(i) => i,
            Err(e) => {
                error!("Failed to parse pcrmask to integer. Error {}.", e);
                return None;
            }
        };

        pcrmask =
            format!("0x{}", (pcrmask_int + (1 << common::TPM_DATA_PCR)));
        let mut command = format!("pcrreset -ix {}", common::TPM_DATA_PCR);

        // RUN
        if let Err(e) = run(command, EXIT_SUCCESS, None) {
            error!("Failed to execute TPM command with error {}.", e);
            return None;
        }

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
        if let Err(e) = run(command, EXIT_SUCCESS, None) {
            error!("Failed to execute TPM command with error {}.", e);
            return None;
        }
    }

    // store quote into the temp file that will be extracted later
    let command = format!(
        "tpmquote -hk {} -pwdk {} -bm {} -nonce {} -noverify -oq {}",
        key_handle, aik_password, pcrmask, nonce, quote_path,
    );

    let (_, _, quote_raw) = match run(command, EXIT_SUCCESS, Some(quote_path))
    {
        Ok((o, c, q)) => ((o, c, q)),
        Err(e) => {
            error!("Failed to execute TPM command with error {}.", e);
            return None;
        }
    };

    let mut quote_return = String::from("r");
    quote_return.push_str(&base64_zlib_encode(quote_raw));
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
    let temp_file = match NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to create new temporary file. Error {}.?", e);
            return None;
        }
    };

    let quote_path = match temp_file.path().to_str() {
        Some(s) => s,
        None => return None,
    };

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
        let vpcrmask_int: i32 = match vpcrmask.parse() {
            Ok(i) => i,
            Err(e) => {
                error!("Failed to parse vpcrmask to integer. Error {}.", e);
                return None;
            }
        };
        vpcrmask =
            format!("0x{}", (vpcrmask_int + (1 << common::TPM_DATA_PCR)));
        let mut command = format!("pcrreset -ix {}", common::TPM_DATA_PCR);

        //RUN
        if let Err(e) = run(command, EXIT_SUCCESS, None) {
            error!("Failed to execute TPM command with error {}.", e);
            return None;
        }

        let mut hasher = sha::Sha1::new();
        hasher.update(data.as_bytes());
        let data_sha1_hash = hasher.finish();

        command = format!(
            "extend -ix {} -ic {}",
            common::TPM_DATA_PCR,
            hex::encode(data_sha1_hash),
        );

        //RUN
        if let Err(e) = run(command, EXIT_SUCCESS, None) {
            error!("Failed to execute TPM command with error {}.", e);
            return None;
        }
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
    let (_, _, quote_raw) = match run(command, EXIT_SUCCESS, Some(quote_path))
    {
        Ok((o, c, q)) => ((o, c, q)),
        Err(e) => {
            error!("Failed to execute TPM command with error {}.", e);
            return None;
        }
    };

    let mut quote_return = String::from("d");
    quote_return.push_str(&quote_raw);
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
 * Input:
 *     command: command to be executed
 *     expect_code: code expect to have from execution result
 *     output_path: file output location
 * return:
 *     tuple contains:
 *         return output: execution standard output
 *         return code: execution result code
 *         file output: output file content if avaiable
 *
 * Set up execution envrionment to execute tpm command through shell commands
 * and return the execution result in a tuple. Based on the latest update of
 * python keylime this function implement the functionality of cmd_exec
 * script in the python keylime repo. RaiseOnError and lock are dropped due
 * to different error handling in Rust. Output are preprocessed to before
 * returning for code efficient.
 */
pub fn run<'a>(
    command: String,
    expect_code: i32,
    output_path: Option<&str>,
) -> Result<(String, i32, String), Box<String>> {
    let mut t_diff: u64 = 0;
    let mut file_output = String::new();
    let mut output: Output;

    // tokenize input command
    let words: Vec<&str> = command.split(" ").collect();
    let mut number_tries = 0;
    let args = &words[1..words.len()];
    let cmd = &words[0];

    // setup environment variable
    let mut env_vars: HashMap<String, String> = HashMap::new();
    for (key, value) in env::vars() {
        env_vars.insert(key.to_string(), value.to_string());
    }
    env_vars.insert("TPM_SERVER_PORT".to_string(), "9998".to_string());
    env_vars.insert("TPM_SERVER_NAME".to_string(), "localhost".to_string());
    match env_vars.get_mut("PATH") {
        Some(v) => v.push_str(common::TPM_TOOLS_PATH),
        None => return emsg("PATH doesn't exist.", None::<String>),
    }

    // main loop
    'exec: loop {
        // Start time stamp
        let t0 = SystemTime::now();

        output = match Command::new(&cmd).args(args).envs(&env_vars).output()
        {
            Ok(o) => o,
            Err(e) => return emsg("Failed to execute command", Some(e)),
        };

        // measure execution time
        t_diff = match t0.duration_since(t0) {
            Ok(t_delta) => t_delta.as_secs(),
            Err(e) => return emsg("Can't get time duration", Some(e)),
        };
        info!("Time cost: {}", t_diff);

        // assume the system is linux
        println!("number tries: {:?}", number_tries);

        match output.status.code() {
            Some(TPM_IO_ERROR) => {
                number_tries += 1;
                if number_tries >= MAX_TRY {
                    return emsg(
                        "TPM appears to be in use by another application. 
                                Keylime is incompatible with other TPM TSS 
                                applications like trousers/tpm-tools. Please 
                                uninstall or disable.",
                        None::<String>,
                    );
                }

                info!(
                    "Failed to call TPM {}/{} times, trying again in {} seconds...",
                    number_tries,
                    MAX_TRY,
                    RETRY,
                );

                thread::sleep(RETRY_SLEEP);
            }

            _ => break 'exec,
        }
    }

    // preprocess execution result
    let return_output = String::from_utf8(output.stdout).map_err(|e| {
        Box::new(format!(
            "Can't convert output to utf8 encoded String. Error {}.",
            e,
        ))
    })?;

    // preprocess execution status code
    let return_code = match output.status.code() {
        Some(c) => c,
        None => {
            return emsg("Execution status code is None.", None::<String>);
        }
    };

    // Execution return code checking
    if return_code != expect_code {
        return emsg(
            format!(
                "Command: {} returned {}, expected {}, output {}",
                command,
                return_code,
                expect_code.to_string(),
                return_output,
            )
            .as_str(),
            None::<String>,
        );
    }

    // Retrive data from output path file
    if let Some(p) = output_path {
        file_output = match read_file_output_path(p.to_string()) {
            Ok(content) => content,
            Err(e) => return emsg("Failed to read output path", Some(e)),
        };
    }

    Ok((return_output, return_code, file_output))
}

/*
 * Input: file name
 * Return: the content of the file int Result<>
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
    fn test_run_command() {
        match command_exist("getrandom") {
            true => {
                let command = "getrandom -size 8 -out foo.out".to_string();
                run(command, EXIT_SUCCESS, None);
                let p = Path::new("foo.out");
                assert_eq!(p.exists(), true);
                fs::remove_file("foo.out").unwrap();
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
