mod tpm {

    extern crate rustc_serialize;
    extern crate serde_json;

    use rustc_serialize::json::Json;
    use std::fs::File;
    use std::io::Read;
    use libc::{umask, geteuid};
    use std::path::Path;
    use std::process::Command;
    use std::process::Output;
    use std::{thread, time};
    use std::time::Duration;
    use std::fs::File;
    use tempfile::tempfile;

    const MAX_TRY: usize = 10;
    const RETRY_SLEEP: Duration = time::Duration::from_millis(50);
    const TPM_IO_ERROR: i32 = 5;



    // temp global variable 
    static mut global_tpmdata: Json = None;


    /***************************************************************
    package from tpm_initialize.py

        
    *****************************************************************/
    /*
    input: a string value
    return: deserlized json object
    */
    fn get_tpm_metadata(key: String) -> String {
        match global_tpmdata {
            Some("") => {
                global_tpmdata = read_tpm_data()
            },
            _ => {},
        }
        global_tpmdata.find("key")
    }

    fn read_tpm_data() -> Result<Json> {
        let path = Path::new("tpmdata.json");
        if path.exists() {
            let f = File::iopen("tpmdata.json");

            //return readin json object
            let mut file = File::open("tpmdata.json").unwrap();
            let mut raw_data = String::new();
            file.read_to_string(&mut raw_data).unwrap();
            tpm_data = Json::from_str(&raw_data).unwrap();
            tpm_data
        } else {
            None
        }
    }

    fn write_tpm_data()  -> Result<()>{

        // set umask to 0o077
        unsafe {
            umask(0o077);
        }

        let mut e_uid = 0;
        unsafe {
            e_uid = geteuid();
        }

        // if root is required
        if e_uid != 1000 {

            /*log placeholder*/
            println!("Creating tpm metadata file without root.  Sensitive trust roots may be at risk!");
        }

        // write tpmdata to tpmdata json file

        let file = File::open("tpmdata.json")?;
        serde_json::to_writer(file, global_tpmdata)?;

        Ok()
    }

    fn is_vtpm() {
        match common::STUB_VTPM {
            true => {
                true
            },
            false => {
                let tpm_manufacturer = get_tpm_manufacturer();
                tpm_manufacturer == "ETHZ"
            },
        }
    }

    fn get_tpm_manufacturer() -> Option<bool>{
        let return_output = tpm_exec::run("getcapability -cap 1a");


        let placeholder = "ETHZ";
        Some(placeholder)
    }




    /***************************************************************
    package from tpm_nvram.py

        
    *****************************************************************/


    
    fn write_key_nvram(key: String) {
        let owner_password = tpm_initialize::get_tpm_metadata("owner_password");

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write(owner_password.as_bytes());
        key_file.flush();

        tpm_exec::run("nv_definespace -pwdo {} -in 1 -sz {} -pwdd {} -per 40004", owner_password, common::BOOTSTRAP_KEY_SIZE, owner_password);
        tpm_exec::run("nv_writevalue -pwdd {} -in 1 -if {}", owner_password,key_file.path());
    }



    /***************************************************************
    package from tpm_exec.py

        
    *****************************************************************/

    /*
    create fingerprint for commad
    */
    pub fn fingerprint(cmd: String) -> String {
        let words: Vec<&str> = cmd.split(" ").collect();
        // println!("{:?}", words);

        let mut fprt: String = words[0].to_string();
        // println!("{:?}", fprt);

        match fprt.as_ref() {
            "getcapability" => {
                if cmd.contains("-cap 5") {
                    fprt.push_str("-cap5");
                } else if cmd.contains("-cap la") {
                    fprt.push_str("-capls");
                }
            },

            "nv_readvalue" => {
                if cmd.contains("-in 100f000") {
                    fprt.push_str("-in100f000");
                } else if cmd.contains("-in 1") {
                    fprt.push_str("-in1");
                }
            },

            _ => (),
        };

        fprt
    }



    /*
    split command to command and its argument
    */
    pub fn command_split(cmd: String) -> usize {
        let bytes = cmd.as_bytes();

        for(i, &item) in bytes.iter().enumerate() {
            if item == b' ' {
                return i;
            }
        }

        cmd.len()
    }

    /*
    execute tpm command through shell command
    */
    pub fn run<'a>(cmd: String) -> (Vec<u8>, Option<i32>) {

        /* stubbing  placeholder */

        let words: Vec<&str> = cmd.split(" ").collect();
        // execute the tpm commands
        let mut number_tries = 0;
        // let pivot = command_split(cmd.clone());
        // let command = &cmd[0..pivot];
        // let args = &cmd[pivot..cmd.len()];
        let command = &words[0];
        let args = &words[1..words.len()];

        println!("{:?}", command);
        println!("{:?}", args);

        // execute the command
        let mut output = Command::new(&cmd)
            .args(args)
            .output()
            .expect("failed to execute process");

        loop {
        // let t0 = System::now();


        // assume the system is linux
            
            println!("number tries: {:?}", number_tries);

            match output.status.code().unwrap() {
                TPM_IO_ERROR => {
                    number_tries += 1;
                    if number_tries >= MAX_TRY {
                        println!("TPM appears to be in use by another application.  Keylime is incompatible with other TPM TSS applications like trousers/tpm-tools. Please uninstall or disable.");
                        //log placeholder
                        break;
                    }

                    output = Command::new(&cmd)
                            .args(args)
                            .output()
                            .expect("failed to execute process");

                    // log placeholder

                    thread::sleep(RETRY_SLEEP);
                },
                _ => {},
             } 

        }

        /*metric output placeholder*/

        (output.stdout, output.status.code())
    }

    #[cfg(test)]
    mod tests {

        use super::*;

        #[test]
        fn fingerprint_it_works() {
            assert_eq!(fingerprint("a b c".to_string()), "a");
        }

        #[test]
        fn fingerprint_getcapability_test() {
            assert_eq!(fingerprint("getcapability -cap 5".to_string()), "getcapability-cap5");  
        }

        #[test]
        fn fingerprint_getcapability_test2() {
            assert_eq!(fingerprint("getcapability -n - e -cap 5".to_string()), "getcapability-cap5");   
        }

        #[test]
        fn fingerprint_nv_readvalue_test() {
            assert_eq!(fingerprint("nv_readvalue".to_string()), "nv_readvalue");
        }


        #[test]
        fn command_split_get_command() {
            let cmd = String::from("ls -d /usr/local/bin");
            let s = command_split(cmd.clone());
            assert_eq!(&cmd[0..s], "ls");
        }

        #[test]
        fn command_split_get_args() {
            let cmd = String::from("ls -d /usr/local/bin");
            let s = command_split(cmd.clone());
            // println!("**************{:?}", &cmd[s+1..cmd.len()-1]);
            assert_eq!(&cmd[s..cmd.len()], " -d /usr/local/bin");
        }

        // #[test]
        // fn run_ls_test() {
        //  let cmd = String::from("ls -asl");

        // }
        #[test]
        fn test_is_vtpm() {
            let return_value = is_vtpm();
            assert_eq!(return_value, true);
        }
    }    
}


mod common {
    extern crate futures;
    extern crate hyper;
    extern crate serde_json;

    use hyper::{Response, StatusCode, Body, header};
    use std::collections::HashMap;



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


}