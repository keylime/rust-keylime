use super::*;
use std::process::Command;
use std::thread;
use std::time::Duration;

const MAX_TRY: usize = 10;
const RETRY_SLEEP: Duration = Duration::from_millis(50);
const TPM_IO_ERROR: i32 = 5;

// static mut global_tpmdata = None;

/***************************************************************
package from tpm_initialize.py        
*****************************************************************/
/*
input: a string value
return: deserlized json object

>>>>> currently not used <<<<<
*/
/*fn get_tpm_metadata(key: String) -> String {
    match global_tpmdata {
        Some("") => {
            global_tpmdata = read_tpm_data()
        },
        _ => {},
    }
    global_tpmdata.find("key")
}*/

/*
input: none
return: tpmdata in json object

>>>>> currently not used <<<<<
*/
/*fn read_tpm_data() -> Result<Json> {
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
}*/

/*
input: noen
return: write result

write tpmdata to tpmdata.json file to store the value

>>>>> currently not used <<<<<
*/
/*fn write_tpm_data()  -> Result<()>{

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

        // log placeholder
        println!("Creating tpm metadata file without root.  Sensitive trust roots may be at risk!");
    }

    // write tpmdata to tpmdata json file

    let file = File::open("tpmdata.json")?;
    serde_json::to_writer(file, global_tpmdata)?;

    Ok()
}*/

pub fn is_vtpm() -> Option<bool> {
    match common::STUB_VTPM {
        true => Some(true),
        false => {
            let tpm_manufacturer = get_tpm_manufacturer();

            // ******* //
            println!("tpm manufacturer: {:?}", tpm_manufacturer);
            Some(tpm_manufacturer.unwrap() == "ETHZ")
        }
    }
}

pub fn get_tpm_manufacturer<'a>() -> Option<&'a str> {
    // let return_output = run("getcapability -cap 1a".to_string());

    let placeholder = "ETHZ";
    Some(placeholder)
}

/***************************************************************
package from tpm_nvram.py    
*****************************************************************/

/*
>>>>> currently not used <<<<<
*/
/*fn write_key_nvram(key: String) {
    let owner_password = tpm_initialize::get_tpm_metadata("owner_password");

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write(owner_password.as_bytes());
    key_file.flush();

    tpm_exec::run("nv_definespace -pwdo {} -in 1 -sz {} -pwdd {} -per 40004", owner_password, common::BOOTSTRAP_KEY_SIZE, owner_password);
    tpm_exec::run("nv_writevalue -pwdd {} -in 1 -if {}", owner_password,key_file.path());
}*/

/***************************************************************
package from tpm_exec.py  
*****************************************************************/

/*
create fingerprint for commad

input: String::String
return the fingerprint of the command

>>>>> currently not used <<<<<
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
        }

        "nv_readvalue" => {
            if cmd.contains("-in 100f000") {
                fprt.push_str("-in100f000");
            } else if cmd.contains("-in 1") {
                fprt.push_str("-in1");
            }
        }

        _ => {}
    };

    fprt
}

/*
split command to command and its argument

input: String::String
return: the index of the first space, usize

find the the first command and return the index to seperate the string 

>>>>> currently not used <<<<<
*/
pub fn command_split(cmd: String) -> usize {
    let bytes = cmd.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
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
            }

            _ => {}
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
        assert_eq!(
            fingerprint("getcapability -cap 5".to_string()),
            "getcapability-cap5"
        );
    }

    #[test]
    fn fingerprint_getcapability_test2() {
        assert_eq!(
            fingerprint("getcapability -n - e -cap 5".to_string()),
            "getcapability-cap5"
        );
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

    #[test]
    fn test_is_vtpm() {
        let return_value = is_vtpm();
        assert_eq!(return_value.unwrap(), true);
    }
}
