use std::process::Command;
use std::process::Output;
use std::{thread, time};
use std::time::Duration;

const MAX_TRY: usize = 10;
const RETRY_SLEEP: Duration = time::Duration::from_millis(50);
const TPM_IO_ERROR: i32 = 5;

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
	// 	let cmd = String::from("ls -asl");

	// }
}
