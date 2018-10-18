extern crate lib;
extern crate rustc_serialize;
extern crate serde_json;

mod common;

use rustc_serialize::json::Json;
use std::fs::File;
use std::io::Read;
use libc::{umask, geteuid};
use std::path::Path;

// temp global variable 
static mut global_tpmdata: Json;

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

fn get_tpm_manufacturer() {
	let return_output = tpm_exec::run("getcapability -cap 1a");


	let placeholder = "ETHZ"
	placeholder
}


#[cfg(test)]
mod tests{
	use super::*;

	#[test]
	fn test_is_vtpm() {
		let return_value = is_vtpm();
		assert_eq!(return_value, true);
	}
}
