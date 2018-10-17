

// temp global variable 
static mut global_tpmdata: String = String::from("");

/*
input: a string value
return: deserlized json object
*/
fn get_tpm_metadata(key: String) {
	match global_tpmdata {
		Some("") => {
			global_tpmdata = read_tpm_data()
		},
		_ => {},
	}

	// 
	// return global_tpmdata;
}

fn read_tpm_data() {

}