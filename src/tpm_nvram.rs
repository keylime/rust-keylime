use std::fs:File;
use tempfile::tempfile;

mod tpm_initialize;
mod tpm_exec;


fn write_key_nvram(key: String) {
	let owner_password = tpm_initialize::get_tpm_metadata("owner_password");

	let mut key_file = NamedTempFile::new().unwrap();
	key_file.write(owner_password.as_bytes());
	key_file.flush();

	tpm_exec::run("nv_definespace -pwdo {} -in 1 -sz {} -pwdd {} -per 40004", owner_password, common::BOOTSTRAP_KEY_SIZE, owner_password);
	tpm_exec::run("nv_writevalue -pwdd {} -in 1 -if {}", owner_password,key_file.path());
}