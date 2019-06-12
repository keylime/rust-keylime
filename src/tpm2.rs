extern crate base64;
extern crate flate2;

use super::*;
use crypto::KeylimeCryptoError;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use openssl::sha::Sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
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
use tpm::KeylimeTpmError;

const MAX_TRY: usize = 10;
const RETRY_SLEEP: Duration = Duration::from_millis(50);
const TPM_IO_ERROR: i32 = 5;

// Empty mask only use the first pcr
static EMPTYMASK: &'static str = "1";

#[derive(Debug, Clone)]
struct TPM {
    tpmdata: Value,
    hash_alg: String,
    encrypt_alg: String,
    sign_alg: String,
    legacy_tools: bool,
}

impl TPM {
    pub fn new() -> TPM {
        TPM {
            tpmdata: json!(null),
            hash_alg: String::from("sha256"),
            encrypt_alg: String::from("rsa"),
            sign_alg: String::from("rsassa"),
            legacy_tools: tpm2::command_exist("tpm2_takeownership"),
        }
    }

    fn read_tpmdata(&mut self) -> Result<(), KeylimeTpmError> {
        self.tpmdata = File::open("tpmdata.json")
            .and_then(|f| serde_json::from_reader(f).map_err(|e| e.into()))?;
        Ok(())
    }

    fn write_tpmdata(&mut self) -> Result<(), KeylimeTpmError> {
        let mut f = File::create("tpmdata.json")?;
        let data_string: String =
            serde_json::to_string_pretty(&self.tpmdata)?;
        f.write_all(data_string.as_bytes())?;
        Ok(())
    }

    pub fn update_tpmdata(
        &mut self,
        key: &str,
        value: &str,
    ) -> Result<(), KeylimeTpmError> {
        match self.tpmdata.get_mut(key) {
            Some(ptr) => *ptr = json!(value),
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    format!("Key: {} is missing in tpmdata.json", key)
                        .as_str(),
                ));
            }
        };
        Ok(())
    }

    // empty string means the value is not exist in the tpmdata.
    pub fn get_tpmdata(&self, key: &str) -> String {
        match self.tpmdata[key].as_str() {
            None => String::new(),
            Some(s) => s.to_string(),
        }
    }

    // Initialize TPM and return the TPM informations to caller.
    // Return: (ek, ekcert, aik, ek_tpm, aik_name)
    pub fn init(
        &mut self,
        self_activate: bool,
        config_pw: String,
    ) -> Result<(String, String, String, String, String), KeylimeTpmError>
    {
        self.startup()?;
        self.read_tpmdata()?;
        self.emulator_warning();
        self.set_password(config_pw)?;
        self.create_ek(None)?;
        self.get_pub_ek()?;
        let ekcert = self.read_ekcert_nvram()?;

        self.update_tpmdata("ekcert", &ekcert)?;
        self.create_aik(self_activate)?;

        let ek = self.get_tpmdata("ek");
        let aik = self.get_tpmdata("aik");
        let ek_tpm = self.get_tpmdata("ek_tpm");
        let aik_name = self.get_tpmdata("aik_name");
        Ok((ek, ekcert.into(), aik, ek_tpm, aik_name))
    }

    fn emulator_warning(&self) {
        if self.is_software_tpm() {
            warn!("{} {} {} {}",
               "INSECURE: Keylime is using a software TPM emulator rather than",
               "a real hardware TPM.\nINSECURE: The security of Keylime is NOT",
               "linked to a hardware root of trust.\nINSECURE: Only use",
               "keylime in this mode for testing or debugging purposes."
           );
        }
    }

    fn set_password(
        &mut self,
        config_pw: String,
    ) -> Result<(), KeylimeTpmError> {
        let owner_pw = match config_pw.as_str() {
            "generate" => self.random_password(20)?,
            _ => config_pw,
        };

        if let Err(e) = match self.legacy_tools {
            true => {
                self.run("tpm2_takeownership -c".into(), None)?;
                self.run(
                    format!(
                        "tpm2_takeownership -o {} -e {}",
                        owner_pw, owner_pw
                    ),
                    None,
                )
            }
            false => self.run(
                format!("tpm2_changeauth -o {} -e {}", owner_pw, owner_pw),
                None,
            ),
        } {
            let cmd = match self.legacy_tools {
                true => format!(
                    "tpm2_takeownership -o {} -e {} -O {} -E {}",
                    owner_pw, owner_pw, owner_pw, owner_pw
                ),
                false => format!(
                    "tpm2_changeauth -o {} -e {} -O {} -E {}",
                    owner_pw, owner_pw, owner_pw, owner_pw
                ),
            };

            self.run(cmd, None)?;
        }

        self.update_tpmdata("owner_pw", &owner_pw)?;
        Ok(())
    }

    fn create_ek(
        &mut self,
        asym_alg_in: Option<&str>,
    ) -> Result<(), KeylimeTpmError> {
        let asym_alg = match asym_alg_in {
            None => self.encrypt_alg.clone(),
            Some(a) => a.to_string(),
        };

        let curr_handle = self.get_tpmdata("ek_handle");
        let mut owner_pw = self.get_tpmdata("owner_pw");

        if !curr_handle.is_empty() && !owner_pw.is_empty() {
            self.run(String::from("tpm_getcap -c handles-persistent"), None)
                .and_then(|(ret_out, _)| {
                    if ret_out.contains(&curr_handle) {
                        let cmd = match self.legacy_tools {
                            true => format!(
                                "tpm2_evictcontrol -A o -c {} -P {}",
                                hex::encode(curr_handle),
                                owner_pw,
                            ),
                            false => format!(
                                "tpm2_evictcontrol -a o -c {} -P {}",
                                hex::encode(curr_handle),
                                owner_pw,
                            ),
                        };

                        self.run(cmd, None)?;
                        self.update_tpmdata("ek_handle", "")?;
                        self.update_tpmdata("ek_pw", "")?;
                    }
                    Ok(())
                })?;
        }

        if owner_pw.is_empty() {
            owner_pw = self.random_password(20)?;
            self.update_tpmdata("owner_pw", &owner_pw)?;
        }

        let ek_pw = self.random_password(20)?;
        let tf = NamedTempFile::new()?;
        let tf_path = self.temp_file_get_path(&tf)?;

        let cmd = match self.legacy_tools {
            true => format!(
                "tpm2_getpubek -H 0x81010007 -g {} -f {} -P {} -o {} -e {}",
                asym_alg, tf_path, ek_pw, owner_pw, owner_pw
            ),
            false => format!(
                "tpm2_createek -c - -G {} -p {} -P {} -o {} -e {}",
                asym_alg, tf_path, ek_pw, owner_pw, owner_pw
            ),
        };

        self.run(
            cmd,
            Some(vec![tf_path]),
        )
        .and_then(|(ret_out, ret_f)| {
            match self.legacy_tools {
                true => self.update_tpmdata("ek_handle", "0x81010007")?,
                false => {
                    let ret_out_map: Value = serde_yaml::from_str(&ret_out)?;
                    match ret_out_map["persistent-handle"].as_str(){
                        None => self.update_tpmdata("ek_handle", "")?,
                        Some(handle) => {
                            self.update_tpmdata("ek_handle", &handle)?
                        }
                    }
                },
            }

            ret_f.get(tf_path).map_or_else(
                || {
                    Err(KeylimeTpmError::new_tpm_rust_error(
                        "tpm2_readpublic fail, ek key is missing is output file.",
                    ))
                },
                |ek_tpm| {
                    self.update_tpmdata("ek_tpm", &base64::encode(&ek_tpm))
                },
            )?;
            self.update_tpmdata("ek_pw", &ek_pw)?;
            self.write_tpmdata()
        })?;
        Ok(())
    }

    fn get_pub_ek(&mut self) -> Result<(), KeylimeTpmError> {
        let tf = NamedTempFile::new()?;
        let tf_path = self.temp_file_get_path(&tf)?;

        let cmd = match self.legacy_tools {
            true => format!(
                "tpm2_readpublic -H {} -o {} -f pem",
                hex::encode(self.get_tpmdata("ek_handle")),
                tf_path
            ),
            false => format!(
                "tpm2_readpublic -c {} -o {} -f pem",
                hex::encode(self.get_tpmdata("ek_handle")),
                tf_path
            ),
        };

        self.run(cmd, Some(vec![tf_path])).and_then(|(_, ret_f)| {
            ret_f.get(tf_path).map_or_else(
                || {
                    Err(KeylimeTpmError::new_tpm_rust_error(
                        "Error: failed to get public ek key.",
                    ))
                },
                |ek| self.update_tpmdata("ek", ek),
            )
        })?;
        Ok(())
    }

    fn get_pub_aik(&mut self) -> Result<(), KeylimeTpmError> {
        if let false = self.legacy_tools {
            return Err(KeylimeTpmError::new_tpm_rust_error(
                "get public aik doesn't apply to modern tpm2-tools",
            ));
        }

        let tf = NamedTempFile::new()?;
        let tf_path = self.temp_file_get_path(&tf)?;

        self.run(
            format!(
                "tpm2_readpublic -H {} -o {} -f pem ",
                hex::encode(self.get_tpmdata("aik_handle")),
                tf_path
            ),
            None,
        )
        .and_then(|(_, file_ret)| {
            if file_ret.is_empty() {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    "unable to read public aik",
                ));
            }
            self.update_tpmdata(
                "aik",
                file_ret.get(tf_path).ok_or_else(|| {
                    KeylimeTpmError::new_tpm_rust_error(
                        "Error: get public aik key failed.",
                    )
                })?,
            )
        })?;
        Ok(())
    }

    pub fn get_tpm_version(&self) -> i32 {
        2
    }

    fn create_aik(&mut self, activate: bool) -> Result<(), KeylimeTpmError> {
        let owner_pw = self.get_tpmdata("owner_pw");
        let aik = self.get_tpmdata("aik");
        let aik_name = self.get_tpmdata("aik_name");

        if !aik.is_empty() && !aik_name.is_empty() {
            let aik_handle = self.get_tpmdata("aik_handle");
            let ret_out_map: Value = self
                .run("tpm2_getcap -c handles-persistent".to_string(), None)
                .and_then(|(ret_out, _)| {
                    serde_yaml::from_str(&ret_out).map_err(|e| e.into())
                })?;

            if ret_out_map[&aik_handle].is_null() {
                let cmd = match self.legacy_tools {
                    true => format!(
                        "tpm2_evictcontrol -A o -c {} -P {}",
                        hex::encode(aik_handle),
                        owner_pw
                    ),
                    false => format!(
                        "tpm2_evictcontrol -a o -c {} -P {}",
                        hex::encode(aik_handle),
                        owner_pw
                    ),
                };

                self.run(cmd, None)?;
                self.update_tpmdata("aik", "")?;
                self.update_tpmdata("aik_name", "")?;
                self.update_tpmdata("aik_pw", "")?;
                self.update_tpmdata("aik_handle", "")?;
            }
        }

        let ek_handle = self.get_tpmdata("ek_handle");
        if ek_handle.is_empty() {
            return Err(KeylimeTpmError::new_tpm_rust_error("EK is emtpy."));
        }

        let aik_pw = self.random_password(20)?;
        let tf = NamedTempFile::new()?;
        let tf_path = self.temp_file_get_path(&tf)?;

        let cmd = match self.legacy_tools {
            true => format!(
                "{} -E {} -k {} -g {} -D {} -s {} -f {} -e {} -P {} -o {}", 
                "tpm2_getpubak",
                "0x81010008",
                ek_handle,
                self.encrypt_alg,
                self.hash_alg,
                self.sign_alg,
                tf_path,
                owner_pw,
                aik_pw,
                owner_pw
            ),
            false => format!(
                "{} -C {} -k - -G {} -D {} -s {} -p {} -f pem -e {} -P {} -o {}", 
                "tpm2_createak",
                ek_handle,
                self.encrypt_alg,
                self.hash_alg,
                self.sign_alg,
                tf_path,
                owner_pw,
                aik_pw,
                owner_pw
            ),
        };

        let ret_out_map: Value = self
            .run(cmd, None)
            .and_then(|(ret_out, _)| Ok(serde_yaml::from_str(&ret_out)?))?;

        match ret_out_map["load-key"]["namne"].as_str() {
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    "Error: akname is missing in return output",
                ))
            }
            Some(s) => self.update_tpmdata("aik_name", s)?,
        }

        match self.legacy_tools {
            true => {
                self.update_tpmdata(
                    "aik_handle",
                    std::str::from_utf8(&hex::decode("81010008")?)?,
                )?;
                self.get_pub_aik()?;
            }
            false => {
                match ret_out_map["ak-persistent-handle"].as_str() {
                    None => {
                        return Err(KeylimeTpmError::new_tpm_rust_error(
                            "ak-persistent-handle is missing",
                        ))
                    }
                    Some(ak_handle) => {
                        self.update_tpmdata("aik_handle", ak_handle)?
                    }
                }

                let aik_pw: String = self.read_file_output_path(tf_path)?;
                self.update_tpmdata("aik_pw", &aik_pw)?;
            }
        }

        self.update_tpmdata("aik_pw", &aik_pw)?;
        Ok(())
    }

    // NVRAM io functions
    fn read_ekcert_nvram(&self) -> Result<String, KeylimeTpmError> {
        let tf = NamedTempFile::new()?;
        let nvpath = self.temp_file_get_path(&tf)?;
        let (ret_out, _): (String, HashMap<String, String>) =
            self.run("tpm2_nvlist".to_string(), None)?;
        let ret_out_value: Value = serde_yaml::from_str(&ret_out)?;
        match ret_out_value["0x1c00002"]["size"].as_str() {
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    "No EK certificate found in TPM NVRAM",
                ))
            }
            Some(s) => {
                let (_, f_out) = self.run(
                    format!(
                        "tpm2_nvread -x 0x1c00002 -s {} -f {}",
                        s, nvpath
                    ),
                    Some(vec![nvpath]),
                )?;
                let ekcert = f_out.get(nvpath).ok_or_else(|| {
                    KeylimeTpmError::new_tpm_rust_error(
                        "failed to read nvram and retrieve ekcert.",
                    )
                })?;
                Ok(base64::encode(ekcert))
            }
        }
    }

    fn read_key_nvram(&mut self) -> Result<String, KeylimeTpmError> {
        self.run(
            format!(
                "tpm2_nvread -x 0x1500018 -a 0x40000001 -s {} -P {})",
                common::BOOTSTRAP_KEY_SIZE,
                self.get_tpmdata("owner_pw")
            ),
            None,
        )
        .and_then(|(ret_out, _)| match ret_out.len() {
            common::BOOTSTRAP_KEY_SIZE => Ok(ret_out),
            _ => Err(KeylimeTpmError::new_tpm_rust_error(
                "Invalid key length from NVRAM.",
            )),
        })
    }

    fn write_key_nvram(
        &mut self,
        key: String,
    ) -> Result<(), KeylimeTpmError> {
        let owner_pw = self.get_tpmdata("owner_pw");
        let mut tf = NamedTempFile::new()?;
        tf.write_all(key.as_bytes())?;
        let nvpath = self.temp_file_get_path(&tf)?;
        let cmd = match self.legacy_tools {
            true => format!(
                "tpm2_nvdefine -x 0x1500018 -a 0x40000001 -s {} -t \"{}\" -I {} -P {}",
                common::BOOTSTRAP_KEY_SIZE,
                "ownerread|policywrite|ownerwrite",
                owner_pw,
                owner_pw
            ),
            false => format!(
                "tpm2_nvdefine -x 0x1500018 -a 0x40000001 -s {} -t \"{}\" -p {} -P {}",
                common::BOOTSTRAP_KEY_SIZE,
                "ownerread|policywrite|ownerwrite",
                owner_pw,
                owner_pw
            ),
        };

        self.run(cmd, None)?;
        self.run(
            format!(
                "tpm2_nvwrite -x 0x1500018 -a 0x40000001 -P {} {}",
                owner_pw, nvpath
            ),
            None,
        )?;
        Ok(())
    }

    // TPM quote functions
    fn create_quote(
        &mut self,
        nonce: String,
        data: String,
        mut pcrmask: String,
    ) -> Result<String, KeylimeTpmError> {
        let quote_tf = NamedTempFile::new()?;
        let sign_tf = NamedTempFile::new()?;
        let pcr_tf = NamedTempFile::new()?;

        if pcrmask.is_empty() {
            pcrmask = EMPTYMASK.to_string();
        }

        if !data.is_empty() {
            self.run(
                format!("tpm2_pcrreset {}", common::TPM_DATA_PCR),
                None,
            )?;
            self.extend_pcr(common::TPM_DATA_PCR, data)?;
        }

        let quote_path = self.temp_file_get_path(&quote_tf)?;
        let sign_path = self.temp_file_get_path(&sign_tf)?;
        let pcr_path = self.temp_file_get_path(&pcr_tf)?;

        let cmd = match self.legacy_tools {
            true => format!(
                "tpm2_quote -k {} -L {}:{} -q {} -m {} -s {} -p {} -G {} -P {}",
                hex::encode(self.get_tpmdata("aik_handle")),
                self.hash_alg,
                self.pcr_mask_to_list(pcrmask, self.hash_alg.to_string())?,
                hex::encode(nonce),
                quote_path,
                sign_path,
                pcr_path,
                self.hash_alg,
                self.get_tpmdata("aik_pw"),
            ),
            false => format!(
                "tpm2_deluxequote -C {} -L {}:{} -q {} -m {} -s {} -p {} -G {} -P {}",
                hex::encode(self.get_tpmdata("aik_handle")),
                self.hash_alg,
                self.pcr_mask_to_list(pcrmask, self.hash_alg.to_string())?,
                hex::encode(nonce),
                quote_path,
                sign_path,
                pcr_path,
                self.hash_alg,
                self.get_tpmdata("aik_pw")
            ),
        };

        self.run(cmd, Some(vec![quote_path, sign_path, pcr_path]))
            .and_then(|(_, quotes)| {
                let mut quote_list = Vec::new();
                for val in quotes.values() {
                    quote_list
                        .push(self.base64_zlib_encode(val.to_string())?);
                }
                Ok(quote_list.as_slice().join(":"))
            })
    }

    pub fn create_deep_quote(
        &self,
        nonce: String,
        data: String,
        pcrmask: String,
        vpcrmask: String,
    ) -> Result<String, KeylimeTpmError> {
        Err(KeylimeTpmError::new_tpm_rust_error(
            "Deep quote in progress.",
        ))
    }

    fn flush_keys(&mut self) -> Result<(), KeylimeTpmError> {
        let (ret_out, _) =
            self.run("tpm2_getcap -c handles-persistent".into(), None)?;
        let owner_pw = self.get_tpmdata("owner_pw");
        let ret_out_val: Value = serde_yaml::from_str(&ret_out)?;
        let ret_out_map: &Map<String, Value> =
            ret_out_val.as_object().ok_or_else(|| {
                KeylimeTpmError::new_tpm_rust_error("Output invalid.")
            })?;
        ret_out_map.iter().for_each(|(k, _)| {
            if let Err(e) = self.run(
                format!(
                    "tpm2_evictcontrol -a o -c {} -P {}",
                    hex::encode(k),
                    owner_pw
                ),
                None,
            ) {
                error!("{}", e.description());
            }
        });
        Ok(())
    }

    // PCR Operation
    fn extend_pcr(
        &self,
        pcrval: usize,
        data: String,
    ) -> Result<(), KeylimeTpmError> {
        let mut hash = Sha256::new();
        hash.update(data.as_bytes());
        self.run(
            format!(
                "tpm2_pcrextend {}:{}={}",
                pcrval,
                self.hash_alg,
                String::from_utf8(hash.finish().to_vec())?
            ),
            None,
        )?;
        Ok(())
    }

    pub fn read_pcr(
        &self,
        pcrval: String,
        hash_alg: Option<String>,
    ) -> Result<String, KeylimeTpmError> {
        let hash_alg_str = hash_alg.unwrap_or_else(|| String::from("sha256"));
        let (ret_out, _) = self.run(String::from("tpm2_pcrlist"), None)?;
        let ret_out_map: Value = serde_yaml::from_str(&ret_out)?;
        let alg_size: usize = match hash_alg_str.as_str() {
            "sha1" => 160,
            "sha256" => 256,
            "sha384" => 384,
            "sha512" => 512,
            _ => 0,
        };

        let value_num: i64 =
            ret_out_map[hash_alg_str][pcrval].as_i64().ok_or_else(|| {
                KeylimeTpmError::new_tpm_rust_error("Invalid pcr valur.")
            })?;
        let pcr_res = format!("{:0width$X}", value_num, width = alg_size / 4);
        Ok(pcr_res)
    }

    pub fn activate_identity(
        &mut self,
        keyblob: String,
    ) -> Result<String, KeylimeTpmError> {
        let mut keyblobfile = NamedTempFile::new()?;
        keyblobfile.write_all(keyblob.as_bytes())?;
        let keyblobfile_path = self.temp_file_get_path(&keyblobfile)?;

        let tf_sec = NamedTempFile::new_in(secure_mount::mount()?)?;
        let tf_sec_path = self.temp_file_get_path(&tf_sec)?;

        let cmd = match self.legacy_tools {
            true => format!(
                "tpm2_activatecredential -H {} -k {} -f {} -o {} -P {} -e {}",
                hex::encode(self.get_tpmdata("aik_handle")),
                hex::encode(self.get_tpmdata("ek_handle")),
                keyblobfile_path,
                tf_sec_path,
                self.get_tpmdata("aik_pw"),
                self.get_tpmdata("owner_pw"),
            ),
            false => format!(
                "tpm2_activatecredential -c {} -C {} -f {} -o {} -P {} -E {}",
                hex::encode(self.get_tpmdata("aik_handle")),
                hex::encode(self.get_tpmdata("ek_handle")),
                keyblobfile_path,
                tf_sec_path,
                self.get_tpmdata("aik_pw"),
                self.get_tpmdata("owner_pw"),
            ),
        };

        self.run(cmd, Some(vec![tf_sec_path]))
            .and_then(|(_, f_out)| match f_out.get(tf_sec_path) {
                None => Err(KeylimeTpmError::new_tpm_rust_error(
                    "Error: invalid file output.",
                )),
                Some(content) => Ok(base64::encode(content)),
            })
    }

    fn run(
        &self,
        command: String,
        output_path: Option<Vec<&str>>,
    ) -> Result<(String, HashMap<String, String>), KeylimeTpmError> {
        let words: Vec<&str> = command.split(" ").collect();
        let mut number_tries = 0;
        let args = &words[1..words.len()];
        let cmd = &words[0];
        let mut env_vars: HashMap<String, String> = HashMap::new();
        for (key, value) in env::vars() {
            env_vars.insert(key.to_string(), value.to_string());
        }
        let lib_path = env_vars
            .get("LD_LIBRARY_PATH")
            .map_or_else(|| String::new(), |v| v.clone());
        env_vars.insert(
            "LD_LIBRARY_PATH".to_string(),
            format!("{}:{}", lib_path, common::TPM_LIBS_PATH),
        );
        env_vars.insert(
            "TPM2TOOLS_TCTI".to_string(),
            "tabrmd:bus_name=com.intel.tss2.Tabrmd".to_string(),
        );
        match env_vars.get_mut("PATH") {
            Some(v) => v.push_str(common::TPM_TOOLS_PATH),
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    "PATH envrionment variable dosen't exist.",
                ));
            }
        }
        let mut output: Output;
        'exec: loop {
            let t0 = SystemTime::now();

            output =
                Command::new(&cmd).args(args).envs(&env_vars).output()?;

            let t_diff = t0.duration_since(t0)?;
            info!("Time cost: {}", t_diff.as_secs());
            match output.status.code() {
                Some(TPM_IO_ERROR) => {
                    number_tries += 1;
                    if number_tries >= MAX_TRY {
                        return Err(KeylimeTpmError::new_tpm_error(
                            TPM_IO_ERROR,
                            format!(
                                "{}{}{}{}",
                                "TPM appears to be in use by another ",
                                "application. Keylime is incompatible with ",
                                "with other TPM TSS application like trousers/",
                                "tpm-tools. Please uninstall or disable.",
                            )
                            .as_str(),
                        ));
                    }

                    info!(
                        "Failed to call TPM {}/{} times, trying again in {}s.",
                        number_tries, MAX_TRY, RETRY_SLEEP.as_secs(),
                    );

                    thread::sleep(RETRY_SLEEP);
                }

                _ => break 'exec,
            }
        }

        let return_output = String::from_utf8(output.stdout)?;
        match output.status.code() {
            None => {
                return Err(KeylimeTpmError::new_tpm_rust_error(
                    "Execution return code is None.",
                ));
            }
            Some(0) => info!("Successfully executed TPM command."),
            Some(c) => {
                return Err(KeylimeTpmError::new_tpm_error(
                    c,
                    format!(
                        "Command: {} returned {}, output {}",
                        command, c, return_output,
                    )
                    .as_str(),
                ));
            }
        }

        let mut file_output: HashMap<String, String> = HashMap::new();
        if let Some(paths) = output_path {
            for p in paths {
                file_output.insert(p.into(), self.read_file_output_path(p)?);
            }
        }
        Ok((return_output, file_output))
    }

    fn pcr_mask_to_list(
        &self,
        mask: String,
        hash_alg: String,
    ) -> Result<String, KeylimeTpmError> {
        let mut pcr_list = Vec::new();
        let mut ima_appended = String::new();

        for pcr in 0..24 {
            let check_result = self.check_mask(&mask, pcr)?;
            if check_result {
                if hash_alg == "SHA1" && pcr == 10 {
                    ima_appended.push_str(format!("+sha1:{}", pcr).as_str());
                } else {
                    pcr_list.push(pcr.to_string());
                }
            }
        }
        let mut result: String = pcr_list.as_slice().join(",");
        result.push_str(&ima_appended);
        Ok(result)
    }

    fn check_mask(
        &self,
        ima_mask: &str,
        ima_pcr: i32,
    ) -> Result<bool, KeylimeTpmError> {
        if ima_mask.is_empty() {
            return Ok(false);
        }
        let ima_mask_int: i32 = ima_mask.parse()?;
        Ok((1 << ima_pcr) & ima_mask_int != 0)
    }

    fn temp_file_get_path<'a>(
        &self,
        ref temp_file: &'a NamedTempFile,
    ) -> Result<&'a str, KeylimeTpmError> {
        temp_file.path().to_str().ok_or_else(|| {
            KeylimeTpmError::new_tpm_rust_error(
                "Can't retrieve temp file path.",
            )
        })
    }

    fn tpm_get_manufacturer(&self) -> Result<String, KeylimeTpmError> {
        self.run("tpm2_getcap -c properties-fixed".to_string(), None)
            .and_then(|(ret_out, _)| {
                serde_json::from_str(&ret_out)
                    .map_err(|e| e.into())
                    .and_then(|ret_out_map: Value| {
                        match ret_out_map["TPM_PT_VENDOR_STRING_1"]["value"]
                            .as_str()
                        {
                            None => Err(KeylimeTpmError::new_tpm_rust_error(
                                "Error: manufacturer not found.",
                            )),
                            Some(content) => Ok(content.to_string()),
                        }
                    })
            })
    }

    fn is_software_tpm(&self) -> bool {
        match self.tpm_get_manufacturer() {
            Ok(data) => data == "SW",
            Err(_) => false,
        }
    }

    fn is_vtpm(&self) -> bool {
        return false;
    }

    fn is_deep_quote(&self, quote: String) -> bool {
        match &quote[0..1] {
            "d" => true,
            "r" => false,
            _ => {
                warn!("Invalid quote type {}.", quote);
                false
            }
        }
    }

    fn random_password(
        &self,
        length: usize,
    ) -> Result<String, KeylimeTpmError> {
        let rand_byte = crypto::generate_random_bytes(&length)?;
        let alphabet: Vec<char> =
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                .chars()
                .collect();

        let mut password = Vec::new();
        for i in rand_byte.as_slice() {
            password.push(alphabet[*i as usize % alphabet.len()]);
        }
        let password_str: String = password.iter().collect();
        Ok(password_str)
    }

    fn read_file_output_path(
        &self,
        output_path: &str,
    ) -> std::io::Result<String> {
        let mut file = File::open(output_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }

    fn startup(&self) -> Result<(), KeylimeTpmError> {
        self.run("tpm2_startup -c".to_string(), None).map(|x| ())
    }

    fn base64_zlib_encode(
        &self,
        data: String,
    ) -> Result<String, KeylimeTpmError> {
        let mut encoder =
            ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data.as_bytes())?;
        let compressed_bytes = encoder.finish()?;
        Ok(base64::encode(&compressed_bytes))
    }
}

pub fn command_exist(command: &str) -> bool {
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
