use core::fmt;
// Use LazyCell for lazy initialization of count file paths
use once_cell::sync::Lazy;

pub const DEFAULT_API_VERSIONS: &[&str] = &["3.0"];
pub const DEFAULT_CERTIFICATION_KEYS_SERVER_IDENTIFIER: &str = "ak";
pub const DEFAULT_CONTACT_IP: &str = "127.0.0.1";
pub const DEFAULT_CONTACT_PORT: u32 = 9002;
pub const DEFAULT_IMA_ML_DIRECTORY_PATH: &str = "/sys/kernel/security/ima";
pub static DEFAULT_IMA_ML_COUNT_FILE: Lazy<String> =
    Lazy::new(|| format!("{}/measurements", DEFAULT_IMA_ML_DIRECTORY_PATH));
pub const DEFAULT_MEASUREDBOOT_ML_DIRECTORY_PATH: &str =
    "/sys/kernel/security/tpm0";
pub static DEFAULT_MEASUREDBOOT_ML_COUNT_FILE: Lazy<String> =
    Lazy::new(|| format!("{}/count", DEFAULT_MEASUREDBOOT_ML_DIRECTORY_PATH));
pub const DEFAULT_EK_HANDLE: &str = "";
pub const DEFAULT_ENABLE_IAK_IDEVID: bool = false;
pub const DEFAULT_IP: &str = "127.0.0.1";
pub const DEFAULT_PORT: u32 = 9002;
pub const DEFAULT_REGISTRAR_API_VERSIONS: &[&str] = &["2.3"];
pub const DEFAULT_REGISTRAR_IP: &str = "127.0.0.1";
pub const DEFAULT_REGISTRAR_PORT: u32 = 8890;
pub const DEFAULT_SERVER_CERT: &str = "server-cert.crt";
pub const DEFAULT_SERVER_KEY: &str = "server-private.pem";
pub const DEFAULT_SERVER_KEY_PASSWORD: &str = "";
pub const DEFAULT_TPM_HASH_ALG: &str = "sha256";
pub const DEFAULT_TPM_ENCRYPTION_ALG: &str = "rsa";
pub const DEFAULT_TPM_SIGNING_ALG: &str = "rsassa";
pub const DEFAULT_UUID: &str = "b0acd25f-2205-4c37-932d-e8f99a8d39ef";

// IMA logs specific defaults
pub const DEFAULT_IMA_LOGS_APPENDABLE: bool = true;
pub const DEFAULT_IMA_LOGS_FORMATS: &[&str] = &["text/plain"];
pub const DEFAULT_IMA_LOGS_SUPPORTS_PARTIAL_ACCESS: bool = true;

//UEFI logs specific defaults
pub const DEFAULT_UEFI_LOGS_APPENDABLE: bool = true;
pub const DEFAULT_UEFI_LOGS_EVIDENCE_VERSION: &str = "2.1";
pub const DEFAULT_UEFI_LOGS_FORMATS: &[&str] = &["application/octet-stream"];
pub const DEFAULT_UEFI_LOGS_SUPPORTS_PARTIAL_ACCESS: bool = true;

pub trait PushModelConfigTrait {
    fn get_certification_keys_server_identifier(&self) -> String;
    fn get_contact_ip(&self) -> String;
    fn get_contact_port(&self) -> u32;
    fn get_enable_iak_idevid(&self) -> bool;
    fn get_ek_handle(&self) -> String;
    fn get_measuredboot_ml_directory_path(&self) -> String;
    fn get_measuredboot_ml_count_file(&self) -> String;
    fn get_ima_logs_appendable(&self) -> bool;
    fn get_ima_logs_formats(&self) -> Vec<String>;
    fn get_ima_logs_supports_partial_access(&self) -> bool;
    fn get_ima_ml_directory_path(&self) -> String;
    fn get_ima_ml_count_file(&self) -> String;
    fn get_registrar_ip(&self) -> String;
    fn get_registrar_port(&self) -> u32;
    fn get_server_cert(&self) -> String;
    fn get_server_key(&self) -> String;
    fn get_server_key_password(&self) -> String;
    fn get_tpm_encryption_alg(&self) -> String;
    fn get_tpm_hash_alg(&self) -> String;
    fn get_tpm_signing_alg(&self) -> String;
    fn get_registrar_api_versions(&self) -> Vec<String>;
    fn get_api_versions(&self) -> Vec<String>;
    fn get_uefi_logs_appendable(&self) -> bool;
    fn get_uefi_logs_evidence_version(&self) -> String;
    fn get_uefi_logs_formats(&self) -> Vec<String>;
    fn get_uefi_logs_supports_partial_access(&self) -> bool;
    fn get_uuid(&self) -> String;
    fn display(&self) -> String;
}

impl Default for PushModelConfig {
    fn default() -> Self {
        PushModelConfig::new()
    }
}

pub struct PushModelConfig {
    api_versions: Vec<String>,
    certification_keys_server_identifier: String,
    contact_ip: String,
    contact_port: u32,
    enable_iak_idevid: bool,
    ek_handle: String,
    ima_logs_appendable: bool,
    ima_logs_formats: Vec<String>,
    ima_logs_supports_partial_access: bool,
    ima_ml_directory_path: String,
    ima_ml_count_file: String,
    measuredboot_ml_directory_path: String,
    measuredboot_ml_count_file: String,
    registrar_api_versions: Vec<String>,
    registrar_ip: String,
    registrar_port: u32,
    server_cert: String,
    server_key: String,
    server_key_password: String,
    tpm_encryption_alg: String,
    tpm_hash_alg: String,
    tpm_signing_alg: String,
    uefi_logs_evidence_version: String,
    uefi_logs_supports_partial_access: bool,
    uefi_logs_appendable: bool,
    uefi_logs_formats: Vec<String>,
    uuid: String,
}

impl PushModelConfig {
    pub fn new() -> Self {
        PushModelConfig {
            certification_keys_server_identifier:
                DEFAULT_CERTIFICATION_KEYS_SERVER_IDENTIFIER.to_string(),
            contact_ip: DEFAULT_CONTACT_IP.to_string(),
            contact_port: DEFAULT_CONTACT_PORT,
            ek_handle: DEFAULT_EK_HANDLE.to_string(),
            enable_iak_idevid: DEFAULT_ENABLE_IAK_IDEVID,
            ima_logs_appendable: DEFAULT_IMA_LOGS_APPENDABLE,
            ima_logs_formats: DEFAULT_IMA_LOGS_FORMATS
                .iter()
                .map(|&s| s.to_string())
                .collect(),
            ima_logs_supports_partial_access:
                DEFAULT_IMA_LOGS_SUPPORTS_PARTIAL_ACCESS,
            ima_ml_directory_path: DEFAULT_IMA_ML_DIRECTORY_PATH
                .to_string()
                .clone(),
            ima_ml_count_file: DEFAULT_IMA_ML_COUNT_FILE.to_string().clone(),
            measuredboot_ml_directory_path:
                DEFAULT_MEASUREDBOOT_ML_DIRECTORY_PATH.to_string().clone(),
            measuredboot_ml_count_file: DEFAULT_MEASUREDBOOT_ML_COUNT_FILE
                .to_string()
                .clone(),
            registrar_ip: DEFAULT_REGISTRAR_IP.to_string(),
            registrar_port: DEFAULT_REGISTRAR_PORT,
            registrar_api_versions: DEFAULT_REGISTRAR_API_VERSIONS
                .iter()
                .map(|&s| s.to_string())
                .collect(),
            server_cert: DEFAULT_SERVER_CERT.to_string(),
            server_key: DEFAULT_SERVER_KEY.to_string(),
            server_key_password: DEFAULT_SERVER_KEY_PASSWORD.to_string(),
            uefi_logs_appendable: DEFAULT_UEFI_LOGS_APPENDABLE,
            uefi_logs_evidence_version: DEFAULT_UEFI_LOGS_EVIDENCE_VERSION
                .to_string(),
            uefi_logs_formats: DEFAULT_UEFI_LOGS_FORMATS
                .iter()
                .map(|&s| s.to_string())
                .collect(),
            uefi_logs_supports_partial_access:
                DEFAULT_UEFI_LOGS_SUPPORTS_PARTIAL_ACCESS,
            tpm_encryption_alg: DEFAULT_TPM_ENCRYPTION_ALG.to_string(),
            tpm_hash_alg: DEFAULT_TPM_HASH_ALG.to_string(),
            tpm_signing_alg: DEFAULT_TPM_SIGNING_ALG.to_string(),
            api_versions: DEFAULT_API_VERSIONS
                .iter()
                .map(|&s| s.to_string())
                .collect(),
            uuid: DEFAULT_UUID.to_string(),
        }
    }
}

impl PushModelConfigTrait for PushModelConfig {
    fn get_certification_keys_server_identifier(&self) -> String {
        self.certification_keys_server_identifier.clone()
    }

    fn get_contact_ip(&self) -> String {
        self.contact_ip.clone()
    }

    fn get_contact_port(&self) -> u32 {
        self.contact_port
    }

    fn get_ek_handle(&self) -> String {
        self.ek_handle.clone()
    }

    fn get_enable_iak_idevid(&self) -> bool {
        self.enable_iak_idevid
    }

    fn get_ima_logs_appendable(&self) -> bool {
        self.ima_logs_appendable
    }

    fn get_ima_logs_formats(&self) -> Vec<String> {
        self.ima_logs_formats.clone()
    }

    fn get_ima_logs_supports_partial_access(&self) -> bool {
        self.ima_logs_supports_partial_access
    }

    fn get_ima_ml_count_file(&self) -> String {
        self.ima_ml_count_file.clone()
    }

    fn get_ima_ml_directory_path(&self) -> String {
        self.ima_ml_directory_path.clone()
    }

    fn get_measuredboot_ml_directory_path(&self) -> String {
        self.measuredboot_ml_directory_path.clone()
    }

    fn get_measuredboot_ml_count_file(&self) -> String {
        self.measuredboot_ml_count_file.clone()
    }

    fn get_registrar_ip(&self) -> String {
        self.registrar_ip.clone()
    }

    fn get_registrar_port(&self) -> u32 {
        self.registrar_port
    }

    fn get_server_cert(&self) -> String {
        self.server_cert.clone()
    }

    fn get_server_key(&self) -> String {
        self.server_key.clone()
    }

    fn get_server_key_password(&self) -> String {
        self.server_key_password.clone()
    }

    fn get_registrar_api_versions(&self) -> Vec<String> {
        self.registrar_api_versions.clone()
    }

    fn get_uefi_logs_appendable(&self) -> bool {
        self.uefi_logs_appendable
    }

    fn get_uefi_logs_evidence_version(&self) -> String {
        self.uefi_logs_evidence_version.clone()
    }

    fn get_uefi_logs_formats(&self) -> Vec<String> {
        self.uefi_logs_formats.clone()
    }

    fn get_uefi_logs_supports_partial_access(&self) -> bool {
        self.uefi_logs_supports_partial_access
    }

    fn get_tpm_encryption_alg(&self) -> String {
        self.tpm_encryption_alg.clone()
    }

    fn get_tpm_hash_alg(&self) -> String {
        self.tpm_hash_alg.clone()
    }

    fn get_tpm_signing_alg(&self) -> String {
        self.tpm_signing_alg.clone()
    }

    fn get_api_versions(&self) -> Vec<String> {
        self.api_versions.clone()
    }

    fn get_uuid(&self) -> String {
        self.uuid.clone()
    }

    fn display(&self) -> String {
        format!(
            "PushModelConfig {{ certification_keys_server_identifier: {},
            contact_ip: {}, contact_port: {},
            enable_iak_idevid: {}, ek_handle: {},
            ima_logs_appendable: {}, ima_logs_formats: {:?}, ima_logs_supports_partial_access: {},
            ima_ml_directory_path: {}, ima_ml_count_file: {},
            measuredboot_ml_directory_path: {}, measuredboot_ml_count_file: {},
            registrar_ip: {}, registrar_port: {}, server_cert: {},
            server_key: {}, server_key_password: {},
            uefi_logs_evidence_version: {}, uefi_logs_supports_partial_access: {},
            uefi_logs_appendable: {}, uefi_logs_formats: {:?},
            tpm_encryption_alg: {}, tpm_hash_alg: {}, tpm_signing_alg: {},
            api_versions: {:?}, registrar_api_versions: {:?}, uuid: {} }}",
            self.certification_keys_server_identifier,
            self.contact_ip,
            self.contact_port,
            self.enable_iak_idevid,
            self.ek_handle,
            self.ima_logs_appendable,
            self.ima_logs_formats,
            self.ima_logs_supports_partial_access,
            self.ima_ml_directory_path,
            self.ima_ml_count_file,
            self.measuredboot_ml_directory_path,
            self.measuredboot_ml_count_file,
            self.registrar_ip,
            self.registrar_port,
            self.server_cert,
            self.server_key,
            self.server_key_password,
            self.uefi_logs_evidence_version,
            self.uefi_logs_supports_partial_access,
            self.uefi_logs_appendable,
            self.uefi_logs_formats,
            self.tpm_encryption_alg,
            self.tpm_hash_alg,
            self.tpm_signing_alg,
            self.api_versions.join(", "),
            self.registrar_api_versions.join(", "),
            self.uuid
        )
    }
}

impl fmt::Display for PushModelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_default_config_test() {
        let pmc = PushModelConfig::default();
        assert!(
            pmc.get_certification_keys_server_identifier()
                == DEFAULT_CERTIFICATION_KEYS_SERVER_IDENTIFIER
        );
        assert!(pmc.get_contact_ip() == DEFAULT_CONTACT_IP);
        assert!(pmc.get_contact_port() == DEFAULT_CONTACT_PORT);
        assert!(pmc.get_ek_handle() == DEFAULT_EK_HANDLE);
        assert!(pmc.get_enable_iak_idevid() == DEFAULT_ENABLE_IAK_IDEVID);
        assert!(pmc.get_ima_logs_appendable() == DEFAULT_IMA_LOGS_APPENDABLE);
        assert!(
            pmc.get_ima_logs_formats()
                == DEFAULT_IMA_LOGS_FORMATS
                    .iter()
                    .map(|&s| s.to_string())
                    .collect::<Vec<String>>()
        );
        assert!(
            pmc.get_ima_logs_supports_partial_access()
                == DEFAULT_IMA_LOGS_SUPPORTS_PARTIAL_ACCESS
        );
        assert!(
            pmc.get_ima_ml_directory_path() == DEFAULT_IMA_ML_DIRECTORY_PATH
        );
        assert!(
            pmc.get_ima_ml_count_file()
                == DEFAULT_IMA_ML_COUNT_FILE.to_string()
        );
        assert!(
            pmc.get_measuredboot_ml_directory_path()
                == DEFAULT_MEASUREDBOOT_ML_DIRECTORY_PATH
        );
        assert!(
            pmc.get_measuredboot_ml_count_file()
                == DEFAULT_MEASUREDBOOT_ML_COUNT_FILE.to_string()
        );
        assert!(pmc.get_registrar_ip() == DEFAULT_REGISTRAR_IP);
        assert!(pmc.get_registrar_port() == DEFAULT_REGISTRAR_PORT);
        assert!(pmc.get_server_cert() == DEFAULT_SERVER_CERT);
        assert!(pmc.get_server_key() == DEFAULT_SERVER_KEY);
        assert!(pmc.get_server_key_password() == DEFAULT_SERVER_KEY_PASSWORD);
        assert!(
            pmc.get_uefi_logs_evidence_version()
                == DEFAULT_UEFI_LOGS_EVIDENCE_VERSION
        );
        assert!(
            pmc.get_uefi_logs_formats()
                == DEFAULT_UEFI_LOGS_FORMATS
                    .iter()
                    .map(|&s| s.to_string())
                    .collect::<Vec<String>>()
        );
        assert!(
            pmc.get_uefi_logs_supports_partial_access()
                == DEFAULT_UEFI_LOGS_SUPPORTS_PARTIAL_ACCESS
        );
        assert!(pmc.get_tpm_encryption_alg() == DEFAULT_TPM_ENCRYPTION_ALG);
        assert!(pmc.get_tpm_hash_alg() == DEFAULT_TPM_HASH_ALG);
        assert!(pmc.get_tpm_signing_alg() == DEFAULT_TPM_SIGNING_ALG);
        assert!(pmc.get_api_versions() == DEFAULT_API_VERSIONS);
        assert!(
            pmc.get_registrar_api_versions()
                == DEFAULT_REGISTRAR_API_VERSIONS
        );
        assert!(pmc.get_uuid() == DEFAULT_UUID);
    } // create_default_config_test

    #[test]
    fn test_display_config() {
        let pmc = PushModelConfig::default();
        let display_string = pmc.to_string();
        assert!(display_string
            .contains(&pmc.get_certification_keys_server_identifier()));
        assert!(display_string.contains(&pmc.get_contact_ip()));
        assert!(display_string.contains(&pmc.get_contact_port().to_string()));
        assert!(display_string.contains(&pmc.get_ek_handle()));
        assert!(
            display_string.contains(&pmc.get_enable_iak_idevid().to_string())
        );
        assert!(display_string
            .contains(&pmc.get_ima_logs_appendable().to_string()));
        assert!(
            display_string.contains(&pmc.get_ima_logs_formats().join(", "))
        );
        assert!(display_string.contains(
            &pmc.get_ima_logs_supports_partial_access().to_string()
        ));
        assert!(display_string.contains(&pmc.get_ima_ml_directory_path()));
        assert!(display_string.contains(&pmc.get_ima_ml_count_file()));
        assert!(display_string
            .contains(&pmc.get_measuredboot_ml_directory_path()));
        assert!(
            display_string.contains(&pmc.get_measuredboot_ml_count_file())
        );
        assert!(display_string.contains(&pmc.get_registrar_ip()));
        assert!(
            display_string.contains(&pmc.get_registrar_port().to_string())
        );
        assert!(display_string.contains(&pmc.get_server_cert()));
        assert!(display_string.contains(&pmc.get_server_key()));
        assert!(display_string.contains(&pmc.get_server_key_password()));
        assert!(
            display_string.contains(&pmc.get_uefi_logs_evidence_version())
        );
        assert!(
            display_string.contains(&pmc.get_uefi_logs_formats().join(", "))
        );
        assert!(display_string.contains(
            &pmc.get_uefi_logs_supports_partial_access().to_string()
        ));
        assert!(display_string
            .contains(&pmc.get_uefi_logs_appendable().to_string()));
        assert!(display_string.contains(&pmc.get_tpm_encryption_alg()));
        assert!(display_string.contains(&pmc.get_tpm_hash_alg()));
        assert!(display_string.contains(&pmc.get_tpm_signing_alg()));
        assert!(display_string.contains(&pmc.get_api_versions().join(", ")));
        assert!(display_string
            .contains(&pmc.get_registrar_api_versions().join(", ")));
        assert!(display_string.contains(&pmc.get_uuid()));
    }
}
