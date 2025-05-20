pub static DEFAULT_REGISTRAR_API_VERSIONS: &[&str] = &["2.3"];
pub static DEFAULT_API_VERSIONS: &[&str] = &["3.0"];
pub static DEFAULT_CONTACT_IP: &str = "127.0.0.1";
pub static DEFAULT_CONTACT_PORT: u32 = 9002;
pub static DEFAULT_EK_HANDLE: &str = "";
pub static DEFAULT_ENABLE_IAK_IDEVID: bool = false;
pub static DEFAULT_IP: &str = "127.0.0.1";
pub static DEFAULT_PORT: u32 = 9002;
pub static DEFAULT_REGISTRAR_IP: &str = "127.0.0.1";
pub static DEFAULT_REGISTRAR_PORT: u32 = 8890;
pub static DEFAULT_SERVER_CERT: &str = "server-cert.crt";
pub static DEFAULT_SERVER_KEY: &str = "server-private.pem";
pub static DEFAULT_SERVER_KEY_PASSWORD: &str = "";
pub static DEFAULT_TPM_HASH_ALG: &str = "sha256";
pub static DEFAULT_TPM_ENCRYPTION_ALG: &str = "rsa";
pub static DEFAULT_TPM_SIGNING_ALG: &str = "rsassa";
pub static DEFAULT_UUID: &str = "b0acd25f-2205-4c37-932d-e8f99a8d39ef";

pub trait PushModelConfigTrait {
    fn get_contact_ip(&self) -> String;
    fn get_contact_port(&self) -> u32;
    fn get_enable_iak_idevid(&self) -> bool;
    fn get_ek_handle(&self) -> String;
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
    contact_ip: String,
    contact_port: u32,
    enable_iak_idevid: bool,
    ek_handle: String,
    registrar_api_versions: Vec<String>,
    registrar_ip: String,
    registrar_port: u32,
    server_cert: String,
    server_key: String,
    server_key_password: String,
    tpm_encryption_alg: String,
    tpm_hash_alg: String,
    tpm_signing_alg: String,
    uuid: String,
}

impl PushModelConfig {
    pub fn new() -> Self {
        PushModelConfig {
            contact_ip: DEFAULT_CONTACT_IP.to_string(),
            contact_port: DEFAULT_CONTACT_PORT,
            ek_handle: DEFAULT_EK_HANDLE.to_string(),
            enable_iak_idevid: DEFAULT_ENABLE_IAK_IDEVID,
            registrar_ip: DEFAULT_REGISTRAR_IP.to_string(),
            registrar_port: DEFAULT_REGISTRAR_PORT,
            registrar_api_versions: DEFAULT_REGISTRAR_API_VERSIONS
                .iter()
                .map(|&s| s.to_string())
                .collect(),
            server_cert: DEFAULT_SERVER_CERT.to_string(),
            server_key: DEFAULT_SERVER_KEY.to_string(),
            server_key_password: DEFAULT_SERVER_KEY_PASSWORD.to_string(),
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
            "PushModelConfig {{ contact_ip: {}, contact_port: {}, enable_iak_idevid: {},
             ek_handle: {}, registrar_ip: {}, registrar_port: {}, server_cert: {},
             server_key: {}, server_key_password: {},
             tpm_encryption_alg: {}, tpm_hash_alg: {}, tpm_signing_alg: {},
             api_versions: {:?}, registrar_api_versions: {:?}, uuid: {} }}",
            self.contact_ip,
            self.contact_port,
            self.enable_iak_idevid,
            self.ek_handle,
            self.registrar_ip,
            self.registrar_port,
            self.server_cert,
            self.server_key,
            self.server_key_password,
            self.tpm_encryption_alg,
            self.tpm_hash_alg,
            self.tpm_signing_alg,
            self.api_versions.join(", "),
            self.registrar_api_versions.join(", "),
            self.uuid
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_default_config_test() {
        let pmc = PushModelConfig::default();
        assert!(pmc.get_contact_ip() == DEFAULT_CONTACT_IP);
        assert!(pmc.get_contact_port() == DEFAULT_CONTACT_PORT);
        assert!(pmc.get_ek_handle() == DEFAULT_EK_HANDLE);
        assert!(pmc.get_enable_iak_idevid() == DEFAULT_ENABLE_IAK_IDEVID);
        assert!(pmc.get_registrar_ip() == DEFAULT_REGISTRAR_IP);
        assert!(pmc.get_registrar_port() == DEFAULT_REGISTRAR_PORT);
        assert!(pmc.get_server_cert() == DEFAULT_SERVER_CERT);
        assert!(pmc.get_server_key() == DEFAULT_SERVER_KEY);
        assert!(pmc.get_server_key_password() == DEFAULT_SERVER_KEY_PASSWORD);
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
}
