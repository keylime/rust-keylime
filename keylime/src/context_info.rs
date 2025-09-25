use crate::{
    agent_data::AgentData,
    algorithms::{self, HashAlgorithm as KeylimeInternalHashAlgorithm},
    config::{KeylimeConfigError, PushModelConfigTrait},
    hash_ek,
    ima::ImaLog,
    structures::{CertificationKey, EvidenceData, EvidenceRequest},
    tpm,
    uefi::UefiLogHandler,
};
use base64::{
    engine::general_purpose::STANDARD as base64_standard, Engine as _,
};
use hex;
use log::*;
use openssl::hash::{Hasher, MessageDigest};
use openssl::{
    bn::BigNum,
    pkey::{PKey, Public},
    rsa::Rsa,
};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use tokio::task;
use tss_esapi::{
    handles::KeyHandle,
    interface_types::algorithm::HashingAlgorithm as TssEsapiInterfaceHashingAlgorithm,
    structures::{Name, Public as TssPublic},
    traits::Marshall,
};

#[derive(Debug, Error)]
pub enum ContextInfoError {
    /// Keylime configuration error
    #[error("Configuration error")]
    Configuration(#[from] KeylimeConfigError),

    /// Invalid algorithm
    #[error("Invalid Algorithm")]
    InvalidAlgorithm(#[from] algorithms::AlgorithmError),

    /// Mismatching AK signing scheme algorithms
    #[error("Mismatching AK signing scheme algorithms. From parameters: {param_sign}, {param_hash}; supported by AK: {ak_sign}, {ak_hash}")]
    MismatchingAKSigningScheme {
        ak_sign: String,
        ak_hash: String,
        param_sign: String,
        param_hash: String,
    },

    /// OpenSSL error
    #[error("OpenSSL error")]
    OpenSSL(#[from] openssl::error::ErrorStack),

    /// TPM Error
    #[error("TPM error")]
    Tpm(#[from] tpm::TpmError),

    /// TSS esapi error
    #[error("TSS esapi  error")]
    TssEsapi(#[from] tss_esapi::Error),

    /// Unsupported AK type
    #[error("Unsupported AK type")]
    UnsupportedAKType,

    /// I/O error for file operations
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    /// Keylime general error
    #[error("Keylime error: {0}")]
    Keylime(String),
}

#[derive(Debug, Clone)]
pub struct AlgorithmConfiguration {
    pub tpm_encryption_alg: algorithms::EncryptionAlgorithm,
    pub tpm_hash_alg: algorithms::HashAlgorithm,
    pub tpm_signing_alg: algorithms::SignAlgorithm,
    pub agent_data_path: String,
}

#[derive(Debug, Clone)]
pub struct AlgorithmConfigurationString {
    pub tpm_encryption_alg: String,
    pub tpm_hash_alg: String,
    pub tpm_signing_alg: String,
    pub agent_data_path: String,
}

#[derive(Clone, Debug)]
pub struct ContextInfo {
    pub tpm_context: tpm::Context<'static>,
    pub tpm_encryption_alg: algorithms::EncryptionAlgorithm,
    pub tpm_hash_alg: algorithms::HashAlgorithm,
    pub tpm_signing_alg: algorithms::SignAlgorithm,
    pub ek_hash: String,
    pub ek_result: tpm::EKResult,
    pub ek_handle: KeyHandle,
    pub ak: tpm::AKResult,
    pub ak_handle: KeyHandle,
}

impl ContextInfo {
    pub fn new_from_str(
        config: AlgorithmConfigurationString,
    ) -> Result<Self, ContextInfoError> {
        let tpm_encryption_alg = algorithms::EncryptionAlgorithm::try_from(
            config.tpm_encryption_alg.as_str(),
        )?;
        let tpm_hash_alg = algorithms::HashAlgorithm::try_from(
            config.tpm_hash_alg.as_str(),
        )?;
        let tpm_signing_alg = algorithms::SignAlgorithm::try_from(
            config.tpm_signing_alg.as_str(),
        )?;
        Self::new(AlgorithmConfiguration {
            tpm_encryption_alg,
            tpm_hash_alg,
            tpm_signing_alg,
            agent_data_path: config.agent_data_path,
        })
    }

    pub fn new(
        config: AlgorithmConfiguration,
    ) -> Result<Self, ContextInfoError> {
        let mut tpm_context =
            tpm::Context::new().expect("Failed to create TPM context");
        let tpm_encryption_alg = config.tpm_encryption_alg;
        let tpm_hash_alg = config.tpm_hash_alg;
        let tpm_signing_alg = config.tpm_signing_alg;

        let ek_result = tpm_context.create_ek(tpm_encryption_alg, None)?;
        let ek_handle = ek_result.key_handle;
        let ek_hash = hash_ek::hash_ek_pubkey(ek_result.public.clone())
            .map_err(|e| ContextInfoError::Keylime(e.to_string()))?;

        let loaded_ak = if config.agent_data_path.is_empty() {
            None
        } else {
            let path = Path::new(&config.agent_data_path);
            if path.exists() {
                match AgentData::load(path) {
                    Ok(data) => {
                        if data.valid(
                            tpm_hash_alg,
                            tpm_signing_alg,
                            ek_hash.as_bytes(),
                        ) {
                            Some(data.get_ak().map_err(|e| {
                                ContextInfoError::Keylime(e.to_string())
                            })?)
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        };

        let ak = if let Some(ak) = loaded_ak {
            ak
        } else {
            match tpm_context.create_ak(
                ek_result.key_handle,
                tpm_hash_alg,
                tpm_encryption_alg,
                tpm_signing_alg,
            ) {
                Ok(ak) => ak,
                Err(e) => {
                    // Clean up EK handle before returning error
                    let _ = tpm_context
                        .flush_context(ek_result.key_handle.into());
                    return Err(ContextInfoError::Tpm(e));
                }
            }
        };

        let ak_handle = match tpm_context.load_ak(ek_result.key_handle, &ak) {
            Ok(handle) => handle,
            Err(e) => {
                // Clean up EK handle before returning error
                let _ =
                    tpm_context.flush_context(ek_result.key_handle.into());
                return Err(ContextInfoError::Tpm(e));
            }
        };

        if !config.agent_data_path.is_empty() {
            let agent_data_to_store = match AgentData::create(
                tpm_hash_alg,
                tpm_signing_alg,
                &ak,
                ek_hash.as_bytes(),
            ) {
                Ok(data) => data,
                Err(e) => {
                    // Clean up both handles before returning error
                    let _ = tpm_context
                        .flush_context(ek_result.key_handle.into());
                    let _ = tpm_context.flush_context(ak_handle.into());
                    return Err(ContextInfoError::Keylime(e.to_string()));
                }
            };
            if let Err(e) =
                agent_data_to_store.store(Path::new(&config.agent_data_path))
            {
                // Clean up both handles before returning error
                let _ =
                    tpm_context.flush_context(ek_result.key_handle.into());
                let _ = tpm_context.flush_context(ak_handle.into());
                return Err(ContextInfoError::Keylime(e.to_string()));
            }
        }

        Ok(ContextInfo {
            tpm_context,
            tpm_encryption_alg,
            tpm_hash_alg,
            tpm_signing_alg,
            ek_hash,
            ek_result,
            ek_handle,
            ak,
            ak_handle,
        })
    }

    pub fn get_mutable_tpm_context(&mut self) -> &mut tpm::Context<'static> {
        &mut self.tpm_context
    }

    pub fn get_tpm_context(&self) -> &tpm::Context<'static> {
        &self.tpm_context
    }

    pub fn flush_context(&mut self) -> Result<(), ContextInfoError> {
        self.tpm_context.flush_context(self.ek_handle.into())?;
        self.tpm_context.flush_context(self.ak_handle.into())?;
        Ok(())
    }

    pub fn get_key_class(&self) -> String {
        algorithms::get_key_class(&self.tpm_encryption_alg).to_string()
    }

    pub fn get_key_size(&self) -> usize {
        algorithms::get_key_size(&self.tpm_encryption_alg)
    }

    pub fn get_public_key_as_base64(
        &self,
    ) -> Result<String, ContextInfoError> {
        let public_key_bytes: Vec<u8> = self.ek_result.public.marshall()?;
        let base64_encoded_key: String =
            base64_standard.encode(&public_key_bytes);
        Ok(base64_encoded_key)
    }

    pub fn get_supported_hash_algorithms(
        &mut self,
    ) -> Result<Vec<String>, ContextInfoError> {
        Ok(self
            .tpm_context
            .get_supported_hash_algorithms_as_strings()?)
    }

    pub fn get_supported_signing_schemes(
        &mut self,
    ) -> Result<Vec<String>, ContextInfoError> {
        Ok(self
            .tpm_context
            .get_supported_signing_algorithms_as_strings()?)
    }

    pub fn get_key_algorithm(&self) -> String {
        self.tpm_encryption_alg.to_string()
    }

    pub fn get_ek_handle(&self) -> KeyHandle {
        self.ek_handle
    }

    pub fn get_ak_handle(&self) -> KeyHandle {
        self.ak_handle
    }

    fn get_ak_public_ref(&self) -> &TssPublic {
        &self.ak.public
    }

    pub fn get_ak_key_class_str(&self) -> String {
        algorithms::KeyClass::Asymmetric.to_string()
    }

    pub fn get_ak_key_algorithm_str(&self) -> String {
        self.tpm_encryption_alg.to_string()
    }

    pub fn get_ak_public_enum_ref(&self) -> &TssPublic {
        &self.ak.public
    }

    pub fn get_ak_key_size(&self) -> Result<u16, ContextInfoError> {
        let ak_public_info = self.get_ak_public_ref();
        match ak_public_info {
            TssPublic::Rsa { parameters, .. } => {
                Ok(parameters.key_bits().into())
            }
            TssPublic::Ecc { parameters, .. } => {
                Ok(algorithms::get_ecc_curve_key_size(parameters.ecc_curve()))
            }
            _ => Err(ContextInfoError::UnsupportedAKType),
        }
    }

    pub fn get_ak_local_identifier_str(
        &self,
    ) -> Result<String, ContextInfoError> {
        let ak_public_info: &TssPublic = self.get_ak_public_ref();
        let marshalled_tpmt_public = ak_public_info.marshall()?;
        let name_h_alg_tss: TssEsapiInterfaceHashingAlgorithm =
            ak_public_info.name_hashing_algorithm();
        let keylime_hash_alg: KeylimeInternalHashAlgorithm =
            name_h_alg_tss.try_into()?;
        let name_alg_id_value: u16 = name_h_alg_tss.into();
        let openssl_message_digest: MessageDigest = keylime_hash_alg.into();
        let mut hasher = Hasher::new(openssl_message_digest)?;
        hasher.update(&marshalled_tpmt_public)?;
        let digest_bytes_vec = hasher.finish()?;
        let digest_bytes: &[u8] = &digest_bytes_vec;
        let mut name_content_buffer: Vec<u8> = Vec::new();
        name_content_buffer
            .extend_from_slice(&name_alg_id_value.to_be_bytes());
        name_content_buffer.extend_from_slice(digest_bytes);
        let ak_name_obj: Name =
            Name::try_from(name_content_buffer).map_err(|e| {
                tpm::TpmError::NameFromBytesError(format!(
                    "Failed to create Name object: {e:?}"
                ))
            })?;
        Ok(hex::encode(ak_name_obj.value()))
    }

    pub fn get_ak_public_key_as_base64(
        &self,
    ) -> Result<String, ContextInfoError> {
        let ak_public_info = self.get_ak_public_ref();
        let public_key_bytes: Vec<u8> = ak_public_info.marshall()?;
        Ok(base64_standard.encode(&public_key_bytes))
    }

    pub fn get_ak_certification_data(
        &mut self,
    ) -> Result<CertificationKey, ContextInfoError> {
        let config = crate::config::get_config();

        // Extract the AK's actual signing scheme and hash algorithm
        let (ak_signing_scheme, ak_hash_algorithm) = self
            .tpm_context
            .extract_ak_scheme_and_hash(self.ak_handle)?;

        Ok(CertificationKey {
            key_class: self.get_ak_key_class_str(),
            key_algorithm: self.get_ak_key_algorithm_str(),
            key_size: self.get_ak_key_size()?.into(),
            server_identifier: config
                .certification_keys_server_identifier()
                .to_string(),
            local_identifier: self.get_ak_local_identifier_str()?,
            public: self.get_ak_public_key_as_base64()?,
            allowable_hash_algorithms: Some(vec![ak_hash_algorithm]),
            allowable_signature_schemes: Some(vec![ak_signing_scheme]),
        })
    }

    fn build_openssl_pkey_from_params(
        &self,
    ) -> Result<PKey<Public>, ContextInfoError> {
        let tss_pub = self.get_ak_public_ref().clone();

        if let TssPublic::Rsa {
            unique, parameters, ..
        } = tss_pub
        {
            let n = BigNum::from_slice(unique.value())?;
            let exponent_val: u32 = parameters.exponent().into();
            let e_val = if exponent_val == 0 {
                65537
            } else {
                exponent_val
            };
            let e = BigNum::from_u32(e_val)?;
            let rsa = Rsa::from_public_components(n, e)?;
            let pkey = PKey::from_rsa(rsa)?;
            Ok(pkey)
        } else {
            Err(ContextInfoError::UnsupportedAKType)
        }
    }

    pub async fn generate_tpm_quote_evidence(
        &mut self,
        challenge: &str,
        signature_scheme: &str,
        hash_algorithm: &str,
        selected_subjects: &HashMap<String, Vec<u32>>,
    ) -> Result<EvidenceData, ContextInfoError> {
        // Get signing scheme and hash algorithm from the parameters
        let param_sign_scheme =
            algorithms::SignAlgorithm::try_from(signature_scheme)?;
        let param_hash_alg =
            algorithms::HashAlgorithm::try_from(hash_algorithm)?;

        // Extract signing scheme and hash algorithm from the AK
        let (ak_sig_str, ak_hash_str) = self
            .tpm_context
            .extract_ak_scheme_and_hash(self.ak_handle)?;
        let ak_sign_scheme =
            algorithms::SignAlgorithm::try_from(ak_sig_str.as_str())?;
        let ak_hash_alg =
            algorithms::HashAlgorithm::try_from(ak_hash_str.as_str())?;

        if (param_sign_scheme != ak_sign_scheme)
            || (param_hash_alg != ak_hash_alg)
        {
            error!("Mismatching AK signing scheme algorithms. From parameters: {param_sign_scheme}, {param_hash_alg}; supported by AK: {ak_sig_str}, {ak_hash_str}");
            return Err(ContextInfoError::MismatchingAKSigningScheme {
                ak_sign: ak_sig_str,
                ak_hash: ak_hash_str,
                param_sign: signature_scheme.to_string(),
                param_hash: hash_algorithm.to_string(),
            });
        }

        let mut pcr_mask: u32 = 0;
        if let Some(pcr_indices) = selected_subjects.get(hash_algorithm) {
            for &pcr_index in pcr_indices {
                pcr_mask |= 1 << pcr_index;
            }
        }

        let pubkey_for_quote = self.build_openssl_pkey_from_params()?;
        let ak_handle = self.ak_handle;
        let challenge_bytes = challenge.to_string().into_bytes();
        let mut tpm_context = self.get_mutable_tpm_context().clone();

        let full_quote_str = task::spawn_blocking(move || {
            tpm_context.quote(
                &challenge_bytes,
                pcr_mask,
                &pubkey_for_quote,
                ak_handle,
                ak_hash_alg,
                ak_sign_scheme,
            )
        })
        .await
        .map_err(|e| ContextInfoError::Keylime(e.to_string()))??;

        let parts: Vec<&str> = full_quote_str.split(':').collect();
        if parts.len() < 3 {
            let msg = "Invalid quote format received from TPM".to_string();
            return Err(ContextInfoError::Keylime(msg));
        }

        let quote_message =
            parts[0].strip_prefix('r').unwrap_or(parts[0]).to_string();
        let quote_signature = parts[1].to_string();
        let pcr_values = parts[2].to_string();

        Ok(EvidenceData::TpmQuote {
            message: quote_message,
            signature: quote_signature,
            subject_data: pcr_values,
            meta: None,
        })
    }

    pub async fn generate_ima_log_evidence(
        &mut self,
        log_path: Option<&str>,
        _format: Option<&str>,
        starting_offset: Option<usize>,
        entry_count: Option<usize>,
    ) -> Result<EvidenceData, ContextInfoError> {
        let entries = if let Some(ima_log_path) = log_path {
            let ima_log = ImaLog::new(ima_log_path).map_err(|e| {
                ContextInfoError::Keylime(format!(
                    "Failed to read IMA log: {e:?}",
                ))
            })?;
            ima_log.get_entries_as_string(
                starting_offset.unwrap_or(0),
                entry_count,
            )
        } else {
            String::new()
        };

        let entry_count = entries.lines().count();
        Ok(EvidenceData::ImaLog {
            entry_count,
            entries: Some(entries),
            meta: None,
        })
    }

    pub async fn generate_uefi_log_evidence(
        &mut self,
        log_path: Option<&str>,
    ) -> Result<EvidenceData, ContextInfoError> {
        let content = if let Some(uefi_log_path) = log_path {
            let uefi_log_handler = UefiLogHandler::new(uefi_log_path)
                .map_err(|e| {
                    ContextInfoError::Keylime(format!(
                        "Failed to create UEFI log handler: {e:?}",
                    ))
                })?;
            match uefi_log_handler.base_64() {
                Ok(content) => content,
                Err(e) => {
                    return Err(ContextInfoError::Keylime(format!(
                        "Failed to read UEFI log: {e:?}",
                    )));
                }
            }
        } else {
            String::new()
        };

        Ok(EvidenceData::UefiLog {
            entries: Some(content),
            meta: None,
        })
    }

    pub async fn collect_evidences(
        &mut self,
        evidence_requests: &[EvidenceRequest],
    ) -> Result<Vec<EvidenceData>, ContextInfoError> {
        let mut evidence_results = Vec::new();

        for request in evidence_requests {
            match request {
                EvidenceRequest::TpmQuote {
                    challenge,
                    signature_scheme,
                    hash_algorithm,
                    selected_subjects,
                } => {
                    let evidence = self
                        .generate_tpm_quote_evidence(
                            challenge,
                            signature_scheme,
                            hash_algorithm,
                            selected_subjects,
                        )
                        .await?;
                    evidence_results.push(evidence);
                }
                EvidenceRequest::ImaLog {
                    starting_offset,
                    entry_count,
                    format,
                    log_path,
                } => {
                    let evidence = self
                        .generate_ima_log_evidence(
                            log_path.as_deref(),
                            format.as_deref(),
                            *starting_offset,
                            *entry_count,
                        )
                        .await?;
                    evidence_results.push(evidence);
                }
                EvidenceRequest::UefiLog { log_path, .. } => {
                    let evidence = self
                        .generate_uefi_log_evidence(log_path.as_deref())
                        .await?;
                    evidence_results.push(evidence);
                }
            }
        }

        Ok(evidence_results)
    }
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {

    use super::*;
    use crate::tpm::testing;

    #[tokio::test]
    async fn test_basic_creation() {
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };
        let mut context_info = ContextInfo::new_from_str(config)
            .expect("Failed to create context from string");
        assert!(!context_info.ek_hash.is_empty());
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_creation_and_get_data() {
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(), // Don't use persistence for this test
        };
        let mut context_info = ContextInfo::new_from_str(config)
            .expect("Failed to create context from string");
        assert!(!context_info.get_public_key_as_base64().unwrap().is_empty()); //#[allow_ci]
        assert_eq!(context_info.get_key_class(), "asymmetric");
        assert_eq!(context_info.get_key_size(), 2048);
        assert_eq!(context_info.get_key_algorithm(), "rsa2048");
        let ek_handle = context_info.get_ek_handle();
        let ak_handle = context_info.get_ak_handle();
        assert!(context_info
            .get_mutable_tpm_context()
            .flush_context((ek_handle).into())
            .is_ok());
        assert!(context_info
            .get_mutable_tpm_context()
            .flush_context((ak_handle).into())
            .is_ok());
    }

    #[tokio::test]
    async fn test_ak_persistence_and_reload() {
        let _mutex = testing::lock_tests().await;
        // The `tempdir` object provides a temporary directory. When it goes out
        // of scope at the end of this test, the directory and all its contents
        // (including our agent_data.json) are automatically deleted.
        let tempdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let data_path = tempdir.path().join("agent_data.json");

        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: data_path.to_str().unwrap().to_string(), //#[allow_ci]
        };

        // First run: should create and store the AK
        let ak_name_1 = {
            let mut context_info_1 =
                ContextInfo::new_from_str(config.clone()).unwrap(); //#[allow_ci]
            let name = context_info_1.get_ak_local_identifier_str().unwrap(); //#[allow_ci]
            context_info_1.flush_context().unwrap(); //#[allow_ci]
            name
        };

        // The agent_data.json file should now exist
        assert!(data_path.exists());

        // Second run: should load the previously stored AK
        let ak_name_2 = {
            let mut context_info_2 =
                ContextInfo::new_from_str(config).unwrap(); //#[allow_ci]
            let name = context_info_2.get_ak_local_identifier_str().unwrap(); //#[allow_ci]
            context_info_2.flush_context().unwrap(); //#[allow_ci]
            name
        };

        // The AK name (a unique identifier) should be the same, proving it was loaded
        assert_eq!(ak_name_1, ak_name_2);
    }

    #[tokio::test]
    async fn test_new_from_str_errors_on_bad_enc_alg() {
        let _mutex = crate::tpm::testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "bad-algorithm".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };
        let r = ContextInfo::new_from_str(config);
        assert!(r.is_err());
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_new_from_str_errors_on_bad_hash_alg() {
        let _mutex = crate::tpm::testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "bad-hash".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };
        let r = ContextInfo::new_from_str(config);
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_new_from_str_errors_on_bad_sign_alg() {
        let _mutex = crate::tpm::testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "bad-signing-alg".to_string(),
            agent_data_path: "".to_string(),
        };
        let r = ContextInfo::new_from_str(config);
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_creation_and_get_all_data() {
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };
        let mut context_info = ContextInfo::new_from_str(config)
            .expect("Failed to create context from string");
        assert!(!context_info.ek_hash.is_empty());
        assert!(!context_info.get_public_key_as_base64().unwrap().is_empty()); //#[allow_ci]
        assert_eq!(context_info.get_key_class(), "asymmetric");
        assert_eq!(context_info.get_key_size(), 2048);
        assert_eq!(context_info.get_key_algorithm(), "rsa2048");
        assert!(!context_info.get_ak_key_class_str().is_empty());
        assert!(!context_info.get_ak_key_algorithm_str().is_empty());
        assert!(context_info.get_ak_key_size().is_ok());
        assert!(context_info.get_ak_local_identifier_str().is_ok());
        assert!(context_info.get_ak_public_key_as_base64().is_ok());
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    async fn test_ak_persistence_with_invalid_data() {
        let _mutex = testing::lock_tests().await;
        let tempdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let data_path = tempdir.path().join("agent_data.json");

        // First run: Create a context with SHA256 and persist it
        let config1 = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: data_path.to_str().unwrap().to_string(), //#[allow_ci]
        };
        let ak_name_1 = {
            let mut context_info_1 =
                ContextInfo::new_from_str(config1.clone()).unwrap(); //#[allow_ci]
            let name = context_info_1.get_ak_local_identifier_str().unwrap(); //#[allow_ci]
            context_info_1.flush_context().unwrap(); //#[allow_ci]
            name
        };

        // Second run: Create a context with a different hash alg (SHA384)
        // This should invalidate the persisted data and force a new key creation.
        let config2 = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha384".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: data_path.to_str().unwrap().to_string(), //#[allow_ci]
        };
        let ak_name_2 = {
            let mut context_info_2 =
                ContextInfo::new_from_str(config2).unwrap(); //#[allow_ci]
            let name = context_info_2.get_ak_local_identifier_str().unwrap(); //#[allow_ci]
            context_info_2.flush_context().unwrap(); //#[allow_ci]
            name
        };

        // The names should be different, proving a new key was created.
        assert_ne!(ak_name_1, ak_name_2);
    }

    #[tokio::test]
    async fn test_ak_persistence_with_corrupt_file() {
        use std::fs::File;
        use std::io::Write;
        let _mutex = testing::lock_tests().await;
        let tempdir = tempfile::tempdir().unwrap(); //#[allow_ci]
        let data_path = tempdir.path().join("agent_data.json");

        let mut file = File::create(&data_path).unwrap(); //#[allow_ci]
        file.write_all(b"this is not valid json").unwrap(); //#[allow_ci]

        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: data_path.to_str().unwrap().to_string(), //#[allow_ci]
        };

        // The creation should not fail, but gracefully create a new key.
        let context_result = ContextInfo::new_from_str(config);
        assert!(context_result.is_ok());

        // We can verify that the newly created context has a valid AK
        let mut context_info = context_result.unwrap(); //#[allow_ci]
        assert!(!context_info
            .get_ak_local_identifier_str()
            .unwrap() //#[allow_ci]
            .is_empty());
        context_info.flush_context().unwrap(); //#[allow_ci]
    }

    #[tokio::test]
    async fn test_perform_attestation() {
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };
        let context_result = ContextInfo::new_from_str(config);
        assert!(context_result.is_ok());

        let mut subjects = HashMap::new();
        subjects
            .insert("sha256".to_string(), vec![0, 1, 2, 3, 4, 5, 6, 7, 10]);

        let evidence_requests = vec![
            EvidenceRequest::TpmQuote {
                challenge: "test_challenge".to_string(),
                signature_scheme: "rsassa".to_string(),
                hash_algorithm: "sha256".to_string(),
                selected_subjects: subjects,
            },
            EvidenceRequest::ImaLog {
                starting_offset: Some(0),
                entry_count: Some(1),
                format: None,
                log_path: Some("test-data/ima_log.txt".to_string()),
            },
            EvidenceRequest::UefiLog {
                format: None,
                log_path: Some("test-data/uefi_log.bin".to_string()),
            },
        ];
        let mut context_info = context_result.unwrap(); //#[allow_ci]
        let result = context_info.collect_evidences(&evidence_requests).await;
        assert!(result.is_ok());
        let evidence_results = result.unwrap(); //#[allow_ci]
        assert_eq!(evidence_results.len(), 3);

        // Check TPM quote evidence
        if let EvidenceData::TpmQuote {
            message, signature, ..
        } = &evidence_results[0]
        {
            assert!(!message.is_empty());
            assert!(!signature.is_empty());
        } else {
            panic!("Expected TPM quote evidence"); //#[allow_ci]
        }

        context_info.flush_context().unwrap(); //#[allow_ci]
    }

    #[tokio::test]
    async fn test_perform_attestation_with_invalid_algs() {
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        let context_result = ContextInfo::new_from_str(config);
        assert!(context_result.is_ok());
        let mut context_info = context_result.unwrap(); //#[allow_ci]

        let mut subjects = HashMap::new();
        subjects.insert("sha256".to_string(), vec![10]);

        let evidence_requests = vec![EvidenceRequest::TpmQuote {
            challenge: "test_challenge".to_string(),
            signature_scheme: "invalid-algorithm".to_string(),
            hash_algorithm: "sha256".to_string(),
            selected_subjects: subjects,
        }];

        let result = context_info.collect_evidences(&evidence_requests).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextInfoError::InvalidAlgorithm(
                algorithms::AlgorithmError::UnsupportedSigningAlgorithm(_)
            )
        ));
        context_info.flush_context().unwrap(); //#[allow_ci]
    }

    #[tokio::test]
    async fn test_perform_attestation_with_mismatching_algs() {
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        let context_result = ContextInfo::new_from_str(config);
        assert!(context_result.is_ok());
        let mut context_info = context_result.unwrap(); //#[allow_ci]

        let mut subjects = HashMap::new();
        subjects.insert("sha256".to_string(), vec![10]);

        let evidence_requests = vec![EvidenceRequest::TpmQuote {
            challenge: "test_challenge".to_string(),
            signature_scheme: "rsassa".to_string(),
            hash_algorithm: "sha384".to_string(), // mismatching hash alg
            selected_subjects: subjects,
        }];

        let result = context_info.collect_evidences(&evidence_requests).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextInfoError::MismatchingAKSigningScheme {
                ak_sign: _,
                ak_hash: _,
                param_sign: _,
                param_hash: _
            },
        ));
        context_info.flush_context().unwrap(); //#[allow_ci]
    }

    #[tokio::test]
    async fn test_verifier_subjects() {
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
            agent_data_path: "".to_string(),
        };

        let context_result = ContextInfo::new_from_str(config);
        assert!(context_result.is_ok());
        let mut context_info = context_result.unwrap(); //#[allow_ci]

        let mut subjects = HashMap::new();
        subjects.insert(
            "sha1".to_string(),
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                18, 19, 20, 21, 22, 23,
            ],
        );
        subjects.insert("sha256".to_string(), vec![10]);
        let evidence_requests = vec![
            EvidenceRequest::TpmQuote {
                challenge: "test_challenge".to_string(),
                signature_scheme: "rsassa".to_string(),
                hash_algorithm: "sha256".to_string(),
                selected_subjects: subjects,
            },
            EvidenceRequest::ImaLog {
                starting_offset: Some(0),
                entry_count: Some(1),
                format: None,
                log_path: Some("test-data/ima_log.txt".to_string()),
            },
            EvidenceRequest::UefiLog {
                format: None,
                log_path: Some("test-data/uefi_log.bin".to_string()),
            },
        ];
        let result = context_info.collect_evidences(&evidence_requests).await;
        assert!(result.is_ok());
        context_info.flush_context().unwrap(); //#[allow_ci]
    }
}
