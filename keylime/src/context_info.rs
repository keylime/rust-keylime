use crate::algorithms::HashAlgorithm as KeylimeInternalHashAlgorithm;
use crate::config::{PushModelConfig, PushModelConfigTrait};
use crate::keylime_error::Error as KeylimeError;
use crate::keylime_error::Error as KeylimeErrorEnum;
use crate::keylime_error::Result;
use crate::structures::CertificationKey;
use crate::{agent_data::AgentData, algorithms, hash_ek, tpm};
use base64::{
    engine::general_purpose::STANDARD as base64_standard, Engine as _,
};
use hex;
use openssl::hash::{Hasher, MessageDigest};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm as TssEsapiInterfaceHashingAlgorithm;
use tss_esapi::structures::Name;
use tss_esapi::structures::Public as TssPublic;
use tss_esapi::traits::Marshall;

pub struct AlgorithmConfiguration {
    pub tpm_encryption_alg: algorithms::EncryptionAlgorithm,
    pub tpm_hash_alg: algorithms::HashAlgorithm,
    pub tpm_signing_alg: algorithms::SignAlgorithm,
}

pub struct AlgorithmConfigurationString {
    pub tpm_encryption_alg: String,
    pub tpm_hash_alg: String,
    pub tpm_signing_alg: String,
}

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
    pub fn new_from_str(config: AlgorithmConfigurationString) -> Self {
        let tpm_encryption_alg = algorithms::EncryptionAlgorithm::try_from(
            config.tpm_encryption_alg.as_str(),
        )
        .expect("Invalid TPM encryption algorithm");
        let tpm_hash_alg =
            algorithms::HashAlgorithm::try_from(config.tpm_hash_alg.as_str())
                .expect("Invalid TPM hash algorithm");
        let tpm_signing_alg = algorithms::SignAlgorithm::try_from(
            config.tpm_signing_alg.as_str(),
        )
        .expect("Invalid TPM signing algorithm");
        Self::new(AlgorithmConfiguration {
            tpm_encryption_alg,
            tpm_hash_alg,
            tpm_signing_alg,
        })
    }
    pub fn new(config: AlgorithmConfiguration) -> Self {
        let mut tpm_context =
            tpm::Context::new().expect("Failed to create TPM context");
        let tpm_encryption_alg = config.tpm_encryption_alg;
        let tpm_hash_alg = config.tpm_hash_alg;
        let tpm_signing_alg = config.tpm_signing_alg;
        let ek_result = tpm_context
            .create_ek(tpm_encryption_alg, None)
            .expect("Failed to create EK");
        let ek_handle = ek_result.key_handle;
        let ek_hash = hash_ek::hash_ek_pubkey(ek_result.public.clone())
            .expect("Failed to hash EK public key");
        let ak = tpm_context
            .create_ak(
                ek_result.key_handle,
                tpm_hash_alg,
                tpm_encryption_alg,
                tpm_signing_alg,
            )
            .expect("Failed to create AK");
        let ak_handle = tpm_context
            .load_ak(ek_result.key_handle, &ak)
            .expect("Failed to load AK");
        AgentData::create(
            tpm_hash_alg,
            tpm_signing_alg,
            &ak,
            ek_hash.as_bytes(),
        )
        .expect("Failed to create AgentData");
        ContextInfo {
            tpm_context,
            tpm_encryption_alg,
            tpm_hash_alg,
            tpm_signing_alg,
            ek_hash,
            ek_result,
            ek_handle,
            ak,
            ak_handle,
        }
    }

    pub fn get_mutable_tpm_context(&mut self) -> &mut tpm::Context<'static> {
        &mut self.tpm_context
    }

    pub fn get_tpm_context(&self) -> &tpm::Context<'static> {
        &self.tpm_context
    }

    pub fn flush_context(&mut self) -> Result<()> {
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

    pub fn get_public_key_as_base64(&self) -> Result<String> {
        let public_key_bytes: Vec<u8> = self.ek_result.public.marshall()?;
        let base64_encoded_key: String =
            base64_standard.encode(&public_key_bytes);
        Ok(base64_encoded_key)
    }

    pub fn get_supported_hash_algorithms(&mut self) -> Result<Vec<String>> {
        self.tpm_context
            .get_supported_hash_algorithms_as_strings()
            .map_err(KeylimeErrorEnum::Tpm)
    }

    pub fn get_supported_signing_schemes(&mut self) -> Result<Vec<String>> {
        self.tpm_context
            .get_supported_signing_algorithms_as_strings()
            .map_err(KeylimeErrorEnum::Tpm)
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

    fn get_ak_public_ref(&self) -> Result<&TssPublic> {
        Ok(&self.ak.public)
    }

    pub fn get_ak_key_class_str(&self) -> String {
        algorithms::KeyClass::Asymmetric.to_string()
    }

    pub fn get_ak_key_algorithm_str(&self) -> String {
        self.tpm_signing_alg.to_string()
    }

    pub fn get_ak_public_enum_ref(&self) -> Result<&TssPublic> {
        Ok(&self.ak.public)
    }

    pub fn get_ak_key_size(&self) -> Result<u16> {
        let ak_public_info = self.get_ak_public_ref()?;
        match ak_public_info {
            TssPublic::Rsa { parameters, .. } => {
                Ok(parameters.key_bits().into())
            }
            TssPublic::Ecc { parameters, .. } => {
                Ok(algorithms::get_ecc_curve_key_size(parameters.ecc_curve()))
            }
            _ => Err(KeylimeError::Tpm(
                tpm::TpmError::PublicKeyCertificateMismatch(
                    "Unsupported AK public key type".to_string(),
                ),
            )),
        }
    }

    pub fn get_ak_local_identifier_str(&self) -> Result<String> {
        let ak_public_info: &TssPublic = self.get_ak_public_ref()?;
        let marshalled_tpmt_public = ak_public_info.marshall()?;
        let name_h_alg_tss: TssEsapiInterfaceHashingAlgorithm =
            ak_public_info.name_hashing_algorithm();
        let keylime_hash_alg: KeylimeInternalHashAlgorithm = name_h_alg_tss
            .try_into()
            .map_err(|e: crate::algorithms::AlgorithmError| {
                KeylimeErrorEnum::Algorithm(e)
            })?;
        let name_alg_id_value: u16 = name_h_alg_tss.into();
        let openssl_message_digest: MessageDigest = keylime_hash_alg.into();
        let mut hasher =
            Hasher::new(openssl_message_digest).map_err(|e| {
                KeylimeErrorEnum::Other(format!(
                    "Error on OpenSSL hasher {}",
                    e
                ))
            })?;
        hasher.update(&marshalled_tpmt_public).map_err(|e| {
            KeylimeErrorEnum::Other(format!(
                "Error on OpenSSL hasher update: {}",
                e
            ))
        })?;
        let digest_bytes_vec = hasher.finish().map_err(|e| {
            KeylimeErrorEnum::Other(format!(
                "Error on OpenSSL hasher finalizer: {}",
                e
            ))
        })?;
        let digest_bytes: &[u8] = &digest_bytes_vec;
        let mut name_content_buffer: Vec<u8> = Vec::new();
        name_content_buffer
            .extend_from_slice(&name_alg_id_value.to_be_bytes());
        name_content_buffer.extend_from_slice(digest_bytes);
        let ak_name_obj: Name =
            Name::try_from(name_content_buffer).map_err(|e| {
                KeylimeErrorEnum::Tpm(tpm::TpmError::NameFromBytesError(
                    format!("Failed to create Name object: {}", e),
                ))
            })?;
        Ok(hex::encode(ak_name_obj.value()))
    }

    pub fn get_ak_public_key_as_base64(&self) -> Result<String> {
        let ak_public_info = self.get_ak_public_ref()?;
        let public_key_bytes: Vec<u8> = ak_public_info.marshall()?;
        Ok(base64_standard.encode(&public_key_bytes))
    }

    /// Gathers all information for a single AK entry in the "certification_keys" array.
    pub fn get_ak_certification_data(&self) -> Result<CertificationKey> {
        let config = PushModelConfig::default();
        Ok(CertificationKey {
            key_class: self.get_ak_key_class_str(),
            key_algorithm: self.get_ak_key_algorithm_str(),
            key_size: self.get_ak_key_size()?.into(),
            server_identifier: config
                .get_certification_keys_server_identifier(),
            local_identifier: self.get_ak_local_identifier_str()?,
            public: self.get_ak_public_key_as_base64()?,
        })
    }
}

// tests
#[cfg(test)]
mod tests {

    #[cfg(feature = "testing")]
    use super::*;

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_basic_creation() {
        use crate::tpm::testing;
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
        };
        let mut context_info = ContextInfo::new_from_str(config);
        assert!(!context_info.ek_hash.is_empty());
        assert!(context_info.flush_context().is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_creation_and_get_data() {
        use crate::tpm::testing;
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
        };
        let mut context_info = ContextInfo::new_from_str(config);
        assert!(!context_info.ek_hash.is_empty());
        assert!(!context_info.get_public_key_as_base64().unwrap().is_empty()); //#[allow_ci]
        assert_eq!(context_info.get_key_class(), "asymmetric");
        assert_eq!(context_info.get_key_size(), 2048);
        assert_eq!(context_info.get_key_algorithm(), "rsa");
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
    #[cfg(feature = "testing")]
    #[should_panic(expected = "Invalid TPM encryption algorithm")]
    async fn test_new_from_str_panics_on_bad_enc_alg() {
        let _mutex = crate::tpm::testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "bad-algorithm".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
        };
        ContextInfo::new_from_str(config);
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    #[should_panic(expected = "Invalid TPM hash algorithm")]
    async fn test_new_from_str_panics_on_bad_hash_alg() {
        let _mutex = crate::tpm::testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "bad-hash".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
        };
        ContextInfo::new_from_str(config);
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    #[should_panic(expected = "Invalid TPM signing algorithm")]
    async fn test_new_from_str_panics_on_bad_sign_alg() {
        let _mutex = crate::tpm::testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "bad-signing-alg".to_string(),
        };
        ContextInfo::new_from_str(config);
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_creation_and_get_all_data() {
        // Renamed for clarity
        use crate::tpm::testing;
        let _mutex = testing::lock_tests().await;
        let config = AlgorithmConfigurationString {
            tpm_encryption_alg: "rsa".to_string(),
            tpm_hash_alg: "sha256".to_string(),
            tpm_signing_alg: "rsassa".to_string(),
        };
        let mut context_info = ContextInfo::new_from_str(config);
        assert!(!context_info.ek_hash.is_empty());
        assert!(!context_info.get_public_key_as_base64().unwrap().is_empty()); //#[allow_ci]
        assert_eq!(context_info.get_key_class(), "asymmetric");
        assert_eq!(context_info.get_key_size(), 2048);
        assert_eq!(context_info.get_key_algorithm(), "rsa");
        assert!(!context_info.get_ak_key_class_str().is_empty());
        assert!(!context_info.get_ak_key_algorithm_str().is_empty());
        assert!(context_info.get_ak_key_size().is_ok());
        assert!(context_info.get_ak_local_identifier_str().is_ok());
        assert!(context_info.get_ak_public_key_as_base64().is_ok());
        assert!(context_info.flush_context().is_ok());
    }
}
