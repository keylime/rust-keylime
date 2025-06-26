use crate::algorithms::{HashAlgorithm, SignAlgorithm};
use crate::error::Result;
use crate::tpm;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use tss_esapi::structures::{Private, Public};
use tss_esapi::traits::{Marshall, UnMarshall};

// TPM data and agent related that can be persisted and loaded on agent startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentData {
    pub ak_hash_alg: HashAlgorithm,
    pub ak_sign_alg: SignAlgorithm,
    ak_public: Vec<u8>,
    ak_private: Vec<u8>,
    ek_hash: Vec<u8>,
}

impl AgentData {
    pub fn create(
        ak_hash_alg: HashAlgorithm,
        ak_sign_alg: SignAlgorithm,
        ak: &tpm::AKResult,
        ek_hash: &[u8],
    ) -> Result<Self> {
        let ak_public = ak.public.marshall()?;
        let ak_private: Vec<u8> = ak.private.to_vec();
        let ek_hash: Vec<u8> = ek_hash.to_vec();
        Ok(Self {
            ak_hash_alg,
            ak_sign_alg,
            ak_public,
            ak_private,
            ek_hash,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let data: Self = serde_json::from_reader(file)?;
        Ok(data)
    }

    pub fn store(&self, path: &Path) -> Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    pub fn get_ak(&self) -> Result<tpm::AKResult> {
        let public = Public::unmarshall(&self.ak_public)?;
        let private = Private::try_from(self.ak_private.clone())?;

        Ok(tpm::AKResult { public, private })
    }

    pub fn valid(
        &self,
        hash_alg: HashAlgorithm,
        sign_alg: SignAlgorithm,
        ek_hash: &[u8],
    ) -> bool {
        hash_alg == self.ak_hash_alg
            && sign_alg == self.ak_sign_alg
            && ek_hash.to_vec() == self.ek_hash
    }
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::{algorithms::EncryptionAlgorithm, config, hash_ek};

    #[tokio::test]
    async fn test_agent_data() -> Result<()> {
        let _mutex = tpm::testing::lock_tests().await;

        let tempdir =
            tempfile::tempdir().expect("failed to create temporary dir");
        let config = config::get_testing_config(tempdir.path());

        let mut ctx = tpm::Context::new().unwrap(); //#[allow_ci]

        let tpm_encryption_alg = EncryptionAlgorithm::try_from(
            config.tpm_encryption_alg.as_str(),
        )?;

        let tpm_hash_alg =
            HashAlgorithm::try_from(config.tpm_hash_alg.as_str())
                .expect("Failed to get hash algorithm");

        let tpm_signing_alg =
            SignAlgorithm::try_from(config.tpm_signing_alg.as_str())
                .expect("Failed to get signing algorithm");

        let ek_result = ctx
            .create_ek(tpm_encryption_alg, None)
            .expect("Failed to create EK");

        let ek_hash = hash_ek::hash_ek_pubkey(ek_result.public)
            .expect("Failed to get pubkey");

        let ak = ctx.create_ak(
            ek_result.key_handle,
            tpm_hash_alg,
            tpm_encryption_alg,
            tpm_signing_alg,
        )?;

        let agent_data_test = AgentData::create(
            tpm_hash_alg,
            tpm_signing_alg,
            &ak,
            ek_hash.as_bytes(),
        )?;

        let valid = AgentData::valid(
            &agent_data_test,
            tpm_hash_alg,
            tpm_signing_alg,
            ek_hash.as_bytes(),
        );

        assert!(valid);

        // Cleanup created keys
        let ak_handle = ctx.load_ak(ek_result.key_handle, &ak)?;
        _ = ctx.flush_context(ak_handle.into());
        _ = ctx.flush_context(ek_result.key_handle.into());

        Ok(())
    }

    #[tokio::test]
    async fn test_hash() -> Result<()> {
        let _mutex = tpm::testing::lock_tests().await;
        let tempdir =
            tempfile::tempdir().expect("failed to create temporary dir");
        let config = config::get_testing_config(tempdir.path());

        let mut ctx = tpm::Context::new().unwrap(); //#[allow_ci]

        let tpm_encryption_alg =
            EncryptionAlgorithm::try_from(config.tpm_encryption_alg.as_str())
                .expect("Failed to get encryption algorithm");

        let ek_result = ctx
            .create_ek(tpm_encryption_alg, None)
            .expect("Failed to create EK");

        let result = hash_ek::hash_ek_pubkey(ek_result.public);

        assert!(result.is_ok());

        // Cleanup created keys
        _ = ctx.flush_context(ek_result.key_handle.into());

        Ok(())
    }
}
