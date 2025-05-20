use crate::algorithms::{HashAlgorithm, SignAlgorithm};
use crate::keylime_error::Result;
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
