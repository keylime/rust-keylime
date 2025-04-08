// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::{
    error::{Error, Result},
    permissions,
};

use keylime::algorithms::{
    EncryptionAlgorithm, HashAlgorithm, SignAlgorithm,
};
use keylime::{
    crypto::{hash, tss_pubkey_to_pem},
    tpm,
};
use log::*;
use openssl::hash::MessageDigest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    convert::{Into, TryFrom, TryInto},
    env,
    ffi::CString,
    fmt::{self, Debug, Display},
    fs::File,
    path::{Path, PathBuf},
    str::FromStr,
};
use tss_esapi::structures::{Private, Public};
use tss_esapi::traits::Marshall;
use tss_esapi::utils::PublicKey;
use tss_esapi::{
    structures::PcrSlot, traits::UnMarshall, utils::TpmsContext,
};

/*
 * Constants and static variables
 */
pub const AUTH_TAG_LEN: usize = 48;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct APIVersion {
    major: u32,
    minor: u32,
}

impl Display for APIVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}", self.major, self.minor)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct JsonWrapper<A> {
    pub code: u16,
    pub status: String,
    pub results: A,
}

impl JsonWrapper<Value> {
    pub(crate) fn error(
        code: u16,
        status: impl ToString,
    ) -> JsonWrapper<Value> {
        JsonWrapper {
            code,
            status: status.to_string(),
            results: json!({}),
        }
    }
}

impl<'de, A> JsonWrapper<A>
where
    A: Deserialize<'de> + Serialize + Debug,
{
    pub(crate) fn success(results: A) -> JsonWrapper<A> {
        JsonWrapper {
            code: 200,
            status: String::from("Success"),
            results,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTag {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for AuthTag {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl TryFrom<&[u8]> for AuthTag {
    type Error = String;

    fn try_from(v: &[u8]) -> std::result::Result<Self, Self::Error> {
        match v.len() {
            AUTH_TAG_LEN => {
                Ok(AuthTag { bytes: v.to_vec() })
            }
            other => Err(format!(
                "auth tag length {other} does not correspond to valid SHA-384 HMAC",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedData {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for EncryptedData {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl From<&[u8]> for EncryptedData {
    fn from(v: &[u8]) -> Self {
        EncryptedData { bytes: v.to_vec() }
    }
}

impl From<Vec<u8>> for EncryptedData {
    fn from(v: Vec<u8>) -> Self {
        EncryptedData { bytes: v }
    }
}

// TPM data and agent related that can be persisted and loaded on agent startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AgentData {
    pub ak_hash_alg: HashAlgorithm,
    pub ak_sign_alg: SignAlgorithm,
    ak_public: Vec<u8>,
    ak_private: Vec<u8>,
    ek_hash: Vec<u8>,
}

impl AgentData {
    pub(crate) fn create(
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

    pub(crate) fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let data: Self = serde_json::from_reader(file)?;
        Ok(data)
    }

    pub(crate) fn store(&self, path: &Path) -> Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    pub(crate) fn get_ak(&self) -> Result<tpm::AKResult> {
        let public = Public::unmarshall(&self.ak_public)?;
        let private = Private::try_from(self.ak_private.clone())?;

        Ok(tpm::AKResult { public, private })
    }

    pub(crate) fn valid(
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

/// Calculate the SHA-256 hash of the TPM public key in PEM format
///
/// This is used as the agent UUID when the configuration option 'uuid' is set as 'hash_ek'
pub(crate) fn hash_ek_pubkey(ek_pub: Public) -> Result<String> {
    // Calculate the SHA-256 hash of the public key in PEM format
    let pem = tss_pubkey_to_pem(ek_pub)?;
    let hash = hash(&pem, MessageDigest::sha256())?;
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeylimeConfig;
    use keylime::algorithms::{
        EncryptionAlgorithm, HashAlgorithm, SignAlgorithm,
    };
    use std::convert::TryFrom;
    use tss_esapi::{
        handles::KeyHandle,
        interface_types::algorithm::AsymmetricAlgorithm,
        interface_types::resource_handles::Hierarchy,
        structures::{Auth, PublicBuffer},
        traits::Marshall,
        Context,
    };

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_agent_data() -> Result<()> {
        let _mutex = tpm::testing::lock_tests().await;
        let mut config = KeylimeConfig::default();

        let mut ctx = tpm::Context::new()?;

        let tpm_encryption_alg = EncryptionAlgorithm::try_from(
            config.agent.tpm_encryption_alg.as_str(),
        )?;

        let tpm_hash_alg =
            HashAlgorithm::try_from(config.agent.tpm_hash_alg.as_str())
                .expect("Failed to get hash algorithm");

        let tpm_signing_alg =
            SignAlgorithm::try_from(config.agent.tpm_signing_alg.as_str())
                .expect("Failed to get signing algorithm");

        let ek_result = ctx
            .create_ek(tpm_encryption_alg, None)
            .expect("Failed to create EK");

        let ek_hash =
            hash_ek_pubkey(ek_result.public).expect("Failed to get pubkey");

        let ak = ctx.create_ak(
            ek_result.key_handle,
            tpm_hash_alg,
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
        ctx.flush_context(ak_handle.into());
        ctx.flush_context(ek_result.key_handle.into());

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_hash() -> Result<()> {
        let _mutex = tpm::testing::lock_tests().await;
        let mut config = KeylimeConfig::default();

        let mut ctx = tpm::Context::new()?;

        let tpm_encryption_alg = EncryptionAlgorithm::try_from(
            config.agent.tpm_encryption_alg.as_str(),
        )
        .expect("Failed to get encryption algorithm");

        let ek_result = ctx
            .create_ek(tpm_encryption_alg, None)
            .expect("Failed to create EK");

        let result = hash_ek_pubkey(ek_result.public);

        assert!(result.is_ok());

        // Cleanup created keys
        ctx.flush_context(ek_result.key_handle.into());

        Ok(())
    }
}
