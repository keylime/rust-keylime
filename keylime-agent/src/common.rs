// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use keylime::keylime_error::{Error, Result};

use crate::permissions;

use keylime::algorithms::{
    EncryptionAlgorithm, HashAlgorithm, SignAlgorithm,
};
use keylime::{
    crypto::{hash, tss_pubkey_to_pem},
    hash_ek, tpm,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeylimeConfig;
    use keylime::agent_data::AgentData;
    use keylime::algorithms::{
        EncryptionAlgorithm, HashAlgorithm, SignAlgorithm,
    };
    use keylime::hash_ek;
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
        ctx.flush_context(ak_handle.into());
        ctx.flush_context(ek_result.key_handle.into());

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_hash() -> Result<()> {
        use keylime::agent_data;
        use keylime::hash_ek;

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

        let result = hash_ek::hash_ek_pubkey(ek_result.public);

        assert!(result.is_ok());

        // Cleanup created keys
        ctx.flush_context(ek_result.key_handle.into());

        Ok(())
    }
}
