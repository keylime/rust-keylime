// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::algorithms::{EncryptionAlgorithm, HashAlgorithm, SignAlgorithm};
use crate::error::{Error, Result};
use crate::{permissions, tpm};
use log::*;
use openssl::{
    hash::{hash, MessageDigest},
    pkey::PKey,
    x509::X509,
};
use picky_asn1_x509::SubjectPublicKeyInfo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::convert::{TryFrom, TryInto};
use std::env;
use std::ffi::CString;
use std::fmt::Debug;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tss_esapi::structures::{Private, Public};
use tss_esapi::traits::Marshall;
use tss_esapi::utils::PublicKey;
use tss_esapi::{
    structures::PcrSlot, traits::UnMarshall, utils::TpmsContext,
};

/*
 * Constants and static variables
 */
pub const API_VERSION: &str = "v2.0";
pub const STUB_VTPM: bool = false;
pub const STUB_IMA: bool = true;
pub const TPM_DATA_PCR: usize = 16;
pub const IMA_PCR: usize = 10;
pub static RSA_PUBLICKEY_EXPORTABLE: &str = "rsa placeholder";
pub static IMA_ML: &str =
    "/sys/kernel/security/ima/ascii_runtime_measurements";
pub static MEASUREDBOOT_ML: &str =
    "/sys/kernel/security/tpm0/binary_bios_measurements";
pub static KEY: &str = "secret";
pub const AGENT_UUID_LEN: usize = 36;
pub const AUTH_TAG_LEN: usize = 96;
pub const AES_128_KEY_LEN: usize = 16;
pub const AES_256_KEY_LEN: usize = 32;
pub const AES_BLOCK_SIZE: usize = 16;

cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        // Secure mount of tpmfs (False is generally used for development environments)
        pub static MOUNT_SECURE: bool = false;

        pub(crate) fn ima_ml_path_get() -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-data")
                .join("ima")
                .join("ascii_runtime_measurements")
        }
    } else {
        pub static MOUNT_SECURE: bool = true;

        pub(crate) fn ima_ml_path_get() -> PathBuf {
            Path::new(IMA_ML).to_path_buf()
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct APIVersion {
    major: u32,
    minor: u32,
}

impl std::fmt::Display for APIVersion {
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

// a vector holding keys
pub type KeySet = Vec<SymmKey>;

// a key of len AES_128_KEY_LEN or AES_256_KEY_LEN
#[derive(Debug, Clone)]
pub struct SymmKey {
    bytes: Vec<u8>,
}

impl SymmKey {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub(crate) fn xor(&self, other: &Self) -> Result<Self> {
        if self.bytes().len() != other.bytes().len() {
            return Err(Error::Other(
                "cannot xor differing length slices".to_string(),
            ));
        }
        let mut outbuf = vec![0u8; self.bytes().len()];
        for (out, (x, y)) in outbuf
            .iter_mut()
            .zip(self.bytes().iter().zip(other.bytes()))
        {
            *out = x ^ y;
        }
        Ok(Self { bytes: outbuf })
    }
}

impl TryFrom<&[u8]> for SymmKey {
    type Error = String;

    fn try_from(v: &[u8]) -> std::result::Result<Self, Self::Error> {
        match v.len() {
            AES_128_KEY_LEN | AES_256_KEY_LEN => {
                Ok(SymmKey { bytes: v.to_vec() })
            }
            other => Err(format!(
                "key length {} does not correspond to valid GCM cipher",
                other
            )),
        }
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
    // Converting Public TPM key to PEM
    let key = SubjectPublicKeyInfo::try_from(ek_pub)?;
    let key_der = picky_asn1_der::to_vec(&key)?;
    let openssl_key = PKey::public_key_from_der(&key_der)?;
    let pem = openssl_key.public_key_to_pem()?;

    // Calculate the SHA-256 hash of the public key in PEM format
    let mut hash = hash(MessageDigest::sha256(), &pem)?;
    Ok(hex::encode(hash))
}
