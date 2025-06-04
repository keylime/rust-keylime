// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::permissions;

use keylime::{
    algorithms::{EncryptionAlgorithm, HashAlgorithm, SignAlgorithm},
    crypto::{hash, tss_pubkey_to_pem},
    error::{Error, Result},
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
