// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

use crate::crypto::AUTH_TAG_LEN;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthTagError {
    // Invalid authentication tag size
    #[error("auth tag length {0} does not correspond to valid SHA-384 HMAC")]
    InvalidAuthTagSize(usize),
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
    type Error = AuthTagError;

    fn try_from(v: &[u8]) -> std::result::Result<Self, Self::Error> {
        match v.len() {
            AUTH_TAG_LEN => Ok(AuthTag { bytes: v.to_vec() }),
            _ => Err(AuthTagError::InvalidAuthTagSize(v.len())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert() {
        let a: [u8; AUTH_TAG_LEN] = [0xAA; AUTH_TAG_LEN];
        let invalid: [u8; 32] = [0xBB; 32];

        let r = AuthTag::try_from(a.as_ref());
        assert!(r.is_ok());

        let r = AuthTag::try_from(invalid.as_ref());
        assert!(r.is_err());
    }
}
