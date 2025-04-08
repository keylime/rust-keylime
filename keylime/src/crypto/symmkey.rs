// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

use crate::crypto::{AES_128_KEY_LEN, AES_256_KEY_LEN};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SymmKeyError {
    // Invalid key size for AES
    #[error("invalid AES key size: {0}")]
    InvalidKeySize(usize),

    // Incompatible sizes for XOR
    #[error("cannot XOR slices of different sizes")]
    XorIncompatibleSizes,
}

// a vector holding keys
pub type KeySet = Vec<SymmKey>;

// a key of len AES_128_KEY_LEN or AES_256_KEY_LEN
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymmKey {
    bytes: Vec<u8>,
}

impl SymmKey {
    pub fn xor(&self, other: &Self) -> Result<Self, SymmKeyError> {
        let my_bytes = self.as_ref();
        let other_bytes = other.as_ref();
        if my_bytes.len() != other_bytes.len() {
            return Err(SymmKeyError::XorIncompatibleSizes);
        }
        let mut outbuf = vec![0u8; my_bytes.len()];
        for (out, (x, y)) in
            outbuf.iter_mut().zip(my_bytes.iter().zip(other_bytes))
        {
            *out = x ^ y;
        }
        Ok(Self { bytes: outbuf })
    }
}

impl AsRef<[u8]> for SymmKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl TryFrom<&[u8]> for SymmKey {
    type Error = SymmKeyError;

    fn try_from(v: &[u8]) -> std::result::Result<Self, SymmKeyError> {
        match v.len() {
            AES_128_KEY_LEN | AES_256_KEY_LEN => {
                Ok(SymmKey { bytes: v.to_vec() })
            }
            other => Err(SymmKeyError::InvalidKeySize(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert() {
        let a_128: [u8; AES_128_KEY_LEN] = [0; AES_128_KEY_LEN];
        let a_256: [u8; AES_256_KEY_LEN] = [0; AES_256_KEY_LEN];
        let a_unknown: [u8; 127] = [0; 127];

        let r_128 = SymmKey::try_from(a_128.as_ref());
        assert!(r_128.is_ok());

        let r_256 = SymmKey::try_from(a_256.as_ref());
        assert!(r_256.is_ok());

        let r_unknown = SymmKey::try_from(a_unknown.as_ref());
        assert!(r_unknown.is_err());
    }

    #[test]
    fn test_xor() {
        // Input for 128 bits keys
        let a: [u8; AES_128_KEY_LEN] = [0xA0; AES_128_KEY_LEN];
        let b: [u8; AES_128_KEY_LEN] = [0x0A; AES_128_KEY_LEN];
        let axb: [u8; AES_128_KEY_LEN] = [0xAA; AES_128_KEY_LEN];
        let r_128 =
            SymmKey::try_from(axb.as_ref()).expect("failed to convert");

        // Input for 256 bits keys
        let c: [u8; AES_256_KEY_LEN] = [0xA0; AES_256_KEY_LEN];
        let d: [u8; AES_256_KEY_LEN] = [0x0A; AES_256_KEY_LEN];
        let cxd: [u8; AES_256_KEY_LEN] = [0xAA; AES_256_KEY_LEN];
        let r_256 =
            SymmKey::try_from(cxd.as_ref()).expect("failed to convert");

        // Test for each set of inputs
        for (i, j, expected) in [
            (a.as_ref(), b.as_ref(), &r_128),
            (c.as_ref(), d.as_ref(), &r_256),
        ] {
            let k_i =
                SymmKey::try_from(i).expect("failed to get key from slice");
            let k_j =
                SymmKey::try_from(j).expect("failed to get key from slice");
            let result = k_i.xor(&k_j);
            assert!(result.is_ok());

            let out = result.expect("xor failed");
            assert_eq!(&out, expected);
        }
    }
}
