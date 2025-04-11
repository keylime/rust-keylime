// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypted_data_as_ref() {
        let a = EncryptedData {
            bytes: vec![0x0A, 16],
        };

        let r = a.as_ref();
        assert_eq!(r, vec![0x0A, 16]);
    }

    #[test]
    fn test_encrypted_data_from_slice() {
        let a: [u8; 16] = [0x0B; 16];
        let expected = EncryptedData {
            bytes: vec![0x0B; 16],
        };

        let r = EncryptedData::from(a.as_ref());

        assert_eq!(r, expected);
    }

    #[test]
    fn test_encrypted_data_from_vec() {
        let a: Vec<u8> = vec![0x0C; 16];
        let expected = EncryptedData {
            bytes: vec![0x0C; 16],
        };

        let r = EncryptedData::from(a);

        assert_eq!(r, expected);
    }
}
