// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

/// Code ported from Hash_Algorithms at https://github.com/keylime/keylime/blob/master/keylime/tpm/tpm_abstract.py

#[derive(Debug)]
struct HashAlgorithms;

impl HashAlgorithms {
    const SHA1: &'static str = "sha1";
    const SHA256: &'static str = "sha256";
    const SHA384: &'static str = "sha384";
    const SHA512: &'static str = "sha512";

    fn is_recognized(algorithm: String) -> bool {
        if [
            HashAlgorithms::SHA1,
            HashAlgorithms::SHA256,
            HashAlgorithms::SHA384,
            HashAlgorithms::SHA512,
        ]
        .contains(&algorithm.as_str())
        {
            return true;
        }
        false
    }

    fn get_hash_size(algorithm: String) -> u16 {
        match algorithm.as_str() {
            HashAlgorithms::SHA1 => 160,
            HashAlgorithms::SHA256 => 256,
            HashAlgorithms::SHA384 => 384,
            HashAlgorithms::SHA512 => 512,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_is_recognized() {
        assert!(HashAlgorithms::is_recognized(String::from("sha256")));
        assert_eq!(
            HashAlgorithms::is_recognized(String::from("wubalubadubdub")),
            false
        );
    }

    #[test]
    fn test_get_hash_size() {
        assert_eq!(
            HashAlgorithms::get_hash_size(String::from("wubalubadubdub")),
            0
        );
        assert_eq!(HashAlgorithms::get_hash_size(String::from("sha1")), 160);
        assert_eq!(
            HashAlgorithms::get_hash_size(String::from("sha256")),
            256
        );
        assert_eq!(
            HashAlgorithms::get_hash_size(String::from("sha384")),
            384
        );
        assert_eq!(
            HashAlgorithms::get_hash_size(String::from("sha512")),
            512
        );
    }
}
