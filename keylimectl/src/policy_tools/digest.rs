// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! File digest calculation for policy generation.

#![allow(dead_code)] // Used in later implementation steps

use crate::commands::error::PolicyGenerationError;
use openssl::hash::{Hasher, MessageDigest};
use std::io::Read;
use std::path::Path;

/// Calculate the digest of a file using the specified algorithm.
///
/// Returns the digest as bare lowercase hex (e.g., `"abcdef1234..."`).
pub fn calculate_file_digest(
    path: &Path,
    algorithm: &str,
) -> Result<String, PolicyGenerationError> {
    let md = algorithm_to_message_digest(algorithm)?;

    let mut file = std::fs::File::open(path).map_err(|e| {
        PolicyGenerationError::Digest {
            path: path.to_path_buf(),
            reason: format!("Failed to open file: {e}"),
        }
    })?;

    let mut hasher =
        Hasher::new(md).map_err(|e| PolicyGenerationError::Digest {
            path: path.to_path_buf(),
            reason: format!("Failed to create hasher: {e}"),
        })?;

    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            PolicyGenerationError::Digest {
                path: path.to_path_buf(),
                reason: format!("Failed to read file: {e}"),
            }
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]).map_err(|e| {
            PolicyGenerationError::Digest {
                path: path.to_path_buf(),
                reason: format!("Hash update failed: {e}"),
            }
        })?;
    }

    let digest =
        hasher.finish().map_err(|e| PolicyGenerationError::Digest {
            path: path.to_path_buf(),
            reason: format!("Hash finalize failed: {e}"),
        })?;

    Ok(hex::encode(digest))
}

/// Map algorithm name string to OpenSSL MessageDigest.
pub fn algorithm_to_message_digest(
    algorithm: &str,
) -> Result<MessageDigest, PolicyGenerationError> {
    match algorithm {
        "sha1" => Ok(MessageDigest::sha1()),
        "sha256" => Ok(MessageDigest::sha256()),
        "sha384" => Ok(MessageDigest::sha384()),
        "sha512" => Ok(MessageDigest::sha512()),
        "sm3_256" | "sm3" => Ok(MessageDigest::sm3()),
        _ => Err(PolicyGenerationError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_calculate_file_digest_sha256() {
        let mut f = NamedTempFile::new().unwrap(); //#[allow_ci]
        f.write_all(b"hello world\n").unwrap(); //#[allow_ci]
        f.flush().unwrap(); //#[allow_ci]

        let result = calculate_file_digest(f.path(), "sha256").unwrap(); //#[allow_ci]

        // sha256 of "hello world\n" — bare hex, 64 chars
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_calculate_file_digest_sha1() {
        let mut f = NamedTempFile::new().unwrap(); //#[allow_ci]
        f.write_all(b"test").unwrap(); //#[allow_ci]
        f.flush().unwrap(); //#[allow_ci]

        let result = calculate_file_digest(f.path(), "sha1").unwrap(); //#[allow_ci]

        // sha1 of "test" — bare hex
        assert_eq!(result, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
    }

    #[test]
    fn test_calculate_file_digest_empty_file() {
        let f = NamedTempFile::new().unwrap(); //#[allow_ci]

        let result = calculate_file_digest(f.path(), "sha256").unwrap(); //#[allow_ci]

        // sha256 of empty string — bare hex
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_unsupported_algorithm() {
        let f = NamedTempFile::new().unwrap(); //#[allow_ci]

        let result = calculate_file_digest(f.path(), "md5");

        assert!(result.is_err());
    }

    #[test]
    fn test_nonexistent_file() {
        let result =
            calculate_file_digest(Path::new("/nonexistent/file"), "sha256");

        assert!(result.is_err());
    }

    #[test]
    fn test_algorithm_to_message_digest() {
        assert!(algorithm_to_message_digest("sha1").is_ok());
        assert!(algorithm_to_message_digest("sha256").is_ok());
        assert!(algorithm_to_message_digest("sha384").is_ok());
        assert!(algorithm_to_message_digest("sha512").is_ok());
        assert!(algorithm_to_message_digest("sm3_256").is_ok());
        assert!(algorithm_to_message_digest("sm3").is_ok());
        assert!(algorithm_to_message_digest("md5").is_err());
    }
}
