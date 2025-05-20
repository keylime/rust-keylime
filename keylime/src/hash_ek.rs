use crate::keylime_error::Result;
use openssl::hash::MessageDigest;
use tss_esapi::structures::Public;

use crate::crypto::{hash, tss_pubkey_to_pem};

/// Calculate the SHA-256 hash of the TPM public key in PEM format
///
/// This is used as the agent UUID when the configuration option 'uuid' is set as 'hash_ek'
pub fn hash_ek_pubkey(ek_pub: Public) -> Result<String> {
    // Calculate the SHA-256 hash of the public key in PEM format
    let pem = tss_pubkey_to_pem(ek_pub)?;
    let hash = hash(&pem, MessageDigest::sha256())?;
    Ok(hex::encode(hash))
}
