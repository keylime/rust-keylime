// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

// use super::*;
use openssl::hash::MessageDigest;
use openssl::pkcs5;
use openssl::pkey::{Id, PKey, PKeyRef, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fs;
use std::io::Read;
use std::string::String;

use crate::{Error, Result};

/*
 * Inputs: secret key
 *        message to sign
 * Output: signed HMAC result
 *
 * Sign message and return HMAC result string
 */
pub(crate) fn do_hmac(
    input_key: String,
    input_message: String,
) -> Result<String> {
    let key = PKey::hmac(input_key.as_bytes())?;
    let message = input_message.as_bytes();
    let mut signer = Signer::new(MessageDigest::sha384(), &key)?;
    signer.update(message)?;
    let hmac = signer.sign_to_vec()?;
    Ok(to_hex_string(hmac))
}

// Reads an X509 cert chain (provided by the tenant with the --cert command) and outputs
// its public key.
pub(crate) fn import_x509(input_key_path: String) -> Result<PKey<Public>> {
    let contents = fs::read_to_string(&input_key_path[..])?;
    let mut cert_chain = X509::stack_from_pem(contents.as_bytes())?;

    if cert_chain.len() != 1 {
        return Err(Error::Other(
            "More than one public key provided in revocation cert"
                .to_string(),
        ));
    }

    let cert = cert_chain.pop().unwrap(); //#[allow_ci]
    cert.public_key().map_err(Error::Crypto)
}

pub(crate) fn rsa_generate(key_size: u32) -> Result<PKey<Private>> {
    PKey::from_rsa(Rsa::generate(key_size)?).map_err(Error::Crypto)
}

pub(crate) fn rsa_generate_pair(
    key_size: u32,
) -> Result<(PKey<Public>, PKey<Private>)> {
    let private = rsa_generate(key_size)?;
    let public = pkey_pub_from_priv(private.clone())?;
    Ok((public, private))
}

pub(crate) fn pkey_pub_from_priv(
    privkey: PKey<Private>,
) -> Result<PKey<Public>> {
    match privkey.id() {
        Id::RSA => {
            let rsa = Rsa::from_public_components(
                privkey.rsa()?.n().to_owned()?,
                privkey.rsa()?.e().to_owned()?,
            )
            .map_err(Error::Crypto)?;
            PKey::from_rsa(rsa).map_err(Error::Crypto)
        }
        id => {
            return Err(Error::Other(format!(
                "pkey_pub_from_priv not yet implemented for key type {:?}",
                id
            )));
        }
    }
}

/*
 * Inputs: OpenSSL RSA key
 *         ciphertext to be decrypted
 * Output: decrypted plaintext
 *
 * Take in an RSA-encrypted ciphertext and an RSA private key and decrypt the
 * ciphertext based on PKCS1 OAEP. Parameters match that of Python-Keylime.
 */
pub(crate) fn rsa_decrypt(
    private_key: Rsa<Private>,
    ciphertext: String,
) -> Result<String> {
    let mut dec_result = vec![0; private_key.size() as usize];
    let dec_len = private_key.private_decrypt(
        ciphertext.as_bytes(),
        &mut dec_result,
        Padding::PKCS1,
    )?;
    Ok(to_hex_string(dec_result[..dec_len].to_vec()))
}

/*
 * Inputs: password to derive key
 *         shared salt
 * Output: derived key
 *
 * Take in a password and shared salt, and derive a key based on the
 * PBKDF2-HMAC key derivation function. Parameters match that of
 * Python-Keylime.
 *
 * NOTE: This uses SHA-1 as the KDF's hash function in order to match the
 * implementation of PBKDF2 in the Python version of Keylime. PyCryptodome's
 * PBKDF2 function defaults to SHA-1 unless otherwise specified, and
 * Python-Keylime uses this default.
 */
pub(crate) fn kdf(
    input_password: String,
    input_salt: String,
) -> Result<String> {
    let password = input_password.as_bytes();
    let salt = input_salt.as_bytes();
    let count = 2000;
    // PyCryptodome's PBKDF2 binding allows key length to be specified
    // explicitly as a parameter; here, key length is implicitly defined in
    // the length of the 'key' variable.
    let mut key = [0; 32];
    pkcs5::pbkdf2_hmac(
        password,
        salt,
        count,
        MessageDigest::sha1(),
        &mut key,
    )?;
    Ok(to_hex_string(key.to_vec()))
}

/*
 * Input: bytes data
 * Output: hex string representation of bytes
 *
 * Convert a byte data to a hex representation
 */
fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> =
        bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
}

/*
 * Input: Trusted public key, and remote message and signature
 * Output: true if they are verified, otherwise false
 *
 * Verify a remote message and signature against a local rsa cert
 */
pub(crate) fn asym_verify(
    keypair: &PKeyRef<Public>,
    message: &str,
    signature: &str,
) -> Result<bool> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), keypair)?;
    verifier.update(message.as_bytes())?;
    Ok(verifier.verify(signature.as_bytes())?)
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    // compare with the result from python output
    #[test]
    fn test_do_hmac() {
        let key = String::from("mysecret");
        let message = String::from("hellothere");
        let mac = do_hmac(key, message);
        assert_eq!(
            format!(
                "{}{}",
                "b8558314f515931c8d9b329805978fe77b9bb020b05406c0e",
                "f189d89846ff8f5f0ca10e387d2c424358171df7f896f9f"
            ),
            mac.unwrap() //#[allow_ci]
        );
    }

    // Test KDF to ensure derived password matches result derived from Python
    // functions.
    #[test]
    fn test_kdf() {
        let password = String::from("myverysecretsecret");
        let salt = String::from("thesaltiestsalt");
        let key = kdf(password, salt);
        assert_eq!(
            "8a6de415abb8b27de5c572c8137bd14e5658395f9a2346e0b1ad8b9d8b9028af"
                .to_string(),
            key.unwrap() //#[allow_ci]
        );
    }

    #[test]
    fn test_hmac_verification() {
        // Generate a keypair
        let keypair = Rsa::generate(2048).unwrap(); //#[allow_ci]
        let keypair = PKey::from_rsa(keypair).unwrap(); //#[allow_ci]
        let data = b"hello, world!";
        let data2 = b"hola, mundo!";

        // Sign the data
        let mut signer =
            Signer::new(MessageDigest::sha256(), &keypair).unwrap(); //#[allow_ci]
        signer.update(data).unwrap(); //#[allow_ci]
        signer.update(data2).unwrap(); //#[allow_ci]
        let signature = signer.sign_to_vec().unwrap(); //#[allow_ci]

        // Verify the data
        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &keypair).unwrap(); //#[allow_ci]
        verifier.update(data).unwrap(); //#[allow_ci]
        verifier.update(data2).unwrap(); //#[allow_ci]
        assert!(verifier.verify(&signature).unwrap()); //#[allow_ci]
    }
}
