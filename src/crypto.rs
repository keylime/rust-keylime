extern crate hex;
extern crate openssl;

// use super::*;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkcs5;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Signer;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Error as StdIOError;
use std::io::Read;
use std::string::String;

/*
 * Inputs: secret key
 *        message to sign
 * Output: signed HMAC result
 *
 * Sign message and return HMAC result string
 */
pub fn do_hmac(
    input_key: String,
    input_message: String,
) -> Result<String, KeylimeCryptoError> {
    let key = PKey::hmac(input_key.as_bytes())?;
    let message = input_message.as_bytes();
    let mut signer = Signer::new(MessageDigest::sha384(), &key)?;
    signer.update(message)?;
    let hmac = signer.sign_to_vec()?;
    Ok(to_hex_string(hmac))
}

/*
 * Input: path to PEM-encoded RSA public key
 * Output: OpenSSL RSA key object
 *
 * Import a PEM-encoded RSA public key and return a callable OpenSSL RSA key
 * object.
 */
pub fn rsa_import_pubkey(
    input_key_path: String,
) -> Result<Rsa<Public>, KeylimeCryptoError> {
    let mut key_buffer = vec![0; 1];
    let mut input_key = File::open(input_key_path)?;
    input_key.read_to_end(&mut key_buffer)?;
    Ok(Rsa::public_key_from_pem(&key_buffer)?)
}

/*
 * Input: desired key size
 * Output: OpenSSL RSA key object
 *
 * Randomly generate a callable OpenSSL RSA key object with desired key size.
 */
pub fn rsa_generate(
    key_size: u32,
) -> Result<Rsa<Private>, KeylimeCryptoError> {
    Ok(Rsa::generate(key_size)?)
}

/*
 * Inputs: OpenSSL RSA key
 *         ciphertext to be decrypted
 * Output: decrypted plaintext
 *
 * Take in an RSA-encrypted ciphertext and an RSA private key and decrypt the
 * ciphertext based on PKCS1 OAEP. Parameters match that of Python-Keylime.
 */
pub fn rsa_decrypt(
    private_key: Rsa<Private>,
    ciphertext: String,
) -> Result<String, KeylimeCryptoError> {
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
pub fn kdf(
    input_password: String,
    input_salt: String,
) -> Result<String, KeylimeCryptoError> {
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
 * KeylimeCryptoError: Custom error type to be thrown by functions in
 * crypto.rs. Wraps I/O errors and OpenSSL ErrorStack structs together into
 * one thing.
 */
#[derive(Debug)]
pub enum KeylimeCryptoError {
    IOError { details: String },
    OpenSSLError { stack: ErrorStack },
}

impl fmt::Display for KeylimeCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeylimeCryptoError::IOError { ref details } => {
                f.write_str(&format!("{:?}", details))
            }
            KeylimeCryptoError::OpenSSLError { ref stack } => {
                f.write_str(&format!("{:?}", stack))
            }
        }
    }
}

impl Error for KeylimeCryptoError {
    fn description(&self) -> &str {
        match *self {
            KeylimeCryptoError::IOError { ref details } => {
                ("Error reading file")
            }
            KeylimeCryptoError::OpenSSLError { ref stack } => {
                ("OpenSSL library error")
            }
        }
    }
}

impl From<ErrorStack> for KeylimeCryptoError {
    fn from(e: ErrorStack) -> Self {
        KeylimeCryptoError::OpenSSLError { stack: e }
    }
}

impl From<StdIOError> for KeylimeCryptoError {
    fn from(e: StdIOError) -> Self {
        KeylimeCryptoError::IOError {
            details: format!("{:?}", e),
        }
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;
    use openssl::sign::Verifier;

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
            mac.unwrap()
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
            key.unwrap()
        );
    }

    #[test]
    fn test_hmac_verification() {
        // Generate a keypair
        let keypair = Rsa::generate(2048).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();
        let data = b"hello, world!";
        let data2 = b"hola, mundo!";

        // Sign the data
        let mut signer =
            Signer::new(MessageDigest::sha256(), &keypair).unwrap();
        signer.update(data).unwrap();
        signer.update(data2).unwrap();
        let signature = signer.sign_to_vec().unwrap();

        // Verify the data
        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
        verifier.update(data).unwrap();
        verifier.update(data2).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }
}
