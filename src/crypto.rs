extern crate hex;
extern crate openssl;

// use super::*;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::string::String;

/*
 * Input: secret key
 *        message to signed
 * Output: signed mac result
 *
 * Sign message and return hmac mac string
 */
pub fn do_hmac(input_key: String, input_message: String) -> String {
    let key = PKey::hmac(input_key.as_bytes()).unwrap();
    let message = input_message.as_bytes();
    let mut signer = Signer::new(MessageDigest::sha384(), &key).unwrap();
    signer.update(message).unwrap();
    let hmac = signer.sign_to_vec().unwrap();
    return to_hex_string(hmac);
}

/*
 * Input: bytes data
 * Output: hex string represenatation of bytes
 *
 * Convert a byte data to a hex representation
 */
fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> =
        bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
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
        assert_eq!("b8558314f515931c8d9b329805978fe77b9bb020b05406c0ef189d89846ff8f5f0ca10e387d2c424358171df7f896f9f".to_string(), mac);
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
