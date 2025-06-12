use crate::{crypto, error::Result};
use log::debug;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use std::path::Path;

pub struct CertificateConfig {
    pub agent_uuid: String,
    pub contact_ip: String,
    pub contact_port: u32,
    pub server_cert: String,
    pub server_key: String,
    pub server_key_password: String,
}

pub fn cert_from_server_key(
    config: &CertificateConfig,
) -> Result<(X509, PKey<Public>)> {
    let cert: X509;
    let (nk_pub, nk_priv) = match config.server_key.as_ref() {
        "" => {
            debug!(
                "The server_key option was not set in the configuration file"
            );
            debug!("Generating new key pair");
            crypto::rsa_generate_pair(2048)?
        }
        path => {
            let key_path = Path::new(&path);
            if key_path.exists() {
                debug!(
                    "Loading existing key pair from {}",
                    key_path.display()
                );
                crypto::load_key_pair(
                    key_path,
                    Some(&config.server_key_password),
                )?
            } else {
                debug!("Generating new key pair");
                let (public, private) = crypto::rsa_generate_pair(2048)?;
                // Write the generated key to the file
                crypto::write_key_pair(
                    &private,
                    key_path,
                    Some(&config.server_key_password),
                )?;
                (public, private)
            }
        }
    };

    let contact_ips = vec![config.contact_ip.as_str()];
    cert = match config.server_cert.as_ref() {
        "" => {
            debug!("The server_cert option was not set in the configuration file");

            crypto::x509::CertificateBuilder::new()
                .private_key(&nk_priv)
                .common_name(&config.agent_uuid)
                .add_ips(contact_ips)
                .build()?
        }
        path => {
            let cert_path = Path::new(&path);
            if cert_path.exists() {
                debug!(
                    "Loading existing mTLS certificate from {}",
                    cert_path.display()
                );
                crypto::load_x509_pem(cert_path)?
            } else {
                debug!("Generating new mTLS certificate");
                let cert = crypto::x509::CertificateBuilder::new()
                    .private_key(&nk_priv)
                    .common_name(&config.agent_uuid)
                    .add_ips(contact_ips)
                    .build()?;
                crypto::write_x509(&cert, cert_path)?;
                cert
            }
        }
    };
    Ok((cert, nk_pub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::CertificateConfig;

    #[test]
    fn test_cert_from_server_key() {
        const TEST_CERT_PATH: &str = "test_cert.pem";
        const TEST_KEY_PATH: &str = "test_key.pem";
        // Ensure the test cert file does not exist before the test
        let _ = std::fs::remove_file(TEST_CERT_PATH);
        let _ = std::fs::remove_file(TEST_KEY_PATH);
        let config = CertificateConfig {
            agent_uuid: "test-uuid".to_string(),
            contact_ip: "1.2.3.4".to_string(),
            contact_port: 8080,
            server_cert: TEST_CERT_PATH.to_string(),
            server_key: TEST_KEY_PATH.to_string(),
            server_key_password: "test_password".to_string(),
        };
        let result = cert_from_server_key(&config);
        assert!(result.is_ok());
        // Clean up the test cert file after the test
        let _ = std::fs::remove_file(TEST_CERT_PATH);
        let _ = std::fs::remove_file(TEST_KEY_PATH);
    } // test_cert_from_server_key

    #[test]
    fn test_cert_no_server_key() {
        const TEST_CERT_PATH: &str = "test_cert2.pem";
        // Ensure the test cert file does not exist before the test
        let _ = std::fs::remove_file(TEST_CERT_PATH);
        let config = CertificateConfig {
            agent_uuid: "test-uuid".to_string(),
            contact_ip: "1.2.3.4".to_string(),
            contact_port: 8080,
            server_cert: TEST_CERT_PATH.to_string(),
            server_key: "".to_string(),
            server_key_password: "test_password2".to_string(),
        };
        let result = cert_from_server_key(&config);
        assert!(result.is_ok());
        // Clean up the test cert file after the test
        let _ = std::fs::remove_file(TEST_CERT_PATH);
    } // test_cert_no_server_key

    #[test]
    fn test_cert_no_server_cert() {
        // Ensure the test cert file does not exist before the test
        const TEST_KEY_PATH: &str = "test_key.pem";
        let _ = std::fs::remove_file(TEST_KEY_PATH);
        let config = CertificateConfig {
            agent_uuid: "test-uuid".to_string(),
            contact_ip: "1.2.3.4".to_string(),
            contact_port: 8080,
            server_cert: "".to_string(),
            server_key: TEST_KEY_PATH.to_string(),
            server_key_password: "test_password".to_string(),
        };
        let result = cert_from_server_key(&config);
        assert!(result.is_ok());
        // Clean up the test key file after the test
        let _ = std::fs::remove_file(TEST_KEY_PATH);
    } // test_cert_no_server_cert

    #[test]
    fn test_cert_wrong_server_key_path() {
        let config = CertificateConfig {
            agent_uuid: "test-uuid".to_string(),
            contact_ip: "1.2.3.4".to_string(),
            contact_port: 8080,
            server_cert: "test_cert3.pem".to_string(),
            server_key: "/server/key/can/not/be/created/here".to_string(),
            server_key_password: "test_password3".to_string(),
        };
        let result = cert_from_server_key(&config);
        assert!(result.is_err());
    } // test_cert_wrong_server_key_path

    #[test]
    fn test_cert_correct_server_key_path() {
        const TEST_KEY_PATH: &str = "test_key2.pem";
        const TEST_CERT_PATH: &str = "test_cert4.pem";
        // Ensure the test key file does not exist before the test
        let _ = std::fs::remove_file(TEST_KEY_PATH);
        let _ = std::fs::remove_file(TEST_CERT_PATH);
        let config = CertificateConfig {
            agent_uuid: "test-uuid".to_string(),
            contact_ip: "1.2.3.4".to_string(),
            contact_port: 8080,
            server_cert: TEST_CERT_PATH.to_string(),
            server_key: TEST_KEY_PATH.to_string(),
            server_key_password: "test_password4".to_string(),
        };
        let result = cert_from_server_key(&config);
        assert!(result.is_ok());
        // Clean up files after the test
        let _ = std::fs::remove_file(TEST_KEY_PATH);
        let _ = std::fs::remove_file(TEST_CERT_PATH);
    } // test_cert_correct_server_key_path
}
