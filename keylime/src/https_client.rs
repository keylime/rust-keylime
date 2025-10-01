use anyhow::{Context, Result};
use std::{
    fs::{self, File},
    io::Read,
    time::Duration,
};

pub struct ClientArgs {
    pub ca_certificate: String,
    pub certificate: String,
    pub key: String,
    pub insecure: Option<bool>,
    pub timeout: u64,
    /// Accept invalid TLS hostnames (INSECURE - for testing only)
    pub accept_invalid_hostnames: bool,
}

pub fn get_https_client(args: &ClientArgs) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connection_verbose(true)
        .timeout(Duration::from_millis(args.timeout));

    if args.insecure.unwrap_or(false) {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        // Get CA certificate from file
        let mut buf = Vec::new();
        File::open(args.ca_certificate.clone())
            .context(format!(
                "Failed to open '{}' file",
                args.ca_certificate
            ))?
            .read_to_end(&mut buf)
            .context(format!(
                "Failed to read '{}' to the end",
                args.ca_certificate
            ))?;
        let ca_cert =
            reqwest::Certificate::from_pem(&buf).context(format!(
                "Failed to parse certificate from PEM file '{}'",
                args.ca_certificate
            ))?;

        // Get client key and certificate from files
        let cert = fs::read(args.certificate.clone()).context(format!(
            "Failed to read client certificate from file '{}'",
            args.certificate
        ))?;
        let key = fs::read(args.key.clone()).context(format!(
            "Failed to read key from file '{}'",
            args.key
        ))?;
        let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key)
            .context(format!(
            "Failed to add client identity from certificate '{}' and key '{}'",
            args.certificate,
            args.key
        ))?;

        builder = builder
            .add_root_certificate(ca_cert)
            .identity(identity)
            .danger_accept_invalid_hostnames(args.accept_invalid_hostnames);
    }
    builder.build().context("Failed to create HTTPS client")
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use std::io::Write;

    // Helper to generate test certificates
    fn generate_test_certificates(
        temp_dir: &std::path::Path,
    ) -> (String, String, String) {
        let ca_path = temp_dir.join("ca.pem");
        let cert_path = temp_dir.join("cert.pem");
        let key_path = temp_dir.join("key.pem");

        // Generate CA certificate
        let ca_key = crypto::testing::rsa_generate(2048)
            .expect("Failed to generate CA key");
        let ca_cert = crypto::x509::CertificateBuilder::new()
            .private_key(&ca_key)
            .common_name("Test HTTPS CA")
            .build()
            .expect("Failed to build CA cert");

        // Generate client certificate
        let client_key = crypto::testing::rsa_generate(2048)
            .expect("Failed to generate client key");
        let client_cert = crypto::x509::CertificateBuilder::new()
            .private_key(&client_key)
            .common_name("test-https-client")
            .build()
            .expect("Failed to build client cert");

        // Write CA certificate
        let mut ca_file =
            File::create(&ca_path).expect("Failed to create CA file");
        ca_file
            .write_all(
                &ca_cert.to_pem().expect("Failed to convert CA to PEM"),
            )
            .expect("Failed to write CA cert");

        // Write client certificate
        let mut cert_file =
            File::create(&cert_path).expect("Failed to create cert file");
        cert_file
            .write_all(
                &client_cert.to_pem().expect("Failed to convert cert to PEM"),
            )
            .expect("Failed to write cert");

        // Write client key
        let mut key_file =
            File::create(&key_path).expect("Failed to create key file");
        key_file
            .write_all(
                &client_key
                    .private_key_to_pem_pkcs8()
                    .expect("Failed to convert key to PEM"),
            )
            .expect("Failed to write key");

        (
            ca_path.to_string_lossy().to_string(),
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        )
    }

    #[test]
    fn test_get_https_client_with_valid_certs() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, cert_path, key_path) =
            generate_test_certificates(tmpdir.path());

        let args = ClientArgs {
            ca_certificate: ca_path,
            certificate: cert_path,
            key: key_path,
            insecure: Some(false),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(
            result.is_ok(),
            "Failed to create HTTPS client with valid certs"
        );
    }

    #[test]
    fn test_get_https_client_insecure_mode() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, cert_path, key_path) =
            generate_test_certificates(tmpdir.path());

        let args = ClientArgs {
            ca_certificate: ca_path,
            certificate: cert_path,
            key: key_path,
            insecure: Some(true),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(
            result.is_ok(),
            "Failed to create HTTPS client in insecure mode"
        );
    }

    #[test]
    fn test_get_https_client_missing_ca_cert() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");

        let args = ClientArgs {
            ca_certificate: tmpdir
                .path()
                .join("nonexistent_ca.pem")
                .to_string_lossy()
                .to_string(),
            certificate: tmpdir
                .path()
                .join("cert.pem")
                .to_string_lossy()
                .to_string(),
            key: tmpdir.path().join("key.pem").to_string_lossy().to_string(),
            insecure: Some(false),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(result.is_err(), "Should fail with missing CA certificate");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to open")
                || err_msg.contains("nonexistent_ca.pem"),
            "Error should mention missing CA file"
        );
    }

    #[test]
    fn test_get_https_client_missing_client_cert() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, _, _) = generate_test_certificates(tmpdir.path());

        let args = ClientArgs {
            ca_certificate: ca_path,
            certificate: tmpdir
                .path()
                .join("nonexistent_cert.pem")
                .to_string_lossy()
                .to_string(),
            key: tmpdir.path().join("key.pem").to_string_lossy().to_string(),
            insecure: Some(false),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(
            result.is_err(),
            "Should fail with missing client certificate"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to read client certificate")
                || err_msg.contains("nonexistent_cert.pem"),
            "Error should mention missing client cert"
        );
    }

    #[test]
    fn test_get_https_client_missing_client_key() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, cert_path, _) =
            generate_test_certificates(tmpdir.path());

        let args = ClientArgs {
            ca_certificate: ca_path,
            certificate: cert_path,
            key: tmpdir
                .path()
                .join("nonexistent_key.pem")
                .to_string_lossy()
                .to_string(),
            insecure: Some(false),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(result.is_err(), "Should fail with missing client key");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to read key")
                || err_msg.contains("nonexistent_key.pem"),
            "Error should mention missing key file"
        );
    }

    #[test]
    fn test_get_https_client_invalid_ca_cert() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (_, cert_path, key_path) =
            generate_test_certificates(tmpdir.path());

        // Create invalid CA cert file
        let invalid_ca_path = tmpdir.path().join("invalid_ca.pem");
        let mut invalid_ca_file =
            File::create(&invalid_ca_path).expect("Failed to create file");
        invalid_ca_file
            .write_all(b"INVALID CERTIFICATE DATA")
            .expect("Failed to write");

        let args = ClientArgs {
            ca_certificate: invalid_ca_path.to_string_lossy().to_string(),
            certificate: cert_path,
            key: key_path,
            insecure: Some(false),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(result.is_err(), "Should fail with invalid CA certificate");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to parse certificate"),
            "Error should mention certificate parsing failure"
        );
    }

    #[test]
    fn test_get_https_client_invalid_client_identity() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, _, _) = generate_test_certificates(tmpdir.path());

        // Create invalid cert/key files
        let invalid_cert_path = tmpdir.path().join("invalid_cert.pem");
        let invalid_key_path = tmpdir.path().join("invalid_key.pem");

        let mut invalid_cert_file =
            File::create(&invalid_cert_path).expect("Failed to create file");
        invalid_cert_file
            .write_all(b"INVALID CERT")
            .expect("Failed to write");

        let mut invalid_key_file =
            File::create(&invalid_key_path).expect("Failed to create file");
        invalid_key_file
            .write_all(b"INVALID KEY")
            .expect("Failed to write");

        let args = ClientArgs {
            ca_certificate: ca_path,
            certificate: invalid_cert_path.to_string_lossy().to_string(),
            key: invalid_key_path.to_string_lossy().to_string(),
            insecure: Some(false),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(result.is_err(), "Should fail with invalid client identity");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to add client identity"),
            "Error should mention identity creation failure"
        );
    }

    #[test]
    fn test_get_https_client_with_different_timeouts() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, cert_path, key_path) =
            generate_test_certificates(tmpdir.path());

        // Test with various timeout values
        for timeout in [0, 1000, 5000, 30000, 300000] {
            let args = ClientArgs {
                ca_certificate: ca_path.clone(),
                certificate: cert_path.clone(),
                key: key_path.clone(),
                insecure: Some(false),
                timeout,
            };

            let result = get_https_client(&args);
            assert!(
                result.is_ok(),
                "Should create client with timeout {}ms",
                timeout
            );
        }
    }

    #[test]
    fn test_get_https_client_insecure_default() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, cert_path, key_path) =
            generate_test_certificates(tmpdir.path());

        // Test with insecure = None (should default to false)
        let args = ClientArgs {
            ca_certificate: ca_path,
            certificate: cert_path,
            key: key_path,
            insecure: None,
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(
            result.is_ok(),
            "Should create client with insecure=None (defaults to secure)"
        );
    }

    #[test]
    fn test_get_https_client_empty_ca_cert_path() {
        let args = ClientArgs {
            ca_certificate: "".to_string(),
            certificate: "cert.pem".to_string(),
            key: "key.pem".to_string(),
            insecure: Some(false),
            timeout: 5000,
        };

        let result = get_https_client(&args);
        assert!(result.is_err(), "Should fail with empty CA cert path");
    }
}
