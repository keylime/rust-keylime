use anyhow::{Context, Result};
use std::{fs::File, io::Read, time::Duration};

/// Arguments for creating a TLS client (server verification only).
/// Used by push model agent for verifier and registrar communication.
pub struct TlsClientArgs {
    pub ca_certificate: String,
    pub insecure: Option<bool>,
    pub timeout: u64,
    /// Accept invalid TLS hostnames (INSECURE - for testing only)
    pub accept_invalid_hostnames: bool,
}

/// Creates an HTTPS client with server verification only (no client certificate).
/// Used by push model for verifier and registrar communication where PoP
/// authentication is used instead of mTLS.
pub fn get_tls_client(args: &TlsClientArgs) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connection_verbose(true)
        .timeout(Duration::from_millis(args.timeout));

    if args.insecure.unwrap_or(false) {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        // Get CA certificate from file
        let mut buf = Vec::new();
        File::open(&args.ca_certificate)
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

        builder = builder
            .add_root_certificate(ca_cert)
            .danger_accept_invalid_hostnames(args.accept_invalid_hostnames);
    }
    builder.build().context("Failed to create TLS client")
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tls_client_with_valid_ca_cert() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, _server_cert, _server_key, _cert_path, _key_path) =
            crate::crypto::testing::generate_tls_certs_for_test(
                tmpdir.path(),
            );

        let args = TlsClientArgs {
            ca_certificate: ca_path.to_string_lossy().to_string(),
            insecure: Some(false),
            timeout: 5000,
            accept_invalid_hostnames: true,
        };

        let result = get_tls_client(&args);
        assert!(
            result.is_ok(),
            "Failed to create TLS client with valid CA cert"
        );
    }

    #[test]
    fn test_get_tls_client_insecure_mode() {
        let args = TlsClientArgs {
            ca_certificate: "nonexistent.pem".to_string(),
            insecure: Some(true),
            timeout: 5000,
            accept_invalid_hostnames: true,
        };

        let result = get_tls_client(&args);
        assert!(
            result.is_ok(),
            "Should create client in insecure mode without valid CA"
        );
    }

    #[test]
    fn test_get_tls_client_missing_ca_cert() {
        let args = TlsClientArgs {
            ca_certificate: "/nonexistent/path/ca.pem".to_string(),
            insecure: Some(false),
            timeout: 5000,
            accept_invalid_hostnames: true,
        };

        let result = get_tls_client(&args);
        assert!(result.is_err(), "Should fail with missing CA certificate");
    }

    #[test]
    fn test_get_tls_client_with_different_timeouts() {
        let tmpdir = tempfile::tempdir().expect("Failed to create tempdir");
        let (ca_path, _server_cert, _server_key, _cert_path, _key_path) =
            crate::crypto::testing::generate_tls_certs_for_test(
                tmpdir.path(),
            );

        for timeout in [0, 1000, 5000, 30000] {
            let args = TlsClientArgs {
                ca_certificate: ca_path.to_string_lossy().to_string(),
                insecure: Some(false),
                timeout,
                accept_invalid_hostnames: true,
            };

            let result = get_tls_client(&args);
            assert!(
                result.is_ok(),
                "Should create client with timeout {}ms",
                timeout
            );
        }
    }
}
