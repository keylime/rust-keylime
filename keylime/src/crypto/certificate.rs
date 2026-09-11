// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Keylime Authors

use log::*;
use openssl::{
    pkey::{Id, PKey, Private, Public},
    ssl::SslAcceptorBuilder,
    x509::X509,
};
use std::{fs, path::Path};

use crate::{
    algorithms::EncryptionAlgorithm,
    config::KeylimeConfigError,
    crypto::{self, x509::CertificateBuilder, CryptoError},
    error::Error,
    list_parser::parse_list,
};

/// Configuration parameters needed to initialize or load agent mTLS credentials.
#[derive(Debug, Clone)]
pub struct MtlsConfig<'a> {
    pub enable_agent_mtls: bool,
    pub server_key: &'a Path,
    pub server_key_password: &'a str,
    pub server_cert: &'a str,
    pub agent_uuid: &'a str,
    pub contact_ip: &'a str,
    pub trusted_client_ca: &'a str,
}

/// Context containing loaded or generated mTLS credentials and TLS acceptor context.
pub struct MtlsContext {
    pub cert: Option<X509>,
    pub priv_key: PKey<Private>,
    pub pub_key: PKey<Public>,
    pub ssl_context: Option<SslAcceptorBuilder>,
}

/// Copies an existing RSA server key to the payload key path if no payload key
/// exists yet, preserving backward compatibility where a single RSA key was used
/// for both mTLS and payload encryption.
///
/// Returns `Ok(())` when the copy succeeds or when a copy is not needed
/// (key already exists, server key missing, or server key is not RSA).
/// Returns `Err` if the server key is a valid RSA key but writing the
/// payload key file fails — continuing in that state could leave a
/// corrupt or insecure file behind.
pub fn ensure_payload_key(
    payload_key_path: &Path,
    payload_key_password: &str,
    server_key_path: &Path,
    server_key_password: &str,
) -> Result<(), Error> {
    if payload_key_path.exists() {
        return Ok(());
    }
    if !server_key_path.exists() {
        return Ok(());
    }

    match crypto::load_key_pair(server_key_path, Some(server_key_password)) {
        Ok((_, priv_key))
            if priv_key.id() == Id::RSA && priv_key.bits() >= 2048 =>
        {
            crypto::write_key_pair(
                &priv_key,
                payload_key_path,
                Some(payload_key_password),
            )
            .map_err(|e| {
                if matches!(e, CryptoError::IOSetPermissionError(_)) {
                    // The key was written successfully but chmod failed.
                    // Remove the file so the next startup retries the copy
                    // rather than loading a key with insecure permissions.
                    // The file did not exist before this call (checked above),
                    // so removal cannot delete pre-existing user data.
                    match fs::remove_file(payload_key_path) {
                        Ok(()) => {
                            error!(
                                "Wrote mTLS key to {} but failed to set \
                                 file permissions: {e}. The file has been \
                                 removed; the copy will be retried on next \
                                 startup.",
                                payload_key_path.display()
                            );
                        }
                        Err(rm_err) => {
                            error!(
                                "Wrote mTLS key to {} but failed to set \
                                 file permissions: {e}. Cleanup also failed: \
                                 {rm_err}. Remove the file manually before \
                                 restarting the agent to prevent loading a key \
                                 with insecure permissions.",
                                payload_key_path.display()
                            );
                        }
                    }
                } else {
                    error!(
                        "Failed to write mTLS key to {}: {e}. \
                         If a partial file was left behind, remove \
                         it manually before restarting the agent.",
                        payload_key_path.display()
                    );
                }
                Error::Crypto(e)
            })?;

            warn!(
                "Payload key not found; wrote mTLS key from {} to {} \
                 for backward compatibility. The same RSA key will \
                 be used for both mTLS and payload encryption.",
                server_key_path.display(),
                payload_key_path.display()
            );
            if !server_key_password.is_empty()
                && payload_key_password.is_empty()
            {
                warn!(
                    "mTLS key has a password set in the configuration \
                     file, but the payload key has no password set; \
                     the payload key was written with an empty password \
                     to match its configuration."
                );
            }
        }
        Ok(_) => {
            debug!(
                "Payload key not found and mTLS key in {} is not an RSA \
                 key with at least 2048 bits; generating a new payload key.",
                server_key_path.display()
            );
        }
        Err(e) => {
            debug!(
                "Could not load mTLS key from {} ({e}); \
                 generating a new payload key.",
                server_key_path.display()
            );
        }
    }

    Ok(())
}

/// Loads or generates an RSA key pair for secure transmission of u, v payload keys.
///
/// Ensures backward compatibility by copying an existing RSA server key if needed,
/// then loads or generates a persistent RSA key of at least 2048 bits.
pub fn load_or_generate_payload_key(
    payload_key_path: &Path,
    payload_key_password: &str,
    server_key_path: &Path,
    server_key_password: &str,
) -> Result<(PKey<Public>, PKey<Private>), Error> {
    ensure_payload_key(
        payload_key_path,
        payload_key_password,
        server_key_path,
        server_key_password,
    )?;

    let (payload_pub_key, payload_priv_key) = crypto::load_or_generate_key(
        payload_key_path,
        Some(payload_key_password),
        EncryptionAlgorithm::Rsa2048,
        false, // Don't validate key size (accept any RSA for backward compatibility)
    )
    .map_err(|e| {
        error!(
            "Failed to load or generate payload key from {}: {e}",
            payload_key_path.display()
        );
        Error::Configuration(KeylimeConfigError::Generic(format!(
            "Failed to load or generate payload key from {}: {e}",
            payload_key_path.display()
        )))
    })?;

    if payload_priv_key.id() != Id::RSA || payload_priv_key.bits() < 2048 {
        error!(
            "Payload key {} must be an RSA key of at least 2048 bits, \
             found {:?} with {} bits",
            payload_key_path.display(),
            payload_priv_key.id(),
            payload_priv_key.bits()
        );
        return Err(Error::Configuration(KeylimeConfigError::Generic(
            format!(
                "Payload key {} must be an RSA key of at least 2048 \
                 bits, found {:?} with {} bits",
                payload_key_path.display(),
                payload_priv_key.id(),
                payload_priv_key.bits()
            ),
        )));
    }

    Ok((payload_pub_key, payload_priv_key))
}

/// Sets up agent mTLS credentials and TLS context.
///
/// Loads or generates the server key (using ECC P-256 by default). If mTLS is enabled,
/// it loads an existing certificate or generates a new one, loads the trusted client CAs,
/// and builds the SSL acceptor context.
pub fn setup_mtls(config: &MtlsConfig<'_>) -> Result<MtlsContext, Error> {
    // Load or generate mTLS key pair (separate from payload keys)
    // The mTLS key is always persistent, stored at the configured path.
    // Uses ECC P-256 by default for better security and performance
    let (mtls_pub, mtls_priv) = crypto::load_or_generate_key(
        config.server_key,
        Some(config.server_key_password),
        EncryptionAlgorithm::Ecc256,
        false, // Don't validate algorithm for mTLS keys (for backward compatibility)
    )?;

    if !config.enable_agent_mtls {
        warn!("mTLS disabled, Tenant and Verifier will reach out to agent via HTTP");
        return Ok(MtlsContext {
            cert: None,
            priv_key: mtls_priv,
            pub_key: mtls_pub,
            ssl_context: None,
        });
    }

    let contact_ips = vec![config.contact_ip];
    let cert = match config.server_cert {
        "" => {
            debug!("The server_cert option was not set in the configuration file");

            CertificateBuilder::new()
                .private_key(&mtls_priv)
                .common_name(config.agent_uuid)
                .add_ips(contact_ips)
                .build()?
        }
        path => {
            let cert_path = Path::new(path);
            if cert_path.exists() {
                debug!(
                    "Loading existing mTLS certificate from {}",
                    cert_path.display()
                );
                crypto::load_x509_pem(cert_path)?
            } else {
                debug!("Generating new mTLS certificate");
                let cert = CertificateBuilder::new()
                    .private_key(&mtls_priv)
                    .common_name(config.agent_uuid)
                    .add_ips(contact_ips)
                    .build()?;
                // Write the generated certificate
                crypto::write_x509(&cert, cert_path)?;
                cert
            }
        }
    };

    let trusted_client_ca = match config.trusted_client_ca {
        "" => {
            error!(
                "Agent mTLS is enabled, but trusted_client_ca option was not provided"
            );
            return Err(Error::Configuration(KeylimeConfigError::Generic(
                "Agent mTLS is enabled, but trusted_client_ca option was not provided"
                    .to_string(),
            )));
        }
        l => l,
    };

    // The trusted_client_ca config option is a list, parse to obtain a vector
    let certs_list = parse_list(trusted_client_ca)?;
    if certs_list.is_empty() {
        error!(
            "Trusted client CA certificate list is empty: could not load any certificate"
        );
        return Err(Error::Configuration(KeylimeConfigError::Generic(
            "Trusted client CA certificate list is empty: could not load any certificate"
                .to_string(),
        )));
    }

    let keylime_ca_certs = match crypto::load_x509_cert_list(
        certs_list.iter().map(Path::new).collect(),
    ) {
        Ok(t) => Ok(t),
        Err(e) => {
            error!("Failed to load trusted CA certificates: {e:?}");
            Err(e)
        }
    }?;

    let ssl_context =
        crypto::generate_tls_context(&cert, &mtls_priv, keylime_ca_certs)?;

    Ok(MtlsContext {
        cert: Some(cert),
        priv_key: mtls_priv,
        pub_key: mtls_pub,
        ssl_context: Some(ssl_context),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::rsa::Rsa;
    use tempfile::TempDir;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn write_rsa_key(path: &Path, bits: u32, password: &str) -> Result<()> {
        let rsa = Rsa::generate(bits)?;
        let key = PKey::from_rsa(rsa)?;
        crypto::write_key_pair(&key, path, Some(password))?;
        Ok(())
    }

    fn write_ec_key(path: &Path, password: &str) -> Result<()> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec = EcKey::generate(&group)?;
        let key = PKey::from_ec_key(ec)?;
        crypto::write_key_pair(&key, path, Some(password))?;
        Ok(())
    }

    #[test]
    fn test_ensure_payload_key_copies_rsa2048() -> Result<()> {
        let dir = TempDir::new()?;
        let server = dir.path().join("server-private.pem");
        let payload = dir.path().join("payload-private.pem");

        write_rsa_key(&server, 2048, "")?;

        ensure_payload_key(&payload, "", &server, "")?;

        assert!(payload.exists());
        let (_, loaded) = crypto::load_key_pair(&payload, Some(""))?;
        assert_eq!(loaded.id(), Id::RSA);
        assert_eq!(loaded.bits(), 2048);
        Ok(())
    }

    #[test]
    fn test_ensure_payload_key_copies_rsa4096() -> Result<()> {
        let dir = TempDir::new()?;
        let server = dir.path().join("server-private.pem");
        let payload = dir.path().join("payload-private.pem");

        write_rsa_key(&server, 4096, "")?;

        ensure_payload_key(&payload, "", &server, "")?;

        assert!(payload.exists());
        let (_, loaded) = crypto::load_key_pair(&payload, Some(""))?;
        assert_eq!(loaded.id(), Id::RSA);
        assert_eq!(loaded.bits(), 4096);
        Ok(())
    }

    #[test]
    fn test_ensure_payload_key_skips_when_exists() -> Result<()> {
        let dir = TempDir::new()?;
        let server = dir.path().join("server-private.pem");
        let payload = dir.path().join("payload-private.pem");

        write_rsa_key(&server, 2048, "")?;
        write_rsa_key(&payload, 2048, "")?;

        let before = fs::read(&payload)?;
        ensure_payload_key(&payload, "", &server, "")?;
        let after = fs::read(&payload)?;

        assert_eq!(before, after);
        Ok(())
    }

    #[test]
    fn test_ensure_payload_key_skips_non_rsa() -> Result<()> {
        let dir = TempDir::new()?;
        let server = dir.path().join("server-private.pem");
        let payload = dir.path().join("payload-private.pem");

        write_ec_key(&server, "")?;

        ensure_payload_key(&payload, "", &server, "")?;

        assert!(!payload.exists());
        Ok(())
    }

    #[test]
    fn test_load_or_generate_payload_key_success() -> Result<()> {
        let dir = TempDir::new()?;
        let server = dir.path().join("server-private.pem");
        let payload = dir.path().join("payload-private.pem");

        let (pub_k, priv_k) =
            load_or_generate_payload_key(&payload, "", &server, "")?;

        assert!(payload.exists());
        assert_eq!(priv_k.id(), Id::RSA);
        assert!(priv_k.bits() >= 2048);
        assert_eq!(pub_k.id(), Id::RSA);
        Ok(())
    }

    #[test]
    fn test_setup_mtls_disabled() -> Result<()> {
        let dir = TempDir::new()?;
        let server = dir.path().join("server-private.pem");

        let config = MtlsConfig {
            enable_agent_mtls: false,
            server_key: &server,
            server_key_password: "",
            server_cert: "",
            agent_uuid: "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
            contact_ip: "127.0.0.1",
            trusted_client_ca: "",
        };

        let ctx = setup_mtls(&config)?;
        assert!(ctx.cert.is_none());
        assert!(ctx.ssl_context.is_none());
        assert!(server.exists());
        Ok(())
    }

    #[test]
    fn test_setup_mtls_enabled_generate_cert() -> Result<()> {
        let dir = TempDir::new()?;
        let server_key = dir.path().join("server-private.pem");
        let server_cert = dir.path().join("server-cert.pem");
        let ca_cert_path = dir.path().join("ca.pem");

        let group =
            openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let (_, ca_priv) = crypto::ecc_generate_pair(&group)?;
        let ca_cert = CertificateBuilder::new()
            .private_key(&ca_priv)
            .common_name("TestCA")
            .build()?;
        crypto::write_x509(&ca_cert, &ca_cert_path)?;

        let trusted_ca_str = format!("['{}']", ca_cert_path.display());
        let config = MtlsConfig {
            enable_agent_mtls: true,
            server_key: &server_key,
            server_key_password: "",
            server_cert: server_cert.to_str().unwrap(),
            agent_uuid: "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
            contact_ip: "127.0.0.1",
            trusted_client_ca: &trusted_ca_str,
        };

        let ctx = setup_mtls(&config)?;
        assert!(ctx.cert.is_some());
        assert!(ctx.ssl_context.is_some());
        assert!(server_key.exists());
        assert!(server_cert.exists());
        Ok(())
    }

    #[test]
    fn test_setup_mtls_missing_trusted_ca_errors() -> Result<()> {
        let dir = TempDir::new()?;
        let server_key = dir.path().join("server-private.pem");

        let config = MtlsConfig {
            enable_agent_mtls: true,
            server_key: &server_key,
            server_key_password: "",
            server_cert: "",
            agent_uuid: "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
            contact_ip: "127.0.0.1",
            trusted_client_ca: "",
        };

        let res = setup_mtls(&config);
        assert!(res.is_err());
        Ok(())
    }
}
