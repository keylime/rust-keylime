// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! TLS certificate diagnostic information.
//!
//! Validates TLS certificate files, checks expiration, and verifies
//! certificate/key pairing. No network calls required.

use log::debug;
use openssl::pkey::PKey;
use openssl::x509::X509;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use crate::config;
use crate::error::KeylimectlError;
use crate::output::OutputHandler;

/// Execute the `info tls` subcommand.
pub fn execute(_output: &OutputHandler) -> Result<Value, KeylimectlError> {
    let cfg = config::singleton::get_config();

    let mut issues: Vec<String> = Vec::new();
    let mut suggestions: Vec<String> = Vec::new();

    let tls_config = json!({
        "verify_server_cert": cfg.tls.verify_server_cert,
        "enable_agent_mtls": cfg.tls.enable_agent_mtls,
    });

    // Inspect client certificate
    let client_cert_info = cfg
        .tls
        .client_cert
        .as_ref()
        .map(|path| {
            inspect_certificate(
                path,
                &mut issues,
                &mut suggestions,
            )
        })
        .unwrap_or_else(|| {
            if cfg.tls.enable_agent_mtls {
                suggestions.push(
                    "enable_agent_mtls is true but no client certificate is configured".to_string(),
                );
            }
            json!({ "configured": false })
        });

    // Inspect client key
    let client_key_info = cfg
        .tls
        .client_key
        .as_ref()
        .map(|path| inspect_key(path, &mut issues))
        .unwrap_or_else(|| {
            if cfg.tls.client_cert.is_some() {
                issues.push(
                    "Client certificate is configured but client key is missing".to_string(),
                );
            }
            json!({ "configured": false })
        });

    // Verify cert/key pairing
    let cert_key_match =
        match (cfg.tls.client_cert.as_ref(), cfg.tls.client_key.as_ref()) {
            (Some(cert_path), Some(key_path)) => {
                verify_cert_key_pair(cert_path, key_path, &mut issues)
            }
            _ => None,
        };

    // Inspect trusted CA certificates
    let trusted_ca_info: Vec<Value> = cfg
        .tls
        .trusted_ca
        .iter()
        .map(|path| inspect_certificate(path, &mut issues, &mut suggestions))
        .collect();

    let mut certificates = json!({
        "client_cert": client_cert_info,
        "client_key": client_key_info,
    });

    if let Some(matches) = cert_key_match {
        certificates["cert_key_match"] = json!(matches);
    }

    if !trusted_ca_info.is_empty() {
        certificates["trusted_ca"] = Value::Array(trusted_ca_info);
    }

    Ok(json!({
        "tls_config": tls_config,
        "certificates": certificates,
        "issues": issues,
        "suggestions": suggestions,
    }))
}

/// Inspect a certificate file and return diagnostic information.
fn inspect_certificate(
    path: &str,
    issues: &mut Vec<String>,
    suggestions: &mut Vec<String>,
) -> Value {
    let p = Path::new(path);

    if !p.exists() {
        issues.push(format!("Certificate file not found: {path}"));
        return json!({
            "path": path,
            "exists": false,
        });
    }

    let pem_data = match fs::read(p) {
        Ok(data) => data,
        Err(e) => {
            issues.push(format!("Cannot read certificate file {path}: {e}"));
            return json!({
                "path": path,
                "exists": true,
                "readable": false,
                "error": e.to_string(),
            });
        }
    };

    let cert = match X509::from_pem(&pem_data) {
        Ok(cert) => cert,
        Err(e) => {
            issues.push(format!("Invalid PEM certificate {path}: {e}"));
            return json!({
                "path": path,
                "exists": true,
                "readable": true,
                "valid_pem": false,
                "error": e.to_string(),
            });
        }
    };

    let subject = x509_name_to_string(cert.subject_name());
    let issuer = x509_name_to_string(cert.issuer_name());
    let not_after = cert.not_after().to_string();
    let not_before = cert.not_before().to_string();

    // Calculate days until expiry
    let days_until_expiry = {
        let now = openssl::asn1::Asn1Time::days_from_now(0);
        match now {
            Ok(now) => {
                let diff = now.diff(cert.not_after());
                match diff {
                    Ok(diff) => Some(diff.days),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    };

    // Check for expiration issues
    if let Some(days) = days_until_expiry {
        if days < 0 {
            issues.push(format!(
                "Certificate {path} has EXPIRED ({} days ago)",
                -days
            ));
        } else if days <= 30 {
            suggestions
                .push(format!("Certificate {path} expires in {days} days"));
        }
    }

    let mut info = json!({
        "path": path,
        "exists": true,
        "readable": true,
        "valid_pem": true,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "status": "ok",
    });

    if let Some(days) = days_until_expiry {
        info["days_until_expiry"] = json!(days);
        if days < 0 {
            info["status"] = json!("expired");
        } else if days <= 30 {
            info["status"] = json!("expiring_soon");
        }
    }

    info
}

/// Convert an X509 name to a human-readable string.
fn x509_name_to_string(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("??");
            let value = entry
                .data()
                .as_utf8()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "??".to_string());
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Inspect a private key file.
fn inspect_key(path: &str, issues: &mut Vec<String>) -> Value {
    let p = Path::new(path);

    if !p.exists() {
        issues.push(format!("Key file not found: {path}"));
        return json!({
            "path": path,
            "exists": false,
        });
    }

    let pem_data = match fs::read(p) {
        Ok(data) => data,
        Err(e) => {
            issues.push(format!("Cannot read key file {path}: {e}"));
            return json!({
                "path": path,
                "exists": true,
                "readable": false,
                "error": e.to_string(),
            });
        }
    };

    // Try parsing as PEM private key
    match PKey::private_key_from_pem(&pem_data) {
        Ok(_) => json!({
            "path": path,
            "exists": true,
            "readable": true,
            "valid_pem": true,
        }),
        Err(e) => {
            debug!("Failed to parse key {path}: {e}");
            issues.push(format!("Invalid PEM private key {path}: {e}"));
            json!({
                "path": path,
                "exists": true,
                "readable": true,
                "valid_pem": false,
                "error": e.to_string(),
            })
        }
    }
}

/// Verify that a certificate and key file match.
fn verify_cert_key_pair(
    cert_path: &str,
    key_path: &str,
    issues: &mut Vec<String>,
) -> Option<bool> {
    let cert_data = fs::read(cert_path).ok()?;
    let key_data = fs::read(key_path).ok()?;

    let cert = X509::from_pem(&cert_data).ok()?;
    let key = PKey::private_key_from_pem(&key_data).ok()?;

    let cert_pubkey = match cert.public_key() {
        Ok(pk) => pk,
        Err(_) => return None,
    };

    let matches = cert_pubkey.public_eq(&key);

    if !matches {
        issues.push(format!(
            "Client certificate ({cert_path}) and key ({key_path}) do not match"
        ));
    }

    Some(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Generate a self-signed certificate and key pair for testing.
    fn generate_test_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{X509NameBuilder, X509};

        let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");
        let key = PKey::from_rsa(rsa).expect("Failed to create PKey");

        let mut name_builder =
            X509NameBuilder::new().expect("Failed to create X509NameBuilder");
        let _ = name_builder.append_entry_by_text("CN", "test-keylimectl");
        let name = name_builder.build();

        let mut builder =
            X509::builder().expect("Failed to create X509 builder");
        let _ = builder.set_version(2);
        let _ = builder.set_subject_name(&name);
        let _ = builder.set_issuer_name(&name);
        let _ = builder.set_pubkey(&key);

        let not_before =
            Asn1Time::days_from_now(0).expect("Failed to create not_before");
        let not_after =
            Asn1Time::days_from_now(365).expect("Failed to create not_after");
        let _ = builder.set_not_before(&not_before);
        let _ = builder.set_not_after(&not_after);

        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&builder.x509v3_context(None, None))
            .expect("Failed to build SAN");
        let _ = builder.append_extension(san);

        let _ = builder.sign(&key, MessageDigest::sha256());
        let cert = builder.build();

        let cert_pem = cert.to_pem().expect("Failed to serialize cert");
        let key_pem = key
            .private_key_to_pem_pkcs8()
            .expect("Failed to serialize key");

        (cert_pem, key_pem)
    }

    #[test]
    fn test_inspect_certificate_not_found() {
        let mut issues = Vec::new();
        let mut suggestions = Vec::new();
        let info = inspect_certificate(
            "/nonexistent/cert.pem",
            &mut issues,
            &mut suggestions,
        );
        assert_eq!(info["exists"], false);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("not found"));
    }

    #[test]
    fn test_inspect_certificate_valid() {
        let (cert_pem, _) = generate_test_cert_and_key();

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        tmpfile.write_all(&cert_pem).unwrap(); //#[allow_ci]

        let mut issues = Vec::new();
        let mut suggestions = Vec::new();
        let info = inspect_certificate(
            tmpfile.path().to_str().unwrap(), //#[allow_ci]
            &mut issues,
            &mut suggestions,
        );

        assert_eq!(info["exists"], true);
        assert_eq!(info["readable"], true);
        assert_eq!(info["valid_pem"], true);
        assert_eq!(info["status"], "ok");
        assert!(info["subject"]
            .as_str()
            .unwrap() //#[allow_ci]
            .contains("test-keylimectl"));
        assert!(issues.is_empty());
    }

    #[test]
    fn test_inspect_certificate_invalid_pem() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        tmpfile.write_all(b"not a certificate").unwrap(); //#[allow_ci]

        let mut issues = Vec::new();
        let mut suggestions = Vec::new();
        let info = inspect_certificate(
            tmpfile.path().to_str().unwrap(), //#[allow_ci]
            &mut issues,
            &mut suggestions,
        );

        assert_eq!(info["valid_pem"], false);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("Invalid PEM"));
    }

    #[test]
    fn test_inspect_key_not_found() {
        let mut issues = Vec::new();
        let info = inspect_key("/nonexistent/key.pem", &mut issues);
        assert_eq!(info["exists"], false);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_inspect_key_valid() {
        let (_, key_pem) = generate_test_cert_and_key();

        let mut tmpfile = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        tmpfile.write_all(&key_pem).unwrap(); //#[allow_ci]

        let mut issues = Vec::new();
        let info = inspect_key(tmpfile.path().to_str().unwrap(), &mut issues); //#[allow_ci]

        assert_eq!(info["exists"], true);
        assert_eq!(info["readable"], true);
        assert_eq!(info["valid_pem"], true);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_verify_cert_key_pair_matching() {
        let (cert_pem, key_pem) = generate_test_cert_and_key();

        let mut cert_file = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        cert_file.write_all(&cert_pem).unwrap(); //#[allow_ci]

        let mut key_file = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        key_file.write_all(&key_pem).unwrap(); //#[allow_ci]

        let mut issues = Vec::new();
        let result = verify_cert_key_pair(
            cert_file.path().to_str().unwrap(), //#[allow_ci]
            key_file.path().to_str().unwrap(),  //#[allow_ci]
            &mut issues,
        );

        assert_eq!(result, Some(true));
        assert!(issues.is_empty());
    }

    #[test]
    fn test_verify_cert_key_pair_mismatched() {
        let (cert_pem, _) = generate_test_cert_and_key();
        let (_, other_key_pem) = generate_test_cert_and_key();

        let mut cert_file = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        cert_file.write_all(&cert_pem).unwrap(); //#[allow_ci]

        let mut key_file = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        key_file.write_all(&other_key_pem).unwrap(); //#[allow_ci]

        let mut issues = Vec::new();
        let result = verify_cert_key_pair(
            cert_file.path().to_str().unwrap(), //#[allow_ci]
            key_file.path().to_str().unwrap(),  //#[allow_ci]
            &mut issues,
        );

        assert_eq!(result, Some(false));
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("do not match"));
    }

    #[test]
    fn test_verify_cert_key_pair_missing_files() {
        let mut issues = Vec::new();
        let result = verify_cert_key_pair(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            &mut issues,
        );
        assert_eq!(result, None);
    }
}
