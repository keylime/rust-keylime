// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Legacy allowlist format conversion to v1 runtime policy.
//!
//! Converts JSON and flat-text allowlists (from the older Python
//! `keylime_create_allowlist` tool) into the v1 runtime policy format
//! used by `keylimectl`.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::ima_parser;
use crate::policy_tools::runtime_policy::RuntimePolicy;
use base64::Engine;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use std::path::Path;

/// Auto-detect the allowlist format and convert to a runtime policy.
///
/// Tries JSON first, then falls back to flat-text format.
pub fn convert_allowlist(
    input: &[u8],
) -> Result<RuntimePolicy, PolicyGenerationError> {
    // Try JSON first
    if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(input) {
        return convert_json_allowlist(&json_val);
    }

    // Fall back to flat-text
    let text = std::str::from_utf8(input).map_err(|e| {
        PolicyGenerationError::AllowlistParse {
            path: "<input>".into(),
            reason: format!("Input is not valid UTF-8: {e}"),
        }
    })?;

    convert_flat_allowlist(text)
}

/// Convert a JSON allowlist to a runtime policy.
///
/// Accepts the legacy format: `{"hashes": {"/path": ["digest"]}}`
/// or the newer: `{"digests": {"/path": ["algorithm:hex"]}}`.
pub fn convert_json_allowlist(
    json: &serde_json::Value,
) -> Result<RuntimePolicy, PolicyGenerationError> {
    let digests = ima_parser::parse_json_allowlist_value(json)?;

    let mut policy = RuntimePolicy::new();
    for (path, digest_list) in &digests {
        for digest in digest_list {
            policy.add_digest(path.clone(), digest.clone());
        }
    }

    Ok(policy)
}

/// Convert a flat-text allowlist to a runtime policy.
///
/// Format: one entry per line, each line is `hex_digest<whitespace>path`.
pub fn convert_flat_allowlist(
    text: &str,
) -> Result<RuntimePolicy, PolicyGenerationError> {
    let digests = ima_parser::parse_flat_allowlist_str(text)?;

    let mut policy = RuntimePolicy::new();
    for (path, digest_list) in &digests {
        for digest in digest_list {
            policy.add_digest(path.clone(), digest.clone());
        }
    }

    Ok(policy)
}

/// Merge an exclude list into a policy.
pub fn merge_excludelist(policy: &mut RuntimePolicy, excludes: &[String]) {
    for exclude in excludes {
        policy.add_exclude(exclude.clone());
    }
}

/// Try parsing file data as a public key using multiple format strategies.
///
/// Attempts (in order): DER x509 cert, PEM x509 cert, DER public key,
/// PEM public key, DER private key, PEM private key.
///
/// Returns the public key and an optional keyidv2 extracted from a
/// certificate's Subject Key Identifier extension.
fn extract_pubkey(
    data: &[u8],
) -> Result<(PKey<Public>, Option<u32>), PolicyGenerationError> {
    // DER x509 certificate
    if let Ok(cert) = X509::from_der(data) {
        let keyidv2 = keyidv2_from_cert(&cert);
        return Ok((
            cert.public_key()
                .map_err(|e| PolicyGenerationError::Output {
                    path: "<key>".into(),
                    reason: format!(
                        "Failed to extract public key from certificate: {e}"
                    ),
                })?,
            keyidv2,
        ));
    }

    // PEM x509 certificate
    if let Ok(cert) = X509::from_pem(data) {
        let keyidv2 = keyidv2_from_cert(&cert);
        return Ok((
            cert.public_key()
                .map_err(|e| PolicyGenerationError::Output {
                    path: "<key>".into(),
                    reason: format!(
                        "Failed to extract public key from certificate: {e}"
                    ),
                })?,
            keyidv2,
        ));
    }

    // DER public key
    if let Ok(pkey) = PKey::public_key_from_der(data) {
        return Ok((pkey, None));
    }

    // PEM public key
    if let Ok(pkey) = PKey::public_key_from_pem(data) {
        return Ok((pkey, None));
    }

    // DER private key — extract public part
    if let Ok(pkey) = PKey::private_key_from_der(data) {
        let pub_der = pkey.public_key_to_der().map_err(|e| {
            PolicyGenerationError::Output {
                path: "<key>".into(),
                reason: format!(
                    "Failed to extract public key from private key: {e}"
                ),
            }
        })?;
        return Ok((
            PKey::public_key_from_der(&pub_der).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<key>".into(),
                    reason: format!("Failed to load public key: {e}"),
                }
            })?,
            None,
        ));
    }

    // PEM private key — extract public part
    if let Ok(pkey) = PKey::private_key_from_pem(data) {
        let pub_der = pkey.public_key_to_der().map_err(|e| {
            PolicyGenerationError::Output {
                path: "<key>".into(),
                reason: format!(
                    "Failed to extract public key from private key: {e}"
                ),
            }
        })?;
        return Ok((
            PKey::public_key_from_der(&pub_der).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<key>".into(),
                    reason: format!("Failed to load public key: {e}"),
                }
            })?,
            None,
        ));
    }

    Err(PolicyGenerationError::Output {
        path: "<key>".into(),
        reason: "Could not parse file as any supported key or certificate format (DER/PEM x509, public key, or private key)".into(),
    })
}

/// Extract keyidv2 from a certificate's Subject Key Identifier extension.
fn keyidv2_from_cert(cert: &X509) -> Option<u32> {
    let skid = cert.subject_key_id()?;
    let digest = skid.as_slice();
    if digest.len() >= 4 {
        let last4 = &digest[digest.len() - 4..];
        Some(u32::from_be_bytes([last4[0], last4[1], last4[2], last4[3]]))
    } else {
        None
    }
}

/// Compute keyidv2 from a public key.
///
/// For RSA keys: SHA-1 of DER PKCS#1 public key bytes, last 4 bytes as
/// big-endian u32.
/// For EC keys: SHA-1 of the uncompressed point encoding, last 4 bytes
/// as big-endian u32.
fn compute_keyidv2(
    pkey: &PKey<Public>,
) -> Result<u32, PolicyGenerationError> {
    let pub_bytes = if pkey.id() == openssl::pkey::Id::RSA {
        let rsa = pkey.rsa().map_err(|e| PolicyGenerationError::Output {
            path: "<key>".into(),
            reason: format!("Failed to extract RSA key: {e}"),
        })?;
        rsa.public_key_to_der_pkcs1().map_err(|e| {
            PolicyGenerationError::Output {
                path: "<key>".into(),
                reason: format!("Failed to serialize RSA key to PKCS1: {e}"),
            }
        })?
    } else if pkey.id() == openssl::pkey::Id::EC {
        let ec =
            pkey.ec_key().map_err(|e| PolicyGenerationError::Output {
                path: "<key>".into(),
                reason: format!("Failed to extract EC key: {e}"),
            })?;
        let group = ec.group();
        let point = ec.public_key();
        let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| {
            PolicyGenerationError::Output {
                path: "<key>".into(),
                reason: format!("Failed to create BigNum context: {e}"),
            }
        })?;
        point
            .to_bytes(
                group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .map_err(|e| PolicyGenerationError::Output {
                path: "<key>".into(),
                reason: format!("Failed to serialize EC point: {e}"),
            })?
    } else {
        return Err(PolicyGenerationError::Output {
            path: "<key>".into(),
            reason: format!(
                "Unsupported key type for keyidv2 computation: {:?}",
                pkey.id()
            ),
        });
    };

    let mut hasher = Hasher::new(MessageDigest::sha1()).map_err(|e| {
        PolicyGenerationError::Output {
            path: "<key>".into(),
            reason: format!("Failed to create SHA-1 hasher: {e}"),
        }
    })?;
    hasher
        .update(&pub_bytes)
        .map_err(|e| PolicyGenerationError::Output {
            path: "<key>".into(),
            reason: format!("Failed to update SHA-1 hash: {e}"),
        })?;
    let digest =
        hasher.finish().map_err(|e| PolicyGenerationError::Output {
            path: "<key>".into(),
            reason: format!("Failed to finalize SHA-1 hash: {e}"),
        })?;

    let len = digest.len();
    let last4 = &digest[len - 4..];
    Ok(u32::from_be_bytes([last4[0], last4[1], last4[2], last4[3]]))
}

/// Add verification keys from a file to a policy.
///
/// Reads the file (binary-safe), auto-detects the format (DER/PEM ×
/// certificate/public key/private key), extracts the public key, and
/// stores it in the policy's `verification-keys` JSON structure:
///
/// ```json
/// {"pubkeys": ["base64-DER-SubjectPublicKeyInfo", ...], "keyids": [keyidv2, ...]}
/// ```
pub fn add_verification_keys(
    policy: &mut RuntimePolicy,
    key_path: &str,
) -> Result<(), PolicyGenerationError> {
    let data = std::fs::read(key_path).map_err(|e| {
        PolicyGenerationError::Output {
            path: key_path.into(),
            reason: format!("Failed to read verification key file: {e}"),
        }
    })?;

    let (pkey, cert_keyidv2) =
        extract_pubkey(&data).map_err(|e| PolicyGenerationError::Output {
            path: key_path.into(),
            reason: format!("Failed to parse key file '{key_path}': {e}"),
        })?;

    // Serialize the public key as DER SubjectPublicKeyInfo and
    // base64-encode.
    let spki_der = pkey.public_key_to_der().map_err(|e| {
        PolicyGenerationError::Output {
            path: key_path.into(),
            reason: format!("Failed to serialize public key to DER: {e}"),
        }
    })?;
    let pubkey_b64 =
        base64::engine::general_purpose::STANDARD.encode(&spki_der);

    // Determine keyidv2: prefer the value from a certificate's SKID,
    // fall back to computing from the raw public key bytes.
    let keyidv2 = match cert_keyidv2 {
        Some(id) => id,
        None => compute_keyidv2(&pkey).map_err(|e| {
            PolicyGenerationError::Output {
                path: key_path.into(),
                reason: format!(
                    "Failed to compute keyidv2 for '{key_path}': {e}"
                ),
            }
        })?,
    };

    // Parse existing verification-keys JSON or start fresh.
    let mut keyring: serde_json::Value =
        if policy.verification_keys.is_empty() {
            serde_json::json!({"pubkeys": [], "keyids": []})
        } else {
            serde_json::from_str(&policy.verification_keys).map_err(|e| {
                PolicyGenerationError::Output {
                    path: key_path.into(),
                    reason: format!(
                        "Failed to parse existing verification-keys JSON: {e}"
                    ),
                }
            })?
        };

    keyring["pubkeys"]
        .as_array_mut()
        .expect("pubkeys must be an array") //#[allow_ci]
        .push(serde_json::Value::String(pubkey_b64));
    keyring["keyids"]
        .as_array_mut()
        .expect("keyids must be an array") //#[allow_ci]
        .push(serde_json::Value::Number(keyidv2.into()));

    policy.verification_keys =
        serde_json::to_string(&keyring).map_err(|e| {
            PolicyGenerationError::Output {
                path: key_path.into(),
                reason: format!(
                    "Failed to serialize verification-keys JSON: {e}"
                ),
            }
        })?;

    Ok(())
}

/// Convert an allowlist file (auto-detect format) to a runtime policy.
pub fn convert_allowlist_file(
    path: &Path,
) -> Result<RuntimePolicy, PolicyGenerationError> {
    let content = std::fs::read(path).map_err(|e| {
        PolicyGenerationError::AllowlistParse {
            path: path.to_path_buf(),
            reason: format!("Failed to read file: {e}"),
        }
    })?;

    convert_allowlist(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::EcKey;
    use openssl::nid::Nid;
    use openssl::rsa::Rsa;
    use serde_json::json;

    #[test]
    fn test_convert_json_allowlist_hashes_key() {
        let json = json!({
            "hashes": {
                "/usr/bin/bash": ["sha256:aabbccdd"],
                "/usr/bin/ls": ["sha256:eeff0011", "sha1:aabb"]
            }
        });

        let policy = convert_json_allowlist(&json).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 2);
        // Algorithm prefix is stripped during conversion
        assert_eq!(policy.digests["/usr/bin/bash"], vec!["aabbccdd"]);
        assert_eq!(policy.digests["/usr/bin/ls"].len(), 2);
    }

    #[test]
    fn test_convert_json_allowlist_digests_key() {
        let json = json!({
            "digests": {
                "/usr/bin/test": ["sha256:1234"]
            }
        });

        let policy = convert_json_allowlist(&json).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 1);
    }

    #[test]
    fn test_convert_flat_allowlist() {
        let text =
            "sha256:aabb1122\t/usr/bin/bash\nsha256:ccdd3344\t/usr/bin/ls\n";

        let policy = convert_flat_allowlist(text).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 2);
        // Algorithm prefix is stripped during conversion
        assert_eq!(policy.digests["/usr/bin/bash"], vec!["aabb1122"]);
    }

    #[test]
    fn test_auto_detect_json() {
        let input = br#"{"hashes": {"/test": ["sha256:abcd"]}}"#;

        let policy = convert_allowlist(input).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 1);
    }

    #[test]
    fn test_auto_detect_flat() {
        let input = b"sha256:abcd\t/test\n";

        let policy = convert_allowlist(input).unwrap(); //#[allow_ci]
        assert_eq!(policy.digest_count(), 1);
    }

    #[test]
    fn test_merge_excludelist() {
        let mut policy = RuntimePolicy::new();
        merge_excludelist(
            &mut policy,
            &["/tmp/*".to_string(), "/proc/*".to_string()],
        );
        assert_eq!(policy.exclude_count(), 2);
    }

    #[test]
    fn test_merge_excludelist_dedup() {
        let mut policy = RuntimePolicy::new();
        policy.add_exclude("/tmp/*".to_string());
        merge_excludelist(
            &mut policy,
            &["/tmp/*".to_string(), "/proc/*".to_string()],
        );
        assert_eq!(policy.exclude_count(), 2);
    }

    fn generate_rsa_pem_keypair() -> (Vec<u8>, Vec<u8>) {
        let rsa = Rsa::generate(2048).expect("RSA key generation"); //#[allow_ci]
        let pkey = PKey::from_rsa(rsa).expect("PKey from RSA"); //#[allow_ci]
        let pub_pem = pkey.public_key_to_pem().expect("public PEM"); //#[allow_ci]
        let priv_pem = pkey.private_key_to_pem_pkcs8().expect("private PEM"); //#[allow_ci]
        (pub_pem, priv_pem)
    }

    fn generate_ec_pem_keypair() -> (Vec<u8>, Vec<u8>) {
        let group =
            openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .expect("EC group"); //#[allow_ci]
        let ec = EcKey::generate(&group).expect("EC key gen"); //#[allow_ci]
        let pkey = PKey::from_ec_key(ec).expect("PKey from EC"); //#[allow_ci]
        let pub_pem = pkey.public_key_to_pem().expect("public PEM"); //#[allow_ci]
        let priv_pem = pkey.private_key_to_pem_pkcs8().expect("private PEM"); //#[allow_ci]
        (pub_pem, priv_pem)
    }

    fn generate_self_signed_cert_pem() -> Vec<u8> {
        let rsa = Rsa::generate(2048).expect("RSA key gen"); //#[allow_ci]
        let pkey = PKey::from_rsa(rsa).expect("PKey from RSA"); //#[allow_ci]

        let mut builder = X509::builder().expect("X509 builder"); //#[allow_ci]
        builder.set_pubkey(&pkey).expect("set pubkey"); //#[allow_ci]
        let mut name =
            openssl::x509::X509Name::builder().expect("name builder"); //#[allow_ci]
        name.append_entry_by_nid(Nid::COMMONNAME, "test")
            .expect("CN"); //#[allow_ci]
        let name = name.build();
        builder.set_subject_name(&name).expect("subject"); //#[allow_ci]
        builder.set_issuer_name(&name).expect("issuer"); //#[allow_ci]
        builder
            .set_not_before(
                &openssl::asn1::Asn1Time::days_from_now(0)
                    .expect("not_before"), //#[allow_ci]
            )
            .expect("set not_before"); //#[allow_ci]
        builder
            .set_not_after(
                &openssl::asn1::Asn1Time::days_from_now(365)
                    .expect("not_after"), //#[allow_ci]
            )
            .expect("set not_after"); //#[allow_ci]

        // Add Subject Key Identifier extension
        let ctx = builder.x509v3_context(None, None);
        let skid = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&ctx)
            .expect("SKID"); //#[allow_ci]
        builder.append_extension(skid).expect("append SKID"); //#[allow_ci]

        builder.sign(&pkey, MessageDigest::sha256()).expect("sign"); //#[allow_ci]
        let cert = builder.build();
        cert.to_pem().expect("cert PEM") //#[allow_ci]
    }

    fn assert_valid_keyring(json_str: &str, expected_count: usize) {
        let v: serde_json::Value =
            serde_json::from_str(json_str).expect("valid JSON"); //#[allow_ci]
        let pubkeys = v["pubkeys"].as_array().expect("pubkeys array"); //#[allow_ci]
        let keyids = v["keyids"].as_array().expect("keyids array"); //#[allow_ci]
        assert_eq!(pubkeys.len(), expected_count);
        assert_eq!(keyids.len(), expected_count);
        for pk in pubkeys {
            assert!(pk.is_string());
            // Verify it's valid base64 that decodes to a DER SPKI key
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(pk.as_str().expect("string")) //#[allow_ci]
                .expect("base64 decode"); //#[allow_ci]
            let _key =
                PKey::public_key_from_der(&decoded).expect("valid SPKI DER"); //#[allow_ci]
        }
        for kid in keyids {
            assert!(kid.is_u64());
        }
    }

    #[test]
    fn test_add_verification_keys_rsa_pem_pubkey() {
        let (pub_pem, _) = generate_rsa_pem_keypair();
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &pub_pem).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 1);
    }

    #[test]
    fn test_add_verification_keys_rsa_der_pubkey() {
        let (pub_pem, _) = generate_rsa_pem_keypair();
        let pkey = PKey::public_key_from_pem(&pub_pem).unwrap(); //#[allow_ci]
        let der = pkey.public_key_to_der().unwrap(); //#[allow_ci]

        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &der).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 1);
    }

    #[test]
    fn test_add_verification_keys_rsa_pem_privkey() {
        let (_, priv_pem) = generate_rsa_pem_keypair();
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &priv_pem).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 1);
    }

    #[test]
    fn test_add_verification_keys_ec_pem_pubkey() {
        let (pub_pem, _) = generate_ec_pem_keypair();
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &pub_pem).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 1);
    }

    #[test]
    fn test_add_verification_keys_x509_cert_pem() {
        let cert_pem = generate_self_signed_cert_pem();
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &cert_pem).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 1);
    }

    #[test]
    fn test_add_verification_keys_x509_cert_der() {
        let cert_pem = generate_self_signed_cert_pem();
        let cert = X509::from_pem(&cert_pem).unwrap(); //#[allow_ci]
        let cert_der = cert.to_der().unwrap(); //#[allow_ci]

        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &cert_der).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 1);
    }

    #[test]
    fn test_add_verification_keys_multiple() {
        let (pub_pem1, _) = generate_rsa_pem_keypair();
        let (pub_pem2, _) = generate_ec_pem_keypair();
        let cert_pem = generate_self_signed_cert_pem();

        let tmp1 = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp1.path(), &pub_pem1).unwrap(); //#[allow_ci]
        let tmp2 = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp2.path(), &pub_pem2).unwrap(); //#[allow_ci]
        let tmp3 = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp3.path(), &cert_pem).unwrap(); //#[allow_ci]

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &tmp1.path().to_string_lossy())
            .unwrap(); //#[allow_ci]
        add_verification_keys(&mut policy, &tmp2.path().to_string_lossy())
            .unwrap(); //#[allow_ci]
        add_verification_keys(&mut policy, &tmp3.path().to_string_lossy())
            .unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 3);
    }

    #[test]
    fn test_add_verification_keys_der_privkey() {
        let (_, priv_pem) = generate_rsa_pem_keypair();
        let pkey = PKey::private_key_from_pem(&priv_pem).unwrap(); //#[allow_ci]
        let der = pkey.private_key_to_der().unwrap(); //#[allow_ci]

        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), &der).unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        add_verification_keys(&mut policy, &path).unwrap(); //#[allow_ci]
        assert_valid_keyring(&policy.verification_keys, 1);
    }

    #[test]
    fn test_add_verification_keys_nonexistent_file() {
        let mut policy = RuntimePolicy::new();
        let result =
            add_verification_keys(&mut policy, "/nonexistent/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_verification_keys_invalid_data() {
        let tmp = tempfile::NamedTempFile::new().unwrap(); //#[allow_ci]
        std::fs::write(tmp.path(), b"not a key at all").unwrap(); //#[allow_ci]
        let path = tmp.path().to_string_lossy().to_string();

        let mut policy = RuntimePolicy::new();
        let result = add_verification_keys(&mut policy, &path);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_nonexistent_file() {
        let result = convert_allowlist_file(Path::new("/nonexistent/file"));
        assert!(result.is_err());
    }
}
