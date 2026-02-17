// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! TPM attestation workflow for pull model (API < 3.0)
//!
//! This module contains the attestation functions used in the pull model
//! where the tenant communicates directly with the agent for TPM quote
//! verification and key exchange.

use super::helpers::load_payload_file;
use crate::client::agent::AgentClient;
use crate::client::factory;
use crate::client::registrar::RegistrarClient;
use crate::commands::error::CommandError;
use crate::output::OutputHandler;
use base64::{engine::general_purpose::STANDARD, Engine};
use keylime::crypto;
use log::debug;
#[cfg(not(feature = "tpm-quote-validation"))]
use log::warn;
use openssl::rand;
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// Validation result for TPM quote verification
#[derive(Debug)]
struct TpmQuoteValidation {
    is_valid: bool,
    nonce_verified: bool,
    aik_verified: bool,
    details: String,
}

/// Perform agent attestation for API < 3.0 (pull model)
///
/// This function implements the TPM quote verification process used in the
/// legacy pull model where the tenant communicates directly with the agent.
///
/// # Arguments
///
/// * `agent_client` - Client for communicating with the agent
/// * `agent_data` - Agent registration data from registrar
/// * `config` - Configuration containing cryptographic settings
/// * `output` - Output handler for progress reporting
///
/// # Returns
///
/// Returns attestation data including generated keys on success.
pub(super) async fn perform_agent_attestation(
    agent_client: &AgentClient,
    _agent_data: &Value,
    agent_id: &str,
    output: &OutputHandler,
) -> Result<Option<Value>, CommandError> {
    output.progress("Generating nonce for TPM quote");

    // Generate random nonce for quote freshness
    let nonce = generate_secure_nonce(20)?;
    debug!("Generated nonce for TPM quote: {nonce}");

    output.progress("Requesting TPM quote from agent");

    // Get TPM quote from agent
    let quote_response =
        agent_client.get_quote(&nonce).await.map_err(|e| {
            CommandError::agent_operation_failed(
                agent_id.to_string(),
                "get_tpm_quote",
                format!("Failed to get TPM quote: {e}"),
            )
        })?;

    debug!("Received quote response: {quote_response:?}");

    // Extract quote data
    let results = quote_response.get("results").ok_or_else(|| {
        CommandError::agent_operation_failed(
            agent_id.to_string(),
            "quote_validation",
            "Missing results in quote response",
        )
    })?;

    let quote =
        results
            .get("quote")
            .and_then(|q| q.as_str())
            .ok_or_else(|| {
                CommandError::agent_operation_failed(
                    agent_id.to_string(),
                    "quote_validation",
                    "Missing quote in response",
                )
            })?;

    let public_key = results
        .get("pubkey")
        .and_then(|pk| pk.as_str())
        .ok_or_else(|| {
            CommandError::agent_operation_failed(
                agent_id.to_string(),
                "quote_validation",
                "Missing public key in response",
            )
        })?;

    output.progress("Validating TPM quote");

    // Create registrar client for validation
    let registrar_client = factory::get_registrar().await.map_err(|e| {
        CommandError::resource_error("registrar", e.to_string())
    })?;

    // Implement structured TPM quote validation
    let validation_result = validate_tpm_quote(
        quote,
        public_key,
        &nonce,
        registrar_client,
        agent_id,
    )
    .await?;

    if !validation_result.is_valid {
        return Err(CommandError::agent_operation_failed(
            agent_id.to_string(),
            "tpm_quote_validation",
            format!(
                "TPM quote validation failed: {}",
                validation_result.details
            ),
        ));
    }

    let nonce_verified = validation_result.nonce_verified;
    let aik_verified = validation_result.aik_verified;
    output.info(format!(
        "TPM quote validation successful: nonce_verified={nonce_verified}, aik_verified={aik_verified}"
    ));

    output.progress("Generating cryptographic keys");

    // Generate U and V keys as random bytes (matching Keylime implementation)
    // Wrapped in Zeroizing to clear from memory on drop
    let mut u_key_bytes = Zeroizing::new([0u8; 32]); // AES-256 key length
    let mut v_key_bytes = Zeroizing::new([0u8; 32]); // AES-256 key length

    // Use OpenSSL's random bytes generator (same as Keylime)
    rand::rand_bytes(u_key_bytes.as_mut()).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to generate U key: {e}"),
        )
    })?;
    rand::rand_bytes(v_key_bytes.as_mut()).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to generate V key: {e}"),
        )
    })?;

    // Compute K key as XOR of U and V (as in Keylime)
    let mut k_key_bytes = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        k_key_bytes[i] = u_key_bytes[i] ^ v_key_bytes[i];
    }

    debug!("Generated U key: {} bytes", u_key_bytes.len());
    debug!("Generated V key: {} bytes", v_key_bytes.len());

    // Encrypt U key with agent's public key
    output.progress("Encrypting U key for agent");

    // Implement proper RSA encryption using agent's public key
    let encrypted_u =
        encrypt_u_key_with_agent_pubkey(u_key_bytes.as_ref(), public_key)?;
    let auth_tag =
        crypto::compute_hmac(k_key_bytes.as_ref(), agent_id.as_bytes())
            .map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to compute auth tag: {e}"),
                )
            })?;

    output.info("TPM quote verification completed successfully");

    Ok(Some(json!({
        "quote": quote,
        "public_key": public_key,
        "nonce": nonce,
        "u_key": STANDARD.encode(u_key_bytes.as_ref()),
        "v_key": STANDARD.encode(v_key_bytes.as_ref()),
        "k_key": STANDARD.encode(k_key_bytes.as_ref()),
        "encrypted_u": encrypted_u,
        "auth_tag": hex::encode(auth_tag)
    })))
}

/// Deliver encrypted U key and payload to agent
///
/// Sends the encrypted U key and any optional payload to the agent
/// after successful TPM quote verification.
pub(super) async fn perform_key_delivery(
    agent_client: &AgentClient,
    attestation: &Value,
    payload_path: Option<&str>,
    output: &OutputHandler,
) -> Result<(), CommandError> {
    output.progress("Delivering encrypted U key to agent");

    let encrypted_u = attestation
        .get("encrypted_u")
        .and_then(|u| u.as_str())
        .ok_or_else(|| {
            CommandError::resource_error("crypto", "Missing encrypted U key")
        })?;

    let auth_tag = attestation
        .get("auth_tag")
        .and_then(|tag| tag.as_str())
        .ok_or_else(|| {
        CommandError::resource_error("crypto", "Missing auth tag")
    })?;

    // Load payload if provided
    let payload = if let Some(path) = payload_path {
        Some(load_payload_file(path)?)
    } else {
        None
    };

    // Deliver key and payload to agent
    // Note: encrypted_u is already base64-encoded, auth_tag should be hex-encoded
    let encrypted_u_bytes = STANDARD.decode(encrypted_u).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to decode encrypted U key: {e}"),
        )
    })?;

    let _delivery_result = agent_client
        .deliver_key(&encrypted_u_bytes, auth_tag, payload.as_deref())
        .await
        .map_err(|e| {
            CommandError::agent_operation_failed(
                "agent".to_string(),
                "key_delivery",
                format!("Failed to deliver key: {e}"),
            )
        })?;

    output.info("U key delivered successfully to agent");
    Ok(())
}

/// Verify key derivation using HMAC challenge
///
/// Sends a challenge to the agent to verify that it can correctly
/// derive keys using the delivered U key.
pub(super) async fn verify_key_derivation(
    agent_client: &AgentClient,
    attestation: &Value,
    output: &OutputHandler,
) -> Result<(), CommandError> {
    output.progress("Generating verification challenge");

    let challenge = generate_secure_nonce(20)?;

    // Calculate expected HMAC using K key
    let k_key_b64 = attestation
        .get("k_key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| {
            CommandError::resource_error("crypto", "Missing K key")
        })?;

    let k_key = Zeroizing::new(STANDARD.decode(k_key_b64).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to decode K key: {e}"),
        )
    })?);

    let expected_hmac =
        crypto::compute_hmac(k_key.as_ref(), challenge.as_bytes()).map_err(
            |e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to compute expected HMAC: {e}"),
                )
            },
        )?;
    let expected_hmac_b64 = STANDARD.encode(&expected_hmac);

    output.progress("Sending verification challenge to agent");

    // Send challenge to agent and verify response
    let is_valid = agent_client
        .verify_key_derivation(&challenge, &expected_hmac_b64)
        .await
        .map_err(|e| {
            CommandError::agent_operation_failed(
                "agent".to_string(),
                "key_derivation_verification",
                format!("Failed to verify key derivation: {e}"),
            )
        })?;

    if is_valid {
        output.info("Key derivation verification successful");
        Ok(())
    } else {
        Err(CommandError::agent_operation_failed(
            "agent".to_string(),
            "key_derivation_verification",
            "Agent HMAC does not match expected value",
        ))
    }
}

/// Generate a cryptographically secure random nonce
///
/// Uses OpenSSL's CSPRNG (`RAND_bytes`) to generate random bytes,
/// then hex-encodes them to produce a string suitable for use as
/// a nonce or challenge.
///
/// # Arguments
/// * `num_bytes` - Number of random bytes to generate (output string will be `2 * num_bytes` hex chars)
fn generate_secure_nonce(num_bytes: usize) -> Result<String, CommandError> {
    let mut buf = vec![0u8; num_bytes];
    rand::rand_bytes(&mut buf).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("CSPRNG failed to generate nonce: {e}"),
        )
    })?;
    Ok(hex::encode(buf))
}

/// Validate TPM quote structure (default: structural checks only)
///
/// # Security Limitations
///
/// Without the `tpm-quote-validation` feature, this function performs
/// **structural validation only**. It does NOT verify:
///
/// - The cryptographic signature on the TPM quote against the registered AIK
///   (a full implementation uses `decode_quote_string` to parse the quote,
///   hashes the `AttestBuffer` with SHA-256, and verifies the signature
///   using the AIK public key with OpenSSL)
/// - The nonce via the `TPMS_ATTEST.extraData` field
///   (a full implementation converts the `AttestBuffer` to `Attest` and
///   compares `extra_data().value()` with the expected nonce bytes)
/// - The PCR digest integrity
///   (a full implementation hashes the selected PCR values and compares
///   with `QuoteInfo.pcr_digest()`)
///
/// Enable the `tpm-quote-validation` cargo feature for full cryptographic
/// verification following the same logic as `tpm2_checkquote`.
#[cfg(not(feature = "tpm-quote-validation"))]
async fn validate_tpm_quote(
    quote: &str,
    _public_key: &str,
    _nonce: &str,
    registrar_client: &RegistrarClient,
    agent_id: &str,
) -> Result<TpmQuoteValidation, CommandError> {
    // SECURITY: This path performs structural validation only.
    // Enable the `tpm-quote-validation` cargo feature for full
    // cryptographic verification of signature, nonce, and PCR digest.
    warn!(
        "TPM quote validation uses structural checks only. \
         Enable the 'tpm-quote-validation' feature for cryptographic verification."
    );
    debug!("Starting structural TPM quote validation for agent {agent_id}");

    // Verify agent is registered (ensures registrar is reachable)
    let agent_data = registrar_client
        .get_agent(agent_id)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "registrar",
                format!("Failed to get agent: {e}"),
            )
        })?
        .ok_or_else(|| {
            CommandError::agent_not_found(agent_id.to_string(), "registrar")
        })?;

    let registered_aik = agent_data["aik_tpm"].as_str().ok_or_else(|| {
        CommandError::agent_operation_failed(
            agent_id.to_string(),
            "aik_validation",
            "Agent AIK not found in registrar",
        )
    })?;

    // Structural check: quote format is r<base64_att>:<base64_sig>:<base64_pcr>
    if !quote.starts_with('r') {
        return Ok(TpmQuoteValidation {
            is_valid: false,
            nonce_verified: false,
            aik_verified: false,
            details: "Quote does not start with expected 'r' prefix"
                .to_string(),
        });
    }

    let quote_parts: Vec<&str> = quote[1..].split(':').collect();
    if quote_parts.len() < 3 {
        return Ok(TpmQuoteValidation {
            is_valid: false,
            nonce_verified: false,
            aik_verified: false,
            details: format!(
                "Quote has {} colon-separated parts, expected at least 3",
                quote_parts.len()
            ),
        });
    }

    // Structural check: base64 components decode successfully
    let labels = ["attestation", "signature", "PCR blob"];
    for (i, part) in quote_parts.iter().take(3).enumerate() {
        if STANDARD.decode(part).is_err() {
            return Ok(TpmQuoteValidation {
                is_valid: false,
                nonce_verified: false,
                aik_verified: false,
                details: format!(
                    "Quote {} component is not valid base64",
                    labels[i]
                ),
            });
        }
    }

    // Structural check: attestation data has reasonable length
    let att_bytes = STANDARD.decode(quote_parts[0]).map_err(|e| {
        CommandError::agent_operation_failed(
            agent_id.to_string(),
            "quote_validation",
            format!("Failed to decode attestation data: {e}"),
        )
    })?;

    if att_bytes.len() < 32 {
        return Ok(TpmQuoteValidation {
            is_valid: false,
            nonce_verified: false,
            aik_verified: false,
            details: "Attestation data too short to be a valid TPM quote"
                .to_string(),
        });
    }

    let aik_available = !registered_aik.is_empty();
    let att_len = att_bytes.len();
    let details = format!(
        "Structural validation only: {} quote parts, \
         {att_len} bytes attestation data, \
         registered AIK available: {aik_available}",
        quote_parts.len()
    );

    debug!("TPM quote structural validation result: {details}");

    // SECURITY: nonce_verified and aik_verified are false because structural
    // validation cannot verify cryptographic properties.
    Ok(TpmQuoteValidation {
        is_valid: true,
        nonce_verified: false,
        aik_verified: false,
        details,
    })
}

/// Validate TPM quote with full cryptographic verification
///
/// This function performs proper TPM quote validation following the same
/// logic as `tpm2_checkquote`:
/// 1. Parses the quote using `decode_quote_string`
/// 2. Verifies the quote signature against the registered AIK using OpenSSL
/// 3. Verifies the nonce from the `TPMS_ATTEST.extraData` field
/// 4. Verifies the PCR digest matches the quoted PCR values
#[cfg(feature = "tpm-quote-validation")]
async fn validate_tpm_quote(
    quote: &str,
    _public_key: &str,
    nonce: &str,
    registrar_client: &RegistrarClient,
    agent_id: &str,
) -> Result<TpmQuoteValidation, CommandError> {
    debug!(
        "Starting cryptographic TPM quote validation for agent {agent_id}"
    );

    // Step 1: Retrieve agent's registered AIK from registrar
    let agent_data = registrar_client
        .get_agent(agent_id)
        .await
        .map_err(|e| {
            CommandError::resource_error(
                "registrar",
                format!("Failed to get agent: {e}"),
            )
        })?
        .ok_or_else(|| {
            CommandError::agent_not_found(agent_id.to_string(), "registrar")
        })?;

    let registered_aik = agent_data["aik_tpm"].as_str().ok_or_else(|| {
        CommandError::agent_operation_failed(
            agent_id.to_string(),
            "aik_validation",
            "Agent AIK not found in registrar",
        )
    })?;

    // Step 2: Parse quote using keylime's decode_quote_string
    let (att, sig, pcrsel, pcrdata) =
        keylime::tpm::testing::decode_quote_string(quote).map_err(|e| {
            CommandError::agent_operation_failed(
                agent_id.to_string(),
                "quote_validation",
                format!("Failed to parse TPM quote: {e}"),
            )
        })?;

    // Step 3: Verify signature against registered AIK using OpenSSL
    let aik_pubkey =
        crypto::pkey_pub_from_pem(registered_aik).map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("Failed to parse AIK public key: {e}"),
            )
        })?;

    let aik_verified =
        verify_quote_signature(&aik_pubkey, att.value(), &sig)?;

    // Step 4: Verify nonce from TPMS_ATTEST.extraData
    let attestation: tss_esapi::structures::Attest =
        att.try_into().map_err(|e: tss_esapi::Error| {
            CommandError::agent_operation_failed(
                agent_id.to_string(),
                "quote_validation",
                format!("Failed to parse attestation structure: {e}"),
            )
        })?;

    let nonce_verified = attestation.extra_data().value() == nonce.as_bytes();

    // Step 5: Verify PCR digest
    let pcr_digest_ok = verify_pcr_digest(&attestation, &pcrsel, &pcrdata)?;

    let details = format!(
        "Cryptographic validation: signature={aik_verified}, \
         nonce={nonce_verified}, pcr_digest={pcr_digest_ok}"
    );

    debug!("TPM quote validation result: {details}");

    Ok(TpmQuoteValidation {
        is_valid: aik_verified && nonce_verified && pcr_digest_ok,
        nonce_verified,
        aik_verified,
        details,
    })
}

/// Verify the TPM quote signature using OpenSSL
///
/// Supports RSA-SSA (PKCS#1 v1.5) and RSA-PSS signature schemes,
/// which cover the vast majority of TPM attestation keys.
#[cfg(feature = "tpm-quote-validation")]
fn verify_quote_signature(
    aik_pubkey: &openssl::pkey::PKey<openssl::pkey::Public>,
    att_data: &[u8],
    sig: &tss_esapi::structures::Signature,
) -> Result<bool, CommandError> {
    use openssl::{rsa::Padding, sign::Verifier};
    use tss_esapi::structures::Signature as TpmSignature;

    match sig {
        TpmSignature::RsaSsa(rsa_sig) => {
            let raw_sig = rsa_sig.signature().value();
            let md = hash_alg_to_message_digest(rsa_sig.hashing_algorithm())?;
            let mut verifier =
                Verifier::new(md, aik_pubkey).map_err(|e| {
                    CommandError::resource_error(
                        "crypto",
                        format!("Failed to create verifier: {e}"),
                    )
                })?;
            verifier.set_rsa_padding(Padding::PKCS1).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to set PKCS1 padding: {e}"),
                )
            })?;
            verifier.update(att_data).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to update verifier: {e}"),
                )
            })?;
            verifier.verify(raw_sig).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Signature verification error: {e}"),
                )
            })
        }
        TpmSignature::RsaPss(rsa_sig) => {
            let raw_sig = rsa_sig.signature().value();
            let md = hash_alg_to_message_digest(rsa_sig.hashing_algorithm())?;
            let mut verifier =
                Verifier::new(md, aik_pubkey).map_err(|e| {
                    CommandError::resource_error(
                        "crypto",
                        format!("Failed to create verifier: {e}"),
                    )
                })?;
            verifier.set_rsa_padding(Padding::PKCS1_PSS).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to set PSS padding: {e}"),
                )
            })?;
            verifier.update(att_data).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to update verifier: {e}"),
                )
            })?;
            verifier.verify(raw_sig).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("PSS signature verification error: {e}"),
                )
            })
        }
        _ => Err(CommandError::resource_error(
            "tpm",
            format!(
                "Unsupported TPM signature algorithm: {:?}. \
                 Only RSA-SSA and RSA-PSS are currently supported.",
                sig.algorithm()
            ),
        )),
    }
}

/// Verify PCR digest matches the quoted PCR values
#[cfg(feature = "tpm-quote-validation")]
fn verify_pcr_digest(
    attestation: &tss_esapi::structures::Attest,
    pcrsel: &tss_esapi::structures::PcrSelectionList,
    pcrdata: &tss_esapi::abstraction::pcr::PcrData,
) -> Result<bool, CommandError> {
    use openssl::hash::{Hasher, MessageDigest};
    use tss_esapi::{
        interface_types::algorithm::HashingAlgorithm, structures::AttestInfo,
    };

    // Get SHA-256 PCR bank
    let pcrbank =
        pcrdata.pcr_bank(HashingAlgorithm::Sha256).ok_or_else(|| {
            CommandError::resource_error(
                "tpm",
                "No SHA-256 PCR bank in quote data",
            )
        })?;

    // Hash selected PCR values in order
    let mut hasher = Hasher::new(MessageDigest::sha256()).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to create hasher: {e}"),
        )
    })?;

    for &sel in pcrsel.get_selections() {
        for i in &sel.selected() {
            if let Some(digest) = pcrbank.get_digest(*i) {
                hasher.update(digest.value()).map_err(|e| {
                    CommandError::resource_error(
                        "crypto",
                        format!("Failed to hash PCR value: {e}"),
                    )
                })?;
            }
        }
    }

    let computed_digest = hasher.finish().map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to finalize PCR hash: {e}"),
        )
    })?;

    // Extract quote info and compare PCR digest
    let quote_info = match attestation.attested() {
        AttestInfo::Quote { info } => info,
        _ => {
            return Err(CommandError::resource_error(
                "tpm",
                format!(
                    "Expected attestation type Quote, got {:?}",
                    attestation.attestation_type()
                ),
            ))
        }
    };

    Ok(quote_info.pcr_digest().value() == computed_digest.as_ref())
}

/// Convert TSS hashing algorithm to OpenSSL message digest
#[cfg(feature = "tpm-quote-validation")]
fn hash_alg_to_message_digest(
    alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
) -> Result<openssl::hash::MessageDigest, CommandError> {
    use openssl::hash::MessageDigest;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;

    match alg {
        HashingAlgorithm::Sha1 => Ok(MessageDigest::sha1()),
        HashingAlgorithm::Sha256 => Ok(MessageDigest::sha256()),
        HashingAlgorithm::Sha384 => Ok(MessageDigest::sha384()),
        HashingAlgorithm::Sha512 => Ok(MessageDigest::sha512()),
        _ => Err(CommandError::resource_error(
            "tpm",
            format!("Unsupported hash algorithm in TPM signature: {alg:?}"),
        )),
    }
}

/// Encrypt U key using agent's RSA public key with OAEP padding
///
/// This function performs proper RSA-OAEP encryption of the U key using the agent's
/// public key. This ensures that only the agent with the corresponding private key
/// can decrypt and use the delivered key.
///
/// # Arguments
/// * `u_key` - The U key to encrypt (typically 32 bytes)
/// * `agent_public_key` - Agent's RSA public key in base64 format
///
/// # Returns
/// Returns base64-encoded encrypted U key
///
/// # Security
/// - Uses RSA-OAEP padding for semantic security
/// - Validates public key format before encryption
/// - Provides cryptographic confidentiality for key delivery
#[must_use = "encrypted key must be sent to the agent"]
fn encrypt_u_key_with_agent_pubkey(
    u_key_bytes: &[u8],
    agent_public_key: &str,
) -> Result<String, CommandError> {
    debug!("Encrypting U key with agent's RSA public key");

    // Step 1: Agent public keys are provided in PEM format by Keylime agents
    // Based on quotes_handler.rs:95 - agents use crypto::pkey_pub_to_pem() to format keys
    debug!("Using public key in PEM format from agent response");
    let pubkey_pem = agent_public_key;

    // Step 2: Import the public key as OpenSSL PKey
    let pubkey = crypto::pkey_pub_from_pem(pubkey_pem).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to parse public key PEM: {e}"),
        )
    })?;

    // Step 3: Perform RSA-OAEP encryption using keylime crypto module
    let encrypted_bytes = crypto::rsa_oaep_encrypt(&pubkey, u_key_bytes)
        .map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("RSA encryption failed: {e}"),
            )
        })?;

    // Step 4: Encode result as base64 for transmission
    let encrypted_b64 = STANDARD.encode(&encrypted_bytes);

    let input_len = u_key_bytes.len();
    let output_len = encrypted_bytes.len();
    debug!(
        "Successfully encrypted U key: {input_len} bytes -> {output_len} bytes"
    );

    Ok(encrypted_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_secure_nonce_length() {
        // Each byte becomes 2 hex chars
        for num_bytes in [1, 10, 16, 20, 32] {
            let nonce =
                generate_secure_nonce(num_bytes).expect("nonce generation"); //#[allow_ci]
            assert_eq!(
                nonce.len(),
                num_bytes * 2,
                "Expected {} hex chars for {} bytes",
                num_bytes * 2,
                num_bytes
            );
        }
    }

    #[test]
    fn test_generate_secure_nonce_hex_chars() {
        let nonce = generate_secure_nonce(32).expect("nonce generation"); //#[allow_ci]
        assert!(
            nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "Nonce contains non-hex characters: {nonce}"
        );
    }

    #[test]
    fn test_generate_secure_nonce_uniqueness() {
        let mut nonces = HashSet::new();
        for _ in 0..100 {
            let nonce = generate_secure_nonce(20).expect("nonce generation"); //#[allow_ci]
            assert!(nonces.insert(nonce), "Duplicate nonce generated");
        }
    }
}
