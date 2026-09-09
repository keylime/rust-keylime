// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! TPM attestation workflow for pull model (API < 3.0)
//!
//! This module contains the attestation functions used in the pull model
//! where the tenant communicates directly with the agent for TPM quote
//! verification and key exchange.

use super::helpers::load_payload_bytes;
use crate::client::agent::AgentClient;
use crate::commands::error::CommandError;
use crate::output::OutputHandler;
use base64::{engine::general_purpose::STANDARD, Engine};
use keylime::crypto;
use log::{debug, warn};
use openssl::rand;
use openssl::symm::{self, Cipher};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Validation result for TPM quote verification
#[derive(Debug)]
struct TpmQuoteValidation {
    is_valid: bool,
    nonce_verified: bool,
    aik_verified: bool,
    details: String,
}

/// Key material and attestation data produced by TPM quote verification
///
/// This struct holds sensitive key material used for provisioning the agent.
/// It implements `Zeroize` and `ZeroizeOnDrop` to ensure all sensitive key
/// material is cleared from memory when no longer needed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct AttestationData {
    /// Base64-encoded RSA-OAEP ciphertext of the U key for the agent
    pub(super) encrypted_u: String,
    /// Hex-encoded HMAC-SHA256 authentication tag (K key over agent ID)
    pub(super) auth_tag: String,
    /// TPM quote string (public, not zeroized)
    #[zeroize(skip)]
    pub(super) quote: String,
    /// Agent RSA public key in PEM format (public, not zeroized)
    #[zeroize(skip)]
    pub(super) public_key: String,
    /// Hex-encoded nonce used for quote freshness (not sensitive)
    #[zeroize(skip)]
    pub(super) nonce: String,
    /// K key bytes (K = U XOR V), zeroed on drop
    pub(super) k_key: Zeroizing<Vec<u8>>,
    /// V key bytes for delivery to verifier, zeroed on drop
    pub(super) v_key: Zeroizing<Vec<u8>>,
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
    agent_data: &Value,
    agent_id: &str,
    allow_unverified_quote: bool,
    output: &OutputHandler,
) -> Result<Option<AttestationData>, CommandError> {
    output.progress("Generating nonce for TPM quote");

    // Generate random nonce for quote freshness
    let nonce = generate_secure_nonce(20)?;
    debug!("Generated nonce for TPM quote ({} chars)", nonce.len());

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

    debug!(
        "Received quote response ({} fields)",
        quote_response.as_object().map_or(0, |m| m.len())
    );

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

    // Implement structured TPM quote validation
    let validation_result =
        validate_tpm_quote(quote, public_key, &nonce, agent_data, agent_id)
            .await?;

    if !validation_result.is_valid && !allow_unverified_quote {
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

    if !nonce_verified || !aik_verified {
        if !allow_unverified_quote {
            return Err(CommandError::agent_operation_failed(
                agent_id.to_string(),
                "tpm_quote_validation",
                "TPM quote was not cryptographically verified (nonce and/or AIK not verified). \
                 Enable the 'tpm-quote-validation' feature for full verification, \
                 or pass --allow-unverified-quote to proceed without verification (INSECURE).",
            ));
        }
        warn!(
            "Proceeding with unverified TPM quote (--allow-unverified-quote). \
             This is INSECURE and should only be used for development/testing."
        );
    }

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

    Ok(Some(AttestationData {
        encrypted_u,
        auth_tag: hex::encode(auth_tag),
        quote: quote.to_string(),
        public_key: public_key.to_string(),
        nonce,
        k_key: Zeroizing::new(k_key_bytes.to_vec()),
        v_key: Zeroizing::new(v_key_bytes.to_vec()),
    }))
}

/// Deliver encrypted U key and payload to agent
///
/// Sends the encrypted U key and any optional payload to the agent
/// after successful TPM quote verification.
pub(super) async fn perform_key_delivery(
    agent_client: &AgentClient,
    attestation: &AttestationData,
    payload_path: Option<&str>,
    output: &OutputHandler,
) -> Result<(), CommandError> {
    output.progress("Delivering encrypted U key to agent");

    // Load and encrypt payload if provided
    // The agent expects the payload as base64-encoded AES-256-GCM ciphertext:
    //   base64(iv || ciphertext || tag)
    // where the encryption key is K (= U XOR V).
    let encrypted_payload = if let Some(path) = payload_path {
        let payload_bytes = load_payload_bytes(path)?;

        output.progress("Encrypting payload for agent");
        Some(encrypt_payload(attestation.k_key.as_ref(), &payload_bytes)?)
    } else {
        None
    };

    // Deliver key and payload to agent
    // Note: encrypted_u is already base64-encoded, auth_tag is hex-encoded
    let encrypted_u_bytes =
        STANDARD.decode(&attestation.encrypted_u).map_err(|e| {
            CommandError::resource_error(
                "crypto",
                format!("Failed to decode encrypted U key: {e}"),
            )
        })?;

    let _delivery_result = agent_client
        .deliver_key(
            &encrypted_u_bytes,
            &attestation.auth_tag,
            encrypted_payload.as_deref(),
        )
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
/// derive keys using the delivered U key. Retries with backoff
/// because the agent may not yet have received V from the verifier.
pub(super) async fn verify_key_derivation(
    agent_client: &AgentClient,
    attestation: &AttestationData,
    output: &OutputHandler,
) -> Result<(), CommandError> {
    output.progress("Generating verification challenge");

    let challenge = generate_secure_nonce(20)?;

    // Calculate expected HMAC using K key
    let expected_hmac = crypto::compute_hmac(
        attestation.k_key.as_ref(),
        challenge.as_bytes(),
    )
    .map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to compute expected HMAC: {e}"),
        )
    })?;
    // Agent returns HMAC as hex string (matching Python's do_hmac hexdigest)
    let expected_hmac_hex = hex::encode(&expected_hmac);

    // Retry loop: the agent may not have received V from the verifier yet,
    // so K = U XOR V is not available until both parts arrive.
    let max_retries = 12;
    let base_interval = std::time::Duration::from_secs(1);

    let wait_handle =
        output.start_wait("Verifying key derivation (attempt 1/12)");

    for attempt in 0..max_retries {
        wait_handle.set_message(format!(
            "Verifying key derivation (attempt {}/{})",
            attempt + 1,
            max_retries
        ));

        match agent_client
            .verify_key_derivation(&challenge, &expected_hmac_hex)
            .await
        {
            Ok(true) => {
                drop(wait_handle);
                output.info("Key derivation verification successful");
                return Ok(());
            }
            Ok(false) => {
                // HMAC mismatch — agent likely hasn't received V yet
                if attempt + 1 >= max_retries {
                    return Err(CommandError::agent_operation_failed(
                        "agent".to_string(),
                        "key_derivation_verification",
                        format!(
                            "Agent HMAC does not match expected value \
                             after {max_retries} attempts"
                        ),
                    ));
                }
                let delay = base_interval
                    * 2u32.saturating_pow(attempt.min(4) as u32);
                debug!(
                    "Key derivation not yet complete (attempt {}/{}), \
                     retrying in {:?}",
                    attempt + 1,
                    max_retries,
                    delay
                );
                tokio::time::sleep(delay).await;
            }
            Err(e) => {
                // Network/protocol error — also retry
                if attempt + 1 >= max_retries {
                    return Err(CommandError::agent_operation_failed(
                        "agent".to_string(),
                        "key_derivation_verification",
                        format!("Failed to verify key derivation: {e}"),
                    ));
                }
                let delay = base_interval
                    * 2u32.saturating_pow(attempt.min(4) as u32);
                debug!(
                    "Verification request failed (attempt {}/{}): {e}, \
                     retrying in {:?}",
                    attempt + 1,
                    max_retries,
                    delay
                );
                tokio::time::sleep(delay).await;
            }
        }
    }

    unreachable!() //#[allow_ci]
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

/// Encrypt payload using AES-256-GCM and return base64-encoded ciphertext
///
/// Matches the format produced by Python keylime's `crypto.encrypt()`:
///   base64(iv || ciphertext || tag)
///
/// where:
/// - iv: 16-byte random initialization vector
/// - ciphertext: AES-256-GCM encrypted data
/// - tag: 16-byte GCM authentication tag
///
/// The agent decrypts this using `crypto::decrypt_aead()` after
/// base64-decoding.
fn encrypt_payload(
    key: &[u8],
    plaintext: &[u8],
) -> Result<String, CommandError> {
    const AES_BLOCK_SIZE: usize = 16;

    let mut iv = [0u8; AES_BLOCK_SIZE];
    rand::rand_bytes(&mut iv).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to generate IV: {e}"),
        )
    })?;

    let cipher = Cipher::aes_256_gcm();
    let mut tag = vec![0u8; AES_BLOCK_SIZE];
    let ciphertext =
        symm::encrypt_aead(cipher, key, Some(&iv), &[], plaintext, &mut tag)
            .map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Payload encryption failed: {e}"),
                )
            })?;

    let mut result =
        Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);

    Ok(STANDARD.encode(&result))
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
    agent_data: &Value,
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

    // SECURITY: is_valid, nonce_verified, and aik_verified are false because
    // structural validation cannot verify cryptographic properties. The caller
    // must check nonce_verified and aik_verified and reject unverified quotes
    // unless --allow-unverified-quote is explicitly passed.
    Ok(TpmQuoteValidation {
        is_valid: false,
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
    agent_data: &Value,
    agent_id: &str,
) -> Result<TpmQuoteValidation, CommandError> {
    debug!(
        "Starting cryptographic TPM quote validation for agent {agent_id}"
    );

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

    // Step 3: Convert registered AIK (base64-encoded TPM2B_PUBLIC) to OpenSSL PKey
    let aik_bytes = STANDARD.decode(registered_aik).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to decode AIK base64: {e}"),
        )
    })?;

    let aik_pubkey = pubkey_from_tpm2b_public(&aik_bytes)?;

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
/// Supports RSA-SSA (PKCS#1 v1.5), RSA-PSS, and ECDSA signature
/// schemes. EC-Schnorr is not supported for software-based
/// verification as OpenSSL lacks EC-Schnorr support.
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
        TpmSignature::EcDsa(ecc_sig) => {
            let md = hash_alg_to_message_digest(ecc_sig.hashing_algorithm())?;

            let r_bn = openssl::bn::BigNum::from_slice(
                ecc_sig.signature_r().value(),
            )
            .map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to create ECDSA r component: {e}"),
                )
            })?;
            let s_bn = openssl::bn::BigNum::from_slice(
                ecc_sig.signature_s().value(),
            )
            .map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to create ECDSA s component: {e}"),
                )
            })?;

            let ecdsa_sig =
                openssl::ecdsa::EcdsaSig::from_private_components(r_bn, s_bn)
                    .map_err(|e| {
                        CommandError::resource_error(
                            "crypto",
                            format!("Failed to create ECDSA signature: {e}"),
                        )
                    })?;
            let der_sig = ecdsa_sig.to_der().map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to DER-encode ECDSA signature: {e}"),
                )
            })?;

            let mut verifier =
                Verifier::new(md, aik_pubkey).map_err(|e| {
                    CommandError::resource_error(
                        "crypto",
                        format!("Failed to create ECDSA verifier: {e}"),
                    )
                })?;
            verifier.update(att_data).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to update ECDSA verifier: {e}"),
                )
            })?;
            verifier.verify(&der_sig).map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("ECDSA signature verification error: {e}"),
                )
            })
        }
        TpmSignature::EcSchnorr(_) => Err(CommandError::resource_error(
            "tpm",
            "EC-Schnorr signature verification is not supported \
             for software-based quote validation. \
             EC-Schnorr requires TPM-based verification.",
        )),
        _ => Err(CommandError::resource_error(
            "tpm",
            format!(
                "Unsupported TPM signature algorithm: {:?}",
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
    use keylime::algorithms::HashAlgorithm;
    use openssl::hash::MessageDigest;

    let hash_alg = HashAlgorithm::try_from(alg).map_err(|e| {
        CommandError::resource_error(
            "tpm",
            format!("Unsupported hash algorithm in TPM signature: {e}"),
        )
    })?;
    MessageDigest::try_from(hash_alg).map_err(|e| {
        CommandError::resource_error(
            "tpm",
            format!("Unsupported message digest: {e}"),
        )
    })
}

/// Parse a TPM2B_PUBLIC structure and extract the public key.
///
/// The TPM2B_PUBLIC format is a 2-byte big-endian size prefix followed
/// by a TPMT_PUBLIC structure, which is deserialized using tss-esapi
/// and converted to an OpenSSL PKey via PEM.
#[cfg(feature = "tpm-quote-validation")]
fn pubkey_from_tpm2b_public(
    data: &[u8],
) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, CommandError> {
    use tss_esapi::traits::UnMarshall;

    if data.len() < 2 {
        return Err(CommandError::resource_error(
            "crypto",
            "TPM2B_PUBLIC data too short",
        ));
    }

    let tpmt_size = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + tpmt_size {
        return Err(CommandError::resource_error(
            "crypto",
            format!(
                "TPM2B_PUBLIC buffer too short: {} < {}",
                data.len(),
                2 + tpmt_size
            ),
        ));
    }

    let public =
        tss_esapi::structures::Public::unmarshall(&data[2..2 + tpmt_size])
            .map_err(|e| {
                CommandError::resource_error(
                    "crypto",
                    format!("Failed to unmarshal TPMT_PUBLIC: {e}"),
                )
            })?;

    let pem_bytes = crypto::tss_pubkey_to_pem(public).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to convert TPM public key to PEM: {e}"),
        )
    })?;

    let pem_str = std::str::from_utf8(&pem_bytes).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("PEM is not valid UTF-8: {e}"),
        )
    })?;

    crypto::pkey_pub_from_pem(pem_str).map_err(|e| {
        CommandError::resource_error(
            "crypto",
            format!("Failed to parse public key PEM: {e}"),
        )
    })
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

    // Negative security tests: attacker-controlled public keys

    #[test]
    fn test_encrypt_u_key_empty_pem() {
        let result = encrypt_u_key_with_agent_pubkey(&[0u8; 32], "");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_u_key_garbage_pem() {
        let result =
            encrypt_u_key_with_agent_pubkey(&[0u8; 32], "not-a-pem-key");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_u_key_truncated_pem() {
        let result = encrypt_u_key_with_agent_pubkey(
            &[0u8; 32],
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_u_key_ec_key_rejected() {
        // RSA-OAEP encryption must reject non-RSA keys
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .expect("EC group"); //#[allow_ci]
        let ec = EcKey::generate(&group).expect("EC key generation"); //#[allow_ci]
        let pkey = PKey::from_ec_key(ec).expect("PKey from EC"); //#[allow_ci]
        let pem = String::from_utf8(
            pkey.public_key_to_pem().expect("PEM encoding"), //#[allow_ci]
        )
        .expect("UTF-8"); //#[allow_ci]

        let result = encrypt_u_key_with_agent_pubkey(&[0u8; 32], &pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_u_key_valid_rsa_key() {
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;

        let rsa = Rsa::generate(2048).expect("RSA key generation"); //#[allow_ci]
        let pkey = PKey::from_rsa(rsa).expect("PKey from RSA"); //#[allow_ci]
        let pem = String::from_utf8(
            pkey.public_key_to_pem().expect("PEM encoding"), //#[allow_ci]
        )
        .expect("UTF-8"); //#[allow_ci]

        let result = encrypt_u_key_with_agent_pubkey(&[0u8; 32], &pem);
        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypt_u_key_empty_plaintext_no_panic() {
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;

        let rsa = Rsa::generate(2048).expect("RSA key generation"); //#[allow_ci]
        let pkey = PKey::from_rsa(rsa).expect("PKey from RSA"); //#[allow_ci]
        let pem = String::from_utf8(
            pkey.public_key_to_pem().expect("PEM encoding"), //#[allow_ci]
        )
        .expect("UTF-8"); //#[allow_ci]

        // Empty plaintext — verifies no panic regardless of result
        let _ = encrypt_u_key_with_agent_pubkey(&[], &pem);
    }

    // Payload encryption tests

    #[test]
    fn test_encrypt_payload_roundtrip() {
        // Verify encrypt_payload produces output compatible with
        // keylime::crypto::decrypt_aead
        let key = [0x42u8; 32]; // AES-256 key
        let plaintext = b"test payload data for the agent";

        let b64_ciphertext =
            encrypt_payload(&key, plaintext).expect("encryption"); //#[allow_ci]

        // Base64 decode
        let raw = STANDARD.decode(&b64_ciphertext).expect("base64 decode"); //#[allow_ci]

        // Decrypt using the same function the agent uses
        let decrypted = crypto::decrypt_aead(&key, &raw).expect("decryption"); //#[allow_ci]

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_payload_empty() {
        let key = [0xAAu8; 32];
        let plaintext = b"";

        let b64_ciphertext =
            encrypt_payload(&key, plaintext).expect("encryption"); //#[allow_ci]
        let raw = STANDARD.decode(&b64_ciphertext).expect("base64 decode"); //#[allow_ci]
        let decrypted = crypto::decrypt_aead(&key, &raw).expect("decryption"); //#[allow_ci]

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_payload_produces_valid_base64() {
        let key = [0xBBu8; 32];
        let plaintext = b"hello world";

        let b64_ciphertext =
            encrypt_payload(&key, plaintext).expect("encryption"); //#[allow_ci]

        // Must be valid base64
        assert!(STANDARD.decode(&b64_ciphertext).is_ok());

        // Must not contain whitespace (which caused the original bug)
        assert!(
            !b64_ciphertext.contains(' '),
            "Encrypted payload contains spaces"
        );
    }

    // Negative security tests: malformed TPM quote parsing

    #[test]
    fn test_malformed_quote_base64_decode() {
        // Verify base64 decode returns Err for garbage, not panic
        assert!(STANDARD.decode("!!!invalid!!!").is_err());
        assert!(STANDARD.decode("").is_ok()); // empty decodes to empty
    }

    #[test]
    fn test_quote_format_parsing_edge_cases() {
        // Verify quote string splitting handles edge cases without panic
        let empty = "";
        assert!(!empty.starts_with('r'));

        let no_parts = "r";
        let parts: Vec<&str> = no_parts[1..].split(':').collect();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].is_empty());

        let one_part = "rYWJj";
        let parts: Vec<&str> = one_part[1..].split(':').collect();
        assert_eq!(parts.len(), 1);

        let two_parts = "rYWJj:ZGVm";
        let parts: Vec<&str> = two_parts[1..].split(':').collect();
        assert_eq!(parts.len(), 2);
    }

    // Zeroization verification tests

    #[test]
    fn test_zeroizing_wraps_and_clears_on_explicit_zeroize() {
        use zeroize::Zeroize;

        // Verify Zeroizing wraps correctly
        let mut key = Zeroizing::new([0xFFu8; 32]);
        assert!(key.iter().all(|&b| b == 0xFF));

        // Verify explicit zeroize clears the value
        key.zeroize();
        assert!(key.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_zeroizing_key_material_operations() {
        // Verify key material operations work correctly with Zeroizing wrapper
        let mut u_key = Zeroizing::new([0u8; 32]);
        let mut v_key = Zeroizing::new([0u8; 32]);

        // Fill with test data (simulating rand::rand_bytes)
        for (i, b) in u_key.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in v_key.iter_mut().enumerate() {
            *b = (255 - i) as u8;
        }

        // XOR operation (K = U ^ V) should work through Zeroizing
        let mut k_key = Zeroizing::new([0u8; 32]);
        for i in 0..32 {
            k_key[i] = u_key[i] ^ v_key[i];
        }

        // Verify XOR result
        for i in 0..32 {
            assert_eq!(k_key[i], (i as u8) ^ (255 - i) as u8);
        }
    }

    #[cfg(feature = "tpm-quote-validation")]
    mod quote_validation_tests {
        use super::super::*;

        fn generate_ec_key_and_sign(
            data: &[u8],
        ) -> (
            openssl::pkey::PKey<openssl::pkey::Public>,
            openssl::bn::BigNum,
            openssl::bn::BigNum,
        ) {
            use openssl::ec::{EcGroup, EcKey};
            use openssl::nid::Nid;
            use openssl::pkey::PKey;

            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .expect("P-256 group"); //#[allow_ci]
            let ec_key = EcKey::generate(&group).expect("EC key generation"); //#[allow_ci]
            let pkey =
                PKey::from_ec_key(ec_key.clone()).expect("PKey from EC"); //#[allow_ci]

            let sig = openssl::ecdsa::EcdsaSig::sign(data, &ec_key)
                .expect("ECDSA sign"); //#[allow_ci]
            let r = sig.r().to_owned().expect("r component"); //#[allow_ci]
            let s = sig.s().to_owned().expect("s component"); //#[allow_ci]

            let pub_key_pem =
                pkey.public_key_to_pem().expect("public key PEM"); //#[allow_ci]
            let pub_pkey = PKey::public_key_from_pem(&pub_key_pem)
                .expect("parse public PEM"); //#[allow_ci]

            (pub_pkey, r, s)
        }

        #[test]
        fn test_verify_ecdsa_signature_valid() {
            use tss_esapi::interface_types::algorithm::HashingAlgorithm;
            use tss_esapi::structures::{
                EccParameter, EccSignature, Signature,
            };

            let att_data = b"test attestation data";
            let digest = openssl::hash::hash(
                openssl::hash::MessageDigest::sha256(),
                att_data,
            )
            .expect("hash"); //#[allow_ci]

            let (pub_pkey, r, s) = generate_ec_key_and_sign(&digest);

            let r_bytes = r.to_vec();
            let s_bytes = s.to_vec();

            let ecc_sig = EccSignature::create(
                HashingAlgorithm::Sha256,
                EccParameter::try_from(r_bytes.as_slice()).expect("r param"), //#[allow_ci]
                EccParameter::try_from(s_bytes.as_slice()).expect("s param"), //#[allow_ci]
            )
            .expect("EccSignature"); //#[allow_ci]

            let sig = Signature::EcDsa(ecc_sig);

            let result = verify_quote_signature(&pub_pkey, att_data, &sig);
            assert!(
                result.is_ok(),
                "verify_quote_signature failed: {result:?}"
            );
            assert!(result.unwrap(), "ECDSA signature should be valid"); //#[allow_ci]
        }

        #[test]
        fn test_verify_ecdsa_signature_wrong_data() {
            use tss_esapi::interface_types::algorithm::HashingAlgorithm;
            use tss_esapi::structures::{
                EccParameter, EccSignature, Signature,
            };

            let att_data = b"test attestation data";
            let digest = openssl::hash::hash(
                openssl::hash::MessageDigest::sha256(),
                att_data,
            )
            .expect("hash"); //#[allow_ci]

            let (pub_pkey, r, s) = generate_ec_key_and_sign(&digest);

            let r_bytes = r.to_vec();
            let s_bytes = s.to_vec();

            let ecc_sig = EccSignature::create(
                HashingAlgorithm::Sha256,
                EccParameter::try_from(r_bytes.as_slice()).expect("r param"), //#[allow_ci]
                EccParameter::try_from(s_bytes.as_slice()).expect("s param"), //#[allow_ci]
            )
            .expect("EccSignature"); //#[allow_ci]

            let sig = Signature::EcDsa(ecc_sig);

            let result =
                verify_quote_signature(&pub_pkey, b"wrong data", &sig);
            assert!(result.is_ok());
            assert!(
                !result.unwrap(), //#[allow_ci]
                "ECDSA signature should be invalid for wrong data"
            );
        }

        #[test]
        fn test_verify_ecschnorr_returns_error() {
            use tss_esapi::interface_types::algorithm::HashingAlgorithm;
            use tss_esapi::structures::{
                EccParameter, EccSignature, Signature,
            };

            let ec_key = openssl::ec::EcKey::generate(
                &openssl::ec::EcGroup::from_curve_name(
                    openssl::nid::Nid::X9_62_PRIME256V1,
                )
                .expect("group"), //#[allow_ci]
            )
            .expect("keygen"); //#[allow_ci]
            let pub_pkey = openssl::pkey::PKey::from_ec_key(
                openssl::ec::EcKey::from_public_key(
                    ec_key.group(),
                    ec_key.public_key(),
                )
                .expect("pub EC"), //#[allow_ci]
            )
            .expect("pub PKey"); //#[allow_ci]

            let dummy = vec![0u8; 32];
            let ecc_sig = EccSignature::create(
                HashingAlgorithm::Sha256,
                EccParameter::try_from(dummy.as_slice()).expect("r"), //#[allow_ci]
                EccParameter::try_from(dummy.as_slice()).expect("s"), //#[allow_ci]
            )
            .expect("EccSignature"); //#[allow_ci]

            let sig = Signature::EcSchnorr(ecc_sig);

            let result = verify_quote_signature(&pub_pkey, b"data", &sig);
            assert!(result.is_err());
            let err_msg = format!("{}", result.unwrap_err()); //#[allow_ci]
            assert!(
                err_msg.contains("EC-Schnorr"),
                "Error should mention EC-Schnorr: {err_msg}"
            );
        }
    }
}
