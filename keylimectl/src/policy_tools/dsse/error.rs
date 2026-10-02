// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! DSSE (Dead Simple Signing Envelope) error types.

use serde::Serialize;
use thiserror::Error;

/// DSSE (Dead Simple Signing Envelope) errors
///
/// These errors represent issues with policy signing and
/// signature verification using the DSSE protocol.
#[derive(Error, Debug, Serialize)]
pub enum DsseError {
    /// Signing operation failed
    #[error("Signing failed: {reason}")]
    SigningFailed { reason: String },

    /// Signature verification failed
    #[error("Signature verification failed: {reason}")]
    VerificationFailed { reason: String },

    /// Invalid DSSE envelope structure
    #[error("Invalid DSSE envelope: {reason}")]
    InvalidEnvelope { reason: String },

    /// Key loading or generation error
    #[error("Key error: {reason}")]
    KeyError { reason: String },
}
