// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use keylime::structures;
use serde_json::{Error, Value};

pub fn dump_attestation_request_to_value(
    request: &structures::AttestationRequest,
) -> Result<Value, Error> {
    serde_json::to_value(request)
}

#[allow(dead_code)]
pub fn dump_session_request_to_value(
    request: &structures::SessionRequest,
) -> Result<Value, Error> {
    serde_json::to_value(request)
}

#[allow(dead_code)]
pub fn dump_evidence_handling_request_to_value(
    request: &structures::EvidenceHandlingRequest,
) -> Result<Value, Error> {
    serde_json::to_value(request)
}
