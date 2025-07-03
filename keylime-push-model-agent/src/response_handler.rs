use anyhow::{anyhow, Result};
use keylime::context_info::AttestationRequiredParams;
use keylime::structures::{AttestationResponse, ChosenParameters};

pub fn process_negotiation_response(
    response_body: &str,
) -> Result<AttestationRequiredParams> {
    let verifier_response: AttestationResponse =
        serde_json::from_str(response_body)?;
    let tpm_quote_request = verifier_response
        .data
        .attributes
        .evidence_requested
        .iter()
        .find(|req| req.evidence_type == "tpm_quote")
        .ok_or_else(|| {
            anyhow!("Verifier response did not request a tpm_quote")
        })?;

    if let Some(ChosenParameters::Parameters(params_box)) =
        &tpm_quote_request.chosen_parameters
    {
        let params = AttestationRequiredParams {
            challenge: params_box.challenge.clone().unwrap_or_default(),
            signature_scheme: params_box
                .signature_scheme
                .clone()
                .unwrap_or_default(),
            hash_algorithm: params_box
                .hash_algorithm
                .clone()
                .unwrap_or_default(),
            selected_subjects: params_box.selected_subjects.as_ref().map_or(
                Default::default(),
                |s| {
                    let mut map = std::collections::HashMap::new();
                    map.insert("sha1".to_string(), s.sha1.clone());
                    map.insert("sha256".to_string(), s.sha256.clone());
                    map
                },
            ),
        };
        Ok(params)
    } else {
        Err(anyhow!(
            "Chosen parameters for tpm_quote not found or invalid"
        ))
    }
}
