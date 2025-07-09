// SPDX-License-agent_identifier: Apache-2.0
// Copyright 2025 Keylime Authors
pub const DEFAULT_API_VERSION: &str = "v3.0";

pub struct UrlArgs {
    pub verifier_url: String,
    pub agent_identifier: Option<String>,
    pub api_version: Option<String>,
    pub location: Option<String>,
}

fn get_api_version(args: &UrlArgs) -> String {
    if args.api_version.is_some() {
        return args.api_version.clone().unwrap();
    }
    DEFAULT_API_VERSION.to_string()
}

pub fn get_negotiations_request_url(args: &UrlArgs) -> String {
    let id = match args.agent_identifier {
        Some(ref identifier) => identifier.clone(),
        None => return "ERROR: No agent identifier provided".to_string(),
    };
    let verifier_url = args.verifier_url.clone();
    let api_version = get_api_version(args);
    if verifier_url.ends_with('/') {
        return format!(
            "{verifier_url}{api_version}/agents/{id}/attestations"
        );
    }
    format!("{verifier_url}/{api_version}/agents/{id}/attestations")
}

pub fn get_evidence_submission_request_url(args: &UrlArgs) -> String {
    let trimmed_base = match args.verifier_url.trim_end_matches('/') {
        "" => return "ERROR: No verifier URL provided".to_string(),
        trimmed => trimmed.to_string(),
    };
    let location = match &args.location {
        Some(loc) => loc.clone(),
        None => return "ERROR: No location provided".to_string(),
    };
    format!("{trimmed_base}{location}")
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn get_attestation_request_url_test() {
        let url = get_negotiations_request_url(&UrlArgs {
            api_version: None,
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            agent_identifier: Some("024680".to_string()),
            location: None,
        });
        assert_eq!(
            url,
            "https://1.2.3.4:5678/v3.0/agents/024680/attestations"
                .to_string()
        );
    } // get_attestation_request_url_test

    #[test]
    fn get_evidence_handling_request_url_test() {
        let urls = vec![
            "https://1.2.3.4:5678/".to_string(),
            "https://1.2.3.4:5678".to_string(),
            "http://1.2.3.4:5678/".to_string(),
            "http://1.2.3.4:5678".to_string(),
        ];
        for u in urls {
            let url = get_evidence_submission_request_url(&UrlArgs {
                verifier_url: u.clone(),
                api_version: None,
                agent_identifier: None,
                location: Some(
                    "/v3.0/agents/024680/attestations/0".to_string(),
                ),
            });

            match u.clone().ends_with('/') {
                true => assert_eq!(
                    url,
                    u.clone().to_string()
                        + "v3.0/agents/024680/attestations/0"
                ),
                false => assert_eq!(
                    url,
                    u.clone().to_string()
                        + "/v3.0/agents/024680/attestations/0"
                ),
            };
        }
    } // get_evidence_handling_request_url_test
}
