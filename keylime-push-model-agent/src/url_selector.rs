// SPDX-License-agent_identifier: Apache-2.0
// Copyright 2025 Keylime Authors
pub const DEFAULT_API_VERSION: &str = "v3.0";
const DEFAULT_INDEX: &str = "1";

pub struct UrlArgs {
    pub verifier_url: String,
    pub agent_identifier: Option<String>,
    pub api_version: Option<String>,
    pub attestation_index: Option<String>,
    pub session_index: Option<String>,
}

pub fn get_attestation_index(args: &UrlArgs) -> String {
    if args.attestation_index.is_some() {
        return args.attestation_index.clone().unwrap();
    }
    DEFAULT_INDEX.to_string()
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

#[allow(dead_code)]
pub fn get_evidence_handling_request_url(args: &UrlArgs) -> String {
    let id = args.agent_identifier.clone().unwrap();
    let verifier_url = args.verifier_url.clone();
    let api_version = get_api_version(args);
    if verifier_url.ends_with('/') {
        return format!(
            "{verifier_url}{api_version}/agents/{id}/attestations"
        );
    }
    format!("{verifier_url}/{api_version}/agents/{id}/attestations")
}

#[allow(dead_code)]
pub fn get_evidence_handling_request_url_with_index(
    args: &UrlArgs,
) -> String {
    let id = args.agent_identifier.clone().unwrap();
    let verifier_url = args.verifier_url.clone();
    let api_version = get_api_version(args);
    let index_suffix = get_index_suffix(args);
    if verifier_url.ends_with('/') {
        return format!(
            "{verifier_url}{api_version}/agents/{id}/attestations{index_suffix}"
        );
    }
    format!(
        "{verifier_url}/{api_version}/agents/{id}/attestations{index_suffix}"
    )
}

#[allow(dead_code)]
fn get_index_suffix(args: &UrlArgs) -> String {
    let index = get_attestation_index(args);
    if args.attestation_index.is_some() {
        return format!("/{index}");
    }
    "".to_string()
}

#[allow(dead_code)]
pub fn get_session_request_url(args: &UrlArgs) -> String {
    let verifier_url = args.verifier_url.clone();
    let api_version = get_api_version(args);
    if verifier_url.ends_with('/') {
        match args.session_index {
            Some(ref index) => {
                return format!(
                    "{verifier_url}{api_version}/sessions/{index}"
                );
            }
            None => {
                return format!("{verifier_url}{api_version}/sessions");
            }
        }
    }
    match args.session_index {
        Some(ref index) => {
            format!("{verifier_url}/{api_version}/sessions/{index}")
        }
        None => format!("{verifier_url}/{api_version}/sessions"),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn get_attestation_index_test() {
        let index = get_attestation_index(&UrlArgs {
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            api_version: Some(DEFAULT_API_VERSION.to_string()),
            agent_identifier: Some("024680".to_string()),
            session_index: None,
            attestation_index: Some("2".to_string()),
        });
        assert_eq!(index, "2".to_string());
    } // get_attestation_index_test

    #[test]
    fn get_attestation_request_url_test() {
        let url = get_negotiations_request_url(&UrlArgs {
            api_version: None,
            verifier_url: "https://1.2.3.4:5678/".to_string(),
            agent_identifier: Some("024680".to_string()),
            attestation_index: Some("2".to_string()),
            session_index: None,
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
            let url = get_evidence_handling_request_url(&UrlArgs {
                verifier_url: u.clone(),
                api_version: Some(DEFAULT_API_VERSION.to_string()),
                agent_identifier: Some("024680".to_string()),
                session_index: None,
                attestation_index: Some("2".to_string()),
            });

            match u.clone().ends_with('/') {
                true => assert_eq!(
                    url,
                    u.clone().to_string() + "v3.0/agents/024680/attestations"
                ),
                false => assert_eq!(
                    url,
                    u.clone().to_string()
                        + "/v3.0/agents/024680/attestations"
                ),
            };
        }
    } // get_evidence_handling_request_url_test

    #[test]
    fn get_sessions_request_url_test() {
        let urls = vec![
            "https://1.2.3.4:5678/".to_string(),
            "https://1.2.3.4:5678".to_string(),
            "http://1.2.3.4:5678/".to_string(),
            "http://1.2.3.4:5678".to_string(),
        ];
        for u in urls {
            let url = get_session_request_url(&UrlArgs {
                verifier_url: u.clone(),
                api_version: Some(DEFAULT_API_VERSION.to_string()),
                agent_identifier: None,
                session_index: Some("024680".to_string()),
                attestation_index: None,
            });

            match u.clone().ends_with('/') {
                true => assert_eq!(
                    url,
                    u.clone().to_string() + "v3.0/sessions/024680"
                ),
                false => assert_eq!(
                    url,
                    u.clone().to_string() + "/v3.0/sessions/024680"
                ),
            };
        }
    } // get_sessions_request_url_test

    #[test]
    fn get_sessions_request_url_no_session_test() {
        let urls = vec![
            "https://1.2.3.4:5678/".to_string(),
            "https://1.2.3.4:5678".to_string(),
            "http://1.2.3.4:5678/".to_string(),
            "http://1.2.3.4:5678".to_string(),
        ];
        for u in urls {
            let url = get_session_request_url(&UrlArgs {
                verifier_url: u.clone(),
                api_version: Some(DEFAULT_API_VERSION.to_string()),
                agent_identifier: None,
                session_index: None,
                attestation_index: None,
            });

            match u.clone().ends_with('/') {
                true => {
                    assert_eq!(url, u.clone().to_string() + "v3.0/sessions")
                }
                false => {
                    assert_eq!(url, u.clone().to_string() + "/v3.0/sessions")
                }
            };
        }
    } // get_sessions_request_url_no_session_test

    #[test]
    fn get_attestation_index_test_no_index() {
        assert_eq!(
            get_attestation_index(&UrlArgs {
                verifier_url: "https://1.2.3.4:5678/".to_string(),
                api_version: Some(DEFAULT_API_VERSION.to_string()),
                agent_identifier: Some("024680".to_string()),
                session_index: None,
                attestation_index: None,
            }),
            DEFAULT_INDEX.to_string()
        );
    } // get_attestation_index_test_no_index

    #[test]
    fn get_evidence_handling_request_with_index_test() {
        for v_url in [
            "https://1.2.3.4:1234/".to_string(),
            "https://1.2.3.4:1234".to_string(),
        ] {
            assert_eq!(
                get_evidence_handling_request_url_with_index(&UrlArgs {
                    verifier_url: v_url,
                    api_version: Some(DEFAULT_API_VERSION.to_string()),
                    agent_identifier: Some("024680".to_string()),
                    session_index: None,
                    attestation_index: None,
                }),
                "https://1.2.3.4:1234/v3.0/agents/024680/attestations"
                    .to_string()
            );
        }
    } // get_evidence_handling_request_with_index_test
}
