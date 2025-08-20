use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/*****************
* POST /sessions *
*      Request.  *
******************/
#[derive(Serialize, Deserialize, Debug)]
pub struct SupportedAuthMethod {
    #[serde(rename(
        serialize = "authentication_class",
        deserialize = "authentication_class"
    ))]
    pub auth_class: String,

    #[serde(rename(
        serialize = "authentication_type",
        deserialize = "authentication_type"
    ))]
    pub auth_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRequestAttributes {
    pub agent_id: String,

    #[serde(rename(
        serialize = "authentication_supported",
        deserialize = "authentication_supported"
    ))]
    pub auth_supported: Vec<SupportedAuthMethod>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRequestData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub data_type: String,
    pub attributes: SessionRequestAttributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRequest {
    pub data: SessionRequestData,
}

/*****************
* POST /sessions *
*      Response. *
******************/
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResponseChosenParams {
    pub challenge: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResponseAuthRequested {
    #[serde(rename(
        serialize = "authentication_class",
        deserialize = "authentication_class"
    ))]
    pub auth_class: String,

    #[serde(rename(
        serialize = "authentication_type",
        deserialize = "authentication_type"
    ))]
    pub auth_type: String,

    #[serde(rename(
        serialize = "chosen_parameters",
        deserialize = "chosen_parameters"
    ))]
    pub parameters: SessionResponseChosenParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResponseAttributes {
    pub agent_id: String,
    #[serde(rename(
        serialize = "authentication_requested",
        deserialize = "authentication_requested"
    ))]
    pub auth_requested: Vec<SessionResponseAuthRequested>,
    pub created_at: DateTime<Utc>,
    pub challenges_expire_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResponseData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub data_type: String,
    pub id: u64,
    pub attributes: SessionResponseAttributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResponse {
    pub data: SessionResponseData,
}

/**********************
* PATCH /sessions/:id *
*      Request.       *
***********************/
#[derive(Serialize, Deserialize, Debug)]
pub struct ProofOfPossession {
    pub message: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdRequestAuthProvided {
    #[serde(rename(
        serialize = "authentication_class",
        deserialize = "authentication_class"
    ))]
    pub auth_class: String,

    #[serde(rename(
        serialize = "authentication_type",
        deserialize = "authentication_type"
    ))]
    pub auth_type: String,

    pub data: ProofOfPossession,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionUpdateAttributes {
    pub agent_id: String,
    #[serde(rename(
        serialize = "authentication_provided",
        deserialize = "authentication_provided"
    ))]
    pub auth_provided: Vec<SessionIdRequestAuthProvided>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdRequestData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    data_type: String,
    pub id: u64,
    pub attributes: SessionUpdateAttributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdRequest {
    pub data: SessionIdRequestData,
}

/**********************
* PATCH /sessions/:id *
*      Response.      *
***********************/
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdResponseAuthData {
    pub message: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdResponseChosenParams {
    pub challenge: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdResponseAuth {
    #[serde(rename(
        serialize = "authentication_class",
        deserialize = "authentication_class"
    ))]
    pub auth_class: String,

    #[serde(rename(
        serialize = "authentication_type",
        deserialize = "authentication_type"
    ))]
    pub auth_type: String,
    #[serde(rename(
        serialize = "chosen_parameters",
        deserialize = "chosen_parameters"
    ))]
    pub params: SessionIdResponseChosenParams,
    pub data: SessionIdResponseAuthData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticationResultAttributes {
    pub agent_id: String,
    pub evaluation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    #[serde(rename(
        serialize = "authentication",
        deserialize = "authentication"
    ))]
    pub auth: Vec<SessionIdResponseAuth>,

    pub created_at: DateTime<Utc>,
    pub challenges_expire_at: DateTime<Utc>,
    pub response_received_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdResponseData {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    data_type: String,
    pub id: u64,
    pub attributes: AuthenticationResultAttributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdResponse {
    pub data: SessionIdResponseData,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn serialize_session_request() {
        let session_request = SessionRequest {
            data: SessionRequestData {
                data_type: "session".to_string(),
                attributes: SessionRequestAttributes {
                    agent_id: "example-agent".to_string(),
                    auth_supported: vec![SupportedAuthMethod {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                    }],
                },
            },
        };

        let serialized =
            serde_json::to_string_pretty(&session_request).unwrap(); //#[allow_ci]
        let expected = r#"{
  "data": {
    "type": "session",
    "attributes": {
      "agent_id": "example-agent",
      "authentication_supported": [
        {
          "authentication_class": "pop",
          "authentication_type": "tpm_pop"
        }
      ]
    }
  }
}"#;
        assert_eq!(serialized, expected);
    } // serialize_session_request

    #[test]
    fn deserialize_session_request() {
        let json = r#"{
            "data": {
                "type": "session",
                "attributes": {
                    "agent_id": "example-deserialized-agent",
                    "authentication_supported": [
                        {
                            "authentication_class": "pop",
                            "authentication_type": "tpm_pop"
                        }
                    ]
                }
            }
        }"#;
        let deserialized: SessionRequest =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(deserialized.data.data_type, "session");
        assert_eq!(
            deserialized.data.attributes.agent_id,
            "example-deserialized-agent"
        );
        assert_eq!(deserialized.data.attributes.auth_supported.len(), 1);
        assert_eq!(
            deserialized.data.attributes.auth_supported[0].auth_class,
            "pop"
        );
        assert_eq!(
            deserialized.data.attributes.auth_supported[0].auth_type,
            "tpm_pop"
        );
    } // deserialize_session_request

    #[test]
    fn serialize_session_response() {
        let session_response = SessionResponse {
            data: SessionResponseData {
                data_type: "session".to_string(),
                id: 1,
                attributes: SessionResponseAttributes {
                    agent_id: "example-agent".to_string(),
                    auth_requested: vec![SessionResponseAuthRequested {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                        parameters: SessionResponseChosenParams {
                            challenge: "example-challenge".to_string(),
                        },
                    }],
                    created_at: "2025-05-08T15:39:00Z".parse().unwrap(), //#[allow_ci]
                    challenges_expire_at: "2026-05-08T15:40:00Z"
                        .parse()
                        .unwrap(), //#[allow_ci]
                },
            },
        };

        let serialized =
            serde_json::to_string_pretty(&session_response).unwrap(); //#[allow_ci]

        let expected = r#"{
  "data": {
    "type": "session",
    "id": 1,
    "attributes": {
      "agent_id": "example-agent",
      "authentication_requested": [
        {
          "authentication_class": "pop",
          "authentication_type": "tpm_pop",
          "chosen_parameters": {
            "challenge": "example-challenge"
          }
        }
      ],
      "created_at": "2025-05-08T15:39:00Z",
      "challenges_expire_at": "2026-05-08T15:40:00Z"
    }
  }
}"#;
        assert_eq!(serialized, expected);
    } // serialize_session_response

    #[test]
    fn deserialize_session_response() {
        let json = r#"{
            "data": {
                "type": "session",
                "id": 1,
                "attributes": {
                    "agent_id": "example-deserialized-agent",
                    "authentication_requested": [
                        {
                            "authentication_class": "pop",
                            "authentication_type": "tpm_pop",
                            "chosen_parameters": {
                                "challenge": "example-deserialized-challenge"
                            }
                        }
                    ],
                    "created_at": "2025-05-08T15:39:00Z",
                    "challenges_expire_at": "2026-05-08T15:39:00Z"
                }
            }
        }"#;
        let deserialized: SessionResponse =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(deserialized.data.data_type, "session");
        assert_eq!(deserialized.data.id, 1);
        assert_eq!(
            deserialized.data.attributes.agent_id,
            "example-deserialized-agent"
        );
        assert_eq!(deserialized.data.attributes.auth_requested.len(), 1);
        assert_eq!(
            deserialized.data.attributes.auth_requested[0].auth_class,
            "pop"
        );
        assert_eq!(
            deserialized.data.attributes.auth_requested[0].auth_type,
            "tpm_pop"
        );
        assert_eq!(
            deserialized.data.attributes.auth_requested[0]
                .parameters
                .challenge,
            "example-deserialized-challenge"
        );
    } // deserialize_session_response

    #[test]
    fn session_id_request_serialization() {
        let session_id_request = SessionIdRequest {
            data: SessionIdRequestData {
                data_type: "session".to_string(),
                id: 1,
                attributes: SessionUpdateAttributes {
                    agent_id: "example-agent".to_string(),
                    auth_provided: vec![SessionIdRequestAuthProvided {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                        data: ProofOfPossession {
                            message: "example-message".to_string(),
                            signature: "example-signature".to_string(),
                        },
                    }],
                },
            },
        };

        let serialized =
            serde_json::to_string_pretty(&session_id_request).unwrap(); //#[allow_ci]
        let expected = r#"{
  "data": {
    "type": "session",
    "id": 1,
    "attributes": {
      "agent_id": "example-agent",
      "authentication_provided": [
        {
          "authentication_class": "pop",
          "authentication_type": "tpm_pop",
          "data": {
            "message": "example-message",
            "signature": "example-signature"
          }
        }
      ]
    }
  }
}"#;
        assert_eq!(serialized, expected);
    } // session_id_request_serialization

    #[test]
    fn session_id_request_deserialization() {
        let json = r#"{
            "data": {
                "type": "session",
                "id": 1,
                "attributes": {
                    "agent_id": "example-deserialized-agent",
                    "authentication_provided": [
                        {
                            "authentication_class": "pop",
                            "authentication_type": "tpm_pop",
                            "data": {
                                "message": "example-deserialized-message",
                                "signature": "example-deserialized-signature"
                            }
                        }
                    ]
                }
            }
        }"#;
        let deserialized: SessionIdRequest =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(deserialized.data.data_type, "session");
        assert_eq!(deserialized.data.id, 1);
        assert_eq!(
            deserialized.data.attributes.agent_id,
            "example-deserialized-agent"
        );
        assert_eq!(deserialized.data.attributes.auth_provided.len(), 1);
        assert_eq!(
            deserialized.data.attributes.auth_provided[0].auth_class,
            "pop"
        );
        assert_eq!(
            deserialized.data.attributes.auth_provided[0].auth_type,
            "tpm_pop"
        );
        assert_eq!(
            deserialized.data.attributes.auth_provided[0].data.message,
            "example-deserialized-message"
        );
    } // session_id_request_deserialization

    #[test]
    fn session_id_success_response_serialization() {
        let session_id_response = SessionIdResponse {
            data: SessionIdResponseData {
                data_type: "session".to_string(),
                id: 1,
                attributes: AuthenticationResultAttributes {
                    agent_id: "example-agent".to_string(),
                    evaluation: "success".to_string(),
                    token: Some("example-token".to_string()),
                    auth: vec![SessionIdResponseAuth {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                        params: SessionIdResponseChosenParams {
                            challenge: "example-challenge".to_string(),
                        },
                        data: SessionIdResponseAuthData {
                            message: "example-message".to_string(),
                            signature: "example-signature".to_string(),
                        },
                    }],
                    created_at: "2025-05-08T15:39:00Z".parse().unwrap(), //#[allow_ci]
                    challenges_expire_at: "2026-05-08T15:40:00Z"
                        .parse()
                        .unwrap(), //#[allow_ci]
                    response_received_at: "2025-05-08T15:39:01Z"
                        .parse()
                        .unwrap(), //#[allow_ci]
                    token_expires_at: Some(
                        "2026-05-08T15:41:00Z"
                            .parse::<DateTime<Utc>>()
                            .unwrap(), //#[allow_ci]
                    ),
                },
            },
        };

        let serialized =
            serde_json::to_string_pretty(&session_id_response).unwrap(); //#[allow_ci]
        let expected = r#"{
  "data": {
    "type": "session",
    "id": 1,
    "attributes": {
      "agent_id": "example-agent",
      "evaluation": "success",
      "token": "example-token",
      "authentication": [
        {
          "authentication_class": "pop",
          "authentication_type": "tpm_pop",
          "chosen_parameters": {
            "challenge": "example-challenge"
          },
          "data": {
            "message": "example-message",
            "signature": "example-signature"
          }
        }
      ],
      "created_at": "2025-05-08T15:39:00Z",
      "challenges_expire_at": "2026-05-08T15:40:00Z",
      "response_received_at": "2025-05-08T15:39:01Z",
      "token_expires_at": "2026-05-08T15:41:00Z"
    }
  }
}"#;
        assert_eq!(serialized, expected);
    } // session_id_success_response_serialization

    #[test]
    fn session_id_success_response_deserialization() {
        let json = r#"{
            "data": {
                "type": "session",
                "id": 1,
                "attributes": {
                    "agent_id": "example-deserialized-agent",
                    "evaluation": "success",
                    "token": "example-deserialized-token",
                    "authentication": [
                        {
                            "authentication_class": "pop",
                            "authentication_type": "tpm_pop",
                            "chosen_parameters": {
                                "challenge": "example-deserialized-challenge"
                            },
                            "data": {
                                "message": "example-deserialized-message",
                                "signature": "example-deserialized-signature"
                            }
                        }
                    ],
                    "created_at": "2025-05-08T15:39:00Z",
                    "challenges_expire_at": "2026-05-08T15:39:00Z",
                    "response_received_at": "2025-05-08T15:39:00Z",
                    "token_expires_at": "2026-05-08T15:39:00Z"
                }
            }
        }"#;
        let deserialized: SessionIdResponse =
            serde_json::from_str(json).unwrap(); //#[allow_ci]
        assert_eq!(deserialized.data.data_type, "session");
        assert_eq!(deserialized.data.id, 1);
        assert_eq!(
            deserialized.data.attributes.agent_id,
            "example-deserialized-agent"
        );
        assert_eq!(deserialized.data.attributes.evaluation, "success");
        assert_eq!(
            deserialized.data.attributes.token,
            Some("example-deserialized-token".to_string())
        );
        assert_eq!(deserialized.data.attributes.auth.len(), 1);
        assert_eq!(deserialized.data.attributes.auth[0].auth_class, "pop");
        assert_eq!(deserialized.data.attributes.auth[0].auth_type, "tpm_pop");
        assert_eq!(
            deserialized.data.attributes.auth[0].params.challenge,
            "example-deserialized-challenge"
        );
        assert_eq!(
            deserialized.data.attributes.created_at,
            "2025-05-08T15:39:00Z".parse::<DateTime<Utc>>().unwrap() //#[allow_ci]
        );
        assert_eq!(
            deserialized.data.attributes.challenges_expire_at,
            "2026-05-08T15:39:00Z".parse::<DateTime<Utc>>().unwrap() //#[allow_ci]
        );
        assert_eq!(
            deserialized.data.attributes.response_received_at,
            "2025-05-08T15:39:00Z".parse::<DateTime<Utc>>().unwrap() //#[allow_ci]
        );
        assert_eq!(
            deserialized.data.attributes.token_expires_at,
            Some(
                "2026-05-08T15:39:00Z".parse::<DateTime<Utc>>().unwrap() //#[allow_ci]
            )
        );
        assert_eq!(
            deserialized.data.attributes.auth[0].data.message,
            "example-deserialized-message"
        );
        assert_eq!(
            deserialized.data.attributes.auth[0].data.signature,
            "example-deserialized-signature"
        );
    } // session_id_success_response_deserialization

    #[test]
    fn session_id_failure_response_serialization() {
        let session_id_response = SessionIdResponse {
            data: SessionIdResponseData {
                data_type: "session".to_string(),
                id: 1,
                attributes: AuthenticationResultAttributes {
                    agent_id: "example-agent".to_string(),
                    evaluation: "fail".to_string(),
                    token: None,
                    auth: vec![SessionIdResponseAuth {
                        auth_class: "pop".to_string(),
                        auth_type: "tpm_pop".to_string(),
                        params: SessionIdResponseChosenParams {
                            challenge: "challenge-example".to_string(),
                        },
                        data: SessionIdResponseAuthData {
                            message: "message-example".to_string(),
                            signature: "signature-example".to_string(),
                        },
                    }],
                    created_at: "2025-04-03T09:44:12Z".parse().unwrap(), //#[allow_ci]
                    challenges_expire_at: "2025-04-03T14:56:57Z"
                        .parse()
                        .unwrap(), //#[allow_ci]
                    response_received_at: "2025-04-03T15:56:57Z"
                        .parse()
                        .unwrap(), //#[allow_ci]
                    token_expires_at: None,
                },
            },
        };
        let serialized =
            serde_json::to_string_pretty(&session_id_response).unwrap(); //#[allow_ci]
        let expected = r#"{
  "data": {
    "type": "session",
    "id": 1,
    "attributes": {
      "agent_id": "example-agent",
      "evaluation": "fail",
      "authentication": [
        {
          "authentication_class": "pop",
          "authentication_type": "tpm_pop",
          "chosen_parameters": {
            "challenge": "challenge-example"
          },
          "data": {
            "message": "message-example",
            "signature": "signature-example"
          }
        }
      ],
      "created_at": "2025-04-03T09:44:12Z",
      "challenges_expire_at": "2025-04-03T14:56:57Z",
      "response_received_at": "2025-04-03T15:56:57Z"
    }
  }
}"#;
        assert_eq!(serialized, expected);
    } // session_id_failure_response_serialization
} // tests
