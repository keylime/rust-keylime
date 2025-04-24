use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/*****************
* POST /sessions *
*      Request.  *
******************/
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRequestAuthSupported {
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
    pub auth_supported: Vec<SessionRequestAuthSupported>,
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
pub struct SessionIdRequestAuthProvidedData {
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

    pub data: SessionIdRequestAuthProvidedData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdRequestAtttributes {
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
    pub attributes: SessionIdRequestAtttributes,
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
pub struct SessionIdResponseAtttributes {
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
    pub attributes: SessionIdResponseAtttributes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionIdResponse {
    pub data: SessionIdResponseData,
}
