use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeVersion {
    pub supported_version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeRegistrarVersion {
    pub current_version: String,
    pub supported_versions: Vec<String>,
}
