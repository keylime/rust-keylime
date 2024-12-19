use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeylimeVersion {
    pub supported_version: String,
}
