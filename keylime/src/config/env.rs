// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors
use crate::config::KeylimeConfigError;
use config::{ConfigError, Environment, Map, Source, Value};
use log::*;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct EnvConfig {
    map: HashMap<String, Value>,
}

impl EnvConfig {
    pub fn new() -> Result<Self, KeylimeConfigError> {
        let env_source = Environment::with_prefix("KEYLIME_AGENT")
            .separator(".")
            .prefix_separator("_");

        // Log debug message for configuration obtained from environment
        env_source
            .collect()?
            .iter()
            .for_each(|(c, v)| debug!("Environment configuration {c}={v}"));

        // Return an EnvConfig containing the collected environment variables in a format that
        // allows it to be used as a Source for AgentConfig
        Ok(EnvConfig {
            map: Map::from([(
                "agent".to_string(),
                Value::from(env_source.collect()?),
            )]),
        })
    }
}

impl Source for EnvConfig {
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        Ok(self.map.clone())
    }

    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::config::{get_testing_config, AgentConfig};
    use config::Config;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Wrapper {
        agent: AgentConfig,
    }

    #[test]
    fn test_env_config_as_source() {
        // Get the configuration using a temporary directory as `keylime_dir`
        let tempdir =
            tempfile::tempdir().expect("failed to create temporary dir");
        let default = get_testing_config(tempdir.path(), None);

        let env_config = EnvConfig::new().unwrap(); //#[allow_ci]

        // Test that the EnvConfig can be used as a source for AgentConfig
        let _config: Wrapper = Config::builder()
            .add_source(default)
            .add_source(env_config)
            .build()
            .expect("failed to build config")
            .try_deserialize()
            .expect("failed to deserialize config");
    }

    #[test]
    fn test_env_var() {
        let override_map: Map<&str, &str> = Map::from([
            ("KEYLIME_AGENT_AGENT_DATA_PATH", "override_agent_data_path"),
            ("KEYLIME_AGENT_ALLOW_PAYLOAD_REVOCATION_ACTIONS", "false"),
            ("KEYLIME_AGENT_API_VERSIONS", "latest"),
            ("KEYLIME_AGENT_CONTACT_IP", "override_contact_ip"),
            ("KEYLIME_AGENT_CONTACT_PORT", "9999"),
            (
                "KEYLIME_AGENT_DEC_PAYLOAD_FILE",
                "override_dec_payload_file",
            ),
            ("KEYLIME_AGENT_EK_HANDLE", "override_ek_handle"),
            ("KEYLIME_AGENT_ENABLE_AGENT_MTLS", "false"),
            ("KEYLIME_AGENT_ENABLE_IAK_IDEVID", "true"),
            ("KEYLIME_AGENT_ENABLE_INSECURE_PAYLOAD", "true"),
            ("KEYLIME_AGENT_ENABLE_REVOCATION_NOTIFICATIONS", "false"),
            ("KEYLIME_AGENT_ENC_KEYNAME", "override_enc_keyname"),
            ("KEYLIME_AGENT_EXTRACT_PAYLOAD_ZIP", "false"),
            ("KEYLIME_AGENT_IAK_CERT", "override_iak_cert"),
            ("KEYLIME_AGENT_IAK_HANDLE", "override_iak_handle"),
            (
                "KEYLIME_AGENT_IAK_IDEVID_ASYMMETRIC_ALG",
                "override_iak_idevid_asymmetric_alg",
            ),
            (
                "KEYLIME_AGENT_IAK_IDEVID_NAME_ALG",
                "override_iak_idevid_name_alg",
            ),
            (
                "KEYLIME_AGENT_IAK_IDEVID_TEMPLATE",
                "override_iak_idevid_template",
            ),
            ("KEYLIME_AGENT_IAK_PASSWORD", "override_iak_password"),
            ("KEYLIME_AGENT_IDEVID_CERT", "override_idevid_cert"),
            ("KEYLIME_AGENT_IDEVID_HANDLE", "override_idevid_handle"),
            ("KEYLIME_AGENT_IDEVID_PASSWORD", "override_idevid_password"),
            ("KEYLIME_AGENT_IMA_ML_PATH", "override_ima_ml_path"),
            ("KEYLIME_AGENT_IP", "override_ip"),
            ("KEYLIME_AGENT_KEYLIME_DIR", "override_keylime_dir"),
            (
                "KEYLIME_AGENT_MEASUREDBOOT_ML_PATH",
                "override_measuredboot_ml_path",
            ),
            ("KEYLIME_AGENT_PAYLOAD_SCRIPT", "override_payload_script"),
            ("KEYLIME_AGENT_PORT", "9999"),
            ("KEYLIME_AGENT_REGISTRAR_IP", "override_registrar_ip"),
            ("KEYLIME_AGENT_REGISTRAR_PORT", "9999"),
            (
                "KEYLIME_AGENT_REVOCATION_ACTIONS",
                "override_revocation_actions",
            ),
            (
                "KEYLIME_AGENT_REVOCATION_ACTIONS_DIR",
                "override_revocation_actions_dir",
            ),
            ("KEYLIME_AGENT_REVOCATION_CERT", "override_revocation_cert"),
            (
                "KEYLIME_AGENT_REVOCATION_NOTIFICATION_IP",
                "override_revocation_notification_ip",
            ),
            ("KEYLIME_AGENT_REVOCATION_NOTIFICATION_PORT", "9999"),
            ("KEYLIME_AGENT_RUN_AS", "override_run_as"),
            ("KEYLIME_AGENT_SECURE_SIZE", "override_secure_size"),
            ("KEYLIME_AGENT_SERVER_CERT", "override_server_cert"),
            ("KEYLIME_AGENT_SERVER_KEY", "override_server_key"),
            (
                "KEYLIME_AGENT_SERVER_KEY_PASSWORD",
                "override_server_key_password",
            ),
            (
                "KEYLIME_AGENT_TPM_ENCRYPTION_ALG",
                "override_tpm_encryption_alg",
            ),
            ("KEYLIME_AGENT_TPM_HASH_ALG", "override_tpm_hash_alg"),
            (
                "KEYLIME_AGENT_TPM_OWNERPASSWORD",
                "override_tpm_ownerpassword",
            ),
            ("KEYLIME_AGENT_TPM_SIGNING_ALG", "override_tpm_signing_alg"),
            (
                "KEYLIME_AGENT_TRUSTED_CLIENT_CA",
                "override_trusted_client_ca",
            ),
            ("KEYLIME_AGENT_UUID", "override_uuid"),
            ("KEYLIME_AGENT_VERSION", "override_version"),
        ]);

        // Get the configuration using a temporary directory as `keylime_dir`
        let tempdir =
            tempfile::tempdir().expect("failed to create temporary dir");
        let default = get_testing_config(tempdir.path(), None);

        // For possible variable
        for (c, v) in override_map.into_iter() {
            // Create a source emulating the environment with a variable set
            let env_source = Environment::with_prefix("KEYLIME_AGENT")
                .separator(".")
                .prefix_separator("_")
                .source(Some(Map::from([(c.into(), v.into())])));

            let env_config = EnvConfig {
                map: Map::from([(
                    "agent".to_string(),
                    Value::from(
                        env_source
                            .collect()
                            .expect("failed to collect env options"),
                    ),
                )]),
            };

            // Create the resulting configuration with a variable overriden
            let overriden: Wrapper = Config::builder()
                .add_source(default.clone())
                .add_source(env_config)
                .build()
                .unwrap() //#[allow_ci]
                .try_deserialize()
                .unwrap(); //#[allow_ci]

            let m = overriden
                .agent
                .collect()
                .expect("Failed to collect env options");
            let internal = m
                .get("agent")
                .expect("Failed to get the internal agent config");
            let obtained = internal
                .to_owned()
                .into_table()
                .expect("failed to convert map into table");

            // Create the expected result by manually replacing the value
            let d = default
                .collect()
                .expect("failed to collect default options");
            let i = d
                .get("agent")
                .expect("failed to get default internal agent config");
            let mut expected = i
                .to_owned()
                .into_table()
                .expect("failed to convert map into table");
            _ = expected.insert(
                c.to_lowercase()
                    .strip_prefix("keylime_agent_")
                    .unwrap() //#[allow_ci]
                    .into(),
                v.into(),
            );

            // Check that the obtained configuration matches the expected one
            for (i, e) in expected.iter() {
                let j = obtained.get(i).unwrap(); //#[allow_ci]
                assert!(
                    e.to_string() == j.to_string(),
                    "Option {i} mismatch: expected == '{e}', obtained == '{j}'"
                );
            }
        }
    }
}
