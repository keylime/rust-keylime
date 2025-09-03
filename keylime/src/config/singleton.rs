// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

use super::{AgentConfig, KeylimeConfigError};
use std::sync::OnceLock;

static GLOBAL_CONFIG: OnceLock<AgentConfig> = OnceLock::new();

/// Initialize the global configuration singleton (optional explicit initialization)
///
/// This function can be called at application startup to explicitly initialize
/// the configuration. If not called, the configuration will be automatically
/// initialized on first access via `get_config()`.
///
/// # Errors
///
/// Returns `KeylimeConfigError::SingletonAlreadyInitialized` if called after
/// the configuration has already been initialized (either explicitly or automatically).
/// Returns any configuration loading error if the configuration cannot be loaded.
pub fn initialize_config() -> Result<(), KeylimeConfigError> {
    let config = AgentConfig::new()?;
    GLOBAL_CONFIG
        .set(config)
        .map_err(|_| KeylimeConfigError::SingletonAlreadyInitialized)?;
    Ok(())
}

/// Get reference to the configuration (factory method)
///
/// This is the main factory method for accessing the configuration.
/// Returns the global singleton reference. If the configuration has not been
/// initialized yet, it will be automatically initialized.
///
/// # Panics
///
/// Panics if configuration loading fails during automatic initialization.
pub fn get_config() -> &'static AgentConfig {
    #[cfg(feature = "testing")]
    {
        // In testing mode, check for testing override first
        use crate::config::testing::TESTING_CONFIG_OVERRIDE;
        use std::sync::Mutex;

        let mutex = TESTING_CONFIG_OVERRIDE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = mutex.lock() {
            if let Some(ref testing_config) = *guard {
                // If there's a testing override, we need to use Box::leak to get a static reference
                let leaked_config =
                    Box::leak(Box::new(testing_config.clone()));
                return leaked_config;
            }
        }
    }

    // Use normal singleton - AgentConfig::new() already handles testing overrides
    GLOBAL_CONFIG.get_or_init(|| {
        AgentConfig::new().expect("Failed to load configuration")
    })
}

/// Check if configuration has been initialized
///
/// This can be used for defensive programming or in tests to verify initialization state.
pub fn is_initialized() -> bool {
    GLOBAL_CONFIG.get().is_some()
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {
    use super::*;
    use crate::config::testing::get_testing_config;
    use crate::config::PushModelConfigTrait;
    use crate::config::DEFAULT_AGENT_DATA_PATH;

    #[actix_rt::test]
    async fn test_singleton() {
        let _mutex = crate::tpm::testing::lock_tests().await;
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = get_testing_config(tmpdir.path(), None);
        let _guard = crate::config::TestConfigGuard::new(config);

        // Test that get_config() works with automatic initialization
        let config = get_config();

        // Verify we got a valid configuration
        assert!(
            !config.agent_data_path().is_empty(),
            "Config should have a valid agent data path"
        );
        assert!(
            !config.keylime_dir.is_empty(),
            "Config should have a keylime directory"
        );

        assert_eq!(config.keylime_dir, tmpdir.path().display().to_string());
        assert_eq!(
            config.agent_data_path,
            tmpdir
                .path()
                .join(DEFAULT_AGENT_DATA_PATH)
                .display()
                .to_string()
        );

        // Subsequent calls should return the same instance
        let config2 = get_config();
        assert_eq!(
            config.agent_data_path(),
            config2.agent_data_path(),
            "Should return same config instance"
        );
    }
}
