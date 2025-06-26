use keylime::config::{
    FileConfigBuilder, KeylimeConfigError, GLOBAL_CONFIG_OVERRIDE_ENV_VAR,
};

use std::{
    env,
    fs::File,
    io::Write,
    sync::{Arc, Mutex, OnceLock},
};
use tempfile::tempdir;

// This mutex is necessary to avoid race condition between tests when setting/unsetting environment
// variables
static TEST_MUTEX: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

#[test]
fn test_env_var_override() {
    let _mutex = TEST_MUTEX.get_or_init(|| Arc::new(Mutex::new(()))).lock();
    let dir = tempdir().unwrap();
    let override_file_path = dir.path().join("override.toml");
    let mut override_file = File::create(&override_file_path).unwrap();
    writeln!(override_file, "[agent]\nip = \"0.0.0.0\"").unwrap();

    // Set the environment variable for this test
    env::set_var(
        GLOBAL_CONFIG_OVERRIDE_ENV_VAR,
        override_file_path.to_str().unwrap(),
    );

    let config = FileConfigBuilder::new().build().unwrap();

    assert_eq!(config.ip, "0.0.0.0");

    // Unset the environment variable to avoid affecting other tests
    env::remove_var(GLOBAL_CONFIG_OVERRIDE_ENV_VAR);
}

#[test]
fn test_env_var_override_file_not_found() {
    let _mutex = TEST_MUTEX.get_or_init(|| Arc::new(Mutex::new(()))).lock();
    // Set the environment variable to a path that doesn't exist
    env::set_var(GLOBAL_CONFIG_OVERRIDE_ENV_VAR, "non_existent_file.toml");

    let result = FileConfigBuilder::new().build();

    // Check that the correct error is returned
    assert!(matches!(
        result,
        Err(KeylimeConfigError::MissingEnvConfigFile { .. })
    ));

    // Unset the environment variable
    env::remove_var(GLOBAL_CONFIG_OVERRIDE_ENV_VAR);
}
