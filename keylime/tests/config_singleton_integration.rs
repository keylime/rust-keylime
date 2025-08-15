use keylime::config::{get_config, initialize_config, PushModelConfigTrait};

#[test]
fn test_configuration_singleton_behavior() {
    // Test that multiple calls to get_config() return the same reference
    let config1 = get_config();
    let config2 = get_config();

    // Verify they return the same configuration
    assert_eq!(
        config1.uuid(),
        config2.uuid(),
        "Multiple get_config() calls should return same configuration"
    );

    // Test that explicit initialization fails after auto-initialization
    let result = initialize_config();
    assert!(
        result.is_err(),
        "Explicit initialization should fail after auto-initialization"
    );
}

#[test]
fn test_config_singleton_properties() {
    // Test that we can access configuration properties efficiently through the singleton
    let config = get_config();

    // Test that we can access configuration properties
    assert!(!config.uuid().is_empty(), "UUID should not be empty");
    assert!(
        !config.keylime_dir.is_empty(),
        "Keylime dir should not be empty"
    );

    // Test multiple accesses return consistent values
    let uuid1 = config.uuid();
    let uuid2 = get_config().uuid();
    assert_eq!(
        uuid1, uuid2,
        "Multiple UUID accesses should return same value"
    );
}
