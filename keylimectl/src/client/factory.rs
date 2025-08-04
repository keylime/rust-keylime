// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Client factory for caching client instances
//!
//! This module provides a factory pattern for creating and caching client
//! instances (VerifierClient, RegistrarClient). Each client is created once
//! per command execution and reused to avoid redundant API version detection.
//!
//! The factory uses `std::sync::OnceLock` to cache clients. Since keylimectl
//! is single-threaded (one command per execution), this provides efficient
//! caching. Note that `OnceLock` can only be initialized once per process
//! lifetime, which is perfect for our use case.

use crate::client::{registrar::RegistrarClient, verifier::VerifierClient};
use crate::config::singleton::get_config;
use crate::error::KeylimectlError;
use std::sync::OnceLock;

static VERIFIER_CLIENT: OnceLock<VerifierClient> = OnceLock::new();
static REGISTRAR_CLIENT: OnceLock<RegistrarClient> = OnceLock::new();

/// Get or create the verifier client
///
/// This function returns a cached verifier client if one exists, or creates
/// a new one if this is the first call. The client is cached for the duration
/// of the process (which is typically one command execution for keylimectl).
///
/// # Errors
///
/// Returns an error if the client cannot be created (e.g., network issues,
/// invalid configuration, or API version detection failure).
///
/// # Examples
///
/// ```rust,ignore
/// use keylimectl::client::factory;
///
/// let verifier = factory::get_verifier().await?;
/// let agents = verifier.list_agents(None).await?;
/// ```
pub async fn get_verifier() -> Result<&'static VerifierClient, KeylimectlError>
{
    if let Some(client) = VERIFIER_CLIENT.get() {
        return Ok(client);
    }

    // Create and initialize the client
    let config = get_config();
    let client = VerifierClient::builder().config(config).build().await?;

    // Try to set it (might fail if another task beat us to it, which is fine)
    match VERIFIER_CLIENT.set(client) {
        Ok(()) => Ok(VERIFIER_CLIENT.get().unwrap()), //#[allow_ci]
        Err(client) => {
            // Another task already set it, return the existing one
            // But this shouldn't happen in single-threaded keylimectl
            drop(client);
            Ok(VERIFIER_CLIENT.get().unwrap()) //#[allow_ci]
        }
    }
}

/// Get or create the registrar client
///
/// This function returns a cached registrar client if one exists, or creates
/// a new one if this is the first call. The client is cached for the duration
/// of the process.
///
/// # Errors
///
/// Returns an error if the client cannot be created.
///
/// # Examples
///
/// ```rust,ignore
/// use keylimectl::client::factory;
///
/// let registrar = factory::get_registrar().await?;
/// let agent_data = registrar.get_agent("agent-uuid").await?;
/// ```
pub async fn get_registrar(
) -> Result<&'static RegistrarClient, KeylimectlError> {
    if let Some(client) = REGISTRAR_CLIENT.get() {
        return Ok(client);
    }

    // Create and initialize the client
    let config = get_config();
    let client = RegistrarClient::builder().config(config).build().await?;

    // Try to set it
    match REGISTRAR_CLIENT.set(client) {
        Ok(()) => Ok(REGISTRAR_CLIENT.get().unwrap()), //#[allow_ci]
        Err(client) => {
            drop(client);
            Ok(REGISTRAR_CLIENT.get().unwrap()) //#[allow_ci]
        }
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests are limited because we can't easily reset OnceLock
    // in unit tests (it's designed to be set once per process lifetime).
    // Integration tests would be better for testing the factory pattern.

    #[test]
    fn test_factory_exists() {
        // Just verify the module compiles and functions are callable
        // No assertions needed - compilation success is the test
    }
}
