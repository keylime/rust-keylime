use anyhow::Result;
use keylime::config::PushModelConfigTrait;
use keylime::context_info::{AlgorithmConfigurationString, ContextInfo};
use log::debug;
use std::sync::{Mutex, OnceLock};

static GLOBAL_CONTEXT: OnceLock<Mutex<Result<ContextInfo, String>>> =
    OnceLock::new();

pub fn init_context_info<T: PushModelConfigTrait>(
    config: &T,
    avoid_tpm: bool,
) -> Result<()> {
    if avoid_tpm {
        debug!("TPM is avoided, skipping context initialization.");
        return Ok(());
    }

    let result = GLOBAL_CONTEXT.set(Mutex::new(
        (|| -> Result<ContextInfo, String> {
            debug!("Initializing unique TPM Context...");
            let context_info =
                ContextInfo::new_from_str(AlgorithmConfigurationString {
                    tpm_encryption_alg: config
                        .tpm_encryption_alg()
                        .to_string(),
                    tpm_hash_alg: config.tpm_hash_alg().to_string(),
                    tpm_signing_alg: config.tpm_signing_alg().to_string(),
                    agent_data_path: config.agent_data_path().to_string(),
                    disabled_signing_algorithms: config
                        .disabled_signing_algorithms()
                        .iter()
                        .map(|e| e.to_string())
                        .collect(),
                })
                .map_err(|e| e.to_string())?;

            Ok(context_info)
        })(),
    ));

    if result.is_err() {
        debug!("Agent context has already been initialized.");
    }

    if let Some(mutex) = GLOBAL_CONTEXT.get() {
        if let Ok(guard) = mutex.lock() {
            if let Err(e) = &*guard {
                return Err(anyhow::anyhow!(
                    "TPM context initialization failed: {}",
                    e
                ));
            }
        }
    }
    Ok(())
}

pub fn get_context_info(avoid_tpm: bool) -> Result<Option<ContextInfo>> {
    if avoid_tpm {
        debug!("TPM is avoided, returning empty context.");
        return Ok(None);
    }
    let mutex = GLOBAL_CONTEXT.get().ok_or_else(|| {
        anyhow::anyhow!("TPM Global context has not been initialized yet. Please call init_context first.")
    })?;
    let guard = mutex
        .lock()
        .map_err(|e| anyhow::anyhow!("TPM context mutex poisoned: {}", e))?;
    match &*guard {
        Ok(context_info) => Ok(Some(context_info.clone())),
        Err(e) => {
            Err(anyhow::anyhow!("Stored context contains an error: {}", e))
        }
    }
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;

    use keylime::{config::get_testing_config, tpm::testing};

    #[tokio::test]
    async fn test_context_with_avoid_tpm_flag() {
        // Lock mutex to avoid race condition accessing the TPM
        // Use temporary directory instead of assuming /var/lib/keylime exists
        let _mutex = testing::lock_tests().await;
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = get_testing_config(tmpdir.path(), None);

        const AVOID_TPM: bool = true;
        let init_res = init_context_info(&config, AVOID_TPM);
        assert!(init_res.is_ok());
        let context_res = get_context_info(AVOID_TPM);
        assert!(context_res.is_ok());
        assert!(
            context_res.unwrap().is_none(),
            "Context should be None when TPM is avoided"
        );
    }

    #[tokio::test]
    async fn test_init_and_get_context() {
        // Lock mutex to avoid race condition accessing the TPM
        // Use temporary directory instead of assuming /var/lib/keylime exists
        let _mutex = testing::lock_tests().await;
        let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
        let config = get_testing_config(tmpdir.path(), None);

        const DONT_AVOID_TPM: bool = false;
        let init_res = init_context_info(&config, DONT_AVOID_TPM);
        assert!(init_res.is_ok());
        let context_res = get_context_info(DONT_AVOID_TPM);
        assert!(context_res.is_ok());
        let context_info_handler = context_res.unwrap(); //#[allow_ci]
        assert!(
            context_info_handler.is_some(),
            "Context should not be None when TPM is not avoided"
        );
        let mut context_info = context_info_handler.unwrap(); //#[allow_ci]
        context_info.flush_context().unwrap(); //#[allow_ci]
    }
}
