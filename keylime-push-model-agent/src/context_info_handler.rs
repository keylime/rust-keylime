use anyhow::Result;
use keylime::config::PushModelConfigTrait;
use keylime::context_info::{AlgorithmConfigurationString, ContextInfo};
use log::debug;
use std::sync::{Mutex, OnceLock};

static GLOBAL_CONTEXT: OnceLock<Mutex<Result<ContextInfo, String>>> =
    OnceLock::new();

pub fn init_context_info(avoid_tpm: bool) -> Result<()> {
    if avoid_tpm {
        debug!("TPM is avoided, skipping context initialization.");
        return Ok(());
    }

    let result = GLOBAL_CONTEXT.set(Mutex::new(
        (|| -> Result<ContextInfo, String> {
            let config = keylime::config::PushModelConfig::default();
            debug!("Initializing unique TPM Context...");
            let context_info =
                ContextInfo::new_from_str(AlgorithmConfigurationString {
                    tpm_encryption_alg: config.get_tpm_encryption_alg(),
                    tpm_hash_alg: config.get_tpm_hash_alg(),
                    tpm_signing_alg: config.get_tpm_signing_alg(),
                    agent_data_path: config.get_agent_data_path(),
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "testing")]
    use super::*;

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_context_with_avoid_tpm_flag() {
        const AVOID_TPM: bool = true;
        let init_res = init_context_info(AVOID_TPM);
        assert!(init_res.is_ok());
        let context_res = get_context_info(AVOID_TPM);
        assert!(context_res.is_ok());
        assert!(
            context_res.unwrap().is_none(),
            "Context should be None when TPM is avoided"
        );
    }
}
