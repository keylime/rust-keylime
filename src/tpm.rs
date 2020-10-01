use std::str::FromStr;

use tss_esapi::constants::algorithm::HashingAlgorithm;
use tss_esapi::constants::tss as tss_constants;
use tss_esapi::tss2_esys::{ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER};
use tss_esapi::Context;
use tss_esapi::Tcti;

/*
 * Input: None
 * Return: Connection context
 *
 * Example call:
 * let mut ctx = tpm::get_tpm2_ctx();
 */
pub(crate) fn get_tpm2_ctx() -> Result<tss_esapi::Context, tss_esapi::Error> {
    let tcti_path = if std::path::Path::new("/dev/tpmrm0").exists() {
        "device:/dev/tpmrm0"
    } else {
        "device:/dev/tpm0"
    };

    let tcti = Tcti::from_str(tcti_path)?;
    unsafe { Context::new(tcti) }
}
