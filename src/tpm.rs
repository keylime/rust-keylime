use std::str::FromStr;

use crate::Result;

use tss_esapi::{
    constants::{algorithm::HashingAlgorithm, tss::*},
    Context, Tcti,
};

/*
 * Input: None
 * Return: Connection context
 *
 * Example call:
 * let mut ctx = tpm::get_tpm2_ctx();
 */
pub(crate) fn get_tpm2_ctx() -> Result<tss_esapi::Context> {
    let tcti_path = if std::path::Path::new("/dev/tpmrm0").exists() {
        "device:/dev/tpmrm0"
    } else {
        "device:/dev/tpm0"
    };

    let tcti = Tcti::from_str(tcti_path)?;
    unsafe { Context::new(tcti) }.map_err(|e| e.into())
}
