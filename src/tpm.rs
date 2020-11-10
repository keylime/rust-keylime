use std::str::FromStr;

use crate::{common::config_get, Error as KeylimeError, Result};

use tss_esapi::{
    abstraction::ek, constants::algorithm::AsymmetricAlgorithm,
    handles::KeyHandle, tss2_esys::Tss2_MU_TPM2B_PUBLIC_Marshal, Context,
    Error as TssError, Tcti,
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

/*
 * Input: Connection context, asymmetric algo (optional)
 * Return: (Key handle, public cert, TPM public object)
 * Example call:
 * let (key, cert, tpm_pub) = tpm::create_ek(context, Some(AsymmetricAlgorithm::Rsa))
 */
pub(crate) fn create_ek(
    context: &mut Context,
    alg: Option<AsymmetricAlgorithm>,
) -> Result<(KeyHandle, Vec<u8>, Vec<u8>)> {
    // Set encryption algorithm
    let alg = match alg {
        Some(a) => a,
        None => {
            match config_get(
                "/etc/keylime.conf",
                "cloud_agent",
                "tpm_encryption_alg",
            )?
            .as_str()
            {
                "rsa" => AsymmetricAlgorithm::Rsa,
                "ecc" => AsymmetricAlgorithm::Ecc,
                _ => return Err(KeylimeError::Configuration(String::from("Encryption algorithm provided in keylime.conf is not supported")))
            }
        }
    };

    // Retrieve EK handle, EK pub cert, and TPM pub object
    let handle = ek::create_ek_object(context, alg)?;
    let cert = ek::retrieve_ek_pubcert(context, alg)?;
    let tpm_pub = context.read_public(handle)?;

    // Convert TPM pub object to Vec<u8>
    // See: https://github.com/fedora-iot/clevis-pin-tpm2/blob/master/src/tpm_objects.rs#L64
    let mut offset = 0u64;
    let mut tpm_pub_vec = Vec::with_capacity((tpm_pub.size + 4) as usize);

    unsafe {
        let res = Tss2_MU_TPM2B_PUBLIC_Marshal(
            &tpm_pub,
            tpm_pub_vec.as_mut_ptr(),
            tpm_pub_vec.capacity() as u64,
            &mut offset,
        );
        if res != 0 {
            panic!("out of memory or invalid data received from TPM");
        }
        tpm_pub_vec.set_len(offset as usize);
    }

    Ok((handle, cert, tpm_pub_vec))
}
