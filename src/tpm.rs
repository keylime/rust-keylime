// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use std::str::FromStr;

use crate::{common::config_get, Error as KeylimeError, Result};

use tss_esapi::{
    abstraction::ek, constants::algorithm::AsymmetricAlgorithm,
    handles::KeyHandle, tss2_esys::Tss2_MU_TPM2B_PUBLIC_Marshal, Context,
    Tcti,
};

/*
 * Input: None
 * Return: Connection context
 *
 * Example call:
 * let mut ctx = tpm::get_tpm2_ctx();
 */
pub(crate) fn get_tpm2_ctx() -> Result<Context> {
    let tcti_path = match std::env::var("TCTI") {
        Ok(val) => val,
        Err(_) => if std::path::Path::new("/dev/tpmrm0").exists() {
            "device:/dev/tpmrm0"
        } else {
            "device:/dev/tpm0"
        }
        .to_string(),
    };

    let tcti = Tcti::from_str(&tcti_path)?;
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
    let (tpm_pub, _, _) = context.read_public(handle)?;

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
            panic!("out of memory or invalid data received from TPM"); //#[allow_ci]
        }
        tpm_pub_vec.set_len(offset as usize);
    }

    Ok((handle, cert, tpm_pub_vec))
}

/* Converts a hex value in the form of a string (ex. from keylime.conf's
 * ek_handle) to a key handle.
 *
 * Input: &str
 * Return: Key handle
 *
 * Example call:
 * let ek_handle = tpm::ek_from_hex_str("0x81000000");
 */
pub(crate) fn ek_from_hex_str(val: &str) -> Result<KeyHandle> {
    let val = val.trim_start_matches("0x");
    Ok(KeyHandle::from(u32::from_str_radix(val, 16)?))
}

#[test]
fn ek_from_hex() {
    assert_eq!(
        ek_from_hex_str("0x81000000").unwrap(), //#[allow_ci]
        ek_from_hex_str("81000000").unwrap()    //#[allow_ci]
    );
    assert_eq!(
        ek_from_hex_str("0xdeadbeef").unwrap(), //#[allow_ci]
        ek_from_hex_str("deadbeef").unwrap()    //#[allow_ci]
    );

    assert!(ek_from_hex_str("a").is_ok());
    assert!(ek_from_hex_str("18bb9").is_ok());

    assert!(ek_from_hex_str("qqq").is_err());
    assert!(ek_from_hex_str("0xqqq").is_err());
    assert!(ek_from_hex_str("0xdeadbeefqwerty").is_err());
    assert!(ek_from_hex_str("0x0x0x").is_err());
}
