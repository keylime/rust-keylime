use std::collections::HashMap;
use std::str::FromStr;
use tss_esapi::constants::algorithm::HashingAlgorithm;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::{ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER};
use tss_esapi::Context;
use tss_esapi::Tcti;

fn int_to_string(num: u32) -> String {
    let mut num = num;
    let mut result = String::new();

    loop {
        let chr: u8 = (num & 0xFF) as u8;
        num >>= 8;
        if chr == 0 {
            continue;
        }
        let chr = char::from(chr);
        result.insert(0, chr);
        if num == 0 {
            break;
        }
    }
    result
}

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

/*
 * Input: None
 * Return:
 *   TPM Vendor Type
 *   tss_esapi::Error
 *
 * get_tpm_vendor will retrieve the type of TPM. This allows us
 * to perform opertions, such as understand the host is using a
 * software TPM as opposed to hardware TPM.
 */
pub fn get_tpm_vendor(ctx: &mut tss_esapi::Context) -> Result<String, tss_esapi::Error> {
    // let mut ctx = get_tpm2_ctx()?;

    let mut allprops = HashMap::new();
    let (capabs, more) = ctx.get_capabilities(
        TPM2_CAP_TPM_PROPERTIES,
        TPM2_PT_MANUFACTURER,
        80,
    )?;

    if capabs.capability != TPM2_CAP_TPM_PROPERTIES {
        panic!("Invalid property returned");
    }

    // SAFETY: This is a C union, and Rust wants us to make sure we're using the correct one.
    // We checked the returned capability type just above, so this should be fine.
    unsafe {
        for i in 0..capabs.data.tpmProperties.count {
            let capab = capabs.data.tpmProperties.tpmProperty[i as usize];
            allprops.insert(capab.property, capab.value);
        }
    }

    // * Use a set of constants (TPM2_PT_VENDOR_STRING_{1,2,3,4}) as lookup indexes
    // into allprops, to get all the values from there where they're set.
    // * Remove the values that don't exist (is_some)
    // * Remove the Option<_> wrappers (unwrap())
    // * Remove the items that are actually a value (i.e. != && 0)
    // * Put the individual parts through int_to_str to get a Vec<String>
    // * Make a single string from them (.join("")).
    // * Remove any whitespace on the end resulting string
    let mut vend_strs: String = [
        TPM2_PT_VENDOR_STRING_1,
        TPM2_PT_VENDOR_STRING_2,
        TPM2_PT_VENDOR_STRING_3,
        TPM2_PT_VENDOR_STRING_4,
    ]
    .iter()
    .map(|propid| allprops.get(&propid))
    .filter(|x| x.is_some())
    .map(|x| x.unwrap())
    .filter(|x| x != &&0)
    .map(|x| int_to_string(*x))
    .collect::<Vec<String>>()
    .join("");
    Ok(vend_strs.split_whitespace().collect())
}
