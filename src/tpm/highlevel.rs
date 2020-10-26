// NOTE: The functions in this function may make their way to the tss-esapi crate
// at some later time, but we're stabilizing them here first.

use crate::error::Result;

use tss_esapi::constants::algorithm::AsymmetricAlgorithm;
use tss_esapi::constants::tss as tss_const;
use tss_esapi::handles::{
    AuthHandle, NvIndexHandle, NvIndexTpmHandle, TpmHandle,
};
use tss_esapi::session::Session;
use tss_esapi::tss2_esys::TPM2B_PUBLIC;
use tss_esapi::utils::{
    ObjectAttributes, PublicIdUnion, PublicParmsUnion, Tpm2BPublicBuilder,
};
use tss_esapi::Context;

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Section 2.2.1.4 (Low Range) for Windows compatibility
const RSA_2048_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c00002;
const ECC_P256_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0000a;

pub(super) fn nv_read_full(
    ctx: &mut Context,
    auth_handle: AuthHandle,
    nv_index_handle: NvIndexHandle,
    size: usize,
) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result.reserve_exact(size);

    let jump: usize = 512;

    for offset in (0..size).step_by(jump) {
        let size: u16 = std::cmp::min(jump, size - offset) as u16;

        let res =
            ctx.nv_read(auth_handle, nv_index_handle, size, offset as u16)?;
        result.extend_from_slice(&res);
    }

    Ok(result)
}

fn create_nullauth_session(ctx: &mut Context) -> Result<Option<Session>> {
    let session = ctx.start_auth_session(
        None,
        None,
        None,
        tss_esapi::constants::types::session::SessionType::Hmac,
        tss_esapi::constants::algorithm::Cipher::aes_256_cfb(),
        tss_esapi::constants::algorithm::HashingAlgorithm::Sha256,
    )?;
    let session_attr = tss_esapi::utils::TpmaSessionBuilder::new()
        .with_flag(tss_esapi::constants::tss::TPMA_SESSION_DECRYPT)
        .with_flag(tss_esapi::constants::tss::TPMA_SESSION_ENCRYPT)
        .build();
    ctx.tr_sess_set_attributes(session.unwrap(), session_attr)?;

    Ok(session)
}

fn execute_with_sessions<F, T>(
    ctx: &mut Context,
    ses: (Option<Session>, Option<Session>, Option<Session>),
    f: F,
) -> Result<T>
where
    F: Fn(&mut Context) -> Result<T>,
{
    let oldses = ctx.sessions();
    ctx.set_sessions(ses);

    let res = f(ctx);

    ctx.set_sessions(oldses);

    res
}

fn execute_with_session<F, T>(
    ctx: &mut Context,
    ses: Option<Session>,
    f: F,
) -> Result<T>
where
    F: Fn(&mut Context) -> Result<T>,
{
    execute_with_sessions(ctx, (ses, None, None), f)
}

fn execute_with_temp_nullauth_session<F, T>(
    ctx: &mut Context,
    f: F,
) -> Result<T>
where
    F: Fn(&mut Context) -> Result<T>,
{
    let ses = create_nullauth_session(ctx)?.unwrap();

    let res = execute_with_session(ctx, Some(ses), f);

    ctx.flush_context(ses.handle().into())?;

    res
}

fn execute_without_session<F, T>(ctx: &mut Context, f: F) -> Result<T>
where
    F: Fn(&mut Context) -> Result<T>,
{
    execute_with_session(ctx, None, f)
}

pub(crate) fn retrieve_ek_pubcert(
    ctx: &mut Context,
    alg: AsymmetricAlgorithm,
) -> Result<Vec<u8>> {
    let nv_idx = match alg {
        AsymmetricAlgorithm::Rsa => RSA_2048_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithm::Ecc => ECC_P256_EK_CERTIFICATE_NV_INDEX,
    };

    let nv_idx = NvIndexTpmHandle::new(nv_idx).unwrap();
    let nv_idx = TpmHandle::NvIndex(nv_idx);
    let nv_idx = ctx.tr_from_tpm_public(nv_idx)?;
    let nv_idx: NvIndexHandle = nv_idx.into();

    let (nvpub, _) = execute_without_session(ctx, |ctx| {
        ctx.nv_read_public(nv_idx).map_err(|e| e.into())
    })?;
    let nvsize = nvpub.data_size();

    execute_with_temp_nullauth_session(ctx, |ctx| {
        nv_read_full(ctx, nv_idx.into(), nv_idx, nvsize)
    })
}

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Appendix B.3.3 and B.3.4
fn create_ek_public_from_default_template(
    alg: AsymmetricAlgorithm,
) -> Result<TPM2B_PUBLIC> {
    let mut obj_attrs = ObjectAttributes(0);
    obj_attrs.set_fixed_tpm(true);
    obj_attrs.set_st_clear(false);
    obj_attrs.set_fixed_parent(true);
    obj_attrs.set_sensitive_data_origin(true);
    obj_attrs.set_user_with_auth(false);
    obj_attrs.set_admin_with_policy(true);
    obj_attrs.set_no_da(false);
    obj_attrs.set_encrypted_duplication(false);
    obj_attrs.set_restricted(true);
    obj_attrs.set_decrypt(true);
    obj_attrs.set_sign_encrypt(false);

    // TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
    // With 32 null-bytes attached, because of the type of with_auth_policy
    let authpolicy: [u8; 64] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
        0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
        0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    match alg {
        AsymmetricAlgorithm::Rsa => Tpm2BPublicBuilder::new()
            .with_type(tss_const::TPM2_ALG_RSA)
            .with_name_alg(tss_const::TPM2_ALG_SHA256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(32, authpolicy)
            .with_parms(PublicParmsUnion::RsaDetail(
                tss_esapi::tss2_esys::TPMS_RSA_PARMS {
                    symmetric: tss_esapi::tss2_esys::TPMT_SYM_DEF_OBJECT {
                        algorithm: tss_const::TPM2_ALG_AES,
                        keyBits: tss_esapi::tss2_esys::TPMU_SYM_KEY_BITS {
                            aes: 128,
                        },
                        mode: tss_esapi::tss2_esys::TPMU_SYM_MODE {
                            aes: tss_const::TPM2_ALG_CFB,
                        },
                    },
                    scheme: tss_esapi::tss2_esys::TPMT_RSA_SCHEME {
                        scheme: tss_const::TPM2_ALG_NULL,
                        details: Default::default(),
                    },
                    keyBits: 2048,
                    exponent: 0,
                },
            ))
            .with_unique(PublicIdUnion::Rsa(Box::new(
                tss_esapi::tss2_esys::TPM2B_PUBLIC_KEY_RSA {
                    size: 256,
                    buffer: [0; 512],
                },
            )))
            .build(),
        AsymmetricAlgorithm::Ecc => Tpm2BPublicBuilder::new()
            .with_type(tss_const::TPM2_ALG_ECC)
            .with_name_alg(tss_const::TPM2_ALG_SHA256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(32, authpolicy)
            .with_parms(PublicParmsUnion::EccDetail(
                tss_esapi::tss2_esys::TPMS_ECC_PARMS {
                    symmetric: tss_esapi::tss2_esys::TPMT_SYM_DEF_OBJECT {
                        algorithm: tss_const::TPM2_ALG_AES,
                        keyBits: tss_esapi::tss2_esys::TPMU_SYM_KEY_BITS {
                            sym: 128,
                        },
                        mode: tss_esapi::tss2_esys::TPMU_SYM_MODE {
                            sym: tss_const::TPM2_ALG_CFB,
                        },
                    },
                    scheme: tss_esapi::tss2_esys::TPMT_ECC_SCHEME {
                        scheme: tss_const::TPM2_ALG_NULL,
                        details: tss_esapi::tss2_esys::TPMU_ASYM_SCHEME {
                            anySig: tss_esapi::tss2_esys::TPMS_SCHEME_HASH {
                                hashAlg: tss_const::TPM2_ALG_NULL,
                            },
                        },
                    },
                    curveID: tss_const::TPM2_ECC_NIST_P256,
                    kdf: tss_esapi::tss2_esys::TPMT_KDF_SCHEME {
                        scheme: tss_const::TPM2_ALG_NULL,
                        details: Default::default(),
                    },
                },
            ))
            .with_unique(PublicIdUnion::Ecc(Box::new(
                tss_esapi::tss2_esys::TPMS_ECC_POINT {
                    x: tss_esapi::tss2_esys::TPM2B_ECC_PARAMETER {
                        size: 32,
                        buffer: [0; 128],
                    },
                    y: tss_esapi::tss2_esys::TPM2B_ECC_PARAMETER {
                        size: 32,
                        buffer: [0; 128],
                    },
                },
            )))
            .build(),
    }
    .map_err(|e| e.into())
}

pub(crate) fn create_ek_object(
    ctx: &mut Context,
    alg: AsymmetricAlgorithm,
) -> Result<tss_esapi::handles::KeyHandle> {
    let ek_public = create_ek_public_from_default_template(alg)?;

    let ses = create_nullauth_session(ctx)?;

    execute_with_session(ctx, ses, |ctx| {
        ctx.create_primary_key(
            tss_esapi::tss2_esys::ESYS_TR_RH_ENDORSEMENT,
            &ek_public,
            None,
            None,
            None,
            &[],
        )
        .map_err(|e| e.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm;

    #[test]
    fn test_retrieve_ek_pubcert() {
        let mut ctx = tpm::get_tpm2_ctx().unwrap();

        let _ =
            retrieve_ek_pubcert(&mut ctx, AsymmetricAlgorithm::Rsa).unwrap();
        let _ =
            retrieve_ek_pubcert(&mut ctx, AsymmetricAlgorithm::Ecc).unwrap();
    }

    #[test]
    fn test_create_ek_public_from_default_template() {
        let rsa_template =
            create_ek_public_from_default_template(AsymmetricAlgorithm::Rsa)
                .unwrap();
        assert_eq!(rsa_template.size, 612);

        let ecc_template =
            create_ek_public_from_default_template(AsymmetricAlgorithm::Ecc)
                .unwrap();
        assert_eq!(ecc_template.size, 612);
    }

    #[test]
    fn test_create_ek() {
        let mut ctx = tpm::get_tpm2_ctx().unwrap();

        create_ek_object(&mut ctx, AsymmetricAlgorithm::Rsa).unwrap();
        create_ek_object(&mut ctx, AsymmetricAlgorithm::Ecc).unwrap();
    }
}
