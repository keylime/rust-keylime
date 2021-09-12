// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use log::*;

use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

use thiserror::Error;

use tss_esapi::{
    handles::PcrHandle,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, DigestValues, PcrSelectionListBuilder, PcrSlot},
    Context, Tcti,
};

const IMA_ML: &str = "/sys/kernel/security/ima/ascii_runtime_measurements";

const START_HASH: &[u8; 20] = &[0u8; 20];
const FF_HASH: &[u8; 20] = &[0xffu8; 20];

#[derive(Error, Debug)]
enum ImaEmulatorError {
    #[error("Invalid envvar")]
    VarError(#[from] std::env::VarError),
    #[error("TPM error")]
    TssEsapiError(#[from] tss_esapi::Error),
    #[error("Decoding error")]
    FromHexError(#[from] hex::FromHexError),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

type Result<T> = std::result::Result<T, ImaEmulatorError>;

fn ml_extend(
    context: &mut Context,
    ml: &str,
    mut position: usize,
    search_hash: Option<&Digest>,
) -> Result<usize> {
    let f = File::open(ml)?;
    let mut reader = BufReader::new(f);
    for line in reader.by_ref().lines().skip(position) {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.splitn(5, ' ').collect();
        if tokens.len() < 5 {
            error!("invalid measurement list file line: -{}-", line);
        }
        position += 1;

        let path = tokens[4];
        let template_hash = hex::decode(tokens[1])?;
        let template_hash = if template_hash == START_HASH {
            Digest::try_from(&FF_HASH[..])
        } else {
            Digest::try_from(template_hash)
        }?;

        match search_hash {
            None => {
                println!(
                    "extending hash {} for {}",
                    hex::encode(template_hash.value()),
                    &path
                );
                let mut vals = DigestValues::new();
                vals.set(HashingAlgorithm::Sha1, template_hash);
                // TODO: Add support for other hash algorithms
                context.execute_with_nullauth_session(|ctx| {
                    ctx.pcr_extend(PcrHandle::Pcr10, vals)
                })?;
            }
            Some(search_hash) => {
                let mut hasher = openssl::sha::Sha1::new();
                hasher.update(START_HASH);
                hasher.update(&template_hash);
                let running_hash: Vec<u8> = hasher.finish().into();
                let running_hash = Digest::try_from(running_hash)?;
                let mut vals = DigestValues::new();
                vals.set(HashingAlgorithm::Sha1, running_hash.clone());

                if running_hash == *search_hash {
                    println!("Located last IMA file updated: {}", path);
                    return Ok(position);
                }
            }
        }
    }

    if search_hash.is_some() {
        return Err(ImaEmulatorError::Other(
            "Unable to find current measurement list position, Resetting the TPM emulator may be neccesary".to_string()));
    }

    Ok(position)
}

fn main() -> std::result::Result<(), ImaEmulatorError> {
    let tcti = Tcti::from_environment_variable()?;
    let mut context = unsafe { Context::new(tcti) }?;

    if !tss_esapi::utils::get_tpm_vendor(&mut context)?.contains("SW") {
        return Err(ImaEmulatorError::Other(
            "This stub should only be used with a TPM emulator".to_string(),
        ));
    }

    // check if pcr is clean
    let pcr_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot10])
        .build();
    let (_, pcrs_read, pcr_data) =
        context.execute_without_session(|ctx| ctx.pcr_read(&pcr_list))?;
    if pcrs_read != pcr_list {
        return Err(ImaEmulatorError::Other(format!(
            "could not read all pcrs; requested: {:?}, read: {:?}",
            pcr_list, pcrs_read
        )));
    }

    let digest = pcr_data
        .pcr_bank(HashingAlgorithm::Sha1)
        .ok_or_else(|| {
            ImaEmulatorError::Other(
                "IMA slot does not have SHA-1 bank".to_string(),
            )
        })?
        .pcr_value(PcrSlot::Slot10)
        .ok_or_else(|| {
            ImaEmulatorError::Other(
                "could not read value from IMA PCR".to_string(),
            )
        })?;

    let mut pos = 0;

    if digest.value() != START_HASH {
        log::warn!("IMA PCR is not empty, trying to find the last updated file in the measurement list...");
        pos = ml_extend(&mut context, IMA_ML, 0, Some(digest))?;
    }

    println!("Monitoring {}", IMA_ML);

    loop {
        pos = ml_extend(&mut context, IMA_ML, pos, None)?;

        // FIXME: We could poll IMA_ML as in the python implementation, though
        // the file is not pollable:
        // https://github.com/torvalds/linux/blob/master/security/integrity/ima/ima_fs.c#L267
        // Better idea might be to check the "runtime_measurements_count" file.
        let duration = std::time::Duration::from_millis(200);
        std::thread::sleep(duration);
    }
}
