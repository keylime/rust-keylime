// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use keylime::algorithms::HashAlgorithm;
use keylime::ima;
use openssl::hash::{hash, MessageDigest};

use log::*;

use clap::Parser;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGTERM;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use thiserror::Error;

use tss_esapi::{
    abstraction::pcr,
    handles::PcrHandle,
    structures::{Digest, DigestValues, PcrSelectionListBuilder, PcrSlot},
    Context, Tcti,
};

const IMA_ML: &str = "/sys/kernel/security/ima/ascii_runtime_measurements";

#[derive(Error, Debug)]
enum ImaEmulatorError {
    #[error("Invalid envvar")]
    VarError(#[from] std::env::VarError),
    #[error("TPM error")]
    TssEsapiError(#[from] tss_esapi::Error),
    #[error("Decoding error")]
    FromHexError(#[from] hex::FromHexError),
    #[error("Algorithm error")]
    AlgorithmError(#[from] keylime::algorithms::AlgorithmError),
    #[error("OpenSSL error")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Integer parsing error")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("{0}")]
    Other(String),
}

type Result<T> = std::result::Result<T, ImaEmulatorError>;

fn ml_extend(
    context: &mut Context,
    ml: &Path,
    mut position: usize,
    ima_hash_alg: HashAlgorithm,
    pcr_hash_alg: HashAlgorithm,
    search_hash: Option<&Digest>,
) -> Result<usize> {
    let f = File::open(ml)?;
    let mut reader = BufReader::new(f);
    let ima_digest: MessageDigest = ima_hash_alg.into();
    let ima_start_hash = ima::Digest::start(ima_hash_alg);
    let pcr_digest: MessageDigest = pcr_hash_alg.into();
    let mut running_hash = ima::Digest::start(pcr_hash_alg);
    let ff_hash = ima::Digest::ff(pcr_hash_alg);
    for line in reader.by_ref().lines().skip(position) {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let entry: ima::Entry = line.as_str().try_into()?;

        position += 1;

        // Set correct hash for time of measure, time of use (ToMToU) errors
        // and if a file is already opened for write.
        // https://elixir.bootlin.com/linux/v5.12.12/source/security/integrity/ima/ima_main.c#L101
        let pcr_template_hash = if entry.template_hash == ima_start_hash {
            Digest::try_from(ff_hash.value())
        } else {
            let mut event_data = vec![];
            entry.event_data.encode(&mut event_data)?;
            let pcr_event_hash = hash(pcr_digest, &event_data)?;
            let ima_event_hash = hash(ima_digest, &event_data)?;
            if ima_event_hash.as_ref() != entry.template_hash.value() {
                return Err(ImaEmulatorError::Other(
                    "IMA template hash doesn't match".to_string(),
                ));
            }
            Digest::try_from(pcr_event_hash.as_ref())
        }?;

        match search_hash {
            None => {
                println!(
                    "extending hash {} for {}",
                    hex::encode(pcr_template_hash.value()),
                    entry.event_data.path(),
                );
                let mut vals = DigestValues::new();
                vals.set(pcr_hash_alg.into(), pcr_template_hash);
                context.execute_with_nullauth_session(|ctx| {
                    ctx.pcr_extend(PcrHandle::Pcr10, vals)
                })?;
            }
            Some(search_hash) => {
                let mut hasher = openssl::hash::Hasher::new(pcr_digest)?;
                hasher.update(running_hash.value())?;
                hasher.update(&pcr_template_hash)?;
                running_hash =
                    ima::Digest::new(pcr_hash_alg, &hasher.finish()?)?;
                let digest = Digest::try_from(running_hash.value())?;
                let mut vals = DigestValues::new();
                vals.set(pcr_hash_alg.into(), digest.clone());

                if digest == *search_hash {
                    println!(
                        "Located last IMA file updated: {}",
                        entry.event_data.path()
                    );
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

#[derive(Parser)]
#[clap(about)]
struct Args {
    #[clap(long = "hash_algs", short = 'a', default_value = "sha1")]
    hash_algs: Vec<String>,
    #[clap(long, short = 'i', default_value = "sha1")]
    ima_hash_alg: String,
    #[clap(long, short = 'f', default_value = IMA_ML)]
    ima_log: PathBuf,
}

fn main() -> std::result::Result<(), ImaEmulatorError> {
    let args = Args::parse();

    let tcti =
        match Tcti::from_environment_variable() {
            Ok(tcti) => tcti,
            Err(_) => return Err(ImaEmulatorError::Other(
                "This stub requires TCTI environment variable set properly"
                    .to_string(),
            )),
        };

    let mut context = Context::new(tcti)?;

    if !tss_esapi::utils::get_tpm_vendor(&mut context)?.contains("SW") {
        return Err(ImaEmulatorError::Other(
            "This stub should only be used with a TPM emulator".to_string(),
        ));
    }

    let ima_hash_alg: HashAlgorithm =
        args.ima_hash_alg.as_str().try_into()?;
    let mut positions = HashMap::new();
    for pcr_hash_alg in args.hash_algs {
        let pcr_hash_alg: HashAlgorithm = pcr_hash_alg.as_str().try_into()?;
        positions.insert(pcr_hash_alg, 0usize);
    }

    for (pcr_hash_alg, position) in positions.iter_mut() {
        // check if pcr is clean
        let pcr_list = PcrSelectionListBuilder::new()
            .with_selection((*pcr_hash_alg).into(), &[PcrSlot::Slot10])
            .build()?;
        let pcr_data = context
            .execute_without_session(|ctx| pcr::read_all(ctx, pcr_list))?;
        let digest = pcr_data
            .pcr_bank((*pcr_hash_alg).into())
            .ok_or_else(|| {
                ImaEmulatorError::Other(format!(
                    "IMA slot does not have {} bank",
                    *pcr_hash_alg,
                ))
            })?
            .get_digest(PcrSlot::Slot10)
            .ok_or_else(|| {
                ImaEmulatorError::Other(
                    "could not read value from IMA PCR".to_string(),
                )
            })?;

        let pcr_digest: MessageDigest = (*pcr_hash_alg).into();
        let pcr_start_hash = vec![0x00u8; pcr_digest.size()];
        if digest.value() != pcr_start_hash {
            log::warn!("IMA PCR is not empty, trying to find the last updated file in the measurement list...");
            *position = ml_extend(
                &mut context,
                &args.ima_log,
                *position,
                ima_hash_alg,
                *pcr_hash_alg,
                Some(digest),
            )?;
        }
    }

    let shutdown_marker = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown_marker))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown_marker))?;
    println!("Monitoring {}", args.ima_log.display());
    while !shutdown_marker.load(Ordering::SeqCst) {
        for (pcr_hash_alg, position) in positions.iter_mut() {
            *position = ml_extend(
                &mut context,
                &args.ima_log,
                *position,
                ima_hash_alg,
                *pcr_hash_alg,
                None,
                ).expect("Error extending position {position} on PCR bank {pcr_hash_alg}");
        }

        // FIXME: We could poll IMA_ML as in the python implementation, though
        // the file is not pollable:
        // https://github.com/torvalds/linux/blob/master/security/integrity/ima/ima_fs.c#L267
        // Better idea might be to check the "runtime_measurements_count" file.
        let duration = std::time::Duration::from_millis(200);
        std::thread::sleep(duration);
    }
    println!("Shutting down keylime IMA emulator");

    Ok(())
}
