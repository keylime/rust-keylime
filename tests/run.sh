#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Keylime Authors

# Store the old TCTI setting
OLD_TCTI=$TCTI
OLD_TPM2TOOLS_TCTI=$TPM2TOOLS_TCTI

set -euf -o pipefail

echo "-------- Setting up Software TPM"

# Create temporary directories
TEMPDIR=$(mktemp -d)
TPMDIR="${TEMPDIR}/tpmdir"
mkdir -p ${TPMDIR}

# Manufacture a new Software TPM
swtpm_setup --tpm2 \
    --tpmstate ${TPMDIR} \
    --createek --decryption --create-ek-cert \
    --create-platform-cert \
    --lock-nvram \
    --not-overwrite \
    --pcr-banks sha256 \
    --display

function start_swtpm {
    # Initialize the swtpm socket
    swtpm socket --tpm2 \
        --tpmstate dir=${TPMDIR} \
        --flags startup-clear \
        --ctrl type=tcp,port=2322 \
        --server type=tcp,port=2321 \
        --log level=1 &
    SWTPM_PID=$!
}

function stop_swtpm {
    # Stop swtpm if running
    if [[ -n "$SWTPM_PID" ]]; then
        echo "Stopping swtpm"
        kill $SWTPM_PID
    fi
}

# Set cleanup function to run at exit
function cleanup {

    echo "-------- Restore TCTI settings"
    TCTI=$OLD_TCTI
    TPM2TOOLS_TCTI=$OLD_TPM2TOOLS_TCTI

    echo "-------- Cleanup processes"
    stop_swtpm
}
trap cleanup EXIT

# Set the TCTI to use the swtpm socket
export TCTI=swtpm
export TPM2TOOLS_TCTI=swtpm

echo "-------- Running clippy"
# The cargo denies are currently disabled, because that will require a bunch of dep cleanup
cargo clippy --all-targets --all-features -- -D clippy::all  # -D clippy::cargo

echo "-------- Building"
RUST_BACKTRACE=1 cargo build

echo "-------- Testing"
start_swtpm
mkdir -p /var/lib/keylime
RUST_BACKTRACE=1 RUST_LOG=info \
KEYLIME_CONFIG=$PWD/keylime-agent.conf \
cargo test --features testing -- --nocapture

echo "-------- Testing with coverage"
RUST_BACKTRACE=1 RUST_LOG=info \
KEYLIME_CONFIG=$PWD/keylime-agent.conf \
cargo tarpaulin --verbose \
      --target-dir target/tarpaulin \
      --workspace \
      --exclude-files 'target/*' \
      --ignore-panics --ignore-tests \
      --out Html --out Json \
      --all-features \
      --engine llvm
