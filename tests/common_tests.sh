#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Keylime Authors

# Check that the script is running from inside the repository tree
GIT_ROOT=$(git rev-parse --show-toplevel) || {
    echo "Please run this script from inside the rust-keylime repository tree"
    exit 1
}

TESTS_DIR="${GIT_ROOT}/tests"
TEST_DATA_DIR="${GIT_ROOT}/test-data"
TPMDIR="${TEST_DATA_DIR}/tpm-state"

# These certificates are used for the keylime/device_id tests
IAK_IDEVID_CERTS="${GIT_ROOT}/keylime/test-data/iak-idevid-certs"

# Store the old TCTI setting
OLD_TCTI=$TCTI
OLD_TPM2TOOLS_TCTI=$TPM2TOOLS_TCTI
OLD_TPM2OPENSSL_TCTI=$TPM2OPENSSL_TCTI

set -euf -o pipefail

echo "-------- Setting up Software TPM"

if [[ ! -d "${TPMDIR}" ]]; then
    mkdir -p "${TPMDIR}"
fi

# Manufacture a new Software TPM
swtpm_setup --tpm2 \
    --tpmstate "${TPMDIR}" \
    --createek --decryption --create-ek-cert \
    --create-platform-cert \
    --lock-nvram \
    --not-overwrite \
    --pcr-banks sha256 \
    --display

function start_swtpm {
    # Initialize the swtpm socket
    swtpm socket --tpm2 \
        --tpmstate dir="${TPMDIR}" \
        --flags startup-clear \
        --ctrl type=tcp,port=2322 \
        --server type=tcp,port=2321 \
        --log level=1 &
    SWTPM_PID=$!
}

function stop_swtpm {
    # Stop swtpm if running
    if [[ -n "${SWTPM_PID}" ]]; then
        echo "Stopping swtpm"
        kill $SWTPM_PID
    fi
}

# Set cleanup function to run at exit
function cleanup {

    echo "-------- Restore TCTI settings"
    TCTI=$OLD_TCTI
    TPM2TOOLS_TCTI=$OLD_TPM2TOOLS_TCTI
    TPM2OPENSSL_TCTI=$OLD_TPM2OPENSSL_TCTI

    echo "-------- Cleanup processes"
    stop_swtpm
}
trap cleanup EXIT

# Set the TCTI to use the swtpm socket
export TCTI=swtpm
export TPM2TOOLS_TCTI=swtpm
export TPM2OPENSSL_TCTI=swtpm
