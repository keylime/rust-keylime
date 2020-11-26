#!/usr/bin/env bash

set -euf -o pipefail

echo "-------- Setting up Virtual TPM"
mkdir /tmp/tpmdir
swtpm_setup --tpm2 \
    --tpmstate /tmp/tpmdir \
    --createek --allow-signing --decryption --create-ek-cert \
    --create-platform-cert \
    --display
swtpm socket --tpm2 \
    --tpmstate dir=/tmp/tpmdir \
    --flags startup-clear \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --daemon
tpm2-abrmd \
    --logger=stdout \
    --tcti=swtpm: \
    --allow-root \
    --session \
    --flush-all &

echo "-------- Running clippy"
# The denies are currently disabled, because that will require a bunch of code cleanup
cargo clippy --all-targets --all-features #  -- -D clippy::all -D clippy::cargo

echo "-------- Building"
RUST_BACKTRACE=1 cargo build

echo "-------- Testing"
TCTI=tabrmd:bus_type=session RUST_BACKTRACE=1 RUST_LOG=info cargo test -- --nocapture
