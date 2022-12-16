# Keylime

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)

## Overview

This is a Rust implementation of
[keylime](https://github.com/keylime/keylime) agent. Keylime is system
integrity monitoring system that has the following features:

* Exposes TPM trust chain for higher-level use
* Provides an end-to-end solution for bootstrapping node cryptographic
  identities
* Securely monitors system integrity

For more information, visit the [keylime website](https://keylime.dev)

For now, this project is focusing on the keylime agent component, which is a
HTTP server running on the machine that executes keylime operations.
Most keylime operations rely on TPM co-processor; therefore, the server needs
a physical TPM chip (or a TPM emulator) to perform keylime operations.  The
TPM emulator is a program that runs in the daemon to mimic TPM commands.

The rust-keylime agent is the official agent (starting with version 0.1.0) and
replaces the Python implementation.

## Prerequisites

### Required Packages
The rust-keylime agent requires the following packages for both compile and run time.

For Fedora, use the following command
```
$ dnf install openssl-devel gcc tpm2-tss-devel zeromq-devel libarchive-devel
```

For Ubuntu OS, use the following command
```
$ apt-get install libssl-dev gcc libtss-dev libzmq3-dev libarchive-dev
```

### Rust

Make sure Rust is installed before running Keylime. Installation
instructions can be found [here](https://www.rust-lang.org/en-US/install.html).

## Logging env

To run with `pretty-env-logger` trace logging active, set cargo run
within `RUST_LOG`, as follows:

    $ RUST_LOG=keylime_agent=trace cargo run --bin keylime_agent

## Testing

Unit tests are gating in CI for new code submission.  To run them:

```
$ cargo test
```

## Running agent as a systemd-managed service

To make deployment and management of the service easier, this crate
comes with a Makefile and systemd unit file.

To install the executables and the unit file, do:

```console
$ make
$ sudo make install
```

Then you should be able to start the service with:

```console
$ sudo systemctl start keylime_agent
```

## Building Debian package with cargo-deb

Cargo deb requires Rust 1.60, so on Debian you need to install it first from rustup.rs.

```shell
# Install cargo-deb
rustup update
cargo install cargo-deb

# Build Debian package
cargo deb -p keylime_agent
```
