# Keylime

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

## Overview

This is a Rust implementation of
[keylime](https://github.com/keylime/keylime) agent. Keylime is system
integrity monitoring system that has the following features:

* Exposes TPM trust chain for higher-level use
* Provides an end-to-end solution for bootstrapping node cryptographic
  identities
* Securely monitors system integrity

For more information, see the original [keylime website](https://keylime.dev)
and paper in the References section.

For now, this project is focusing on the keylime agent component, which is a
HTTP server running on the machine that executes keylime operations.
Most keylime operations rely on TPM co-processor; therefore, the server needs
a physical TPM chip (or a TPM emulator) to perform keylime operations.  The
TPM emulator is a program that runs in the deamon to mimic TPM commands.

## Prerequisites

### Required Packages
The rust-keylime agent requires the following packages for both compile and run time.

For Fedora, use the following command
```
$ dnf install openssl-devel gcc
```

For Ubuntu OS, use the following command
```
$ apt-get install openssl-dev gcc
```

### Rust

Make sure Rust is installed before running Keylime. Installation
instructions can be found [here](https://www.rust-lang.org/en-US/install.html).

## Logging env

To run with `pretty-env-logger` trace logging active, set cargo run
within `RUST_LOG`, as follows:

    $ RUST_LOG=keylime_agent=trace cargo run

## Testing

Unit tests are gating in CI for new code submission.  To run them:

```
$ cargo test
```

## References
1. Keylime Paper: [here](https://github.com/keylime/keylime/blob/master/doc/tci-acm.pdf)
