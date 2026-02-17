# keylimectl Feature Parity Analysis

Comparison between the Python `keylime_tenant` and the Rust `keylimectl` implementation.

Legend: **Yes** = implemented, **No** = not implemented, **Partial** = partially implemented, **Deprecated** = deprecated in Python tenant

---

## Agent Lifecycle Management

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 1 | Add agent (`-c add` / `agent add`) | Yes | Yes | Both pull and push model supported |
| 2 | Delete agent (`-c delete` / `agent remove`) | Yes | Yes | |
| 3 | Update agent (`-c update` / `agent update`) | Yes | Yes | Delete + re-add pattern in both |
| 4 | Reactivate agent (`-c reactivate` / `agent reactivate`) | Yes | Yes | |

## Agent Status and Monitoring

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 5 | Combined status (`-c status` / `agent status`) | Yes | Yes | Queries both verifier and registrar |
| 6 | Verifier-only status (`-c cvstatus` / `--verifier-only`) | Yes | Yes | |
| 7 | Registrar-only status (`-c regstatus` / `--registrar-only`) | Yes | Yes | |
| 8 | Bulk agent info (`-c bulkinfo` / `list agents --detailed`) | Yes | Yes | |

## Agent Listing and Registry

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 9 | List agents on verifier (`-c cvlist` / `list agents`) | Yes | Yes | |
| 10 | List agents on registrar (`-c reglist` / `list agents --registrar-only`) | Yes | Yes | |
| 11 | Delete agent from registrar (`-c regdelete` / `agent remove --from-registrar`) | Yes | Yes | |

## Runtime Policy Management

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 12 | Add runtime policy (`-c addruntimepolicy` / `policy create`) | Yes | Yes | |
| 13 | Show runtime policy (`-c showruntimepolicy` / `policy show`) | Yes | Yes | |
| 14 | Update runtime policy (`-c updateruntimepolicy` / `policy update`) | Yes | Yes | |
| 15 | Delete runtime policy (`-c deleteruntimepolicy` / `policy delete`) | Yes | Yes | |
| 16 | List runtime policies (`-c listruntimepolicy` / `list policies`) | Yes | Yes | |

## Measured Boot Policy Management

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 17 | Add MB policy (`-c addmbpolicy` / `measured-boot create`) | Yes | Yes | |
| 18 | Show MB policy (`-c showmbpolicy` / `measured-boot show`) | Yes | Yes | |
| 19 | Update MB policy (`-c updatembpolicy` / `measured-boot update`) | Yes | Yes | |
| 20 | Delete MB policy (`-c deletembpolicy` / `measured-boot delete`) | Yes | Yes | |
| 21 | List MB policies (`-c listmbpolicy` / `list measured-boot-policies`) | Yes | Yes | |

## Attestation Protocol (Pull Model)

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 22 | TPM quote request (nonce-based) | Yes | Yes | |
| 23 | TPM quote validation (AIK, nonce) | Yes | Yes | Full cryptographic verification behind `tpm-quote-validation` feature flag; structural validation by default |
| 24 | EK certificate verification | Yes | No | Python checks EK cert against `tpm_cert_store` |
| 25 | EK check script (`ek_check_script`) | Yes | No | Python runs external script for custom EK validation |
| 26 | U/V/K key generation | Yes | Yes | Uses OpenSSL `rand_bytes` for U and V |
| 27 | RSA-OAEP encryption of U key | Yes | Yes | Uses `crypto::rsa_oaep_encrypt` (moved from `testing` module to production API) |
| 28 | HMAC auth tag computation | Yes | Yes | |
| 29 | Key delivery to agent (`POST /keys/ukey`) | Yes | Yes | |
| 30 | Key derivation verification (`--verify`) | Yes | Yes | |

## Payload and Certificate Delivery

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 31 | Plaintext file delivery (`-f` / `--payload`) | Yes | Yes | Auto-encrypted for agent |
| 32 | Certificate generation and delivery (`--cert` / `--cert-dir`) | Yes | Yes | CA-based cert generation |
| 33 | Pre-encrypted key file (`-k`) | Yes | No | For use with `user_data_encrypt` |
| 34 | Encrypted payload (`-p`) | Yes | No | Paired with `-k` |
| 35 | Include directory (`--include`) | Yes | No | Additional files in certificate zip |

## Connection and Configuration

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 36 | Verifier IP/port override | Yes | Yes | |
| 37 | Registrar IP/port override | Yes | Yes | |
| 38 | Agent IP/port (`-t/-tp` / `--ip/--port`) | Yes | Yes | |
| 39 | CV target host (`--cv_targethost`) | Yes | No | Agent IP as seen by the verifier (NAT/proxy scenarios) |
| 40 | Verifier ID (`-vi/--cvid`) | Yes | No | For multi-verifier setups |
| 41 | No-verifier-check (`-nvc` / `--force`) | Yes | Yes | |
| 42 | TLS configuration | Yes | Yes | Config file based in both |
| 43 | Agent mTLS | Yes | Yes | |
| 44 | Agent API version override (`--agent-api-version`) | Yes | No | Manual version specification |
| 45 | API version auto-negotiation | Yes | Yes | |
| 46 | Push model (`--push-model`) | Yes | Yes | |

## Policy Options (When Adding Agents)

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 47 | Runtime policy file (`--runtime-policy`) | Yes | Yes | |
| 48 | Runtime policy URL (`--runtime-policy-url`) | Yes | No | Download policy from remote URL |
| 49 | Runtime policy checksum (`--runtime-policy-checksum`) | Yes | No | SHA-256 verification of downloaded policy |
| 50 | Runtime policy signature key (`--runtime-policy-sig-key`) | Yes | No | GPG key for policy signature verification |
| 51 | TPM policy (`--tpm_policy` / `--tpm-policy`) | Yes | Yes | |
| 52 | MB policy file (`--mb-policy`) | Yes | Yes | |

## Legacy/Deprecated Features (Python Only)

These features are deprecated in the Python tenant and are intentionally **not** implemented
in keylimectl. They are listed here for completeness.

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 53 | Allowlist (`--allowlist`) | Deprecated | No | Replaced by `--runtime-policy` |
| 54 | Allowlist URL (`--allowlist-url`) | Deprecated | No | Replaced by `--runtime-policy-url` |
| 55 | IMA exclude list (`--exclude`) | Deprecated | No | Included in runtime policy |
| 56 | Allowlist name (`--allowlist-name`) | Deprecated | No | Replaced by `--runtime-policy-name` |
| 57 | `--supported-version` | Deprecated | No | Replaced by `--agent-api-version` |
| 58 | `addallowlist` / `showallowlist` / `deleteallowlist` commands | Deprecated | No | Replaced by runtime policy commands |
| 59 | `--mb_refstate` | Deprecated | No | Replaced by `--mb-policy` |
| 60 | Local IMA signature verification key (`--signature-verification-key`) | Deprecated | No | Include in runtime policy |
| 61 | Remote IMA signature verification key URL | Deprecated | No | Include in runtime policy |
| 62 | IMA key signature verification (GPG) | Deprecated | No | Include in runtime policy |

## New keylimectl Features (Not in Python Tenant)

| # | Feature | Python tenant | keylimectl | Notes |
|---|---------|:---:|:---:|-------|
| 63 | Multiple output formats (`--format json/table/yaml`) | No | Yes | |
| 64 | Verbosity levels (`-v` / `-vv` / `-vvv`) | No | Yes | Structured logging levels |
| 65 | Quiet mode (`--quiet`) | No | Yes | Suppress non-result output |
| 66 | Dedicated config file (TOML) | No | Yes | `keylimectl.conf` with precedence chain |
| 67 | Step-by-step progress reporting | No | Yes | "Step 1 of 4: Retrieving agent data..." |
| 68 | Structured JSON error output | No | Yes | Machine-parseable error codes |
| 69 | Subcommand-based CLI | No | Yes | `agent add` vs `-c add` |
| 70 | `mb` alias for `measured-boot` | No | Yes | Shorter command |

## Security Items

| # | Issue | Severity | Location | Details |
|---|-------|----------|----------|---------|
| A | ~~Non-cryptographic RNG for nonces~~ | ~~High~~ | ~~`commands/agent/attestation.rs`~~ | **Fixed** (Phase 1.1): Replaced with OpenSSL `rand::rand_bytes` CSPRNG. `generate_random_string()` removed entirely. |
| B | ~~`crypto::testing` module usage in production~~ | ~~Medium~~ | ~~`commands/agent/attestation.rs`~~ | **Fixed** (Phase 1.2/1.2b): `pkey_pub_from_pem()` and `rsa_oaep_encrypt()` exposed as public API in `keylime::crypto` module. |
| C | Missing EK certificate verification | Medium | Not implemented | Python tenant verifies EK certificates against `tpm_cert_store` and supports `ek_check_script`. keylimectl does not perform these checks. |

## Summary

| Category | Total | Implemented | Missing | N/A (Deprecated) |
|----------|:-----:|:-----------:|:-------:|:-----------------:|
| Agent Lifecycle | 4 | 4 | 0 | 0 |
| Agent Status | 4 | 4 | 0 | 0 |
| Agent Listing | 3 | 3 | 0 | 0 |
| Runtime Policy Mgmt | 5 | 5 | 0 | 0 |
| Measured Boot Policy Mgmt | 5 | 5 | 0 | 0 |
| Attestation Protocol | 9 | 8 | 1 | 0 |
| Payload/Cert Delivery | 5 | 2 | 3 | 0 |
| Connection/Config | 11 | 8 | 3 | 0 |
| Policy Options (agent add) | 6 | 4 | 2 | 0 |
| Deprecated Features | 10 | 0 | 0 | 10 |
| **Totals** | **62** | **43** | **9** | **10** |
| New keylimectl features | 8 | 8 | -- | -- |
| Security items | 3 | 2 | 1 | -- |
