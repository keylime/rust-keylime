# keylimectl Roadmap

## Vision

`keylimectl` replaces the Python `keylime_tenant` as the official Keylime CLI tool.
The primary goal is to provide a modern, user-friendly interface for managing Keylime
remote attestation, with the push model (API 3.x) as the primary operational mode.

`keylimectl` also consolidates the `keylime-policies` suite of tools
(`keylime_create_policy`, `keylime_convert_runtime_policy`, `keylime_sign_runtime_policy`,
`keylime-policy`) into a single binary, providing policy generation, signing, validation,
and one-shot evidence verification.

### Guiding Principles

1. **Push model first**: API 3.x (push model) is the default and recommended mode.
   API 2.x (pull model) is maintained for backward compatibility and will eventually
   be deprecated and removed.
2. **Clean API separation**: API 2.x and 3.x code paths are separated behind Rust
   feature flags (`api-v2`, `api-v3`), enabling compile-time removal of legacy code.
3. **Zero-config operation**: The tool works out of the box with sane defaults for
   all options. No configuration file is required.
4. **Progressive configuration**: An interactive wizard helps users create
   configuration files tailored to their environment.
5. **Observability**: Built-in diagnostics show effective configuration, server
   information, and system health.
6. **Unified tooling**: All Keylime management operations -- agent lifecycle,
   policy creation, signing, validation, and evidence verification -- are
   available from a single `keylimectl` binary.
7. **Test with every change**: Every feature is tested before it is merged.
   Each phase includes its own testing requirements so the codebase is always
   in a tested, releasable state.

---

## Current State

### What is implemented

- [x] Subcommand-based CLI with `clap` (agent, policy, measured-boot, list)
- [x] Agent lifecycle: add, remove, update, status, reactivate
- [x] Runtime policy CRUD: create, show, update, delete, list
- [x] Measured boot policy CRUD: create, show, update, delete, list
- [x] Agent listing: verifier, registrar, detailed (bulk)
- [x] Pull model attestation flow (TPM quote, key exchange)
- [x] Push model agent add (basic -- sends to verifier without agent contact)
- [x] TLS/mTLS support for verifier, registrar, and agent communication
- [x] API version auto-detection with v3 -> v2 fallback
- [x] TOML configuration file with search path precedence
- [x] Sane defaults for all configuration options (no config file required)
- [x] Multiple output formats: JSON, table, YAML
- [x] Verbosity levels and quiet mode
- [x] Step-by-step progress reporting
- [x] Structured JSON error output
- [x] Retry logic with exponential backoff
- [x] RSA-OAEP encryption of U key (via `crypto::testing` module)
- [x] HMAC auth tag computation
- [x] Key derivation verification (`--verify`)
- [x] Payload and certificate delivery
- [x] Comprehensive unit tests for policy, measured-boot, and list commands

### What needs attention

- [x] ~~`generate_random_string()` uses time-seeded LCG instead of CSPRNG~~ (Phase 1.1)
- [x] ~~RSA encryption calls `crypto::testing::*` functions~~ (Phase 1.2/1.2b)
- [ ] No EK certificate verification (Python tenant has this)
- [ ] No `ek_check_script` support
- [x] ~~API 2.x and 3.x code paths are interleaved (no feature flag separation)~~ (Phase 2)
- [ ] Some client methods lack v3 fallback (inconsistent coverage)
- [x] ~~`push_model` field in `AddAgentParams` is `#[allow(dead_code)]`~~ (Phase 2.3)
- [ ] No interactive configuration wizard
- [ ] No diagnostics commands
- [ ] Missing: `--runtime-policy-url`, `--cv_targethost`, `--verifier-id`, `--agent-api-version`
- [ ] No policy generation (runtime, measured boot) -- requires porting keylime-policies
- [ ] No policy signing (DSSE)
- [ ] No policy validation
- [ ] No evidence verification (`/verify/evidence` endpoint)
- [ ] No interactive policy creation wizards
- [x] ~~`commands/agent.rs` is 2200+ lines -- needs splitting into submodules~~ (Phase 0.2)
- [x] ~~No secret zeroization for U/V/K keys in memory~~ (Phase 1.4)
- [ ] No IPv6 address support (Python tenant uses `bracketize_ipv6`)
- [ ] Config singleton pattern hinders test parallelism
- [ ] `AddAgentRequest` has mandatory `cloudagent_ip`/`cloudagent_port` -- incompatible with push model
- [ ] No revocation workflow handling
- [x] ~~No basic CI pipeline (`cargo build/test/clippy/fmt`)~~ (Phase 0.1)

---

## Phase 0: CI Foundation and Code Health

Establish the foundation that supports "test with every change" from the start.

### 0.1 Basic CI pipeline

- [x] Set up CI for keylimectl: `cargo build`, `cargo test`, `cargo clippy`,
      `cargo fmt --check`
- [x] Run CI on every PR and push to the feature branch
- [x] Enable `#[deny(warnings)]` in CI to catch regressions early
- [x] Add `keylimectl` to `tests/nopanic.ci` scan list
- [x] Add `[lints.clippy]` section to `keylimectl/Cargo.toml` (`all = "deny"`,
      `must_use_candidate = "warn"`)
- [x] Add `RUSTFLAGS="-D warnings"` to `.github/workflows/rust.yml`
- [x] Annotate all `unwrap()`/`panic!()` in keylimectl with `//#[allow_ci]`

### 0.2 Split `commands/agent.rs` into submodules

At 3377 lines, `commands/agent.rs` was too large to work with effectively.
Splitting it now makes all subsequent phases (especially feature flag gating)
dramatically simpler.

- [x] Extract `commands/agent/add.rs` -- agent add flow (both pull and push model)
- [x] Extract `commands/agent/status.rs` -- agent status queries
- [x] Extract `commands/agent/remove.rs` -- agent removal
- [x] Extract `commands/agent/update.rs` -- agent update (uses add + remove)
- [x] Extract `commands/agent/reactivate.rs` -- agent reactivation
- [x] Extract `commands/agent/attestation.rs` -- TPM attestation, quote
      validation, key encryption, key delivery
- [x] Extract `commands/agent/types.rs` -- `AddAgentParams`, `AddAgentRequest`,
      builder, and validation helpers
- [x] Extract `commands/agent/helpers.rs` -- policy/payload file loading,
      TPM policy resolution
- [x] Keep `commands/agent/mod.rs` as the dispatch entry point
- [x] Distribute tests to their respective submodules
- [x] Ensure all 293 existing tests pass after the split

**Design decisions:**
- No separate `add_push.rs`: `build_push_model_request()` is ~50 lines, kept
  in `add.rs` alongside `add_agent()` for simpler push/pull branching.
- Named `attestation.rs` (not `crypto.rs`): these functions implement TPM
  attestation workflow, not generic crypto. Generic crypto lives in
  `keylime::crypto`.
- Named `helpers.rs` (not `policy.rs`): avoids naming collision with the
  sibling `commands/policy.rs` module.
- Validation helpers (`is_valid_tpm_*()`, `is_valid_api_version()`) kept in
  `types.rs` since they are called exclusively by `AddAgentRequest::validate()`.

### 0.3 `#[must_use]` and lint audit

- [x] Enable `clippy::must_use_candidate` lint (via `[lints.clippy]` in Cargo.toml)
- [x] Add `#[must_use]` to 27 functions: `AddAgentRequest::new()`, all 17
      `with_*()` builder methods, `validate()`, 4 validation helpers,
      `generate_random_string()`, `encrypt_u_key_with_agent_pubkey()`,
      `load_policy_file()`, `load_payload_file()`, `resolve_tpm_policy_enhanced()`,
      `extract_tpm_policy_from_mb_policy()`
- [x] Fix clippy `needless_borrow` warning in `attestation.rs`
- [x] Run `cargo fmt` to normalize formatting across all split files
- [x] Zero clippy warnings for keylimectl

---

## Phase 1: Security and Correctness Fixes

Critical items that must be resolved before any release.

### 1.1 Cryptographically secure random number generation

- [x] Replace `generate_random_string()` (time-seeded LCG in `commands/agent/attestation.rs`)
      with OpenSSL `rand::rand_bytes` or the `rand` crate (already in workspace deps)
- [x] Ensure all nonces and challenges are generated with a CSPRNG
- [x] Remove the `generate_random_string()` function entirely

### 1.2 Move crypto functions out of `testing` module

- [x] Expose `pkey_pub_from_pem()` and `rsa_oaep_encrypt()` as public API in the
      `keylime::crypto` module (not under `testing`)
- [x] Update keylimectl to import from the production module path
- [ ] Coordinate with rust-keylime upstream if these functions are needed there too

**Note:** The `keylime` crate is shared with `keylime-agent` and
`keylime-push-model-agent`. Changes to its public API must be backward-compatible.
Submit the crypto module changes as a separate PR to the shared crate, independent
of keylimectl changes, so that the agent is not broken.

### 1.3 TPM quote validation review

- [x] Audit the current quote validation in `commands/agent/attestation.rs` against
      the Python tenant implementation for completeness
- [x] Ensure AIK verification, nonce verification, and PCR validation match the
      Python tenant behavior for API 2.x (implemented behind `tpm-quote-validation`
      feature flag with full cryptographic verification)

### 1.4 Secret zeroization

- [x] Add the `zeroize` crate as a dependency
- [x] Apply `Zeroize` and `ZeroizeOnDrop` to all key material: U key, V key,
      K (derived) key, nonces, and HMAC secrets
- [x] Ensure key material is cleared from memory after use in both pull and push
      model flows
- [ ] Audit all `String` and `Vec<u8>` variables that hold cryptographic secrets

### 1.5 TLS configuration audit

- [x] Verify certificate hostname verification is enforced (verifier and registrar)
      (made configurable via `tls.accept_invalid_hostnames`, default true for
      Keylime cert compatibility)
- [x] Ensure minimum TLS version is enforced (TLS 1.2+)
- [ ] Evaluate certificate revocation checking (CRL/OCSP) -- decide if keylimectl
      should support it or delegate to the OS trust store
- [ ] Document the TLS security posture in `--help` and README

### 1.6 Testing

- [x] Unit tests for CSPRNG: verify output length, uniqueness, and that the old
      `generate_random_string()` is no longer reachable (3 tests in attestation.rs;
      `generate_random_string()` removed entirely)
- [x] Unit tests for `rsa_oaep_encrypt()` and `pkey_pub_from_pem()` in their new
      production module location (roundtrip tests in `keylime/src/crypto.rs`;
      negative tests for empty, garbage, truncated PEM and EC/oversized inputs)
- [x] Verify existing tests still pass after the module move (312 tests pass)
- [x] Test that zeroized memory does not retain key material: explicit `.zeroize()`
      clears data; `Zeroizing` wrapper supports key operations (XOR) correctly.
      Drop-based zeroization tested by the `zeroize` crate internally.
- [x] Negative security tests: malformed TPM quotes (bad base64, truncated data)
      — structural validation uses safe Rust patterns; building block tests verify
      no panics on edge cases. Full pipeline tests (with mock registrar) deferred
      to Phase 8 infrastructure.
- [x] Negative security tests: attacker-controlled public keys do not cause panics
      in RSA encryption (empty/garbage/truncated/EC PEM, empty plaintext, oversized
      plaintext all return Err without panics)

---

## Phase 2: API Version Separation (Feature Flags)

Clean separation of API 2.x (pull model) and API 3.x (push model) code paths using
Rust feature flags. This enables future removal of pull model code by disabling a
feature.

**Architecture decision:** After evaluation, `#[cfg]` attributes were chosen over
an `ApiClient` trait because v3 methods are already separate (`*_v3()` suffix),
the agent client is entirely v2-only, and `attestation.rs` is entirely pull-model
code. The trait approach would require heavy refactoring for marginal benefit.
Phase 9 removal is just deleting `#[cfg(feature = "api-v2")]` blocks.

### 2.1 Add feature flag infrastructure

- [x] Add `[features]` section to `keylimectl/Cargo.toml`:
      ```toml
      [features]
      default = ["api-v2", "api-v3"]
      api-v2 = []
      api-v3 = []
      ```
- [x] Add `compile_error!` guard: at least one of `api-v2` or `api-v3` must be enabled
- [x] Verify the project builds with all feature combinations:
      `default`, `api-v2` only, `api-v3` only

### 2.2 Gate supported version constants

- [x] Create `api_versions.rs` module as single source of truth for version constants
      (`SUPPORTED_API_VERSIONS`, `SUPPORTED_AGENT_API_VERSIONS`, `DEFAULT_API_VERSION`,
      `is_v3()`), replacing duplicated arrays in verifier, registrar, and agent clients
- [x] Make `SUPPORTED_API_VERSIONS` feature-conditional: v2 versions behind `api-v2`,
      v3 versions behind `api-v3`
- [x] Gate `client/agent.rs` entirely behind `#[cfg(feature = "api-v2")]` since the
      agent client is only used in pull model

### 2.3 Separate client methods

- [x] In `client/verifier.rs`: gate all `*_v3()` helper methods with
      `#[cfg(feature = "api-v3")]`
- [x] In `client/verifier.rs`: gate v2.x fallback paths with
      `#[cfg(feature = "api-v2")]`
- [x] Restructure 6 public methods (`get_agent`, `delete_agent`, `reactivate_agent`,
      `list_agents`, `get_bulk_info`, `add_runtime_policy`) with `#[cfg]` blocks
- [x] Apply the same pattern to `client/registrar.rs`: split `test_api_version`
      into v2/v3 variants, restructure `detect_api_version` with 410 Gone handler
      and cfg-conditional version probing
- [x] ~~Ensure methods that currently lack v3 fallback are properly gated~~ —
      `update_runtime_policy`, `delete_runtime_policy`, `list_runtime_policies`,
      and MB policy methods are version-agnostic (use `self.api_version` in URLs),
      so no gating is needed; callers in command modules remain version-independent

### 2.4 Separate command-level logic

- [x] In `commands/agent/attestation.rs`: gate pull-model attestation flow (quote
      request, key exchange, key delivery) behind `#[cfg(feature = "api-v2")]`
- [x] In `commands/agent/add.rs`: ensure push-model path works independently when
      only `api-v3` is enabled
- [x] Gate v2-only fields and imports with `#[cfg(feature = "api-v2")]` or
      `#[cfg_attr(not(feature = "api-v2"), allow(dead_code))]`

### 2.5 Separate version detection logic

- [x] In `client/verifier.rs`: make version detection conditional -- 410 Gone
      match arm gated behind `api-v3`, version probing uses cfg-conditional blocks
- [x] Apply the same pattern to `client/registrar.rs`: 410 Gone match arm,
      cfg-conditional version probing with `test_api_version` / `test_api_version_v3`
- [x] When only `api-v3` is enabled, skip v2.x detection (uses `false` fallback)
- [x] When only `api-v2` is enabled, skip v3.x detection (uses `false` fallback)

### 2.6 Testing

- [x] Add CI matrix entries for: `--features api-v2`, `--features api-v3`,
      `--features "api-v2,api-v3"` (default)
- [x] Ensure `cargo build` succeeds for all feature combinations
- [x] Ensure `cargo test` passes for all combinations (302, 301, 290)
- [x] Ensure `cargo clippy` passes for all combinations
- [x] Verify `compile_error!` triggers when neither feature is enabled
- [x] Test that gated code is absent from the binary when its feature is disabled
      (verified: no `attestation`, `agent_client`, or `test_api_version` v2 symbols
      in api-v3 binary; no `*_v3` symbols in api-v2 binary)

---

## Phase 3: Push Model as Primary Mode

Make the push model (API 3.x) the recommended and default operational mode.

### 3.1 Push model `agent add`

- [x] ~~Remove `#[allow(dead_code)]` from `push_model` field in `AddAgentParams`~~ (Phase 2.4)
- [x] Restructure `AddAgentRequest`: `cloudagent_ip` and `cloudagent_port` are now
      `Option<String>` / `Option<u16>` with `skip_serializing_if` (omitted when None)
- [x] When `--push-model` is used (or API 3.x is detected), skip the agent contact
      steps (quote request, key exchange) entirely — auto-detection logic in `add.rs`
- [x] Send agent data to verifier without requiring `--ip` / `--port` — IP/port
      fall back to registrar data or "0.0.0.0":0 for push model
- [x] Document push model as the recommended approach — `--help` describes push model
      as default for API 3.x; pull model as legacy
- [x] Add `--wait-for-attestation` flag: polls verifier for `operational_state` with
      configurable `--attestation-timeout` (default 60s); detects initial, failure,
      and progress states

**Push model error handling:**

- [x] Handle case where the agent has not yet registered with the registrar —
      actionable error with `keylimectl agent status --registrar-only` guidance
- [x] Handle case where the agent ID does not match any registered agent —
      same as above (agent not found in registrar = not registered)
- [x] Handle case where the verifier cannot reach the agent for initial attestation —
      `--wait-for-attestation` detects failure states and reports them
- [x] Document expected error messages and user guidance for each scenario —
      error messages include recovery commands (retry, remove+re-add)

### 3.2 Push model `agent status`

- [x] In push model, agent status comes entirely from verifier and registrar
      (no direct agent contact) — already gated behind `api_version < 3.0`
- [x] Direct agent communication path in `get_agent_status()` is gated behind
      `#[cfg(feature = "api-v2")]` and `api_version < 3.0`; response includes
      `"model": "push"` or `"model": "pull"` indicator

### 3.3 Push model `agent update`

- [x] Update works without agent contact in push model — `update.rs` does
      remove + re-add, and `add_agent` auto-detects push model
- [x] Re-attestation (quote) only required for pull model updates — push model
      path in `add_agent` skips attestation step entirely
- [x] Update semantics: in push model, updating an agent's policy means updating
      the verifier's record via remove + re-add; the verifier triggers re-evaluation
      on the next agent-initiated attestation cycle

### 3.4 Default to push model when API 3.x is available

- [x] When verifier reports API 3.x, auto-select push model without `--push-model`
      flag — `is_push_model` determined after API version detection; uses
      `api_version >= 3.0` for auto-detection when neither flag is set
- [x] Added `--pull-model` flag (`conflicts_with = "push_model"`) for users who
      need to force pull model with a v3.x verifier
- [x] Deprecation warning emitted when `--pull-model` is used with a v3.x verifier
      (both `log::warn!` and `output.info()`)
- [x] Mixed deployments handled: auto-detection uses the verifier's reported API
      version; `--pull-model` overrides for migration scenarios

### 3.5 Graceful failure in multi-step operations

The `agent add` flow is multi-step (registrar lookup, agent quote, key delivery,
verifier registration). If a later step fails after earlier steps succeed, the
system may be in an inconsistent state.

- [x] Error messages include context about what step failed and what the user
      should do to recover (e.g., "Failed to enroll agent (push model): ... Retry with:")
- [x] Key delivery failure includes recovery guidance: "remove and re-add"
- [x] Push model verifier rejection includes model context and retry command

### 3.6 Testing

- [x] Unit tests for `extract_operational_state()`: nested, top-level, missing,
      empty, prefers-nested (5 tests in `add.rs`)
- [x] Unit tests for attestation state classification: initial, failure, and
      progress states correctly categorized (1 test in `add.rs`)
- [x] Unit tests for model auto-detection logic: explicit push, explicit pull,
      auto-detect v2.x/v3.x (1 test with 8 assertions in `add.rs`)
- [x] Unit tests for `AddAgentRequest` Optional fields: None not serialized,
      Some serialized, validate with None succeeds, validate empty IP fails,
      validate zero port fails (5 tests in `types.rs`)
- [x] Unit tests for `AddAgentParams` with `pull_model` and `wait_for_attestation`
      fields (2 tests in `types.rs`)
- [x] All tests pass across all feature combinations: 327 (default), 326 (api-v2),
      305 (api-v3); clippy clean on all 3
- [ ] Integration tests (end-to-end against running/mocked verifier) deferred to
      Phase 8 mock infrastructure

---

## Phase 4: Configuration and Usability

### 4.1 Sane defaults audit

- [x] Verify all configuration options have sensible defaults (current state is good)
- [x] Ensure keylimectl runs without any config file: `keylimectl list agents` should
      attempt `127.0.0.1:8881` (verifier) and `127.0.0.1:8891` (registrar) by default
- [x] Document the default values in `--help` output for each option
- [x] Add environment variable support: `KEYLIME_VERIFIER__IP`,
      `KEYLIME_VERIFIER__PORT`, `KEYLIME_REGISTRAR__IP`,
      `KEYLIME_REGISTRAR__PORT` (uses `config` crate's env var support with
      `KEYLIME_` prefix and double-underscore separators)
- [x] Support IPv6 addresses: validate and format both IPv4 and IPv6 addresses
      (bracket notation for IPv6 in URLs, e.g., `[::1]:8881`)
- [x] Add `--timeout` CLI override for per-command timeout control (useful for
      long-running operations like policy generation from RPM repos)
- [x] Evaluate replacing the config singleton pattern (`config::singleton`) with
      passing config through function parameters for better testability and
      parallel test execution. **Decision**: Keep singleton, document as known
      limitation. Tests work around it by constructing `Config` directly. Defer
      refactoring to a later phase if parallel test execution becomes blocking.

### 4.2 No-argument behavior and configuration wizard

When `keylimectl` is invoked without any subcommand, the behavior depends on
whether a configuration file is found:

**No config file found → offer wizard:**

```
$ keylimectl
keylimectl v0.1.0

No configuration file found.
Would you like to run the configuration wizard? [Y/n]

  Tip: You can also run `keylimectl configure` at any time.
```

- [x] Detect absence of config file at all search path locations
- [x] If stdin is a TTY, show tip about `keylimectl configure`
- [x] If stdin is not a TTY (scripted/piped), show config summary and
      clap's auto-generated `--help` output (no interactive prompts)
- [x] Show config summary followed by clap's dynamically generated help

**Config file found → show summary and usage:**

```
$ keylimectl
keylimectl v0.1.0

Configuration: ~/.config/keylimectl/config.toml
Verifier:      10.0.0.1:8881
Registrar:     10.0.0.2:8891
TLS:           mTLS enabled (client cert: /var/lib/keylime/cv_ca/client-cert.crt)
API:           v3.0 (push model)

Usage: keylimectl <COMMAND>

Commands:
  agent          Manage agents
  policy         Manage runtime policies
  measured-boot  Manage measured boot policies
  list           List resources
  verify         Verify attestation evidence
  configure      Reconfigure keylimectl
  info           Show diagnostics and server information

Run `keylimectl <COMMAND> --help` for more information on a command.
```

- [x] Show keylimectl version (via clap's auto-generated help)
- [x] Show which config file was loaded (full path) or "(defaults)"
- [x] Show verifier IP:port
- [x] Show registrar IP:port
- [x] Show TLS status summary (mTLS/server-only/disabled)
- [ ] Show detected API version and model (push/pull) if possible (deferred:
      requires connecting to verifier, better suited for a `keylimectl info` command)
- [x] Follow with a compact usage summary listing available commands (via
      clap's `CommandFactory::command().print_help()` for dynamic rendering)
- [x] Mention `keylimectl configure` for reconfiguration

**`keylimectl configure` subcommand:**

Explicitly invokes the interactive configuration wizard.

**Crate evaluation for interactive prompts:**

| Crate | Status | Features | Recommendation |
|-------|--------|----------|----------------|
| `dialoguer` 0.11 | Actively maintained, most downloads | Input, Confirm, Select, MultiSelect, Password, FuzzySelect | **Safe choice**: mature, large community |
| `inquire` 0.7 | Actively maintained | Text, Confirm, Select, MultiSelect, CustomType, autocomplete | **Best features**: typed input, validators, autocomplete |
| `cliclack` 0.3 | Actively maintained | Input, Confirm, Select, intro/outro, spinner | **Best UX**: wizard-like flow with polished styling |
| `requestty` 0.5 | Unmaintained (stale since 2022) | Batch questions, conditional flow | Not recommended |
| `promptly` 0.3 | Abandoned | Text input only | Not recommended |

**Recommended**: `dialoguer` or `inquire` (evaluate both before deciding). `cliclack`
is worth considering if a polished wizard UX is a priority.

**Wizard implementation:**

- [x] Add `configure` subcommand to CLI
- [x] Add interactive prompt crate as an optional dependency behind a feature flag
      (`wizard` feature using `dialoguer` 0.12, enabled by default)
- [x] Implement wizard flow:
  1. Choose configuration scope via `--scope` (local/user/system)
  2. Verifier connection: IP, port
  3. Registrar connection: IP, port
  4. TLS setup: verify server cert, enable mTLS, client cert/key paths
  5. Client settings: timeout
  6. Test connectivity (optional, `--test-connectivity` flag, not yet implemented)
  7. Write configuration file with `toml::to_string_pretty()`
- [x] Support `--non-interactive` flag for scripted configuration
      (e.g., `keylimectl configure --verifier-ip 10.0.0.1 --non-interactive`)
- [x] Print the generated configuration file path on success
- [x] If a config file already exists, ask for confirmation before overwriting
      (in interactive mode)

### 4.3 Configuration file locations

Formalize the search path and directory naming:

- [x] CLI argument: `--config <FILE>` (highest priority)
- [x] Local: `./.keylimectl/config.toml` (project-local)
- [x] User: `~/.config/keylimectl/config.toml` (XDG standard)
- [x] System: `/etc/keylime/keylimectl.conf` (system-wide, shared with keylime)
- [x] Document the precedence order in `--help` (`after_long_help`) and module docs

### 4.4 Testing

- [x] Unit tests for config loading: verify defaults work with no config file
- [x] Unit tests for config precedence: CLI > env var > config file > default
- [x] Unit tests for environment variable overrides (existing from Phase 2)
- [x] Test no-argument behavior without config file: "No configuration file found"
      message shown, config summary with defaults, clap help on stdout
- [x] Test no-argument behavior shows config summary with correct values
      (verifier, registrar, TLS, config path)
- [x] Test no-argument behavior exits successfully (integration test)
- [x] Test configuration wizard in non-interactive mode
      (`keylimectl configure --verifier-ip 10.0.0.1 --non-interactive`)
- [x] Test wizard output: generated TOML is valid and contains expected values
      (unit test: `test_generated_toml_roundtrips`, `test_write_config_file_creates_dirs_and_file`)
- [x] Test config file search path resolution (local, user, system)
      (unit tests: `test_resolve_config_path_*`)
- [x] Test `--config <FILE>` override (existing: `test_get_config_paths_explicit`)
- [x] All tests pass across all feature combinations: 340 unit + 8 integration
      (default), 339 unit (api-v2 only), 318 unit (api-v3 only); clippy clean

---

## Phase 5: Diagnostics

### 5.1 `keylimectl info` command

Show the effective runtime configuration and environment.

- [ ] Add `info` subcommand (or `diagnostics` / `diag`)
- [ ] Show effective configuration (merged from all sources, with source annotations):
      ```
      Verifier:
        IP:   10.0.0.1   (from: ~/.config/keylimectl/config.toml)
        Port: 8881        (from: default)
      Registrar:
        IP:   10.0.0.2   (from: KEYLIMECTL_REGISTRAR_IP)
        Port: 8891        (from: default)
      TLS:
        Client cert: /var/lib/keylime/cv_ca/client-cert.crt  (from: default)
        Verify server: true                                   (from: default)
      ```
- [ ] Show configuration file search results (which files were found/loaded)
- [ ] Show keylimectl version, build info, and enabled features (`api-v2`, `api-v3`)

### 5.2 `keylimectl info verifier`

- [ ] Query verifier `/version` endpoint and display supported API versions
- [ ] Show verifier build version if available
- [ ] Test TLS connectivity and report certificate details
- [ ] Report number of monitored agents

### 5.3 `keylimectl info registrar`

- [ ] Query registrar `/version` endpoint and display supported API versions
- [ ] Test TLS connectivity and report certificate details
- [ ] Report number of registered agents

### 5.4 `keylimectl info agent <AGENT_ID>`

- [ ] Combine verifier + registrar data for a single agent
- [ ] Show operational state, IP, port, policies, TPM info
- [ ] In pull model: attempt direct agent contact and show agent version
- [ ] Show attestation history summary if available

### 5.5 `keylimectl info tls`

- [ ] Validate all configured TLS certificate files exist and are readable
- [ ] Check certificate expiration dates
- [ ] Verify cert/key pairing
- [ ] Test TLS handshake with verifier and registrar
- [ ] Report any TLS issues with actionable suggestions

### 5.6 Testing

- [ ] Unit tests for `info` output formatting (JSON, table, YAML)
- [ ] Unit tests for configuration source annotation logic
- [ ] Integration tests: `info verifier` and `info registrar` against mocked
      servers returning known `/version` responses
- [ ] Integration tests: `info tls` with valid certs, expired certs, and
      mismatched cert/key pairs
- [ ] Test `info agent <ID>` with agents in various operational states

---

## Phase 6: Policy Tools Integration

Consolidate the Python `keylime-policies` tools into `keylimectl`, providing policy
generation, signing, validation, and one-shot evidence verification from a single binary.

**Prerequisites -- evaluate before starting this phase:**

- [ ] **Error type audit**: The codebase already has `KeylimectlError`,
      `CommandError`, `ClientError`, `CryptoError`, and `CryptoTestError`. Phase 6
      will add policy parsing, DSSE, and evidence errors. Decide on a unified error
      strategy (e.g., `thiserror` enum nesting, single top-level error with sources)
      before adding more error types.
- [ ] **Async vs blocking strategy**: Phase 6 mixes CPU-bound work (digest
      computation, filesystem scanning) with IO-bound work (HTTP requests to
      verifier). Decide whether to use `tokio::spawn_blocking` for CPU work or
      `rayon` for parallel digests alongside tokio. Using `rayon` for digest
      calculation is a common pattern but requires care to avoid blocking the
      tokio runtime.

**Python tools being replaced:**

| Python tool | keylimectl equivalent |
|-------------|----------------------|
| `keylime_create_policy` | `keylimectl policy generate runtime` |
| `keylime-policy create runtime` | `keylimectl policy generate runtime` |
| `keylime-policy create measured-boot` | `keylimectl policy generate measured-boot` |
| `keylime_convert_runtime_policy` | `keylimectl policy convert` |
| `keylime_sign_runtime_policy` | `keylimectl policy sign` |
| `keylime-policy sign runtime` | `keylimectl policy sign` |
| `keylime_oneshot_attestation` | `keylimectl verify evidence` |

### 6.1 Runtime policy generation (`keylimectl policy generate runtime`)

Rewrite `keylime/policy/create_runtime_policy.py` functionality in Rust.

**Input sources:**

- [ ] IMA measurement list (`--ima-measurement-list`, default:
      `/sys/kernel/security/ima/ascii_runtime_measurements`)
- [ ] Plain-text allowlist files (`--allowlist`, hash + path format)
- [ ] Local filesystem scanning (`--rootfs`, with `--skip-path` exclusions).
      Note: the Python code uses `psutil.disk_partitions()` to detect non-root
      filesystems; in Rust, read `/proc/mounts` or `/proc/self/mountinfo` instead.
- [ ] Initramfs extraction (`--ramdisk-dir`). **Library evaluation required:**
      initramfs files are concatenated CPIO archives (microcode + main) with
      multiple compression formats. Needed crates: `cpio` (basic), `flate2`
      (gzip), `xz2` (xz), `zstd` (zstd), `lz4_flex` (lz4). Evaluate whether
      the existing Rust crates handle the concatenated-archive case or if
      custom parsing is needed. Consider making initramfs support an optional
      feature flag if the dependency footprint is large.
- [ ] Local RPM repository (`--local-rpm-repo`). **Library evaluation required:**
      the Python code uses the `rpm` C library via Python bindings to parse RPM
      headers and extract file digests. Options in Rust:
      1. Bind to `librpm` via FFI (adds C dependency, fragile)
      2. Use the `rpm-rs` crate (evaluate maturity and completeness)
      3. Implement basic RPM header parsing in Rust (significant effort)
      4. Defer RPM support behind a feature flag (e.g., `rpm`) and implement
         the other input sources first
- [ ] Remote RPM repository (`--remote-rpm-repo`) -- same library dependency
      as local RPM, plus HTTP fetching of repository metadata
- [ ] Base policy merging (`--base-policy`, merge new data into existing policy)
- [ ] IMA exclude list (`--excludelist`)

**Policy features:**

- [ ] Parse IMA log entries (ima, ima-ng, ima-sig templates)
- [ ] Extract keyrings entries (`--keyrings`)
- [ ] Extract ima-buf entries (`--ima-buf`)
- [ ] Add IMA signature verification keys (`--add-ima-signature-verification-key`)
- [ ] Multi-algorithm support (SHA-1, SHA-256, SHA-384, SHA-512, SM3-256)
- [ ] Automatic hash algorithm detection from digests
- [ ] Parallel digest calculation (thread pool)
- [ ] Boot aggregate detection and parsing
- [ ] Ignored keyrings (`--ignored-keyrings`)
- [ ] Device-mapper policy support (`dm_policy` field): dm-verity and dm-crypt
      IMA policy handling

**Output:**

- [ ] JSON runtime policy following the v1 schema (`meta`, `release`, `digests`,
      `excludes`, `keyrings`, `ima`, `ima-buf`, `verification-keys`)
- [ ] Output to file (`--output`) or stdout
- [ ] Legacy allowlist format output (`--show-legacy-allowlist`)

### 6.2 Measured boot policy generation (`keylimectl policy generate measured-boot`)

Rewrite `keylime/policy/create_mb_policy.py` functionality in Rust.

- [ ] Parse binary UEFI event log (`--eventlog-file`, typically
      `/sys/kernel/security/tpm0/binary_bios_measurements`)
- [ ] Extract UEFI Secure Boot variables (PK, KEK, DB, DBX)
- [ ] Extract platform firmware digests (S-CRTM, firmware blobs)
- [ ] Extract bootloader digests and authcodes (SHIM, GRUB)
- [ ] Extract kernel digests, command line, and initrd digests
- [ ] Extract MOK/MOKx digests (Machine Owner Keys)
- [ ] Detect Secure Boot enabled status
- [ ] Support `--without-secureboot` flag
- [ ] Output JSON measured boot reference state to file (`--output`) or stdout

**Reference state structure:**

```json
{
  "has_secureboot": true,
  "scrtm_and_bios": [{"scrtm": {"sha256": "0x..."}, "platform_firmware": [...]}],
  "pk": [{"SignatureOwner": "...", "SignatureData": "0x..."}],
  "kek": [...], "db": [...], "dbx": [...],
  "vendor_db": [...],
  "kernels": [{
    "shim_authcode_sha256": "0x...",
    "grub_authcode_sha256": "0x...",
    "kernel_authcode_sha256": "0x...",
    "initrd_plain_sha256": "0x...",
    "kernel_cmdline": "..."
  }],
  "mokdig": [...], "mokxdig": [...]
}
```

### 6.3 TPM policy generation (`keylimectl policy generate tpm`)

TPM policies (PCR mask and expected values) are simpler but currently require
manual JSON construction.

- [ ] Add `keylimectl policy generate tpm` subcommand
- [ ] Read current PCR values from a TPM or from a file
- [ ] Allow selecting PCR indices (e.g., `--pcrs 0,1,2,7`)
- [ ] Support PCR mask specification (`--mask 0x408000`)
- [ ] Generate JSON TPM policy with mask and expected PCR values
- [ ] Support specifying hash algorithm (`--hash-alg sha256`)

**Dependency note:** Reading PCR values from a local TPM requires the `tss-esapi`
crate, which depends on the `tss2` C libraries at build time. This should be behind
an optional feature flag (e.g., `tpm-local`) so that builds without TPM libraries
are possible. Users without a TPM can still generate policies from file input.
CI environments typically do not have TPM libraries installed.

### 6.4 Policy signing (`keylimectl policy sign`)

Rewrite `keylime/policy/sign_runtime_policy.py` functionality in Rust.

**DSSE implementation options:**

- [ ] Evaluate `sigstore-rs` crate for existing Rust DSSE support before
      implementing from scratch
- [ ] Evaluate whether the `keylime::crypto::x509::CertificateBuilder` from the
      shared crate can be reused for the X.509 signing backend (it already
      supports self-signed certificate generation)
- [ ] If no suitable crate exists, implement DSSE from the specification
      (relatively simple: base64url encode payload, sign with ECDSA, build envelope)

- [ ] DSSE (Dead Simple Signing Envelope) implementation
- [ ] ECDSA signing backend (default)
- [ ] X.509 certificate-based signing backend (`--backend x509`)
- [ ] Sign with existing private key (`--keyfile`)
- [ ] Generate new EC key pair if no key provided (`--keypath` to save key)
- [ ] Output signed policy to file (`--output`) or stdout
- [ ] Output X.509 certificate (`--cert-outfile`, for x509 backend)
- [ ] Verify existing signature (`keylimectl policy verify-signature`)
- [ ] Ensure all generated private key files have restrictive permissions
      (`0o600`), consistent with `keylime::crypto::write_key_pair()`
- [ ] Use constant-time comparison for DSSE signature verification
      (same as `openssl::memcmp::eq()` used in HMAC verification)

**DSSE envelope structure:**

```json
{
  "payload": "base64url_encoded_policy",
  "payloadType": "application/vnd.keylime+json",
  "signatures": [{"keyid": "...", "sig": "..."}]
}
```

### 6.5 Legacy policy conversion (`keylimectl policy convert`)

Rewrite `keylime/cmd/convert_runtime_policy.py` functionality in Rust.

- [ ] Convert JSON-format allowlists (`{"hashes": {"/path": ["digest"]}}`)
- [ ] Convert flat-text allowlists (`digest  /path` format)
- [ ] Upgrade older policy versions to current version
- [ ] Merge exclude lists into converted policy (`--excludelist`)
- [ ] Add verification keys during conversion (`--verification-keys`)
- [ ] Output to file (`--output`, required)

### 6.6 Policy validation (`keylimectl policy validate`)

- [ ] Add `validate` subcommand for each policy type
- [ ] Evaluate using the `jsonschema` crate for formal JSON Schema (RFC draft)
      validation, sharing the same schema definition as the Python implementation.
      Alternative: manual field-by-field validation (as the Python code does in
      `ima.validate_runtime_policy()`). The `jsonschema` crate is more maintainable
      and ensures schema consistency across implementations.
- [ ] Runtime policy: JSON schema validation against the v1 runtime policy schema
- [ ] Runtime policy: verify DSSE signature if signed (`--signature-key`)
- [ ] Measured boot policy: validate JSON structure and field types
- [ ] TPM policy: validate mask format and PCR value formats
- [ ] Report validation errors with actionable messages
- [ ] Exit code 0 on valid, non-zero on invalid (for scripting)

### 6.7 Evidence verification (`keylimectl verify evidence`)

Provide a client for the verifier's `POST /v{api_version}/verify/evidence` endpoint
to perform one-shot attestation without agent registration.

**API version note:** The v2.x verifier accepts `{"type": "tpm", "data": {...}}`
(simple envelope). The Rust agent's 3.x evidence handling structures use a JSON:API
-style format with `data.type`, `data.attributes.evidence_collected[]`. When
targeting a 3.x verifier, the request format may differ. Implement support for both
formats and select based on the detected API version.

- [ ] Add `verify` top-level subcommand with `evidence` action
- [ ] Send TPM evidence to verifier for verification:
  ```
  keylimectl verify evidence \
    --nonce <NONCE> \
    --quote <QUOTE_FILE> \
    --hash-alg sha256 \
    --tpm-ak <AK_FILE> \
    --tpm-ek <EK_FILE> \
    --runtime-policy <POLICY_FILE> \
    --ima-measurement-list <IMA_LOG>
  ```
- [ ] Support all evidence types: `--type tpm` (default), `--type tee`
- [ ] Support all policy types: `--tpm-policy`, `--runtime-policy`, `--mb-policy`
- [ ] Support measurement logs: `--ima-measurement-list`, `--mb-log`
- [ ] Read evidence from local files or stdin
- [ ] Display verification result (valid/invalid) with detailed failure information
- [ ] Support collecting evidence from local TPM (`--collect-local`, requires
      TPM access) for self-attestation testing
- [ ] Machine-readable output in JSON format (default)
- [ ] Human-readable summary in table format (`--format table`)

**Request format (sent to verifier):**

```json
{
  "type": "tpm",
  "data": {
    "nonce": "...", "quote": "...", "hash_alg": "sha256",
    "tpm_ak": "...", "tpm_ek": "...",
    "tpm_policy": "...", "runtime_policy": "...", "mb_policy": "...",
    "ima_measurement_list": "...", "mb_log": "..."
  }
}
```

**Response parsing:**

```json
{
  "valid": true/false,
  "claims": {...},
  "failures": [{"type": "event_id", "context": {"message": "..."}}]
}
```

### 6.8 Interactive policy wizards

Add interactive wizards (using the same prompt crate as the configuration wizard)
to guide users through policy creation.

**Runtime policy wizard (`keylimectl policy generate runtime --interactive`):**

- [ ] Ask: What input sources? (IMA log, filesystem, RPM repo, allowlist)
- [ ] Ask: IMA measurement list path (offer default
      `/sys/kernel/security/ima/ascii_runtime_measurements`)
- [ ] Ask: Include keyrings? Which keyrings to ignore?
- [ ] Ask: Include ima-buf entries?
- [ ] Ask: Exclude patterns? (show examples)
- [ ] Ask: Add IMA signature verification keys?
- [ ] Ask: Hash algorithm (auto-detect or specify)
- [ ] Ask: Merge into existing base policy?
- [ ] Preview generated policy summary (file count, digest count)
- [ ] Ask: Output file location

**Measured boot policy wizard (`keylimectl policy generate measured-boot --interactive`):**

- [ ] Ask: Event log file path (offer default
      `/sys/kernel/security/tpm0/binary_bios_measurements`)
- [ ] Ask: Include Secure Boot variables?
- [ ] Preview: Show detected Secure Boot status, kernel count, MOK status
- [ ] Ask: Output file location

**TPM policy wizard (`keylimectl policy generate tpm --interactive`):**

- [ ] Ask: Read PCRs from local TPM or specify manually?
- [ ] Ask: Which PCR indices to include? (show descriptions of standard PCRs)
- [ ] Ask: Hash algorithm?
- [ ] Preview: Show selected PCR values
- [ ] Ask: Output file location

**Verify evidence wizard (`keylimectl verify evidence --interactive`):**

- [ ] Ask: Evidence type (TPM or TEE)
- [ ] Ask: Collect from local TPM or provide files?
- [ ] Ask: Which policies to verify against?
- [ ] Ask: Verifier connection details (use configured defaults)
- [ ] Execute and display results

### 6.9 Policy-related CLI restructuring

Integrate the new policy commands into the existing CLI structure.

Current structure:
```
keylimectl policy create <NAME> --file <FILE>    # upload to verifier
keylimectl policy show <NAME>                     # read from verifier
keylimectl policy update <NAME> --file <FILE>     # update on verifier
keylimectl policy delete <NAME>                   # delete from verifier
```

Extended structure:
```
keylimectl policy create <NAME> --file <FILE>     # upload to verifier (existing)
keylimectl policy show <NAME>                      # read from verifier (existing)
keylimectl policy update <NAME> --file <FILE>      # update on verifier (existing)
keylimectl policy delete <NAME>                    # delete from verifier (existing)
keylimectl policy generate runtime [OPTIONS]       # generate locally (new)
keylimectl policy generate measured-boot [OPTIONS] # generate locally (new)
keylimectl policy generate tpm [OPTIONS]           # generate locally (new)
keylimectl policy sign <FILE> [OPTIONS]            # sign locally (new)
keylimectl policy verify-signature <FILE> [OPTIONS]# verify signature (new)
keylimectl policy validate <FILE> [OPTIONS]        # validate locally (new)
keylimectl policy convert <FILE> [OPTIONS]         # convert legacy (new)

keylimectl verify evidence [OPTIONS]               # one-shot attestation (new)
```

- [ ] Add `generate` subcommand group under `policy`
- [ ] Add `sign`, `verify-signature`, `validate`, `convert` subcommands under `policy`
- [ ] Add `verify` top-level command with `evidence` subcommand
- [ ] Ensure no naming conflicts with existing `policy create` (CRUD) and
      `policy generate` (local generation) subcommands. **UX decision needed:**
      the verbs "create" and "generate" are similar and may confuse users.
      Alternatives to consider:
      - `policy push` / `policy upload` for server-side CRUD
      - Keep current naming but add strong help text distinguishing them
      - Use a different grouping (e.g., `policy remote create` vs `policy generate`)
- [ ] Apply the same pattern to `measured-boot`: add `measured-boot generate`
      for local policy creation vs `measured-boot create` for verifier upload
- [ ] Add `policy diff <OLD_FILE> <NEW_FILE>`: show added/removed digests,
      changed excludes, etc. between two policy files. Useful when updating
      policies to see what changed.

### 6.10 Testing

**Unit tests (per feature, merged with the implementation):**

- [ ] Runtime policy generation: parse known IMA log entries (ima, ima-ng,
      ima-sig templates) and verify output matches expected policy structure
- [ ] Runtime policy generation: test multi-algorithm digest extraction
- [ ] Runtime policy generation: test allowlist parsing (flat-text and JSON)
- [ ] Runtime policy generation: test base policy merging (digests, excludes,
      keyrings are correctly merged)
- [ ] Runtime policy generation: test exclude list validation (valid and invalid
      patterns)
- [ ] Measured boot policy generation: parse a known binary UEFI event log and
      verify extracted Secure Boot variables, kernel digests, etc.
- [ ] TPM policy generation: test PCR mask and value formatting
- [ ] Policy signing: DSSE sign/verify round-trip (ECDSA backend)
- [ ] Policy signing: DSSE sign/verify round-trip (X.509 backend)
- [ ] Policy signing: verify that signing with an existing key produces a
      verifiable signature
- [ ] Legacy policy conversion: convert known JSON allowlist and verify output
- [ ] Legacy policy conversion: convert known flat-text allowlist and verify output
- [ ] Policy validation: valid policies pass, invalid policies fail with
      actionable error messages
- [ ] Policy validation: each policy type (runtime, measured boot, TPM)

**Integration tests:**

- [ ] Evidence verification: send known-good evidence to a mocked verifier and
      verify the response is parsed correctly
- [ ] Evidence verification: send evidence that fails attestation and verify
      failure details are displayed
- [ ] Policy generation end-to-end: generate a runtime policy from a test IMA
      log, sign it, validate it, and verify the signature

**Fuzz testing:**

For a security-critical tool that parses IMA logs, UEFI event logs, TPM quote
structures, and JSON policies, fuzz testing is important to find crashes and
edge cases.

- [ ] Set up `cargo-fuzz` or `AFL` targets for:
  - IMA measurement list parser
  - UEFI binary event log parser
  - Policy JSON deserialization
  - Legacy allowlist parser (flat-text and JSON formats)
  - DSSE envelope parser
- [ ] Run fuzz testing as part of periodic CI (not necessarily on every PR,
      but on a scheduled basis)

**Performance benchmarks:**

- [ ] Add `criterion` benchmarks for large-scale policy generation (e.g., 100K
      files, large IMA logs) to detect performance regressions
- [ ] Benchmark parallel digest calculation with varying thread counts

---

## Phase 7: Feature Parity Gaps

Address remaining gaps from the Python tenant that are worth keeping.

### 7.1 Missing CLI options

- [ ] `--runtime-policy-url`: download runtime policy from a URL
- [ ] `--runtime-policy-checksum`: SHA-256 verification of downloaded policy
- [ ] `--cv-targethost`: agent IP as seen by the verifier (NAT/proxy scenarios)
- [ ] `--verifier-id` (`-vi`): filter by verifier in multi-verifier setups
- [ ] `--agent-api-version`: manually specify the agent API version
      (skip auto-detection)

### 7.2 Revocation workflow

The Python tenant's `AddAgentRequest` includes a `revocation_key` field, and
the current Rust `AddAgentRequest` has it as `Option<String>`. The tenant
generates a revocation key from the CA certificate. This is security-critical.

- [ ] Audit the revocation key generation and distribution workflow
- [ ] Ensure revocation keys are generated correctly in both push and pull model
- [ ] Test that revocation notifications are properly triggered when an agent
      is removed or fails attestation
- [ ] Evaluate: should keylimectl support configuring revocation notification
      callbacks/webhooks? (The Python tenant has this capability)

### 7.3 Evaluate and decide: keep or drop

These features exist in the Python tenant. Decide whether to implement them in
keylimectl or formally drop them.

- [ ] Pre-encrypted key delivery (`-k` / `--key`): used with `user_data_encrypt`.
      Evaluate if this workflow is still needed or if `--payload` covers all use cases.
- [ ] Encrypted payload (`-p` / `--payload` with `-k`): same as above.
- [ ] Include directory (`--include`): additional files in certificate zip.
      Evaluate if `--cert-dir` is sufficient.
- [ ] EK certificate verification: currently done by the tenant in pull model.
      In push model, this should be the verifier's responsibility. Decide if
      keylimectl needs this for pull model support.
- [ ] `ek_check_script`: external script for custom EK validation. Same
      consideration as above.
- [ ] `--runtime-policy-sig-key`: GPG signature verification of runtime policies.
      Evaluate if this should be a keylimectl concern or a server-side concern.
- [ ] Auto-generated agent UUIDs: the Python tenant supports
      `uuid_service_generate_locally` for auto-generating agent UUIDs. Decide
      if `keylimectl agent add` should support `--generate-uuid` or if the user
      must always supply one.

### 7.4 Testing

- [ ] Test `--runtime-policy-url`: download from a URL, verify checksum
- [ ] Test `--cv-targethost`: verify the value is sent to the verifier correctly
- [ ] Test `--verifier-id`: verify filtering by verifier in list operations
- [ ] Test `--agent-api-version`: verify auto-detection is skipped
- [ ] Test each implemented feature from 7.2 with unit and integration tests

---

## Phase 8: Documentation and CI

Note: Unit and integration tests for each feature are listed in their respective
phases. This section covers cross-cutting CI infrastructure and documentation that
span the entire project.

### 8.1 CI infrastructure

Note: A basic CI pipeline (`cargo build/test/clippy/fmt`) is established in
Phase 0. This section covers expanded CI concerns.

- [ ] Add feature flag matrix (see Phase 2.6)
- [ ] Add test coverage reporting (`tarpaulin` or `llvm-cov`)
- [ ] Set up integration test environment with mocked verifier and registrar.
      **Approach:** use `wiremock` or `mockito` for HTTP mocking, or lightweight
      `actix-web` / `axum` test servers that simulate verifier/registrar responses.
      Document the chosen approach so all phases use the same infrastructure.
- [ ] Test TLS configurations in CI (mTLS, server-only TLS, TLS disabled)
- [ ] Test API version negotiation with mixed-version deployments
- [ ] Schedule periodic fuzz testing runs (see Phase 6.10)

### 8.2 End-to-end tests (keylime-tests repository)

- [ ] Create BeakerLib test cases for keylimectl in the keylime-tests repository
- [ ] Mirror existing `keylime_tenant` test coverage
- [ ] Add push-model-specific test scenarios
- [ ] Add pull-model test scenarios (behind `api-v2` feature)
- [ ] Add configuration wizard test (scripted via `--non-interactive`)
- [ ] Add policy generation tests (runtime from IMA log, measured boot from event log)
- [ ] Add policy signing and evidence verification tests
- [ ] Add TLS configuration tests (mTLS, custom certificates)

### 8.3 Documentation

- [ ] Update README.md with push-model-first examples
- [ ] Update MIGRATION.md with feature flag information
- [ ] Write man page (`keylimectl.1`)
- [ ] Add shell completion generation (clap supports bash, zsh, fish, powershell)
- [ ] Document policy generation workflows with examples
- [ ] Document evidence verification usage

---

## Phase 9: Deprecation and Removal of Pull Model

This phase is long-term and depends on ecosystem readiness.

### 9.1 Deprecation warnings

- [ ] When `api-v2` feature is enabled and pull model is used, emit a deprecation
      warning to stderr
- [ ] Include migration guidance in the warning message
- [ ] Add `--suppress-deprecation-warnings` flag for CI environments.
      **Security note:** in a security tool, silencing deprecation warnings about
      a less-secure model could lead to operational blind spots. Consider also
      logging to a file when suppressed, or requiring the flag to be set via
      config file (not just CLI) to make suppression more deliberate.

### 9.2 Default feature change

- [ ] Change default features from `["api-v2", "api-v3"]` to `["api-v3"]`
- [ ] Users needing pull model must explicitly enable `api-v2`
- [ ] Announce in release notes

### 9.3 Removal

- [ ] Remove all `#[cfg(feature = "api-v2")]` code
- [ ] Remove `api-v2` feature flag
- [ ] Remove `client/agent.rs` (pull model agent client)
- [ ] Simplify `AddAgentRequest` (remove v2-only fields)
- [ ] Simplify version detection (v3.x only)
- [ ] Update all documentation

### 9.4 Testing

- [ ] Test deprecation warning is emitted on stderr when pull model is used
- [ ] Test `--suppress-deprecation-warnings` suppresses the warning
- [ ] After default feature change: verify `cargo build` without explicit
      features produces a push-model-only binary
- [ ] After removal: verify all tests pass with the simplified codebase
- [ ] Update CI matrix to remove `api-v2` combinations
- [ ] Update end-to-end tests to remove pull-model scenarios

---

## Appendix A: Configuration File Format

```toml
# keylimectl configuration file
# Location: ~/.config/keylimectl/config.toml

[verifier]
ip = "127.0.0.1"
port = 8881
# id = "default"          # For multi-verifier setups

[registrar]
ip = "127.0.0.1"
port = 8891

[tls]
client_cert = "/var/lib/keylime/cv_ca/client-cert.crt"
client_key = "/var/lib/keylime/cv_ca/client-private.pem"
# client_key_password = ""
trusted_ca = ["/var/lib/keylime/cv_ca/cacert.crt"]
verify_server_cert = true
enable_agent_mtls = true

[client]
timeout = 60
retry_interval = 1.0
exponential_backoff = true
max_retries = 3
```

## Appendix B: Runtime Policy Schema (v1)

```json
{
  "meta": {
    "version": 1,
    "generator": 0,
    "timestamp": "2025-01-01T00:00:00Z"
  },
  "release": 0,
  "digests": {
    "/usr/bin/example": ["sha256:abc123...", "sha256:def456..."]
  },
  "excludes": ["boot_aggregate"],
  "keyrings": {
    ".ima": ["sha256:..."]
  },
  "ima": {
    "ignored_keyrings": [],
    "log_hash_alg": "sha256",
    "dm_policy": null
  },
  "ima-buf": {
    "dm_table_load": ["sha256:..."]
  },
  "verification-keys": ""
}
```

**Generator types:**

| Value | Constant | Description |
|:-----:|----------|-------------|
| 0 | `Unknown` | Unknown generator |
| 1 | `EmptyAllowList` | Empty policy |
| 2 | `CompatibleAllowList` | Generated from compatible allowlist |
| 3 | `LegacyAllowList` | Converted from legacy allowlist |

## Appendix C: Evidence Verification API

**Endpoint:** `POST /v{api_version}/verify/evidence`

**Request:**
```json
{
  "type": "tpm",
  "data": {
    "nonce": "base64_nonce",
    "quote": "base64_tpm_quote",
    "hash_alg": "sha256",
    "tpm_ak": "base64_attestation_key",
    "tpm_ek": "base64_endorsement_key",
    "tpm_policy": "{\"22\": [...], \"mask\": \"0x408000\"}",
    "runtime_policy": "{...}",
    "mb_policy": "[...]",
    "ima_measurement_list": "10 0ade... ima-ng sha256:0000... boot_aggregate\n...",
    "mb_log": "base64_uefi_event_log"
  }
}
```

**Response:**
```json
{
  "code": 200,
  "status": "Success",
  "results": {
    "valid": true,
    "claims": { "...echoed input..." },
    "failures": [
      {
        "type": "ima.validation.ima-ng.not_in_allowlist",
        "context": { "message": "File not found in allowlist: /root/evil.sh" }
      }
    ]
  }
}
```

**Required parameters:** `nonce`, `quote`, `hash_alg`, `tpm_ak`, `tpm_ek`, and at
least one of `tpm_policy`, `runtime_policy`, or `mb_policy`.

**Authentication:** Public endpoint (no mTLS required).

## Appendix D: Feature Flag Build Matrix

| Build | `api-v2` | `api-v3` | Use Case |
|-------|:--------:|:--------:|----------|
| Default | Yes | Yes | Development, mixed deployments |
| Push-only | No | Yes | Production (target state) |
| Pull-only | Yes | No | Legacy environments |
| Neither | -- | -- | Compile error |
