# Heim

Local-first Just-In-Time credential and capability broker for autonomous agents
and developer tools.

## Status

This repository is currently only a Rust workspace scaffold. Product specs and
runtime behavior are still being finalized, so crates are placeholders.

## Install

```bash
cargo build --workspace
```

## Development Setup

Install the local Rust components required by `make ci`:

```bash
make setup
```

If your Rust toolchain is not managed by `rustup`, `make setup` expects
`cargo`, `rustfmt`, and `clippy` to already be available.

## CLI

The current CLI exposes the initial command surface while product behavior is
still being finalized.

```bash
heim --help
heim --version
heim doctor
heim exec <grant> [<grant> ...] -- <command> [args...]
heim config
heim policy
heim policy validate --file examples/policy.toml
heim policy check --file examples/policy.toml aws.prod-readonly --requester codex -- aws sts get-caller-identity
heim audit
heim approvals
```

Only `doctor`, `policy validate`, `policy check`, `--help`, and `--version` are
implemented today. The other commands are parsed and return an explicit "not
implemented yet" error until their behavior is accepted.

## Grant Policy Model

`heim-core` defines the first policy primitives for named JIT credential grants.
A grant names a temporary credential, such as `aws.prod-readonly` or
`github.drymn-pr-write`.

Grant policies can express:

- which configured provider backs the grant
- which requester binaries may ask for it, including `*`
- which wrapped commands are allowed, including token wildcards such as `aws *`
- whether access is pre-authorized by policy or requires JIT approval through a
  configured transport such as `slack`

These are model types only. They do not load config, contact providers, request
approval, or execute commands yet.

Policy files can be loaded and validated:

```bash
heim policy validate --file examples/policy.toml
```

One grant request can be evaluated locally:

```bash
heim policy check --file examples/policy.toml aws.prod-readonly --requester codex -- aws sts get-caller-identity
```

Policy evaluation returns `allow`, `deny`, or `require_approval`. It does not
contact providers, request approvals, issue credentials, or execute commands.

See `docs/policy.md` and `examples/policy.toml` for the current policy model
draft.

## Run Checks

```bash
make ci
```

Equivalent explicit commands:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Layout

```text
crates/heim-cli/
crates/heim-core/
crates/heim-config/
crates/heim-policy/
crates/heim-approvals/
crates/heim-providers/
crates/heim-sources/
crates/heim-audit/
crates/heim-exec/
examples/
docs/
```

The product brief is currently kept as a local, ignored project note while the
specification is in progress.

## License

Apache-2.0.
