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
heim audit
heim approvals
```

Only `doctor`, `--help`, and `--version` are implemented today. The other
commands are parsed and return an explicit "not implemented yet" error until
their behavior is accepted.

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

The product brief is currently kept as a local, ignored project note until the
specification is finalized.

## License

Apache-2.0.
