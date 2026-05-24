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
