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
heim config validate
heim policy
heim policy validate
heim policy check aws.prod-readonly --requester codex -- aws sts get-caller-identity
heim audit
heim approvals
```

Only `doctor`, `config validate`, `policy validate`, `policy check`, `exec`
policy preflight, approval request preparation, GitHub PAT environment
injection for allowed `exec` requests, approval decision handling, allowed
command execution, `--help`, and `--version` are implemented today. The other
commands are parsed and return an explicit "not implemented yet" error until
their behavior is accepted.

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

Policy evaluation can drive local preflight and allowed command execution.
When JIT approval is required, Heim prepares transport-neutral approval
requests from the execution context and config. It can apply approval decisions
returned by an approval provider, but built-in Slack dispatch is not implemented
yet.

Policy files are loaded from the platform config directory by default:

- Linux: `$XDG_CONFIG_HOME/heim/policies` when `XDG_CONFIG_HOME` is set,
  otherwise `~/.config/heim/policies`
- macOS: `~/Library/Application Support/heim/policies`
- Windows: `%APPDATA%\heim\policies`

Heim reads all `.toml` files in that directory, ignores other files, and merges
them into one policy document before validation.

Provider configuration is loaded from the platform config directory:

- Linux: `$XDG_CONFIG_HOME/heim/config.toml` when `XDG_CONFIG_HOME` is set,
  otherwise `~/.config/heim/config.toml`
- macOS: `~/Library/Application Support/heim/config.toml`
- Windows: `%APPDATA%\heim\config.toml`

The config schema can model AWS STS, GitHub App, GitHub PAT providers, and
approval transports such as Slack. Heim validates this schema and can issue a
configured GitHub PAT into an allowed child process. AWS STS, GitHub App
credential issuance, and built-in approval transport dispatch are not
implemented yet.

Unsafe local auth entries can be stored in `<config>/heim/.auth.json`. This is
supported but should be avoided for sensitive use when better sources are
available. On Unix, Heim requires owner-only permissions for this file.
The `heim-sources` crate can resolve these local auth references into typed
secret material for providers, with redacted debug output.

The default config file can be validated:

```bash
heim config validate
```

A specific config file and unsafe local auth file can also be validated:

```bash
heim config validate --file examples/config.toml
heim config validate --file examples/config.toml --policy-file examples/policy.toml
heim config validate --file examples/config.toml --auth-file ~/.config/heim/.auth.json
```

The default policy directory can be validated:

```bash
heim policy validate
```

A specific file or directory can also be validated for local testing:

```bash
heim policy validate --file examples/policy.toml
heim policy validate --dir examples/policies
```

One grant request can be evaluated locally:

```bash
heim policy check aws.prod-readonly --requester codex -- aws sts get-caller-identity
```

`heim exec` also runs a local policy preflight for one or more grants:

```bash
heim exec aws.prod-readonly -- aws sts get-caller-identity
heim exec --file examples/policy.toml github.personal-readonly -- gh pr view 42
heim exec --file examples/policy.toml --config-file examples/config.toml --auth-file ~/.config/heim/.auth.json github.personal-readonly -- gh pr view 42
```

For `heim exec`, the requester is inferred from the parent process that invoked
the `heim` binary. Policy evaluation returns `allow`, `deny`, or
`require_approval`. When every requested grant is allowed directly by policy,
Heim loads provider configuration and issues supported local credentials before
starting the wrapped command. The current issuer supports `github_pat` only and
injects `GH_TOKEN` and `GITHUB_TOKEN` into the child process. AWS STS and
GitHub App providers fail closed until their provider implementations are
added. When approval is required, Heim loads config, validates the referenced
approval transports, builds approval requests with configured options, and
applies returned approval decisions. The default runtime still fails closed
because no built-in approval transport dispatch is implemented yet. Heim does
not contact AWS, GitHub, or Slack, request approvals through Slack, or mint
GitHub App tokens yet.

Injected variables are scoped to the child process. If `GH_TOKEN` or
`GITHUB_TOKEN` already exist in the parent environment, Heim's issued values
override them for the wrapped command only.

The `heim-exec` crate builds the local execution context used by this preflight:
requested grants, inferred requester, wrapped command, current working
directory, and Git remote or branch metadata when they can be detected. This
context is prepared for future approval messages and provider calls. Git
metadata detection is best-effort; Heim continues without it when `git` is
unavailable or the current directory is not a Git repository.

## Audit Model

`heim-audit` defines typed audit events and an append-only JSONL sink. The model
records request context, grant/provider names, policy decisions, approval
metadata, credential issuance timestamps, and redacted credential carrier
metadata such as environment variable names.

By default, audit writes target the platform config directory:

- Linux: `$XDG_CONFIG_HOME/heim/logs/audit.jsonl` when `XDG_CONFIG_HOME` is set,
  otherwise `~/.config/heim/logs/audit.jsonl`
- macOS: `~/Library/Application Support/heim/logs/audit.jsonl`
- Windows: `%APPDATA%\heim\logs\audit.jsonl`

Audit records must never contain credential secret values. `heim exec` emits one
local audit event for the policy preflight decision and records redacted
credential carrier metadata for issued GitHub PAT grants. It does not contact
AWS or GitHub, request approvals through Slack, or mint GitHub App tokens yet.
`heim audit` does not read audit events yet.

See `docs/policy.md`, `docs/config.md`, `examples/policy.toml`, and
`examples/config.toml` for the current policy and provider model drafts.

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
