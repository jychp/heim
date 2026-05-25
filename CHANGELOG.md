# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial Rust workspace scaffold.
- Initial typed CLI command surface for `heim`.
- Core grant policy primitives for named grants, requester rules, command
  wildcards, and grant vs JIT approval modes.
- Draft policy documentation and example policy configuration.
- TOML policy loading and `heim policy validate --file <path>`.
- Local grant policy evaluation and `heim policy check`.
- Platform config directory policy loading with platform-specific defaults (XDG
  on Linux, Application Support on macOS, APPDATA on Windows).
- `heim exec` policy preflight with requester inference from the invoking
  parent process.
- `heim-exec` execution context planning with cwd and Git metadata detection for
  future approvals and audit events.
- `heim-audit` event model and JSONL sink under the platform config log
  directory without storing credential secret values.
- `heim exec` preflight audit event emission for allow, deny, and
  require-approval policy decisions.
- `heim exec` command execution for requests fully allowed by local policy,
  without credential injection yet.
- Transport-neutral approval request and decision contract for future JIT
  approval providers.
- Provider configuration schema for future AWS STS, GitHub App, and GitHub PAT
  credential issuance.
- Unsafe local auth file schema for GitHub App private keys and GitHub PATs,
  with strict Unix file permission checks.
- Unsafe local auth secret source resolution for GitHub App private keys and
  GitHub PATs, without provider calls or credential injection.
- GitHub PAT credential issuance for allowed `heim exec` requests, with
  process-scoped `GH_TOKEN` and `GITHUB_TOKEN` environment injection.
- Minimal `cargo-deny` policy for dependency license, advisory, and source
  checks, wired into GitHub Actions.
