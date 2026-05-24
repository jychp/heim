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
- Minimal `cargo-deny` policy for dependency license, advisory, and source
  checks, wired into GitHub Actions.
