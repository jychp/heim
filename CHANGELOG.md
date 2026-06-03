# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial Rust workspace scaffold.
- Initial typed CLI command surface for `heim`.
- `heim init` for creating the default local config, policy, and log layout
  without overwriting existing files.
- `heimd` local daemon skeleton with Unix socket `ping`/`pong` IPC for future
  long-lived approval workflows.
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
- Runtime approval session model that connects one approval request to one
  validated decision.
- `heim exec` approval request preparation for JIT policy decisions, including
  configured transport options, while approval dispatch remains deferred.
- `heim exec` approval decision handling for approved, approved-with-option,
  denied, timed-out, and unavailable approval provider outcomes.
- Approval options for provider-configured choices such as approving a request
  for a specific duration.
- Policy loading for approval transport options using compact TOML arrays.
- Runtime approval transport dispatch with a Slack provider boundary that loads
  Slack bot tokens from unsafe local auth and fails closed until Slack API
  calls are implemented.
- Provider configuration schema for future AWS STS, GitHub App, and GitHub PAT
  credential issuance.
- Unsafe local auth file schema for GitHub App private keys and GitHub PATs,
  with strict Unix file permission checks.
- Unsafe local auth secret source resolution for GitHub App private keys and
  GitHub PATs, without provider calls or credential injection.
- GitHub App installation token issuance for allowed `heim exec` requests, with
  process-scoped `GH_TOKEN` and `GITHUB_TOKEN` environment injection.
- GitHub PAT credential issuance for allowed `heim exec` requests, with
  process-scoped `GH_TOKEN` and `GITHUB_TOKEN` environment injection.
- AWS STS AssumeRole credential issuance for allowed `heim exec` requests, with
  process-scoped AWS environment variable injection.
- `heim audit list` for reading local audit JSONL events from the default log
  file or an explicit file.
- Minimal `cargo-deny` policy for dependency license, advisory, and source
  checks, wired into GitHub Actions.

### Changed

- Allowed additional permissive dependency licenses required by the GitHub App
  provider HTTP, TLS, and JWT stack.
- Added the official AWS SDK crates required by the AWS STS provider.

### Fixed

- Validate AWS STS AssumeRole durations against AWS API bounds before issuing
  provider requests.
