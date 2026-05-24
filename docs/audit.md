# Audit Model

Heim audit events describe local security-relevant decisions and credential
issuance metadata. The current implementation defines the typed event model in
`heim-audit` and can append those events to a local JSONL file. It does not
expose `heim audit` or emit events from `heim exec` yet.

## Event Scope

An audit event records the local request context that future approval,
provider, and execution paths will need:

- request ID
- timestamp
- requester binary
- wrapped command and arguments
- current working directory
- Git remote and branch when available
- requested grants and their providers
- decision outcome
- approval metadata when approval is required or completed
- credential issuance timestamps when credentials are issued
- policy version when known
- Heim version

The model supports requests with one or more grants because `heim exec` accepts
multiple grant names for one wrapped command.

## Decisions

The current decision model covers the expected v0 lifecycle:

- `Allow`
- `Deny`
- `RequireApproval`
- `Approved`
- `CredentialsIssued`
- `CommandCompleted`
- `Failed`

These are event labels only. They do not imply that approval calls, provider
calls, command execution, or CLI integration are implemented.

## Credential Metadata

Audit events must never contain credential secret values.

Allowed credential metadata includes:

- provider or credential kind, such as `aws-sts` or `github-app`
- environment variable names that received credentials
- temporary file labels or paths when temporary files are created later
- issuance and expiration timestamps

Forbidden values include:

- AWS secret access keys
- AWS session tokens
- GitHub tokens
- GitHub App private keys
- personal access tokens

This lets audit records explain what Heim issued without making audit storage a
secret store.

## Persistence

`heim-audit` provides an append-only JSONL sink. Each audit event is serialized
as one JSON object followed by one newline.

The default audit log file is:

- Linux: `$XDG_CONFIG_HOME/heim/logs/audit.jsonl` when `XDG_CONFIG_HOME` is set,
  otherwise `~/.config/heim/logs/audit.jsonl`
- macOS: `~/Library/Application Support/heim/logs/audit.jsonl`
- Windows: `%APPDATA%\heim\logs\audit.jsonl`

The sink creates the `logs` directory when it writes. Event emission from
`heim exec` and audit log viewing through `heim audit` are intentionally
deferred.
