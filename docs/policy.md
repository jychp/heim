# Policy Model

Heim policy describes which temporary credential grants can be requested, who
may request them, which commands may run with them, and how approval is decided.

The policy loader validates TOML policy documents and converts grants into the
typed core model. The policy engine can evaluate one local grant request and
return `allow`, `deny`, or `require_approval`.

```bash
heim policy validate
heim policy check aws.prod-readonly --requester codex -- aws sts get-caller-identity
heim exec aws.prod-readonly -- aws sts get-caller-identity
```

## Policy Directory

Heim loads policies from the platform config directory by default:

- Linux: `$XDG_CONFIG_HOME/heim/policies` when `XDG_CONFIG_HOME` is set,
  otherwise `~/.config/heim/policies`
- macOS: `~/Library/Application Support/heim/policies`
- Windows: `%APPDATA%\heim\policies`

The directory may contain one or more `.toml` files. Non-TOML files are
ignored.

All TOML files are merged before validation. Policy files contain grants only.
Approval transport configuration lives in `config.toml`.

```text
$XDG_CONFIG_HOME/heim/policies/
  aws.toml
  github.toml
```

Grant names must be unique across the full directory.

Files are loaded in sorted path order so diagnostics are stable. Policy meaning
must not depend on file order because all files are merged before validation.

For local testing, the CLI can still validate an explicit file or directory:

```bash
heim policy validate --file examples/policy.toml
heim policy validate --dir examples/policies
```

## Grants

A grant is a named temporary credential:

```text
aws.prod-readonly
github.drymn-pr-write
github.personal-readonly
```

Each grant points to a configured provider and defines local policy constraints.
Provider values reference provider names from `config.toml`.

```toml
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit:slack"
```

## Allow

A requester is the local binary asking Heim for a grant. The v0 model supports
binary-name rules and an explicit wildcard.

```toml
allow = ["codex", "claude-code", "*"]
```

`*` means any requester binary may ask for the grant, subject to the rest of the
grant policy.

For `heim policy check`, the requester is provided explicitly with
`--requester`. For `heim exec`, the requester is inferred from the parent
process that invoked the `heim` binary. This models the tool asking Heim for a
grant, rather than the wrapped command that would receive credentials later.

## Commands

Command rules constrain which wrapped command may receive credentials from the
grant.

```toml
commands = ["aws *", "gh pr view *"]
```

The current wildcard model is intentionally small:

- `*` must be a full command token.
- A final `*` matches the rest of the command.
- A middle `*` matches exactly one argument.
- Partial wildcards such as `s3*` are not valid.

For example, `aws *` matches `aws`, `aws s3 ls`, and `aws sts get-caller-identity`.

## Approval

Approval has two modes.

`grant` means policy grants access directly when requester and command rules
match.

```toml
approval = "grant"
```

`jit` means Heim must request approval at execution time through a configured
transport.

```toml
approval = "jit:slack"
```

The transport name references an approval transport in `config.toml`.

```toml
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
bot_token = { auth = "slack_bot_token" }
options = ["15m", "60m"]
```

Transport configuration is intentionally separate from grants so Slack channel
settings and auth references do not live in policy files. Slack secret values
live in `.auth.json`.

`options` is optional. When present, each value becomes an approval option
available to the transport. Heim maps `15m` to a default label of `Approve 15m`.

The approval runtime contract is transport-neutral. Slack is the first planned
v0 transport, but future transports can implement the same request and decision
model without changing grant policy syntax.

## Evaluation

`heim policy check` evaluates one grant request without executing the command:

```bash
heim policy check github.personal-readonly --requester gh -- gh pr view 42
```

The decision is based on:

- the named grant
- the requester binary
- the command rule match
- the grant approval mode

If the grant uses `approval = "grant"` and the requester and command match, the
decision is `allow`.

If the grant uses `approval = "jit:slack"` and the requester and command match,
the decision is `require_approval` with the configured transport.

If the grant is unknown, the requester does not match, or the command does not
match, the decision is `deny`.

This is still local policy evaluation only. Heim does not contact Slack, issue
provider credentials, write audit events, or spawn child processes in this path.

## Exec Preflight

`heim exec` evaluates every requested grant against the loaded policy before any
future approval or credential issuance can happen:

```bash
heim exec aws.prod-readonly github.drymn-pr-write -- claude-code
```

The same policy source options are available for local testing:

```bash
heim exec --file examples/policy.toml github.personal-readonly -- gh pr view 42
heim exec --dir examples/policies aws.prod-readonly -- aws sts get-caller-identity
```

When every requested grant is allowed directly by policy, Heim resolves the
configured providers, injects supported credentials into the child process, and
returns the command exit code. The current provider issuer supports
`aws_sts`, `github_app`, and `github_pat`. AWS STS grants inject
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and
configured region variables. GitHub grants map the issued token to `GH_TOKEN`
and `GITHUB_TOKEN`.

Injected variables override same-named parent environment variables for the
wrapped command only.

When any requested grant requires approval, Heim loads config, validates the
referenced approval transport, builds one approval request per transport, and
creates daemon approval sessions. Approved decisions continue to credential
issuance and command execution. Denied, timed-out, unavailable, wait-timeout,
or invalid approval decisions fail closed and do not start the wrapped command.
Denied policy requests return the policy denial exit code and do not start the
wrapped command.

During preflight, Heim also builds a local execution context:

- requested grant names
- inferred requester binary
- wrapped command and arguments
- current working directory
- Git remote and branch when the command is run inside a Git repository

This context feeds current audit events and prepared approval requests, and is
intended to feed future provider requests. Heim does not send it to Slack or
contact AWS yet. Git metadata detection is best-effort; Heim continues without
it when `git` is unavailable or the current directory is not a Git repository.
