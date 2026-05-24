# Policy Model

Heim policy describes which temporary credential grants can be requested, who
may request them, which commands may run with them, and how approval is decided.

The policy loader validates TOML policy documents and converts grants into the
typed core model. Runtime policy evaluation is not implemented yet.

```bash
heim policy validate --file examples/policy.toml
```

## Grants

A grant is a named temporary credential:

```text
aws.prod-readonly
github.drymn-pr-write
github.personal-readonly
```

Each grant points to a configured provider and defines local policy constraints.

```toml
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
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

The transport name references a separate transport configuration.

```toml
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
```

Transport configuration is intentionally separate from grants so Slack can be
configured once and reused by multiple grants.
