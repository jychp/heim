# Approval Contract

Heim approvals are modeled as transport-neutral requests and decisions. A
transport can be Slack, a future CLI prompt, a ticketing system, or another
approval backend.

The current implementation defines the contract in `heim-approvals`. `heim
exec` can prepare approval requests from a JIT policy decision and configured
transport options, then apply a decision returned by an approval provider. It
does not call Slack or any external approval system yet.

## Request

An approval request contains the context a human approver needs:

- request id
- approval transport name
- requested grants and their configured providers
- requester binary
- wrapped command and arguments
- current working directory
- Git remote and branch when detected
- provider-configured approval options when available

This mirrors the local context already collected by `heim exec` for preflight,
audit, and future provider requests.

`heim-approvals` also exposes a request builder for callers that already have
this context. The builder validates that a request has at least one grant, a
request id, requester, command, and current working directory before it can be
sent to a transport.

Approval options are configured by the approval provider or transport
integration. `config.toml` uses the compact form:

```toml
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
options = ["15m", "60m"]
```

The config loader maps each option to the common request model:

```text
id = "15m"
label = "Approve 15m"
```

Duration buttons such as `15m` or `60m` are the expected v0 Slack use case, but
the contract does not require options to be durations.

## Decision

An approval provider returns a transport-neutral decision:

- `approved` with approver and decision timestamp metadata
- `approved_with_option` with approver, decision timestamp metadata, and the
  selected option
- `denied` with approver and decision timestamp metadata
- `timed_out`

Transport failures are separate errors. The default product posture remains
fail closed: when approval cannot be obtained, Heim must not start the wrapped
command or issue credentials.

`heim exec` currently handles these decisions:

- `approved` continues to credential issuance and command execution
- `approved_with_option` continues when the selected option was configured for
  the transport
- `denied` fails closed
- `timed_out` fails closed

Approval provider errors also fail closed.
For `approved_with_option`, the selected option id must match one of the
options configured for the transport.

## Transports

Policy references transports by name:

```toml
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit:slack"
```

The transport itself lives in `config.toml`:

```toml
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
options = ["15m", "60m"]
```

Slack is the first planned v0 transport. The contract intentionally does not
encode Slack-only fields in the common request or decision types.

## Current Limitations

`heim exec` still fails closed with the default runtime when a grant requires
JIT approval because no built-in approval transport dispatch is implemented
yet. Slack API calls and real approval timeouts are intentionally deferred.
