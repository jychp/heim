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
bot_token = { auth = "slack_bot_token" }
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

## Session

An approval session is the runtime object that connects one approval request to
one eventual decision. It contains:

- session id
- approval request
- optional expiration timestamp
- status

Session status starts as `pending`. A session can resolve to `approved`,
`approved_with_option`, `denied`, `timed_out`, or `expired`.

The session model validates decisions before applying them. In particular,
`approved_with_option` is accepted only when the selected option id exists on
the original request. Once a session is resolved, later decisions are rejected.

Requests, decisions, and sessions are serializable as JSON. Decision and status
enums use a `type` field with snake-case values such as
`approved_with_option`, `denied`, or `expired`. The approval transport name is
serialized as the configured transport string, such as `slack`.

This prepares the daemon workflow without making a transport-specific storage
choice yet:

1. `heim exec` creates an approval request for a JIT policy decision.
2. `heimd` creates a pending approval session.
3. An approval transport presents the request to an approver.
4. The transport sends back approve, deny, or approve-with-option.
5. `heimd` resolves the session and `heim exec` applies the decision.

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
bot_token = { auth = "slack_bot_token" }
options = ["15m", "60m"]
```

Slack is the first planned v0 transport. The contract intentionally does not
encode Slack-only fields in the common request or decision types.

Slack secrets live in `.auth.json`, not `config.toml`:

```json
{
  "slack_bot_token": {
    "type": "slack_bot_token",
    "token": "xoxb-redacted"
  }
}
```

`heim exec` now dispatches JIT approval requests through the configured
transport boundary. The built-in Slack provider validates the configured
channel and bot token reference, then fails closed until the Slack API flow is
implemented.

## Current Limitations

`heim exec` still fails closed with the default runtime when a grant requires
JIT approval because the built-in Slack provider does not call the Slack API
yet. Slack API calls and real approval timeouts are intentionally deferred.
