# Local Daemon

`heimd` is the local daemon boundary for long-lived approval workflows. It
receives asynchronous decisions from transports such as Slack Socket Mode.

The current daemon implements Slack Socket Mode dispatch and a local JSONL IPC
protocol for health checks and in-memory approval sessions:

```bash
heimd doctor
heimd serve
heimd ping
```

On Unix platforms, `heimd serve` binds a Unix socket. `heimd ping` connects to
that socket, sends a JSONL `ping` request, and expects a JSONL `pong` response.

Default socket path:

- Linux with `XDG_RUNTIME_DIR`: `$XDG_RUNTIME_DIR/heim/heimd.sock`
- Other platforms: the Heim config directory with `heimd.sock`

Windows named pipe support is intentionally deferred. The daemon path and IPC
message model are kept separate so Windows support can be added without
changing approval request semantics.

## Protocol

Ping request:

```json
{"type":"ping"}
```

Ping response:

```json
{"type":"pong"}
```

## Approval Sessions

`heim-approvals` defines the runtime approval session model used by daemon IPC.
A session wraps a session id, one approval request, an optional expiration
timestamp, and a status.

The daemon stores approval sessions in memory for the lifetime of the process.
It supports:

- create a pending approval session from a JIT approval request
- get an existing approval session
- wait for a pending approval session to resolve
- resolve a session with approve, deny, or approve-with-option

`heim exec` uses this boundary for JIT grants. It creates a daemon session for
each approval request, then waits for the current session status to resolve.
Approved and approve-with-option sessions allow the command to run. Denied,
expired, timed-out, unavailable, and wait-timeout sessions fail closed.

Create request:

```json
{"type":"approval_create","session_id":"session-1","request":{"request_id":"request-1","transport":"slack","grants":[{"name":"aws.prod-readonly","provider":"aws_prod"}],"requester":"codex","command":["aws","sts","get-caller-identity"],"cwd":"/workspace","git":null,"options":[{"id":"15m","label":"Approve 15m"}]},"expires_at":"2026-05-24T12:15:00Z"}
```

Create response:

```json
{"type":"approval_created","session":{"id":"session-1","request":{"request_id":"request-1","transport":"slack","grants":[{"name":"aws.prod-readonly","provider":"aws_prod"}],"requester":"codex","command":["aws","sts","get-caller-identity"],"cwd":"/workspace","git":null,"options":[{"id":"15m","label":"Approve 15m"}]},"expires_at":"2026-05-24T12:15:00Z","status":{"type":"pending"}}}
```

Get request:

```json
{"type":"approval_get","session_id":"session-1"}
```

Wait request:

```json
{"type":"approval_wait","session_id":"session-1","timeout_ms":300000}
```

Wait response:

```json
{"type":"approval_waited","session":{"id":"session-1","request":{"request_id":"request-1","transport":"slack","grants":[{"name":"aws.prod-readonly","provider":"aws_prod"}],"requester":"codex","command":["aws","sts","get-caller-identity"],"cwd":"/workspace","git":null,"options":[{"id":"15m","label":"Approve 15m"}]},"expires_at":"2026-05-24T12:15:00Z","status":{"type":"approved_with_option","decision":{"approver":"alice","decided_at":"2026-05-24T12:00:00Z"},"option":{"id":"15m","label":"Approve 15m"}}}}
```

Decision request:

```json
{"type":"approval_decide","session_id":"session-1","decision":{"type":"approved_with_option","decision":{"approver":"alice","decided_at":"2026-05-24T12:00:00Z"},"option":{"id":"15m","label":"Approve 15m"}}}
```

Decision response:

```json
{"type":"approval_decided","session":{"id":"session-1","request":{"request_id":"request-1","transport":"slack","grants":[{"name":"aws.prod-readonly","provider":"aws_prod"}],"requester":"codex","command":["aws","sts","get-caller-identity"],"cwd":"/workspace","git":null,"options":[{"id":"15m","label":"Approve 15m"}]},"expires_at":"2026-05-24T12:15:00Z","status":{"type":"approved_with_option","decision":{"approver":"alice","decided_at":"2026-05-24T12:00:00Z"},"option":{"id":"15m","label":"Approve 15m"}}}}
```

Functional errors are returned as JSON responses:

```json
{"type":"error","message":"approval session missing not found"}
```

Persistent session storage is intentionally deferred. Other asynchronous
transports can build on this session boundary without changing the core
approval request and decision schema.
