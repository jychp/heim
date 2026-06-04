# Local Daemon

`heimd` is the local daemon boundary for long-lived approval workflows. It is
required for future transports that need to receive asynchronous decisions, such
as Slack Socket Mode.

The current daemon implements a local JSONL IPC protocol for health checks and
in-memory approval sessions:

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
- resolve a session with approve, deny, or approve-with-option

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
{"type":"error","message":"approval session missing was not found"}
```

`approval_wait` and persistent session storage are intentionally deferred.
Slack Socket Mode and other asynchronous transports can build on this session
boundary without changing the core approval request and decision schema.
