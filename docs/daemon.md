# Local Daemon

`heimd` is the local daemon boundary for long-lived approval workflows. It is
required for future transports that need to receive asynchronous decisions, such
as Slack Socket Mode.

The current daemon implements a minimal local IPC health protocol:

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

Request:

```json
{"type":"ping"}
```

Response:

```json
{"type":"pong"}
```

Future approval messages will extend this protocol without changing the
transport-neutral approval request and decision contract.
