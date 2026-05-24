# Examples

Example configurations and workflows live here while the specification is
in progress.

- `policy.toml` shows the current grant policy format.

Validate the example policy:

```bash
heim policy validate --file examples/policy.toml
```

Evaluate a JIT grant:

```bash
heim policy check --file examples/policy.toml aws.prod-readonly --requester codex -- aws sts get-caller-identity
```

Evaluate a direct grant:

```bash
heim policy check --file examples/policy.toml github.personal-readonly --requester gh -- gh pr view 42
```

Evaluate a denied request:

```bash
heim policy check --file examples/policy.toml github.personal-readonly --requester codex -- gh pr view 42
```
