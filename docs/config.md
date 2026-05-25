# Configuration

Heim configuration describes provider metadata, approval transports, and
optional unsafe local auth entries. The current implementation validates
config, provider, approval transport, and unsafe local auth file schemas. It
can also prepare JIT approval requests from configured transports, resolve a
GitHub PAT from unsafe local auth, and inject it into allowed `heim exec` child
processes. It does not call AWS, call GitHub, mint GitHub App tokens, call
Slack, or request approvals yet.

## Config File

The default config file is:

- Linux: `$XDG_CONFIG_HOME/heim/config.toml` when `XDG_CONFIG_HOME` is set,
  otherwise `~/.config/heim/config.toml`
- macOS: `~/Library/Application Support/heim/config.toml`
- Windows: `%APPDATA%\heim\config.toml`

`config.toml` contains non-secret provider metadata.

```toml
[providers.aws_prod]
type = "aws_sts"
role_arn = "arn:aws:iam::123456789012:role/ProdReadonly"
region = "eu-west-1"
duration = "15m"
source_profile = "prod"

[providers.github_drymn]
type = "github_app"
app_id = 123456
installation_id = 987654
private_key = { auth = "github_drymn_app_private_key" }
repositories = ["drymn/backend"]

[providers.github_personal]
type = "github_pat"
token = { auth = "github_personal_pat" }

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
options = ["15m", "60m"]
```

Provider names may contain ASCII letters, digits, hyphens, and underscores.
Policy grant `provider` values should reference these provider names.

The default config file can be validated with:

```bash
heim config validate
```

An explicit config file can be validated with:

```bash
heim config validate --file examples/config.toml
```

Policy provider and approval transport references can also be checked against a
config file:

```bash
heim config validate --file examples/config.toml --policy-file examples/policy.toml
```

`heim exec` loads config when policy allows a command to run or when policy
requires JIT approval. For local testing, pass an explicit config file:

```bash
heim exec --file examples/policy.toml --config-file examples/config.toml github.personal-readonly -- gh pr view 42
```

## Approval Transports

Approval transports are configured in `config.toml`, not policy files. Policy
grants reference these transports by name with values such as `approval =
"jit:slack"`.

`slack` transport config describes a future Slack approval provider.

Required:

- `channel`

Optional:

- `options`

Each option id is mapped to a default approval label. For example, `15m`
becomes `Approve 15m`.

## Providers

`aws_sts` config describes a future AWS STS AssumeRole provider.

Required:

- `role_arn`

Optional:

- `region`
- `duration`
- `source_profile`
- `session_name`
- `external_id`

`github_app` config describes a future GitHub App installation token provider.

Required:

- `app_id`
- `installation_id`
- `private_key = { auth = "<entry>" }`

Optional:

- `repositories`

`github_pat` config describes a GitHub PAT provider. PATs are supported for
compatibility, but GitHub App installation tokens are preferred.

Required:

- `token = { auth = "<entry>" }`

## Unsafe Local Auth File

The unsafe local auth file is:

- Linux: `$XDG_CONFIG_HOME/heim/.auth.json` when `XDG_CONFIG_HOME` is set,
  otherwise `~/.config/heim/.auth.json`
- macOS: `~/Library/Application Support/heim/.auth.json`
- Windows: `%APPDATA%\heim\.auth.json`

This file stores secret values on disk. It is supported, but unsafe and should
be avoided for sensitive use when a better source is available. Prefer AWS SSO
or profiles for AWS, and prefer future OS keychain, 1Password, Vault, AWS
Secrets Manager, or Infisical integrations when they are implemented.

```json
{
  "github_drymn_app_private_key": {
    "type": "github_app_private_key",
    "pem": "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----\n"
  },
  "github_personal_pat": {
    "type": "github_pat",
    "token": "redacted"
  }
}
```

On Unix, Heim refuses to load `.auth.json` when group or other users can read
or write it. Use mode `0600`.

```bash
chmod 0600 ~/.config/heim/.auth.json
```

An explicit unsafe local auth file can be validated together with config:

```bash
heim config validate --file examples/config.toml --auth-file ~/.config/heim/.auth.json
```

Secret values from `.auth.json` must never be written to logs, audit events, or
error messages.

## Secret Source Resolution

The `heim-sources` crate can resolve unsafe local auth references from a
validated `.auth.json` file into typed secret material:

- GitHub App private keys
- GitHub PATs

It can also resolve the local secrets required by one configured provider:
GitHub App providers require a private key, GitHub PAT providers require a
token, and AWS STS providers require no unsafe local auth secret.

`heim exec` now uses this source boundary for `github_pat` providers when a
grant is allowed directly by policy. The GitHub PAT provider injects:

```text
GH_TOKEN
GITHUB_TOKEN
```

These variables are scoped to the child process. If either variable already
exists in the parent environment, Heim's issued value overrides it for the
wrapped command only.

GitHub App and AWS STS providers are configured and validated, but they cannot
issue credentials yet.

Resolved secrets redact their values in `Debug` output. Error messages include
auth entry names and secret types only, never secret values.
