//! Configuration loading for Heim.
//!
//! This crate validates policy documents and converts them into core grant
//! policy types. It does not evaluate policies or execute commands.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use heim_core::{
    ApprovalPolicy, ApprovalTransportName, CommandRule, GrantName, GrantPolicy, ProviderName,
    RequesterRule,
};
use serde::Deserialize;

/// A validated policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    pub grants: Vec<GrantPolicy>,
    pub approval_transports: Vec<ApprovalTransportName>,
}

/// Load and validate a TOML policy file.
pub fn load_policy_file(path: impl AsRef<Path>) -> Result<PolicyDocument, ConfigError> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;

    parse_policy_str(&contents)
}

/// Parse and validate a TOML policy document.
pub fn parse_policy_str(contents: &str) -> Result<PolicyDocument, ConfigError> {
    let raw: RawPolicyDocument = toml::from_str(contents).map_err(ConfigError::ParseToml)?;
    raw.try_into()
}

#[derive(Debug)]
pub enum ConfigError {
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    ParseToml(toml::de::Error),
    InvalidApprovalMode {
        grant: String,
        mode: String,
    },
    MissingGrants,
    DuplicateGrantName {
        grant: String,
    },
    MissingJitTransport {
        grant: String,
    },
    UnknownApprovalTransport {
        grant: String,
        transport: String,
    },
    InvalidApprovalTransportName {
        name: String,
        message: String,
    },
    InvalidGrantName {
        name: String,
        message: String,
    },
    InvalidProviderName {
        grant: String,
        provider: String,
        message: String,
    },
    InvalidRequester {
        grant: String,
        requester: String,
        message: String,
    },
    InvalidCommand {
        grant: String,
        command: String,
        message: String,
    },
    InvalidGrantPolicy {
        grant: String,
        message: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile { path, source } => {
                write!(formatter, "failed to read policy file {path}: {source}")
            }
            Self::ParseToml(error) => write!(formatter, "failed to parse policy TOML: {error}"),
            Self::InvalidApprovalMode { grant, mode } => {
                write!(formatter, "grant {grant} uses unknown approval mode {mode}")
            }
            Self::MissingGrants => formatter.write_str("policy must contain at least one grant"),
            Self::DuplicateGrantName { grant } => {
                write!(formatter, "policy contains duplicate grant {grant}")
            }
            Self::MissingJitTransport { grant } => {
                write!(
                    formatter,
                    "grant {grant} uses jit approval without a transport"
                )
            }
            Self::UnknownApprovalTransport { grant, transport } => write!(
                formatter,
                "grant {grant} references unknown approval transport {transport}"
            ),
            Self::InvalidApprovalTransportName { name, message } => write!(
                formatter,
                "approval transport {name} is not a valid name: {message}"
            ),
            Self::InvalidGrantName { name, message } => {
                write!(formatter, "grant {name} is not a valid name: {message}")
            }
            Self::InvalidProviderName {
                grant,
                provider,
                message,
            } => write!(
                formatter,
                "grant {grant} references invalid provider {provider}: {message}"
            ),
            Self::InvalidRequester {
                grant,
                requester,
                message,
            } => write!(
                formatter,
                "grant {grant} has invalid requester {requester}: {message}"
            ),
            Self::InvalidCommand {
                grant,
                command,
                message,
            } => write!(
                formatter,
                "grant {grant} has invalid command rule {command}: {message}"
            ),
            Self::InvalidGrantPolicy { grant, message } => {
                write!(formatter, "grant {grant} is invalid: {message}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } => Some(source),
            Self::ParseToml(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawPolicyDocument {
    #[serde(default)]
    grants: Vec<RawGrant>,
    #[serde(default)]
    approval_transports: BTreeMap<String, RawApprovalTransport>,
}

#[derive(Debug, Deserialize)]
struct RawGrant {
    name: String,
    provider: String,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    commands: Vec<String>,
    approval: String,
}

#[derive(Debug, Deserialize)]
struct RawApprovalTransport {
    #[serde(rename = "type")]
    transport_type: String,
}

impl TryFrom<RawPolicyDocument> for PolicyDocument {
    type Error = ConfigError;

    fn try_from(raw: RawPolicyDocument) -> Result<Self, Self::Error> {
        if raw.grants.is_empty() {
            return Err(ConfigError::MissingGrants);
        }

        let mut grant_names = BTreeSet::new();
        for grant in &raw.grants {
            if !grant_names.insert(grant.name.as_str()) {
                return Err(ConfigError::DuplicateGrantName {
                    grant: grant.name.clone(),
                });
            }
        }

        let approval_transports = raw
            .approval_transports
            .into_iter()
            .map(|(name, transport)| {
                let _transport_type = transport.transport_type;

                ApprovalTransportName::new(&name).map_err(|error| {
                    ConfigError::InvalidApprovalTransportName {
                        name,
                        message: error.to_string(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let grants = raw
            .grants
            .into_iter()
            .map(|raw_grant| convert_grant(raw_grant, &approval_transports))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            grants,
            approval_transports,
        })
    }
}

fn convert_grant(
    raw_grant: RawGrant,
    approval_transports: &[ApprovalTransportName],
) -> Result<GrantPolicy, ConfigError> {
    let raw_name = raw_grant.name;
    let name = GrantName::new(&raw_name).map_err(|error| ConfigError::InvalidGrantName {
        name: raw_name.clone(),
        message: error.to_string(),
    })?;

    let provider = ProviderName::new(&raw_grant.provider).map_err(|error| {
        ConfigError::InvalidProviderName {
            grant: raw_name.to_owned(),
            provider: raw_grant.provider.clone(),
            message: error.to_string(),
        }
    })?;

    let requesters = raw_grant
        .allow
        .into_iter()
        .map(|requester| {
            requester
                .parse()
                .map_err(
                    |error: heim_core::BinaryNameError| ConfigError::InvalidRequester {
                        grant: raw_name.clone(),
                        requester,
                        message: error.to_string(),
                    },
                )
        })
        .collect::<Result<Vec<RequesterRule>, _>>()?;

    let commands = raw_grant
        .commands
        .into_iter()
        .map(|command| {
            command
                .parse()
                .map_err(
                    |error: heim_core::CommandRuleError| ConfigError::InvalidCommand {
                        grant: raw_name.to_owned(),
                        command,
                        message: error.to_string(),
                    },
                )
        })
        .collect::<Result<Vec<CommandRule>, _>>()?;

    let approval = convert_approval(&raw_name, raw_grant.approval, approval_transports)?;

    GrantPolicy::new(name, provider, requesters, commands, approval).map_err(|error| {
        ConfigError::InvalidGrantPolicy {
            grant: raw_name.to_owned(),
            message: error.to_string(),
        }
    })
}

fn convert_approval(
    grant: &str,
    raw: String,
    approval_transports: &[ApprovalTransportName],
) -> Result<ApprovalPolicy, ConfigError> {
    if raw == "grant" {
        return Ok(ApprovalPolicy::grant());
    }

    if raw == "jit" {
        return Err(ConfigError::MissingJitTransport {
            grant: grant.to_owned(),
        });
    }

    if let Some(transport) = raw.strip_prefix("jit:") {
        if transport.is_empty() {
            return Err(ConfigError::MissingJitTransport {
                grant: grant.to_owned(),
            });
        }

        if !approval_transports
            .iter()
            .any(|candidate| candidate.as_str() == transport)
        {
            return Err(ConfigError::UnknownApprovalTransport {
                grant: grant.to_owned(),
                transport: transport.to_owned(),
            });
        }

        let transport = ApprovalTransportName::new(transport).map_err(|error| {
            ConfigError::InvalidApprovalTransportName {
                name: transport.to_owned(),
                message: error.to_string(),
            }
        })?;

        return Ok(ApprovalPolicy::jit(transport));
    }

    Err(ConfigError::InvalidApprovalMode {
        grant: grant.to_owned(),
        mode: raw,
    })
}

#[cfg(test)]
mod tests {
    use heim_core::ApprovalMode;

    use super::{ConfigError, parse_policy_str};

    const VALID_POLICY: &str = r##"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex", "*"]
commands = ["aws *"]
approval = "jit:slack"

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
"##;

    #[test]
    fn parses_valid_policy_into_core_grants() {
        let document = parse_policy_str(VALID_POLICY).expect("valid policy");

        assert_eq!(document.grants.len(), 1);
        assert_eq!(document.approval_transports.len(), 1);

        let grant = &document.grants[0];
        assert_eq!(grant.name.as_str(), "aws.prod-readonly");
        assert_eq!(grant.provider.as_str(), "aws.prod");
        assert_eq!(grant.requesters.len(), 2);
        assert_eq!(grant.commands.len(), 1);
        assert!(matches!(grant.approval.mode, ApprovalMode::Jit { .. }));
    }

    #[test]
    fn rejects_jit_policy_without_transport() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit"
"#,
        )
        .expect_err("missing jit transport");

        assert!(matches!(error, ConfigError::MissingJitTransport { .. }));
    }

    #[test]
    fn rejects_unknown_approval_transport() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit:slack"
"#,
        )
        .expect_err("unknown transport");

        assert!(matches!(
            error,
            ConfigError::UnknownApprovalTransport { .. }
        ));
    }

    #[test]
    fn rejects_missing_provider() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        )
        .expect_err("missing provider");

        assert!(matches!(error, ConfigError::ParseToml(_)));
    }

    #[test]
    fn rejects_empty_requesters() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = []
commands = ["aws *"]
approval = "grant"
"#,
        )
        .expect_err("missing requesters");

        assert!(matches!(error, ConfigError::InvalidGrantPolicy { .. }));
    }

    #[test]
    fn rejects_empty_commands() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex"]
approval = "grant"
"#,
        )
        .expect_err("missing commands");

        assert!(matches!(error, ConfigError::InvalidGrantPolicy { .. }));
    }

    #[test]
    fn rejects_invalid_command_wildcard() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex"]
commands = ["aws s3*"]
approval = "grant"
"#,
        )
        .expect_err("invalid command");

        assert!(matches!(error, ConfigError::InvalidCommand { .. }));
    }

    #[test]
    fn rejects_policy_without_grants() {
        let error = parse_policy_str(
            r##"
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
"##,
        )
        .expect_err("missing grants");

        assert!(matches!(error, ConfigError::MissingGrants));
    }

    #[test]
    fn rejects_duplicate_grant_names() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"

[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        )
        .expect_err("duplicate grant");

        assert!(matches!(error, ConfigError::DuplicateGrantName { .. }));
    }
}
