use std::fmt;
use std::str::FromStr;

use crate::{ApprovalPolicy, CommandRule, RequesterRule};

/// A named capability that Heim can issue temporarily.
///
/// Examples include `aws.prod-readonly` and `github.drymn-pr-write`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantName(String);

impl GrantName {
    pub fn new(value: impl Into<String>) -> Result<Self, GrantNameError> {
        let value = value.into();
        validate_dotted_identifier(&value).map_err(GrantNameError)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GrantName {
    type Err = GrantNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantNameError(&'static str);

impl fmt::Display for GrantNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for GrantNameError {}

/// A configured provider reference used by a grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderName(String);

impl ProviderName {
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderNameError> {
        let value = value.into();
        validate_dotted_identifier(&value).map_err(ProviderNameError)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ProviderName {
    type Err = ProviderNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderNameError(&'static str);

impl fmt::Display for ProviderNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ProviderNameError {}

/// Policy attached to a named grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPolicy {
    pub name: GrantName,
    pub provider: ProviderName,
    pub requesters: Vec<RequesterRule>,
    pub commands: Vec<CommandRule>,
    pub approval: ApprovalPolicy,
}

impl GrantPolicy {
    pub fn new(
        name: GrantName,
        provider: ProviderName,
        requesters: Vec<RequesterRule>,
        commands: Vec<CommandRule>,
        approval: ApprovalPolicy,
    ) -> Result<Self, GrantPolicyError> {
        if requesters.is_empty() {
            return Err(GrantPolicyError::MissingRequesters);
        }

        if commands.is_empty() {
            return Err(GrantPolicyError::MissingCommands);
        }

        Ok(Self {
            name,
            provider,
            requesters,
            commands,
            approval,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantPolicyError {
    MissingRequesters,
    MissingCommands,
}

impl fmt::Display for GrantPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequesters => formatter.write_str("grant policy must list requesters"),
            Self::MissingCommands => formatter.write_str("grant policy must list commands"),
        }
    }
}

impl std::error::Error for GrantPolicyError {}

pub(crate) fn validate_dotted_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("identifier cannot be empty");
    }

    if value.starts_with('.') || value.ends_with('.') {
        return Err("identifier cannot start or end with a dot");
    }

    if value.contains("..") {
        return Err("identifier cannot contain empty segments");
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(
            "identifier may only contain ASCII letters, digits, dots, hyphens, and underscores",
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        ApprovalPolicy, ApprovalTransportName, CommandRule, GrantPolicy, RequesterRule,
        grant::{GrantName, GrantPolicyError, ProviderName},
    };

    #[test]
    fn grant_names_accept_project_examples() {
        for value in [
            "aws.prod-readonly",
            "github.drymn-pr-write",
            "github.personal-readonly",
        ] {
            let grant = GrantName::new(value).expect("valid grant name");
            assert_eq!(grant.as_str(), value);
        }
    }

    #[test]
    fn grant_names_reject_ambiguous_values() {
        for value in ["", ".aws", "aws.", "aws..prod", "aws prod", "aws/prod"] {
            assert!(GrantName::new(value).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn provider_names_use_same_identifier_rules() {
        let provider = ProviderName::new("github.drymn").expect("valid provider");

        assert_eq!(provider.as_str(), "github.drymn");
        assert!(ProviderName::new("github drymn").is_err());
    }

    #[test]
    fn grant_policy_requires_requesters_and_commands() {
        let name = GrantName::new("aws.prod-readonly").expect("valid grant");
        let provider = ProviderName::new("aws.prod").expect("valid provider");
        let approval = ApprovalPolicy::grant();

        assert_eq!(
            GrantPolicy::new(
                name.clone(),
                provider.clone(),
                Vec::new(),
                vec![CommandRule::new("aws *").expect("valid command")],
                approval.clone(),
            )
            .expect_err("missing requesters"),
            GrantPolicyError::MissingRequesters
        );

        assert_eq!(
            GrantPolicy::new(
                name,
                provider,
                vec![RequesterRule::Any],
                Vec::new(),
                approval,
            )
            .expect_err("missing commands"),
            GrantPolicyError::MissingCommands
        );
    }

    #[test]
    fn grant_policy_can_model_jit_slack_approval() {
        let policy = GrantPolicy::new(
            GrantName::new("aws.prod-readonly").expect("valid grant"),
            ProviderName::new("aws.prod").expect("valid provider"),
            vec![
                RequesterRule::binary("codex").expect("valid requester"),
                RequesterRule::Any,
            ],
            vec![CommandRule::new("aws *").expect("valid command")],
            ApprovalPolicy::jit(ApprovalTransportName::new("slack").expect("valid transport")),
        )
        .expect("valid policy");

        assert_eq!(policy.name.as_str(), "aws.prod-readonly");
        assert_eq!(policy.provider.as_str(), "aws.prod");
        assert!(
            policy
                .requesters
                .iter()
                .any(|rule| rule.matches_binary("codex"))
        );
        assert!(
            policy
                .commands
                .iter()
                .any(|rule| rule.matches(["aws", "s3", "ls"]))
        );
    }
}
