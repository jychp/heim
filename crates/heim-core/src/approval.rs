use std::fmt;
use std::str::FromStr;

use crate::grant::validate_dotted_identifier;

/// Approval behavior for a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPolicy {
    pub mode: ApprovalMode,
}

impl ApprovalPolicy {
    pub fn grant() -> Self {
        Self {
            mode: ApprovalMode::Grant,
        }
    }

    pub fn jit(transport: ApprovalTransportName) -> Self {
        Self {
            mode: ApprovalMode::Jit { transport },
        }
    }
}

/// Whether a grant is pre-authorized by policy or requires JIT approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalMode {
    Grant,
    Jit { transport: ApprovalTransportName },
}

/// Name of a configured approval transport, such as `slack`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApprovalTransportName(String);

impl ApprovalTransportName {
    pub fn new(value: impl Into<String>) -> Result<Self, ApprovalTransportNameError> {
        let value = value.into();
        validate_dotted_identifier(&value).map_err(ApprovalTransportNameError)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApprovalTransportName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ApprovalTransportName {
    type Err = ApprovalTransportNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTransportNameError(&'static str);

impl fmt::Display for ApprovalTransportNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ApprovalTransportNameError {}

#[cfg(test)]
mod tests {
    use super::{ApprovalMode, ApprovalPolicy, ApprovalTransportName};

    #[test]
    fn approval_policy_supports_grant_mode() {
        assert_eq!(ApprovalPolicy::grant().mode, ApprovalMode::Grant);
    }

    #[test]
    fn approval_policy_supports_jit_transport() {
        let transport = ApprovalTransportName::new("slack").expect("valid transport");

        assert_eq!(
            ApprovalPolicy::jit(transport.clone()).mode,
            ApprovalMode::Jit { transport }
        );
    }
}
