use std::fmt;
use std::str::FromStr;

/// A binary name that may request a grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BinaryName(String);

impl BinaryName {
    pub fn new(value: impl Into<String>) -> Result<Self, BinaryNameError> {
        let value = value.into();
        validate_binary_name(&value).map_err(BinaryNameError)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BinaryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for BinaryName {
    type Err = BinaryNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryNameError(&'static str);

impl fmt::Display for BinaryNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for BinaryNameError {}

/// A rule for who may request a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequesterRule {
    Any,
    Binary(BinaryName),
}

impl RequesterRule {
    pub fn binary(value: impl Into<String>) -> Result<Self, BinaryNameError> {
        BinaryName::new(value).map(Self::Binary)
    }

    pub fn matches_binary(&self, binary: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Binary(expected) => expected.as_str() == binary,
        }
    }
}

impl FromStr for RequesterRule {
    type Err = BinaryNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "*" {
            Ok(Self::Any)
        } else {
            Self::binary(value)
        }
    }
}

fn validate_binary_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("binary name cannot be empty");
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(
            "binary name may only contain ASCII letters, digits, dots, hyphens, and underscores",
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::RequesterRule;

    #[test]
    fn requester_rule_can_allow_any_binary() {
        let rule = RequesterRule::from_str("*").expect("wildcard requester");

        assert!(rule.matches_binary("codex"));
        assert!(rule.matches_binary("claude-code"));
    }

    #[test]
    fn requester_rule_can_limit_to_one_binary() {
        let rule = RequesterRule::from_str("codex").expect("binary requester");

        assert!(rule.matches_binary("codex"));
        assert!(!rule.matches_binary("claude-code"));
    }
}
