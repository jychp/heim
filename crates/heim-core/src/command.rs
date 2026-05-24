use std::fmt;
use std::str::FromStr;

/// A command pattern allowed for a grant.
///
/// `*` matches one argument when used in the middle of a pattern. A final `*`
/// matches the rest of the command, which supports rules such as `aws *`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRule {
    pattern: String,
    tokens: Vec<CommandToken>,
}

impl CommandRule {
    pub fn new(pattern: impl Into<String>) -> Result<Self, CommandRuleError> {
        let pattern = pattern.into();
        let tokens = parse_pattern(&pattern)?;

        Ok(Self { pattern, tokens })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn matches<I, S>(&self, argv: I) -> bool
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let argv = argv
            .into_iter()
            .map(|value| value.as_ref().to_owned())
            .collect::<Vec<_>>();

        let trailing_rest = matches!(self.tokens.last(), Some(CommandToken::Any));
        if !trailing_rest && self.tokens.len() != argv.len() {
            return false;
        }

        if trailing_rest && argv.len() < self.tokens.len() - 1 {
            return false;
        }

        for (index, token) in self.tokens.iter().enumerate() {
            if trailing_rest && index == self.tokens.len() - 1 {
                return true;
            }

            let Some(argument) = argv.get(index) else {
                return false;
            };

            match token {
                CommandToken::Literal(expected) if expected != argument => return false,
                CommandToken::Literal(_) | CommandToken::Any => {}
            }
        }

        true
    }
}

impl FromStr for CommandRule {
    type Err = CommandRuleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandToken {
    Literal(String),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRuleError(&'static str);

impl fmt::Display for CommandRuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for CommandRuleError {}

fn parse_pattern(pattern: &str) -> Result<Vec<CommandToken>, CommandRuleError> {
    let tokens = pattern.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err(CommandRuleError("command rule cannot be empty"));
    }

    tokens
        .into_iter()
        .map(|token| {
            if token == "*" {
                Ok(CommandToken::Any)
            } else if token.contains('*') {
                Err(CommandRuleError(
                    "wildcards must be written as a full command token",
                ))
            } else {
                Ok(CommandToken::Literal(token.to_owned()))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::CommandRule;

    #[test]
    fn command_rule_matches_exact_command() {
        let rule = CommandRule::new("gh pr create").expect("valid rule");

        assert!(rule.matches(["gh", "pr", "create"]));
        assert!(!rule.matches(["gh", "pr", "view"]));
        assert!(!rule.matches(["gh", "pr", "create", "--draft"]));
    }

    #[test]
    fn command_rule_supports_trailing_wildcard() {
        let rule = CommandRule::new("aws *").expect("valid rule");

        assert!(rule.matches(["aws"]));
        assert!(rule.matches(["aws", "s3", "ls"]));
        assert!(!rule.matches(["gh", "pr", "create"]));
    }

    #[test]
    fn command_rule_supports_middle_wildcard_for_one_argument() {
        let rule = CommandRule::new("gh pr * --repo drymn/backend").expect("valid rule");

        assert!(rule.matches(["gh", "pr", "view", "--repo", "drymn/backend"]));
        assert!(!rule.matches(["gh", "pr", "view", "12", "--repo", "drymn/backend"]));
    }

    #[test]
    fn command_rule_rejects_partial_wildcards() {
        assert!(CommandRule::new("aws s3*").is_err());
    }
}
