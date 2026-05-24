//! Policy evaluation crate for Heim.
//!
//! This crate evaluates validated grant policies. It does not load config,
//! request approvals, issue credentials, or execute commands.

use std::fmt;

use heim_core::{ApprovalMode, ApprovalTransportName, GrantPolicy};

/// A request to evaluate against loaded grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub grant: String,
    pub requester: String,
    pub command: Vec<String>,
}

impl PolicyRequest {
    pub fn new(
        grant: impl Into<String>,
        requester: impl Into<String>,
        command: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            grant: grant.into(),
            requester: requester.into(),
            command: command.into_iter().map(Into::into).collect(),
        }
    }
}

/// Result of evaluating a policy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: DenyReason },
    RequireApproval { transport: ApprovalTransportName },
}

impl PolicyDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::RequireApproval { .. })
    }
}

/// Reason a request was denied before approval or credential issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    UnknownGrant { grant: String },
    RequesterNotAllowed { requester: String },
    CommandNotAllowed { command: Vec<String> },
}

impl fmt::Display for DenyReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownGrant { grant } => write!(formatter, "unknown grant {grant}"),
            Self::RequesterNotAllowed { requester } => {
                write!(formatter, "requester {requester} is not allowed")
            }
            Self::CommandNotAllowed { command } => {
                write!(formatter, "command {} is not allowed", command.join(" "))
            }
        }
    }
}

/// Evaluate one grant request against the loaded grant list.
pub fn evaluate_policy(grants: &[GrantPolicy], request: &PolicyRequest) -> PolicyDecision {
    let Some(grant) = grants
        .iter()
        .find(|candidate| candidate.name.as_str() == request.grant)
    else {
        return PolicyDecision::Deny {
            reason: DenyReason::UnknownGrant {
                grant: request.grant.clone(),
            },
        };
    };

    if !grant
        .requesters
        .iter()
        .any(|rule| rule.matches_binary(&request.requester))
    {
        return PolicyDecision::Deny {
            reason: DenyReason::RequesterNotAllowed {
                requester: request.requester.clone(),
            },
        };
    }

    if !grant
        .commands
        .iter()
        .any(|rule| rule.matches(request.command.iter()))
    {
        return PolicyDecision::Deny {
            reason: DenyReason::CommandNotAllowed {
                command: request.command.clone(),
            },
        };
    }

    match &grant.approval.mode {
        ApprovalMode::Grant => PolicyDecision::Allow,
        ApprovalMode::Jit { transport } => PolicyDecision::RequireApproval {
            transport: transport.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use heim_core::{
        ApprovalPolicy, ApprovalTransportName, CommandRule, GrantName, GrantPolicy, ProviderName,
        RequesterRule,
    };

    use super::{DenyReason, PolicyDecision, PolicyRequest, evaluate_policy};

    #[test]
    fn allows_grant_mode_when_requester_and_command_match() {
        let grants = vec![grant_policy(
            "github.personal-readonly",
            vec!["gh"],
            vec!["gh pr view *"],
            ApprovalPolicy::grant(),
        )];

        let decision = evaluate_policy(
            &grants,
            &PolicyRequest::new("github.personal-readonly", "gh", ["gh", "pr", "view", "42"]),
        );

        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn requires_approval_for_jit_grant() {
        let transport = ApprovalTransportName::new("slack").expect("valid transport");
        let grants = vec![grant_policy(
            "aws.prod-readonly",
            vec!["codex"],
            vec!["aws *"],
            ApprovalPolicy::jit(transport.clone()),
        )];

        let decision = evaluate_policy(
            &grants,
            &PolicyRequest::new(
                "aws.prod-readonly",
                "codex",
                ["aws", "sts", "get-caller-identity"],
            ),
        );

        assert_eq!(decision, PolicyDecision::RequireApproval { transport });
    }

    #[test]
    fn denies_unknown_grant() {
        let decision = evaluate_policy(
            &[],
            &PolicyRequest::new("aws.prod-readonly", "codex", ["aws", "s3", "ls"]),
        );

        assert_eq!(
            decision,
            PolicyDecision::Deny {
                reason: DenyReason::UnknownGrant {
                    grant: "aws.prod-readonly".to_owned()
                }
            }
        );
    }

    #[test]
    fn denies_requester_mismatch() {
        let grants = vec![grant_policy(
            "aws.prod-readonly",
            vec!["codex"],
            vec!["aws *"],
            ApprovalPolicy::grant(),
        )];

        let decision = evaluate_policy(
            &grants,
            &PolicyRequest::new("aws.prod-readonly", "gh", ["aws", "s3", "ls"]),
        );

        assert_eq!(
            decision,
            PolicyDecision::Deny {
                reason: DenyReason::RequesterNotAllowed {
                    requester: "gh".to_owned()
                }
            }
        );
    }

    #[test]
    fn denies_command_mismatch() {
        let grants = vec![grant_policy(
            "aws.prod-readonly",
            vec!["codex"],
            vec!["aws s3 ls"],
            ApprovalPolicy::grant(),
        )];

        let decision = evaluate_policy(
            &grants,
            &PolicyRequest::new(
                "aws.prod-readonly",
                "codex",
                ["aws", "sts", "get-caller-identity"],
            ),
        );

        assert_eq!(
            decision,
            PolicyDecision::Deny {
                reason: DenyReason::CommandNotAllowed {
                    command: vec![
                        "aws".to_owned(),
                        "sts".to_owned(),
                        "get-caller-identity".to_owned()
                    ]
                }
            }
        );
    }

    fn grant_policy(
        name: &str,
        requesters: Vec<&str>,
        commands: Vec<&str>,
        approval: ApprovalPolicy,
    ) -> GrantPolicy {
        GrantPolicy::new(
            GrantName::new(name).expect("valid grant"),
            ProviderName::new("provider.test").expect("valid provider"),
            requesters
                .into_iter()
                .map(|requester| requester.parse::<RequesterRule>().expect("valid requester"))
                .collect(),
            commands
                .into_iter()
                .map(|command| CommandRule::new(command).expect("valid command"))
                .collect(),
            approval,
        )
        .expect("valid policy")
    }
}
