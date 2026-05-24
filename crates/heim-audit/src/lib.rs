//! Audit event model for Heim.
//!
//! This crate defines typed audit events only. It does not persist events to
//! JSONL, contact providers, or execute commands.

use std::path::PathBuf;

/// One local audit event for a Heim request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub request_id: String,
    pub timestamp: String,
    pub requester: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub git: Option<AuditGitContext>,
    pub grants: Vec<AuditGrant>,
    pub decision: AuditDecision,
    pub approval: Option<AuditApproval>,
    pub policy_version: Option<String>,
    pub heim_version: String,
}

impl AuditEvent {
    pub fn new(
        request_id: impl Into<String>,
        timestamp: impl Into<String>,
        requester: impl Into<String>,
        command: impl IntoIterator<Item = impl Into<String>>,
        cwd: PathBuf,
        heim_version: impl Into<String>,
        decision: AuditDecision,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            timestamp: timestamp.into(),
            requester: requester.into(),
            command: command.into_iter().map(Into::into).collect(),
            cwd,
            git: None,
            grants: Vec::new(),
            decision,
            approval: None,
            policy_version: None,
            heim_version: heim_version.into(),
        }
    }

    pub fn with_git(mut self, git: AuditGitContext) -> Self {
        self.git = Some(git);
        self
    }

    pub fn with_grants(mut self, grants: impl IntoIterator<Item = AuditGrant>) -> Self {
        self.grants = grants.into_iter().collect();
        self
    }

    pub fn with_approval(mut self, approval: AuditApproval) -> Self {
        self.approval = Some(approval);
        self
    }

    pub fn with_policy_version(mut self, policy_version: impl Into<String>) -> Self {
        self.policy_version = Some(policy_version.into());
        self
    }
}

/// Git metadata attached to an audit event when it can be detected locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditGitContext {
    pub remote: Option<String>,
    pub branch: Option<String>,
}

impl AuditGitContext {
    pub fn new(remote: Option<String>, branch: Option<String>) -> Self {
        Self { remote, branch }
    }
}

/// Grant-specific metadata recorded in an audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditGrant {
    pub name: String,
    pub provider: String,
    pub approval_required: bool,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub credential: Option<AuditCredentialMetadata>,
}

impl AuditGrant {
    pub fn new(
        name: impl Into<String>,
        provider: impl Into<String>,
        approval_required: bool,
    ) -> Self {
        Self {
            name: name.into(),
            provider: provider.into(),
            approval_required,
            issued_at: None,
            expires_at: None,
            credential: None,
        }
    }

    pub fn with_issuance(
        mut self,
        issued_at: impl Into<String>,
        expires_at: impl Into<String>,
        credential: AuditCredentialMetadata,
    ) -> Self {
        self.issued_at = Some(issued_at.into());
        self.expires_at = Some(expires_at.into());
        self.credential = Some(credential);
        self
    }
}

/// Redacted metadata about issued credentials.
///
/// This intentionally stores only credential kind and exposed carrier names,
/// such as environment variable names. It must not store secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCredentialMetadata {
    pub kind: String,
    pub env_vars: Vec<String>,
    pub temp_files: Vec<String>,
}

impl AuditCredentialMetadata {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            env_vars: Vec::new(),
            temp_files: Vec::new(),
        }
    }

    pub fn with_env_vars(mut self, env_vars: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.env_vars = env_vars.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_temp_files(
        mut self,
        temp_files: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.temp_files = temp_files.into_iter().map(Into::into).collect();
        self
    }
}

/// High-level outcome recorded for an audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDecision {
    Allow,
    Deny { reason: String },
    RequireApproval { transports: Vec<String> },
    Approved,
    CredentialsIssued,
    CommandCompleted { exit_code: Option<i32> },
    Failed { reason: String },
}

/// Approval metadata attached when a request enters or completes approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditApproval {
    pub transport: String,
    pub approver: Option<String>,
    pub decided_at: Option<String>,
}

impl AuditApproval {
    pub fn pending(transport: impl Into<String>) -> Self {
        Self {
            transport: transport.into(),
            approver: None,
            decided_at: None,
        }
    }

    pub fn decided(
        transport: impl Into<String>,
        approver: impl Into<String>,
        decided_at: impl Into<String>,
    ) -> Self {
        Self {
            transport: transport.into(),
            approver: Some(approver.into()),
            decided_at: Some(decided_at.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        AuditApproval, AuditCredentialMetadata, AuditDecision, AuditEvent, AuditGitContext,
        AuditGrant,
    };

    #[test]
    fn builds_denied_preflight_event() {
        let event = AuditEvent::new(
            "req-1",
            "2026-05-24T12:00:00Z",
            "codex",
            ["aws", "s3", "ls"],
            PathBuf::from("/workspace"),
            "0.1.0",
            AuditDecision::Deny {
                reason: "requester codex is not allowed".to_owned(),
            },
        )
        .with_git(AuditGitContext::new(
            Some("git@github.com:jychp/heim.git".to_owned()),
            Some("main".to_owned()),
        ))
        .with_grants([AuditGrant::new("aws.prod-readonly", "aws.prod", true)])
        .with_policy_version("local");

        assert_eq!(event.request_id, "req-1");
        assert_eq!(event.requester, "codex");
        assert_eq!(event.command, ["aws", "s3", "ls"]);
        assert_eq!(event.cwd, PathBuf::from("/workspace"));
        assert_eq!(
            event.git.and_then(|git| git.branch),
            Some("main".to_owned())
        );
        assert_eq!(event.grants[0].name, "aws.prod-readonly");
        assert_eq!(
            event.decision,
            AuditDecision::Deny {
                reason: "requester codex is not allowed".to_owned()
            }
        );
        assert_eq!(event.policy_version.as_deref(), Some("local"));
    }

    #[test]
    fn builds_credential_issuance_event_with_expiration() {
        let credential = AuditCredentialMetadata::new("aws-sts").with_env_vars([
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ]);
        let grant = AuditGrant::new("aws.prod-readonly", "aws.prod", true).with_issuance(
            "2026-05-24T12:00:00Z",
            "2026-05-24T12:15:00Z",
            credential,
        );

        let event = AuditEvent::new(
            "req-2",
            "2026-05-24T12:00:00Z",
            "codex",
            ["claude-code"],
            PathBuf::from("/workspace"),
            "0.1.0",
            AuditDecision::CredentialsIssued,
        )
        .with_grants([grant])
        .with_approval(AuditApproval::decided(
            "slack",
            "alice",
            "2026-05-24T12:00:05Z",
        ));

        let grant = &event.grants[0];
        assert_eq!(grant.issued_at.as_deref(), Some("2026-05-24T12:00:00Z"));
        assert_eq!(grant.expires_at.as_deref(), Some("2026-05-24T12:15:00Z"));
        assert_eq!(
            grant.credential.as_ref().expect("credential metadata").kind,
            "aws-sts"
        );
        assert_eq!(
            event.approval.and_then(|approval| approval.approver),
            Some("alice".to_owned())
        );
    }

    #[test]
    fn credential_metadata_records_carriers_without_secret_values() {
        let metadata = AuditCredentialMetadata::new("github-app")
            .with_env_vars(["GH_TOKEN", "GITHUB_TOKEN"])
            .with_temp_files(["github-app-token"]);

        assert_eq!(metadata.kind, "github-app");
        assert_eq!(metadata.env_vars, ["GH_TOKEN", "GITHUB_TOKEN"]);
        assert_eq!(metadata.temp_files, ["github-app-token"]);
    }

    #[test]
    fn builds_pending_approval_event() {
        let event = AuditEvent::new(
            "req-3",
            "2026-05-24T12:00:00Z",
            "codex",
            ["gh", "pr", "create"],
            PathBuf::from("/workspace"),
            "0.1.0",
            AuditDecision::RequireApproval {
                transports: vec!["slack".to_owned()],
            },
        )
        .with_approval(AuditApproval::pending("slack"));

        assert_eq!(
            event.approval.expect("approval metadata").transport,
            "slack"
        );
    }

    #[test]
    fn event_can_record_multiple_grants_for_one_command() {
        let event = AuditEvent::new(
            "req-4",
            "2026-05-24T12:00:00Z",
            "codex",
            ["claude-code"],
            PathBuf::from("/workspace"),
            "0.1.0",
            AuditDecision::RequireApproval {
                transports: vec!["slack".to_owned()],
            },
        )
        .with_grants([
            AuditGrant::new("aws.prod-readonly", "aws.prod", true),
            AuditGrant::new("github.drymn-pr-write", "github.drymn", true),
        ]);

        assert_eq!(event.command, ["claude-code"]);
        assert_eq!(event.grants.len(), 2);
        assert_eq!(event.grants[0].name, "aws.prod-readonly");
        assert_eq!(event.grants[1].name, "github.drymn-pr-write");
        assert!(event.grants.iter().all(|grant| grant.approval_required));
    }
}
