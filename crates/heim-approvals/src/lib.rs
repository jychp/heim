//! Approval workflow contract for Heim.
//!
//! This crate models transport-neutral approval requests and decisions. Slack
//! is one possible transport, but the contract is intentionally not Slack
//! specific and does not call external approval systems yet.

use std::fmt;
use std::path::PathBuf;

pub use heim_core::ApprovalTransportName;

/// Request context sent to one approval transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub transport: ApprovalTransportName,
    pub grants: Vec<ApprovalGrant>,
    pub requester: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub git: Option<ApprovalGitContext>,
}

impl ApprovalRequest {
    pub fn new(
        request_id: impl Into<String>,
        transport: ApprovalTransportName,
        requester: impl Into<String>,
        command: impl IntoIterator<Item = impl Into<String>>,
        cwd: PathBuf,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            transport,
            grants: Vec::new(),
            requester: requester.into(),
            command: command.into_iter().map(Into::into).collect(),
            cwd,
            git: None,
        }
    }

    pub fn with_grants(mut self, grants: impl IntoIterator<Item = ApprovalGrant>) -> Self {
        self.grants = grants.into_iter().collect();
        self
    }

    pub fn with_git(mut self, git: ApprovalGitContext) -> Self {
        self.git = Some(git);
        self
    }

    pub fn builder(
        request_id: impl Into<String>,
        transport: ApprovalTransportName,
    ) -> ApprovalRequestBuilder {
        ApprovalRequestBuilder::new(request_id, transport)
    }
}

/// Builder for validated approval requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequestBuilder {
    request_id: String,
    transport: ApprovalTransportName,
    grants: Vec<ApprovalGrant>,
    requester: Option<String>,
    command: Vec<String>,
    cwd: Option<PathBuf>,
    git: Option<ApprovalGitContext>,
}

impl ApprovalRequestBuilder {
    pub fn new(request_id: impl Into<String>, transport: ApprovalTransportName) -> Self {
        Self {
            request_id: request_id.into(),
            transport,
            grants: Vec::new(),
            requester: None,
            command: Vec::new(),
            cwd: None,
            git: None,
        }
    }

    pub fn grants(mut self, grants: impl IntoIterator<Item = ApprovalGrant>) -> Self {
        self.grants = grants.into_iter().collect();
        self
    }

    pub fn requester(mut self, requester: impl Into<String>) -> Self {
        self.requester = Some(requester.into());
        self
    }

    pub fn command(mut self, command: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.command = command.into_iter().map(Into::into).collect();
        self
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn git(mut self, git: ApprovalGitContext) -> Self {
        self.git = Some(git);
        self
    }

    pub fn build(self) -> Result<ApprovalRequest, ApprovalRequestBuildError> {
        if self.request_id.is_empty() {
            return Err(ApprovalRequestBuildError::MissingRequestId);
        }

        if self.grants.is_empty() {
            return Err(ApprovalRequestBuildError::MissingGrants);
        }

        let requester = self
            .requester
            .filter(|requester| !requester.is_empty())
            .ok_or(ApprovalRequestBuildError::MissingRequester)?;

        if self.command.is_empty() {
            return Err(ApprovalRequestBuildError::MissingCommand);
        }

        let cwd = self.cwd.ok_or(ApprovalRequestBuildError::MissingCwd)?;

        Ok(ApprovalRequest {
            request_id: self.request_id,
            transport: self.transport,
            grants: self.grants,
            requester,
            command: self.command,
            cwd,
            git: self.git,
        })
    }
}

/// Error returned when building an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalRequestBuildError {
    MissingRequestId,
    MissingGrants,
    MissingRequester,
    MissingCommand,
    MissingCwd,
}

impl fmt::Display for ApprovalRequestBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequestId => formatter.write_str("approval request id is required"),
            Self::MissingGrants => formatter.write_str("approval request must include grants"),
            Self::MissingRequester => formatter.write_str("approval requester is required"),
            Self::MissingCommand => formatter.write_str("approval command is required"),
            Self::MissingCwd => formatter.write_str("approval current directory is required"),
        }
    }
}

impl std::error::Error for ApprovalRequestBuildError {}

/// One grant included in an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrant {
    pub name: String,
    pub provider: String,
}

impl ApprovalGrant {
    pub fn new(name: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provider: provider.into(),
        }
    }
}

/// Git metadata included in an approval request when available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGitContext {
    pub remote: Option<String>,
    pub branch: Option<String>,
}

impl ApprovalGitContext {
    pub fn new(remote: Option<String>, branch: Option<String>) -> Self {
        Self { remote, branch }
    }
}

/// Transport-neutral approval outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved(ApprovalGrantDecision),
    Denied(ApprovalGrantDecision),
    TimedOut,
}

impl ApprovalDecision {
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved(_))
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied(_))
    }
}

/// Metadata supplied by an approval transport when a human decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrantDecision {
    pub approver: String,
    pub decided_at: String,
}

impl ApprovalGrantDecision {
    pub fn new(approver: impl Into<String>, decided_at: impl Into<String>) -> Self {
        Self {
            approver: approver.into(),
            decided_at: decided_at.into(),
        }
    }
}

/// Common behavior for approval transports.
pub trait ApprovalProvider {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError>;
}

/// Error returned by an approval transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    TransportUnavailable {
        transport: ApprovalTransportName,
        message: String,
    },
    RequestRejected {
        transport: ApprovalTransportName,
        message: String,
    },
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportUnavailable { transport, message } => {
                write!(
                    formatter,
                    "approval transport {transport} is unavailable: {message}"
                )
            }
            Self::RequestRejected { transport, message } => {
                write!(
                    formatter,
                    "approval transport {transport} rejected request: {message}"
                )
            }
        }
    }
}

impl std::error::Error for ApprovalError {}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::{
        ApprovalDecision, ApprovalError, ApprovalGitContext, ApprovalGrant, ApprovalGrantDecision,
        ApprovalProvider, ApprovalRequest, ApprovalTransportName,
    };

    #[test]
    fn approval_request_models_transport_neutral_context() {
        let transport = ApprovalTransportName::new("slack").expect("valid transport");
        let request = ApprovalRequest::new(
            "request-1",
            transport.clone(),
            "codex",
            ["aws", "s3", "ls"],
            PathBuf::from("/workspace"),
        )
        .with_grants([ApprovalGrant::new("aws.prod-readonly", "aws_prod")])
        .with_git(ApprovalGitContext::new(
            Some("git@github.com:jychp/heim.git".to_owned()),
            Some("main".to_owned()),
        ));

        assert_eq!(request.request_id, "request-1");
        assert_eq!(request.transport, transport);
        assert_eq!(request.requester, "codex");
        assert_eq!(request.command, ["aws", "s3", "ls"]);
        assert_eq!(request.cwd, PathBuf::from("/workspace"));
        assert_eq!(request.grants[0].name, "aws.prod-readonly");
        assert_eq!(request.grants[0].provider, "aws_prod");
        assert_eq!(
            request.git.expect("git context").remote.as_deref(),
            Some("git@github.com:jychp/heim.git")
        );
    }

    #[test]
    fn approval_request_builder_creates_valid_multi_grant_request() {
        let transport = ApprovalTransportName::new("slack").expect("valid transport");
        let request = ApprovalRequest::builder("request-1", transport.clone())
            .grants([
                ApprovalGrant::new("aws.prod-readonly", "aws_prod"),
                ApprovalGrant::new("github.drymn-pr-write", "github_drymn"),
            ])
            .requester("codex")
            .command(["claude-code"])
            .cwd("/workspace")
            .git(ApprovalGitContext::new(
                Some("git@github.com:jychp/heim.git".to_owned()),
                Some("feature/test".to_owned()),
            ))
            .build()
            .expect("approval request");

        assert_eq!(request.request_id, "request-1");
        assert_eq!(request.transport, transport);
        assert_eq!(request.grants.len(), 2);
        assert_eq!(request.grants[0].name, "aws.prod-readonly");
        assert_eq!(request.grants[1].name, "github.drymn-pr-write");
        assert_eq!(request.requester, "codex");
        assert_eq!(request.command, ["claude-code"]);
        assert_eq!(request.cwd, PathBuf::from("/workspace"));
        assert_eq!(
            request.git.expect("git context").branch.as_deref(),
            Some("feature/test")
        );
    }

    #[test]
    fn approval_request_builder_rejects_missing_grants() {
        let error = ApprovalRequest::builder(
            "request-1",
            ApprovalTransportName::new("slack").expect("valid transport"),
        )
        .requester("codex")
        .command(["aws", "s3", "ls"])
        .cwd("/workspace")
        .build()
        .expect_err("missing grants");

        assert_eq!(error.to_string(), "approval request must include grants");
    }

    #[test]
    fn approval_decision_reports_outcome() {
        let approved =
            ApprovalDecision::Approved(ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"));
        let denied =
            ApprovalDecision::Denied(ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"));

        assert!(approved.is_approved());
        assert!(!approved.is_denied());
        assert!(denied.is_denied());
        assert!(!denied.is_approved());
        assert!(!ApprovalDecision::TimedOut.is_approved());
    }

    #[test]
    fn approval_provider_trait_is_transport_agnostic() {
        let provider = RecordingApprovalProvider::new(ApprovalDecision::TimedOut);
        let request = ApprovalRequest::new(
            "request-1",
            ApprovalTransportName::new("ticket").expect("valid transport"),
            "codex",
            ["gh", "pr", "merge", "42"],
            PathBuf::from("/workspace"),
        );

        let decision = provider.request_approval(&request).expect("decision");

        assert_eq!(decision, ApprovalDecision::TimedOut);
        assert_eq!(
            provider.request_ids.borrow().as_slice(),
            ["request-1".to_owned()]
        );
    }

    #[test]
    fn approval_errors_include_transport_without_transport_specific_schema() {
        let transport = ApprovalTransportName::new("slack").expect("valid transport");
        let error = ApprovalError::TransportUnavailable {
            transport,
            message: "webhook not configured".to_owned(),
        };

        assert_eq!(
            error.to_string(),
            "approval transport slack is unavailable: webhook not configured"
        );
    }

    struct RecordingApprovalProvider {
        decision: ApprovalDecision,
        request_ids: RefCell<Vec<String>>,
    }

    impl RecordingApprovalProvider {
        fn new(decision: ApprovalDecision) -> Self {
            Self {
                decision,
                request_ids: RefCell::new(Vec::new()),
            }
        }
    }

    impl ApprovalProvider for RecordingApprovalProvider {
        fn request_approval(
            &self,
            request: &ApprovalRequest,
        ) -> Result<ApprovalDecision, ApprovalError> {
            self.request_ids
                .borrow_mut()
                .push(request.request_id.clone());
            Ok(self.decision.clone())
        }
    }
}
