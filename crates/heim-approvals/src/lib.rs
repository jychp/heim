//! Approval workflow contract for Heim.
//!
//! This crate models transport-neutral approval requests and decisions. Slack
//! is one possible transport, but the contract is intentionally not Slack
//! specific and does not call external approval systems yet.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use heim_core::ApprovalTransportName;

/// Request context sent to one approval transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    #[serde(with = "approval_transport_name_serde")]
    pub transport: ApprovalTransportName,
    pub grants: Vec<ApprovalGrant>,
    pub requester: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub git: Option<ApprovalGitContext>,
    pub options: Vec<ApprovalOption>,
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
            options: Vec::new(),
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

    pub fn with_options(mut self, options: impl IntoIterator<Item = ApprovalOption>) -> Self {
        self.options = options.into_iter().collect();
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
    options: Vec<ApprovalOption>,
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
            options: Vec::new(),
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

    pub fn options(mut self, options: impl IntoIterator<Item = ApprovalOption>) -> Self {
        self.options = options.into_iter().collect();
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
        validate_approval_options(&self.options)?;

        Ok(ApprovalRequest {
            request_id: self.request_id,
            transport: self.transport,
            grants: self.grants,
            requester,
            command: self.command,
            cwd,
            git: self.git,
            options: self.options,
        })
    }
}

fn validate_approval_options(options: &[ApprovalOption]) -> Result<(), ApprovalRequestBuildError> {
    let mut ids = BTreeSet::new();
    for option in options {
        if option.id.is_empty() {
            return Err(ApprovalRequestBuildError::InvalidOption {
                message: "approval option id is required".to_owned(),
            });
        }

        if option.label.is_empty() {
            return Err(ApprovalRequestBuildError::InvalidOption {
                message: format!("approval option {} must include a label", option.id),
            });
        }

        if !ids.insert(option.id.as_str()) {
            return Err(ApprovalRequestBuildError::InvalidOption {
                message: format!("approval option {} is duplicated", option.id),
            });
        }
    }

    Ok(())
}

/// Error returned when building an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalRequestBuildError {
    MissingRequestId,
    MissingGrants,
    MissingRequester,
    MissingCommand,
    MissingCwd,
    InvalidOption { message: String },
}

impl fmt::Display for ApprovalRequestBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequestId => formatter.write_str("approval request id is required"),
            Self::MissingGrants => formatter.write_str("approval request must include grants"),
            Self::MissingRequester => formatter.write_str("approval requester is required"),
            Self::MissingCommand => formatter.write_str("approval command is required"),
            Self::MissingCwd => formatter.write_str("approval current directory is required"),
            Self::InvalidOption { message } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ApprovalRequestBuildError {}

/// One grant included in an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalGitContext {
    pub remote: Option<String>,
    pub branch: Option<String>,
}

impl ApprovalGitContext {
    pub fn new(remote: Option<String>, branch: Option<String>) -> Self {
        Self { remote, branch }
    }
}

/// Provider-configured approval option, such as a duration button.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalOption {
    pub id: String,
    pub label: String,
}

impl ApprovalOption {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
        }
    }
}

/// Transport-neutral approval outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved {
        decision: ApprovalGrantDecision,
    },
    ApprovedWithOption {
        decision: ApprovalGrantDecision,
        option: ApprovalOption,
    },
    Denied {
        decision: ApprovalGrantDecision,
    },
    TimedOut,
}

impl ApprovalDecision {
    pub fn is_approved(&self) -> bool {
        matches!(
            self,
            Self::Approved { .. } | Self::ApprovedWithOption { .. }
        )
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    pub fn validate_for_request(
        &self,
        request: &ApprovalRequest,
    ) -> Result<(), ApprovalDecisionValidationError> {
        match self {
            Self::Approved { .. } | Self::Denied { .. } | Self::TimedOut => Ok(()),
            Self::ApprovedWithOption { option, .. } => {
                if request
                    .options
                    .iter()
                    .any(|candidate| candidate.id == option.id)
                {
                    Ok(())
                } else {
                    Err(ApprovalDecisionValidationError::UnconfiguredOption {
                        transport: request.transport.clone(),
                        option: option.id.clone(),
                    })
                }
            }
        }
    }
}

/// Error returned when an approval decision does not match its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecisionValidationError {
    UnconfiguredOption {
        transport: ApprovalTransportName,
        option: String,
    },
}

impl fmt::Display for ApprovalDecisionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnconfiguredOption { transport, option } => write!(
                formatter,
                "approval transport {transport} returned unconfigured option {option}"
            ),
        }
    }
}

impl std::error::Error for ApprovalDecisionValidationError {}

/// Runtime approval session tracked while an approval request is pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSession {
    id: String,
    request: ApprovalRequest,
    expires_at: Option<String>,
    status: ApprovalSessionStatus,
}

impl ApprovalSession {
    pub fn new(
        id: impl Into<String>,
        request: ApprovalRequest,
        expires_at: Option<String>,
    ) -> Result<Self, ApprovalSessionError> {
        let id = id.into();
        if id.is_empty() {
            return Err(ApprovalSessionError::MissingSessionId);
        }

        Ok(Self {
            id,
            request,
            expires_at,
            status: ApprovalSessionStatus::Pending,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn request(&self) -> &ApprovalRequest {
        &self.request
    }

    pub fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }

    pub fn status(&self) -> &ApprovalSessionStatus {
        &self.status
    }

    pub fn is_pending(&self) -> bool {
        matches!(self.status, ApprovalSessionStatus::Pending)
    }

    pub fn expire(&mut self) -> Result<(), ApprovalSessionError> {
        if !self.is_pending() {
            return Err(ApprovalSessionError::AlreadyResolved {
                session_id: self.id.clone(),
            });
        }

        self.status = ApprovalSessionStatus::Expired;
        Ok(())
    }

    pub fn apply_decision(
        &mut self,
        decision: ApprovalDecision,
    ) -> Result<(), ApprovalSessionError> {
        if !self.is_pending() {
            return Err(ApprovalSessionError::AlreadyResolved {
                session_id: self.id.clone(),
            });
        }

        decision
            .validate_for_request(&self.request)
            .map_err(ApprovalSessionError::InvalidDecision)?;
        self.status = ApprovalSessionStatus::from(decision);
        Ok(())
    }
}

/// Current state of an approval session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalSessionStatus {
    Pending,
    Approved {
        decision: ApprovalGrantDecision,
    },
    ApprovedWithOption {
        decision: ApprovalGrantDecision,
        option: ApprovalOption,
    },
    Denied {
        decision: ApprovalGrantDecision,
    },
    TimedOut,
    Expired,
}

impl From<ApprovalDecision> for ApprovalSessionStatus {
    fn from(decision: ApprovalDecision) -> Self {
        match decision {
            ApprovalDecision::Approved { decision } => Self::Approved { decision },
            ApprovalDecision::ApprovedWithOption { decision, option } => {
                Self::ApprovedWithOption { decision, option }
            }
            ApprovalDecision::Denied { decision } => Self::Denied { decision },
            ApprovalDecision::TimedOut => Self::TimedOut,
        }
    }
}

/// Error returned when creating or resolving an approval session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalSessionError {
    MissingSessionId,
    AlreadyResolved { session_id: String },
    InvalidDecision(ApprovalDecisionValidationError),
}

impl fmt::Display for ApprovalSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSessionId => formatter.write_str("approval session id is required"),
            Self::AlreadyResolved { session_id } => {
                write!(
                    formatter,
                    "approval session {session_id} is already resolved"
                )
            }
            Self::InvalidDecision(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for ApprovalSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidDecision(source) => Some(source),
            Self::MissingSessionId | Self::AlreadyResolved { .. } => None,
        }
    }
}

mod approval_transport_name_serde {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    use super::ApprovalTransportName;

    pub fn serialize<S>(transport: &ApprovalTransportName, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(transport.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ApprovalTransportName, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        ApprovalTransportName::new(value).map_err(D::Error::custom)
    }
}

/// Metadata supplied by an approval transport when a human decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Redacted Slack bot token used by Slack approval transports.
#[derive(Clone, PartialEq, Eq)]
pub struct SlackBotToken(String);

impl SlackBotToken {
    pub fn new(token: impl Into<String>) -> Result<Self, SlackApprovalConfigError> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err(SlackApprovalConfigError::MissingBotToken);
        }

        Ok(Self(token))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SlackBotToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SlackBotToken")
            .field(&"<redacted>")
            .finish()
    }
}

/// Config error for a Slack approval provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackApprovalConfigError {
    MissingChannel,
    MissingBotToken,
}

impl fmt::Display for SlackApprovalConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChannel => formatter.write_str("slack approval channel is required"),
            Self::MissingBotToken => formatter.write_str("slack bot token is required"),
        }
    }
}

impl std::error::Error for SlackApprovalConfigError {}

/// Slack approval provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackApprovalProvider<C = UnavailableSlackApprovalClient> {
    transport: ApprovalTransportName,
    channel: String,
    bot_token: SlackBotToken,
    client: C,
}

impl<C> SlackApprovalProvider<C> {
    pub fn new(
        transport: ApprovalTransportName,
        channel: impl Into<String>,
        bot_token: SlackBotToken,
        client: C,
    ) -> Result<Self, SlackApprovalConfigError> {
        let channel = channel.into();
        if channel.trim().is_empty() {
            return Err(SlackApprovalConfigError::MissingChannel);
        }

        Ok(Self {
            transport,
            channel,
            bot_token,
            client,
        })
    }

    pub fn transport_name(&self) -> &ApprovalTransportName {
        &self.transport
    }
}

impl SlackApprovalProvider {
    pub fn with_default_client(
        transport: ApprovalTransportName,
        channel: impl Into<String>,
        bot_token: SlackBotToken,
    ) -> Result<Self, SlackApprovalConfigError> {
        Self::new(
            transport,
            channel,
            bot_token,
            UnavailableSlackApprovalClient,
        )
    }
}

impl<C> ApprovalProvider for SlackApprovalProvider<C>
where
    C: SlackApprovalClient,
{
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError> {
        if request.transport != self.transport {
            return Err(ApprovalError::RequestRejected {
                transport: request.transport.clone(),
                message: format!(
                    "request targets transport {}, but provider is configured for {}",
                    request.transport, self.transport
                ),
            });
        }

        self.client
            .request_slack_approval(&self.transport, &self.channel, &self.bot_token, request)
    }
}

/// Client boundary used by Slack approval providers.
pub trait SlackApprovalClient {
    fn request_slack_approval(
        &self,
        transport: &ApprovalTransportName,
        channel: &str,
        bot_token: &SlackBotToken,
        request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError>;
}

/// Placeholder Slack client used until the real Slack API flow is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnavailableSlackApprovalClient;

impl SlackApprovalClient for UnavailableSlackApprovalClient {
    fn request_slack_approval(
        &self,
        transport: &ApprovalTransportName,
        _channel: &str,
        _bot_token: &SlackBotToken,
        _request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError> {
        Err(ApprovalError::TransportUnavailable {
            transport: transport.clone(),
            message: "Slack approval dispatch is not implemented yet".to_owned(),
        })
    }
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
        ApprovalOption, ApprovalProvider, ApprovalRequest, ApprovalSession, ApprovalSessionError,
        ApprovalSessionStatus, ApprovalTransportName, SlackApprovalClient,
        SlackApprovalConfigError, SlackApprovalProvider, SlackBotToken,
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
        assert!(request.options.is_empty());
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
            .options([
                ApprovalOption::new("15m", "Approve 15m"),
                ApprovalOption::new("60m", "Approve 60m"),
            ])
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
        assert_eq!(request.options[0].id, "15m");
        assert_eq!(request.options[1].label, "Approve 60m");
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
    fn approval_request_builder_rejects_duplicate_option_ids() {
        let error = ApprovalRequest::builder(
            "request-1",
            ApprovalTransportName::new("slack").expect("valid transport"),
        )
        .grants([ApprovalGrant::new("aws.prod-readonly", "aws_prod")])
        .requester("codex")
        .command(["aws", "s3", "ls"])
        .cwd("/workspace")
        .options([
            ApprovalOption::new("15m", "Approve 15m"),
            ApprovalOption::new("15m", "Approve 15 minutes"),
        ])
        .build()
        .expect_err("duplicate option id");

        assert_eq!(error.to_string(), "approval option 15m is duplicated");
    }

    #[test]
    fn approval_decision_reports_outcome() {
        let approved = ApprovalDecision::Approved {
            decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
        };
        let approved_with_option = ApprovalDecision::ApprovedWithOption {
            decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            option: ApprovalOption::new("15m", "Approve 15m"),
        };
        let denied = ApprovalDecision::Denied {
            decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
        };

        assert!(approved.is_approved());
        assert!(approved_with_option.is_approved());
        assert!(!approved.is_denied());
        assert!(denied.is_denied());
        assert!(!denied.is_approved());
        assert!(!ApprovalDecision::TimedOut.is_approved());
    }

    #[test]
    fn approval_decision_validates_selected_option() {
        let request = approval_request_with_options();
        let decision = ApprovalDecision::ApprovedWithOption {
            decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            option: ApprovalOption::new("15m", "Approve 15m"),
        };

        decision
            .validate_for_request(&request)
            .expect("configured option");
    }

    #[test]
    fn approval_decision_rejects_unconfigured_option() {
        let request = approval_request_with_options();
        let decision = ApprovalDecision::ApprovedWithOption {
            decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            option: ApprovalOption::new("24h", "Approve 24h"),
        };

        let error = decision
            .validate_for_request(&request)
            .expect_err("unconfigured option");

        assert_eq!(
            error.to_string(),
            "approval transport slack returned unconfigured option 24h"
        );
    }

    #[test]
    fn approval_session_starts_pending() {
        let session = ApprovalSession::new(
            "session-1",
            approval_request_with_options(),
            Some("2026-05-24T12:15:00Z".to_owned()),
        )
        .expect("approval session");

        assert_eq!(session.id(), "session-1");
        assert!(session.is_pending());
        assert_eq!(session.expires_at(), Some("2026-05-24T12:15:00Z"));
        assert_eq!(session.request().request_id, "request-1");
    }

    #[test]
    fn approval_session_applies_approved_option() {
        let mut session = ApprovalSession::new("session-1", approval_request_with_options(), None)
            .expect("approval session");

        session
            .apply_decision(ApprovalDecision::ApprovedWithOption {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                option: ApprovalOption::new("60m", "Approve 60m"),
            })
            .expect("approval decision");

        assert_eq!(
            session.status(),
            &ApprovalSessionStatus::ApprovedWithOption {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                option: ApprovalOption::new("60m", "Approve 60m"),
            }
        );
    }

    #[test]
    fn approval_session_applies_denial() {
        let mut session = ApprovalSession::new("session-1", approval_request_with_options(), None)
            .expect("approval session");

        session
            .apply_decision(ApprovalDecision::Denied {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            })
            .expect("approval decision");

        assert_eq!(
            session.status(),
            &ApprovalSessionStatus::Denied {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z")
            }
        );
    }

    #[test]
    fn approval_session_rejects_second_decision() {
        let mut session = ApprovalSession::new("session-1", approval_request_with_options(), None)
            .expect("approval session");
        session
            .apply_decision(ApprovalDecision::TimedOut)
            .expect("timeout decision");

        let error = session
            .apply_decision(ApprovalDecision::Approved {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            })
            .expect_err("already resolved");

        assert_eq!(
            error,
            ApprovalSessionError::AlreadyResolved {
                session_id: "session-1".to_owned()
            }
        );
    }

    #[test]
    fn approval_session_can_expire() {
        let mut session = ApprovalSession::new(
            "session-1",
            approval_request_with_options(),
            Some("2026-05-24T12:15:00Z".to_owned()),
        )
        .expect("approval session");

        session.expire().expect("expire session");

        assert_eq!(session.status(), &ApprovalSessionStatus::Expired);
    }

    #[test]
    fn approval_session_rejects_expiration_after_decision() {
        let mut session = ApprovalSession::new("session-1", approval_request_with_options(), None)
            .expect("approval session");
        session
            .apply_decision(ApprovalDecision::Approved {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            })
            .expect("approval decision");

        let error = session.expire().expect_err("already resolved");

        assert_eq!(
            error,
            ApprovalSessionError::AlreadyResolved {
                session_id: "session-1".to_owned()
            }
        );
    }

    #[test]
    fn approval_session_rejects_invalid_decision() {
        let mut session = ApprovalSession::new("session-1", approval_request_with_options(), None)
            .expect("approval session");

        let error = session
            .apply_decision(ApprovalDecision::ApprovedWithOption {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                option: ApprovalOption::new("24h", "Approve 24h"),
            })
            .expect_err("invalid option");

        assert_eq!(
            error.to_string(),
            "approval transport slack returned unconfigured option 24h"
        );
        assert!(session.is_pending());
    }

    #[test]
    fn approval_request_serializes_transport_as_name() {
        let request = approval_request_with_options();

        let json = serde_json::to_string(&request).expect("serialize request");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        let parsed: ApprovalRequest = serde_json::from_str(&json).expect("deserialize request");

        assert_eq!(value["transport"], "slack");
        assert_eq!(value["options"][0]["id"], "15m");
        assert_eq!(parsed, request);
    }

    #[test]
    fn approval_decision_serializes_as_tagged_json() {
        let decision = ApprovalDecision::ApprovedWithOption {
            decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            option: ApprovalOption::new("15m", "Approve 15m"),
        };

        let json = serde_json::to_string(&decision).expect("serialize decision");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        let parsed: ApprovalDecision = serde_json::from_str(&json).expect("deserialize decision");

        assert_eq!(value["type"], "approved_with_option");
        assert_eq!(value["decision"]["approver"], "alice");
        assert_eq!(value["option"]["id"], "15m");
        assert_eq!(parsed, decision);
    }

    #[test]
    fn approval_session_serializes_status() {
        let mut session = ApprovalSession::new("session-1", approval_request_with_options(), None)
            .expect("approval session");
        session
            .apply_decision(ApprovalDecision::Denied {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            })
            .expect("approval decision");

        let json = serde_json::to_string(&session).expect("serialize session");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        let parsed: ApprovalSession = serde_json::from_str(&json).expect("deserialize session");

        assert_eq!(value["id"], "session-1");
        assert_eq!(value["request"]["transport"], "slack");
        assert_eq!(value["status"]["type"], "denied");
        assert_eq!(parsed, session);
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

    #[test]
    fn slack_bot_token_debug_redacts_secret_value() {
        let token = SlackBotToken::new("xoxb-secret").expect("token");

        let debug = format!("{token:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("xoxb-secret"));
    }

    #[test]
    fn slack_provider_rejects_empty_channel() {
        let error = SlackApprovalProvider::new(
            ApprovalTransportName::new("slack").expect("valid transport"),
            "",
            SlackBotToken::new("xoxb-secret").expect("token"),
            RecordingSlackClient::new(ApprovalDecision::TimedOut),
        )
        .expect_err("missing channel");

        assert_eq!(error, SlackApprovalConfigError::MissingChannel);
    }

    #[test]
    fn slack_provider_delegates_requests_to_client() {
        let client = RecordingSlackClient::new(ApprovalDecision::Approved {
            decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
        });
        let provider = SlackApprovalProvider::new(
            ApprovalTransportName::new("slack").expect("valid transport"),
            "#heim-approvals",
            SlackBotToken::new("xoxb-secret").expect("token"),
            client,
        )
        .expect("provider");
        let request = ApprovalRequest::new(
            "request-1",
            ApprovalTransportName::new("slack").expect("valid transport"),
            "codex",
            ["aws", "s3", "ls"],
            PathBuf::from("/workspace"),
        );

        let decision = provider.request_approval(&request).expect("decision");

        assert!(decision.is_approved());
        assert_eq!(
            provider.client.seen.borrow().as_slice(),
            [(
                "slack".to_owned(),
                "#heim-approvals".to_owned(),
                "xoxb-secret".to_owned(),
                "request-1".to_owned(),
            )]
        );
    }

    #[test]
    fn slack_provider_rejects_wrong_transport_request() {
        let provider = SlackApprovalProvider::new(
            ApprovalTransportName::new("slack").expect("valid transport"),
            "#heim-approvals",
            SlackBotToken::new("xoxb-secret").expect("token"),
            RecordingSlackClient::new(ApprovalDecision::TimedOut),
        )
        .expect("provider");
        let request = ApprovalRequest::new(
            "request-1",
            ApprovalTransportName::new("ticket").expect("valid transport"),
            "codex",
            ["aws", "s3", "ls"],
            PathBuf::from("/workspace"),
        );

        let error = provider
            .request_approval(&request)
            .expect_err("wrong transport");

        assert!(
            error
                .to_string()
                .contains("provider is configured for slack")
        );
    }

    fn approval_request_with_options() -> ApprovalRequest {
        ApprovalRequest::builder(
            "request-1",
            ApprovalTransportName::new("slack").expect("valid transport"),
        )
        .grants([ApprovalGrant::new("aws.prod-readonly", "aws_prod")])
        .requester("codex")
        .command(["aws", "sts", "get-caller-identity"])
        .cwd("/workspace")
        .options([
            ApprovalOption::new("15m", "Approve 15m"),
            ApprovalOption::new("60m", "Approve 60m"),
        ])
        .build()
        .expect("approval request")
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

    #[derive(Debug)]
    struct RecordingSlackClient {
        decision: ApprovalDecision,
        seen: RefCell<Vec<(String, String, String, String)>>,
    }

    impl RecordingSlackClient {
        fn new(decision: ApprovalDecision) -> Self {
            Self {
                decision,
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl SlackApprovalClient for RecordingSlackClient {
        fn request_slack_approval(
            &self,
            transport: &ApprovalTransportName,
            channel: &str,
            bot_token: &SlackBotToken,
            request: &ApprovalRequest,
        ) -> Result<ApprovalDecision, ApprovalError> {
            self.seen.borrow_mut().push((
                transport.to_string(),
                channel.to_owned(),
                bot_token.as_str().to_owned(),
                request.request_id.clone(),
            ));
            Ok(self.decision.clone())
        }
    }
}
