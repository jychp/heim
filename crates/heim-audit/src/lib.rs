//! Audit event model for Heim.
//!
//! This crate defines typed audit events and local JSONL persistence. It does
//! not contact providers or execute commands.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use heim_config::default_audit_log_file;
#[cfg(test)]
use heim_config::default_audit_log_file_from_env;
use serde::{Deserialize, Serialize};

/// One local audit event for a Heim request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Append-only JSONL sink for local audit events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlAuditSink {
    path: PathBuf,
}

impl JsonlAuditSink {
    /// Build a sink targeting Heim's default audit log file.
    pub fn open_default() -> Result<Self, AuditLogError> {
        Ok(Self::new(default_audit_log_file()?))
    }

    #[cfg(test)]
    fn open_default_from_env(
        var_os: impl FnMut(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Self, AuditLogError> {
        Ok(Self::new(default_audit_log_file_from_env(var_os)?))
    }

    /// Build a sink targeting an explicit JSONL file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event as one JSON object followed by a newline.
    pub fn append(&self, event: &AuditEvent) -> Result<(), AuditLogError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| AuditLogError::CreateDirectory {
                path: parent.display().to_string(),
                source,
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| AuditLogError::OpenFile {
                path: self.path.display().to_string(),
                source,
            })?;

        let mut record = serde_json::to_vec(event).map_err(AuditLogError::Serialize)?;
        record.push(b'\n');

        file.write_all(&record)
            .map_err(|source| AuditLogError::WriteFile {
                path: self.path.display().to_string(),
                source,
            })?;

        Ok(())
    }
}

/// Error raised while writing local audit logs.
#[derive(Debug)]
pub enum AuditLogError {
    Config(heim_config::ConfigError),
    CreateDirectory {
        path: String,
        source: std::io::Error,
    },
    OpenFile {
        path: String,
        source: std::io::Error,
    },
    WriteFile {
        path: String,
        source: std::io::Error,
    },
    Serialize(serde_json::Error),
}

impl fmt::Display for AuditLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => write!(formatter, "failed to resolve audit log path: {source}"),
            Self::CreateDirectory { path, source } => {
                write!(
                    formatter,
                    "failed to create audit log directory {path}: {source}"
                )
            }
            Self::OpenFile { path, source } => {
                write!(formatter, "failed to open audit log file {path}: {source}")
            }
            Self::WriteFile { path, source } => {
                write!(formatter, "failed to write audit log file {path}: {source}")
            }
            Self::Serialize(source) => {
                write!(formatter, "failed to serialize audit event: {source}")
            }
        }
    }
}

impl std::error::Error for AuditLogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::CreateDirectory { source, .. } => Some(source),
            Self::OpenFile { source, .. } => Some(source),
            Self::WriteFile { source, .. } => Some(source),
            Self::Serialize(source) => Some(source),
        }
    }
}

impl From<heim_config::ConfigError> for AuditLogError {
    fn from(source: heim_config::ConfigError) -> Self {
        Self::Config(source)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        AuditApproval, AuditCredentialMetadata, AuditDecision, AuditEvent, AuditGitContext,
        AuditGrant, JsonlAuditSink,
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

    #[test]
    fn serializes_audit_event_as_json() {
        let event = sample_event("req-5", AuditDecision::Allow);

        let json = serde_json::to_string(&event).expect("serialize event");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(value["request_id"], "req-5");
        assert_eq!(value["decision"]["type"], "allow");
        assert_eq!(value["grants"][0]["name"], "aws.prod-readonly");
    }

    #[test]
    fn deserializes_audit_event_from_json() {
        let event = sample_event(
            "req-6",
            AuditDecision::Deny {
                reason: "requester gh is not allowed".to_owned(),
            },
        );

        let json = serde_json::to_string(&event).expect("serialize event");
        let parsed: AuditEvent = serde_json::from_str(&json).expect("deserialize event");

        assert_eq!(parsed, event);
    }

    #[test]
    fn jsonl_sink_appends_one_event_per_line() {
        let dir = TempAuditDir::new();
        let log = dir.path().join("nested").join("audit.jsonl");
        let sink = JsonlAuditSink::new(&log);

        sink.append(&sample_event("req-7", AuditDecision::Allow))
            .expect("append first event");
        sink.append(&sample_event(
            "req-8",
            AuditDecision::CommandCompleted { exit_code: Some(0) },
        ))
        .expect("append second event");

        let contents = fs::read_to_string(log).expect("read audit log");
        let lines = contents.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first line json");
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("second line json");

        assert_eq!(first["request_id"], "req-7");
        assert_eq!(second["decision"]["type"], "command_completed");
    }

    #[test]
    fn jsonl_sink_exposes_default_audit_file_name() {
        let sink = JsonlAuditSink::new(PathBuf::from("/tmp/heim/logs/audit.jsonl"));

        assert_eq!(sink.path(), Path::new("/tmp/heim/logs/audit.jsonl"));
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn default_sink_uses_config_log_file_on_linux() {
        let sink = JsonlAuditSink::open_default_from_env(|name| match name {
            "XDG_CONFIG_HOME" => Some(OsString::from("/tmp/config")),
            "HOME" => Some(OsString::from("/home/alice")),
            _ => None,
        })
        .expect("default sink");

        assert_eq!(sink.path(), Path::new("/tmp/config/heim/logs/audit.jsonl"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_sink_uses_config_log_file_on_macos() {
        let sink = JsonlAuditSink::open_default_from_env(|name| match name {
            "HOME" => Some(OsString::from("/Users/alice")),
            _ => None,
        })
        .expect("default sink");

        assert_eq!(
            sink.path(),
            Path::new("/Users/alice/Library/Application Support/heim/logs/audit.jsonl")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn default_sink_uses_config_log_file_on_windows() {
        let sink = JsonlAuditSink::open_default_from_env(|name| match name {
            "APPDATA" => Some(OsString::from(r"C:\Users\Alice\AppData\Roaming")),
            "USERPROFILE" => Some(OsString::from(r"C:\Users\Alice")),
            _ => None,
        })
        .expect("default sink");

        assert_eq!(
            sink.path(),
            PathBuf::from(r"C:\Users\Alice\AppData\Roaming").join("heim/logs/audit.jsonl")
        );
    }

    fn sample_event(request_id: &str, decision: AuditDecision) -> AuditEvent {
        AuditEvent::new(
            request_id,
            "2026-05-24T12:00:00Z",
            "codex",
            ["aws", "sts", "get-caller-identity"],
            PathBuf::from("/workspace"),
            "0.1.0",
            decision,
        )
        .with_grants([AuditGrant::new("aws.prod-readonly", "aws.prod", false)])
    }

    struct TempAuditDir {
        path: PathBuf,
    }

    impl TempAuditDir {
        fn new() -> Self {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "heim-audit-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temp audit directory");

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempAuditDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
