//! Execution planning for Heim.
//!
//! This crate builds the local execution context and evaluates policy preflight.
//! It does not request approvals, issue credentials, or spawn child processes.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use heim_core::GrantPolicy;
use heim_policy::{DenyReason, PolicyDecision, PolicyRequest, evaluate_policy};

/// Local context for a future `heim exec` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRequest {
    pub grants: Vec<String>,
    pub requester: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub git: Option<GitContext>,
}

impl ExecutionRequest {
    /// Collect local context for a future command execution.
    pub fn collect(
        grants: Vec<String>,
        requester: impl Into<String>,
        command: Vec<String>,
    ) -> Result<Self, ExecContextError> {
        let cwd = std::env::current_dir().map_err(ExecContextError::CurrentDirectory)?;
        Ok(Self::new(grants, requester, command, cwd))
    }

    /// Build a request from explicit values.
    pub fn new(
        grants: Vec<String>,
        requester: impl Into<String>,
        command: Vec<String>,
        cwd: PathBuf,
    ) -> Self {
        let git = detect_git_context(&cwd);

        Self {
            grants,
            requester: requester.into(),
            command,
            cwd,
            git,
        }
    }
}

/// Git repository metadata detected for an execution request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitContext {
    pub remote: Option<String>,
    pub branch: Option<String>,
}

/// Error raised while collecting local execution context.
#[derive(Debug)]
pub enum ExecContextError {
    CurrentDirectory(std::io::Error),
}

impl fmt::Display for ExecContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentDirectory(source) => {
                write!(formatter, "failed to read current directory: {source}")
            }
        }
    }
}

impl std::error::Error for ExecContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CurrentDirectory(source) => Some(source),
        }
    }
}

/// Result of evaluating all requested grants for an execution request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPreflight {
    pub request: ExecutionRequest,
    pub decisions: Vec<GrantPreflightDecision>,
}

impl ExecutionPreflight {
    pub fn first_denial(&self) -> Option<&GrantPreflightDecision> {
        self.decisions
            .iter()
            .find(|decision| matches!(decision.decision, PolicyDecision::Deny { .. }))
    }

    pub fn approval_transports(&self) -> BTreeSet<String> {
        self.decisions
            .iter()
            .filter_map(|decision| match &decision.decision {
                PolicyDecision::RequireApproval { transport } => Some(transport.to_string()),
                PolicyDecision::Allow | PolicyDecision::Deny { .. } => None,
            })
            .collect()
    }

    pub fn requested_grant_count(&self) -> usize {
        self.decisions.len()
    }
}

/// Policy decision for one requested grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPreflightDecision {
    pub grant: String,
    pub decision: PolicyDecision,
}

impl GrantPreflightDecision {
    pub fn deny_reason(&self) -> Option<&DenyReason> {
        match &self.decision {
            PolicyDecision::Deny { reason } => Some(reason),
            PolicyDecision::Allow | PolicyDecision::RequireApproval { .. } => None,
        }
    }
}

/// Evaluate every requested grant for a future execution.
pub fn evaluate_preflight(grants: &[GrantPolicy], request: ExecutionRequest) -> ExecutionPreflight {
    let decisions = request
        .grants
        .iter()
        .map(|grant| {
            let policy_request = PolicyRequest::new(
                grant.clone(),
                request.requester.clone(),
                request.command.clone(),
            );
            GrantPreflightDecision {
                grant: grant.clone(),
                decision: evaluate_policy(grants, &policy_request),
            }
        })
        .collect();

    ExecutionPreflight { request, decisions }
}

fn detect_git_context(cwd: &Path) -> Option<GitContext> {
    let remote = run_git(cwd, ["config", "--get", "remote.origin.url"]);
    let branch = run_git(cwd, ["branch", "--show-current"]);

    if remote.is_none() && branch.is_none() {
        None
    } else {
        Some(GitContext { remote, branch })
    }
}

fn run_git<const N: usize>(cwd: &Path, args: [&str; N]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use heim_core::{
        ApprovalPolicy, ApprovalTransportName, CommandRule, GrantName, GrantPolicy, ProviderName,
        RequesterRule,
    };
    use heim_policy::{DenyReason, PolicyDecision};

    use super::{ExecutionRequest, evaluate_preflight};

    #[test]
    fn builds_execution_request_with_local_context() {
        let dir = TempDir::new();

        let request = ExecutionRequest::new(
            vec!["aws.prod-readonly".to_owned()],
            "codex",
            vec!["aws".to_owned(), "s3".to_owned(), "ls".to_owned()],
            dir.path().to_path_buf(),
        );

        assert_eq!(request.grants, ["aws.prod-readonly"]);
        assert_eq!(request.requester, "codex");
        assert_eq!(request.command, ["aws", "s3", "ls"]);
        assert_eq!(request.cwd, dir.path());
        assert_eq!(request.git, None);
    }

    #[test]
    fn detects_git_context_when_available() {
        let dir = TempDir::new();
        run_command(dir.path(), ["git", "init", "-b", "main"]);
        run_command(dir.path(), ["git", "checkout", "-b", "feature/test"]);
        run_command(
            dir.path(),
            [
                "git",
                "remote",
                "add",
                "origin",
                "git@github.com:jychp/heim.git",
            ],
        );

        let request = ExecutionRequest::new(
            vec!["github.drymn-pr-write".to_owned()],
            "codex",
            vec![
                "gh".to_owned(),
                "pr".to_owned(),
                "view".to_owned(),
                "42".to_owned(),
            ],
            dir.path().to_path_buf(),
        );

        let git = request.git.expect("git context");
        assert_eq!(git.remote.as_deref(), Some("git@github.com:jychp/heim.git"));
        assert_eq!(git.branch.as_deref(), Some("feature/test"));
    }

    #[test]
    fn preflight_allows_all_grant_mode_requests() {
        let request = request(
            ["github.personal-readonly"],
            "gh",
            ["gh", "pr", "view", "42"],
        );
        let grants = vec![grant_policy(
            "github.personal-readonly",
            vec!["gh"],
            vec!["gh pr view *"],
            ApprovalPolicy::grant(),
        )];

        let preflight = evaluate_preflight(&grants, request);

        assert_eq!(preflight.requested_grant_count(), 1);
        assert_eq!(preflight.first_denial(), None);
        assert!(preflight.approval_transports().is_empty());
        assert_eq!(preflight.decisions[0].decision, PolicyDecision::Allow);
    }

    #[test]
    fn preflight_reports_required_approval_transports() {
        let transport = ApprovalTransportName::new("slack").expect("valid transport");
        let request = request(
            ["aws.prod-readonly", "github.drymn-pr-write"],
            "codex",
            ["claude-code"],
        );
        let grants = vec![
            grant_policy(
                "aws.prod-readonly",
                vec!["codex"],
                vec!["claude-code"],
                ApprovalPolicy::jit(transport.clone()),
            ),
            grant_policy(
                "github.drymn-pr-write",
                vec!["codex"],
                vec!["claude-code"],
                ApprovalPolicy::jit(transport.clone()),
            ),
        ];

        let preflight = evaluate_preflight(&grants, request);

        assert_eq!(preflight.first_denial(), None);
        assert_eq!(
            preflight
                .approval_transports()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![transport.to_string()]
        );
    }

    #[test]
    fn preflight_keeps_first_denial() {
        let request = request(
            ["github.personal-readonly", "aws.prod-readonly"],
            "codex",
            ["aws", "s3", "ls"],
        );
        let grants = vec![grant_policy(
            "aws.prod-readonly",
            vec!["codex"],
            vec!["aws *"],
            ApprovalPolicy::grant(),
        )];

        let preflight = evaluate_preflight(&grants, request);
        let denial = preflight.first_denial().expect("first denial");

        assert_eq!(denial.grant, "github.personal-readonly");
        assert_eq!(
            denial.deny_reason(),
            Some(&DenyReason::UnknownGrant {
                grant: "github.personal-readonly".to_owned()
            })
        );
    }

    fn request<const G: usize, const C: usize>(
        grants: [&str; G],
        requester: &str,
        command: [&str; C],
    ) -> ExecutionRequest {
        ExecutionRequest::new(
            grants.into_iter().map(str::to_owned).collect(),
            requester,
            command.into_iter().map(str::to_owned).collect(),
            PathBuf::from("/workspace"),
        )
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
        .expect("valid grant policy")
    }

    fn run_command<const N: usize>(cwd: &Path, command: [&str; N]) {
        let status = Command::new(command[0])
            .args(&command[1..])
            .current_dir(cwd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run command");
        assert!(status.success(), "{command:?} failed");
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "heim-exec-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temp directory");

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
