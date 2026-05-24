use std::path::PathBuf;
use std::{ffi::OsStr, fmt};

use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};
use heim_exec::{ExecutionPreflight, ExecutionRequest, evaluate_preflight};
use heim_policy::{DenyReason, PolicyDecision, PolicyRequest, evaluate_policy};

const NOT_IMPLEMENTED_EXIT_CODE: i32 = 2;
const POLICY_DENIED_EXIT_CODE: i32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub struct CommandResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "heim",
    version,
    disable_help_subcommand = true,
    about = "Local-first JIT credential and capability broker."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check the local Heim CLI installation.
    Doctor,
    /// Execute a command with one or more named grants.
    Exec {
        /// Single policy file to evaluate instead of the default policy directory.
        #[arg(long, conflicts_with = "dir")]
        file: Option<PathBuf>,

        /// Policy directory to evaluate instead of the default policy directory.
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Grant names to request for the command.
        #[arg(required = true, num_args = 1..)]
        grants: Vec<String>,

        /// Command and arguments to execute after `--`.
        #[arg(required = true, last = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Manage Heim configuration.
    Config,
    /// Inspect and test policy definitions.
    Policy {
        #[command(subcommand)]
        command: Option<PolicyCommand>,
    },
    /// Inspect local audit events.
    Audit,
    /// Inspect and manage approval requests.
    Approvals,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Validate policy configuration.
    Validate {
        /// Single policy file to validate instead of the default policy directory.
        #[arg(long, conflicts_with = "dir")]
        file: Option<PathBuf>,

        /// Policy directory to validate instead of the default policy directory.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Evaluate one grant request against policy configuration.
    Check {
        /// Single policy file to evaluate instead of the default policy directory.
        #[arg(long, conflicts_with = "dir")]
        file: Option<PathBuf>,

        /// Policy directory to evaluate instead of the default policy directory.
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Grant name to request.
        grant: String,

        /// Requesting binary name.
        #[arg(long)]
        requester: String,

        /// Command and arguments to check after `--`.
        #[arg(required = true, last = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

pub fn run_from<I, T>(args: I) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    run_from_with_requester(args, infer_requester_from_parent_process)
}

fn run_from_with_requester<I, T, F>(args: I, infer_requester: F) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
    F: FnOnce() -> Result<String, RequesterInferenceError>,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => run(cli, infer_requester),
        Err(error) => {
            let output = error.to_string();
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                CommandResult {
                    code: 0,
                    stdout: output,
                    stderr: String::new(),
                }
            } else {
                CommandResult {
                    code: error.exit_code(),
                    stdout: String::new(),
                    stderr: output,
                }
            }
        }
    }
}

fn run<F>(cli: Cli, infer_requester: F) -> CommandResult
where
    F: FnOnce() -> Result<String, RequesterInferenceError>,
{
    match cli.command {
        Some(Command::Doctor) => ok("heim: ok\n"),
        Some(Command::Exec {
            file,
            dir,
            grants,
            command,
        }) => run_exec(file, dir, grants, command, infer_requester),
        Some(Command::Config) => not_implemented("heim config is not implemented yet\n"),
        Some(Command::Policy { command }) => run_policy(command),
        Some(Command::Audit) => not_implemented("heim audit is not implemented yet\n"),
        Some(Command::Approvals) => not_implemented("heim approvals is not implemented yet\n"),
        None => {
            let mut command = Cli::command();
            let mut stdout = Vec::new();
            if let Err(error) = command.write_help(&mut stdout) {
                return CommandResult {
                    code: 1,
                    stdout: String::new(),
                    stderr: format!("failed to render help: {error}\n"),
                };
            }

            CommandResult {
                code: 0,
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::new(),
            }
        }
    }
}

fn run_exec<F>(
    file: Option<PathBuf>,
    dir: Option<PathBuf>,
    grants: Vec<String>,
    command: Vec<String>,
    infer_requester: F,
) -> CommandResult
where
    F: FnOnce() -> Result<String, RequesterInferenceError>,
{
    let document = match load_policy_source(file, dir) {
        Ok(document) => document,
        Err(error) => {
            return CommandResult {
                code: NOT_IMPLEMENTED_EXIT_CODE,
                stdout: String::new(),
                stderr: format!("{error}\n"),
            };
        }
    };

    let requester = match infer_requester() {
        Ok(requester) => requester,
        Err(error) => {
            return CommandResult {
                code: NOT_IMPLEMENTED_EXIT_CODE,
                stdout: String::new(),
                stderr: format!("failed to infer requester from parent process: {error}\n"),
            };
        }
    };

    let request = match ExecutionRequest::collect(grants, requester, command) {
        Ok(request) => request,
        Err(error) => {
            return CommandResult {
                code: NOT_IMPLEMENTED_EXIT_CODE,
                stdout: String::new(),
                stderr: format!("{error}\n"),
            };
        }
    };

    format_exec_preflight(evaluate_preflight(&document.grants, request))
}

fn run_policy(command: Option<PolicyCommand>) -> CommandResult {
    match command {
        Some(PolicyCommand::Validate { file, dir }) => match load_policy_source(file, dir) {
            Ok(document) => ok(format!(
                "policy: ok ({} grant(s), {} approval transport(s))\n",
                document.grants.len(),
                document.approval_transports.len()
            )),
            Err(error) => CommandResult {
                code: 2,
                stdout: String::new(),
                stderr: format!("{error}\n"),
            },
        },
        Some(PolicyCommand::Check {
            file,
            dir,
            grant,
            requester,
            command,
        }) => match load_policy_source(file, dir) {
            Ok(document) => {
                let request = PolicyRequest::new(grant, requester, command);
                format_policy_decision(evaluate_policy(&document.grants, &request))
            }
            Err(error) => CommandResult {
                code: 2,
                stdout: String::new(),
                stderr: format!("{error}\n"),
            },
        },
        None => not_implemented("heim policy is not implemented yet\n"),
    }
}

fn load_policy_source(
    file: Option<PathBuf>,
    dir: Option<PathBuf>,
) -> Result<heim_config::PolicyDocument, heim_config::ConfigError> {
    if let Some(file) = file {
        return heim_config::load_policy_file(file);
    }

    if let Some(dir) = dir {
        return heim_config::load_policy_dir(dir);
    }

    heim_config::load_default_policy_dir()
}

fn format_exec_preflight(preflight: ExecutionPreflight) -> CommandResult {
    if let Some(denial) = preflight.first_denial() {
        let Some(reason) = denial.deny_reason() else {
            return CommandResult {
                code: 1,
                stdout: String::new(),
                stderr: "failed to format policy denial\n".to_owned(),
            };
        };

        return CommandResult {
            code: POLICY_DENIED_EXIT_CODE,
            stdout: String::new(),
            stderr: format!(
                "exec: deny grant {} for requester {} ({})\n",
                denial.grant,
                preflight.request.requester,
                format_deny_reason(reason.clone())
            ),
        };
    }

    let approval_transports = preflight.approval_transports();

    if approval_transports.is_empty() {
        CommandResult {
            code: NOT_IMPLEMENTED_EXIT_CODE,
            stdout: format!(
                "exec: preflight allow (requester {}, {} grant(s))\n",
                preflight.request.requester,
                preflight.requested_grant_count()
            ),
            stderr: "heim exec command execution is not implemented yet\n".to_owned(),
        }
    } else {
        CommandResult {
            code: NOT_IMPLEMENTED_EXIT_CODE,
            stdout: format!(
                "exec: preflight require_approval (requester {}, transport(s) {})\n",
                preflight.request.requester,
                approval_transports
                    .into_iter()
                    .map(|transport| transport.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            stderr: "heim exec approval flow is not implemented yet\n".to_owned(),
        }
    }
}

fn format_policy_decision(decision: PolicyDecision) -> CommandResult {
    match decision {
        PolicyDecision::Allow => ok("policy: allow\n"),
        PolicyDecision::RequireApproval { transport } => ok(format!(
            "policy: require_approval (transport {transport})\n"
        )),
        PolicyDecision::Deny { reason } => CommandResult {
            code: POLICY_DENIED_EXIT_CODE,
            stdout: String::new(),
            stderr: format!("policy: deny ({})\n", format_deny_reason(reason)),
        },
    }
}

fn format_deny_reason(reason: DenyReason) -> String {
    reason.to_string()
}

fn ok(stdout: impl Into<String>) -> CommandResult {
    CommandResult {
        code: 0,
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

fn not_implemented(stderr: impl Into<String>) -> CommandResult {
    CommandResult {
        code: NOT_IMPLEMENTED_EXIT_CODE,
        stdout: String::new(),
        stderr: stderr.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequesterInferenceError(String);

impl RequesterInferenceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RequesterInferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RequesterInferenceError {}

fn infer_requester_from_parent_process() -> Result<String, RequesterInferenceError> {
    let system = sysinfo::System::new_all();
    let current_pid = sysinfo::get_current_pid().map_err(RequesterInferenceError::new)?;
    let current_process = system
        .process(current_pid)
        .ok_or_else(|| RequesterInferenceError::new("current process was not found"))?;
    let parent_pid = current_process
        .parent()
        .ok_or_else(|| RequesterInferenceError::new("parent process was not found"))?;
    let parent_process = system
        .process(parent_pid)
        .ok_or_else(|| RequesterInferenceError::new("parent process metadata was not found"))?;

    process_name(parent_process.name())
        .or_else(|| {
            parent_process
                .exe()
                .and_then(|path| process_name(path.file_name()?))
        })
        .ok_or_else(|| RequesterInferenceError::new("parent process name was empty"))
}

fn process_name(name: &OsStr) -> Option<String> {
    let name = name.to_string_lossy();
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{RequesterInferenceError, run_from, run_from_with_requester};

    fn run_from_requester<I, T>(args: I, requester: &str) -> super::CommandResult
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        run_from_with_requester(args, || Ok(requester.to_owned()))
    }

    #[test]
    fn help_lists_available_commands() {
        let result = run_from(["heim", "--help"]);

        assert_eq!(result.code, 0);
        assert!(result.stdout.contains("Commands:"));
        assert!(result.stdout.contains("doctor"));
        assert!(result.stdout.contains("exec"));
        assert!(!result.stdout.contains("help       "));
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn version_uses_cargo_package_version() {
        let result = run_from(["heim", "--version"]);

        assert_eq!(result.code, 0);
        assert!(result.stdout.contains(env!("CARGO_PKG_VERSION")));
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn doctor_reports_ok() {
        let result = run_from(["heim", "doctor"]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "heim: ok\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn unknown_command_returns_error() {
        let result = run_from(["heim", "wat"]);

        assert_ne!(result.code, 0);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("unrecognized subcommand"));
    }

    #[test]
    fn exec_parses_grants_and_trailing_command_without_executing() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "aws.prod-readonly",
                "--",
                "aws",
                "sts",
                "get-caller-identity",
            ],
            "codex",
        );

        assert_eq!(result.code, 2);
        assert_eq!(
            result.stdout,
            "exec: preflight require_approval (requester codex, transport(s) slack)\n"
        );
        assert!(
            result
                .stderr
                .contains("heim exec approval flow is not implemented yet")
        );
    }

    #[test]
    fn exec_preflight_allows_grant_policy() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            "gh",
        );

        assert_eq!(result.code, 2);
        assert_eq!(
            result.stdout,
            "exec: preflight allow (requester gh, 1 grant(s))\n"
        );
        assert!(
            result
                .stderr
                .contains("heim exec command execution is not implemented yet")
        );
    }

    #[test]
    fn exec_preflight_denies_policy_mismatch() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            "codex",
        );

        assert_eq!(result.code, 3);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("exec: deny grant github.personal-readonly for requester codex")
        );
    }

    #[test]
    fn exec_preflight_requires_approval_when_any_grant_requires_jit() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "github.personal-readonly",
                "github.drymn-pr-write",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            "gh",
        );

        assert_eq!(result.code, 2);
        assert_eq!(
            result.stdout,
            "exec: preflight require_approval (requester gh, transport(s) slack)\n"
        );
        assert!(
            result
                .stderr
                .contains("heim exec approval flow is not implemented yet")
        );
    }

    #[test]
    fn exec_preflight_denies_before_reporting_approval() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "aws.prod-readonly",
                "github.personal-readonly",
                "--",
                "aws",
                "sts",
                "get-caller-identity",
            ],
            "codex",
        );

        assert_eq!(result.code, 3);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("exec: deny grant github.personal-readonly for requester codex")
        );
    }

    #[test]
    fn exec_reports_requester_inference_failure() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_with_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            || Err(RequesterInferenceError::new("no parent")),
        );

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("failed to infer requester from parent process: no parent")
        );
    }

    #[test]
    fn future_commands_are_parsed_but_not_implemented() {
        for command in ["config", "audit", "approvals"] {
            let result = run_from(["heim", command]);

            assert_eq!(result.code, 2);
            assert!(result.stdout.is_empty());
            assert!(result.stderr.contains("not implemented yet"));
        }
    }

    #[test]
    fn policy_without_subcommand_is_not_implemented_yet() {
        let result = run_from(["heim", "policy"]);

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("not implemented yet"));
    }

    #[test]
    fn policy_validate_reports_valid_file() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from(["heim", "policy", "validate", "--file", &file]);

        assert_eq!(result.code, 0);
        assert_eq!(
            result.stdout,
            "policy: ok (3 grant(s), 1 approval transport(s))\n"
        );
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn policy_validate_reports_valid_directory() {
        let dir = format!("{}/../../examples/policies", env!("CARGO_MANIFEST_DIR"));
        let result = run_from(["heim", "policy", "validate", "--dir", &dir]);

        assert_eq!(result.code, 0);
        assert_eq!(
            result.stdout,
            "policy: ok (3 grant(s), 1 approval transport(s))\n"
        );
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn policy_validate_reports_missing_file() {
        let result = run_from([
            "heim",
            "policy",
            "validate",
            "--file",
            "missing-policy.toml",
        ]);

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("failed to read policy file"));
    }

    #[test]
    fn policy_check_reports_jit_decision() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from([
            "heim",
            "policy",
            "check",
            "--file",
            &file,
            "aws.prod-readonly",
            "--requester",
            "codex",
            "--",
            "aws",
            "sts",
            "get-caller-identity",
        ]);

        assert_eq!(result.code, 0);
        assert_eq!(
            result.stdout,
            "policy: require_approval (transport slack)\n"
        );
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn policy_check_can_evaluate_directory() {
        let dir = format!("{}/../../examples/policies", env!("CARGO_MANIFEST_DIR"));
        let result = run_from([
            "heim",
            "policy",
            "check",
            "--dir",
            &dir,
            "github.personal-readonly",
            "--requester",
            "gh",
            "--",
            "gh",
            "pr",
            "view",
            "42",
        ]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "policy: allow\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn policy_check_reports_grant_decision() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from([
            "heim",
            "policy",
            "check",
            "--file",
            &file,
            "github.personal-readonly",
            "--requester",
            "gh",
            "--",
            "gh",
            "pr",
            "view",
            "42",
        ]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "policy: allow\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn policy_check_reports_denial() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from([
            "heim",
            "policy",
            "check",
            "--file",
            &file,
            "github.personal-readonly",
            "--requester",
            "codex",
            "--",
            "gh",
            "pr",
            "view",
            "42",
        ]);

        assert_eq!(result.code, 3);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("policy: deny (requester codex is not allowed)")
        );
    }

    #[test]
    fn policy_check_reports_unknown_grant_denial() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from([
            "heim",
            "policy",
            "check",
            "--file",
            &file,
            "aws.missing",
            "--requester",
            "codex",
            "--",
            "aws",
            "sts",
            "get-caller-identity",
        ]);

        assert_eq!(result.code, 3);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("policy: deny (unknown grant aws.missing)")
        );
    }

    #[test]
    fn policy_check_reports_command_denial() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from([
            "heim",
            "policy",
            "check",
            "--file",
            &file,
            "github.personal-readonly",
            "--requester",
            "gh",
            "--",
            "gh",
            "repo",
            "delete",
            "drymn/backend",
        ]);

        assert_eq!(result.code, 3);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("policy: deny (command gh repo delete drymn/backend is not allowed)")
        );
    }
}
