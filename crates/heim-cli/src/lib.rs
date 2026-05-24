use std::path::PathBuf;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ffi::OsStr, fmt};

use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};
use heim_core::{ApprovalMode, GrantPolicy};
use heim_exec::{ExecutionPreflight, ExecutionRequest, evaluate_preflight};
use heim_policy::{DenyReason, PolicyDecision, PolicyRequest, evaluate_policy};

const NOT_IMPLEMENTED_EXIT_CODE: i32 = 2;
const POLICY_DENIED_EXIT_CODE: i32 = 3;
const AUDIT_ERROR_EXIT_CODE: i32 = 4;

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
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommand>,
    },
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

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate Heim provider configuration.
    Validate {
        /// Config file to validate instead of the default config file.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Policy file to validate against provider references in the config.
        #[arg(long)]
        policy_file: Option<PathBuf>,

        /// Unsafe local auth file to validate.
        #[arg(long)]
        auth_file: Option<PathBuf>,
    },
}

pub fn run_from<I, T>(args: I) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    run_from_with_context(
        args,
        infer_requester_from_parent_process,
        default_audit_context,
        append_default_audit_event,
        execute_command,
    )
}

#[cfg(test)]
fn run_from_with_requester<I, T, F>(args: I, infer_requester: F) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
    F: FnOnce() -> Result<String, RequesterInferenceError>,
{
    run_from_with_context(
        args,
        infer_requester,
        test_audit_context,
        |_| Ok(()),
        test_execute_command,
    )
}

fn run_from_with_context<I, T, F, C, A>(
    args: I,
    infer_requester: F,
    audit_context: C,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String]) -> CommandResult,
) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
    F: FnOnce() -> Result<String, RequesterInferenceError>,
    C: FnOnce() -> AuditContext,
    A: FnOnce(&heim_audit::AuditEvent) -> Result<(), heim_audit::AuditLogError>,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => run(
            cli,
            infer_requester,
            audit_context,
            append_audit_event,
            execute_command,
        ),
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

fn run<F, C, A>(
    cli: Cli,
    infer_requester: F,
    audit_context: C,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String]) -> CommandResult,
) -> CommandResult
where
    F: FnOnce() -> Result<String, RequesterInferenceError>,
    C: FnOnce() -> AuditContext,
    A: FnOnce(&heim_audit::AuditEvent) -> Result<(), heim_audit::AuditLogError>,
{
    match cli.command {
        Some(Command::Doctor) => ok("heim: ok\n"),
        Some(Command::Exec {
            file,
            dir,
            grants,
            command,
        }) => run_exec(
            PolicySource { file, dir },
            grants,
            command,
            infer_requester,
            audit_context,
            append_audit_event,
            execute_command,
        ),
        Some(Command::Config { command }) => run_config(command),
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

fn run_exec<F, C, A>(
    policy_source: PolicySource,
    grants: Vec<String>,
    command: Vec<String>,
    infer_requester: F,
    audit_context: C,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String]) -> CommandResult,
) -> CommandResult
where
    F: FnOnce() -> Result<String, RequesterInferenceError>,
    C: FnOnce() -> AuditContext,
    A: FnOnce(&heim_audit::AuditEvent) -> Result<(), heim_audit::AuditLogError>,
{
    let document = match load_policy_source(policy_source) {
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

    let preflight = evaluate_preflight(&document.grants, request);
    let event = audit_event_from_preflight(
        &preflight,
        &document.grants,
        audit_context(),
        env!("CARGO_PKG_VERSION"),
    );

    if let Err(error) = append_audit_event(&event) {
        return CommandResult {
            code: AUDIT_ERROR_EXIT_CODE,
            stdout: String::new(),
            stderr: format!("failed to write exec audit event: {error}\n"),
        };
    }

    run_exec_preflight(preflight, execute_command)
}

fn run_policy(command: Option<PolicyCommand>) -> CommandResult {
    match command {
        Some(PolicyCommand::Validate { file, dir }) => {
            match load_policy_source(PolicySource { file, dir }) {
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
            }
        }
        Some(PolicyCommand::Check {
            file,
            dir,
            grant,
            requester,
            command,
        }) => match load_policy_source(PolicySource { file, dir }) {
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

fn run_config(command: Option<ConfigCommand>) -> CommandResult {
    match command {
        Some(ConfigCommand::Validate {
            file,
            policy_file,
            auth_file,
        }) => {
            let config = match file {
                Some(file) => heim_config::load_config_file(file),
                None => heim_config::load_default_config_file(),
            };

            let config = match config {
                Ok(config) => config,
                Err(error) => {
                    return CommandResult {
                        code: 2,
                        stdout: String::new(),
                        stderr: format!("{error}\n"),
                    };
                }
            };

            if let Some(policy_file) = policy_file {
                let policy = match heim_config::load_policy_file(policy_file) {
                    Ok(policy) => policy,
                    Err(error) => {
                        return CommandResult {
                            code: 2,
                            stdout: String::new(),
                            stderr: format!("{error}\n"),
                        };
                    }
                };

                if let Err(error) = heim_config::validate_policy_provider_refs(&policy, &config) {
                    return CommandResult {
                        code: 2,
                        stdout: String::new(),
                        stderr: format!("{error}\n"),
                    };
                }
            }

            if let Some(auth_file) = auth_file
                && let Err(error) = heim_config::load_auth_file(auth_file)
            {
                return CommandResult {
                    code: 2,
                    stdout: String::new(),
                    stderr: format!("{error}\n"),
                };
            }

            ok(format!(
                "config: ok ({} provider(s))\n",
                config.providers.len()
            ))
        }
        None => not_implemented("heim config is not implemented yet\n"),
    }
}

struct PolicySource {
    file: Option<PathBuf>,
    dir: Option<PathBuf>,
}

fn load_policy_source(
    source: PolicySource,
) -> Result<heim_config::PolicyDocument, heim_config::ConfigError> {
    if let Some(file) = source.file {
        return heim_config::load_policy_file(file);
    }

    if let Some(dir) = source.dir {
        return heim_config::load_policy_dir(dir);
    }

    heim_config::load_default_policy_dir()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditContext {
    request_id: String,
    timestamp: String,
}

fn default_audit_context() -> AuditContext {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    AuditContext {
        request_id: format!(
            "heim-{}-{}-{}",
            std::process::id(),
            now.as_secs(),
            now.subsec_nanos()
        ),
        timestamp: format_unix_timestamp(now.as_secs(), now.subsec_nanos()),
    }
}

fn format_unix_timestamp(seconds: u64, nanos: u32) -> String {
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z")
}

fn civil_from_unix_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year, month as u64, day as u64)
}

#[cfg(test)]
fn test_audit_context() -> AuditContext {
    AuditContext {
        request_id: "test-request".to_owned(),
        timestamp: "2026-05-24T12:00:00Z".to_owned(),
    }
}

#[cfg(test)]
fn test_execute_command(_: &[String]) -> CommandResult {
    CommandResult {
        code: 0,
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn append_default_audit_event(
    event: &heim_audit::AuditEvent,
) -> Result<(), heim_audit::AuditLogError> {
    heim_audit::JsonlAuditSink::open_default()?.append(event)
}

fn audit_event_from_preflight(
    preflight: &ExecutionPreflight,
    grants: &[GrantPolicy],
    context: AuditContext,
    heim_version: &str,
) -> heim_audit::AuditEvent {
    let decision = audit_decision_from_preflight(preflight);
    let mut event = heim_audit::AuditEvent::new(
        context.request_id,
        context.timestamp,
        preflight.request.requester.clone(),
        preflight.request.command.clone(),
        preflight.request.cwd.clone(),
        heim_version,
        decision,
    )
    .with_grants(audit_grants_from_preflight(preflight, grants));

    if let Some(git) = &preflight.request.git {
        event = event.with_git(heim_audit::AuditGitContext::new(
            git.remote.clone(),
            git.branch.clone(),
        ));
    }

    event
}

fn audit_decision_from_preflight(preflight: &ExecutionPreflight) -> heim_audit::AuditDecision {
    if let Some(denial) = preflight.first_denial() {
        let reason = denial
            .deny_reason()
            .map(|reason| reason.to_string())
            .unwrap_or_else(|| "policy denied request".to_owned());
        return heim_audit::AuditDecision::Deny { reason };
    }

    let transports = preflight
        .approval_transports()
        .into_iter()
        .map(|transport| transport.to_string())
        .collect::<Vec<_>>();

    if transports.is_empty() {
        heim_audit::AuditDecision::Allow
    } else {
        heim_audit::AuditDecision::RequireApproval { transports }
    }
}

fn audit_grants_from_preflight(
    preflight: &ExecutionPreflight,
    grants: &[GrantPolicy],
) -> Vec<heim_audit::AuditGrant> {
    preflight
        .decisions
        .iter()
        .map(|decision| {
            let grant = grants
                .iter()
                .find(|candidate| candidate.name.as_str() == decision.grant);
            let provider = grant
                .map(|grant| grant.provider.as_str())
                .unwrap_or("unknown");
            let approval_required = grant
                .map(|grant| matches!(grant.approval.mode, ApprovalMode::Jit { .. }))
                .unwrap_or(false);

            heim_audit::AuditGrant::new(&decision.grant, provider, approval_required)
        })
        .collect()
}

fn run_exec_preflight(
    preflight: ExecutionPreflight,
    execute_command: impl FnOnce(&[String]) -> CommandResult,
) -> CommandResult {
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
        execute_command(&preflight.request.command)
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

fn execute_command(command: &[String]) -> CommandResult {
    let Some((program, args)) = command.split_first() else {
        return CommandResult {
            code: 1,
            stdout: String::new(),
            stderr: "exec: command is empty\n".to_owned(),
        };
    };

    let status = match std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            return CommandResult {
                code: 1,
                stdout: String::new(),
                stderr: format!("failed to execute command {program}: {error}\n"),
            };
        }
    };

    CommandResult {
        code: status.code().unwrap_or(1),
        stdout: String::new(),
        stderr: String::new(),
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
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use heim_audit::AuditDecision;

    use super::{
        RequesterInferenceError, run_from, run_from_with_context, run_from_with_requester,
    };

    fn run_from_requester<I, T>(args: I, requester: &str) -> super::CommandResult
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        run_from_with_requester(args, || Ok(requester.to_owned()))
    }

    fn run_from_requester_with_audit<I, T>(
        args: I,
        requester: &str,
    ) -> (super::CommandResult, heim_audit::AuditEvent)
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let event = Rc::new(RefCell::new(None));
        let event_sink = Rc::clone(&event);
        let result = run_from_with_context(
            args,
            || Ok(requester.to_owned()),
            super::test_audit_context,
            |audit_event| {
                *event_sink.borrow_mut() = Some(audit_event.clone());
                Ok(())
            },
            super::test_execute_command,
        );
        let event = event.borrow_mut().take().expect("audit event");

        (result, event)
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
    fn config_validate_accepts_config_file() {
        let file = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from(["heim", "config", "validate", "--file", &file]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "config: ok (3 provider(s))\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn config_validate_checks_policy_provider_refs() {
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let policy = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from([
            "heim",
            "config",
            "validate",
            "--file",
            &config,
            "--policy-file",
            &policy,
        ]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "config: ok (3 provider(s))\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn config_validate_rejects_unknown_policy_provider_ref() {
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let policy = TestFile::new(
            "policy",
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "missing_provider"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        );
        let result = run_from([
            "heim",
            "config",
            "validate",
            "--file",
            &config,
            "--policy-file",
            policy.path().to_str().expect("utf-8 path"),
        ]);

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("grant aws.prod-readonly references provider missing_provider")
        );
    }

    #[test]
    fn config_validate_rejects_invalid_config_file() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from(["heim", "config", "validate", "--file", &file]);

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("Heim config must contain"));
    }

    #[test]
    fn audit_timestamp_uses_utc_rfc3339_shape() {
        assert_eq!(
            super::format_unix_timestamp(0, 0),
            "1970-01-01T00:00:00.000000000Z"
        );
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

        assert_eq!(result.code, 0);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn exec_runs_allowed_command_and_propagates_exit_code() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let command_seen = Rc::new(RefCell::new(Vec::new()));
        let command_sink = Rc::clone(&command_seen);
        let result = run_from_with_context(
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
            || Ok("gh".to_owned()),
            super::test_audit_context,
            |_| Ok(()),
            |command| {
                *command_sink.borrow_mut() = command.to_vec();
                super::CommandResult {
                    code: 17,
                    stdout: "child stdout\n".to_owned(),
                    stderr: "child stderr\n".to_owned(),
                }
            },
        );

        assert_eq!(result.code, 17);
        assert_eq!(result.stdout, "child stdout\n");
        assert_eq!(result.stderr, "child stderr\n");
        assert_eq!(command_seen.borrow().as_slice(), ["gh", "pr", "view", "42"]);
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
    fn exec_emits_allow_audit_event() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let (result, event) = run_from_requester_with_audit(
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

        assert_eq!(result.code, 0);
        assert_eq!(event.request_id, "test-request");
        assert_eq!(event.requester, "gh");
        assert_eq!(event.command, ["gh", "pr", "view", "42"]);
        assert_eq!(event.decision, AuditDecision::Allow);
        assert_eq!(event.grants.len(), 1);
        assert_eq!(event.grants[0].name, "github.personal-readonly");
        assert_eq!(event.grants[0].provider, "github_personal");
        assert!(!event.grants[0].approval_required);
        assert_eq!(event.heim_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn exec_emits_denial_audit_event() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let (result, event) = run_from_requester_with_audit(
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
        assert_eq!(
            event.decision,
            AuditDecision::Deny {
                reason: "requester codex is not allowed".to_owned()
            }
        );
        assert_eq!(event.grants[0].name, "github.personal-readonly");
        assert_eq!(event.grants[0].provider, "github_personal");
    }

    #[test]
    fn exec_emits_require_approval_audit_event() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let (result, event) = run_from_requester_with_audit(
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
            event.decision,
            AuditDecision::RequireApproval {
                transports: vec!["slack".to_owned()]
            }
        );
        assert_eq!(event.grants[0].name, "aws.prod-readonly");
        assert_eq!(event.grants[0].provider, "aws_prod");
        assert!(event.grants[0].approval_required);
    }

    #[test]
    fn exec_fails_when_audit_event_write_fails() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_with_context(
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
            || Ok("gh".to_owned()),
            super::test_audit_context,
            |_| {
                let sink = heim_audit::JsonlAuditSink::new("/dev/null/audit.jsonl");
                sink.append(&sample_audit_event())
            },
            |_| panic!("command should not execute when audit write fails"),
        );

        assert_eq!(result.code, 4);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("failed to write exec audit event"));
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

    fn sample_audit_event() -> heim_audit::AuditEvent {
        heim_audit::AuditEvent::new(
            "test-request",
            "2026-05-24T12:00:00Z",
            "gh",
            ["gh", "pr", "view", "42"],
            std::path::PathBuf::from("/workspace"),
            env!("CARGO_PKG_VERSION"),
            AuditDecision::Allow,
        )
    }

    struct TestFile {
        path: PathBuf,
    }

    impl TestFile {
        fn new(prefix: &str, contents: &str) -> Self {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "heim-cli-{prefix}-{}-{}.toml",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::write(&path, contents).expect("write test file");

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
