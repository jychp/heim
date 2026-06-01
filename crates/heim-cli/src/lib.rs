use std::path::PathBuf;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ffi::OsStr, fmt};

use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};
use heim_approvals::{
    ApprovalDecision, ApprovalError, ApprovalGitContext, ApprovalGrant, ApprovalProvider,
    ApprovalRequest, SlackApprovalProvider, SlackBotToken,
};
use heim_core::{ApprovalMode, GrantPolicy};
use heim_exec::{ExecutionPreflight, ExecutionRequest, evaluate_preflight};
use heim_policy::{DenyReason, PolicyDecision, PolicyRequest, evaluate_policy};
use heim_providers::{
    AwsStsProvider, CredentialEnvVar, CredentialProvider, CredentialRequest, GithubAppProvider,
    GithubPatProvider, IssuedCredential, ProviderGitContext,
};
use heim_sources::{ProviderLocalSecrets, SecretKind, SecretSource, UnsafeLocalAuthSource};

const NOT_IMPLEMENTED_EXIT_CODE: i32 = 2;
const POLICY_DENIED_EXIT_CODE: i32 = 3;
const AUDIT_ERROR_EXIT_CODE: i32 = 4;
const CREDENTIAL_ERROR_EXIT_CODE: i32 = 5;
const APPROVAL_ERROR_EXIT_CODE: i32 = 6;

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

        /// Config file to use instead of the default config file.
        #[arg(long)]
        config_file: Option<PathBuf>,

        /// Unsafe local auth file to use instead of the default auth file.
        #[arg(long)]
        auth_file: Option<PathBuf>,

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
    Audit {
        #[command(subcommand)]
        command: Option<AuditCommand>,
    },
    /// Inspect and manage approval requests.
    Approvals,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// List local audit events.
    List {
        /// Audit JSONL file to read instead of the default audit log file.
        #[arg(long)]
        file: Option<PathBuf>,
    },
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
    /// Validate Heim configuration.
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
    run_from_with_context_runtime(
        args,
        infer_requester_from_parent_process,
        default_audit_context,
        ApprovalRuntime::built_in(),
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
        UnsupportedApprovalProvider,
        |_| Ok(()),
        test_execute_command,
    )
}

#[cfg(test)]
fn run_from_with_context<I, T, F, C, A>(
    args: I,
    infer_requester: F,
    audit_context: C,
    approval_provider: impl ApprovalProvider,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String], &[CredentialEnvVar]) -> CommandResult,
) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
    F: FnOnce() -> Result<String, RequesterInferenceError>,
    C: FnOnce() -> AuditContext,
    A: FnOnce(&heim_audit::AuditEvent) -> Result<(), heim_audit::AuditLogError>,
{
    run_from_with_context_runtime(
        args,
        infer_requester,
        audit_context,
        ApprovalRuntime::Injected(&approval_provider),
        append_audit_event,
        execute_command,
    )
}

fn run_from_with_context_runtime<I, T, F, C, A>(
    args: I,
    infer_requester: F,
    audit_context: C,
    approval_runtime: ApprovalRuntime<'_>,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String], &[CredentialEnvVar]) -> CommandResult,
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
            approval_runtime,
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

#[cfg(test)]
fn run_from_with_context_and_approvals<I, T, F, C, A, P>(
    args: I,
    infer_requester: F,
    audit_context: C,
    approval_provider: P,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String], &[CredentialEnvVar]) -> CommandResult,
) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
    F: FnOnce() -> Result<String, RequesterInferenceError>,
    C: FnOnce() -> AuditContext,
    A: FnOnce(&heim_audit::AuditEvent) -> Result<(), heim_audit::AuditLogError>,
    P: ApprovalProvider,
{
    run_from_with_context(
        args,
        infer_requester,
        audit_context,
        approval_provider,
        append_audit_event,
        execute_command,
    )
}

fn run<F, C, A>(
    cli: Cli,
    infer_requester: F,
    audit_context: C,
    approval_runtime: ApprovalRuntime<'_>,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String], &[CredentialEnvVar]) -> CommandResult,
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
            config_file,
            auth_file,
            grants,
            command,
        }) => run_exec(
            ExecCliRequest {
                policy_source: PolicySource { file, dir },
                config_source: ConfigSource {
                    file: config_file,
                    auth_file,
                },
                grants,
                command,
            },
            infer_requester,
            audit_context,
            approval_runtime,
            append_audit_event,
            execute_command,
        ),
        Some(Command::Config { command }) => run_config(command),
        Some(Command::Policy { command }) => run_policy(command),
        Some(Command::Audit { command }) => run_audit(command),
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
    cli_request: ExecCliRequest,
    infer_requester: F,
    audit_context: C,
    approval_runtime: ApprovalRuntime<'_>,
    append_audit_event: A,
    execute_command: impl FnOnce(&[String], &[CredentialEnvVar]) -> CommandResult,
) -> CommandResult
where
    F: FnOnce() -> Result<String, RequesterInferenceError>,
    C: FnOnce() -> AuditContext,
    A: FnOnce(&heim_audit::AuditEvent) -> Result<(), heim_audit::AuditLogError>,
{
    let document = match load_policy_source(cli_request.policy_source) {
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

    let request =
        match ExecutionRequest::collect(cli_request.grants, requester, cli_request.command) {
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
    let context = audit_context();
    let approval_requests =
        if preflight.first_denial().is_none() && !preflight.approval_transports().is_empty() {
            match approval_requests_for_preflight(
                &preflight,
                &document,
                &cli_request.config_source,
                &context.request_id,
            ) {
                Ok(requests) => requests,
                Err(error) => {
                    return CommandResult {
                        code: APPROVAL_ERROR_EXIT_CODE,
                        stdout: String::new(),
                        stderr: format!("failed to prepare approval request: {error}\n"),
                    };
                }
            }
        } else {
            Vec::new()
        };

    if preflight.first_denial().is_none() && !approval_requests.is_empty() {
        let event = audit_event_from_preflight(
            &preflight,
            &document.grants,
            &[],
            context,
            env!("CARGO_PKG_VERSION"),
        );

        if let Err(error) = append_audit_event(&event) {
            return CommandResult {
                code: AUDIT_ERROR_EXIT_CODE,
                stdout: String::new(),
                stderr: format!("failed to write exec audit event: {error}\n"),
            };
        }

        if let Err(error) = apply_approval_requests(
            approval_runtime,
            &cli_request.config_source,
            &approval_requests,
        ) {
            return CommandResult {
                code: APPROVAL_ERROR_EXIT_CODE,
                stdout: String::new(),
                stderr: format!("failed to obtain approval: {error}\n"),
            };
        }

        let credentials = match issue_credentials_for_preflight(
            &preflight,
            &document.grants,
            cli_request.config_source,
        ) {
            Ok(credentials) => credentials,
            Err(error) => {
                return CommandResult {
                    code: CREDENTIAL_ERROR_EXIT_CODE,
                    stdout: String::new(),
                    stderr: format!("failed to issue credentials: {error}\n"),
                };
            }
        };

        return execute_preflight_command(&preflight, &credentials, execute_command);
    }

    let credentials = if preflight.first_denial().is_none() {
        match issue_credentials_for_preflight(
            &preflight,
            &document.grants,
            cli_request.config_source,
        ) {
            Ok(credentials) => credentials,
            Err(error) => {
                return CommandResult {
                    code: CREDENTIAL_ERROR_EXIT_CODE,
                    stdout: String::new(),
                    stderr: format!("failed to issue credentials: {error}\n"),
                };
            }
        }
    } else {
        Vec::new()
    };
    let event = audit_event_from_preflight(
        &preflight,
        &document.grants,
        &credentials,
        context,
        env!("CARGO_PKG_VERSION"),
    );

    if let Err(error) = append_audit_event(&event) {
        return CommandResult {
            code: AUDIT_ERROR_EXIT_CODE,
            stdout: String::new(),
            stderr: format!("failed to write exec audit event: {error}\n"),
        };
    }

    run_exec_preflight(preflight, credentials, execute_command)
}

fn run_audit(command: Option<AuditCommand>) -> CommandResult {
    match command {
        Some(AuditCommand::List { file }) => {
            let events = match file {
                Some(file) => heim_audit::read_audit_events(file),
                None => heim_audit::read_default_audit_events(),
            };

            match events {
                Ok(events) => ok(format_audit_events(&events)),
                Err(error) => CommandResult {
                    code: 2,
                    stdout: String::new(),
                    stderr: format!("{error}\n"),
                },
            }
        }
        None => not_implemented("heim audit is not implemented yet\n"),
    }
}

fn run_policy(command: Option<PolicyCommand>) -> CommandResult {
    match command {
        Some(PolicyCommand::Validate { file, dir }) => {
            match load_policy_source(PolicySource { file, dir }) {
                Ok(document) => ok(format!("policy: ok ({} grant(s))\n", document.grants.len())),
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
                "config: ok ({} provider(s), {} approval transport(s))\n",
                config.providers.len(),
                config.approval_transports.len()
            ))
        }
        None => not_implemented("heim config is not implemented yet\n"),
    }
}

struct PolicySource {
    file: Option<PathBuf>,
    dir: Option<PathBuf>,
}

struct ConfigSource {
    file: Option<PathBuf>,
    auth_file: Option<PathBuf>,
}

struct ExecCliRequest {
    policy_source: PolicySource,
    config_source: ConfigSource,
    grants: Vec<String>,
    command: Vec<String>,
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

fn load_config_source(
    source: &ConfigSource,
) -> Result<heim_config::HeimConfig, heim_config::ConfigError> {
    match &source.file {
        Some(file) => heim_config::load_config_file(file),
        None => heim_config::load_default_config_file(),
    }
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
fn test_execute_command(_: &[String], _: &[CredentialEnvVar]) -> CommandResult {
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
    credentials: &[IssuedGrantCredential],
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
    .with_grants(audit_grants_from_preflight(preflight, grants, credentials));

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
    credentials: &[IssuedGrantCredential],
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

            let mut audit_grant =
                heim_audit::AuditGrant::new(&decision.grant, provider, approval_required);
            if let Some(credential) = credentials
                .iter()
                .find(|credential| credential.grant == decision.grant)
            {
                let metadata = credential.credential.metadata();
                audit_grant.credential = Some(
                    heim_audit::AuditCredentialMetadata::new(metadata.kind)
                        .with_env_vars(metadata.env_vars)
                        .with_temp_files(metadata.temp_files),
                );
            }

            audit_grant
        })
        .collect()
}

fn run_exec_preflight(
    preflight: ExecutionPreflight,
    credentials: Vec<IssuedGrantCredential>,
    execute_command: impl FnOnce(&[String], &[CredentialEnvVar]) -> CommandResult,
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
        execute_preflight_command(&preflight, &credentials, execute_command)
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

fn execute_preflight_command(
    preflight: &ExecutionPreflight,
    credentials: &[IssuedGrantCredential],
    execute_command: impl FnOnce(&[String], &[CredentialEnvVar]) -> CommandResult,
) -> CommandResult {
    let env_vars = credentials
        .iter()
        .flat_map(|credential| credential.credential.env_vars())
        .cloned()
        .collect::<Vec<_>>();
    execute_command(&preflight.request.command, &env_vars)
}

fn execute_command(command: &[String], env_vars: &[CredentialEnvVar]) -> CommandResult {
    let Some((program, args)) = command.split_first() else {
        return CommandResult {
            code: 1,
            stdout: String::new(),
            stderr: "exec: command is empty\n".to_owned(),
        };
    };

    let status = match std::process::Command::new(program)
        .args(args)
        .envs(env_vars.iter().map(|env| (env.name(), env.value())))
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

#[cfg(test)]
struct UnsupportedApprovalProvider;

#[cfg(test)]
impl ApprovalProvider for UnsupportedApprovalProvider {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError> {
        Err(ApprovalError::TransportUnavailable {
            transport: request.transport.clone(),
            message: "approval dispatch is not implemented yet".to_owned(),
        })
    }
}

#[derive(Clone, Copy)]
enum ApprovalRuntime<'a> {
    BuiltIn(std::marker::PhantomData<&'a ()>),
    #[cfg(test)]
    Injected(&'a dyn ApprovalProvider),
}

impl<'a> ApprovalRuntime<'a> {
    fn built_in() -> Self {
        Self::BuiltIn(std::marker::PhantomData)
    }
}

fn apply_approval_requests(
    runtime: ApprovalRuntime<'_>,
    config_source: &ConfigSource,
    requests: &[ApprovalRequest],
) -> Result<(), ExecApprovalError> {
    match runtime {
        ApprovalRuntime::BuiltIn(_) => {
            let provider = RuntimeApprovalProvider::from_config_source(config_source, requests)?;
            apply_approval_requests_with_provider(&provider, requests)
        }
        #[cfg(test)]
        ApprovalRuntime::Injected(provider) => {
            apply_approval_requests_with_provider(provider, requests)
        }
    }
}

fn apply_approval_requests_with_provider(
    provider: &dyn ApprovalProvider,
    requests: &[ApprovalRequest],
) -> Result<(), ExecApprovalError> {
    for request in requests {
        let decision = provider
            .request_approval(request)
            .map_err(ExecApprovalError::ApprovalProvider)?;
        validate_approval_decision(request, decision)?;
    }

    Ok(())
}

struct RuntimeApprovalProvider {
    transports: Vec<RuntimeApprovalTransport>,
}

impl RuntimeApprovalProvider {
    fn from_config_source(
        config_source: &ConfigSource,
        requests: &[ApprovalRequest],
    ) -> Result<Self, ExecApprovalError> {
        let config = load_config_source(config_source).map_err(ExecApprovalError::LoadConfig)?;
        let source = match &config_source.auth_file {
            Some(auth_file) => UnsafeLocalAuthSource::load_file(auth_file),
            None => UnsafeLocalAuthSource::load_default(),
        }
        .map_err(ExecApprovalError::ResolveSecret)?;
        let transports = config
            .approval_transports
            .into_iter()
            .filter(|transport| {
                requests
                    .iter()
                    .any(|request| request.transport.as_str() == transport.name.as_str())
            })
            .map(|transport| RuntimeApprovalTransport::from_config(transport, &source))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { transports })
    }
}

impl ApprovalProvider for RuntimeApprovalProvider {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError> {
        let Some(transport) = self
            .transports
            .iter()
            .find(|transport| transport.name() == request.transport.as_str())
        else {
            return Err(ApprovalError::TransportUnavailable {
                transport: request.transport.clone(),
                message: "approval transport is not configured".to_owned(),
            });
        };

        transport.request_approval(request)
    }
}

enum RuntimeApprovalTransport {
    Slack(SlackApprovalProvider),
}

impl RuntimeApprovalTransport {
    fn from_config(
        transport: heim_config::ApprovalTransportConfig,
        source: &UnsafeLocalAuthSource,
    ) -> Result<Self, ExecApprovalError> {
        match transport.kind {
            heim_config::ApprovalTransportKind::Slack { channel, bot_token } => {
                let secret = source
                    .resolve(&bot_token, SecretKind::SlackBotToken)
                    .map_err(ExecApprovalError::ResolveSecret)?;
                let heim_sources::ResolvedSecret::SlackBotToken { token } = secret else {
                    return Err(ExecApprovalError::TransportSecretMismatch {
                        transport: transport.name.to_string(),
                    });
                };
                let bot_token =
                    SlackBotToken::new(token).map_err(ExecApprovalError::SlackConfig)?;
                let provider =
                    SlackApprovalProvider::with_default_client(transport.name, channel, bot_token)
                        .map_err(ExecApprovalError::SlackConfig)?;

                Ok(Self::Slack(provider))
            }
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Slack(provider) => provider.transport_name().as_str(),
        }
    }
}

impl ApprovalProvider for RuntimeApprovalTransport {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalDecision, ApprovalError> {
        match self {
            Self::Slack(provider) => provider.request_approval(request),
        }
    }
}

fn validate_approval_decision(
    request: &ApprovalRequest,
    decision: ApprovalDecision,
) -> Result<(), ExecApprovalError> {
    match decision {
        ApprovalDecision::Approved(_) => Ok(()),
        ApprovalDecision::ApprovedWithOption { option, .. } => {
            if request
                .options
                .iter()
                .any(|candidate| candidate.id == option.id)
            {
                Ok(())
            } else {
                Err(ExecApprovalError::UnconfiguredApprovalOption {
                    transport: request.transport.to_string(),
                    option: option.id,
                })
            }
        }
        ApprovalDecision::Denied(_) => Err(ExecApprovalError::ApprovalDenied {
            transport: request.transport.to_string(),
        }),
        ApprovalDecision::TimedOut => Err(ExecApprovalError::ApprovalTimedOut {
            transport: request.transport.to_string(),
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssuedGrantCredential {
    grant: String,
    credential: IssuedCredential,
}

fn issue_credentials_for_preflight(
    preflight: &ExecutionPreflight,
    grants: &[GrantPolicy],
    config_source: ConfigSource,
) -> Result<Vec<IssuedGrantCredential>, ExecCredentialError> {
    let config = load_config_source(&config_source).map_err(ExecCredentialError::LoadConfig)?;
    let mut credentials = Vec::new();

    for decision in &preflight.decisions {
        let grant = grants
            .iter()
            .find(|candidate| candidate.name.as_str() == decision.grant)
            .ok_or_else(|| ExecCredentialError::MissingGrant {
                grant: decision.grant.clone(),
            })?;
        let provider = config.provider(grant.provider.as_str()).ok_or_else(|| {
            ExecCredentialError::MissingProviderConfig {
                grant: decision.grant.clone(),
                provider: grant.provider.to_string(),
            }
        })?;
        let request = credential_request_for_grant(preflight, grant);
        let credential = match provider {
            heim_config::ProviderConfig::GithubPat(_) => {
                let source = match &config_source.auth_file {
                    Some(auth_file) => UnsafeLocalAuthSource::load_file(auth_file),
                    None => UnsafeLocalAuthSource::load_default(),
                }
                .map_err(ExecCredentialError::ResolveSecret)?;
                let ProviderLocalSecrets::GithubPat { token } =
                    source
                        .resolve_provider(provider)
                        .map_err(ExecCredentialError::ResolveSecret)?
                else {
                    return Err(ExecCredentialError::ProviderSecretMismatch {
                        provider: grant.provider.to_string(),
                    });
                };
                GithubPatProvider::from_secret(token)
                    .map_err(ExecCredentialError::IssueCredential)?
                    .issue(&request)
                    .map_err(ExecCredentialError::IssueCredential)?
            }
            heim_config::ProviderConfig::AwsSts(provider_config) => {
                AwsStsProvider::with_default_client(
                    provider_config.role_arn.clone(),
                    provider_config.region.clone(),
                    provider_config.duration.clone(),
                    provider_config.source_profile.clone(),
                    provider_config.session_name.clone(),
                    provider_config.external_id.clone(),
                )
                .map_err(ExecCredentialError::IssueCredential)?
                .issue(&request)
                .map_err(ExecCredentialError::IssueCredential)?
            }
            heim_config::ProviderConfig::GithubApp(provider_config) => {
                let source = match &config_source.auth_file {
                    Some(auth_file) => UnsafeLocalAuthSource::load_file(auth_file),
                    None => UnsafeLocalAuthSource::load_default(),
                }
                .map_err(ExecCredentialError::ResolveSecret)?;
                let ProviderLocalSecrets::GithubApp { private_key } = source
                    .resolve_provider(provider)
                    .map_err(ExecCredentialError::ResolveSecret)?
                else {
                    return Err(ExecCredentialError::ProviderSecretMismatch {
                        provider: grant.provider.to_string(),
                    });
                };
                GithubAppProvider::from_secret_with_default_client(
                    provider_config.app_id,
                    provider_config.installation_id,
                    provider_config.repositories.clone(),
                    private_key,
                )
                .map_err(ExecCredentialError::IssueCredential)?
                .issue(&request)
                .map_err(ExecCredentialError::IssueCredential)?
            }
        };

        credentials.push(IssuedGrantCredential {
            grant: decision.grant.clone(),
            credential,
        });
    }

    Ok(credentials)
}

fn credential_request_for_grant(
    preflight: &ExecutionPreflight,
    grant: &GrantPolicy,
) -> CredentialRequest {
    let mut request = CredentialRequest::new(
        grant.name.to_string(),
        grant.provider.to_string(),
        preflight.request.requester.clone(),
        preflight.request.command.clone(),
        preflight.request.cwd.clone(),
    );

    if let Some(git) = &preflight.request.git {
        request = request.with_git(ProviderGitContext::new(
            git.remote.clone(),
            git.branch.clone(),
        ));
    }

    request
}

fn approval_requests_for_preflight(
    preflight: &ExecutionPreflight,
    document: &heim_config::PolicyDocument,
    config_source: &ConfigSource,
    request_id: &str,
) -> Result<Vec<ApprovalRequest>, ExecApprovalError> {
    let config = load_config_source(config_source).map_err(ExecApprovalError::LoadConfig)?;
    let mut requests = Vec::new();

    for transport_name in preflight.approval_transports() {
        let transport = config.approval_transport(&transport_name).ok_or_else(|| {
            ExecApprovalError::MissingApprovalTransport {
                transport: transport_name.clone(),
            }
        })?;
        let approval_grants = approval_grants_for_transport(
            &preflight.decisions,
            &document.grants,
            &config,
            transport.name.as_str(),
        )?;
        let mut builder = ApprovalRequest::builder(request_id.to_owned(), transport.name.clone())
            .grants(approval_grants)
            .requester(preflight.request.requester.clone())
            .command(preflight.request.command.clone())
            .cwd(preflight.request.cwd.clone())
            .options(transport.options.clone());

        if let Some(git) = &preflight.request.git {
            builder = builder.git(ApprovalGitContext::new(
                git.remote.clone(),
                git.branch.clone(),
            ));
        }

        requests.push(builder.build().map_err(ExecApprovalError::BuildRequest)?);
    }

    Ok(requests)
}

fn approval_grants_for_transport(
    decisions: &[heim_exec::GrantPreflightDecision],
    grants: &[GrantPolicy],
    config: &heim_config::HeimConfig,
    transport: &str,
) -> Result<Vec<ApprovalGrant>, ExecApprovalError> {
    decisions
        .iter()
        .filter(|decision| match &decision.decision {
            PolicyDecision::RequireApproval {
                transport: decision_transport,
            } => decision_transport.as_str() == transport,
            PolicyDecision::Allow | PolicyDecision::Deny { .. } => false,
        })
        .map(|decision| {
            let grant = grants
                .iter()
                .find(|candidate| candidate.name.as_str() == decision.grant)
                .ok_or_else(|| ExecApprovalError::MissingGrant {
                    grant: decision.grant.clone(),
                })?;
            if !config.contains_provider(grant.provider.as_str()) {
                return Err(ExecApprovalError::MissingProviderConfig {
                    grant: grant.name.to_string(),
                    provider: grant.provider.to_string(),
                });
            }

            Ok(ApprovalGrant::new(
                grant.name.to_string(),
                grant.provider.to_string(),
            ))
        })
        .collect()
}

#[derive(Debug)]
enum ExecApprovalError {
    LoadConfig(heim_config::ConfigError),
    ResolveSecret(heim_sources::SecretSourceError),
    BuildRequest(heim_approvals::ApprovalRequestBuildError),
    ApprovalProvider(heim_approvals::ApprovalError),
    SlackConfig(heim_approvals::SlackApprovalConfigError),
    MissingGrant { grant: String },
    MissingProviderConfig { grant: String, provider: String },
    MissingApprovalTransport { transport: String },
    TransportSecretMismatch { transport: String },
    ApprovalDenied { transport: String },
    ApprovalTimedOut { transport: String },
    UnconfiguredApprovalOption { transport: String, option: String },
}

impl fmt::Display for ExecApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadConfig(source) => write!(formatter, "{source}"),
            Self::ResolveSecret(source) => write!(formatter, "{source}"),
            Self::BuildRequest(source) => write!(formatter, "{source}"),
            Self::ApprovalProvider(source) => write!(formatter, "{source}"),
            Self::SlackConfig(source) => write!(formatter, "{source}"),
            Self::MissingGrant { grant } => {
                write!(
                    formatter,
                    "policy decision referenced missing grant {grant}"
                )
            }
            Self::MissingProviderConfig { grant, provider } => write!(
                formatter,
                "grant {grant} references provider {provider}, but it is not configured"
            ),
            Self::MissingApprovalTransport { transport } => write!(
                formatter,
                "approval transport {transport} is required by policy but is not configured"
            ),
            Self::TransportSecretMismatch { transport } => write!(
                formatter,
                "approval transport {transport} resolved an unexpected local secret"
            ),
            Self::ApprovalDenied { transport } => {
                write!(formatter, "approval request was denied by {transport}")
            }
            Self::ApprovalTimedOut { transport } => {
                write!(formatter, "approval request timed out on {transport}")
            }
            Self::UnconfiguredApprovalOption { transport, option } => write!(
                formatter,
                "approval transport {transport} returned unconfigured option {option}"
            ),
        }
    }
}

impl std::error::Error for ExecApprovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LoadConfig(source) => Some(source),
            Self::ResolveSecret(source) => Some(source),
            Self::BuildRequest(source) => Some(source),
            Self::ApprovalProvider(source) => Some(source),
            Self::SlackConfig(source) => Some(source),
            Self::MissingGrant { .. }
            | Self::MissingProviderConfig { .. }
            | Self::MissingApprovalTransport { .. }
            | Self::TransportSecretMismatch { .. }
            | Self::ApprovalDenied { .. }
            | Self::ApprovalTimedOut { .. }
            | Self::UnconfiguredApprovalOption { .. } => None,
        }
    }
}

#[derive(Debug)]
enum ExecCredentialError {
    LoadConfig(heim_config::ConfigError),
    ResolveSecret(heim_sources::SecretSourceError),
    IssueCredential(heim_providers::ProviderError),
    MissingGrant { grant: String },
    MissingProviderConfig { grant: String, provider: String },
    ProviderSecretMismatch { provider: String },
}

impl fmt::Display for ExecCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadConfig(source) => write!(formatter, "{source}"),
            Self::ResolveSecret(source) => write!(formatter, "{source}"),
            Self::IssueCredential(source) => write!(formatter, "{source}"),
            Self::MissingGrant { grant } => {
                write!(
                    formatter,
                    "policy decision referenced missing grant {grant}"
                )
            }
            Self::MissingProviderConfig { grant, provider } => write!(
                formatter,
                "grant {grant} references provider {provider}, but it is not configured"
            ),
            Self::ProviderSecretMismatch { provider } => write!(
                formatter,
                "provider {provider} resolved an unexpected local secret set"
            ),
        }
    }
}

impl std::error::Error for ExecCredentialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LoadConfig(source) => Some(source),
            Self::ResolveSecret(source) => Some(source),
            Self::IssueCredential(source) => Some(source),
            Self::MissingGrant { .. }
            | Self::MissingProviderConfig { .. }
            | Self::ProviderSecretMismatch { .. } => None,
        }
    }
}

fn format_audit_events(events: &[heim_audit::AuditEvent]) -> String {
    if events.is_empty() {
        return "audit: no events\n".to_owned();
    }

    let mut output = String::new();
    for event in events {
        let grants = if event.grants.is_empty() {
            "-".to_owned()
        } else {
            event
                .grants
                .iter()
                .map(|grant| grant.name.as_str())
                .collect::<Vec<_>>()
                .join(",")
        };
        let command = if event.command.is_empty() {
            "-".to_owned()
        } else {
            event.command.join(" ")
        };

        output.push_str(&format!(
            "{} {} requester={} grants={} command={}\n",
            event.timestamp,
            audit_decision_label(&event.decision),
            event.requester,
            grants,
            command
        ));
    }

    output
}

fn audit_decision_label(decision: &heim_audit::AuditDecision) -> &'static str {
    match decision {
        heim_audit::AuditDecision::Allow => "allow",
        heim_audit::AuditDecision::Deny { .. } => "deny",
        heim_audit::AuditDecision::RequireApproval { .. } => "require_approval",
        heim_audit::AuditDecision::Approved => "approved",
        heim_audit::AuditDecision::CredentialsIssued => "credentials_issued",
        heim_audit::AuditDecision::CommandCompleted { .. } => "command_completed",
        heim_audit::AuditDecision::Failed { .. } => "failed",
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
    use std::collections::VecDeque;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use heim_approvals::{
        ApprovalDecision, ApprovalError, ApprovalGrantDecision, ApprovalOption, ApprovalProvider,
        ApprovalRequest,
    };
    use heim_audit::AuditDecision;

    use super::{
        RequesterInferenceError, run_from, run_from_with_context,
        run_from_with_context_and_approvals, run_from_with_requester,
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
            super::UnsupportedApprovalProvider,
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
        assert_eq!(
            result.stdout,
            "config: ok (3 provider(s), 1 approval transport(s))\n"
        );
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
        assert_eq!(
            result.stdout,
            "config: ok (3 provider(s), 1 approval transport(s))\n"
        );
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
    fn audit_list_reads_events_from_file() {
        let file = TestFile::new("audit", "");
        let sink = heim_audit::JsonlAuditSink::new(file.path());
        sink.append(
            &sample_audit_event().with_grants([heim_audit::AuditGrant::new(
                "github.personal-readonly",
                "github",
                false,
            )]),
        )
        .expect("append audit event");

        let result = run_from([
            "heim",
            "audit",
            "list",
            "--file",
            file.path().to_str().expect("utf-8 path"),
        ]);

        assert_eq!(result.code, 0);
        assert_eq!(
            result.stdout,
            "2026-05-24T12:00:00Z allow requester=gh grants=github.personal-readonly command=gh pr view 42\n"
        );
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn audit_list_treats_missing_file_as_empty_log() {
        let file = std::env::temp_dir().join(format!(
            "heim-cli-missing-audit-{}-{}.jsonl",
            std::process::id(),
            0
        ));
        let result = run_from([
            "heim",
            "audit",
            "list",
            "--file",
            file.to_str().expect("utf-8 path"),
        ]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "audit: no events\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn audit_list_reports_invalid_jsonl_line() {
        let file = TestFile::new(
            "audit",
            r#"{"request_id":"req","timestamp":"2026-05-24T12:00:00Z","requester":"gh","command":["gh"],"cwd":"/workspace","git":null,"grants":[],"decision":{"type":"allow"},"approval":null,"policy_version":null,"heim_version":"0.1.0"}
not-json
"#,
        );

        let result = run_from([
            "heim",
            "audit",
            "list",
            "--file",
            file.path().to_str().expect("utf-8 path"),
        ]);

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("failed to parse audit log file"));
        assert!(result.stderr.contains("line 2"));
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
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "--config-file",
                &config,
                "aws.prod-readonly",
                "--",
                "aws",
                "sts",
                "get-caller-identity",
            ],
            "codex",
        );

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("approval transport slack is unavailable")
        );
    }

    #[test]
    fn exec_preflight_allows_grant_policy() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let auth = TestFile::unsafe_auth_file();
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "--config-file",
                &config,
                "--auth-file",
                auth.path().to_str().expect("utf-8 path"),
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
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let auth = TestFile::unsafe_auth_file();
        let command_seen = Rc::new(RefCell::new(Vec::new()));
        let command_sink = Rc::clone(&command_seen);
        let env_seen = Rc::new(RefCell::new(Vec::new()));
        let env_sink = Rc::clone(&env_seen);
        let result = run_from_with_context(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "--config-file",
                &config,
                "--auth-file",
                auth.path().to_str().expect("utf-8 path"),
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            || Ok("gh".to_owned()),
            super::test_audit_context,
            super::UnsupportedApprovalProvider,
            |_| Ok(()),
            |command, env_vars| {
                *command_sink.borrow_mut() = command.to_vec();
                *env_sink.borrow_mut() = env_vars
                    .iter()
                    .map(|env| (env.name().to_owned(), env.value().to_owned()))
                    .collect();
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
        assert_eq!(
            env_seen.borrow().as_slice(),
            [
                ("GH_TOKEN".to_owned(), "ghp_secret".to_owned()),
                ("GITHUB_TOKEN".to_owned(), "ghp_secret".to_owned())
            ]
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
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let result = run_from_requester(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "--config-file",
                &config,
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

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("approval transport slack is unavailable")
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
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let auth = TestFile::unsafe_auth_file();
        let (result, event) = run_from_requester_with_audit(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "--config-file",
                &config,
                "--auth-file",
                auth.path().to_str().expect("utf-8 path"),
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
        let credential = event.grants[0].credential.as_ref().expect("credential");
        assert_eq!(credential.kind, "github_pat");
        assert_eq!(credential.env_vars, ["GH_TOKEN", "GITHUB_TOKEN"]);
        assert_eq!(credential.temp_files, Vec::<String>::new());
        assert!(!format!("{event:?}").contains("ghp_secret"));
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
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let (result, event) = run_from_requester_with_audit(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "--config-file",
                &config,
                "aws.prod-readonly",
                "--",
                "aws",
                "sts",
                "get-caller-identity",
            ],
            "codex",
        );

        assert_eq!(result.code, 6);
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
    fn exec_builds_approval_requests_from_configured_transport_options() {
        let config = TestFile::new(
            "config",
            r##"
[providers.aws_prod]
type = "aws_sts"
role_arn = "arn:aws:iam::123456789012:role/ProdReadonly"

[providers.github_drymn]
type = "github_app"
app_id = 123456
installation_id = 987654
private_key = { auth = "github_drymn_app_private_key" }

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
bot_token = { auth = "slack_bot_token" }
options = ["15m", "60m"]
"##,
        );
        let document = heim_config::parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["claude-code"]
approval = "jit:slack"

[[grants]]
name = "github.drymn-pr-write"
provider = "github_drymn"
allow = ["codex"]
commands = ["claude-code"]
approval = "jit:slack"
"#,
        )
        .expect("policy document");
        let request = heim_exec::ExecutionRequest::new(
            vec![
                "aws.prod-readonly".to_owned(),
                "github.drymn-pr-write".to_owned(),
            ],
            "codex",
            vec!["claude-code".to_owned()],
            PathBuf::from("/workspace"),
        );
        let preflight = heim_exec::evaluate_preflight(&document.grants, request);

        let requests = super::approval_requests_for_preflight(
            &preflight,
            &document,
            &super::ConfigSource {
                file: Some(config.path().to_path_buf()),
                auth_file: None,
            },
            "test-request",
        )
        .expect("approval requests");

        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.request_id, "test-request");
        assert_eq!(request.transport.as_str(), "slack");
        assert_eq!(request.requester, "codex");
        assert_eq!(request.command, ["claude-code"]);
        assert_eq!(request.cwd, PathBuf::from("/workspace"));
        assert_eq!(request.grants.len(), 2);
        assert_eq!(request.grants[0].name, "aws.prod-readonly");
        assert_eq!(request.grants[0].provider, "aws_prod");
        assert_eq!(request.grants[1].name, "github.drymn-pr-write");
        assert_eq!(request.grants[1].provider, "github_drymn");
        assert_eq!(request.options[0].id, "15m");
        assert_eq!(request.options[0].label, "Approve 15m");
        assert_eq!(request.options[1].id, "60m");
        assert_eq!(request.options[1].label, "Approve 60m");
    }

    #[test]
    fn exec_fails_closed_when_jit_transport_is_not_configured() {
        let policy = TestFile::new(
            "policy",
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit:slack"
"#,
        );
        let config = TestFile::new(
            "config",
            r#"
[providers.aws_prod]
type = "aws_sts"
role_arn = "arn:aws:iam::123456789012:role/ProdReadonly"
"#,
        );
        let result = run_from_with_context(
            [
                "heim",
                "exec",
                "--file",
                policy.path().to_str().expect("utf-8 path"),
                "--config-file",
                config.path().to_str().expect("utf-8 path"),
                "aws.prod-readonly",
                "--",
                "aws",
                "sts",
                "get-caller-identity",
            ],
            || Ok("codex".to_owned()),
            super::test_audit_context,
            super::UnsupportedApprovalProvider,
            |_| Ok(()),
            |_, _| panic!("command should not execute without approval transport config"),
        );

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("approval transport slack is required by policy but is not configured")
        );
    }

    #[test]
    fn exec_runs_command_after_approval() {
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let provider = TestApprovalProvider::new(
            [Ok(ApprovalDecision::Approved(ApprovalGrantDecision::new(
                "alice",
                "2026-05-24T12:00:00Z",
            )))],
            Rc::clone(&seen_requests),
        );
        let command_seen = Rc::new(RefCell::new(Vec::new()));
        let command_sink = Rc::clone(&command_seen);
        let env_seen = Rc::new(RefCell::new(Vec::new()));
        let env_sink = Rc::clone(&env_seen);

        let result = run_jit_github_exec(provider, |command, env_vars| {
            *command_sink.borrow_mut() = command.to_vec();
            *env_sink.borrow_mut() = env_vars
                .iter()
                .map(|env| (env.name().to_owned(), env.value().to_owned()))
                .collect();
            super::CommandResult {
                code: 17,
                stdout: "child stdout\n".to_owned(),
                stderr: "child stderr\n".to_owned(),
            }
        });

        assert_eq!(result.code, 17);
        assert_eq!(result.stdout, "child stdout\n");
        assert_eq!(result.stderr, "child stderr\n");
        assert_eq!(seen_requests.borrow().as_slice(), ["test-request"]);
        assert_eq!(command_seen.borrow().as_slice(), ["gh", "pr", "view", "42"]);
        assert_eq!(
            env_seen.borrow().as_slice(),
            [
                ("GH_TOKEN".to_owned(), "ghp_secret".to_owned()),
                ("GITHUB_TOKEN".to_owned(), "ghp_secret".to_owned())
            ]
        );
    }

    #[test]
    fn exec_runs_command_after_approval_with_configured_option() {
        let provider = TestApprovalProvider::new(
            [Ok(ApprovalDecision::ApprovedWithOption {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                option: ApprovalOption::new("15m", "Approve 15m"),
            })],
            Rc::new(RefCell::new(Vec::new())),
        );
        let command_seen = Rc::new(RefCell::new(Vec::new()));
        let command_sink = Rc::clone(&command_seen);

        let result = run_jit_github_exec(provider, |command, _| {
            *command_sink.borrow_mut() = command.to_vec();
            super::CommandResult {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        });

        assert_eq!(result.code, 0);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
        assert_eq!(command_seen.borrow().as_slice(), ["gh", "pr", "view", "42"]);
    }

    #[test]
    fn exec_fails_closed_when_approval_option_is_not_configured() {
        let provider = TestApprovalProvider::new(
            [Ok(ApprovalDecision::ApprovedWithOption {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                option: ApprovalOption::new("24h", "Approve 24h"),
            })],
            Rc::new(RefCell::new(Vec::new())),
        );

        let result = run_jit_github_exec(provider, |_, _| {
            panic!("command should not execute with an unconfigured approval option")
        });

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("approval transport slack returned unconfigured option 24h")
        );
    }

    #[test]
    fn exec_fails_closed_when_approval_is_denied() {
        let provider = TestApprovalProvider::new(
            [Ok(ApprovalDecision::Denied(ApprovalGrantDecision::new(
                "alice",
                "2026-05-24T12:00:00Z",
            )))],
            Rc::new(RefCell::new(Vec::new())),
        );

        let result = run_jit_github_exec(provider, |_, _| {
            panic!("command should not execute when approval is denied")
        });

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("approval request was denied by slack")
        );
    }

    #[test]
    fn exec_fails_closed_when_approval_times_out() {
        let provider = TestApprovalProvider::new(
            [Ok(ApprovalDecision::TimedOut)],
            Rc::new(RefCell::new(Vec::new())),
        );

        let result = run_jit_github_exec(provider, |_, _| {
            panic!("command should not execute when approval times out")
        });

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("approval request timed out on slack")
        );
    }

    #[test]
    fn exec_runtime_dispatches_jit_requests_to_configured_slack_transport() {
        let policy = TestFile::new(
            "policy",
            r#"
[[grants]]
name = "github.personal-readonly"
provider = "github_personal"
allow = ["gh"]
commands = ["gh pr view *"]
approval = "jit:slack"
"#,
        );
        let config = TestFile::new(
            "config",
            r##"
[providers.github_personal]
type = "github_pat"
token = { auth = "github_personal_pat" }

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
bot_token = { auth = "slack_bot_token" }
options = ["15m", "60m"]
"##,
        );
        let auth = TestFile::unsafe_auth_file();
        let result = super::run_from_with_context_runtime(
            [
                "heim",
                "exec",
                "--file",
                policy.path().to_str().expect("utf-8 path"),
                "--config-file",
                config.path().to_str().expect("utf-8 path"),
                "--auth-file",
                auth.path().to_str().expect("utf-8 path"),
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            || Ok("gh".to_owned()),
            super::test_audit_context,
            super::ApprovalRuntime::built_in(),
            |_| Ok(()),
            |_, _| panic!("command should not execute without Slack approval dispatch"),
        );

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("approval transport slack is unavailable")
        );
        assert!(
            result
                .stderr
                .contains("Slack approval dispatch is not implemented yet")
        );
    }

    #[test]
    fn exec_runtime_fails_closed_when_slack_token_is_missing() {
        let policy = TestFile::new(
            "policy",
            r#"
[[grants]]
name = "github.personal-readonly"
provider = "github_personal"
allow = ["gh"]
commands = ["gh pr view *"]
approval = "jit:slack"
"#,
        );
        let config = TestFile::new(
            "config",
            r##"
[providers.github_personal]
type = "github_pat"
token = { auth = "github_personal_pat" }

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
bot_token = { auth = "missing_slack_bot_token" }
"##,
        );
        let auth = TestFile::unsafe_auth_file();
        let result = super::run_from_with_context_runtime(
            [
                "heim",
                "exec",
                "--file",
                policy.path().to_str().expect("utf-8 path"),
                "--config-file",
                config.path().to_str().expect("utf-8 path"),
                "--auth-file",
                auth.path().to_str().expect("utf-8 path"),
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            || Ok("gh".to_owned()),
            super::test_audit_context,
            super::ApprovalRuntime::built_in(),
            |_| Ok(()),
            |_, _| panic!("command should not execute without Slack token"),
        );

        assert_eq!(result.code, 6);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("unsafe local auth entry missing_slack_bot_token was not found")
        );
    }

    #[test]
    fn exec_fails_when_audit_event_write_fails() {
        let file = format!("{}/../../examples/policy.toml", env!("CARGO_MANIFEST_DIR"));
        let config = format!("{}/../../examples/config.toml", env!("CARGO_MANIFEST_DIR"));
        let auth = TestFile::unsafe_auth_file();
        let result = run_from_with_context(
            [
                "heim",
                "exec",
                "--file",
                &file,
                "--config-file",
                &config,
                "--auth-file",
                auth.path().to_str().expect("utf-8 path"),
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            || Ok("gh".to_owned()),
            super::test_audit_context,
            super::UnsupportedApprovalProvider,
            |_| {
                let sink = heim_audit::JsonlAuditSink::new("/dev/null/audit.jsonl");
                sink.append(&sample_audit_event())
            },
            |_, _| panic!("command should not execute when audit write fails"),
        );

        assert_eq!(result.code, 4);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("failed to write exec audit event"));
    }

    #[test]
    fn exec_fails_closed_for_invalid_aws_sts_config() {
        let config = TestFile::new(
            "config",
            r#"
[providers.aws_prod]
type = "aws_sts"
role_arn = "arn:aws:iam::123456789012:role/ProdReadonly"
duration = "soon"
"#,
        );
        let policy = TestFile::new(
            "policy",
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        );
        let result = run_from_with_context(
            [
                "heim",
                "exec",
                "--file",
                policy.path().to_str().expect("utf-8 path"),
                "--config-file",
                config.path().to_str().expect("utf-8 path"),
                "aws.prod-readonly",
                "--",
                "aws",
                "sts",
                "get-caller-identity",
            ],
            || Ok("codex".to_owned()),
            super::test_audit_context,
            super::UnsupportedApprovalProvider,
            |_| Ok(()),
            |_, _| panic!("command should not execute when provider cannot issue credentials"),
        );

        assert_eq!(result.code, 5);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("provider aws_sts config is invalid: duration soon is invalid")
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
        for command in ["config", "approvals"] {
            let result = run_from(["heim", command]);

            assert_eq!(result.code, 2);
            assert!(result.stdout.is_empty());
            assert!(result.stderr.contains("not implemented yet"));
        }
    }

    #[test]
    fn audit_without_subcommand_is_not_implemented_yet() {
        let result = run_from(["heim", "audit"]);

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.contains("not implemented yet"));
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
        assert_eq!(result.stdout, "policy: ok (3 grant(s))\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn policy_validate_reports_valid_directory() {
        let dir = format!("{}/../../examples/policies", env!("CARGO_MANIFEST_DIR"));
        let result = run_from(["heim", "policy", "validate", "--dir", &dir]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "policy: ok (3 grant(s))\n");
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

    fn run_jit_github_exec<P>(
        approval_provider: P,
        execute_command: impl FnOnce(
            &[String],
            &[heim_providers::CredentialEnvVar],
        ) -> super::CommandResult,
    ) -> super::CommandResult
    where
        P: ApprovalProvider,
    {
        let policy = TestFile::new(
            "policy",
            r#"
[[grants]]
name = "github.personal-readonly"
provider = "github_personal"
allow = ["gh"]
commands = ["gh pr view *"]
approval = "jit:slack"
"#,
        );
        let config = TestFile::new(
            "config",
            r##"
[providers.github_personal]
type = "github_pat"
token = { auth = "github_personal_pat" }

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
bot_token = { auth = "slack_bot_token" }
options = ["15m", "60m"]
"##,
        );
        let auth = TestFile::unsafe_auth_file();

        run_from_with_context_and_approvals(
            [
                "heim",
                "exec",
                "--file",
                policy.path().to_str().expect("utf-8 path"),
                "--config-file",
                config.path().to_str().expect("utf-8 path"),
                "--auth-file",
                auth.path().to_str().expect("utf-8 path"),
                "github.personal-readonly",
                "--",
                "gh",
                "pr",
                "view",
                "42",
            ],
            || Ok("gh".to_owned()),
            super::test_audit_context,
            approval_provider,
            |_| Ok(()),
            execute_command,
        )
    }

    struct TestApprovalProvider {
        decisions: RefCell<VecDeque<Result<ApprovalDecision, ApprovalError>>>,
        seen_requests: Rc<RefCell<Vec<String>>>,
    }

    impl TestApprovalProvider {
        fn new(
            decisions: impl IntoIterator<Item = Result<ApprovalDecision, ApprovalError>>,
            seen_requests: Rc<RefCell<Vec<String>>>,
        ) -> Self {
            Self {
                decisions: RefCell::new(decisions.into_iter().collect()),
                seen_requests,
            }
        }
    }

    impl ApprovalProvider for TestApprovalProvider {
        fn request_approval(
            &self,
            request: &ApprovalRequest,
        ) -> Result<ApprovalDecision, ApprovalError> {
            self.seen_requests
                .borrow_mut()
                .push(request.request_id.clone());
            self.decisions
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok(ApprovalDecision::TimedOut))
        }
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

        fn unsafe_auth_file() -> Self {
            let file = Self::new(
                "auth",
                r#"{
                    "github_personal_pat": {
                        "type": "github_pat",
                        "token": "ghp_secret"
                    },
                    "slack_bot_token": {
                        "type": "slack_bot_token",
                        "token": "xoxb_secret"
                    }
                }"#,
            );
            set_owner_only_permissions(file.path());
            file
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(unix)]
    fn set_owner_only_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).expect("set owner-only permissions");
    }

    #[cfg(not(unix))]
    fn set_owner_only_permissions(_: &Path) {}

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
