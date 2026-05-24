use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};

const NOT_IMPLEMENTED_EXIT_CODE: i32 = 2;

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
    /// Validate a policy file.
    Validate {
        /// Policy file to validate.
        #[arg(long)]
        file: PathBuf,
    },
}

pub fn run_from<I, T>(args: I) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => run(cli),
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

fn run(cli: Cli) -> CommandResult {
    match cli.command {
        Some(Command::Doctor) => ok("heim: ok\n"),
        Some(Command::Exec { grants, command }) => not_implemented(format!(
            "heim exec is not implemented yet; parsed {} grant(s) and {} command argument(s)\n",
            grants.len(),
            command.len()
        )),
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

fn run_policy(command: Option<PolicyCommand>) -> CommandResult {
    match command {
        Some(PolicyCommand::Validate { file }) => match heim_config::load_policy_file(&file) {
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
        None => not_implemented("heim policy is not implemented yet\n"),
    }
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

#[cfg(test)]
mod tests {
    use super::run_from;

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
        let result = run_from([
            "heim",
            "exec",
            "aws.prod-readonly",
            "github.pr-write",
            "--",
            "gh",
            "pr",
            "create",
        ]);

        assert_eq!(result.code, 2);
        assert!(result.stdout.is_empty());
        assert!(
            result
                .stderr
                .contains("parsed 2 grant(s) and 3 command argument(s)")
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
}
