//! Local daemon for Heim approval workflows.
//!
//! `heimd` owns long-lived local IPC needed by interactive approval transports.
//! Slack Socket Mode will build on this daemon boundary in a later change.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, error::ErrorKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "heimd",
    version,
    disable_help_subcommand = true,
    about = "Local daemon for Heim approval workflows."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check the local Heim daemon binary.
    Doctor,
    /// Run the local IPC daemon.
    Serve {
        /// Socket path to bind instead of the default path.
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Handle one request and exit.
        #[arg(long)]
        once: bool,
    },
    /// Check that a local daemon is reachable.
    Ping {
        /// Socket path to connect instead of the default path.
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

pub fn run_from<I, T>(args: I) -> CommandResult
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
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
        Some(Command::Doctor) => ok("heimd: ok\n"),
        Some(Command::Serve { socket, once }) => run_serve(socket, once),
        Some(Command::Ping { socket }) => run_ping(socket),
        None => ok("heimd: ok\n"),
    }
}

fn run_serve(socket: Option<PathBuf>, once: bool) -> CommandResult {
    let socket = match socket.or_else(|| default_socket_path().ok()) {
        Some(socket) => socket,
        None => {
            return command_error(2, "failed to resolve heimd socket path\n");
        }
    };

    let result = if once {
        serve_once(&socket)
    } else {
        serve_forever(&socket)
    };

    match result {
        Ok(()) => ok(format!("heimd: listening on {}\n", socket.display())),
        Err(error) => command_error(2, format!("{error}\n")),
    }
}

fn run_ping(socket: Option<PathBuf>) -> CommandResult {
    let socket = match socket.or_else(|| default_socket_path().ok()) {
        Some(socket) => socket,
        None => {
            return command_error(2, "failed to resolve heimd socket path\n");
        }
    };

    match ping_daemon(&socket) {
        Ok(DaemonResponse::Pong) => ok("pong\n"),
        Err(error) => command_error(2, format!("{error}\n")),
    }
}

pub fn default_socket_path() -> Result<PathBuf, DaemonError> {
    default_socket_path_from_env(|name| env::var_os(name))
}

fn default_socket_path_from_env(
    mut var_os: impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, DaemonError> {
    if let Some(runtime_dir) = var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime_dir).join("heim").join("heimd.sock"));
    }

    Ok(heim_config::default_heim_config_dir()
        .map_err(DaemonError::ConfigPath)?
        .join("heimd.sock"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonRequest {
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    Pong,
}

fn handle_request(request: DaemonRequest) -> DaemonResponse {
    match request {
        DaemonRequest::Ping => DaemonResponse::Pong,
    }
}

pub fn encode_request(request: &DaemonRequest) -> Result<String, DaemonError> {
    encode_json_line(request)
}

pub fn encode_response(response: &DaemonResponse) -> Result<String, DaemonError> {
    encode_json_line(response)
}

fn encode_json_line(value: &impl Serialize) -> Result<String, DaemonError> {
    let mut line = serde_json::to_string(value).map_err(DaemonError::Serialize)?;
    line.push('\n');
    Ok(line)
}

#[cfg(unix)]
pub fn serve_once(socket: &Path) -> Result<(), DaemonError> {
    serve(socket, true)
}

#[cfg(not(unix))]
pub fn serve_once(_socket: &Path) -> Result<(), DaemonError> {
    Err(DaemonError::UnsupportedPlatform {
        feature: "local daemon sockets",
    })
}

#[cfg(unix)]
pub fn serve_forever(socket: &Path) -> Result<(), DaemonError> {
    serve(socket, false)
}

#[cfg(not(unix))]
pub fn serve_forever(_socket: &Path) -> Result<(), DaemonError> {
    Err(DaemonError::UnsupportedPlatform {
        feature: "local daemon sockets",
    })
}

#[cfg(unix)]
fn serve(socket: &Path, once: bool) -> Result<(), DaemonError> {
    use std::os::unix::net::UnixListener;

    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).map_err(|source| DaemonError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }

    if socket.exists() {
        return Err(DaemonError::SocketExists {
            path: socket.display().to_string(),
        });
    }

    let listener = UnixListener::bind(socket).map_err(|source| DaemonError::BindSocket {
        path: socket.display().to_string(),
        source,
    })?;

    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|source| DaemonError::AcceptConnection { source })?;
        handle_stream(stream)?;

        if once {
            break;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn handle_stream(stream: std::os::unix::net::UnixStream) -> Result<(), DaemonError> {
    let reader = stream
        .try_clone()
        .map_err(|source| DaemonError::CloneConnection { source })?;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|source| DaemonError::ReadConnection { source })?;
    let request = serde_json::from_str::<DaemonRequest>(&line).map_err(DaemonError::Parse)?;
    let response = handle_request(request);
    let line = encode_response(&response)?;
    let mut writer = stream;
    writer
        .write_all(line.as_bytes())
        .map_err(|source| DaemonError::WriteConnection { source })?;
    Ok(())
}

#[cfg(unix)]
pub fn ping_daemon(socket: &Path) -> Result<DaemonResponse, DaemonError> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket).map_err(|source| DaemonError::ConnectSocket {
        path: socket.display().to_string(),
        source,
    })?;
    let line = encode_request(&DaemonRequest::Ping)?;
    stream
        .write_all(line.as_bytes())
        .map_err(|source| DaemonError::WriteConnection { source })?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|source| DaemonError::ReadConnection { source })?;
    serde_json::from_str(&response).map_err(DaemonError::Parse)
}

#[cfg(not(unix))]
pub fn ping_daemon(_socket: &Path) -> Result<DaemonResponse, DaemonError> {
    Err(DaemonError::UnsupportedPlatform {
        feature: "local daemon sockets",
    })
}

fn ok(stdout: impl Into<String>) -> CommandResult {
    CommandResult {
        code: 0,
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

fn command_error(code: i32, stderr: impl Into<String>) -> CommandResult {
    CommandResult {
        code,
        stdout: String::new(),
        stderr: stderr.into(),
    }
}

#[derive(Debug)]
pub enum DaemonError {
    ConfigPath(heim_config::ConfigError),
    UnsupportedPlatform {
        feature: &'static str,
    },
    CreateDir {
        path: String,
        source: std::io::Error,
    },
    SocketExists {
        path: String,
    },
    BindSocket {
        path: String,
        source: std::io::Error,
    },
    ConnectSocket {
        path: String,
        source: std::io::Error,
    },
    AcceptConnection {
        source: std::io::Error,
    },
    CloneConnection {
        source: std::io::Error,
    },
    ReadConnection {
        source: std::io::Error,
    },
    WriteConnection {
        source: std::io::Error,
    },
    Serialize(serde_json::Error),
    Parse(serde_json::Error),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigPath(source) => write!(formatter, "{source}"),
            Self::UnsupportedPlatform { feature } => {
                write!(
                    formatter,
                    "{feature} are not supported on this platform yet"
                )
            }
            Self::CreateDir { path, source } => {
                write!(formatter, "failed to create directory {path}: {source}")
            }
            Self::SocketExists { path } => write!(formatter, "socket {path} already exists"),
            Self::BindSocket { path, source } => {
                write!(formatter, "failed to bind socket {path}: {source}")
            }
            Self::ConnectSocket { path, source } => {
                write!(formatter, "failed to connect socket {path}: {source}")
            }
            Self::AcceptConnection { source } => {
                write!(formatter, "failed to accept daemon connection: {source}")
            }
            Self::CloneConnection { source } => {
                write!(formatter, "failed to clone daemon connection: {source}")
            }
            Self::ReadConnection { source } => {
                write!(formatter, "failed to read daemon connection: {source}")
            }
            Self::WriteConnection { source } => {
                write!(formatter, "failed to write daemon connection: {source}")
            }
            Self::Serialize(source) => {
                write!(formatter, "failed to serialize daemon message: {source}")
            }
            Self::Parse(source) => write!(formatter, "failed to parse daemon message: {source}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigPath(source) => Some(source),
            Self::CreateDir { source, .. }
            | Self::BindSocket { source, .. }
            | Self::ConnectSocket { source, .. }
            | Self::AcceptConnection { source }
            | Self::CloneConnection { source }
            | Self::ReadConnection { source }
            | Self::WriteConnection { source } => Some(source),
            Self::Serialize(source) | Self::Parse(source) => Some(source),
            Self::UnsupportedPlatform { .. } | Self::SocketExists { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{
        DaemonRequest, DaemonResponse, default_socket_path_from_env, encode_request,
        encode_response, run_from,
    };

    #[test]
    fn doctor_reports_ok() {
        let result = run_from(["heimd", "doctor"]);

        assert_eq!(result.code, 0);
        assert_eq!(result.stdout, "heimd: ok\n");
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn daemon_protocol_serializes_ping_and_pong() {
        let request = encode_request(&DaemonRequest::Ping).expect("request");
        let response = encode_response(&DaemonResponse::Pong).expect("response");

        assert_eq!(request, "{\"type\":\"ping\"}\n");
        assert_eq!(response, "{\"type\":\"pong\"}\n");
    }

    #[test]
    fn default_socket_path_prefers_xdg_runtime_dir() {
        let path = default_socket_path_from_env(|name| match name {
            "XDG_RUNTIME_DIR" => Some(OsString::from("/tmp/runtime")),
            _ => None,
        })
        .expect("socket path");

        assert_eq!(path, PathBuf::from("/tmp/runtime/heim/heimd.sock"));
    }

    #[test]
    fn daemon_handles_ping_as_pong() {
        let response = super::handle_request(DaemonRequest::Ping);

        assert_eq!(response, DaemonResponse::Pong);
    }
}
