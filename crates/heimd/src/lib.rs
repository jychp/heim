//! Local daemon for Heim approval workflows.
//!
//! `heimd` owns long-lived local IPC needed by interactive approval transports.
//! Slack Socket Mode will build on this daemon boundary in a later change.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, error::ErrorKind};
use heim_approvals::{ApprovalDecision, ApprovalRequest, ApprovalSession, ApprovalSessionStatus};
use serde::{Deserialize, Serialize};

const MAX_ACTIVE_CONNECTIONS: usize = 64;
const INITIAL_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

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
        Ok(response) => command_error(2, format!("unexpected daemon response: {response:?}\n")),
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
    ApprovalCreate {
        session_id: String,
        request: ApprovalRequest,
        expires_at: Option<String>,
    },
    ApprovalGet {
        session_id: String,
    },
    ApprovalWait {
        session_id: String,
        timeout_ms: u64,
    },
    ApprovalDecide {
        session_id: String,
        decision: ApprovalDecision,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    Pong,
    ApprovalCreated {
        session: ApprovalSession,
    },
    ApprovalSession {
        session: ApprovalSession,
    },
    ApprovalWaited {
        session: ApprovalSession,
    },
    ApprovalDecided {
        session: ApprovalSession,
    },
    Error {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<DaemonErrorCode>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonErrorCode {
    ApprovalWaitTimedOut,
}

#[derive(Debug, Default)]
pub struct DaemonState {
    approvals: ApprovalSessionStore,
}

impl DaemonState {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Default)]
struct SharedDaemonState {
    state: Mutex<DaemonState>,
    approvals_changed: Condvar,
}

impl SharedDaemonState {
    fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, DaemonState> {
        self.state.lock().expect("daemon state lock poisoned")
    }
}

#[derive(Debug, Default)]
pub struct ApprovalSessionStore {
    sessions: BTreeMap<String, ApprovalSession>,
}

impl ApprovalSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(
        &mut self,
        session_id: String,
        request: ApprovalRequest,
        expires_at: Option<String>,
    ) -> Result<ApprovalSession, ApprovalSessionStoreError> {
        if self.sessions.contains_key(&session_id) {
            return Err(ApprovalSessionStoreError::DuplicateSession { session_id });
        }

        let session = ApprovalSession::new(session_id.clone(), request, expires_at)
            .map_err(ApprovalSessionStoreError::Session)?;
        self.sessions.insert(session_id, session.clone());
        Ok(session)
    }

    pub fn get(&self, session_id: &str) -> Result<ApprovalSession, ApprovalSessionStoreError> {
        self.sessions.get(session_id).cloned().ok_or_else(|| {
            ApprovalSessionStoreError::MissingSession {
                session_id: session_id.to_owned(),
            }
        })
    }

    pub fn decide(
        &mut self,
        session_id: &str,
        decision: ApprovalDecision,
    ) -> Result<ApprovalSession, ApprovalSessionStoreError> {
        let session = self.sessions.get_mut(session_id).ok_or_else(|| {
            ApprovalSessionStoreError::MissingSession {
                session_id: session_id.to_owned(),
            }
        })?;
        session
            .apply_decision(decision)
            .map_err(ApprovalSessionStoreError::Session)?;
        Ok(session.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalSessionStoreError {
    DuplicateSession { session_id: String },
    MissingSession { session_id: String },
    Session(heim_approvals::ApprovalSessionError),
}

impl fmt::Display for ApprovalSessionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateSession { session_id } => {
                write!(formatter, "approval session {session_id} already exists")
            }
            Self::MissingSession { session_id } => {
                write!(formatter, "approval session {session_id} not found")
            }
            Self::Session(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for ApprovalSessionStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(source) => Some(source),
            Self::DuplicateSession { .. } | Self::MissingSession { .. } => None,
        }
    }
}

fn handle_request(state: &SharedDaemonState, request: DaemonRequest) -> DaemonResponse {
    match request {
        DaemonRequest::Ping => DaemonResponse::Pong,
        DaemonRequest::ApprovalCreate {
            session_id,
            request,
            expires_at,
        } => {
            let response = match state
                .lock()
                .approvals
                .create(session_id, request, expires_at)
            {
                Ok(session) => DaemonResponse::ApprovalCreated { session },
                Err(error) => DaemonResponse::Error {
                    message: error.to_string(),
                    code: None,
                },
            };
            state.approvals_changed.notify_all();
            response
        }
        DaemonRequest::ApprovalGet { session_id } => {
            match state.lock().approvals.get(&session_id) {
                Ok(session) => DaemonResponse::ApprovalSession { session },
                Err(error) => DaemonResponse::Error {
                    message: error.to_string(),
                    code: None,
                },
            }
        }
        DaemonRequest::ApprovalWait {
            session_id,
            timeout_ms,
        } => handle_approval_wait(state, &session_id, Duration::from_millis(timeout_ms)),
        DaemonRequest::ApprovalDecide {
            session_id,
            decision,
        } => {
            let response = match state.lock().approvals.decide(&session_id, decision) {
                Ok(session) => DaemonResponse::ApprovalDecided { session },
                Err(error) => DaemonResponse::Error {
                    message: error.to_string(),
                    code: None,
                },
            };
            state.approvals_changed.notify_all();
            response
        }
    }
}

fn handle_approval_wait(
    state: &SharedDaemonState,
    session_id: &str,
    timeout: Duration,
) -> DaemonResponse {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut guard = state.lock();

    loop {
        match guard.approvals.get(session_id) {
            Ok(session) if approval_session_is_resolved(session.status()) => {
                return DaemonResponse::ApprovalWaited { session };
            }
            Ok(_) => {}
            Err(error) => {
                return DaemonResponse::Error {
                    message: error.to_string(),
                    code: None,
                };
            }
        }

        let now = Instant::now();
        if now >= deadline {
            return DaemonResponse::Error {
                message: format!("approval session {session_id} wait timed out"),
                code: Some(DaemonErrorCode::ApprovalWaitTimedOut),
            };
        }

        let remaining = deadline.saturating_duration_since(now);
        let (next_guard, _) = state
            .approvals_changed
            .wait_timeout(guard, remaining)
            .expect("daemon state lock poisoned");
        guard = next_guard;
    }
}

fn approval_session_is_resolved(status: &ApprovalSessionStatus) -> bool {
    !matches!(status, ApprovalSessionStatus::Pending)
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
    let _socket_file_guard = SocketFileGuard::new(socket);
    let state = Arc::new(SharedDaemonState::new());
    let connection_limit = Arc::new(ActiveConnectionLimit::new(MAX_ACTIVE_CONNECTIONS));

    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|source| DaemonError::AcceptConnection { source })?;
        if once {
            if let Err(error) = handle_stream(&state, stream) {
                handle_connection_error(error, true)?;
            }
        } else {
            let state = Arc::clone(&state);
            let permit = Arc::clone(&connection_limit).acquire();
            std::thread::spawn(move || {
                let _permit = permit;
                if let Err(error) = handle_stream(&state, stream) {
                    eprintln!("heimd: connection error: {error}");
                }
            });
        }

        if once {
            break;
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ActiveConnectionLimit {
    max: usize,
    active: Mutex<usize>,
    changed: Condvar,
}

impl ActiveConnectionLimit {
    fn new(max: usize) -> Self {
        Self {
            max,
            active: Mutex::new(0),
            changed: Condvar::new(),
        }
    }

    fn acquire(self: Arc<Self>) -> ActiveConnectionPermit {
        let mut active = self.active.lock().expect("connection limit lock poisoned");
        while *active >= self.max {
            active = self
                .changed
                .wait(active)
                .expect("connection limit lock poisoned");
        }
        *active += 1;
        drop(active);
        ActiveConnectionPermit { limit: self }
    }

    fn release(&self) {
        let mut active = self.active.lock().expect("connection limit lock poisoned");
        *active = active.saturating_sub(1);
        self.changed.notify_one();
    }
}

#[derive(Debug)]
struct ActiveConnectionPermit {
    limit: Arc<ActiveConnectionLimit>,
}

impl Drop for ActiveConnectionPermit {
    fn drop(&mut self) {
        self.limit.release();
    }
}

#[cfg(unix)]
struct SocketFileGuard {
    path: PathBuf,
    identity: Option<SocketFileIdentity>,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct SocketFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SocketFileGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            identity: SocketFileIdentity::current(path),
        }
    }
}

#[cfg(unix)]
impl Drop for SocketFileGuard {
    fn drop(&mut self) {
        let Some(identity) = self.identity else {
            return;
        };

        if identity.matches(&self.path) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
impl SocketFileIdentity {
    fn current(path: &Path) -> Option<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.file_type().is_socket() {
            return None;
        }

        Some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn matches(self, path: &Path) -> bool {
        Self::current(path)
            .is_some_and(|current| current.device == self.device && current.inode == self.inode)
    }
}

#[cfg(unix)]
fn handle_connection_error(error: DaemonError, once: bool) -> Result<(), DaemonError> {
    if once {
        return Err(error);
    }

    eprintln!("heimd: connection error: {error}");
    Ok(())
}

#[cfg(unix)]
fn handle_stream(
    state: &SharedDaemonState,
    stream: std::os::unix::net::UnixStream,
) -> Result<(), DaemonError> {
    stream
        .set_read_timeout(Some(INITIAL_REQUEST_READ_TIMEOUT))
        .map_err(|source| DaemonError::ConfigureConnection { source })?;
    let reader = stream
        .try_clone()
        .map_err(|source| DaemonError::CloneConnection { source })?;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|source| DaemonError::ReadConnection { source })?;
    let request = serde_json::from_str::<DaemonRequest>(&line).map_err(DaemonError::Parse)?;
    let response = handle_request(state, request);
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
    ConfigureConnection {
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
            Self::ConfigureConnection { source } => {
                write!(formatter, "failed to configure daemon connection: {source}")
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
            | Self::ConfigureConnection { source }
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
    use std::io::{BufRead, BufReader, Write};
    use std::path::PathBuf;

    use heim_approvals::{
        ApprovalDecision, ApprovalGrant, ApprovalGrantDecision, ApprovalOption, ApprovalRequest,
        ApprovalSessionStatus, ApprovalTransportName,
    };

    use super::{
        DaemonErrorCode, DaemonRequest, DaemonResponse, SharedDaemonState,
        default_socket_path_from_env, encode_request, encode_response, run_from,
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
    fn daemon_protocol_serializes_approval_create() {
        let request = encode_request(&DaemonRequest::ApprovalCreate {
            session_id: "session-1".to_owned(),
            request: approval_request(),
            expires_at: Some("2026-05-24T12:15:00Z".to_owned()),
        })
        .expect("request");
        let value: serde_json::Value = serde_json::from_str(request.trim()).expect("json");

        assert_eq!(value["type"], "approval_create");
        assert_eq!(value["session_id"], "session-1");
        assert_eq!(value["request"]["transport"], "slack");
        assert_eq!(value["expires_at"], "2026-05-24T12:15:00Z");
    }

    #[test]
    fn daemon_protocol_serializes_approval_get_and_session_response() {
        let session = heim_approvals::ApprovalSession::new(
            "session-1",
            approval_request(),
            Some("2026-05-24T12:15:00Z".to_owned()),
        )
        .expect("approval session");
        let request = encode_request(&DaemonRequest::ApprovalGet {
            session_id: "session-1".to_owned(),
        })
        .expect("request");
        let response =
            encode_response(&DaemonResponse::ApprovalSession { session }).expect("response");
        let request_value: serde_json::Value =
            serde_json::from_str(request.trim()).expect("request json");
        let response_value: serde_json::Value =
            serde_json::from_str(response.trim()).expect("response json");

        assert_eq!(request_value["type"], "approval_get");
        assert_eq!(request_value["session_id"], "session-1");
        assert_eq!(response_value["type"], "approval_session");
        assert_eq!(response_value["session"]["id"], "session-1");
        assert_eq!(response_value["session"]["request"]["transport"], "slack");
        assert_eq!(response_value["session"]["status"]["type"], "pending");
    }

    #[test]
    fn daemon_protocol_serializes_approval_wait_and_waited_response() {
        let mut session = heim_approvals::ApprovalSession::new(
            "session-1",
            approval_request(),
            Some("2026-05-24T12:15:00Z".to_owned()),
        )
        .expect("approval session");
        session
            .apply_decision(ApprovalDecision::Approved {
                decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
            })
            .expect("approval decision");
        let request = encode_request(&DaemonRequest::ApprovalWait {
            session_id: "session-1".to_owned(),
            timeout_ms: 30_000,
        })
        .expect("request");
        let response =
            encode_response(&DaemonResponse::ApprovalWaited { session }).expect("response");
        let request_value: serde_json::Value =
            serde_json::from_str(request.trim()).expect("request json");
        let response_value: serde_json::Value =
            serde_json::from_str(response.trim()).expect("response json");

        assert_eq!(request_value["type"], "approval_wait");
        assert_eq!(request_value["session_id"], "session-1");
        assert_eq!(request_value["timeout_ms"], 30_000);
        assert_eq!(response_value["type"], "approval_waited");
        assert_eq!(response_value["session"]["status"]["type"], "approved");
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
        let state = SharedDaemonState::new();
        let response = super::handle_request(&state, DaemonRequest::Ping);

        assert_eq!(response, DaemonResponse::Pong);
    }

    #[test]
    fn daemon_creates_and_gets_approval_session() {
        let state = SharedDaemonState::new();

        let create_response = super::handle_request(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );
        let get_response = super::handle_request(
            &state,
            DaemonRequest::ApprovalGet {
                session_id: "session-1".to_owned(),
            },
        );

        assert!(matches!(
            create_response,
            DaemonResponse::ApprovalCreated { ref session } if session.id() == "session-1"
        ));
        assert!(matches!(
            get_response,
            DaemonResponse::ApprovalSession { ref session } if session.id() == "session-1"
        ));
    }

    #[test]
    fn daemon_rejects_duplicate_approval_session() {
        let state = SharedDaemonState::new();
        let create = DaemonRequest::ApprovalCreate {
            session_id: "session-1".to_owned(),
            request: approval_request(),
            expires_at: None,
        };

        let first = super::handle_request(&state, create.clone());
        let second = super::handle_request(&state, create);

        assert!(matches!(first, DaemonResponse::ApprovalCreated { .. }));
        assert!(matches!(
            second,
            DaemonResponse::Error { ref message, .. }
                if message == "approval session session-1 already exists"
        ));
    }

    #[test]
    fn daemon_decides_approval_session() {
        let state = SharedDaemonState::new();
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );

        let response = super::handle_request(
            &state,
            DaemonRequest::ApprovalDecide {
                session_id: "session-1".to_owned(),
                decision: ApprovalDecision::ApprovedWithOption {
                    decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                    option: ApprovalOption::new("15m", "Approve 15m"),
                },
            },
        );

        assert!(matches!(
            response,
            DaemonResponse::ApprovalDecided { ref session }
                if session.status()
                    == &ApprovalSessionStatus::ApprovedWithOption {
                        decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                        option: ApprovalOption::new("15m", "Approve 15m"),
                    }
        ));
    }

    #[test]
    fn daemon_wait_returns_resolved_approval_session() {
        let state = SharedDaemonState::new();
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalDecide {
                session_id: "session-1".to_owned(),
                decision: ApprovalDecision::Approved {
                    decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                },
            },
        );

        let response = super::handle_request(
            &state,
            DaemonRequest::ApprovalWait {
                session_id: "session-1".to_owned(),
                timeout_ms: 1,
            },
        );

        assert!(matches!(
            response,
            DaemonResponse::ApprovalWaited { ref session }
                if session.status()
                    == &ApprovalSessionStatus::Approved {
                        decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                    }
        ));
    }

    #[test]
    fn daemon_wait_returns_after_approval_decision() {
        let state = std::sync::Arc::new(SharedDaemonState::new());
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );
        let waiter_state = std::sync::Arc::clone(&state);

        let waiter = std::thread::spawn(move || {
            super::handle_request(
                &waiter_state,
                DaemonRequest::ApprovalWait {
                    session_id: "session-1".to_owned(),
                    timeout_ms: 2_000,
                },
            )
        });

        std::thread::sleep(std::time::Duration::from_millis(20));
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalDecide {
                session_id: "session-1".to_owned(),
                decision: ApprovalDecision::Approved {
                    decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                },
            },
        );

        let response = waiter.join().expect("waiter thread");
        assert!(matches!(
            response,
            DaemonResponse::ApprovalWaited { ref session }
                if session.status()
                    == &ApprovalSessionStatus::Approved {
                        decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                    }
        ));
    }

    #[test]
    fn daemon_wait_times_out_while_session_is_pending() {
        let state = SharedDaemonState::new();
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );

        let response = super::handle_request(
            &state,
            DaemonRequest::ApprovalWait {
                session_id: "session-1".to_owned(),
                timeout_ms: 1,
            },
        );

        assert!(matches!(
            response,
            DaemonResponse::Error { ref message, code }
                if message == "approval session session-1 wait timed out"
                    && code == Some(DaemonErrorCode::ApprovalWaitTimedOut)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn serve_forever_allows_wait_and_decide_on_separate_connections() {
        let dir = TestDir::new("approval-wait-ipc");
        let socket = dir.path().join("heimd.sock");
        if !unix_socket_bind_is_supported(&socket) {
            return;
        }

        let server_socket = socket.clone();
        let _server = std::thread::spawn(move || {
            super::serve_forever(&server_socket).expect("serve forever")
        });

        wait_for_socket(&socket);
        let create_response = send_daemon_request(
            &socket,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );
        assert!(matches!(
            create_response,
            DaemonResponse::ApprovalCreated { .. }
        ));

        let wait_socket = socket.clone();
        let waiter = std::thread::spawn(move || {
            send_daemon_request(
                &wait_socket,
                DaemonRequest::ApprovalWait {
                    session_id: "session-1".to_owned(),
                    timeout_ms: 2_000,
                },
            )
        });

        std::thread::sleep(std::time::Duration::from_millis(20));
        let decide_response = send_daemon_request(
            &socket,
            DaemonRequest::ApprovalDecide {
                session_id: "session-1".to_owned(),
                decision: ApprovalDecision::Approved {
                    decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                },
            },
        );
        assert!(matches!(
            decide_response,
            DaemonResponse::ApprovalDecided { .. }
        ));

        let wait_response = waiter.join().expect("waiter thread");
        assert!(matches!(
            wait_response,
            DaemonResponse::ApprovalWaited { ref session }
                if session.status()
                    == &ApprovalSessionStatus::Approved {
                        decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                    }
        ));

        drop(dir);
    }

    #[test]
    fn daemon_rejects_invalid_approval_decision() {
        let state = SharedDaemonState::new();
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );

        let response = super::handle_request(
            &state,
            DaemonRequest::ApprovalDecide {
                session_id: "session-1".to_owned(),
                decision: ApprovalDecision::ApprovedWithOption {
                    decision: ApprovalGrantDecision::new("alice", "2026-05-24T12:00:00Z"),
                    option: ApprovalOption::new("15m", "Approve 24h"),
                },
            },
        );

        assert!(matches!(
            response,
            DaemonResponse::Error { ref message, .. }
                if message == "approval transport slack returned unconfigured option 15m"
        ));
    }

    #[test]
    fn daemon_reports_missing_approval_session() {
        let state = SharedDaemonState::new();

        let response = super::handle_request(
            &state,
            DaemonRequest::ApprovalGet {
                session_id: "missing".to_owned(),
            },
        );

        assert!(matches!(
            response,
            DaemonResponse::Error { ref message, .. }
                if message == "approval session missing not found"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn socket_file_guard_preserves_non_socket_file_on_drop() {
        let dir = TestDir::new("socket-file-guard");
        let socket = dir.path().join("heimd.sock");
        std::fs::write(&socket, b"replacement").expect("replacement file");

        {
            let _guard = super::SocketFileGuard::new(&socket);
            assert!(socket.exists());
        }

        assert_eq!(
            std::fs::read(&socket).expect("replacement file"),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_file_guard_preserves_replaced_file_on_drop() {
        let dir = TestDir::new("socket-file-replacement-guard");
        let socket = dir.path().join("heimd.sock");
        let guard = super::SocketFileGuard {
            path: socket.clone(),
            identity: Some(super::SocketFileIdentity {
                device: u64::MAX,
                inode: u64::MAX,
            }),
        };
        std::fs::write(&socket, b"replacement").expect("replacement file");

        drop(guard);

        assert_eq!(
            std::fs::read(&socket).expect("replacement file"),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn serve_once_propagates_connection_errors() {
        let error = super::DaemonError::SocketExists {
            path: "stale.sock".to_string(),
        };

        let result = super::handle_connection_error(error, true);

        assert!(matches!(
            result,
            Err(super::DaemonError::SocketExists { path }) if path == "stale.sock"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn serve_forever_keeps_running_after_connection_errors() {
        let error = super::DaemonError::SocketExists {
            path: "stale.sock".to_string(),
        };

        let result = super::handle_connection_error(error, false);

        assert!(result.is_ok());
    }

    #[cfg(unix)]
    struct TestDir {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl TestDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "heimd-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("test directory");
            Self { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    #[cfg(unix)]
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn wait_for_socket(socket: &std::path::Path) {
        for _ in 0..100 {
            if socket.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        panic!("daemon socket was not created");
    }

    #[cfg(unix)]
    fn send_daemon_request(socket: &std::path::Path, request: DaemonRequest) -> DaemonResponse {
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(socket).expect("connect daemon socket");
        let line = encode_request(&request).expect("request line");
        stream.write_all(line.as_bytes()).expect("write request");

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).expect("read response");
        serde_json::from_str(&response).expect("daemon response")
    }

    #[cfg(unix)]
    fn unix_socket_bind_is_supported(socket: &std::path::Path) -> bool {
        match std::os::unix::net::UnixListener::bind(socket) {
            Ok(listener) => {
                drop(listener);
                std::fs::remove_file(socket).expect("remove probe socket");
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
            Err(error) => panic!("probe daemon socket bind failed: {error}"),
        }
    }

    fn approval_request() -> ApprovalRequest {
        ApprovalRequest::builder(
            "request-1",
            ApprovalTransportName::new("slack").expect("transport"),
        )
        .grants([ApprovalGrant::new("aws.prod-readonly", "aws_prod")])
        .requester("codex")
        .command(["aws", "sts", "get-caller-identity"])
        .cwd("/workspace")
        .options([ApprovalOption::new("15m", "Approve 15m")])
        .build()
        .expect("approval request")
    }
}
