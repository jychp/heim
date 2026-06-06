//! Local daemon for Heim approval workflows.
//!
//! `heimd` owns long-lived local IPC needed by interactive approval transports.
//! Slack Socket Mode uses this daemon boundary to dispatch and resolve approvals.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, error::ErrorKind};
use heim_approvals::{
    ApprovalDecision, ApprovalGrantDecision, ApprovalOption, ApprovalRequest, ApprovalSession,
    ApprovalSessionStatus,
};
use heim_sources::{ResolvedSecret, SecretKind, SecretSource, UnsafeLocalAuthSource};
use serde::{Deserialize, Serialize};

const MAX_ACTIVE_CONNECTIONS: usize = 64;
const MAX_ACTIVE_APPROVAL_WAITS: usize = 48;
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

        /// Config file to load approval transports from.
        #[arg(long)]
        config_file: Option<PathBuf>,

        /// Unsafe local auth file to resolve approval transport secrets from.
        #[arg(long)]
        auth_file: Option<PathBuf>,

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
        Some(Command::Serve {
            socket,
            config_file,
            auth_file,
            once,
        }) => run_serve(socket, config_file, auth_file, once),
        Some(Command::Ping { socket }) => run_ping(socket),
        None => ok("heimd: ok\n"),
    }
}

fn run_serve(
    socket: Option<PathBuf>,
    config_file: Option<PathBuf>,
    auth_file: Option<PathBuf>,
    once: bool,
) -> CommandResult {
    let socket = match socket.or_else(|| default_socket_path().ok()) {
        Some(socket) => socket,
        None => {
            return command_error(2, "failed to resolve heimd socket path\n");
        }
    };

    let dispatch = match ApprovalDispatchRuntime::from_sources(config_file, auth_file) {
        Ok(dispatch) => dispatch,
        Err(error) => return command_error(2, format!("{error}\n")),
    };

    let result = if once {
        serve_once_with_dispatch(&socket, dispatch)
    } else {
        serve_forever_with_dispatch(&socket, dispatch)
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
    ApprovalWaitLimitReached,
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

#[derive(Debug)]
struct ApprovalDispatchRuntime<C = SlackSocketModeClient> {
    slack: Option<SlackApprovalRuntime<C>>,
}

impl ApprovalDispatchRuntime<SlackSocketModeClient> {
    fn from_sources(
        config_file: Option<PathBuf>,
        auth_file: Option<PathBuf>,
    ) -> Result<Self, DaemonError> {
        let config = match config_file {
            Some(path) => heim_config::load_config_file(path),
            None => heim_config::load_default_config_file(),
        }
        .map_err(DaemonError::LoadConfig)?;

        if config.approval_transports.is_empty() {
            return Ok(Self::empty());
        }

        let source = match auth_file {
            Some(path) => UnsafeLocalAuthSource::load_file(path),
            None => UnsafeLocalAuthSource::load_default(),
        }
        .map_err(DaemonError::ResolveSecret)?;

        Ok(Self {
            slack: SlackApprovalRuntime::from_config(&config, &source)?,
        })
    }
}

impl<C> ApprovalDispatchRuntime<C>
where
    C: SlackSocketModeApi + Clone + Send + Sync + 'static,
{
    fn empty() -> Self {
        Self { slack: None }
    }

    fn dispatch_session(&self, session: &ApprovalSession) -> Result<(), DaemonError> {
        if let Some(slack) = &self.slack {
            slack.dispatch_session(session)?;
        }
        Ok(())
    }

    fn start_socket_mode(&self, state: Arc<SharedDaemonState>) {
        if let Some(slack) = &self.slack {
            slack.start_socket_mode(state);
        }
    }
}

#[derive(Debug, Clone)]
struct SlackApprovalRuntime<C> {
    client: C,
    transports: Arc<BTreeMap<String, SlackTransportRuntime>>,
}

impl SlackApprovalRuntime<SlackSocketModeClient> {
    fn from_config(
        config: &heim_config::HeimConfig,
        source: &dyn SecretSource,
    ) -> Result<Option<Self>, DaemonError> {
        let mut transports = BTreeMap::new();
        for transport in &config.approval_transports {
            let heim_config::ApprovalTransportKind::Slack {
                channel,
                bot_token,
                app_token,
            } = &transport.kind;
            let ResolvedSecret::SlackBotToken { token: bot_token } = source
                .resolve(bot_token, SecretKind::SlackBotToken)
                .map_err(DaemonError::ResolveSecret)?
            else {
                return Err(DaemonError::ApprovalDispatchConfig {
                    transport: transport.name.to_string(),
                    message: "bot_token did not resolve to a Slack bot token".to_owned(),
                });
            };
            let ResolvedSecret::SlackAppToken { token: app_token } = source
                .resolve(app_token, SecretKind::SlackAppToken)
                .map_err(DaemonError::ResolveSecret)?
            else {
                return Err(DaemonError::ApprovalDispatchConfig {
                    transport: transport.name.to_string(),
                    message: "app_token did not resolve to a Slack app token".to_owned(),
                });
            };
            transports.insert(
                transport.name.to_string(),
                SlackTransportRuntime {
                    name: transport.name.to_string(),
                    channel: channel.clone(),
                    bot_token,
                    app_token,
                },
            );
        }

        if transports.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            client: SlackSocketModeClient::new(),
            transports: Arc::new(transports),
        }))
    }
}

impl<C> SlackApprovalRuntime<C>
where
    C: SlackSocketModeApi + Clone + Send + Sync + 'static,
{
    #[cfg(test)]
    #[cfg(test)]
    fn new(client: C, transports: impl IntoIterator<Item = SlackTransportRuntime>) -> Self {
        Self {
            client,
            transports: Arc::new(
                transports
                    .into_iter()
                    .map(|transport| (transport.name.clone(), transport))
                    .collect(),
            ),
        }
    }

    fn dispatch_session(&self, session: &ApprovalSession) -> Result<(), DaemonError> {
        let Some(transport) = self.transports.get(session.request().transport.as_str()) else {
            return Ok(());
        };

        self.client
            .post_approval_request(transport, session)
            .map_err(DaemonError::Slack)
    }

    fn start_socket_mode(&self, state: Arc<SharedDaemonState>) {
        let transports = self.transports.values().cloned().collect::<Vec<_>>();
        for transport in transports {
            let client = self.client.clone();
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                loop {
                    if let Err(error) = client.run_socket_mode(&transport, &state) {
                        eprintln!("heimd: slack socket mode error: {error}");
                    }
                    std::thread::sleep(Duration::from_secs(5));
                }
            });
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlackTransportRuntime {
    name: String,
    channel: String,
    bot_token: String,
    app_token: String,
}

trait SlackSocketModeApi {
    fn post_approval_request(
        &self,
        transport: &SlackTransportRuntime,
        session: &ApprovalSession,
    ) -> Result<(), SlackRuntimeError>;

    fn run_socket_mode(
        &self,
        transport: &SlackTransportRuntime,
        state: &SharedDaemonState,
    ) -> Result<(), SlackRuntimeError>;
}

#[derive(Debug, Clone)]
struct SlackSocketModeClient {
    http: reqwest::blocking::Client,
}

impl SlackSocketModeClient {
    fn new() -> Self {
        Self {
            http: reqwest::blocking::Client::new(),
        }
    }
}

impl SlackSocketModeApi for SlackSocketModeClient {
    fn post_approval_request(
        &self,
        transport: &SlackTransportRuntime,
        session: &ApprovalSession,
    ) -> Result<(), SlackRuntimeError> {
        let response = self
            .http
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&transport.bot_token)
            .json(&SlackPostMessageRequest::for_session(
                &transport.channel,
                session,
            ))
            .send()
            .map_err(SlackRuntimeError::Http)?;
        let response: SlackApiResponse = response.json().map_err(SlackRuntimeError::Http)?;
        if response.ok {
            Ok(())
        } else {
            Err(SlackRuntimeError::Api {
                method: "chat.postMessage",
                error: response.error.unwrap_or_else(|| "unknown_error".to_owned()),
            })
        }
    }

    fn run_socket_mode(
        &self,
        transport: &SlackTransportRuntime,
        state: &SharedDaemonState,
    ) -> Result<(), SlackRuntimeError> {
        let response = self
            .http
            .post("https://slack.com/api/apps.connections.open")
            .bearer_auth(&transport.app_token)
            .send()
            .map_err(SlackRuntimeError::Http)?;
        let response: SlackConnectionOpenResponse =
            response.json().map_err(SlackRuntimeError::Http)?;
        if !response.ok {
            return Err(SlackRuntimeError::Api {
                method: "apps.connections.open",
                error: response.error.unwrap_or_else(|| "unknown_error".to_owned()),
            });
        }
        let url = response.url.ok_or(SlackRuntimeError::MissingSocketUrl)?;
        let (mut socket, _) = tungstenite::connect(url).map_err(SlackRuntimeError::WebSocket)?;

        loop {
            let message = socket.read().map_err(SlackRuntimeError::WebSocket)?;
            if !message.is_text() {
                continue;
            }
            let envelope: SlackSocketEnvelope =
                serde_json::from_str(message.to_text().unwrap_or_default())
                    .map_err(SlackRuntimeError::Parse)?;
            socket
                .send(tungstenite::Message::Text(
                    serde_json::to_string(&SlackSocketAck {
                        envelope_id: envelope.envelope_id.clone(),
                    })
                    .map_err(SlackRuntimeError::Serialize)?
                    .into(),
                ))
                .map_err(SlackRuntimeError::WebSocket)?;
            if let Some(decision) = envelope.into_decision() {
                apply_slack_decision(state, decision)?;
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct SlackPostMessageRequest {
    channel: String,
    text: String,
    blocks: Vec<SlackBlock>,
}

impl SlackPostMessageRequest {
    fn for_session(channel: &str, session: &ApprovalSession) -> Self {
        let request = session.request();
        let grants = request
            .grants
            .iter()
            .map(|grant| format!("{} via {}", grant.name, grant.provider))
            .collect::<Vec<_>>()
            .join(", ");
        let command = request.command.join(" ");
        let mut elements = vec![
            SlackElement::button(
                "Approve",
                "primary",
                "heim.approve",
                SlackActionValue::approved(session.id()),
            ),
            SlackElement::button(
                "Deny",
                "danger",
                "heim.deny",
                SlackActionValue::denied(session.id()),
            ),
        ];

        for option in &request.options {
            elements.push(SlackElement::button(
                option.label.as_str(),
                "primary",
                "heim.approve_option",
                SlackActionValue::approved_with_option(session.id(), option),
            ));
        }

        Self {
            channel: channel.to_owned(),
            text: format!("Heim approval requested for {command}"),
            blocks: vec![
                SlackBlock::section(format!(
                    "*Heim approval requested*\nRequester: `{}`\nCommand: `{}`\nGrants: `{}`\nSession: `{}`",
                    request.requester,
                    command,
                    grants,
                    session.id()
                )),
                SlackBlock::actions(elements),
            ],
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SlackBlock {
    Section { text: SlackText },
    Actions { elements: Vec<SlackElement> },
}

impl SlackBlock {
    fn section(text: String) -> Self {
        Self::Section {
            text: SlackText::mrkdwn(text),
        }
    }

    fn actions(elements: Vec<SlackElement>) -> Self {
        Self::Actions { elements }
    }
}

#[derive(Debug, Serialize)]
struct SlackText {
    #[serde(rename = "type")]
    text_type: &'static str,
    text: String,
}

impl SlackText {
    fn mrkdwn(text: String) -> Self {
        Self {
            text_type: "mrkdwn",
            text,
        }
    }

    fn plain(text: &str) -> Self {
        Self {
            text_type: "plain_text",
            text: text.to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SlackElement {
    #[serde(rename = "type")]
    element_type: &'static str,
    text: SlackText,
    style: &'static str,
    action_id: &'static str,
    value: String,
}

impl SlackElement {
    fn button(
        text: &str,
        style: &'static str,
        action_id: &'static str,
        value: SlackActionValue,
    ) -> Self {
        Self {
            element_type: "button",
            text: SlackText::plain(text),
            style,
            action_id,
            value: serde_json::to_string(&value).expect("slack action value serializes"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SlackActionValue {
    session_id: String,
    decision: SlackActionDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    option_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    option_label: Option<String>,
}

impl SlackActionValue {
    fn approved(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_owned(),
            decision: SlackActionDecision::Approved,
            option_id: None,
            option_label: None,
        }
    }

    fn denied(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_owned(),
            decision: SlackActionDecision::Denied,
            option_id: None,
            option_label: None,
        }
    }

    fn approved_with_option(session_id: &str, option: &ApprovalOption) -> Self {
        Self {
            session_id: session_id.to_owned(),
            decision: SlackActionDecision::ApprovedWithOption,
            option_id: Some(option.id.clone()),
            option_label: Some(option.label.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SlackActionDecision {
    Approved,
    Denied,
    ApprovedWithOption,
}

#[derive(Debug, Deserialize)]
struct SlackApiResponse {
    ok: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackConnectionOpenResponse {
    ok: bool,
    url: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackSocketEnvelope {
    envelope_id: String,
    payload: Option<SlackSocketPayload>,
}

impl SlackSocketEnvelope {
    fn into_decision(self) -> Option<SlackResolvedDecision> {
        let payload = self.payload?;
        if payload.payload_type != "block_actions" {
            return None;
        }
        let action = payload.actions.into_iter().next()?;
        let value: SlackActionValue = serde_json::from_str(&action.value).ok()?;
        Some(SlackResolvedDecision {
            value,
            approver: payload
                .user
                .map(|user| user.id)
                .unwrap_or_else(|| "slack".to_owned()),
        })
    }
}

#[derive(Debug, Deserialize)]
struct SlackSocketPayload {
    #[serde(rename = "type")]
    payload_type: String,
    user: Option<SlackSocketUser>,
    #[serde(default)]
    actions: Vec<SlackSocketAction>,
}

#[derive(Debug, Deserialize)]
struct SlackSocketUser {
    id: String,
}

#[derive(Debug, Deserialize)]
struct SlackSocketAction {
    value: String,
}

#[derive(Debug, Serialize)]
struct SlackSocketAck {
    envelope_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlackResolvedDecision {
    value: SlackActionValue,
    approver: String,
}

fn apply_slack_decision(
    state: &SharedDaemonState,
    decision: SlackResolvedDecision,
) -> Result<(), SlackRuntimeError> {
    let approval = match decision.value.decision {
        SlackActionDecision::Approved => ApprovalDecision::Approved {
            decision: ApprovalGrantDecision::new(decision.approver, slack_decided_at()),
        },
        SlackActionDecision::Denied => ApprovalDecision::Denied {
            decision: ApprovalGrantDecision::new(decision.approver, slack_decided_at()),
        },
        SlackActionDecision::ApprovedWithOption => ApprovalDecision::ApprovedWithOption {
            decision: ApprovalGrantDecision::new(decision.approver, slack_decided_at()),
            option: ApprovalOption::new(
                decision.value.option_id.unwrap_or_default(),
                decision.value.option_label.unwrap_or_default(),
            ),
        },
    };
    match handle_request(
        state,
        DaemonRequest::ApprovalDecide {
            session_id: decision.value.session_id,
            decision: approval,
        },
    ) {
        DaemonResponse::ApprovalDecided { .. } => Ok(()),
        DaemonResponse::Error { message, .. } => Err(SlackRuntimeError::Decision(message)),
        other => Err(SlackRuntimeError::Decision(format!(
            "unexpected daemon response: {other:?}"
        ))),
    }
}

fn slack_decided_at() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

#[derive(Debug)]
pub enum SlackRuntimeError {
    Http(reqwest::Error),
    WebSocket(tungstenite::Error),
    Serialize(serde_json::Error),
    Parse(serde_json::Error),
    Api { method: &'static str, error: String },
    MissingSocketUrl,
    Decision(String),
}

impl fmt::Display for SlackRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(source) => write!(formatter, "slack HTTP request failed: {source}"),
            Self::WebSocket(source) => write!(formatter, "slack socket mode failed: {source}"),
            Self::Serialize(source) => {
                write!(formatter, "failed to serialize slack message: {source}")
            }
            Self::Parse(source) => {
                write!(formatter, "failed to parse slack socket message: {source}")
            }
            Self::Api { method, error } => write!(formatter, "slack API {method} failed: {error}"),
            Self::MissingSocketUrl => formatter
                .write_str("slack API apps.connections.open did not return a Socket Mode URL"),
            Self::Decision(message) => write!(
                formatter,
                "failed to apply slack approval decision: {message}"
            ),
        }
    }
}

impl std::error::Error for SlackRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(source) => Some(source),
            Self::WebSocket(source) => Some(source),
            Self::Serialize(source) | Self::Parse(source) => Some(source),
            Self::Api { .. } | Self::MissingSocketUrl | Self::Decision(_) => None,
        }
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
    handle_request_with_dispatch::<SlackSocketModeClient>(state, request, None)
}

fn handle_request_with_dispatch<C>(
    state: &SharedDaemonState,
    request: DaemonRequest,
    dispatch: Option<&ApprovalDispatchRuntime<C>>,
) -> DaemonResponse
where
    C: SlackSocketModeApi + Clone + Send + Sync + 'static,
{
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
            if let (DaemonResponse::ApprovalCreated { session }, Some(dispatch)) =
                (&response, dispatch)
                && let Err(error) = dispatch.dispatch_session(session)
            {
                eprintln!("heimd: approval dispatch failed: {error}");
            }
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
    serve_once_with_dispatch(socket, ApprovalDispatchRuntime::empty())
}

#[cfg(unix)]
fn serve_once_with_dispatch(
    socket: &Path,
    dispatch: ApprovalDispatchRuntime,
) -> Result<(), DaemonError> {
    serve(socket, true, dispatch)
}

#[cfg(not(unix))]
pub fn serve_once(_socket: &Path) -> Result<(), DaemonError> {
    serve_once_with_dispatch(_socket, ApprovalDispatchRuntime::empty())
}

#[cfg(not(unix))]
fn serve_once_with_dispatch(
    _socket: &Path,
    _dispatch: ApprovalDispatchRuntime,
) -> Result<(), DaemonError> {
    Err(DaemonError::UnsupportedPlatform {
        feature: "local daemon sockets",
    })
}

#[cfg(unix)]
pub fn serve_forever(socket: &Path) -> Result<(), DaemonError> {
    serve_forever_with_dispatch(socket, ApprovalDispatchRuntime::empty())
}

#[cfg(unix)]
fn serve_forever_with_dispatch(
    socket: &Path,
    dispatch: ApprovalDispatchRuntime,
) -> Result<(), DaemonError> {
    serve(socket, false, dispatch)
}

#[cfg(not(unix))]
pub fn serve_forever(_socket: &Path) -> Result<(), DaemonError> {
    serve_forever_with_dispatch(_socket, ApprovalDispatchRuntime::empty())
}

#[cfg(not(unix))]
fn serve_forever_with_dispatch(
    _socket: &Path,
    _dispatch: ApprovalDispatchRuntime,
) -> Result<(), DaemonError> {
    Err(DaemonError::UnsupportedPlatform {
        feature: "local daemon sockets",
    })
}

#[cfg(unix)]
fn serve(socket: &Path, once: bool, dispatch: ApprovalDispatchRuntime) -> Result<(), DaemonError> {
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
    dispatch.start_socket_mode(Arc::clone(&state));
    let dispatch = Arc::new(dispatch);
    let connection_limit = Arc::new(ActiveConnectionLimit::new(MAX_ACTIVE_CONNECTIONS));
    let wait_limit = Arc::new(ActiveConnectionLimit::new(MAX_ACTIVE_APPROVAL_WAITS));

    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|source| DaemonError::AcceptConnection { source })?;
        if once {
            if let Err(error) = handle_stream(&state, &dispatch, stream, None, &wait_limit) {
                handle_connection_error(error, true)?;
            }
        } else {
            let state = Arc::clone(&state);
            let dispatch = Arc::clone(&dispatch);
            let permit = Arc::clone(&connection_limit).acquire();
            let wait_limit = Arc::clone(&wait_limit);
            std::thread::spawn(move || {
                if let Err(error) =
                    handle_stream(&state, &dispatch, stream, Some(permit), &wait_limit)
                {
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

    fn try_acquire(self: Arc<Self>) -> Option<ActiveConnectionPermit> {
        let mut active = self.active.lock().expect("connection limit lock poisoned");
        if *active >= self.max {
            return None;
        }

        *active += 1;
        drop(active);
        Some(ActiveConnectionPermit { limit: self })
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
    dispatch: &ApprovalDispatchRuntime,
    stream: std::os::unix::net::UnixStream,
    read_permit: Option<ActiveConnectionPermit>,
    wait_limit: &Arc<ActiveConnectionLimit>,
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

    let is_approval_wait = matches!(request, DaemonRequest::ApprovalWait { .. });
    let _read_permit = if is_approval_wait {
        drop(read_permit);
        None
    } else {
        read_permit
    };

    let _wait_permit = if is_approval_wait {
        match Arc::clone(wait_limit).try_acquire() {
            Some(permit) => Some(permit),
            None => {
                let response = DaemonResponse::Error {
                    message: "too many active approval_wait requests".to_owned(),
                    code: Some(DaemonErrorCode::ApprovalWaitLimitReached),
                };
                let line = encode_response(&response)?;
                let mut writer = stream;
                writer
                    .write_all(line.as_bytes())
                    .map_err(|source| DaemonError::WriteConnection { source })?;
                return Ok(());
            }
        }
    } else {
        None
    };

    let response = handle_request_with_dispatch(state, request, Some(dispatch));
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
    LoadConfig(heim_config::ConfigError),
    ResolveSecret(heim_sources::SecretSourceError),
    ApprovalDispatchConfig {
        transport: String,
        message: String,
    },
    Slack(SlackRuntimeError),
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
            Self::LoadConfig(source) => write!(formatter, "failed to load daemon config: {source}"),
            Self::ResolveSecret(source) => write!(formatter, "{source}"),
            Self::ApprovalDispatchConfig { transport, message } => {
                write!(
                    formatter,
                    "approval transport {transport} is invalid: {message}"
                )
            }
            Self::Slack(source) => write!(formatter, "{source}"),
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
            Self::ConfigPath(source) | Self::LoadConfig(source) => Some(source),
            Self::ResolveSecret(source) => Some(source),
            Self::Slack(source) => Some(source),
            Self::CreateDir { source, .. }
            | Self::BindSocket { source, .. }
            | Self::ConnectSocket { source, .. }
            | Self::AcceptConnection { source }
            | Self::CloneConnection { source }
            | Self::ConfigureConnection { source }
            | Self::ReadConnection { source }
            | Self::WriteConnection { source } => Some(source),
            Self::Serialize(source) | Self::Parse(source) => Some(source),
            Self::ApprovalDispatchConfig { .. }
            | Self::UnsupportedPlatform { .. }
            | Self::SocketExists { .. } => None,
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
    fn slack_runtime_dispatches_matching_approval_session() {
        let client = RecordingSlackSocketModeClient::default();
        let runtime = test_slack_runtime(client.clone());
        let session = heim_approvals::ApprovalSession::new("session-1", approval_request(), None)
            .expect("session");

        runtime.dispatch_session(&session).expect("dispatch");

        assert_eq!(
            client.posts.lock().expect("posts").as_slice(),
            [("slack".to_owned(), "session-1".to_owned())]
        );
    }

    #[test]
    fn approval_create_dispatches_slack_session() {
        let state = SharedDaemonState::new();
        let client = RecordingSlackSocketModeClient::default();
        let dispatch = super::ApprovalDispatchRuntime {
            slack: Some(test_slack_runtime(client.clone())),
        };

        let response = super::handle_request_with_dispatch(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
            Some(&dispatch),
        );

        assert!(matches!(response, DaemonResponse::ApprovalCreated { .. }));
        assert_eq!(
            client.posts.lock().expect("posts").as_slice(),
            [("slack".to_owned(), "session-1".to_owned())]
        );
    }

    #[test]
    fn approval_create_returns_created_when_slack_dispatch_fails() {
        let state = SharedDaemonState::new();
        let client = RecordingSlackSocketModeClient {
            fail_posts: true,
            ..Default::default()
        };
        let dispatch = super::ApprovalDispatchRuntime {
            slack: Some(test_slack_runtime(client)),
        };

        let response = super::handle_request_with_dispatch(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
            Some(&dispatch),
        );
        let stored = super::handle_request(
            &state,
            DaemonRequest::ApprovalGet {
                session_id: "session-1".to_owned(),
            },
        );

        assert!(matches!(response, DaemonResponse::ApprovalCreated { .. }));
        assert!(matches!(stored, DaemonResponse::ApprovalSession { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn dispatch_runtime_does_not_load_auth_without_approval_transports() {
        let dir = TestDir::new("dispatch-no-transports");
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            r#"
[providers.aws_prod]
type = "aws_sts"
role_arn = "arn:aws:iam::123456789012:role/ProdReadonly"
"#,
        )
        .expect("write config");

        let runtime = super::ApprovalDispatchRuntime::from_sources(Some(config), None)
            .expect("dispatch runtime");

        assert!(runtime.slack.is_none());
    }

    #[test]
    fn slack_action_applies_approval_decision() {
        let state = SharedDaemonState::new();
        let _ = super::handle_request(
            &state,
            DaemonRequest::ApprovalCreate {
                session_id: "session-1".to_owned(),
                request: approval_request(),
                expires_at: None,
            },
        );

        super::apply_slack_decision(
            &state,
            super::SlackResolvedDecision {
                approver: "U123".to_owned(),
                value: super::SlackActionValue {
                    session_id: "session-1".to_owned(),
                    decision: super::SlackActionDecision::ApprovedWithOption,
                    option_id: Some("15m".to_owned()),
                    option_label: Some("Approve 15m".to_owned()),
                },
            },
        )
        .expect("slack decision");

        let response = super::handle_request(
            &state,
            DaemonRequest::ApprovalGet {
                session_id: "session-1".to_owned(),
            },
        );
        assert!(matches!(
            response,
            DaemonResponse::ApprovalSession { ref session }
                if matches!(
                    session.status(),
                    ApprovalSessionStatus::ApprovedWithOption { option, .. }
                        if option.id == "15m"
                )
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

    #[test]
    fn active_connection_limit_releases_permits_on_drop() {
        let limit = std::sync::Arc::new(super::ActiveConnectionLimit::new(1));
        let permit = std::sync::Arc::clone(&limit)
            .try_acquire()
            .expect("first permit");

        assert!(std::sync::Arc::clone(&limit).try_acquire().is_none());

        drop(permit);

        assert!(std::sync::Arc::clone(&limit).try_acquire().is_some());
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

    #[derive(Clone, Default)]
    struct RecordingSlackSocketModeClient {
        posts: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
        fail_posts: bool,
    }

    impl super::SlackSocketModeApi for RecordingSlackSocketModeClient {
        fn post_approval_request(
            &self,
            transport: &super::SlackTransportRuntime,
            session: &heim_approvals::ApprovalSession,
        ) -> Result<(), super::SlackRuntimeError> {
            if self.fail_posts {
                return Err(super::SlackRuntimeError::Decision(
                    "dispatch failed".to_owned(),
                ));
            }
            self.posts
                .lock()
                .expect("posts")
                .push((transport.name.clone(), session.id().to_owned()));
            Ok(())
        }

        fn run_socket_mode(
            &self,
            _transport: &super::SlackTransportRuntime,
            _state: &super::SharedDaemonState,
        ) -> Result<(), super::SlackRuntimeError> {
            Ok(())
        }
    }

    fn test_slack_runtime(
        client: RecordingSlackSocketModeClient,
    ) -> super::SlackApprovalRuntime<RecordingSlackSocketModeClient> {
        super::SlackApprovalRuntime::new(
            client,
            [super::SlackTransportRuntime {
                name: "slack".to_owned(),
                channel: "#heim-approvals".to_owned(),
                bot_token: "xoxb-secret".to_owned(),
                app_token: "xapp-secret".to_owned(),
            }],
        )
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
