//! Configuration loading for Heim.
//!
//! This crate validates policy documents and converts them into core grant
//! policy types. It does not evaluate policies or execute commands.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fmt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use heim_core::{
    ApprovalPolicy, ApprovalTransportName, CommandRule, GrantName, GrantPolicy, ProviderName,
    RequesterRule,
};
use serde::Deserialize;

/// A validated policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    pub grants: Vec<GrantPolicy>,
    pub approval_transports: Vec<ApprovalTransportName>,
}

/// Validated Heim configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeimConfig {
    pub providers: Vec<ProviderConfig>,
}

impl HeimConfig {
    pub fn provider(&self, name: &str) -> Option<&ProviderConfig> {
        self.providers
            .iter()
            .find(|provider| provider.name().as_str() == name)
    }

    pub fn contains_provider(&self, name: &str) -> bool {
        self.provider(name).is_some()
    }
}

/// One configured credential provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderConfig {
    AwsSts(AwsStsProviderConfig),
    GithubApp(GithubAppProviderConfig),
    GithubPat(GithubPatProviderConfig),
}

impl ProviderConfig {
    pub fn name(&self) -> &ProviderConfigName {
        match self {
            Self::AwsSts(provider) => &provider.name,
            Self::GithubApp(provider) => &provider.name,
            Self::GithubPat(provider) => &provider.name,
        }
    }
}

/// Name of a configured provider in `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderConfigName(String);

impl ProviderConfigName {
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderConfigNameError> {
        let value = value.into();
        validate_config_identifier(&value).map_err(ProviderConfigNameError)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderConfigName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfigNameError(&'static str);

impl fmt::Display for ProviderConfigNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ProviderConfigNameError {}

/// AWS STS provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsStsProviderConfig {
    pub name: ProviderConfigName,
    pub role_arn: String,
    pub region: Option<String>,
    pub duration: Option<String>,
    pub source_profile: Option<String>,
    pub session_name: Option<String>,
    pub external_id: Option<String>,
}

/// GitHub App provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubAppProviderConfig {
    pub name: ProviderConfigName,
    pub app_id: u64,
    pub installation_id: u64,
    pub private_key: LocalAuthRef,
    pub repositories: Vec<String>,
}

/// GitHub PAT provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubPatProviderConfig {
    pub name: ProviderConfigName,
    pub token: LocalAuthRef,
}

/// Reference to an entry in Heim's unsafe local auth file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAuthRef(String);

impl LocalAuthRef {
    pub fn new(value: impl Into<String>) -> Result<Self, LocalAuthRefError> {
        let value = value.into();
        validate_config_identifier(&value).map_err(LocalAuthRefError)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LocalAuthRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAuthRefError(&'static str);

impl fmt::Display for LocalAuthRefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for LocalAuthRefError {}

/// Parsed unsafe local auth file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAuthFile {
    pub secrets: BTreeMap<String, LocalAuthSecret>,
}

impl LocalAuthFile {
    pub fn get(&self, name: &str) -> Option<&LocalAuthSecret> {
        self.secrets.get(name)
    }
}

/// Secret material stored in `.auth.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAuthSecret {
    GithubAppPrivateKey { pem: String },
    GithubPat { token: String },
}

/// Return Heim's default policy directory.
///
/// On Linux this follows `XDG_CONFIG_HOME` when set and falls back to
/// `$HOME/.config`. On macOS it uses `$HOME/Library/Application Support`.
/// On Windows it uses `%APPDATA%`.
pub fn default_policy_dir() -> Result<PathBuf, ConfigError> {
    default_policy_dir_from_env(|name| env::var_os(name))
}

/// Return Heim's default configuration directory.
///
/// This is the platform configuration directory with the `heim` application
/// directory appended.
pub fn default_heim_config_dir() -> Result<PathBuf, ConfigError> {
    default_heim_config_dir_from_env(|name| env::var_os(name))
}

/// Return Heim's default configuration file.
pub fn default_config_file() -> Result<PathBuf, ConfigError> {
    Ok(default_heim_config_dir()?.join("config.toml"))
}

/// Return Heim's unsafe local auth file.
pub fn default_auth_file() -> Result<PathBuf, ConfigError> {
    Ok(default_heim_config_dir()?.join(".auth.json"))
}

/// Return Heim's default local log directory.
pub fn default_log_dir() -> Result<PathBuf, ConfigError> {
    default_log_dir_from_env(|name| env::var_os(name))
}

/// Return Heim's default local audit JSONL file.
pub fn default_audit_log_file() -> Result<PathBuf, ConfigError> {
    default_audit_log_file_from_env(|name| env::var_os(name))
}

/// Return Heim's default local audit JSONL file from an injected environment.
///
/// This is mainly useful for deterministic tests and callers that need to
/// preview the platform default without reading the process environment.
pub fn default_audit_log_file_from_env(
    mut var_os: impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    Ok(default_log_dir_from_env(&mut var_os)?.join("audit.jsonl"))
}

/// Load and validate all TOML policy files from Heim's default policy directory.
pub fn load_default_policy_dir() -> Result<PolicyDocument, ConfigError> {
    load_policy_dir(default_policy_dir()?)
}

/// Load and validate Heim's default configuration file.
pub fn load_default_config_file() -> Result<HeimConfig, ConfigError> {
    load_config_file(default_config_file()?)
}

/// Load and validate a Heim configuration file.
pub fn load_config_file(path: impl AsRef<Path>) -> Result<HeimConfig, ConfigError> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;

    parse_config_str(&contents)
}

/// Parse and validate a Heim configuration file.
pub fn parse_config_str(contents: &str) -> Result<HeimConfig, ConfigError> {
    let raw: RawHeimConfig = toml::from_str(contents).map_err(ConfigError::ParseConfigToml)?;
    raw.try_into()
}

/// Load and validate Heim's unsafe local auth file.
pub fn load_default_auth_file() -> Result<LocalAuthFile, ConfigError> {
    load_auth_file(default_auth_file()?)
}

/// Load and validate an unsafe local auth file.
pub fn load_auth_file(path: impl AsRef<Path>) -> Result<LocalAuthFile, ConfigError> {
    let path = path.as_ref();
    validate_auth_file_permissions(path)?;
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;

    parse_auth_json_str(&contents)
}

/// Parse and validate an unsafe local auth file.
pub fn parse_auth_json_str(contents: &str) -> Result<LocalAuthFile, ConfigError> {
    let raw: BTreeMap<String, RawLocalAuthSecret> =
        serde_json::from_str(contents).map_err(ConfigError::ParseAuthJson)?;
    convert_auth_file(raw)
}

/// Load and validate a TOML policy file.
pub fn load_policy_file(path: impl AsRef<Path>) -> Result<PolicyDocument, ConfigError> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;

    parse_policy_str(&contents)
}

/// Load and validate all `.toml` policy files in a directory.
pub fn load_policy_dir(path: impl AsRef<Path>) -> Result<PolicyDocument, ConfigError> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path).map_err(|source| ConfigError::ReadDir {
        path: path.display().to_string(),
        source,
    })?;

    if !metadata.is_dir() {
        return Err(ConfigError::PolicyPathIsNotDirectory {
            path: path.display().to_string(),
        });
    }

    let mut policy_files = std::fs::read_dir(path)
        .map_err(|source| ConfigError::ReadDir {
            path: path.display().to_string(),
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| ConfigError::ReadDirEntry {
                    path: path.display().to_string(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    policy_files.retain(|candidate| candidate.is_file() && has_toml_extension(candidate));
    policy_files.sort();

    let mut raw_documents = Vec::with_capacity(policy_files.len());
    for file in policy_files {
        let contents = std::fs::read_to_string(&file).map_err(|source| ConfigError::ReadFile {
            path: file.display().to_string(),
            source,
        })?;
        let raw: RawPolicyDocument =
            toml::from_str(&contents).map_err(|source| ConfigError::ParsePolicyToml {
                path: file.display().to_string(),
                source,
            })?;
        raw_documents.push(raw);
    }

    merge_raw_policy_documents(raw_documents)?.try_into()
}

/// Parse and validate a TOML policy document.
pub fn parse_policy_str(contents: &str) -> Result<PolicyDocument, ConfigError> {
    let raw: RawPolicyDocument = toml::from_str(contents).map_err(ConfigError::ParseToml)?;
    raw.try_into()
}

/// Validate that each policy grant references a configured provider.
pub fn validate_policy_provider_refs(
    policy: &PolicyDocument,
    config: &HeimConfig,
) -> Result<(), ConfigError> {
    for grant in &policy.grants {
        let provider = grant.provider.as_str();
        if !config.contains_provider(provider) {
            return Err(ConfigError::UnknownProviderConfig {
                grant: grant.name.as_str().to_owned(),
                provider: provider.to_owned(),
            });
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum ConfigError {
    ConfigDirectoryNotFound,
    ReadDir {
        path: String,
        source: std::io::Error,
    },
    ReadDirEntry {
        path: String,
        source: std::io::Error,
    },
    PolicyPathIsNotDirectory {
        path: String,
    },
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    ParseToml(toml::de::Error),
    ParseConfigToml(toml::de::Error),
    ParsePolicyToml {
        path: String,
        source: toml::de::Error,
    },
    ParseAuthJson(serde_json::Error),
    UnsafeAuthFilePermissions {
        path: String,
        mode: u32,
    },
    MissingProviders,
    InvalidProviderConfigName {
        name: String,
        message: String,
    },
    InvalidProviderType {
        provider: String,
        provider_type: String,
    },
    InvalidProviderConfig {
        provider: String,
        message: String,
    },
    UnknownProviderConfig {
        grant: String,
        provider: String,
    },
    InvalidAuthRef {
        provider: String,
        auth: String,
        message: String,
    },
    InvalidAuthSecretName {
        name: String,
        message: String,
    },
    InvalidAuthSecret {
        name: String,
        message: String,
    },
    InvalidApprovalMode {
        grant: String,
        mode: String,
    },
    MissingGrants,
    DuplicateGrantName {
        grant: String,
    },
    DuplicateApprovalTransport {
        transport: String,
    },
    MissingJitTransport {
        grant: String,
    },
    UnknownApprovalTransport {
        grant: String,
        transport: String,
    },
    InvalidApprovalTransportName {
        name: String,
        message: String,
    },
    InvalidGrantName {
        name: String,
        message: String,
    },
    InvalidProviderName {
        grant: String,
        provider: String,
        message: String,
    },
    InvalidRequester {
        grant: String,
        requester: String,
        message: String,
    },
    InvalidCommand {
        grant: String,
        command: String,
        message: String,
    },
    InvalidGrantPolicy {
        grant: String,
        message: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirectoryNotFound => {
                formatter.write_str("failed to find config directory for Heim")
            }
            Self::ReadDir { path, source } => {
                write!(
                    formatter,
                    "failed to read policy directory {path}: {source}"
                )
            }
            Self::ReadDirEntry { path, source } => write!(
                formatter,
                "failed to read an entry from policy directory {path}: {source}"
            ),
            Self::PolicyPathIsNotDirectory { path } => {
                write!(formatter, "policy path {path} is not a directory")
            }
            Self::ReadFile { path, source } => {
                write!(formatter, "failed to read policy file {path}: {source}")
            }
            Self::ParseToml(error) => write!(formatter, "failed to parse policy TOML: {error}"),
            Self::ParseConfigToml(error) => {
                write!(formatter, "failed to parse Heim config TOML: {error}")
            }
            Self::ParsePolicyToml { path, source } => {
                write!(formatter, "failed to parse policy TOML {path}: {source}")
            }
            Self::ParseAuthJson(source) => {
                write!(
                    formatter,
                    "failed to parse unsafe local auth JSON: {source}"
                )
            }
            Self::UnsafeAuthFilePermissions { path, mode } => write!(
                formatter,
                "unsafe local auth file {path} must not be readable or writable by group or other users; current mode is {mode:o}"
            ),
            Self::MissingProviders => {
                formatter.write_str("Heim config must contain at least one provider")
            }
            Self::InvalidProviderConfigName { name, message } => write!(
                formatter,
                "provider config {name} is not a valid name: {message}"
            ),
            Self::InvalidProviderType {
                provider,
                provider_type,
            } => write!(
                formatter,
                "provider {provider} uses unknown provider type {provider_type}"
            ),
            Self::InvalidProviderConfig { provider, message } => {
                write!(formatter, "provider {provider} is invalid: {message}")
            }
            Self::UnknownProviderConfig { grant, provider } => write!(
                formatter,
                "grant {grant} references provider {provider}, but it is not configured"
            ),
            Self::InvalidAuthRef {
                provider,
                auth,
                message,
            } => write!(
                formatter,
                "provider {provider} references invalid auth entry {auth}: {message}"
            ),
            Self::InvalidAuthSecretName { name, message } => write!(
                formatter,
                "unsafe local auth entry {name} is not a valid name: {message}"
            ),
            Self::InvalidAuthSecret { name, message } => {
                write!(
                    formatter,
                    "unsafe local auth entry {name} is invalid: {message}"
                )
            }
            Self::InvalidApprovalMode { grant, mode } => {
                write!(formatter, "grant {grant} uses unknown approval mode {mode}")
            }
            Self::MissingGrants => formatter.write_str("policy must contain at least one grant"),
            Self::DuplicateGrantName { grant } => {
                write!(formatter, "policy contains duplicate grant {grant}")
            }
            Self::DuplicateApprovalTransport { transport } => {
                write!(
                    formatter,
                    "policy contains duplicate approval transport {transport}"
                )
            }
            Self::MissingJitTransport { grant } => {
                write!(
                    formatter,
                    "grant {grant} uses jit approval without a transport"
                )
            }
            Self::UnknownApprovalTransport { grant, transport } => write!(
                formatter,
                "grant {grant} references unknown approval transport {transport}"
            ),
            Self::InvalidApprovalTransportName { name, message } => write!(
                formatter,
                "approval transport {name} is not a valid name: {message}"
            ),
            Self::InvalidGrantName { name, message } => {
                write!(formatter, "grant {name} is not a valid name: {message}")
            }
            Self::InvalidProviderName {
                grant,
                provider,
                message,
            } => write!(
                formatter,
                "grant {grant} references invalid provider {provider}: {message}"
            ),
            Self::InvalidRequester {
                grant,
                requester,
                message,
            } => write!(
                formatter,
                "grant {grant} has invalid requester {requester}: {message}"
            ),
            Self::InvalidCommand {
                grant,
                command,
                message,
            } => write!(
                formatter,
                "grant {grant} has invalid command rule {command}: {message}"
            ),
            Self::InvalidGrantPolicy { grant, message } => {
                write!(formatter, "grant {grant} is invalid: {message}")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadDir { source, .. } => Some(source),
            Self::ReadDirEntry { source, .. } => Some(source),
            Self::ReadFile { source, .. } => Some(source),
            Self::ParseToml(source) => Some(source),
            Self::ParseConfigToml(source) => Some(source),
            Self::ParsePolicyToml { source, .. } => Some(source),
            Self::ParseAuthJson(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawHeimConfig {
    #[serde(default)]
    providers: BTreeMap<String, RawProviderConfig>,
}

#[derive(Debug, Deserialize)]
struct RawProviderConfig {
    #[serde(rename = "type")]
    provider_type: String,
    role_arn: Option<String>,
    region: Option<String>,
    duration: Option<String>,
    source_profile: Option<String>,
    session_name: Option<String>,
    external_id: Option<String>,
    app_id: Option<u64>,
    installation_id: Option<u64>,
    private_key: Option<RawAuthRef>,
    token: Option<RawAuthRef>,
    #[serde(default)]
    repositories: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawAuthRef {
    auth: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RawLocalAuthSecret {
    GithubAppPrivateKey { pem: String },
    GithubPat { token: String },
}

impl TryFrom<RawHeimConfig> for HeimConfig {
    type Error = ConfigError;

    fn try_from(raw: RawHeimConfig) -> Result<Self, Self::Error> {
        if raw.providers.is_empty() {
            return Err(ConfigError::MissingProviders);
        }

        let providers = raw
            .providers
            .into_iter()
            .map(|(name, provider)| convert_provider_config(name, provider))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { providers })
    }
}

fn convert_provider_config(
    raw_name: String,
    raw: RawProviderConfig,
) -> Result<ProviderConfig, ConfigError> {
    let name = ProviderConfigName::new(&raw_name).map_err(|error| {
        ConfigError::InvalidProviderConfigName {
            name: raw_name.clone(),
            message: error.to_string(),
        }
    })?;

    match raw.provider_type.as_str() {
        "aws_sts" => convert_aws_sts_provider(name, raw_name, raw),
        "github_app" => convert_github_app_provider(name, raw_name, raw),
        "github_pat" => convert_github_pat_provider(name, raw_name, raw),
        provider_type => Err(ConfigError::InvalidProviderType {
            provider: raw_name,
            provider_type: provider_type.to_owned(),
        }),
    }
}

fn convert_aws_sts_provider(
    name: ProviderConfigName,
    raw_name: String,
    raw: RawProviderConfig,
) -> Result<ProviderConfig, ConfigError> {
    let role_arn = required_string(&raw_name, "role_arn", raw.role_arn)?;

    Ok(ProviderConfig::AwsSts(AwsStsProviderConfig {
        name,
        role_arn,
        region: raw.region,
        duration: raw.duration,
        source_profile: raw.source_profile,
        session_name: raw.session_name,
        external_id: raw.external_id,
    }))
}

fn convert_github_app_provider(
    name: ProviderConfigName,
    raw_name: String,
    raw: RawProviderConfig,
) -> Result<ProviderConfig, ConfigError> {
    let app_id = required_number(&raw_name, "app_id", raw.app_id)?;
    let installation_id = required_number(&raw_name, "installation_id", raw.installation_id)?;
    let private_key = convert_auth_ref(&raw_name, "private_key", raw.private_key)?;

    Ok(ProviderConfig::GithubApp(GithubAppProviderConfig {
        name,
        app_id,
        installation_id,
        private_key,
        repositories: raw.repositories,
    }))
}

fn convert_github_pat_provider(
    name: ProviderConfigName,
    raw_name: String,
    raw: RawProviderConfig,
) -> Result<ProviderConfig, ConfigError> {
    let token = convert_auth_ref(&raw_name, "token", raw.token)?;

    Ok(ProviderConfig::GithubPat(GithubPatProviderConfig {
        name,
        token,
    }))
}

fn required_string(
    provider: &str,
    field: &str,
    value: Option<String>,
) -> Result<String, ConfigError> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        Some(_) | None => Err(ConfigError::InvalidProviderConfig {
            provider: provider.to_owned(),
            message: format!("{field} is required"),
        }),
    }
}

fn required_number(provider: &str, field: &str, value: Option<u64>) -> Result<u64, ConfigError> {
    value.ok_or_else(|| ConfigError::InvalidProviderConfig {
        provider: provider.to_owned(),
        message: format!("{field} is required"),
    })
}

fn convert_auth_ref(
    provider: &str,
    field: &str,
    value: Option<RawAuthRef>,
) -> Result<LocalAuthRef, ConfigError> {
    let Some(value) = value else {
        return Err(ConfigError::InvalidProviderConfig {
            provider: provider.to_owned(),
            message: format!("{field}.auth is required"),
        });
    };

    LocalAuthRef::new(&value.auth).map_err(|error| ConfigError::InvalidAuthRef {
        provider: provider.to_owned(),
        auth: value.auth,
        message: error.to_string(),
    })
}

fn convert_auth_file(
    raw: BTreeMap<String, RawLocalAuthSecret>,
) -> Result<LocalAuthFile, ConfigError> {
    let secrets = raw
        .into_iter()
        .map(|(name, secret)| {
            let name = validate_auth_secret_name(name)?;
            let secret = convert_auth_secret(&name, secret)?;
            Ok((name, secret))
        })
        .collect::<Result<BTreeMap<_, _>, ConfigError>>()?;

    Ok(LocalAuthFile { secrets })
}

fn validate_auth_secret_name(name: String) -> Result<String, ConfigError> {
    validate_config_identifier(&name).map_err(|error| ConfigError::InvalidAuthSecretName {
        name: name.clone(),
        message: error.to_owned(),
    })?;
    Ok(name)
}

fn convert_auth_secret(
    name: &str,
    raw: RawLocalAuthSecret,
) -> Result<LocalAuthSecret, ConfigError> {
    match raw {
        RawLocalAuthSecret::GithubAppPrivateKey { pem } if pem.trim().is_empty() => {
            Err(ConfigError::InvalidAuthSecret {
                name: name.to_owned(),
                message: "pem is required".to_owned(),
            })
        }
        RawLocalAuthSecret::GithubAppPrivateKey { pem } => {
            Ok(LocalAuthSecret::GithubAppPrivateKey { pem })
        }
        RawLocalAuthSecret::GithubPat { token } if token.trim().is_empty() => {
            Err(ConfigError::InvalidAuthSecret {
                name: name.to_owned(),
                message: "token is required".to_owned(),
            })
        }
        RawLocalAuthSecret::GithubPat { token } => Ok(LocalAuthSecret::GithubPat { token }),
    }
}

fn validate_config_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("identifier cannot be empty");
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("identifier may only contain ASCII letters, digits, hyphens, and underscores");
    }

    Ok(())
}

#[cfg(unix)]
fn validate_auth_file_permissions(path: &Path) -> Result<(), ConfigError> {
    let metadata = std::fs::metadata(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;

    if mode & 0o077 != 0 {
        return Err(ConfigError::UnsafeAuthFilePermissions {
            path: path.display().to_string(),
            mode,
        });
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_auth_file_permissions(path: &Path) -> Result<(), ConfigError> {
    std::fs::metadata(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RawPolicyDocument {
    #[serde(default)]
    grants: Vec<RawGrant>,
    #[serde(default)]
    approval_transports: BTreeMap<String, RawApprovalTransport>,
}

#[derive(Debug, Deserialize)]
struct RawGrant {
    name: String,
    provider: String,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    commands: Vec<String>,
    approval: String,
}

#[derive(Debug, Deserialize)]
struct RawApprovalTransport {
    #[serde(rename = "type")]
    transport_type: String,
}

fn has_toml_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "toml")
}

fn default_policy_dir_from_env(
    mut var_os: impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    Ok(default_heim_config_dir_from_env(&mut var_os)?.join("policies"))
}

fn default_log_dir_from_env(
    mut var_os: impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    Ok(default_heim_config_dir_from_env(&mut var_os)?.join("logs"))
}

fn default_heim_config_dir_from_env(
    mut var_os: impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    let config_dir = platform_config_dir(&mut var_os)?;
    Ok(config_dir.join("heim"))
}

#[cfg(target_os = "macos")]
fn platform_config_dir(
    var_os: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    let home = var_os("HOME").ok_or(ConfigError::ConfigDirectoryNotFound)?;
    Ok(PathBuf::from(home).join("Library/Application Support"))
}

#[cfg(target_os = "windows")]
fn platform_config_dir(
    var_os: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    if let Some(appdata) = var_os("APPDATA") {
        return Ok(PathBuf::from(appdata));
    }

    let profile = var_os("USERPROFILE").ok_or(ConfigError::ConfigDirectoryNotFound)?;
    Ok(PathBuf::from(profile).join("AppData/Roaming"))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_config_dir(
    var_os: &mut impl FnMut(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    if let Some(xdg_config_home) = var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg_config_home));
    }

    let home = var_os("HOME").ok_or(ConfigError::ConfigDirectoryNotFound)?;
    Ok(PathBuf::from(home).join(".config"))
}

fn merge_raw_policy_documents(
    documents: Vec<RawPolicyDocument>,
) -> Result<RawPolicyDocument, ConfigError> {
    let mut grants = Vec::new();
    let mut approval_transports = BTreeMap::new();

    for document in documents {
        grants.extend(document.grants);

        for (name, transport) in document.approval_transports {
            if approval_transports
                .insert(name.clone(), transport)
                .is_some()
            {
                return Err(ConfigError::DuplicateApprovalTransport { transport: name });
            }
        }
    }

    Ok(RawPolicyDocument {
        grants,
        approval_transports,
    })
}

impl TryFrom<RawPolicyDocument> for PolicyDocument {
    type Error = ConfigError;

    fn try_from(raw: RawPolicyDocument) -> Result<Self, Self::Error> {
        if raw.grants.is_empty() {
            return Err(ConfigError::MissingGrants);
        }

        let mut grant_names = BTreeSet::new();
        for grant in &raw.grants {
            if !grant_names.insert(grant.name.as_str()) {
                return Err(ConfigError::DuplicateGrantName {
                    grant: grant.name.clone(),
                });
            }
        }

        let approval_transports = raw
            .approval_transports
            .into_iter()
            .map(|(name, transport)| {
                let _transport_type = transport.transport_type;

                ApprovalTransportName::new(&name).map_err(|error| {
                    ConfigError::InvalidApprovalTransportName {
                        name,
                        message: error.to_string(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let grants = raw
            .grants
            .into_iter()
            .map(|raw_grant| convert_grant(raw_grant, &approval_transports))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            grants,
            approval_transports,
        })
    }
}

fn convert_grant(
    raw_grant: RawGrant,
    approval_transports: &[ApprovalTransportName],
) -> Result<GrantPolicy, ConfigError> {
    let raw_name = raw_grant.name;
    let name = GrantName::new(&raw_name).map_err(|error| ConfigError::InvalidGrantName {
        name: raw_name.clone(),
        message: error.to_string(),
    })?;

    let provider = ProviderName::new(&raw_grant.provider).map_err(|error| {
        ConfigError::InvalidProviderName {
            grant: raw_name.to_owned(),
            provider: raw_grant.provider.clone(),
            message: error.to_string(),
        }
    })?;

    let requesters = raw_grant
        .allow
        .into_iter()
        .map(|requester| {
            requester
                .parse()
                .map_err(
                    |error: heim_core::BinaryNameError| ConfigError::InvalidRequester {
                        grant: raw_name.clone(),
                        requester,
                        message: error.to_string(),
                    },
                )
        })
        .collect::<Result<Vec<RequesterRule>, _>>()?;

    let commands = raw_grant
        .commands
        .into_iter()
        .map(|command| {
            command
                .parse()
                .map_err(
                    |error: heim_core::CommandRuleError| ConfigError::InvalidCommand {
                        grant: raw_name.to_owned(),
                        command,
                        message: error.to_string(),
                    },
                )
        })
        .collect::<Result<Vec<CommandRule>, _>>()?;

    let approval = convert_approval(&raw_name, raw_grant.approval, approval_transports)?;

    GrantPolicy::new(name, provider, requesters, commands, approval).map_err(|error| {
        ConfigError::InvalidGrantPolicy {
            grant: raw_name.to_owned(),
            message: error.to_string(),
        }
    })
}

fn convert_approval(
    grant: &str,
    raw: String,
    approval_transports: &[ApprovalTransportName],
) -> Result<ApprovalPolicy, ConfigError> {
    if raw == "grant" {
        return Ok(ApprovalPolicy::grant());
    }

    if raw == "jit" {
        return Err(ConfigError::MissingJitTransport {
            grant: grant.to_owned(),
        });
    }

    if let Some(transport) = raw.strip_prefix("jit:") {
        if transport.is_empty() {
            return Err(ConfigError::MissingJitTransport {
                grant: grant.to_owned(),
            });
        }

        if !approval_transports
            .iter()
            .any(|candidate| candidate.as_str() == transport)
        {
            return Err(ConfigError::UnknownApprovalTransport {
                grant: grant.to_owned(),
                transport: transport.to_owned(),
            });
        }

        let transport = ApprovalTransportName::new(transport).map_err(|error| {
            ConfigError::InvalidApprovalTransportName {
                name: transport.to_owned(),
                message: error.to_string(),
            }
        })?;

        return Ok(ApprovalPolicy::jit(transport));
    }

    Err(ConfigError::InvalidApprovalMode {
        grant: grant.to_owned(),
        mode: raw,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use heim_core::ApprovalMode;

    use super::{
        ConfigError, LocalAuthSecret, ProviderConfig, default_audit_log_file_from_env,
        default_log_dir_from_env, default_policy_dir_from_env, load_auth_file, load_policy_dir,
        parse_auth_json_str, parse_config_str, parse_policy_str,
    };

    const VALID_POLICY: &str = r##"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex", "*"]
commands = ["aws *"]
approval = "jit:slack"

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
"##;

    const VALID_CONFIG: &str = r#"
[providers.aws_prod]
type = "aws_sts"
role_arn = "arn:aws:iam::123456789012:role/ProdReadonly"
region = "eu-west-1"
duration = "15m"
source_profile = "prod"

[providers.github_drymn]
type = "github_app"
app_id = 123456
installation_id = 987654
private_key = { auth = "github_drymn_app_private_key" }
repositories = ["drymn/backend"]

[providers.github_personal]
type = "github_pat"
token = { auth = "github_personal_pat" }
"#;

    const VALID_AUTH: &str = r#"
{
  "github_drymn_app_private_key": {
    "type": "github_app_private_key",
    "pem": "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----\n"
  },
  "github_personal_pat": {
    "type": "github_pat",
    "token": "redacted"
  }
}
"#;

    #[test]
    fn parses_valid_config_into_provider_configs() {
        let config = parse_config_str(VALID_CONFIG).expect("valid config");

        assert_eq!(config.providers.len(), 3);

        let Some(ProviderConfig::AwsSts(provider)) = config.provider("aws_prod") else {
            panic!("aws provider");
        };
        assert_eq!(
            provider.role_arn,
            "arn:aws:iam::123456789012:role/ProdReadonly"
        );
        assert_eq!(provider.region.as_deref(), Some("eu-west-1"));

        let Some(ProviderConfig::GithubApp(provider)) = config.provider("github_drymn") else {
            panic!("github app provider");
        };
        assert_eq!(provider.app_id, 123456);
        assert_eq!(provider.installation_id, 987654);
        assert_eq!(
            provider.private_key.as_str(),
            "github_drymn_app_private_key"
        );
        assert_eq!(provider.repositories, ["drymn/backend"]);

        let Some(ProviderConfig::GithubPat(provider)) = config.provider("github_personal") else {
            panic!("github pat provider");
        };
        assert_eq!(provider.token.as_str(), "github_personal_pat");
    }

    #[test]
    fn rejects_config_without_providers() {
        let error = parse_config_str("").expect_err("missing providers");

        assert!(matches!(error, ConfigError::MissingProviders));
    }

    #[test]
    fn rejects_unknown_provider_type() {
        let error = parse_config_str(
            r#"
[providers.test]
type = "unknown"
"#,
        )
        .expect_err("unknown provider");

        assert!(matches!(error, ConfigError::InvalidProviderType { .. }));
    }

    #[test]
    fn rejects_missing_provider_fields() {
        let error = parse_config_str(
            r#"
[providers.github_drymn]
type = "github_app"
app_id = 123456
private_key = { auth = "github_drymn_app_private_key" }
"#,
        )
        .expect_err("missing provider field");

        assert!(matches!(error, ConfigError::InvalidProviderConfig { .. }));
    }

    #[test]
    fn rejects_invalid_auth_ref() {
        let error = parse_config_str(
            r#"
[providers.github_personal]
type = "github_pat"
token = { auth = "github.personal.pat" }
"#,
        )
        .expect_err("invalid auth ref");

        assert!(matches!(error, ConfigError::InvalidAuthRef { .. }));
    }

    #[test]
    fn validates_policy_provider_refs_against_config() {
        let policy = parse_policy_str(VALID_POLICY).expect("valid policy");
        let config = parse_config_str(VALID_CONFIG).expect("valid config");

        super::validate_policy_provider_refs(&policy, &config).expect("provider refs");
    }

    #[test]
    fn rejects_unknown_policy_provider_ref() {
        let policy = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "missing_provider"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        )
        .expect("valid policy");
        let config = parse_config_str(VALID_CONFIG).expect("valid config");

        let error = super::validate_policy_provider_refs(&policy, &config)
            .expect_err("unknown provider ref");

        assert!(matches!(error, ConfigError::UnknownProviderConfig { .. }));
    }

    #[test]
    fn parses_unsafe_local_auth_file() {
        let auth = parse_auth_json_str(VALID_AUTH).expect("valid auth");

        assert!(matches!(
            auth.get("github_drymn_app_private_key"),
            Some(LocalAuthSecret::GithubAppPrivateKey { .. })
        ));
        assert!(matches!(
            auth.get("github_personal_pat"),
            Some(LocalAuthSecret::GithubPat { .. })
        ));
    }

    #[test]
    fn rejects_empty_unsafe_local_auth_secret() {
        let error = parse_auth_json_str(
            r#"
{
  "github_personal_pat": {
    "type": "github_pat",
    "token": ""
  }
}
"#,
        )
        .expect_err("empty secret");

        assert!(matches!(error, ConfigError::InvalidAuthSecret { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unsafe_local_auth_file_with_group_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempPolicyDir::new();
        let path = dir.path().join(".auth.json");
        fs::write(&path, VALID_AUTH).expect("write auth file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("set auth file permissions");

        let error = load_auth_file(&path).expect_err("unsafe auth file");

        assert!(matches!(
            error,
            ConfigError::UnsafeAuthFilePermissions { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn loads_unsafe_local_auth_file_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempPolicyDir::new();
        let path = dir.path().join(".auth.json");
        fs::write(&path, VALID_AUTH).expect("write auth file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set auth file permissions");

        let auth = load_auth_file(&path).expect("safe enough auth file");

        assert!(auth.get("github_personal_pat").is_some());
    }

    #[test]
    fn parses_valid_policy_into_core_grants() {
        let document = parse_policy_str(VALID_POLICY).expect("valid policy");

        assert_eq!(document.grants.len(), 1);
        assert_eq!(document.approval_transports.len(), 1);

        let grant = &document.grants[0];
        assert_eq!(grant.name.as_str(), "aws.prod-readonly");
        assert_eq!(grant.provider.as_str(), "aws_prod");
        assert_eq!(grant.requesters.len(), 2);
        assert_eq!(grant.commands.len(), 1);
        assert!(matches!(grant.approval.mode, ApprovalMode::Jit { .. }));
    }

    #[test]
    fn rejects_jit_policy_without_transport() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit"
"#,
        )
        .expect_err("missing jit transport");

        assert!(matches!(error, ConfigError::MissingJitTransport { .. }));
    }

    #[test]
    fn rejects_unknown_approval_transport() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit:slack"
"#,
        )
        .expect_err("unknown transport");

        assert!(matches!(
            error,
            ConfigError::UnknownApprovalTransport { .. }
        ));
    }

    #[test]
    fn rejects_missing_provider() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        )
        .expect_err("missing provider");

        assert!(matches!(error, ConfigError::ParseToml(_)));
    }

    #[test]
    fn rejects_empty_requesters() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = []
commands = ["aws *"]
approval = "grant"
"#,
        )
        .expect_err("missing requesters");

        assert!(matches!(error, ConfigError::InvalidGrantPolicy { .. }));
    }

    #[test]
    fn rejects_empty_commands() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
approval = "grant"
"#,
        )
        .expect_err("missing commands");

        assert!(matches!(error, ConfigError::InvalidGrantPolicy { .. }));
    }

    #[test]
    fn rejects_invalid_command_wildcard() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws s3*"]
approval = "grant"
"#,
        )
        .expect_err("invalid command");

        assert!(matches!(error, ConfigError::InvalidCommand { .. }));
    }

    #[test]
    fn rejects_policy_without_grants() {
        let error = parse_policy_str(
            r##"
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
"##,
        )
        .expect_err("missing grants");

        assert!(matches!(error, ConfigError::MissingGrants));
    }

    #[test]
    fn rejects_duplicate_grant_names() {
        let error = parse_policy_str(
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"

[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        )
        .expect_err("duplicate grant");

        assert!(matches!(error, ConfigError::DuplicateGrantName { .. }));
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn default_policy_dir_uses_xdg_config_home_on_linux() {
        let path = default_policy_dir_from_env(|name| match name {
            "XDG_CONFIG_HOME" => Some(OsString::from("/tmp/config")),
            "HOME" => Some(OsString::from("/home/alice")),
            _ => None,
        })
        .expect("default policy directory");

        assert_eq!(path, PathBuf::from("/tmp/config/heim/policies"));
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn default_log_dir_uses_xdg_config_home_on_linux() {
        let path = default_log_dir_from_env(|name| match name {
            "XDG_CONFIG_HOME" => Some(OsString::from("/tmp/config")),
            "HOME" => Some(OsString::from("/home/alice")),
            _ => None,
        })
        .expect("default log directory");

        assert_eq!(path, PathBuf::from("/tmp/config/heim/logs"));
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn default_audit_log_file_uses_xdg_config_home_on_linux() {
        let path = default_audit_log_file_from_env(|name| match name {
            "XDG_CONFIG_HOME" => Some(OsString::from("/tmp/config")),
            "HOME" => Some(OsString::from("/home/alice")),
            _ => None,
        })
        .expect("default audit log file");

        assert_eq!(path, PathBuf::from("/tmp/config/heim/logs/audit.jsonl"));
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn default_policy_dir_falls_back_to_home_config_on_linux() {
        let path = default_policy_dir_from_env(|name| match name {
            "HOME" => Some(OsString::from("/home/alice")),
            _ => None,
        })
        .expect("default policy directory");

        assert_eq!(path, PathBuf::from("/home/alice/.config/heim/policies"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_policy_dir_uses_application_support_on_macos() {
        let path = default_policy_dir_from_env(|name| match name {
            "HOME" => Some(OsString::from("/Users/alice")),
            _ => None,
        })
        .expect("default policy directory");

        assert_eq!(
            path,
            PathBuf::from("/Users/alice/Library/Application Support/heim/policies")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_log_dir_uses_application_support_on_macos() {
        let path = default_log_dir_from_env(|name| match name {
            "HOME" => Some(OsString::from("/Users/alice")),
            _ => None,
        })
        .expect("default log directory");

        assert_eq!(
            path,
            PathBuf::from("/Users/alice/Library/Application Support/heim/logs")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn default_policy_dir_uses_appdata_on_windows() {
        let path = default_policy_dir_from_env(|name| match name {
            "APPDATA" => Some(OsString::from(r"C:\Users\Alice\AppData\Roaming")),
            "USERPROFILE" => Some(OsString::from(r"C:\Users\Alice")),
            _ => None,
        })
        .expect("default policy directory");

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\Alice\AppData\Roaming").join("heim/policies")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn default_log_dir_uses_appdata_on_windows() {
        let path = default_log_dir_from_env(|name| match name {
            "APPDATA" => Some(OsString::from(r"C:\Users\Alice\AppData\Roaming")),
            "USERPROFILE" => Some(OsString::from(r"C:\Users\Alice")),
            _ => None,
        })
        .expect("default log directory");

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\Alice\AppData\Roaming").join("heim/logs")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn default_policy_dir_falls_back_to_user_profile_on_windows() {
        let path = default_policy_dir_from_env(|name| match name {
            "USERPROFILE" => Some(OsString::from(r"C:\Users\Alice")),
            _ => None,
        })
        .expect("default policy directory");

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\Alice\AppData\Roaming\heim\policies")
        );
    }

    #[test]
    fn loads_policy_directory_from_multiple_toml_files() {
        let dir = TempPolicyDir::new();
        dir.write(
            "approval.toml",
            r##"
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
"##,
        );
        dir.write(
            "aws.toml",
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "jit:slack"
"#,
        );
        dir.write(
            "notes.txt",
            r#"
this is ignored
"#,
        );

        let document = load_policy_dir(dir.path()).expect("valid policy directory");

        assert_eq!(document.grants.len(), 1);
        assert_eq!(document.grants[0].name.as_str(), "aws.prod-readonly");
        assert_eq!(document.approval_transports.len(), 1);
        assert_eq!(document.approval_transports[0].as_str(), "slack");
    }

    #[test]
    fn rejects_policy_directory_without_grants() {
        let dir = TempPolicyDir::new();
        dir.write(
            "approval.toml",
            r##"
[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
"##,
        );

        let error = load_policy_dir(dir.path()).expect_err("missing grants");

        assert!(matches!(error, ConfigError::MissingGrants));
    }

    #[test]
    fn rejects_duplicate_grants_across_policy_directory() {
        let dir = TempPolicyDir::new();
        dir.write(
            "one.toml",
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        );
        dir.write(
            "two.toml",
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"
"#,
        );

        let error = load_policy_dir(dir.path()).expect_err("duplicate grant");

        assert!(matches!(error, ConfigError::DuplicateGrantName { .. }));
    }

    #[test]
    fn rejects_duplicate_approval_transports_across_policy_directory() {
        let dir = TempPolicyDir::new();
        dir.write(
            "one.toml",
            r#"
[[grants]]
name = "aws.prod-readonly"
provider = "aws_prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"

[approval_transports.slack]
type = "slack"
"#,
        );
        dir.write(
            "two.toml",
            r#"
[[grants]]
name = "github.personal-readonly"
provider = "github_personal"
allow = ["gh"]
commands = ["gh pr view *"]
approval = "grant"

[approval_transports.slack]
type = "slack"
"#,
        );

        let error = load_policy_dir(dir.path()).expect_err("duplicate transport");

        assert!(matches!(
            error,
            ConfigError::DuplicateApprovalTransport { .. }
        ));
    }

    #[test]
    fn rejects_missing_policy_directory() {
        let dir = TempPolicyDir::new();
        let missing = dir.path().join("missing");

        let error = load_policy_dir(missing).expect_err("missing directory");

        assert!(matches!(error, ConfigError::ReadDir { .. }));
    }

    #[test]
    fn rejects_policy_path_that_is_not_a_directory() {
        let dir = TempPolicyDir::new();
        dir.write("policy.toml", VALID_POLICY);

        let error = load_policy_dir(dir.path().join("policy.toml")).expect_err("not directory");

        assert!(matches!(
            error,
            ConfigError::PolicyPathIsNotDirectory { .. }
        ));
    }

    struct TempPolicyDir {
        path: PathBuf,
    }

    impl TempPolicyDir {
        fn new() -> Self {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "heim-config-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temp policy directory");

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, name: &str, contents: &str) {
            fs::write(self.path.join(name), contents).expect("write policy fixture");
        }
    }

    impl Drop for TempPolicyDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
