//! Configuration loading for Heim.
//!
//! This crate validates policy documents and converts them into core grant
//! policy types. It does not evaluate policies or execute commands.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fmt;
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

/// Return Heim's default policy directory.
///
/// On Linux this follows `XDG_CONFIG_HOME` when set and falls back to
/// `$HOME/.config`. On macOS it uses `$HOME/Library/Application Support`.
/// On Windows it uses `%APPDATA%`.
pub fn default_policy_dir() -> Result<PathBuf, ConfigError> {
    default_policy_dir_from_env(|name| env::var_os(name))
}

/// Load and validate all TOML policy files from Heim's default policy directory.
pub fn load_default_policy_dir() -> Result<PolicyDocument, ConfigError> {
    load_policy_dir(default_policy_dir()?)
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
    ParsePolicyToml {
        path: String,
        source: toml::de::Error,
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
                formatter.write_str("failed to find config directory for Heim policy config")
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
            Self::ParsePolicyToml { path, source } => {
                write!(formatter, "failed to parse policy TOML {path}: {source}")
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
            Self::ParsePolicyToml { source, .. } => Some(source),
            _ => None,
        }
    }
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
    let config_dir = platform_config_dir(&mut var_os)?;
    Ok(config_dir.join("heim").join("policies"))
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

    use super::{ConfigError, default_policy_dir_from_env, load_policy_dir, parse_policy_str};

    const VALID_POLICY: &str = r##"
[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
allow = ["codex", "*"]
commands = ["aws *"]
approval = "jit:slack"

[approval_transports.slack]
type = "slack"
channel = "#heim-approvals"
"##;

    #[test]
    fn parses_valid_policy_into_core_grants() {
        let document = parse_policy_str(VALID_POLICY).expect("valid policy");

        assert_eq!(document.grants.len(), 1);
        assert_eq!(document.approval_transports.len(), 1);

        let grant = &document.grants[0];
        assert_eq!(grant.name.as_str(), "aws.prod-readonly");
        assert_eq!(grant.provider.as_str(), "aws.prod");
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
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "aws.prod"
allow = ["codex"]
commands = ["aws *"]
approval = "grant"

[[grants]]
name = "aws.prod-readonly"
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "aws.prod"
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
provider = "github.personal"
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
