//! Credential providers for Heim.
//!
//! This crate converts resolved secret material into process-scoped credential
//! carriers. It does not call AWS or GitHub APIs yet.

use std::fmt;
use std::path::PathBuf;

use heim_sources::ResolvedSecret;

/// Request context passed to a credential provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    pub grant: String,
    pub provider: String,
    pub requester: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub git: Option<ProviderGitContext>,
}

impl CredentialRequest {
    pub fn new(
        grant: impl Into<String>,
        provider: impl Into<String>,
        requester: impl Into<String>,
        command: impl IntoIterator<Item = impl Into<String>>,
        cwd: PathBuf,
    ) -> Self {
        Self {
            grant: grant.into(),
            provider: provider.into(),
            requester: requester.into(),
            command: command.into_iter().map(Into::into).collect(),
            cwd,
            git: None,
        }
    }

    pub fn with_git(mut self, git: ProviderGitContext) -> Self {
        self.git = Some(git);
        self
    }
}

/// Git metadata available to providers when detected locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGitContext {
    pub remote: Option<String>,
    pub branch: Option<String>,
}

impl ProviderGitContext {
    pub fn new(remote: Option<String>, branch: Option<String>) -> Self {
        Self { remote, branch }
    }
}

/// Environment variable carrying credential material.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialEnvVar {
    name: String,
    value: String,
}

impl CredentialEnvVar {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for CredentialEnvVar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialEnvVar")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Credential material ready to inject into a child process.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    kind: String,
    env_vars: Vec<CredentialEnvVar>,
    temp_files: Vec<String>,
}

impl IssuedCredential {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            env_vars: Vec::new(),
            temp_files: Vec::new(),
        }
    }

    pub fn with_env_var(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push(CredentialEnvVar::new(name, value));
        self
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn env_vars(&self) -> &[CredentialEnvVar] {
        &self.env_vars
    }

    pub fn temp_files(&self) -> &[String] {
        &self.temp_files
    }

    pub fn metadata(&self) -> CredentialMetadata {
        CredentialMetadata {
            kind: self.kind.clone(),
            env_vars: self.env_vars.iter().map(|env| env.name.clone()).collect(),
            temp_files: self.temp_files.clone(),
        }
    }
}

impl fmt::Debug for IssuedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedCredential")
            .field("kind", &self.kind)
            .field("env_vars", &self.env_vars)
            .field("temp_files", &self.temp_files)
            .finish()
    }
}

/// Redacted credential metadata suitable for audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMetadata {
    pub kind: String,
    pub env_vars: Vec<String>,
    pub temp_files: Vec<String>,
}

/// Common behavior for credential providers.
pub trait CredentialProvider {
    fn issue(&self, request: &CredentialRequest) -> Result<IssuedCredential, ProviderError>;
}

/// GitHub PAT pass-through provider.
///
/// PAT support is an unsafe compatibility provider. GitHub App installation
/// tokens remain the preferred GitHub provider once implemented.
#[derive(Clone, PartialEq, Eq)]
pub struct GithubPatProvider {
    token: String,
}

impl GithubPatProvider {
    pub fn from_secret(secret: ResolvedSecret) -> Result<Self, ProviderError> {
        match secret {
            ResolvedSecret::GithubPat { token } => Ok(Self { token }),
            other => Err(ProviderError::SecretKindMismatch {
                provider: "github_pat".to_owned(),
                actual: other.kind().to_string(),
            }),
        }
    }
}

impl fmt::Debug for GithubPatProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPatProvider")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl CredentialProvider for GithubPatProvider {
    fn issue(&self, _request: &CredentialRequest) -> Result<IssuedCredential, ProviderError> {
        Ok(IssuedCredential::new("github_pat")
            .with_env_var("GH_TOKEN", self.token.clone())
            .with_env_var("GITHUB_TOKEN", self.token.clone()))
    }
}

/// Provider error without credential secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    UnsupportedProvider {
        provider: String,
        provider_type: &'static str,
    },
    SecretKindMismatch {
        provider: String,
        actual: String,
    },
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProvider {
                provider,
                provider_type,
            } => write!(
                formatter,
                "provider {provider} has type {provider_type}, which cannot issue credentials yet"
            ),
            Self::SecretKindMismatch { provider, actual } => write!(
                formatter,
                "provider {provider} received secret type {actual}, but expected github_pat"
            ),
        }
    }
}

impl std::error::Error for ProviderError {}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use heim_sources::ResolvedSecret;

    use super::{CredentialProvider, CredentialRequest, GithubPatProvider};

    #[test]
    fn github_pat_provider_issues_gh_environment_variables() {
        let provider = GithubPatProvider::from_secret(ResolvedSecret::GithubPat {
            token: "ghp_secret".to_owned(),
        })
        .expect("provider");
        let request = CredentialRequest::new(
            "github.personal-readonly",
            "github_personal",
            "gh",
            ["gh", "pr", "view", "42"],
            PathBuf::from("/workspace"),
        );

        let credential = provider.issue(&request).expect("credential");

        assert_eq!(credential.kind(), "github_pat");
        assert_eq!(credential.env_vars()[0].name(), "GH_TOKEN");
        assert_eq!(credential.env_vars()[0].value(), "ghp_secret");
        assert_eq!(credential.env_vars()[1].name(), "GITHUB_TOKEN");
        assert_eq!(credential.env_vars()[1].value(), "ghp_secret");
    }

    #[test]
    fn issued_credential_metadata_excludes_secret_values() {
        let provider = GithubPatProvider::from_secret(ResolvedSecret::GithubPat {
            token: "ghp_secret".to_owned(),
        })
        .expect("provider");
        let request = CredentialRequest::new(
            "github.personal-readonly",
            "github_personal",
            "gh",
            ["gh", "pr", "view", "42"],
            PathBuf::from("/workspace"),
        );

        let credential = provider.issue(&request).expect("credential");
        let metadata = credential.metadata();
        let debug = format!("{credential:?}");

        assert_eq!(metadata.kind, "github_pat");
        assert_eq!(metadata.env_vars, ["GH_TOKEN", "GITHUB_TOKEN"]);
        assert_eq!(metadata.temp_files, Vec::<String>::new());
        assert!(!debug.contains("ghp_secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn github_pat_provider_rejects_wrong_secret_kind_without_printing_secret() {
        let error = GithubPatProvider::from_secret(ResolvedSecret::GithubAppPrivateKey {
            pem: "secret-pem".to_owned(),
        })
        .expect_err("wrong secret kind");

        assert_eq!(
            error.to_string(),
            "provider github_pat received secret type github_app_private_key, but expected github_pat"
        );
        assert!(!format!("{error:?}").contains("secret-pem"));
    }
}
